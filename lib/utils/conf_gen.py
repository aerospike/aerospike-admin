import asyncio
import logging
from typing import Any
from lib.base_get_controller import BaseGetConfigController
from lib.live_cluster.get_controller import GetClusterMetadataController
from lib.utils import version
from lib.utils.types import NodeDict

logger = logging.getLogger(__name__)


class ConfigGenerator:
    async def generate(self) -> str:
        raise NotImplementedError("ConfigGenerator.generate not implemented")

    def __str__(self):
        return self.generate()


class YamlConfigGenerator(ConfigGenerator):
    def __init__(
        self,
        config_getter: BaseGetConfigController,
        metadata_getter: GetClusterMetadataController,
    ):
        self.config_getter = config_getter

    def _split_subcontexts(self, config_dict: dict[str, Any]) -> None:
        """Takes a config dict and splits any subcontexts that are joined with a dot
        into their own subdicts. E.g. "heartbeat.interval" -> {"heartbeat": {"interval": ...}}

        Arguments:
            config_dict {dict[str, Any]} -- A dictionary that needs config params split.
        """
        for config, value in config_dict.items():
            if isinstance(value, dict):
                self._split_subcontexts(value)
                continue

            contexts = config.split(".")

            if len(contexts) > 1:
                del config_dict[config]
                dict_ptr: dict[str, Any] = config_dict

                for c in contexts[:-1]:
                    """
                    Handles cases like index-type=pmem index-type.mounts-high-water-pct=99
                    Should end up with "index-type": {"name": "pmem",
                    "mounts-high-water-pct":99}. We will need to deal with indexed
                    params later. e.g. "mount[i]"
                    """
                    if c in dict_ptr:
                        name = dict_ptr[c]
                        dict_ptr[c] = {"name": name}
                    else:
                        dict_ptr = dict_ptr.setdefault(c, {})

                dict_ptr[contexts[-1]] = value

    def _create_lists_indexed_config(self, config_dict: dict[str, Any]):
        tmp_list_dict: dict[str, list[tuple[int, str]]] = {}

        for config in list(config_dict.keys()):
            value = config_dict[config]

            if isinstance(value, dict):
                self._create_lists_indexed_config(config_dict[config])
                continue

            if config.endswith("]"):
                config_split = config.split("[")
                config_name = config_split[0]
                config_index = int(config_split[1][:-1])

                if config_name not in tmp_list_dict:
                    tmp_list_dict[config_name] = []

                tmp_list_dict[config_name].append((config_index, value))
                del config_dict[config]

        for config_name, config_list in tmp_list_dict.items():
            config_dict[config_name] = sorted(config_list, key=lambda x: x[0])

            # Find the rest of the configs

    def _remove_set_stats(self, config_dict: dict[str, Any]):
        sets_config_and_stats = config_dict.get("namespace", {}).get("sets", {})

        for set_config_and_stats in list(sets_config_and_stats.values()):
            for config in list(set_config_and_stats.keys()):
                if (
                    "_" in config
                    or config
                    in {  # TODO: Should we cross check with the config schemas and not hardcode this?
                        "objects",
                        "tombstones",
                        "truncating",
                        "sindexes",
                        "ns",
                        "set",
                    }
                ):
                    del set_config_and_stats[config]

    def _remove_enable_security_post_5_6(self, config_dict: dict[str, Any], build: str):
        security_config = config_dict.get("security", {})

        # If security is not enabled, remove the security config for either pre 5.6 or post 5.6
        if security_config.get("enable-security", False):
            del config_dict["security"]
            return

        # If security is enabled in post 5.6 then remove enable-security because it will
        # cause aerospike to not start. :(
        if version.LooseVersion("5.7.0") <= version.LooseVersion(build):
            if "enable-security" in security_config:
                del config_dict["security"]["enable-security"]
            elif not security_config:
                # If security config returns empty then security was never enabled.
                del config_dict["security"]

    async def generate(self) -> str:
        """Generate a YAML config file from the current cluster state."""
        intermediate_dict: NodeDict[Any] = {}
        (
            logging_config,
            service_config,
            network_config,
            security_config,
            namespace_config,
            set_config,
            rack_id_config,
            xdr_config,
            xdr_dc_config,
            xdr_namespace_config,
            build,
        ) = await asyncio.gather(
            self.config_getter.get_logging(),
            self.config_getter.get_service(),
            self.config_getter.get_network(),
            self.config_getter.get_security(),
            self.config_getter.get_namespace(),
            self.config_getter.get_sets(),
            self.config_getter.get_rack_ids(),
            self.config_getter.get_xdr(),
            self.config_getter.get_xdr_dcs(),
            self.config_getter.get_xdr_namespaces(),
        )

        for host in namespace_config:
            intermediate_dict.setdefault(host, {})
            host_namespace_config = namespace_config[host]
            self._split_subcontexts(host_namespace_config)
            for ns in host_namespace_config:
                # Insert set config into namespace config
                host_set_config = set_config.get(host, {})

                for ns2, set2 in host_set_config:
                    if ns2 == ns:
                        namespace_config[host][ns]["sets"][set2] = host_set_config[
                            (ns2, set2)
                        ]

                # Insert rack id config into namespace config
                host_rack_id_config = rack_id_config.get(host, {})
                if ns in host_rack_id_config:
                    namespace_config[host][ns]["rack-id"] = host_rack_id_config[ns]

        # Deconstruct network config params that are joined with contexts using a dot. .e.g. "heartbeat.interval"
        for host in network_config:
            intermediate_dict.setdefault(host, {})
            host_network_config = network_config[host]
            self._split_subcontexts(host_network_config)

        # Combine xdr top level config with xdr dc config and xdr namespace config
        for host in xdr_config:
            intermediate_dict.setdefault(host, {})
            host_xdr_config = xdr_config[host]

            for config in host_xdr_config:
                # TODO: Should we cross check with the config schemas and not hardcode this?
                if config in {
                    "trace-sample"
                }:  # No need to include "dcs" because it is overwritten below
                    del host_xdr_config[config]

            host_xdr_dc_config = xdr_dc_config.get(
                host, {}
            )  # TODO: maybe try accept and raise error if not found?

            if "dcs" not in host_xdr_config:
                host_xdr_config["dcs"] = {}

            for dc in host_xdr_dc_config:
                host_xdr_config["dcs"][dc] = host_xdr_dc_config[dc]
                host_xdr_config["dcs"][dc]["namespaces"] = {}

                host_xdr_namespace_config = xdr_namespace_config.get(host, {})

                for ns in host_xdr_namespace_config.get(
                    dc, {}
                ):  # TODO: Again, maybe error out if not found?
                    host_xdr_config["dcs"][dc]["namespaces"][
                        ns
                    ] = host_xdr_namespace_config[dc][ns]

        for host in logging_config:
            intermediate_dict.setdefault(host, {})
            host_logging_config = logging_config[host]
            for log in host_logging_config:
                if log in {"stderr"}:
                    host_logging_config["console"] = host_logging_config[log]
                    del host_logging_config[log]
                elif log.endswith(".log"):
                    host_logging_config[f"file {log}"] = host_logging_config[log]
                    del host_logging_config[log]
                else:
                    # TODO: It is either a syslog or a file without a .log extension. What
                    # to do?
                    host_logging_config[f"syslog {log}"] = host_logging_config[log]
                    del host_logging_config[log]

        for host, host_dict in intermediate_dict.items():
            # Consolidate all configs under correct host
            host_dict["logging"] = logging_config[host]
            host_dict["service"] = service_config[host]
            host_dict["security"] = security_config[host]
            host_dict["namespace"] = namespace_config[host]
            host_dict["xdr"] = xdr_config[host]

            self._split_subcontexts(host_dict)
            self._create_lists_indexed_config(host_dict)
            self._remove_set_stats(host_dict)
            self._remove_enable_security_post_5_6(
                host_dict, build.get(host, None)
            )  # TODO, error out?
            # self._split_mesh_seed_address_port(host_dict) #TODO <<<<<<<<<< Work on next
