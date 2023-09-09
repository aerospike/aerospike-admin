import asyncio
import logging
import pprint
from typing import Any, TypedDict
from typing_extensions import NotRequired
from lib.base_get_controller import BaseGetConfigController
from lib.live_cluster.get_controller import GetClusterMetadataController
from lib.utils import version
from lib.utils.types import NodeDict

logger = logging.getLogger(__name__)
MINIMUM_SUPPORTED_VERSION = "5.0.0"

"""
Generating a config is a 2 step process. First generate the intermediate dict and then
finally generate the config from the intermediate dict. The code that generates the
config should not have to worry about the server version or any edge cases. All the
information it need should be in the intermediate dict.
"""


class IntermediateKey:
    pass


class InterNamedSectionKey(IntermediateKey):
    def __init__(self, type: str, name: str):
        self.type = type
        self.name = name

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.type, self.name))

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, InterNamedSectionKey):
            return False

        return self.name == __value.name and self.type == __value.type

    def __str__(self) -> str:
        return f"({self.__class__.__name__}, {self.type}, {self.name})"

    def __repr__(self) -> str:
        return self.__str__()


class InterUnnamedSectionKey(IntermediateKey):
    def __init__(
        self,
        type: str,
    ):
        self.type = type

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.type))

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, InterUnnamedSectionKey):
            return False

        return self.type == __value.type

    def __str__(self) -> str:
        return f"({self.__class__.__name__}, {self.type})"

    def __repr__(self) -> str:
        return self.__str__()


class InterTupleConfig(IntermediateKey):
    def __init__(self, name: str):
        self.name = name

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.name))

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, InterTupleConfig):
            return False

        return self.name == __value.name

    def __str__(self) -> str:
        return f"({self.__class__.__name__}, {self.name})"

    def __repr__(self) -> str:
        return self.__str__()


class InterLoggingContextKey(InterTupleConfig):
    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.name))

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, InterLoggingContextKey):
            return False

        return self.name == __value.name and super().__eq__(__value)

    def __str__(self) -> str:
        return f"({self.__class__.__name__}, {self.name})"

    def __repr__(self) -> str:
        return self.__str__()


class InterListKey(IntermediateKey):
    def __init__(self, name: str):
        self.name = name

    def __hash__(self) -> int:
        return hash((self.__class__.__name__, self.name))

    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, InterListKey):
            return False

        return self.name == __value.name

    def __str__(self) -> str:
        return f"({self.__class__.__name__}, {self.name})"

    def __repr__(self) -> str:
        return self.__str__()


class ConfigGenerator:
    async def generate(self) -> str:
        raise NotImplementedError("ConfigGenerator.generate not implemented")

    def __str__(self):
        return self.generate()


class ASConfigGenerator(ConfigGenerator):
    def __init__(
        self,
        config_getter: BaseGetConfigController,
        metadata_getter: GetClusterMetadataController,
    ):
        self.config_getter = config_getter
        self.metadata_getter = metadata_getter

    def _split_subcontexts(self, config_dict: dict[str | IntermediateKey, Any]) -> None:
        """Takes a config dict and splits any subcontexts that are joined with a dot
        into their own subdicts. E.g. "heartbeat.interval" -> {"heartbeat": {"interval": ...}}

        Arguments:
            config_dict {dict[str, Any]} -- A dictionary that needs config params split.
        """
        contexts_to_delete = []

        for config, value in list(config_dict.items()):
            if isinstance(value, dict):
                self._split_subcontexts(value)
                continue

            if not isinstance(config, str):
                continue

            contexts = config.split(".")

            if len(contexts) > 1:
                del config_dict[
                    config
                ]  # Delete it so we can reassign it after the loop

                dict_ptr = config_dict

                for c in contexts[:-1]:
                    """
                    Handles cases like index-type=pmem index-type.mounts-high-water-pct=99
                    Should end up with "index-type": {"name": "pmem",
                    "mounts-high-water-pct":99}. We will need to deal with indexed
                    params later. e.g. "mount[i]"
                    """

                    if c in dict_ptr and isinstance(dict_ptr[c], str):
                        name = dict_ptr[c]
                        dict_ptr = dict_ptr.setdefault(
                            InterNamedSectionKey(c, name), {}
                        )

                        """
                        Don't delete the config e.g. index-type because we need the name
                        field in order to continually generate the InterNamedSectionKey
                        """
                        contexts_to_delete.append(c)
                    else:
                        dict_ptr = dict_ptr.setdefault(InterUnnamedSectionKey(c), {})

                dict_ptr[contexts[-1]] = value

        for c in contexts_to_delete:
            if c in config_dict:
                del config_dict[c]

    def _create_lists_indexed_config(
        self, config_dict: dict[str | IntermediateKey, Any]
    ):
        tmp_list_dict: dict[str, list[tuple[int, str]]] = {}

        for config in list(config_dict.keys()):
            value = config_dict[config]

            if isinstance(value, dict):
                self._create_lists_indexed_config(config_dict[config])
                continue

            if not isinstance(config, str):
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
            config_dict[InterListKey(config_name)] = sorted(
                config_list, key=lambda x: x[0]
            )

            # Find the rest of the configs

    def _remove_set_stats(
        self, config_dict: dict[str | IntermediateKey, Any], remove=False
    ):
        for key, val in list(config_dict.items()):
            if isinstance(val, dict):
                remove = (
                    isinstance(key, InterNamedSectionKey)
                    and key.type == "set"
                    or remove
                )
                self._remove_set_stats(val, remove)
                continue

            if not isinstance(key, str):
                continue

            if remove and (
                "_" in key
                or key
                in {  # TODO: Should we cross check with the config schemas and not hardcode this?
                    "objects",
                    "tombstones",
                    "truncating",
                    "sindexes",
                    "ns",
                    "set",
                }
            ):
                del config_dict[key]

    def _remove_enable_security_post_5_6(
        self, config_dict: dict[IntermediateKey | str, Any], build: str
    ):
        security_key = InterUnnamedSectionKey("security")
        security_config = config_dict.get(InterUnnamedSectionKey("security"), {})

        # If security is not enabled, remove the security config for either pre 5.6 or post 5.6
        if security_config.get("enable-security", False):
            del config_dict[security_key]
            return

        # If security is enabled in post 5.6 then remove enable-security because it will
        # cause aerospike to not start. :(
        if version.LooseVersion("5.7.0") <= version.LooseVersion(build):
            if "enable-security" in security_config:
                del config_dict[security_key]["enable-security"]
            elif not security_config:
                # If security config returns empty then security was never enabled.
                del config_dict[security_key]

    def _remove_xdr_if_no_dcs(self, config_dict: dict[IntermediateKey | str, Any]):
        xdr_key = InterUnnamedSectionKey("xdr")
        xdr_config = config_dict.get(xdr_key, {})

        for key in xdr_config:
            if isinstance(key, InterNamedSectionKey) and key.type == "dc":
                return

        del config_dict[xdr_key]

    def _split_colon_separated(self, config_dict: dict[IntermediateKey | str, Any]):
        for key, value in config_dict.items():
            if isinstance(value, dict):
                self._split_colon_separated(value)
                continue

            if not isinstance(value, str):
                continue

            if ":" in value and not key in {"cipher-suites"}:
                value_split = value.split(":")
                config_dict[key] = " ".join(value_split)

    def _remove_redundant_nested_keys(
        self,
        parent_keys: list[str | IntermediateKey],
        config_dict: dict[IntermediateKey | str, Any],
    ):
        for key, value in list(config_dict.items()):
            if isinstance(value, dict):
                new_parent_keys = list(parent_keys)

                if isinstance(key, InterNamedSectionKey):
                    new_parent_keys.append(key.name)
                    new_parent_keys.append(key.type)
                elif isinstance(key, InterUnnamedSectionKey):
                    new_parent_keys.append(key.type)

                self._remove_redundant_nested_keys(new_parent_keys, value)
                continue

            if value in parent_keys:
                del config_dict[key]

    def _convert_logging_contexts(self, config_dict: dict[IntermediateKey | str, Any]):
        logging_key = InterUnnamedSectionKey("logging")
        logging_config = config_dict.get(logging_key, {})

        for key, val in list(logging_config.items()):
            if isinstance(val, dict):
                self._convert_logging_contexts(
                    val
                )  # TODO finish handling logging contexts
                continue

            if not isinstance(key, str):
                continue

            logging_config[InterLoggingContextKey(key)] = val
            del logging_config[key]

    # TODO: Make the intermediate and config_getter dicts separate
    async def _generate_intermediate(self) -> NodeDict[Any]:
        """Generate a YAML config file from the current cluster state."""
        intermediate_dict: NodeDict[Any] = {}
        (
            logging_config,
            service_config,
            network_config,
            security_config,
            namespaces_config,
            set_config,
            rack_id_config,
            xdr_config,
            xdr_dc_config,
            xdr_namespace_config,
            builds,
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
            self.metadata_getter.get_builds(),
        )

        for host, build in builds.items():
            if version.LooseVersion(build) < version.LooseVersion(
                MINIMUM_SUPPORTED_VERSION
            ):
                raise NotImplementedError(
                    f"Config generation is not supported for Aerospike versions less than {MINIMUM_SUPPORTED_VERSION}"
                )

        for host in namespaces_config:
            host_namespaces_config = namespaces_config[host]
            for ns in list(host_namespaces_config.keys()):
                # Insert set config into namespace config
                host_set_config = set_config.get(host, {})

                for ns2, set2 in host_set_config:
                    if ns2 == ns:
                        host_namespaces_config[ns][
                            InterNamedSectionKey("set", set2)
                        ] = host_set_config[(ns2, set2)]

                # Insert rack id config into namespace config
                host_rack_id_config = rack_id_config.get(host, {})
                if ns in host_rack_id_config:
                    host_namespaces_config[ns]["rack-id"] = host_rack_id_config[ns]

                host_namespaces_config[
                    InterNamedSectionKey("namespace", ns)
                ] = host_namespaces_config[ns]
                del host_namespaces_config[ns]

        # Combine xdr top level config with xdr dc config and xdr namespace config
        for host in list(xdr_config.keys()):
            host_xdr_config = xdr_config[host]

            for config in list(host_xdr_config.keys()):
                # TODO: Should we cross check with the config schemas and not hardcode this?
                if config in {
                    "trace-sample"
                }:  # No need to include "dcs" because it is overwritten below
                    del host_xdr_config[config]

            host_xdr_dc_config = xdr_dc_config.get(
                host, {}
            )  # TODO: maybe try accept and raise error if not found?

            # The 'dcs' is present in the top level xdr config but as a string of DCS.
            # Overwrite it with a dict of DCS.
            if "dcs" in host_xdr_config:
                del host_xdr_config["dcs"]

            for dc in host_xdr_dc_config:
                host_xdr_config[InterNamedSectionKey("dc", dc)] = host_xdr_dc_config[dc]

                host_xdr_namespace_config = xdr_namespace_config.get(host, {})

                for ns in host_xdr_namespace_config.get(
                    dc, {}
                ):  # TODO: Again, maybe error out if not found?
                    host_xdr_config[InterNamedSectionKey("dc", dc)][
                        InterNamedSectionKey("namespace", ns)
                    ] = host_xdr_namespace_config[dc][ns]

        for host in list(logging_config.keys()):
            host_logging_config = logging_config[host]
            self._convert_logging_contexts(host_logging_config)
            for log in list(host_logging_config.keys()):
                if log in {"stderr"}:
                    host_logging_config[
                        InterUnnamedSectionKey("console")
                    ] = host_logging_config[log]
                    del host_logging_config[log]
                elif log.endswith(".log"):
                    host_logging_config[
                        InterNamedSectionKey("file", log)
                    ] = host_logging_config[log]
                    del host_logging_config[log]
                else:
                    # TODO: It is either a syslog or a file without a .log extension. What
                    # to do?
                    syslog_config = host_logging_config[
                        InterUnnamedSectionKey("syslog")
                    ] = host_logging_config[log]
                    syslog_config["path"] = log
                    del host_logging_config[log]

        hosts = set(
            [
                *logging_config.keys(),
                *service_config.keys(),
                *network_config.keys(),
                *security_config.keys(),
                *namespaces_config.keys(),
                *xdr_config.keys(),
            ]
        )

        for host in hosts:
            # Consolidate all configs under correct host
            host_dict: dict[IntermediateKey | str, Any] = {
                InterUnnamedSectionKey("logging"): logging_config.get(host, {}),
                InterUnnamedSectionKey("service"): service_config.get(host, {}),
                InterUnnamedSectionKey("network"): network_config.get(host, {}),
                InterUnnamedSectionKey("security"): security_config.get(host, {}),
                InterUnnamedSectionKey("xdr"): xdr_config.get(host, {}),
            }
            host_dict.update(
                namespaces_config.get(host, {})
            )  # namespaces are top level keys

            self._split_subcontexts(host_dict)
            self._create_lists_indexed_config(host_dict)
            self._remove_set_stats(host_dict)
            self._remove_enable_security_post_5_6(host_dict, builds.get(host, None))
            self._remove_xdr_if_no_dcs(host_dict)
            self._split_colon_separated(host_dict)
            self._remove_redundant_nested_keys([], host_dict)

            intermediate_dict[host] = host_dict

        return intermediate_dict

    def _generate_helper(
        self,
        result: list[str],
        intermediate_dict: dict[IntermediateKey | str, Any],
        indent=0,
    ):
        adjusted_indent = indent * 4
        first = False
        for key, val in intermediate_dict.items():
            if isinstance(key, InterUnnamedSectionKey):
                result.append(f"{'  ' * adjusted_indent}{key.type} {{")
                self._generate_helper(result, val, indent + 1)
                result.append(f"{'  ' * adjusted_indent}}}\n")
            elif isinstance(key, InterNamedSectionKey):
                result.append(f"{'  ' * adjusted_indent}{key.type} {key.name} {{")
                self._generate_helper(result, val, indent + 1)
                result.append(f"{'  ' * adjusted_indent}}}\n")
            elif isinstance(key, InterListKey):
                for index, value in val:
                    result.append(f"{'  ' * adjusted_indent}{key.name} {value}")
            elif isinstance(val, str):
                result.append(f"{'  ' * adjusted_indent}{key} {val}")
            else:
                raise NotImplementedError(
                    f"Unsupported type {type(key)} for {key} and {val}"
                )

    async def generate(self) -> str:
        """Generate a YAML config file from the current cluster state."""
        intermediate_dict = await self._generate_intermediate()
        lines = []

        self._generate_helper(lines, list(intermediate_dict.values())[0])
        pass
        return "\n".join(lines)

        return pprint.pformat(intermediate_dict, sort_dicts=True, width=120)
