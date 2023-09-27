import asyncio
import copy
import logging
from typing import Any
from lib.base_get_controller import BaseGetConfigController
from lib.live_cluster.client.config_handler import (
    BaseConfigHandler,
    JsonDynamicConfigHandler,
)
from lib.live_cluster.get_controller import GetClusterMetadataController
from lib.utils import constants, version
from lib.utils.types import NodeDict

logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
MINIMUM_SUPPORTED_VERSION = "5.0.0"
INTERMEDIATE = "intermediate"

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


class InterLoggingContextKey(str):
    pass


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


class ConfigPipelineStep:
    async def __call__(self, intermediate_dict: dict[IntermediateKey | str, Any]):
        raise NotImplementedError("ConfigPipelineStep.__call__ not implemented")


class ConfigPipeline(ConfigPipelineStep):
    def __init__(self, steps: list["ConfigPipelineStep"]):
        self._steps = steps

    def add_step(self, step: "ConfigPipelineStep"):
        self._steps.append(step)

    async def __call__(self, intermediate_dict: dict[str | IntermediateKey, Any]):
        for step in self._steps:
            await step(intermediate_dict)


class GetConfigStep(ConfigPipelineStep):
    def __init__(
        self,
        config_getter: BaseGetConfigController,
        metadata_getter: GetClusterMetadataController,
        node_selector: constants.NodeSelectionType,
    ):
        self.node_selector = node_selector
        self.config_getter = config_getter
        self.metadata_getter = metadata_getter
        super().__init__()

    async def __call__(self, context_dict: dict[str, Any]):
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
            self.config_getter.get_logging(nodes=self.node_selector),
            self.config_getter.get_service(nodes=self.node_selector),
            self.config_getter.get_network(nodes=self.node_selector),
            self.config_getter.get_security(nodes=self.node_selector),
            self.config_getter.get_namespace(nodes=self.node_selector),
            self.config_getter.get_sets(nodes=self.node_selector),
            self.config_getter.get_rack_ids(nodes=self.node_selector),
            self.config_getter.get_xdr(nodes=self.node_selector),
            self.config_getter.get_xdr_dcs(nodes=self.node_selector),
            self.config_getter.get_xdr_namespaces(nodes=self.node_selector),
            self.metadata_getter.get_builds(nodes=self.node_selector),
        )

        context_dict["logging"] = logging_config
        context_dict["service"] = service_config
        context_dict["network"] = network_config
        context_dict["security"] = security_config
        context_dict["namespaces"] = namespaces_config
        context_dict["sets"] = set_config
        context_dict["rack-ids"] = rack_id_config
        context_dict["xdr"] = xdr_config
        context_dict["xdr-dcs"] = xdr_dc_config
        context_dict["xdr-namespaces"] = xdr_namespace_config
        context_dict["builds"] = builds


class ServerVersionCheck(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        builds = context_dict["builds"]

        for host, build in builds.items():
            if version.LooseVersion(build) < version.LooseVersion(
                MINIMUM_SUPPORTED_VERSION
            ):
                raise NotImplementedError(
                    f"Config generation is not supported for Aerospike versions less than {MINIMUM_SUPPORTED_VERSION}"
                )


class CreateIntermediateDict(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        context_dict[INTERMEDIATE] = {}
        hosts = set(
            [
                *context_dict.get("logging", {}).keys(),
                *context_dict.get("service", {}).keys(),
                *context_dict.get("network", {}).keys(),
                *context_dict.get("security", {}).keys(),
                *context_dict.get("namespaces", {}).keys(),
                *context_dict.get("xdr", {}).keys(),
            ]
        )

        for host in hosts:
            context_dict[INTERMEDIATE][host] = {}


class CopyNamespaceConfig(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        namespace_config = context_dict["namespaces"]

        for host in namespace_config:
            host_namespaces_config = namespace_config[host]
            for ns in list(host_namespaces_config.keys()):
                context_dict[INTERMEDIATE][host][
                    InterNamedSectionKey("namespace", ns)
                ] = copy.deepcopy(host_namespaces_config[ns])


class CopySetConfig(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        set_config = context_dict["sets"]

        for host in set_config:
            host_set_config = set_config[host]

            for ns, set_name in host_set_config:
                context_dict[INTERMEDIATE][host][InterNamedSectionKey("namespace", ns)][
                    InterNamedSectionKey("set", set_name)
                ] = copy.deepcopy(host_set_config[(ns, set_name)])


class OverrideNamespaceRackID(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        rack_id_config = context_dict["rack-ids"]

        for host in rack_id_config:
            host_rack_id_config = rack_id_config[host]
            for ns in host_rack_id_config:
                context_dict[INTERMEDIATE][host][InterNamedSectionKey("namespace", ns)][
                    "rack-id"
                ] = host_rack_id_config[ns]


class CopyXDRConfig(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        xdr_config = context_dict["xdr"]

        for host in xdr_config:
            host_xdr_config = xdr_config[host]

            context_dict[INTERMEDIATE][host][
                InterUnnamedSectionKey("xdr")
            ] = copy.deepcopy(host_xdr_config)


class CopyXDRDCConfig(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        xdr_dc_config = context_dict["xdr-dcs"]

        for host in xdr_dc_config:
            host_xdr_dc_config = xdr_dc_config[host]
            for dc in host_xdr_dc_config:
                context_dict[INTERMEDIATE][host][InterUnnamedSectionKey("xdr")][
                    InterNamedSectionKey("dc", dc)
                ] = copy.deepcopy(host_xdr_dc_config[dc])


class CopyXDRNamespaceConfig(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        xdr_namespace_config = context_dict["xdr-namespaces"]

        for host in xdr_namespace_config:
            host_xdr_namespace_config = xdr_namespace_config[host]
            for dc in host_xdr_namespace_config:
                for ns in host_xdr_namespace_config[dc]:
                    context_dict[INTERMEDIATE][host][InterUnnamedSectionKey("xdr")][
                        InterNamedSectionKey("dc", dc)
                    ][InterNamedSectionKey("namespace", ns)] = copy.deepcopy(
                        host_xdr_namespace_config[dc][ns]
                    )


class CopyLoggingConfig(ConfigPipelineStep):
    def _copy_subcontext(self, config_dict: dict[str, Any]):
        result = {}

        for config, val in config_dict.items():
            result[InterLoggingContextKey(config)] = val

        return result

    async def __call__(self, context_dict: dict[str, Any]):
        logging_config = context_dict["logging"]

        for host in list(logging_config.keys()):
            host_logging_config = logging_config[host]
            for log in list(host_logging_config.keys()):
                inter_logging_config = context_dict[INTERMEDIATE][host].setdefault(
                    InterUnnamedSectionKey("logging"), {}
                )
                if log in {"stderr"}:
                    inter_logging_config[
                        InterUnnamedSectionKey("console")
                    ] = self._copy_subcontext(host_logging_config[log])
                elif log.endswith(".log"):
                    inter_logging_config[
                        InterNamedSectionKey("file", log)
                    ] = self._copy_subcontext(host_logging_config[log])
                else:
                    # It is either a syslog or a file without a .log extension.
                    syslog_config = inter_logging_config[
                        InterUnnamedSectionKey("syslog")
                    ] = self._copy_subcontext(host_logging_config[log])
                    syslog_config["path"] = log


class CopyServiceConfig(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        service_config = context_dict["service"]

        for host in list(service_config.keys()):
            host_service_config = service_config[host]
            context_dict[INTERMEDIATE][host][
                InterUnnamedSectionKey("service")
            ] = copy.deepcopy(host_service_config)


class CopyNetworkConfig(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        network_config = context_dict["network"]

        for host in list(network_config.keys()):
            host_network_config = network_config[host]
            context_dict[INTERMEDIATE][host][
                InterUnnamedSectionKey("network")
            ] = copy.deepcopy(host_network_config)


class CopySecurityConfig(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        security_config = context_dict["security"]

        for host in list(security_config.keys()):
            host_security_config = security_config[host]
            context_dict[INTERMEDIATE][host][
                InterUnnamedSectionKey("security")
            ] = copy.deepcopy(host_security_config)


class CopyToIntermediateDict(ConfigPipeline):
    def __init__(self):
        super().__init__(
            [
                CreateIntermediateDict(),
                CopyLoggingConfig(),
                CopyServiceConfig(),
                CopyNetworkConfig(),
                CopySecurityConfig(),
                CopyNamespaceConfig(),
                CopySetConfig(),
                CopyXDRConfig(),
                CopyXDRDCConfig(),
                CopyXDRNamespaceConfig(),
            ],
        )


class SplitSubcontexts(ConfigPipelineStep):
    """Takes a config dict and splits any subcontexts that are joined with a dot
    into their own subdicts. E.g. "heartbeat.interval" -> {"heartbeat": {"interval": ...}}
    """

    def _helper(self, config_dict: dict[str | IntermediateKey, Any]) -> None:
        contexts_to_delete = []

        for config, value in list(config_dict.items()):
            if isinstance(value, dict):
                self._helper(value)
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
                    Should end up with "index-type pmem": {
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

    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]

        for host in intermediate_dict:
            config_dict = intermediate_dict[host]
            self._helper(config_dict)


class ConvertIndexesSubcontextsToNamedSection(ConfigPipelineStep):
    """Converts subcontext sections that are indexed to named sections. E.g.:
    "network":
        {
            "tls[0]": {
               "name": "tls-name"
            }
        }
    "network":
        {
            NamedSection("tls", "tls-name"): {
               . . .
            }
        }
    should be
    """

    def _helper(self, config_dict: dict[str | IntermediateKey, Any]):
        for config in list(config_dict.keys()):
            value = config_dict[config]

            if isinstance(value, dict):
                self._helper(config_dict[config])

                if isinstance(config, InterUnnamedSectionKey):
                    config_split = config.type.split("[")

                    if len(config_split) > 1:
                        if "name" in config_dict[config]:
                            name = config_dict[config]["name"]
                            del config_dict[config]["name"]

                            del config_dict[config]
                            config_dict[
                                InterNamedSectionKey(config_split[0], name)
                            ] = value

    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]

        for host in intermediate_dict:
            config_dict = intermediate_dict[host]
            self._helper(config_dict)


class ConvertIndexedToList(ConfigPipelineStep):
    def _helper(self, config_dict: dict[str | IntermediateKey, Any]):
        tmp_list_dict: dict[str, list[tuple[int, str]]] = {}

        for config in list(config_dict.keys()):
            value = config_dict[config]

            if isinstance(value, dict):
                self._helper(config_dict[config])
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
            config_dict[InterListKey(config_name)] = [
                value for _, value in sorted(config_list, key=lambda x: x[0])
            ]

    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]

        for host in intermediate_dict:
            config_dict = intermediate_dict[host]
            self._helper(config_dict)


class ConvertCommaSeparatedToList(ConfigPipelineStep):
    """Convert comma separated values to a list. E.g.: "multicast-group" is returned
    comma separated but needs to be on separate lines in the config.
    """

    def _helper(self, config_dict: dict[str | IntermediateKey, Any]):
        for config in list(config_dict.keys()):
            value = config_dict[config]

            if isinstance(value, dict):
                self._helper(config_dict[config])
                continue

            if not isinstance(config, str):
                continue

            split_value = value.split(",")

            if len(split_value) > 1:
                config_dict[InterListKey(config)] = split_value

                del config_dict[config]

    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]

        for host in intermediate_dict:
            config_dict = intermediate_dict[host]
            self._helper(config_dict)


class RemoveSecurityIfNotEnabled(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]
        builds = context_dict["builds"]

        for host in intermediate_dict:
            host_dict = intermediate_dict[host]
            security_key = InterUnnamedSectionKey("security")
            security_config = host_dict.get(security_key, {})

            # If security is not enabled, remove the security config for either pre 5.6
            # or post 5.6
            if (
                "enable-security" in security_config
                and str(security_config["enable-security"]).lower() == "false"
            ):
                del host_dict[security_key]
                continue

            build = builds[host]
            # If security is enabled in post 5.6 then remove enable-security because it will
            # cause aerospike to not start. :(
            if version.LooseVersion("5.7.0") <= version.LooseVersion(build):
                if "enable-security" in security_config:
                    del host_dict[security_key]["enable-security"]
                elif not security_config:
                    # If security config returns empty then security was never enabled.
                    del host_dict[security_key]


class RemoveEmptyGeo2DSpheres(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]

        for host in intermediate_dict:
            host_dict = intermediate_dict[host]

            for config in host_dict:
                if (
                    isinstance(config, InterNamedSectionKey)
                    and config.type == "namespace"
                ):
                    namespace_config = host_dict[config]
                    geo2dsphere_config = namespace_config.get(
                        InterUnnamedSectionKey("geo2dsphere-within"), None
                    )

                    if geo2dsphere_config is not None and geo2dsphere_config == {}:
                        del namespace_config[
                            InterUnnamedSectionKey("geo2dsphere-within")
                        ]


class RemoveXDRIfNoDCs(ConfigPipelineStep):
    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]

        for host in intermediate_dict:
            host_dict = intermediate_dict[host]
            xdr_key = InterUnnamedSectionKey("xdr")
            xdr_config = host_dict.get(xdr_key, {})

            """ "dcs" is not remove yet because we have not removed values that are not
            found in the schemas yet
            """
            if not xdr_config.get("dcs", ""):
                del host_dict[xdr_key]


class SplitColonSeparatedValues(ConfigPipelineStep):
    """
    Some values are split by colon when returned by the server but must be space
    separated in the config. One exception is 'cipher-suites'.
    """

    def _helper(self, config_dict: dict[IntermediateKey | str, Any]):
        for key, value in config_dict.items():
            if isinstance(value, dict):
                self._helper(value)
                continue

            if not isinstance(value, str):
                continue

            if ":" in value and not key in {"cipher-suites"}:
                value_split = value.split(":")
                config_dict[key] = " ".join(value_split)

    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]

        for host in intermediate_dict:
            self._helper(intermediate_dict[host])


class RemoveInvalidKeysFoundInSchemas(ConfigPipelineStep):
    """Remove keys found in the schemas but are not allowed in the final config. E.g.:
    "dcs" and "namespaces"

    "xdr": {
        "dcs": "dc1,dc2", # Found in the schemas but not allowed in the config
        "dc DC1": {
            "namespaces": # Also remove in this step
            "namespace test": {

            }
        }
    }
    """

    def _helper(
        self,
        config_dict: dict[IntermediateKey | str, Any],
    ):
        delete_after = []

        for key, value in list(config_dict.items()):
            if isinstance(value, dict):
                if isinstance(key, InterNamedSectionKey):
                    if key.type + "s" in config_dict:
                        delete_after.append(key.type + "s")
                elif isinstance(key, InterUnnamedSectionKey):
                    if key.type + "s" in config_dict:
                        delete_after.append(key.type + "s")

                self._helper(value)
                continue

        for key in delete_after:
            if key in config_dict:
                del config_dict[key]

    async def __call__(self, context_dict: dict[str, Any]):
        intermediate_dict = context_dict[INTERMEDIATE]

        for host in intermediate_dict:
            self._helper(intermediate_dict[host])


class RemoveNullOrEmptyValues(ConfigPipelineStep):
    """Some values return "null" but that is not a valid config value. You would think
    that the step that removes non-defaults would handle this case but it does not.
    e.g.: xdr.dc.namespace.remote-namespace
    """

    def _helper(self, config_dict: dict[IntermediateKey | str, Any]):
        for key, value in list(config_dict.items()):
            if isinstance(value, dict):
                self._helper(value)
                continue

            if isinstance(value, str) and (value.lower() == "null" or value == ""):
                del config_dict[key]

    async def __call__(self, context_dict: dict[str, Any]):
        for host in context_dict[INTERMEDIATE]:
            self._helper(context_dict[INTERMEDIATE][host])


class RemoveDefaultAndNonExistentKeys(ConfigPipelineStep):
    def __init__(self, config_handler: type[BaseConfigHandler]):
        self.config_handler = config_handler
        super().__init__()

    def _get_config_name(self, config: str | InterLoggingContextKey) -> str:
        if isinstance(config, str):
            return config

        if isinstance(config, InterListKey):
            return config.name

        return config.type

    def _helper(
        self,
        config_handler: BaseConfigHandler,
        context: list[str],
        config_dict: dict[str, Any],
    ):
        for config, val in list(config_dict.items()):
            new_context = list(context)

            if isinstance(val, dict):
                if isinstance(config, InterNamedSectionKey) or isinstance(
                    config, InterUnnamedSectionKey
                ):
                    new_context.append(config.type)
                elif isinstance(config, str):
                    new_context.append(config)

                self._helper(config_handler, list(new_context), val)
                continue

            if isinstance(config, str) or isinstance(config, InterListKey):
                conf_type = config_handler.get_types(
                    list(new_context), self._get_config_name(config)
                )[self._get_config_name(config)]

                if conf_type is None:
                    """
                    Handles configs like network.heartbeat.multicast-group which is stored
                    in the config as multicast-groups
                    """
                    conf_type = config_handler.get_types(
                        list(new_context), self._get_config_name(config) + "s"
                    )[self._get_config_name(config) + "s"]

                    if conf_type is None:
                        """
                        Handles configs like network.service.address which is stored
                        in the config as addresses
                        """
                        conf_type = config_handler.get_types(
                            list(new_context), self._get_config_name(config) + "es"
                        )[self._get_config_name(config) + "es"]

                    if conf_type is None:
                        """
                        Handles cases where the config is also a subcontext like in the
                        case if storage-engine. It can just be 'storage-engine memory'
                        or it can have it's own subcontext like 'storage-engine device'.
                        Regardless, it is stored in the schemas a sub-context.
                        """
                        new_context.append(self._get_config_name(config))
                        params = config_handler.get_params(list(new_context))

                        if params:
                            logger.debug(
                                f"The config {config} is also a subcontext. Could not determine default value and not removing it."
                            )
                            continue

                if conf_type is None:
                    logger.warning(f"Could not find config type for {config}")
                    del config_dict[config]
                elif str(conf_type.default).lower() == str(config_dict[config]).lower():
                    logger.debug("Removing default value for %s", config)
                    del config_dict[config]
                else:
                    logger.debug(
                        f"Not removing default value for {config} value: {config_dict[config]} default: {conf_type.default}"
                    )
            else:
                raise NotImplementedError(
                    f"Unsupported type in {self.__class__.__name__} step {config} {val}"
                )

    def _logging_helper(
        self,
        config_dict: dict[str | IntermediateKey, Any],
    ):
        configs_set_info = []
        configs_set_critical = []
        configs_set_other = []

        for config, val in list(config_dict.items()):
            if isinstance(val, dict):
                self._logging_helper(val)
                continue

            if val.lower() == "info":
                configs_set_info.append(config)
            elif val.lower() == "critical":
                configs_set_critical.append(config)
            else:
                configs_set_other.append(config)

        # We are only simplifying the two most common logging config cases. Either most
        # are set to critical or most are set to info.
        if len(configs_set_info) > len(configs_set_critical) + len(configs_set_other):
            for config in configs_set_info:
                del config_dict[config]

            config_dict[InterLoggingContextKey("any")] = "info"
        elif len(configs_set_critical) > len(configs_set_info) + len(configs_set_other):
            for config in configs_set_critical:
                del config_dict[config]

            config_dict[InterLoggingContextKey("any")] = "critical"

    def _remove_default_values(
        self, build: str, configs: dict[InterUnnamedSectionKey, Any]
    ):
        config_handler = self.config_handler(
            constants.CONFIG_SCHEMAS_HOME, build, strict=True
        )

        for top_level_config in configs.keys():
            if top_level_config.type == "logging":
                self._logging_helper(configs[top_level_config])
            else:
                self._helper(
                    config_handler, [top_level_config.type], configs[top_level_config]
                )

    async def __call__(self, context_dict: dict[str, Any]):
        builds = context_dict["builds"]

        for host in context_dict[INTERMEDIATE]:
            build = builds[host]
            host_config = context_dict[INTERMEDIATE][host]
            self._remove_default_values(build, host_config)


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

    async def _generate_intermediate(
        self, node_selector: constants.NodeSelectionType
    ) -> NodeDict[Any]:
        """Generate a YAML config file from the current cluster state."""

        pipeline = ConfigPipeline(
            [
                GetConfigStep(self.config_getter, self.metadata_getter, node_selector),
                ServerVersionCheck(),
                CopyToIntermediateDict(),
                OverrideNamespaceRackID(),
                SplitSubcontexts(),
                ConvertIndexesSubcontextsToNamedSection(),
                RemoveSecurityIfNotEnabled(),
                RemoveXDRIfNoDCs(),
                RemoveNullOrEmptyValues(),
                ConvertIndexedToList(),
                SplitColonSeparatedValues(),
                RemoveDefaultAndNonExistentKeys(JsonDynamicConfigHandler),
                RemoveInvalidKeysFoundInSchemas(),
                ConvertCommaSeparatedToList(),
                RemoveEmptyGeo2DSpheres(),  # Should be after RemoveDefaultValues
            ],
        )

        context_dict = {}
        await pipeline(context_dict)
        return context_dict[INTERMEDIATE]

    def _generate_helper(
        self,
        result: list[str],
        intermediate_dict: dict[IntermediateKey | str, Any],
        indent=0,
    ):
        adjusted_indent = indent * 2

        for key, val in intermediate_dict.items():
            if isinstance(key, InterUnnamedSectionKey):
                result.append(f"\n{'  ' * adjusted_indent}{key.type} {{")
                self._generate_helper(result, val, indent + 1)
                result.append(f"{'  ' * adjusted_indent}}}")
            elif isinstance(key, InterNamedSectionKey):
                result.append(f"\n{'  ' * adjusted_indent}{key.type} {key.name} {{")
                self._generate_helper(result, val, indent + 1)
                result.append(f"{'  ' * adjusted_indent}}}")
            elif isinstance(key, InterListKey):
                for value in val:
                    result.append(f"{'  ' * adjusted_indent}{key.name} {value}")
            elif isinstance(key, InterLoggingContextKey):
                result.append(f"{'  ' * adjusted_indent} context {key} {val}")
            elif isinstance(val, str):
                result.append(f"{'  ' * adjusted_indent}{key} {val}")
            else:
                raise NotImplementedError(
                    f"Unsupported type {type(key)} for {key} and {val}"
                )

    async def generate(
        self, node_selector: constants.NodeSelectionType = constants.NodeSelection.ALL
    ) -> str:
        """Generate a YAML config file from the current cluster state."""
        intermediate_dict = await self._generate_intermediate(node_selector)
        lines = []

        self._generate_helper(lines, list(intermediate_dict.values())[0])
        return "\n".join(lines)
