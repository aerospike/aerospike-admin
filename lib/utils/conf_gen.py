import asyncio
from lib.base_get_controller import BaseGetConfigController


class ConfigGenerator:
    async def generate(self) -> str:
        raise NotImplementedError("ConfigGenerator.generate not implemented")

    def __str__(self):
        return self.generate()


class YamlConfigGenerator(ConfigGenerator):
    def __init__(self, config_getter: BaseGetConfigController):
        self.config_getter = config_getter

    async def generate(self) -> str:
        """Generate a YAML config file from the current cluster state.
        Here are the top-level keys:
        logging, service, mode-lua

        """
        (
            service_config,
            namespace_config,
            set_config,
            rack_id_config,
            xdr_config,
            xdr_dc_config,
            xdr_namespace_config,
        ) = await asyncio.gather(
            self.config_getter.get_service(),
            self.config_getter.get_namespace(),
            self.config_getter.get_sets(),
            self.config_getter.get_rack_ids(),
            self.config_getter.get_xdr(),
            self.config_getter.get_xdr_dcs(),
            self.config_getter.get_xdr_namespaces(),
        )
