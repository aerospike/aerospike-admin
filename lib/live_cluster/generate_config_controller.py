import logging
from lib.base_controller import CommandHelp, ModifierHelp, ShellException
from lib.live_cluster.get_controller import (
    GetClusterMetadataController,
    GetConfigController,
)
from lib.live_cluster.live_cluster_command_controller import (
    LiveClusterCommandController,
)
from lib.utils import util
from lib.utils.conf_gen import ASConfigGenerator
from lib.utils.constants import ModifierUsage, Modifiers

logger = logging.getLogger(__name__)


@CommandHelp(
    "BETA: Currently only supports generating a static configuration file from a live node via the 'config' subcommand.",
)
class GenerateController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "config": GenerateConfigController,
        }


@CommandHelp(
    "BETA: Generates a static configuration file from a live node,",
    usage=f"[-o <output_file>] {ModifierUsage.WITH}",
    modifiers=(
        ModifierHelp(
            "-o",
            "The output file to write the generated configuration to. If not specified, the configuration will be printed to stdout.",
        ),
        ModifierHelp(
            Modifiers.WITH,
            "Generate an aerospike.conf file from the specified node. If multiple are selected a random node is used. Acceptable values are ip:port, node-id, or FQDN",
        ),
    ),
)
class GenerateConfigController(LiveClusterCommandController):
    def __init__(self):
        self.required_modifiers = set(["with"])

    async def _do_default(self, line):
        out_file = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-o",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        conf_gen = ASConfigGenerator(
            GetConfigController(self.cluster),
            GetClusterMetadataController(self.cluster),
        )

        try:
            s = await conf_gen.generate(
                self.mods["with"],
            )
        except NotImplementedError as e:
            raise ShellException(e)
        except Exception as e:
            raise

        if out_file:
            with open(out_file, "w") as f:
                f.write(s)
        else:
            self.view.print_result(s + "\n")

        logger.warning(
            "Community Edition is not supported. Generated static configuration does not save logging.syslog, mod-lua, service.user and service.group."
        )
        logger.warning(
            "This feature is currently in beta. Use at your own risk and please report any issue to support."
        )
