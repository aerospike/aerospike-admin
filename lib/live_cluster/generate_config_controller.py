import logging
from build.tmp.lib.utils.constants import ModifierHelpText
from lib.base_controller import CommandHelp, ModifierHelp
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


@CommandHelp(
    "Generates a static configuration file from a live node.",
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
class ConfGenController(LiveClusterCommandController):
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
        s = await conf_gen.generate()

        if out_file:
            with open(out_file, "w") as f:
                f.write(s)
        else:
            self.view.print_result(s + "\n")

        self.logger.warning(
            "Generated static configuration does not currently take into account logging.syslog and mod-lua contexts."
        )
