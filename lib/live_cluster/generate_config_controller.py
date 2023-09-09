from lib.base_controller import CommandHelp, ModifierHelp
from lib.live_cluster.get_controller import (
    GetClusterMetadataController,
    GetConfigController,
)
from lib.live_cluster.live_cluster_command_controller import (
    LiveClusterCommandController,
)
from lib.utils.conf_gen import ASConfigGenerator


@CommandHelp(
    "Provides raw access to the info protocol.",
    usage="[-v <command>] [-l] [--no_node_name]",
    modifiers=(
        ModifierHelp(
            "-v",
            "TODO",
        ),
    ),
)
class ConfGenController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with"])

    async def _do_default(self, line):
        conf_gen = ASConfigGenerator(
            GetConfigController(self.cluster),
            GetClusterMetadataController(self.cluster),
        )
        s = await conf_gen.generate()
        print(s)
