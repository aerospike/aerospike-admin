from lib.get_controller import GetFeaturesController
from lib.utils import util
from lib.base_controller import CommandHelp

from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp("Lists the features in use in a running Aerospike cluster.")
class FeaturesController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like"])
        self.getter = GetFeaturesController(self.cluster)

    async def _do_default(self, line):

        features = self.getter.get_features(nodes=self.nodes)

        return util.Future(
            self.view.show_config, "Features", features, self.cluster, **self.mods
        )
