# Copyright 2021-2023 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from lib.live_cluster.get_controller import GetFeaturesController
from lib.utils import constants
from lib.base_controller import CommandHelp, ModifierHelp

from .live_cluster_command_controller import LiveClusterCommandController

with_modifier_help = ModifierHelp(constants.Modifiers.WITH, constants.ModifierHelp.WITH)


@CommandHelp(
    "Lists the features in use in a running Aerospike cluster.",
    usage=f"[{constants.Modifiers.LIKE} <feature-substring>] [{constants.ModifierUsage.WITH}]",
    modifiers=(
        ModifierHelp(constants.Modifiers.LIKE, "Filter features by substring match"),
        with_modifier_help,
    ),
)
class FeaturesController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like"])
        self.getter = GetFeaturesController(self.cluster)

    async def _do_default(self, line):
        features = await self.getter.get_features(nodes=self.nodes)
        self.view.show_config("Features", features, self.cluster, **self.mods)
