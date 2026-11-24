# Copyright 2026 Aerospike, Inc.
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

from lib.base_controller import CommandHelp, ShellException

from .collectinfo_controller import CollectinfoController
from .collectlogs_controller import CollectlogsController
from .collectusage_controller import CollectusageController
from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp(
    "Collects cluster info, logs or usage records to send to Aerospike.",
    "Without a subcommand, runs 'collect info'.",
    short_msg="Collects cluster info, logs or usage records",
    usage=CommandHelp.usage(CollectinfoController),
)
class CollectController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "info": CollectinfoController,
            "logs": CollectlogsController,
            "usage": CollectusageController,
        }

    @CommandHelp("Runs 'collect info'")
    async def _do_default(self, line):
        if line and (
            line[0] in ("-h", "--help")
            or (line[0] != "with" and not line[0].startswith("-"))
        ):
            raise ShellException(
                f"collect: '{line[0]}' is not a valid subcommand. See 'help collect' for available subcommands."
            )

        return await self.controller_map["info"]()(line)
