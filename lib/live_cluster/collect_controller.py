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

from lib.base_controller import CommandHelp

from .collectinfo_controller import CollectinfoController
from .collectlogs_controller import CollectlogsController
from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp(
    "Collects cluster info or logs to send to Aerospike Support.",
    "Without a subcommand, runs 'collect info'.",
    short_msg="Collects cluster info or logs",
)
class CollectController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "info": CollectinfoController,
            "logs": CollectlogsController,
        }

    @CommandHelp("Runs 'collect info'")
    async def _do_default(self, line):
        return await self.controller_map["info"]()(line)
