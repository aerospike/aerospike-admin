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
from lib.utils import util
from lib.base_controller import CommandHelp, ShellException

from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp(
    '"asinfo" provides raw access to the info protocol.',
    "  Options:",
    "    -v <command>   - The command to execute",
    '    -l             - Replace semicolons ";" with newlines. If output does',
    '                     not contain semicolons "-l" will attempt to use',
    '                     colons ":" followed by commas ",".',
    "    --no_node_name - Force to display output without printing node names.",
)
class ASInfoController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like"])

    @CommandHelp("Executes an info command.")
    async def _do_default(self, line):
        mods = self.parse_modifiers(line)
        line = mods["line"]
        nodes = self.nodes

        value = None
        line_sep = False
        show_node_name = True

        tline = line[:]

        try:
            while tline:
                word = tline.pop(0)
                if word == "-v":
                    value = tline.pop(0)
                elif word == "-l":
                    line_sep = True
                elif word == "--no_node_name":
                    show_node_name = False
                else:
                    raise ShellException(
                        "Do not understand '%s' in '%s'" % (word, " ".join(line))
                    )
        except Exception:
            self.logger.warning(
                "Do not understand '%s' in '%s'" % (word, " ".join(line))
            )
            return
        if value is not None:
            value = value.translate(str.maketrans("", "", "'\""))

        results = await self.cluster.info(value, nodes=nodes)

        return self.view.asinfo(results, line_sep, show_node_name, self.cluster, **mods)
