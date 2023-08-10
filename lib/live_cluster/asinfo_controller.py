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
import logging
from lib.utils import constants
from lib.base_controller import CommandHelp, ModifierHelp, ShellException

from .live_cluster_command_controller import LiveClusterCommandController

logger = logging.getLogger(__name__)


@CommandHelp(
    "Provides raw access to the info protocol.",
    usage=f"[-v <command>] [-l] [--no_node_name] [{constants.Modifiers.LIKE} <field-substring>] [{constants.ModifierUsage.WITH}]",
    modifiers=(
        ModifierHelp(
            "-v",
            'The command to execute, e.g. "get-stats:context=xdr;dc=dataCenterName"',
        ),
        ModifierHelp(
            "-l",
            'Replace semicolons ";" with newlines. If output does not contain semicolons "-l" will attempt to use colons ":" followed by commas ",".',
        ),
        ModifierHelp(
            "--no_node_name", "Force to display output without printing node names."
        ),
        ModifierHelp(
            constants.Modifiers.LIKE, "Filter returned fields by substring match"
        ),
        ModifierHelp(constants.Modifiers.WITH, constants.ModifierHelp.WITH),
    ),
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
            logger.warning("Do not understand '%s' in '%s'" % (word, " ".join(line)))
            return
        if value is not None:
            value = value.translate(str.maketrans("", "", "'\""))

        results = await self.cluster.info(value, nodes=nodes)

        return self.view.asinfo(results, line_sep, show_node_name, self.cluster, **mods)
