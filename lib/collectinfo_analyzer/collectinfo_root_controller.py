# Copyright 2013-2025 Aerospike, Inc.
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

from lib.base_controller import (
    BaseController,
    CommandHelp,
    ShellException,
    create_deprecated_controller,
)

from .collectinfo_handler.log_handler import CollectinfoLogHandler, LogHandlerException
from .collectinfo_command_controller import CollectinfoCommandController
from .features_controller import FeaturesController
from .health_check_controller import HealthCheckController
from .info_controller import InfoController
from .list_controller import ListController
from .page_controller import PagerController
from .show_controller import ShowController
from .summary_controller import SummaryController

logger = logging.getLogger(__name__)


@CommandHelp("Aerospike Admin")
class CollectinfoRootController(BaseController):
    log_handler = None
    command = None

    def __init__(self, asadm_version="", clinfo_path="", asadm_build=""):
        """Build the analyzer's controller tree for one bundle.

        The version and build are stored on BaseController, so constructing this
        overwrites them for every controller in the process, the live session's
        included. Callers that build one mid-session (collectinfo, which analyzes
        the bundle it just wrote) save and restore them around this.
        """
        BaseController.asadm_version = asadm_version
        BaseController.asadm_build = asadm_build

        # Create Static Instance of Loghdlr
        try:
            CollectinfoRootController.log_handler = CollectinfoLogHandler(
                clinfo_path, asadm_version=asadm_version
            )
        except LogHandlerException as e:
            raise ShellException(e)

        CollectinfoRootController.command = CollectinfoCommandController(
            self.log_handler
        )

        self.controller_map = {
            "list": ListController,
            "show": ShowController,
            "info": InfoController,
            "features": FeaturesController,
            "pager": PagerController,
            "health": HealthCheckController,
            "summary": create_deprecated_controller(
                SummaryController, "summary", "info summary"
            ),
        }

    async def execute(self, line):
        if self.log_handler.all_cinfo_logs or self._runs_on_a_usage_archive(line):
            return await super().execute(line)

        logger.warning(
            "%s: no collectinfo data in this usage archive. Run 'show usage'.",
            " ".join(line),
        )

    def _runs_on_a_usage_archive(self, line):
        self._init()
        command = self._resolve(self, line[0]) if line else None

        if command in ("help", "pager", "exit"):
            return True

        if command != "show" or len(line) < 2:
            return False

        show = self.commands.get_exact("show")
        show._init()

        return self._resolve(show, line[1]) == "usage"

    @staticmethod
    def _resolve(controller, word):
        word = controller.aliases.get(word, word)

        if word in controller.commands.keys():
            return word

        try:
            keys = controller.commands.get_key(word)
        except KeyError:
            return None

        return keys[0] if len(keys) == 1 else None

    def close(self):
        try:
            self.log_handler.close()
        except Exception:
            pass

    @CommandHelp("Terminate session")
    def do_exit(self, line):
        # This function is a hack for autocomplete
        return "EXIT"

    @CommandHelp(
        "Displays the documentation for the specified command.",
        "For example, to see the documentation for the 'info' command,",
        "use the command 'help info'.",
        short_msg="Displays the documentation for the specified command",
        hide=True,
    )
    def do_help(self, line):
        self.view.print_result(self.execute_help(line))
