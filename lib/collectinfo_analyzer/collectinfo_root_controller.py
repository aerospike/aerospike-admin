# Copyright 2013-2021 Aerospike, Inc.
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

from lib.base_controller import BaseController, CommandHelp

from .collectinfo_handler.log_handler import CollectinfoLogHandler
from .collectinfo_command_controller import CollectinfoCommandController
from .features_controller import FeaturesController
from .health_check_controller import HealthCheckController
from .info_controller import InfoController
from .list_controller import ListController
from .page_controller import PagerController
from .show_controller import ShowController
from .summary_controller import SummaryController


@CommandHelp("Aerospike Admin")
class CollectinfoRootController(BaseController):

    log_handler = None
    command = None

    def __init__(self, asadm_version="", clinfo_path=" "):

        super(CollectinfoRootController, self).__init__(asadm_version)

        # Create Static Instance of Loghdlr
        CollectinfoRootController.log_handler = CollectinfoLogHandler(clinfo_path)

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
            "summary": SummaryController,
        }

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
        "Returns documentation related to a command.",
        'for example, to retrieve documentation for the "info"',
        'command use "help info".',
    )
    def do_help(self, line):
        self.execute_help(line)
