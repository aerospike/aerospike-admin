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

from lib.utils import constants, util
from lib.base_controller import (
    DisableAutoComplete,
    BaseController,
    CommandHelp,
    create_disabled_controller,
)
from lib.utils.async_object import AsyncObject

from .live_cluster_command_controller import LiveClusterCommandController
from .client.cluster import Cluster
from .asinfo_controller import ASInfoController
from .collectinfo_controller import CollectinfoController
from .features_controller import FeaturesController
from .health_check_controller import HealthCheckController
from .pager_controller import PagerController
from .info_controller import InfoController
from .show_controller import ShowController
from .summary_controller import SummaryController
from .manage_controller import (
    ManageController,
    ManageLeafCommandController,
)


@CommandHelp("Aerospike Admin")
class LiveClusterRootController(BaseController, AsyncObject):

    cluster = None
    command = None

    async def __init__(
        self,
        seed_nodes=[("127.0.0.1", 3000, None)],
        user=None,
        password=None,
        auth_mode=constants.AuthMode.INTERNAL,
        use_services_alumni=False,
        use_services_alt=False,
        ssl_context=None,
        only_connect_seed=False,
        timeout=5,
        asadm_version="",
    ):

        super().__init__(asadm_version)

        # Create static instance of cluster
        LiveClusterRootController.cluster = await Cluster(
            seed_nodes,
            user,
            password,
            auth_mode,
            use_services_alumni,
            use_services_alt,
            ssl_context,
            only_connect_seed,
            timeout=timeout,
        )

        # Create Basic Command Controller Object
        LiveClusterRootController.command = LiveClusterCommandController(self.cluster)

        self.controller_map = {
            "health": HealthCheckController,
            "summary": SummaryController,
            "features": FeaturesController,
            "pager": PagerController,
            "collectinfo": CollectinfoController,
            "asinfo": create_disabled_controller(ASInfoController, "asinfo"),
            "manage": create_disabled_controller(ManageController, "manage"),
            "show": ShowController,
            "info": InfoController,
        }

    async def close(self):
        try:
            await self.cluster.close()
        except Exception:
            pass

    def _do_default(self, line):
        self.execute_help(line)

    # This function is a hack for autocomplete
    @CommandHelp("Terminate session")
    def do_exit(self, line):
        return "EXIT"

    @CommandHelp(
        "Displays the documentation for the specified command.",
        "For example, to see the documentation for the 'info' command,",
        "use the command 'help info'.",
    )
    def do_help(self, line):
        self.execute_help(line)

    @CommandHelp(
        "Runs a command for a specified pause and iterations.",
        "Usage: watch [pause] [iterations] [--no-diff] command",
        "   pause:      The duration between executions.",
        "               [default: 2 seconds]",
        "   iterations: Number of iterations to execute command.",
        "               [default: until keyboard interrupt]",
        "  Options:",
        "   --no-diff:  Do not highlight differences",
        "Example 1: Show 'info network' 3 times and pause for 1 second each time.",
        "           watch 1 3 info network",
        'Example 2: Show "info namespace" with 5 seconds pause until',
        "           interrupted",
        "           watch 5 info namespace",
    )
    @DisableAutoComplete()
    async def do_watch(self, line):
        await self.view.watch(self, line)

    @DisableAutoComplete()
    @CommandHelp(
        "Enters privileged mode, which allows a you to issue manage",
        "and asinfo commands.",
        "  Options:",
        "    --warn:    Use this option to receive a prompt to confirm",
        "               that you want to run the command.",
    )
    def do_enable(self, line):
        warn = util.check_arg_and_delete_from_mods(
            line=line, arg="--warn", default=False, modifiers={}, mods={}
        )
        ManageLeafCommandController.warn = warn
        self.controller_map.update(
            {"manage": ManageController, "asinfo": ASInfoController}
        )
        return "ENABLE"

    def do_disable(self, line):
        self.controller_map.update(
            {
                "manage": create_disabled_controller(ManageController, "manage"),
                "asinfo": create_disabled_controller(ASInfoController, "asinfo"),
            }
        )
        return "DISABLE"
