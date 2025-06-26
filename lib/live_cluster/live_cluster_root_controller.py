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

import asyncio
from io import StringIO
import sys

from OpenSSL import SSL
from lib.live_cluster.collectlogs_controller import CollectlogsController

from lib.utils import constants, util
from lib.base_controller import (
    DisableAutoComplete,
    BaseController,
    CommandHelp,
    ModifierHelp,
    ShellException,
    create_disabled_controller,
)
from lib.utils.async_object import AsyncObject
from .live_cluster_command_controller import LiveClusterCommandController
from .client import Cluster, Addr_Port_TLSName
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


@CommandHelp("A tool for interacting with your Aerospike cluster")
class LiveClusterRootController(BaseController, AsyncObject):
    cluster: Cluster

    async def __init__(
        self,
        seed_nodes: list[Addr_Port_TLSName] = [("127.0.0.1", 3000, None)],
        user=None,
        password=None,
        auth_mode=constants.AuthMode.INTERNAL,
        use_services_alumni=False,
        use_services_alt=False,
        ssl_context: SSL.Context | None = None,
        only_connect_seed=False,
        timeout=5,
        asadm_version="",
        user_agent="1,asadm-development,unknown",
    ):
        BaseController.asadm_version = asadm_version

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
            user_agent=user_agent,
        )  # type: ignore linter does not understand AsyncObject

        # Create Basic Command Controller Object
        LiveClusterCommandController.cluster = self.cluster

        self.controller_map = {
            "health": HealthCheckController,
            "summary": SummaryController,
            "features": FeaturesController,
            "pager": PagerController,
            "collectinfo": CollectinfoController,
            "collectlogs": CollectlogsController,
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

    # This function is a hack for autocomplete
    @CommandHelp("Terminate session")
    def do_exit(self, line):
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

    @CommandHelp(
        "Runs a command for a specified pause and iterations.",
        short_msg="Runs a command for a specified pause and iterations",
        usage="[--no-diff] [pause [iterations]] <command>",
        modifiers=(
            ModifierHelp(
                "pause", "The duration between executions", default="2 seconds"
            ),
            ModifierHelp(
                "iterations",
                "Number of iterations to execute command",
                default="until keyboard interrupt",
            ),
            ModifierHelp("command", "The command to execute e.g. 'info network'"),
            ModifierHelp("--no-diff", "Do not highlight differences"),
        ),
    )
    async def do_watch(self, line):
        sleep = 2.0
        num_iterations = 0

        try:
            sleep = float(line[0])
            line.pop(0)
        except Exception:
            pass
        else:
            try:
                num_iterations = int(line[0])
                line.pop(0)
            except Exception:
                pass

        diff_highlight = not util.check_arg_and_delete_from_mods(
            line, "--no-diff", False, self.modifiers, self.mods
        )

        if not line:
            raise ShellException("Watch requires a single command argument")

        real_stdout = sys.stdout
        try:
            sys.stdout = mystdout = StringIO()

            previous = None
            count = 1

            while True:
                await self.execute(line[:])
                output = mystdout.getvalue()
                mystdout.truncate(0)
                mystdout.seek(0)

                previous = await self.view.watch(
                    real_stdout, output, line, sleep, count, previous, diff_highlight
                )

                if num_iterations != 0 and num_iterations <= count:
                    break

                count += 1
                await asyncio.sleep(sleep)

        except asyncio.CancelledError:
            return
        finally:
            sys.stdout = real_stdout
            print("")

    @DisableAutoComplete()
    @CommandHelp(
        "Enters privileged mode, which allows a you to issue manage",
        "and asinfo commands.",
        "  Options:",
        "    --warn:    Use this option to receive a prompt to confirm",
        "               that you want to run the command.",
        short_msg="Enters privileged mode",
        usage="[--warn]",
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

    @CommandHelp(
        "Exits privileged mode, which protects you from issuing manage and asinfo commands.",
        short_msg="Exits privileged mode",
    )
    def do_disable(self, line):
        self.controller_map.update(
            {
                "manage": create_disabled_controller(ManageController, "manage"),
                "asinfo": create_disabled_controller(ASInfoController, "asinfo"),
            }
        )
        return "DISABLE"
