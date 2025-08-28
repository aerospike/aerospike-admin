# Copyright 2021-2025 Aerospike, Inc.
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

import unittest
from pytest import PytestUnraisableExceptionWarning
from lib.base_controller import (
    BaseController,
    CommandController,
    CommandHelp,
    ModifierHelp,
    ShellException,
)
from mock import MagicMock, create_autospec, patch
from mock.mock import AsyncMock, call
from parameterized import parameterized

from lib.live_cluster.client import (
    ASINFO_RESPONSE_OK,
    ASInfoClusterStableError,
    ASInfoResponseError,
    ASProtocolError,
    ASResponse,
    Cluster,
)
from lib.live_cluster.client.config_handler import JsonDynamicConfigHandler
from lib.live_cluster.client.ctx import ASValues, CDTContext, CTXItems
from lib.live_cluster.client.node import Node
from lib.live_cluster.get_controller import GetClusterMetadataController
from lib.live_cluster.live_cluster_command_controller import (
    LiveClusterCommandController,
)
from lib.live_cluster.manage_controller import (
    LiveClusterManageCommandController,
    ManageACLCreateRoleController,
    ManageACLCreateUserController,
    ManageACLQuotasRoleController,
    ManageConfigController,
    ManageConfigLeafController,
    ManageJobsKillAllScansController,
    ManageJobsKillAllQueriesController,
    ManageJobsKillTridController,
    ManageQuiesceController,
    ManageReclusterController,
    ManageReviveController,
    ManageRosterAddController,
    ManageRosterLeafCommandController,
    ManageRosterRemoveController,
    ManageRosterStageNodesController,
    ManageRosterStageObservedController,
    ManageSIndexCreateController,
    ManageSIndexDeleteController,
    ManageTruncateController,
)
from lib.utils import constants
from test.unit import util as test_util

import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import asynctest


@CommandHelp(
    "I am ROOT!!!",
)
class FakeRoot(BaseController):
    def __init__(self):
        self.modifiers = set()

        self.controller_map = {"fakea1": FakeCommand1, "fakeb2": FakeCommand2}


@CommandHelp(
    "Fake Command 1 Help",
    short_msg="Fake Command 1 Help.",
    usage="<default usage>",
)
class FakeCommand1(LiveClusterManageCommandController):
    def __init__(self):
        pass

    @CommandHelp(
        "Fake Command 1 Default",
    )
    async def _do_default(self, line):
        return await self.do_cmd(line[:])

    @CommandHelp(
        "Fake Command 1 cmd but is hidden so should not be in the list",
        hide=True,
    )
    async def do_cmd(self, line):
        return "fake1", line


@CommandHelp(
    "Fake Command 2 Help. Here is a really long line that should wrap around. Let's check if it does. We need to make sure it is long enough",
    short_msg="Fake Command 2 Help.",
    usage="<default usage>",
)
class FakeCommand2(LiveClusterManageCommandController):
    def __init__(self):
        self.controller_arg = "arg2"

    @CommandHelp("Fake Command 2 Default")
    async def _do_default(self, line):
        return await self.do_cmd(line[:])

    @CommandHelp(
        "cmd help",
    )
    async def do_cmd(self, line):
        return "fake2", line

    @CommandHelp(
        "foo help",
        usage="<foo usage>",
        modifiers=(
            ModifierHelp("one", "all about one", default="1"),
            ModifierHelp("two", "all about two", default="2"),
        ),
    )
    async def do_foo(self, line):
        return "foo", line

    async def do_for(self, line):
        return "for", line

    async def do_zoo(self, line):
        return "zoo", line


class BaseControllerTest(asynctest.TestCase):
    maxDiff = None

    @parameterized.expand(
        [
            (
                [],
                """
I am ROOT!!!.

Usage:   COMMAND

Commands:

    Default     Print this help message
    fakea1      Fake Command 1 Help
    fakeb2      Fake Command 2 Help

Run 'help COMMAND' for more information on a command.
""",
            ),
            (["fake"], "ShellException"),
            (
                ["fakea1"],
                """
Fake Command 1 Help.

Usage:  fakea1 COMMAND
or
Usage:  fakea1 <default usage>

Commands:

    Default     Fake Command 1 Default

Run 'help fakea1 COMMAND' for more information on a command.
""",
            ),
            (
                ["fakeb2"],
                """
Fake Command 2 Help. Here is a really long line that should wrap around. Let's
check if it does. We need to make sure it is long enough.

Usage:  fakeb2 <arg2> COMMAND
or
Usage:  fakeb2 <arg2> <default usage>

Commands:

    Default     Fake Command 2 Default
    cmd         cmd help
    foo         foo help

Run 'help fakeb2 COMMAND' for more information on a command.
""",
            ),
            (
                ["fakeb2", "foo"],
                """
foo help.

Usage:  fakeb2 <arg2> foo <foo usage>

        one     - all about one
                  Default: 1
        two     - all about two
                  Default: 2
""",
            ),
        ]
    )
    def test_execute_help(self, line, expected_result):
        r = FakeRoot()

        try:
            actual_result = r.execute_help(line)
            print(actual_result)
        except ShellException:
            self.assertEqual(expected_result, "ShellException")
        else:
            self.assertListEqual(expected_result.split("\n"), actual_result.split("\n"))


@asynctest.fail_on(active_handles=True)
class ManageACLCreateUserControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLCreateUserController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageACLCreateUserController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

        self.addCleanup(patch.stopall)

    async def test_no_roles_and_no_password(self):
        getpass_mock = patch("lib.live_cluster.manage_controller.getpass").start()
        getpass_mock.return_value = "pass"
        self.cluster_mock.admin_create_user.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(["test-user"])

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", [], nodes="principal"
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created user test-user."
        )

    async def test_with_roles_and_password(self):
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(
            ["test-user", "password", "pass", "roles", "role1", "role2", "role3"]
        )

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", ["role1", "role2", "role3"], nodes="principal"
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created user test-user."
        )

    async def test_with_role_and_password(self):
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(
            ["test-user", "password", "pass", "role", "role1", "role2", "role3"]
        )

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", ["role1", "role2", "role3"], nodes="principal"
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created user test-user."
        )

    async def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASProtocolError(ASResponse.USER_ALREADY_EXISTS, "test-message")
        line = "test-user password pass"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {"principal_ip": as_error}

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", [], nodes="principal"
        )
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    async def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "test-user password pass"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {"principal_ip": as_error}

        await test_util.assert_exception_async(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", [], nodes="principal"
        )
        self.view_mock.print_result.assert_not_called()


@asynctest.fail_on(active_handles=True)
class ManageACLCreateRoleControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLCreateRoleController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageACLCreateRoleController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}

        self.addCleanup(patch.stopall)

    async def test_logs_error_when_server_does_not_support_quotas(self):
        log_message = (
            "'read' and 'write' quotas are only supported on server v. 5.6 and later."
        )
        line = "test-role priv test-priv read 100 write 200"
        self.cluster_mock.info_build.side_effect = [
            {"principal": "5.5.0.0"},
            {"principal": "5.5.9.9"},
        ]
        self.cluster_mock.admin_create_role.side_effect = [
            {"principal_ip": ASResponse.OK}
        ] * 2

        for _ in range(2):
            await self.controller.execute(line.split())
            self.logger_mock.warning.assert_called_with(log_message)

    async def test_with_only_privilege(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_privilege_with_namespace(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_privilege_and_namespace_and_set(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns set test-set"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns.test-set"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_privilege_and_set_logs_error(self):
        self.controller.execute_help = MagicMock()
        line = "test-role priv test-priv set test-set"

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_with(
            "A set must be accompanied by a namespace."
        )

    async def test_with_privilege_and_allowlist(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns set test-set allow 3.3.3.3 4.4.4.4"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns.test-set"],
            whitelist=["3.3.3.3", "4.4.4.4"],
            read_quota=None,
            write_quota=None,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_privilege_and_read_and_write_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns set test-set read 111 write 222"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns.test-set"],
            whitelist=[],
            read_quota=111,
            write_quota=222,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_privilege_and_allowlist_and_read_and_write_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns set test-set allow 3.3.3.3 4.4.4.4 read 111 write 222"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns.test-set"],
            whitelist=["3.3.3.3", "4.4.4.4"],
            read_quota=111,
            write_quota=222,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_read_privilege_only(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }

        line = "test-role priv read"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["read"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_write_privilege_only(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }

        line = "test-role priv write"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["write"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_conflicting_write_privilege_and_write_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv write write 111"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["write"],
            whitelist=[],
            read_quota=None,
            write_quota=111,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_conflicting_read_privilege_and_read_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv read read 111"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["read"],
            whitelist=[],
            read_quota=111,
            write_quota=None,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_with_conflicting_read_privilege_and_write_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv read write 111"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["read"],
            whitelist=[],
            read_quota=None,
            write_quota=111,
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    async def test_logs_error_when_quotas_are_not_int(self):
        log_message = "Quotas must be integers."
        line = "test-role priv write write 100a read 100"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_not_called()
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

        line = "test-role priv write write 100 read 100a"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_not_called()
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

    async def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASProtocolError(ASResponse.ROLE_ALREADY_EXISTS, "test-message")
        line = "test-role priv sys-admin"
        self.cluster_mock.admin_create_role.return_value = {"principal_ip": as_error}

        await self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["sys-admin"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes="principal",
        )
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    async def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "test-role priv sys-admin"
        self.cluster_mock.admin_create_role.return_value = {"principal_ip": as_error}

        await test_util.assert_exception_async(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["sys-admin"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes="principal",
        )
        self.view_mock.print_result.assert_not_called()


@asynctest.fail_on(active_handles=True)
class ManageACLQuotasControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLQuotasRoleController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageACLQuotasRoleController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}

        self.addCleanup(patch.stopall)

    async def test_logs_error_when_server_does_not_support_quotas(self):
        log_message = "'manage quotas' is not supported on aerospike versions <= 5.5"
        line = "role test-role read 100 write 200"
        self.cluster_mock.info_build.side_effect = [
            {"principal": "5.5.0.0"},
            {"principal": "5.5.9.9"},
        ]
        self.cluster_mock.admin_set_quotas.side_effect = [
            {"principal_ip": ASResponse.OK}
        ] * 2

        for _ in range(2):
            await self.controller.execute(line.split())
            self.logger_mock.error.assert_called_with(log_message)

    async def test_logs_error_with_read_and_write_not_provided(self):
        log_message = "'read' or 'write' is required."

        await self.controller.execute(["role", "test-role"])

        self.logger_mock.error.assert_called_with(log_message)

    async def test_success_with_read_and_write(self):
        log_message = "Successfully set quotas for role test-role."
        line = "role test-role read 100 write 200"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=200, nodes="principal"
        )
        self.view_mock.print_result.assert_called_with(log_message)

    async def test_success_with_just_read(self):
        log_message = "Successfully set quota for role test-role."
        line = "role test-role read 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=None, nodes="principal"
        )
        self.view_mock.print_result.assert_called_with(log_message)

    async def test_success_with_just_write(self):
        log_message = "Successfully set quota for role test-role."
        line = "role test-role write 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=None, write_quota=100, nodes="principal"
        )
        self.view_mock.print_result.assert_called_with(log_message)

    async def test_correct_call_with_conflicting_read_role_and_read_quota(self):
        line = "role read read 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "read", read_quota=100, write_quota=None, nodes="principal"
        )

    async def test_correct_call_with_conflicting_write_role_and_write_quota(self):
        line = "role write write 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "write", read_quota=None, write_quota=100, nodes="principal"
        )

    async def test_correct_call_with_conflicting_write_role_and_read_quota(self):
        line = "role write read 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "write", read_quota=100, write_quota=None, nodes="principal"
        )

    async def test_logs_error_when_quotas_are_not_int(self):
        log_message = "Quotas must be integers."
        line = "role test-role write 100a read 100"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_not_called()
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

        line = "role test-role write 100 read 100a"

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_not_called()
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

    async def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASProtocolError(ASResponse.RATE_QUOTA_EXCEEDED, "test-message")
        line = "role test-role write 100 read 100"
        self.cluster_mock.admin_set_quotas.return_value = {"principal_ip": as_error}

        await self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=100, nodes="principal"
        )
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    async def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "role test-role write 100 read 100"
        self.cluster_mock.admin_set_quotas.return_value = {"principal_ip": as_error}

        await test_util.assert_exception_async(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=100, nodes="principal"
        )
        self.view_mock.print_result.assert_not_called()


@asynctest.fail_on(active_handles=True)
class ManageConfigControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageConfigLeafController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageConfigController()
        ManageConfigLeafController.mods = {}
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageConfigLeafController.prompt_challenge"
        ).start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def _get_controller_mods(
        self, controller: BaseController, cmds: list[str]
    ) -> dict[str, str]:
        if len(cmds) == 0:
            return controller.mods

        cmd = cmds.pop(0)
        return self._get_controller_mods(controller._find_method([cmd]), cmds)

    async def test_logging_prompt(self):
        line = (
            "logging file test-file param test-param to test-value with 1.1.1.1 2.2.2.2"
        )
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change logging context test-param to test-value for file test-file"
        )
        self.cluster_mock.info_set_config_logging.assert_not_called()

    async def test_logging_success(self):
        line = (
            "logging file test-file param test-param to test-value with 1.1.1.1 2.2.2.2"
        )
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_logging.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_logging.assert_called_once_with(
            "test-file", "test-param", "test-value", nodes=["1.1.1.1", "2.2.2.2"]
        )
        title = "Set Logging Context test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["logging"]),
        )

    async def test_service_prompt(self):
        line = "service param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change service param test-param to test-value"
        )
        self.cluster_mock.info_set_config_service.assert_not_called()

    async def test_service_success(self):
        line = "service param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_service.return_value = resp
        mods = {
            "with": ["1.1.1.1", "2.2.2.2"],
            "param": [],
            "to": [],
            "line": [],
        }

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_service.assert_called_once_with(
            "test-param", "test-value", nodes=["1.1.1.1", "2.2.2.2"]
        )
        title = "Set Service Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **mods
        )

    async def test_network_subcontext_required(self):
        line = "network param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with("Subcontext required.")
        self.cluster_mock.info_set_config_network.assert_not_called()

    async def test_network_prompt(self):
        line = "network sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change network sub-context param test-param to test-value"
        )
        self.cluster_mock.info_set_config_network.assert_not_called()

    async def test_network_success(self):
        line = "network sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_network.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_network.assert_called_once_with(
            "test-param", "test-value", "sub-context", nodes=["1.1.1.1", "2.2.2.2"]
        )
        title = "Set Network Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["network"]),
        )

    async def test_security_prompt_with_subcontext(self):
        line = (
            "security sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        )
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change security sub-context param test-param to test-value"
        )
        self.cluster_mock.info_set_config_security.assert_not_called()

    async def test_security_prompt(self):
        line = "security param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change security param test-param to test-value"
        )
        self.cluster_mock.info_set_config_security.assert_not_called()

    async def test_security_success(self):
        line = (
            "security sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        )
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_security.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_security.assert_called_once_with(
            "test-param", "test-value", "sub-context", nodes=["1.1.1.1", "2.2.2.2"]
        )
        title = "Set Security Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["security"]),
        )

    async def test_namespace_prompt_with_subcontext(self):
        line = "namespace test-ns sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change namespace test-ns sub-context param test-param to test-value"
        )
        self.cluster_mock.info_set_config_namespace.assert_not_called()

    async def test_namespace_prompt(self):
        line = "namespace test-ns param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change namespace test-ns param test-param to test-value"
        )
        self.cluster_mock.info_set_config_namespace.assert_not_called()

    async def test_namespace_success(self):
        line = "namespace test-ns sub-context param rack-id to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_namespace.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_namespace.assert_called_once_with(
            "rack-id",
            "test-value",
            "test-ns",
            subcontext="sub-context",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set Namespace Param rack-id to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["namespace"]),
        )
        self.view_mock.print_result.assert_called_once_with(
            'Run "manage recluster" for your changes to rack-id to take affect.'
        )

    async def test_namespace_success_with_pair(self):
        line = "namespace test-ns sub-context param compression-level to test-value with 1.1.1.1 2.2.2.2"

        await self.controller.execute(line.split())

    async def test_set_prompt(self):
        line = "namespace test-ns set test-set param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change namespace test-ns set test-set param test-param to test-value"
        )
        self.cluster_mock.info_set_config_namespace.assert_not_called()

    async def test_set_success(self):
        line = "namespace test-ns set test-set param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_namespace.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_namespace.assert_called_once_with(
            "test-param",
            "test-value",
            "test-ns",
            set_="test-set",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set Namespace Set Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["namespace", "set"]),
        )

    async def test_XDR_prompt(self):
        line = "xdr param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change XDR param test-param to test-value"
        )
        self.cluster_mock.info_set_config_xdr.assert_not_called()

    async def test_XDR_success(self):
        line = "xdr param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr.assert_called_once_with(
            "test-param",
            "test-value",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set XDR Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["xdr"]),
        )

    async def test_XDR_create_dc_prompt(self):
        line = "xdr create dc test-dc with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Create XDR DC test-dc")
        self.cluster_mock.info_set_config_xdr_create_dc.assert_not_called()

    async def test_XDR_create_dc_success(self):
        line = "xdr create dc test-dc with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_create_dc.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_create_dc.assert_called_once_with(
            "test-dc",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Create XDR DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["xdr", "create"]),
        )

    async def test_XDR_delete_dc_prompt(self):
        line = "xdr delete dc test-dc with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Delete XDR DC test-dc")
        self.cluster_mock.info_set_config_xdr_delete_dc.assert_not_called()

    async def test_XDR_delete_dc_success(self):
        line = "xdr delete dc test-dc with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_delete_dc.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_delete_dc.assert_called_once_with(
            "test-dc",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Delete XDR DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["xdr", "delete"]),
        )

    async def test_XDR_dc_prompt(self):
        line = "xdr dc test-dc param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change XDR DC test-dc param test-param to test-value"
        )
        self.cluster_mock.info_set_config_xdr.assert_not_called()

    async def test_XDR_dc_success(self):
        line = "xdr dc test-dc param auth-user to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr.assert_called_once_with(
            "auth-user",
            "test-value",
            dc="test-dc",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set XDR DC Param auth-user to test-value"
        self.view_mock.print_info_responses(
            title, resp, self.cluster_mock, **self.controller.mods
        )

    async def test_XDR_dc_add_node_prompt(self):
        line = "xdr dc test-dc add node 3.3.3.3 with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Add node 3.3.3.3 to DC test-dc")
        self.cluster_mock.info_set_config_xdr_add_node.assert_not_called()

    async def test_XDR_dc_add_node_success(self):
        line = "xdr dc test-dc add node 3.3.3.3 with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_add_node.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_add_node.assert_called_once_with(
            "test-dc",
            "3.3.3.3",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Add XDR Node 3.3.3.3 to DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["xdr", "dc", "add", "node"]),
        )

    async def test_XDR_dc_remove_node_prompt(self):
        line = "xdr dc test-dc remove node 3.3.3.3 with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Remove node 3.3.3.3 from DC test-dc")
        self.cluster_mock.info_set_config_xdr_remove_node.assert_not_called()

    async def test_XDR_dc_remove_node_success(self):
        line = "xdr dc test-dc remove node 3.3.3.3 with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_remove_node.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_remove_node.assert_called_once_with(
            "test-dc",
            "3.3.3.3",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Remove XDR Node 3.3.3.3 from DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(
                self.controller, ["xdr", "dc", "remove", "node"]
            ),
        )

    async def test_XDR_dc_add_namespace_prompt(self):
        line = "xdr dc test-dc add namespace test-env with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Add namespace test-env to DC test-dc")
        self.cluster_mock.info_set_config_xdr_add_namespace.assert_not_called()

    async def test_XDR_dc_add_namespace_with_rewind_prompt(self):
        line = "xdr dc test-dc add namespace test-env rewind all with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Add namespace test-env to DC test-dc with rewind all"
        )
        self.cluster_mock.info_set_config_xdr_add_namespace.assert_not_called()

    async def test_XDR_dc_add_namespace_success(self):
        line = "xdr dc test-dc add namespace test-ns with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_add_namespace.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_add_namespace.assert_called_once_with(
            "test-dc",
            "test-ns",
            None,
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Add XDR Namespace test-ns to DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(
                self.controller, ["xdr", "dc", "add", "namespace"]
            ),
        )

    async def test_XDR_dc_remove_namespace_prompt(self):
        line = "xdr dc test-dc remove namespace test-ns with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Remove namespace test-ns from DC test-dc"
        )
        self.cluster_mock.info_set_config_xdr_remove_namespace.assert_not_called()

    async def test_XDR_dc_remove_namespace_success(self):
        line = "xdr dc test-dc remove namespace test-ns with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_remove_namespace.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_remove_namespace.assert_called_once_with(
            "test-dc",
            "test-ns",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Remove XDR Namespace test-ns from DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(
                self.controller, ["xdr", "dc", "remove", "namespace"]
            ),
        )

    async def test_XDR_dc_namespace_prompt(self):
        line = "xdr dc test-dc namespace test-ns param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change XDR DC test-dc namespace test-ns param test-param to test-value"
        )
        self.cluster_mock.info_set_config_xdr.assert_not_called()

    async def test_XDR_dc_namespace_success(self):
        line = "xdr dc test-dc namespace test-ns param compression-level to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr.return_value = resp

        await self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr.assert_called_once_with(
            "compression-level",
            "test-value",
            dc="test-dc",
            namespace="test-ns",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set XDR Namespace Param compression-level to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title,
            resp,
            self.cluster_mock,
            **self._get_controller_mods(self.controller, ["xdr", "dc", "namespace"]),
        )


@asynctest.fail_on(active_handles=True)
class ManageConfigAutoCompleteTest(asynctest.TestCase):
    async def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster = await Cluster([("1.1.1.1", 3000, None)], timeout=0)
        self.root_controller = LiveClusterCommandController(self.cluster)
        self.node = list(self.cluster.nodes.values())[0]
        self.node.conf_schema_handler = JsonDynamicConfigHandler(
            constants.CONFIG_SCHEMAS_HOME, "5.6.0"
        )
        self.node.alive = True
        self.cluster.update_node(self.node)
        self.controller = ManageConfigController()
        self.controller._context = ["manage", "config"]
        ManageConfigLeafController.mods = {}
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageConfigLeafController.prompt_challenge"
        ).start()

        self.addCleanup(patch.stopall)

    @parameterized.expand(
        [
            ("net", ["network"]),
            ("network", ["network"]),
            ("network ", ["fabric", "heartbeat"]),
            ("network fab", ["fabric"]),
            ("network fabric", []),
            ("network fabric ", []),
            (
                "network fabric param",
                [
                    "param",
                ],
            ),
            (
                "network fabric param ",
                [
                    "channel-bulk-recv-threads",
                    "channel-ctrl-recv-threads",
                    "channel-meta-recv-threads",
                    "channel-rw-recv-threads",
                    "recv-rearm-threshold",
                ],
            ),
            (
                "network heartbeat param ",
                ["connect-timeout-ms", "interval", "mtu", "protocol", "timeout"],
            ),
            (
                "network heartbeat param protocol",
                ["protocol to"],
            ),
            (
                "network heartbeat param protocol ",
                ["to"],
            ),
            (
                "network heartbeat param protocol to",
                ["to"],
            ),
            (
                "network heartbeat param protocol to none",
                [],
            ),
            (
                "namespace",
                ["namespace"],
            ),
            (
                "namespace ",
                ["<ns>"],
            ),
            (
                "namespace test",
                [],
            ),
            (
                "namespace test ",
                ["geo2dsphere-within", "index-type", "set", "storage-engine"],
            ),
            (
                "namespace test set ",
                ["<set>"],
            ),
            (
                "namespace test storage-engine param co",
                ["compression", "compression-level"],
            ),
            (
                "namespace test storage-engine param compression",
                ["compression", "compression-level"],
            ),
            (
                "namespace test storage-engine param compression ",
                ["to"],
            ),
            (
                "namespace test storage-engine param compression-level to ",
                ["<int>"],
            ),
            (
                "namespace test storage-engine param compression-level to <int>",
                [],
            ),
            (
                "namespace test storage-engine param compression-level to <int> ",
                [],
            ),
        ]
    )
    def test_auto_complete(self, line, possible_completions):
        actual = self.controller.complete(line.split(" "))
        self.assertCountEqual(
            possible_completions,
            actual,
            'Failed with input: "{}"'.format(line),
        )


class ManageSIndexCreateStrToCTXTest(unittest.TestCase):
    def test_str_to_cdt_ctx_with_list_index(self):
        line = "list_index(3)"
        expected = CDTContext([CTXItems.ListIndex(3)])

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_list_rank(self):
        line = "list_rank(2)"
        expected = CDTContext([CTXItems.ListRank(2)])

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_list_str_value(self):
        line = "list_value(str)"
        expected = CDTContext([CTXItems.ListValue(ASValues.ASString("str"))])

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_map_index(self):
        line = "map_index(3)"
        expected = CDTContext([CTXItems.MapIndex(3)])

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_map_rank(self):
        line = "map_rank(2)"
        expected = CDTContext([CTXItems.MapRank(2)])

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_map_str_key(self):
        line = "map_key(str)"
        expected = CDTContext([CTXItems.MapKey(ASValues.ASString("str"))])

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_map_str_value(self):
        line = "map_value(str)"
        expected = CDTContext([CTXItems.MapValue(ASValues.ASString("str"))])

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_multiple_items(self):
        line = "list_index(3) list_rank(2) list_value(str) map_index(3) map_rank(2) map_key(str) map_value('str')"
        expected = CDTContext(
            [
                CTXItems.ListIndex(3),
                CTXItems.ListRank(2),
                CTXItems.ListValue(ASValues.ASString("str")),
                CTXItems.MapIndex(3),
                CTXItems.MapRank(2),
                CTXItems.MapKey(ASValues.ASString("str")),
                CTXItems.MapValue(ASValues.ASString("'str'")),
            ]
        )

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_double(self):
        line = "map_key(float(3.14159)) map_key(float(0.0)) map_key(float(-3.14159))"
        expected = CDTContext(
            [
                CTXItems.MapKey(ASValues.ASDouble(3.14159)),
                CTXItems.MapKey(ASValues.ASDouble(0.0)),
                CTXItems.MapKey(ASValues.ASDouble(-3.14159)),
            ]
        )

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_int(self):
        line = "map_key(int(3)) map_key(int(0)) map_key(int(-3))"
        expected = CDTContext(
            [
                CTXItems.MapKey(ASValues.ASInt(3)),
                CTXItems.MapKey(ASValues.ASInt(0)),
                CTXItems.MapKey(ASValues.ASInt(-3)),
            ]
        )

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertEqual(expected, actual)

    def test_str_to_cdt_ctx_with_str(self):
        line = [
            'map_key(abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP QRSTUVWXYZ1234567890"-=!@#$%^&*()_+[]\\,.;/`~)'
        ]
        expected = CDTContext(
            [
                CTXItems.MapKey(
                    ASValues.ASString(
                        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP QRSTUVWXYZ1234567890"-=!@#$%^&*()_+[]\\,.;/`~'
                    )
                ),
            ]
        )

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line)

        self.assertListEqual(expected, actual)

    def test_str_to_cdt_ctx_with_bool(self):
        line = "map_key(bool(FaLsE)) map_key(bool(TRUE))"
        expected = CDTContext(
            [
                CTXItems.MapKey(ASValues.ASBool(False)),
                CTXItems.MapKey(ASValues.ASBool(True)),
            ]
        )

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())

        self.assertListEqual(expected, actual)

    def test_str_to_cdt_ctx_with_bytes(self):
        line = "map_key(bytes(YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkwLT1gIUAjJV4mKigpXytbXXt9Oyc6IltdOiwu)) map_key(bytes(YmxhaA==))"
        expected = CDTContext(
            [
                CTXItems.MapKey(
                    ASValues.ASBytes(
                        bytes(
                            "abcdefghijklmnopqrstuvwxyz1234567890-=`!@#%^&*()_+[]{};':\"[]:,.",
                            encoding="utf-8",
                        )
                    )
                ),
                CTXItems.MapKey(ASValues.ASBytes(bytes("blah", encoding="utf-8"))),
            ]
        )

        actual = ManageSIndexCreateController._list_to_cdt_ctx(line.split())
        self.assertListEqual(expected, actual)

    def test_str_to_cdt_ctx_with_bool_fails(self):
        line = "map_key(bool(FaLs))"

        self.assertRaisesRegex(
            ShellException,
            r"Unable to parse bool FaLs",
            ManageSIndexCreateController._list_to_cdt_ctx,
            line.split(),
        )

    def test_str_to_cdt_ctx_with_bytes_fails(self):
        line = "map_key(bytes(abc))"

        self.assertRaisesRegex(
            ShellException,
            r"Unable to decode base64 encoded bytes : Incorrect padding",
            ManageSIndexCreateController._list_to_cdt_ctx,
            line.split(),
        )

    def test_incorrect_item_sytax_raises_shell_exception(self):
        line = "map_index(1.'5)"

        self.assertRaisesRegex(
            ShellException,
            r"Unable to parse ctx item map_index\(1.'5\)",
            ManageSIndexCreateController._list_to_cdt_ctx,
            line.split(),
        )


class ManageSIndexCreateControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageSIndexCreateController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageSIndexCreateController.prompt_challenge"
        ).start()
        self.meta_mock = self.controller.meta_getter = create_autospec(
            GetClusterMetadataController
        )

        self.addCleanup(patch.stopall)

    async def test_prompt_challenge_fails(self):
        line = "numeric a-index ns test bin a ctx list_value(1)".split()
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.meta_mock.get_builds.return_value = {"principal": "6.1.0.0"}

        await self.controller.execute(line)

        self.prompt_mock.assert_called_once_with(
            "Adding a secondary index will cause longer restart times."
        )

    @parameterized.expand([("numeric",), ("string",), ("geo2dsphere",), ("blob",)])
    async def test_create_successful(self, bin_type):
        line = f"{bin_type} a-index ns test set testset bin a in mapkeys ctx list_value(int(1))".split()
        self.cluster_mock.info_sindex_create.return_value = {
            "1.1.1.1": ASINFO_RESPONSE_OK
        }
        self.meta_mock.get_builds.return_value = {"principal": "7.0.0.0"}

        await self.controller.execute(line)

        self.cluster_mock.info_sindex_create.assert_called_once_with(
            "a-index",
            "test",
            "a",
            bin_type,
            "mapkeys",
            "testset",
            CDTContext([CTXItems.ListValue(ASValues.ASInt(1))]),
            None,
            None,
            {'cdt_indexing': True, 'expression_indexing': False, 'namespace_query_selector_support': False},
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_once_with(
            "Use 'show sindex' to confirm a-index was created successfully."
        )

    async def test_create_fails_with_asinfo_error(self):
        line = "numeric a-index ns test bin a ctx list_value(1)".split()
        self.meta_mock.get_builds.return_value = {"principal": "6.1.0.0"}
        self.cluster_mock.info_sindex_create.return_value = {
            "1.1.1.1": ASInfoResponseError("foo", "ERROR::bar")
        }

        await self.assertAsyncRaisesRegex(
            ASInfoResponseError, "bar", self.controller.execute(line)
        )

    async def test_ctx_invalid_format(self):
        line = "numeric a-index ns test bin a ctx foo".split()
        self.meta_mock.get_builds.return_value = {"principal": "6.1.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Unable to parse ctx item foo",
            self.controller.execute(line),
        )

    async def test_ctx_not_supported(self):
        line = "numeric a-index ns test bin a ctx [foo]".split()
        self.meta_mock.get_builds.return_value = {"principal": "6.0.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "One or more servers does not support 'ctx'.",
            self.controller.execute(line),
        )

    async def test_blob_not_supported(self):
        line = "blob a-index ns test bin a ctx [foo]".split()
        self.meta_mock.get_builds.return_value = {"principal": "6.4.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Blob type secondary index is not supported on server version < 7.0",
            self.controller.execute(line),
        )

    async def test_create_successful_with_exp_base64(self):
        line = "string exp-index ns test exp_base64 dGVzdA==".split()
        self.cluster_mock.info_sindex_create.return_value = {
            "1.1.1.1": ASINFO_RESPONSE_OK
        }
        self.meta_mock.get_builds.return_value = {"principal": "8.1.0.0"}

        await self.controller.execute(line)

        self.cluster_mock.info_sindex_create.assert_called_once_with(
            "exp-index",
            "test",
            "",
            "string",
            None,
            None,
            None,
            None,
            "dGVzdA==",
            {'cdt_indexing': True, 'expression_indexing': True, 'namespace_query_selector_support': True},
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_once_with(
            "Use 'show sindex' to confirm exp-index was created successfully."
        )

    async def test_create_successful_with_ctx_base64(self):
        line = "string ctx-index ns test bin mybin ctx_base64 dGVzdA==".split()
        self.cluster_mock.info_sindex_create.return_value = {
            "1.1.1.1": ASINFO_RESPONSE_OK
        }
        self.meta_mock.get_builds.return_value = {"principal": "6.1.0.0"}

        await self.controller.execute(line)

        self.cluster_mock.info_sindex_create.assert_called_once_with(
            "ctx-index",
            "test",
            "mybin",
            "string",
            None,
            None,
            None,
            "dGVzdA==",
            None,
            {'cdt_indexing': True, 'expression_indexing': False, 'namespace_query_selector_support': False},
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_once_with(
            "Use 'show sindex' to confirm ctx-index was created successfully."
        )

    async def test_exp_base64_not_supported(self):
        line = "string exp-index ns test exp_base64 dGVzdA==".split()
        self.meta_mock.get_builds.return_value = {"principal": "8.0.0.0"}

        result = await self.controller.execute(line)

        self.assertFalse(result)
        self.logger_mock.error.assert_called_once_with(
            "One or more servers does not support 'expression' modifier."
        )

    async def test_exp_base64_invalid_base64(self):
        line = "string exp-index ns test exp_base64 invalid_base64!".split()
        self.meta_mock.get_builds.return_value = {"principal": "8.1.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Unable to parse expression 'invalid_base64!'",
            self.controller.execute(line),
        )

    async def test_ctx_and_ctx_base64_conflict(self):
        line = (
            "string idx ns test bin mybin ctx list_index(0) ctx_base64 dGVzdA==".split()
        )
        self.meta_mock.get_builds.return_value = {"principal": "8.1.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Cannot use both 'ctx' and 'ctx_base64' modifiers together",
            self.controller.execute(line),
        )

    async def test_ctx_and_exp_base64_conflict(self):
        line = (
            "string idx ns test bin mybin ctx list_index(0) exp_base64 dGVzdA==".split()
        )
        self.meta_mock.get_builds.return_value = {"principal": "8.1.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Cannot use both 'ctx' and 'exp_base64' modifiers together",
            self.controller.execute(line),
        )

    async def test_ctx_base64_and_exp_base64_conflict(self):
        line = "string idx ns test bin mybin ctx_base64 dGVzdA== exp_base64 ZXhwcmVzc2lvbg==".split()
        self.meta_mock.get_builds.return_value = {"principal": "8.1.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Cannot use both 'ctx_base64' and 'exp_base64' modifiers together",
            self.controller.execute(line),
        )

    async def test_bin_and_exp_base64_conflict(self):
        line = "string idx ns test bin mybin exp_base64 dGVzdA==".split()
        self.meta_mock.get_builds.return_value = {"principal": "8.1.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Cannot use both 'bin' and 'exp_base64' modifiers together",
            self.controller.execute(line),
        )

    async def test_missing_bin_and_exp_base64(self):
        line = "string idx ns test".split()
        self.meta_mock.get_builds.return_value = {"principal": "8.1.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Either 'bin' or 'exp_base64' modifier is required",
            self.controller.execute(line),
        )

    async def test_ctx_base64_not_supported(self):
        line = "string idx ns test bin mybin ctx_base64 dGVzdA==".split()
        self.meta_mock.get_builds.return_value = {"principal": "6.0.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "One or more servers does not support 'ctx_base64'",
            self.controller.execute(line),
        )

    async def test_ctx_base64_invalid_base64(self):
        line = "string idx ns test bin mybin ctx_base64 invalid_base64!".split()
        self.meta_mock.get_builds.return_value = {"principal": "6.1.0.0"}

        await self.assertAsyncRaisesRegex(
            ShellException,
            "Unable to parse ctx_base64 'invalid_base64!'",
            self.controller.execute(line),
        )


class ManageSIndexDeleteControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageSIndexDeleteController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageSIndexDeleteController.prompt_challenge"
        ).start()

        self.cluster_mock.info_build.return_value = {"principal": "6.1.0.0"}

        self.addCleanup(patch.stopall)

    async def test_prompt_challenge_fails(self):
        line = "a-index ns test set testset".split()
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_sindex_statistics.return_value = {
            "1.1.1.1": {"keys": 1111},
            "2.2.2.2": {"keys": 2222},
        }

        await self.controller.execute(line)

        self.prompt_mock.assert_called_once_with(
            "The secondary index a-index has 3333 keys indexed."
        )
        self.cluster_mock.info_sindex_delete.assert_not_called()

    async def test_delete_successful(self):
        line = "a-index ns test set testset".split()
        self.cluster_mock.info_sindex_delete.return_value = {
            "1.1.1.1": ASINFO_RESPONSE_OK
        }

        await self.controller.execute(line)

        self.cluster_mock.info_sindex_delete.assert_called_once_with(
            "a-index",
            "test",
            "testset",
            {'namespace_query_selector_support': False},
            nodes="principal",
        )
        self.view_mock.print_result.assert_called_once_with(
            "Successfully deleted sindex a-index."
        )

    async def test_create_fails_with_asinfo_error(self):
        line = "a-index ns test set testset".split()
        self.cluster_mock.info_sindex_delete.return_value = {
            "1.1.1.1": ASInfoResponseError("foo", "ERROR::bar")
        }

        await self.assertAsyncRaisesRegex(
            ASInfoResponseError, "bar", self.controller.execute(line)
        )


@asynctest.fail_on(active_handles=True)
class ManageTruncateControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageTruncateController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageTruncateController.prompt_challenge"
        ).start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}

        self.addCleanup(patch.stopall)

    async def test_parse_lut_with_incorrect_before_len(self):
        self.controller.mods = {"before": ["12344352"]}

        self.assertRaisesRegex(
            ShellException,
            'Last update time must be followed by "unix-epoch" or "iso-8601".',
            self.controller._parse_lut,
        )

        self.controller.mods = {"before": ["12344352", "unix-epoch", "extra"]}

        self.assertRaisesRegex(
            ShellException,
            'Last update time must be followed by "unix-epoch" or "iso-8601".',
            self.controller._parse_lut,
        )

    async def test_parse_lut_with_incorrect_epoch_format(self):
        self.controller.mods = {"before": ["12345v6789", "unix-epoch"]}

        self.assertRaises(ShellException, self.controller._parse_lut)

    async def test_parse_lut_with_date_too_new(self):
        self.controller.mods = {"before": ["12345678900", "unix-epoch"]}

        self.assertRaisesRegex(
            ShellException,
            "Date provided is too far in the future.",
            self.controller._parse_lut,
        )

        self.controller.mods = {"before": ["2483-05-30T04:26:40Z", "iso-8601"]}

        self.assertRaisesRegex(
            ShellException,
            "Date provided is too far in the future.",
            self.controller._parse_lut,
        )

    async def test_parse_lut_with_date_too_old(self):
        self.controller.mods = {"before": ["123456789", "unix-epoch"]}

        self.assertRaisesRegex(
            ShellException,
            "Date provided is too far in the past.",
            self.controller._parse_lut,
        )

        self.controller.mods = {"before": ["1970-05-30T04:26:40Z", "iso-8601"]}

        self.assertRaisesRegex(
            ShellException,
            "Date provided is too far in the past.",
            self.controller._parse_lut,
        )

    async def test_parse_lut_with_incorrect_iso_format(self):
        self.controller.mods = {"before": ["123", "iso-8601"]}

        self.assertRaises(ShellException, self.controller._parse_lut)

    async def test_parse_lut_with_iso_without_timezone(self):
        self.controller.mods = {"before": ["2020-05-04T04:20:40", "iso-8601"]}

        self.assertRaisesRegex(
            ShellException,
            "iso-8601 format must contain a timezone.",
            self.controller._parse_lut,
        )

    async def test_parse_lut_iso_gives_correct_epoch_time(self):
        input_output = [
            ("2021-05-04T22:44:05Z", "1620168245000000000"),
            ("2021-05-04T22:44:05+00:00", "1620168245000000000"),
            ("2021-05-04T22:44:05-07:00", "1620193445000000000"),
            ("2021-05-04T23:54:30.123456+00:00", "1620172470123456000"),
            ("2021-05-04T22:54:30.123456-01:00", "1620172470123456000"),
            ("2021-05-04T00:54:30.123456+01:00", "1620086070123456000"),
            ("20210503T195430.123456-0400", "1620086070123456000"),
            ("2021-05-04T11:40:34.100-12:00", "1620171634100000000"),
        ]

        for input, output in input_output:
            with self.subTest(input_output):
                self.controller.mods = {"before": [input, "iso-8601"]}
                lut_datetime, lut_epoch_time = self.controller._parse_lut()

                self.assertEqual(lut_epoch_time, output)

    async def test_parse_lut_epoch_gives_correct_epoch_time(self):
        input_output = [
            ("1234567899", "1234567899000000000"),
            ("1234567899.123456789", "1234567899123456789"),
            ("1234567899.123", "1234567899123000000"),
        ]

        for input, output in input_output:
            self.controller.mods = {"before": [input, "unix-epoch"]}
            lut_datetime, lut_epoch_time = self.controller._parse_lut()

            self.assertEqual(lut_epoch_time, output)

    async def test_get_namespace_master_objects(self):
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {
                "a": 1,
                "b": 12,
                "c": 23,
                "d": 34,
                "e": 45,
                "f": 56,
                "master_objects": 33,
            },
            "2.2.2.2": {
                "a": 1,
                "b": 12,
                "c": 23,
                "d": 34,
                "e": 45,
                "f": 56,
                "master_objects": 44,
            },
            "3.3.3.3": {
                "a": 1,
                "b": 12,
                "c": 23,
                "d": 34,
                "e": 45,
                "f": 56,
                "master_objects": 55,
            },
            "4.4.4.4": {"a": 1, "b": 12, "c": 23, "d": 34, "e": 45, "f": 56},
        }

        master_objects = await self.controller._get_namespace_master_objects("test-ns")

        self.cluster_mock.info_namespace_statistics.assert_called_with(
            "test-ns", nodes="all"
        )
        self.assertEqual(master_objects, str(33 + 44 + 55))

    async def test_get_set_master_objects(self):
        self.cluster_mock.info_set_statistics.return_value = {
            "1.1.1.1": {
                "a": 1,
                "b": 12,
                "c": 23,
                "d": 34,
                "e": 45,
                "f": 56,
                "objects": 11,
            },
            "4.4.4.4": {"a": 1, "b": 12, "c": 23, "d": 34, "e": 45, "f": 56},
            "2.2.2.2": {
                "a": 1,
                "b": 12,
                "c": 23,
                "d": 34,
                "e": 45,
                "f": 56,
                "objects": 55,
            },
            "3.3.3.3": {
                "a": 1,
                "b": 12,
                "c": 23,
                "d": 34,
                "e": 45,
                "f": 56,
                "objects": 66,
            },
        }
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"effective_repl_factor": 11}
        }

        master_objects = await self.controller._get_set_master_objects(
            "test-ns", "test-set"
        )

        self.cluster_mock.info_set_statistics.assert_called_with(
            "test-ns", "test-set", nodes="all"
        )
        self.assertEqual(master_objects, str((11 + 55 + 66) // 11))

    async def test_returns_on_lut_error(self):
        line = "ns test before 123456789 unix-epoch"
        await self.assertAsyncRaisesRegex(
            ShellException,
            "Date provided is too far in the past.",
            self.controller.execute(line.split()),
        )
        # await awaitable
        self.cluster_mock.info_truncate.assert_not_called()

    @patch(
        "lib.live_cluster.manage_controller.ManageTruncateController._get_namespace_master_objects"
    )
    async def test_prompts_error_without_lut(self, _get_namespace_master_objects_mock):
        _get_namespace_master_objects_mock.return_value = 50
        self.controller.warn = True
        self.prompt_mock.side_effect = lambda x: False
        line = "ns test"

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You're about to truncate up to 50 records from namespace test"
        )

    async def test_prompts_error_without_lut_or_set(self):
        self.controller._get_set_master_objects = AsyncMock()
        self.controller._get_set_master_objects.return_value = 60
        self.controller.warn = True
        self.prompt_mock.side_effect = lambda x: False

        line = "ns test set test-set"

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You're about to truncate up to 60 records from set test-set for namespace test"
        )

    async def test_prompts_error_with_lut(self):
        self.controller._get_set_master_objects = AsyncMock()
        self.controller._get_set_master_objects.return_value = 60
        self.controller.warn = True
        self.prompt_mock.side_effect = lambda x: False

        line = "ns test set test-set before 1620690614 unix-epoch"

        await self.controller.execute(line.split())

        # Fails with pytest when you add -s
        self.prompt_mock.assert_called_with(
            "You're about to truncate up to 60 records from set test-set for namespace test with LUT before 23:50:14.000000 UTC on May 10, 2021"
        )

    async def test_success_with_no_set(self):
        self.controller._get_namespace_master_objects = AsyncMock()
        self.controller._get_namespace_master_objects.return_value = 10
        self.cluster_mock.info_truncate.return_value = {"principal": "not an error"}
        line = "ns test before 1620690614 unix-epoch"

        await self.controller.execute(line.split())

        self.cluster_mock.info_truncate.assert_called_with(
            "test", None, "1620690614000000000", nodes="principal"
        )
        self.logger_mock.error.assert_not_called()
        self.view_mock.print_result.assert_called_with(
            "Successfully started truncation for namespace test"
        )

    async def test_success_with_set(self):
        self.cluster_mock.info_truncate.return_value = {"principal": "not an error"}
        line = "ns test set test-set before 1620690614 unix-epoch --no-warn"

        await self.controller.execute(line.split())

        self.cluster_mock.info_truncate.assert_called_with(
            "test", "test-set", "1620690614000000000", nodes="principal"
        )
        self.logger_mock.error.assert_not_called()
        self.view_mock.print_result.assert_called_with(
            "Successfully started truncation for set test-set of namespace test"
        )

    async def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASInfoResponseError("An error message", "test-resp")
        line = "ns test set test-set before 1620690614 unix-epoch --no-warn"
        self.cluster_mock.info_truncate.return_value = {"principal_ip": as_error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_truncate.assert_called_with(
            "test", "test-set", "1620690614000000000", nodes="principal"
        )
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    async def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "ns test set test-set before 1620690614 unix-epoch --no-warn"
        self.cluster_mock.info_truncate.return_value = {"principal_ip": as_error}

        await test_util.assert_exception_async(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.info_truncate.assert_called_with(
            "test", "test-set", "1620690614000000000", nodes="principal"
        )
        self.view_mock.print_result.assert_not_called()


@asynctest.fail_on(active_handles=True)
class ManageTruncateUndoControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageTruncateController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageTruncateController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageTruncateController.prompt_challenge"
        ).start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    async def test_warn_prompt_and_return(self):
        self.controller.warn = True
        self.prompt_mock.return_value = False
        line = "ns test undo"

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("")
        self.cluster_mock.info_truncate_undo.assert_not_called()

    async def test_success_with_ns(self):
        line = "undo ns test"
        self.cluster_mock.info_truncate_undo.return_value = {
            "principal-ip": ASINFO_RESPONSE_OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.info_truncate_undo.assert_called_once_with(
            "test", None, nodes="principal"
        )
        self.view_mock.print_result.assert_called_once_with(
            "Successfully triggered undoing truncation for namespace test on next cold restart"
        )

    async def test_success_with_set(self):
        line = "undo ns test set test-set"
        self.cluster_mock.info_truncate_undo.return_value = {
            "principal-ip": ASINFO_RESPONSE_OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.info_truncate_undo.assert_called_once_with(
            "test", "test-set", nodes="principal"
        )
        self.view_mock.print_result.assert_called_once_with(
            "Successfully triggered undoing truncation for set test-set of namespace test on next cold restart"
        )

    async def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASInfoResponseError("An error message", "test-resp")
        line = "ns test set test-set undo"
        self.cluster_mock.info_truncate_undo.return_value = {"principal_ip": as_error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_truncate_undo.assert_called_with(
            "test", "test-set", nodes="principal"
        )
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    async def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "undo ns test set test-set"
        self.cluster_mock.info_truncate_undo.return_value = {"principal_ip": as_error}

        await test_util.assert_exception_async(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.info_truncate_undo.assert_called_with(
            "test", "test-set", nodes="principal"
        )
        self.view_mock.print_result.assert_not_called()


@asynctest.fail_on(active_handles=True)
class ManageReclusterControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageReclusterController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageReclusterController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}

        self.addCleanup(patch.stopall)

    async def test_success(self):
        line = ""
        self.cluster_mock.info_recluster.return_value = {
            "principal-ip": ASINFO_RESPONSE_OK
        }

        await self.controller.execute(line.split())

        self.cluster_mock.info_recluster.assert_called_once_with(nodes="principal")
        self.view_mock.print_result.assert_called_once_with(
            "Successfully started recluster"
        )

    async def test_logs_error_when_asinfo_error_returned(self):
        as_error = ASInfoResponseError("An error message", "test-resp")
        line = ""
        self.cluster_mock.info_recluster.return_value = {"principal_ip": as_error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_recluster.assert_called_with(nodes="principal")
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    async def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = ""
        self.cluster_mock.info_recluster.return_value = {"principal_ip": as_error}

        await test_util.assert_exception_async(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.info_recluster.assert_called_with(nodes="principal")
        self.view_mock.print_result.assert_not_called()


@asynctest.fail_on(active_handles=True)
class ManageQuiesceControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageQuiesceController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageQuiesceController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_success(self):
        line = "with 1.1.1.1"
        self.cluster_mock.info_quiesce.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}
        mods = {"with": ["1.1.1.1"], "undo": [], "line": []}

        await self.controller.execute(line.split())

        self.cluster_mock.info_quiesce.assert_called_once_with(nodes=["1.1.1.1"])
        self.view_mock.print_info_responses.assert_called_once_with(
            "Quiesce Nodes", {"1.1.1.1": ASINFO_RESPONSE_OK}, self.cluster_mock, **mods
        )
        self.view_mock.print_result.assert_called_once_with(
            'Run "manage recluster" for your changes to take effect.'
        )

    async def test_success_with_undo(self):
        line = "with 1.1.1.1 2.2.2.2 undo"
        self.cluster_mock.info_quiesce_undo.return_value = {
            "1.1.1.1": ASINFO_RESPONSE_OK
        }
        mods = {"with": ["1.1.1.1", "2.2.2.2"], "undo": [], "line": []}

        await self.controller.execute(line.split())

        self.cluster_mock.info_quiesce_undo.assert_called_once_with(
            nodes=["1.1.1.1", "2.2.2.2"]
        )
        self.view_mock.print_info_responses.assert_called_once_with(
            "Undo Quiesce for Nodes",
            {"1.1.1.1": ASINFO_RESPONSE_OK},
            self.cluster_mock,
            **mods,
        )
        self.view_mock.print_result(
            'Run "manage recluster for your changes to take effect.'
        )


@asynctest.fail_on(active_handles=True)
class ManageReviveControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageReviveController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.prompt_challenge"
        ).start()

        self.addCleanup(patch.stopall)

    async def test_success(self):
        line = "ns test"
        self.cluster_mock.info_revive.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        await self.controller.execute(line.split())

        self.cluster_mock.info_revive.assert_called_once_with(
            "test", nodes=self.controller.nodes
        )
        self.view_mock.print_info_responses.assert_called_once_with(
            "Revive Namespace Partitions",
            {"1.1.1.1": ASINFO_RESPONSE_OK},
            self.cluster_mock,
            **self.controller.mods,
        )
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take effect.'
        )

    async def test_warn_prompt_returns_false(self):
        line = "ns test"
        self.prompt_mock.return_value = False
        self.controller.warn = True

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "You are about to revive namespace test"
        )

    async def test_warn_prompt_returns_true(self):
        line = "ns test"
        self.prompt_mock.return_value = True
        self.controller.warn = True
        self.cluster_mock.info_revive.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "You are about to revive namespace test"
        )
        self.cluster_mock.info_revive.assert_called_once()


@asynctest.fail_on(active_handles=True)
class ManageJobsKillTridControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillTridController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageJobsKillTridController()
        self.getter_mock = patch(
            "lib.live_cluster.manage_controller.GetJobsController", AsyncMock()
        ).start()
        self.controller.getter = self.getter_mock
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillTridController.prompt_challenge"
        ).start()

        self.addCleanup(patch.stopall)

    async def test_kill_trids(self):
        trids = ["123", "789", "101", "456"]
        self.getter_mock.get_all.return_value = {
            "scan": {
                "1.1.1.1": {
                    "123": {"trid": "123"},
                }
            },
            "query": {
                "2.2.2.2": {
                    "456": {"trid": "456"},
                }
            },
            "sindex-builder": {
                "3.3.3.3": {
                    "789": {"trid": "789"},
                },
                "1.1.1.1": {
                    "101": {"trid": "101"},
                },
            },
        }
        self.cluster_mock.info_scan_abort.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}
        self.cluster_mock.info_query_abort.return_value = {
            "2.2.2.2": ASINFO_RESPONSE_OK
        }
        self.cluster_mock.info_jobs_kill.return_value = {"3.3.3.3": ASINFO_RESPONSE_OK}

        await self.controller.execute(trids)

        self.cluster_mock.info_scan_abort.assert_called_with("123", nodes=["1.1.1.1"])
        self.cluster_mock.info_query_abort.assert_called_with("456", nodes=["2.2.2.2"])
        self.cluster_mock.info_jobs_kill.assert_has_calls(
            [
                call("sindex-builder", "789", nodes=["3.3.3.3"]),
                call("sindex-builder", "101", nodes=["1.1.1.1"]),
            ]
        )
        self.view_mock.killed_jobs.assert_called_once_with(
            self.cluster_mock,
            {
                "1.1.1.1": {
                    "123": {"trid": "123", "response": "ok"},
                    "101": {"trid": "101", "response": "ok"},
                },
                "2.2.2.2": {
                    "456": {"trid": "456", "response": "ok"},
                },
                "3.3.3.3": {
                    "789": {"trid": "789", "response": "ok"},
                },
            },
            **self.controller.mods,
        )

    async def test_kill_same_trid_on_multiple_hosts(self):
        trids = ["123", "789"]
        self.getter_mock.get_all.return_value = {
            "scan": {
                "1.1.1.1": {
                    "123": {"trid": "123"},
                },
                "2.2.2.2": {
                    "123": {"trid": "123"},
                },
            },
            "query": {
                "2.2.2.2": {
                    "789": {"trid": "789"},
                },
                "3.3.3.3": {
                    "789": {"trid": "789"},
                },
            },
        }
        self.cluster_mock.info_scan_abort.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}
        self.cluster_mock.info_query_abort.return_value = {
            "2.2.2.2": ASINFO_RESPONSE_OK
        }

        await self.controller.execute(trids)

        self.cluster_mock.info_scan_abort.assert_has_calls(
            [call("123", nodes=["1.1.1.1"]), call("123", nodes=["2.2.2.2"])]
        )
        self.cluster_mock.info_query_abort.assert_has_calls(
            [call("789", nodes=["2.2.2.2"]), call("789", nodes=["3.3.3.3"])]
        )
        self.cluster_mock.info_jobs_kill.assert_not_called()
        self.view_mock.killed_jobs.assert_called_once_with(
            self.cluster_mock,
            {
                "1.1.1.1": {
                    "123": {"trid": "123", "response": "ok"},
                },
                "2.2.2.2": {
                    "123": {"trid": "123", "response": "ok"},
                    "789": {"trid": "789", "response": "ok"},
                },
                "3.3.3.3": {
                    "789": {"trid": "789", "response": "ok"},
                },
            },
            **self.controller.mods,
        )

    async def test_kill_trids_warn(self):
        trids = ["123", "789", "101", "456"]
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.controller._kill_trid = AsyncMock()
        self.getter_mock.get_all.return_value = {
            "scan": {
                "1.1.1.1": {
                    "123": {"trid": "123"},
                }
            },
        }

        await self.controller.execute(trids)

        self.prompt_mock.assert_called_with(
            "You're about to kill the following transactions: 123, 789, 101, 456"
        )
        self.controller._kill_trid.assert_not_called()


@asynctest.fail_on(active_handles=True)
class ManageJobsKillAllScansControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillAllScansController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageJobsKillAllScansController()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillAllScansController.prompt_challenge"
        ).start()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.addCleanup(patch.stopall)

    async def test_kill_all_scans(self):
        module = "scan"
        self.cluster_mock.info_scan_abort_all.return_value = {"1.1.1.1": "ok"}
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "5.7"}

        await self.controller.execute(module.split())

        self.cluster_mock.info_scan_abort_all.assert_called_with(nodes="all")

    async def test_kill_all_warn(self):
        module = "scans"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "5.7"}

        await self.controller.execute(module.split())

        self.prompt_mock.assert_called_with(
            "You're about to kill all scan jobs on all nodes."
        )
        self.cluster_mock.info_scan_abort_all.assert_not_called()

    async def test_kill_not_supported(self):
        module = "scans"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "6.0"}

        await self.controller.execute(module.split())

        self.cluster_mock.info_scan_abort_all.assert_not_called()
        self.logger_mock.error.assert_called_with(
            "Killing scans is not supported on server v. 6.0 and later."
        )


@asynctest.fail_on(active_handles=True)
class ManageJobsKillAllQueriesControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillAllQueriesController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageJobsKillAllQueriesController()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillAllQueriesController.prompt_challenge"
        ).start()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.addCleanup(patch.stopall)

    async def test_kill_all_queries(self):
        module = "queries"
        self.cluster_mock.info_query_abort_all.return_value = {"1.1.1.1": "ok"}
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "6.0"}

        await self.controller.execute(module.split())

        self.cluster_mock.info_query_abort_all.assert_called_with(nodes="all")

    async def test_kill_all_warn(self):
        module = "queries"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "6.0"}

        await self.controller.execute(module.split())

        self.prompt_mock.assert_called_with(
            "You're about to kill all query jobs on all nodes."
        )
        self.cluster_mock.info_query_abort_all.assert_not_called()

    async def test_kill_not_supported(self):
        module = "queries"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "5.9"}

        await self.controller.execute(module.split())

        self.cluster_mock.info_scan_abort_all.assert_not_called()
        self.logger_mock.error.assert_called_with(
            "Killing all queries is only supported on server v. 6.0 and later."
        )


@asynctest.fail_on(active_handles=True)
class ManageRosterLeafCommandControllerTest(asynctest.TestCase):
    def setUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController.cluster",
            AsyncMock,
        ).start()
        self.controller = ManageRosterLeafCommandController(self.cluster_mock)
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()

        self.addCleanup(patch.stopall)

    def test_check_and_log_cluster_stable(self):
        class test_case:
            def __init__(self, input, output):
                self.input = input
                self.output = output

        test_cases = [
            test_case({"1.1.1.1": "ABC", "2.2.2.2": "ABC", "3.3.3.3": "ABC"}, True),
            test_case({"1.1.1.1": "ABC", "2.2.2.2": "DEF", "3.3.3.3": "ABC"}, False),
            test_case(
                {
                    "1.1.1.1": "ABC",
                    "2.2.2.2": "ABC",
                    "3.3.3.3": ASInfoClusterStableError("foo"),
                },
                False,
            ),
        ]

        for tc in test_cases:
            result = self.controller._check_and_log_cluster_stable(tc.input)

            self.assertEqual(
                result,
                tc.output,
                "Failed with input: {} and output: {}".format(tc.input, tc.output),
            )

            if tc.output is False:
                self.logger_mock.warning.assert_called_with(
                    "It is advised that you do not manage the roster. Run 'info network' for more information."
                )

        self.assertEqual(
            False,
            self.controller._check_and_log_cluster_stable(
                {
                    "1.1.1.1": "ABC",
                    "2.2.2.2": "ABC",
                    "3.3.3.3": ASInfoResponseError("", "foo"),
                }
            ),
        )

    def test_check_and_log_nodes_in_observed(self):
        class test_case:
            def __init__(self, observed, nodes, output, warning=None):
                self.observed = observed
                self.nodes = nodes
                self.output = output
                self.warning = warning

        test_cases = [
            test_case(["A", "B", "C"], ["A", "B", "C"], True),
            test_case(
                ["A", "B", "C"],
                ["A", "B", "C", "D"],
                False,
            ),
            test_case(
                [],
                ["A", "B"],
                False,
            ),
            test_case(["A", "B"], [], True),
        ]

        for tc in test_cases:
            self.logger_mock.reset_mock()
            result = self.controller._check_and_log_nodes_in_observed(
                tc.observed, tc.nodes
            )

            self.assertEqual(
                tc.output,
                result,
                "Failed with observed: {}, nodes: {}".format(tc.observed, tc.nodes),
            )

            if tc.output is True:
                self.logger_mock.warning.assert_not_called()
            else:
                self.logger_mock.warning.assert_called_once()


@asynctest.fail_on(active_handles=True)
class ManageRosterAddControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageRosterAddController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController.prompt_challenge"
        ).start()
        self.check_and_log_cluster_stable_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController._check_and_log_cluster_stable"
        ).start()
        self.check_and_log_nodes_in_observed_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController._check_and_log_nodes_in_observed"
        ).start()
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_success(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": []}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["GHI", "ABC@rack1", "DEF@rack2"], nodes="principal"
        )
        self.view_mock.print_result.assert_any_call(
            "Node(s) successfully added to pending-roster."
        )
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take effect.'
        )

    async def test_logs_error_from_roster(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        error = ASInfoResponseError("blah", "error::foo")
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    async def test_logs_error_from_roster_set(self):
        error = ASInfoResponseError("blah", "error::foo")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": []}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_called_once()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    async def test_raises_warn_from_none_ns(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = None

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called()
        self.cluster_mock.info_namespace_statistics.assert_called()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.logger_mock.error.assert_any_call(
            "namespace test does not exist on this node"
        )

    async def test_raises_warn_from_invalid_ns(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": {}}
        self.cluster_mock.info_namespace_statistics.return_value = {"1.1.1.1": {}}

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called()
        self.cluster_mock.info_namespace_statistics.assert_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.logger_mock.error.assert_any_call(
            "namespace test does not exist on this node"
        )

    async def test_raises_warn_from_ap_ns(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": {}}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "false"}
        }

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.logger_mock.error.assert_any_call(
            "namespace test is not in strong consistency mode"
        )

    async def test_raises_error_from_ns_stats(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}
        self.cluster_mock.info_namespace_statistics.return_value = error

        await test_util.assert_exception_async(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_called()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    async def test_raises_error_from_roster(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }

        await test_util.assert_exception_async(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    async def test_raises_error_from_roster_set(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": []}
        }
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await test_util.assert_exception_async(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    async def test_warn_returns_false(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": ["foo"]}
        }

        await self.controller.execute(line.split())

        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.check_and_log_nodes_in_observed_mock.assert_called_once_with(
            ["foo"], ["ABC@rack1", "DEF@rack2"]
        )
        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI, ABC@rack1, DEF@rack2"
        )
        self.cluster_mock.info_roster_set.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_warn_returns_true(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = True
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": ["bar"]}
        }
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        await self.controller.execute(line.split())

        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.check_and_log_nodes_in_observed_mock.assert_called_once_with(
            ["bar"], ["ABC@rack1", "DEF@rack2"]
        )
        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI, ABC@rack1, DEF@rack2"
        )
        self.cluster_mock.info_roster_set.assert_called_once()
        self.cluster_mock.info_namespace_statistics.assert_called_once()


@asynctest.fail_on(active_handles=True)
class ManageRosterRemoveControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageRosterRemoveController()
        self.check_and_log_cluster_stable_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController._check_and_log_cluster_stable"
        ).start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.prompt_challenge"
        ).start()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

    async def test_success(self):
        line = "nodes ABC ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["ABC", "DEF"], "observed_nodes": []}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["DEF"], nodes="principal"
        )
        self.view_mock.print_result.assert_any_call(
            "Node(s) successfully removed from pending-roster."
        )
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take effect.'
        )
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_logs_error_from_roster(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test  --no-warn"
        error = ASInfoResponseError("blah", "error::foo")
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_logs_error_from_roster_set(self):
        error = ASInfoResponseError("blah", "error::foo")
        line = "nodes ABC@rack1 DEF@rack2 ns test  --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["ABC@rack1", "DEF@rack2", "GHI"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_logs_error_when_node_not_in_pending(self):
        line = "nodes GHI ns test"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["ABC", "DEF"], "observed_nodes": []}
        }
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "CDEF"}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.prompt_mock.return_value = False
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        await self.controller.execute(line.split())

        self.logger_mock.warning.assert_any_call(
            "The following nodes are not in the pending-roster: {}", "GHI"
        )
        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "CDEF"}
        )
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_raises_error_from_roster(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }

        await test_util.assert_exception_async(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    async def test_raises_error_from_roster_set(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["GHI", "ABC@rack1", "DEF@rack2"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await test_util.assert_exception_async(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    async def test_raises_warn_from_none_ns(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = None
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["GHI", "ABC@rack1", "DEF@rack2"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.logger_mock.error.assert_any_call(
            "namespace test does not exist on this node"
        )

    async def test_raises_warn_from_invalid_ns(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["GHI", "ABC@rack1", "DEF@rack2"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_namespace_statistics.return_value = {"1.1.1.1": {}}

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called()
        self.cluster_mock.info_namespace_statistics.assert_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.logger_mock.error.assert_any_call(
            "namespace test does not exist on this node"
        )

    async def test_raises_warn_from_ap_ns(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "false"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["GHI", "ABC@rack1", "DEF@rack2"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.logger_mock.error.assert_any_call(
            "namespace test is not in strong consistency mode"
        )

    async def test_raises_error_from_ns_stats(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = {"1.1.1.1": error}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["GHI", "ABC@rack1", "DEF@rack2"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.logger_mock.error.assert_any_call(
            "namespace test does not exist on this node"
        )

    async def test_warn_returns_false(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["ABC@rack1", "DEF@rack2", "GHI"],
                "observed_nodes": [],
            }
        }

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI"
        )
        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.cluster_mock.info_roster_set.assert_not_called()

    async def test_warn_returns_true(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = True
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["ABC@rack1", "DEF@rack2", "GHI"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI"
        )
        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.cluster_mock.info_roster_set.assert_called_once()
        self.cluster_mock.info_namespace_statistics.assert_called_once()


@asynctest.fail_on(active_handles=True)
class ManageRosterStageNodesControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageRosterStageNodesController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.prompt_challenge"
        ).start()
        self.check_and_log_cluster_stable_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController._check_and_log_cluster_stable"
        ).start()
        self.check_and_log_nodes_in_observed_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController._check_and_log_nodes_in_observed"
        ).start()
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_success(self):
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC@rack1", "DEF@rack2"], nodes="principal"
        )
        self.view_mock.print_result.assert_any_call("Pending roster successfully set.")
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take effect.'
        )
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_logs_error_from_roster_set(self):
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        error = ASInfoResponseError("blah", "error::foo")
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC@rack1", "DEF@rack2"], nodes="principal"
        )

        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.logger_mock.error.assert_called_once_with(error)
        self.view_mock.print_result.assert_not_called()

    async def test_raises_error_from_roster_set(self):
        error = Exception("test exception")
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await test_util.assert_exception_async(
            self, Exception, "test exception", self.controller.execute, line.split()
        )

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC@rack1", "DEF@rack2"], nodes="principal"
        )
        self.logger_mock.error.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_raises_warn_from_none_ns(self):
        error = Exception("test exception")
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = None
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.logger_mock.error.assert_any_call(
            "namespace test does not exist on this node"
        )

    async def test_raises_warn_from_invalid_ns(self):
        error = Exception("test exception")
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = {"1.1.1.1": {}}
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.logger_mock.error.assert_any_call(
            "namespace test does not exist on this node"
        )

    async def test_raises_warn_from_ap_ns(self):
        error = Exception("test exception")
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "false"}
        }
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.logger_mock.error.assert_any_call(
            "namespace test is not in strong consistency mode"
        )

    async def test_raises_error_from_ns_stats(self):
        error = Exception("test exception")
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_namespace_statistics.return_value = {"1.1.1.1": error}
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
        self.logger_mock.error.assert_any_call(
            "namespace test does not exist on this node"
        )

    async def test_warn_returns_false(self):
        line = "ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": [],
            }
        }

        await self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: ABC@rack1, DEF@rack2"
        )
        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.check_and_log_nodes_in_observed_mock.assert_called_once_with(
            [], ["ABC@rack1", "DEF@rack2"]
        )
        self.cluster_mock.info_roster_set.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_warn_returns_true(self):
        line = "ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = True
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": ["jar"],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        await self.controller.execute(line.split())

        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.check_and_log_nodes_in_observed_mock.assert_called_once_with(
            ["jar"], ["ABC@rack1", "DEF@rack2"]
        )
        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: ABC@rack1, DEF@rack2"
        )
        self.cluster_mock.info_roster_set.assert_called_once()
        self.cluster_mock.info_namespace_statistics.assert_called_once()


@asynctest.fail_on(active_handles=True)
class ManageRosterStageObservedControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster",
            AsyncMock(),
        ).start()
        self.controller = ManageRosterStageObservedController()
        self.logger_mock = patch("lib.live_cluster.manage_controller.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.prompt_challenge"
        ).start()
        self.check_and_log_cluster_stable_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController._check_and_log_cluster_stable"
        ).start()
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_success(self):
        line = "ns test"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["ABC", "DEF"]}
        }
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC", "DEF"], nodes="principal"
        )
        self.view_mock.print_result.assert_any_call(
            "Pending roster now contains observed nodes."
        )
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take effect.'
        )

    async def test_logs_error_from_roster(self):
        line = "ns test"
        error = ASInfoResponseError("blah", "error::foo")
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_logs_error_from_roster_set(self):
        line = "ns test"
        error = ASInfoResponseError("blah", "error::foo")
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["ABC", "DEF"]}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC", "DEF"], nodes="principal"
        )
        self.logger_mock.error.assert_called_once_with(error)
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_raises_error_from_roster(self):
        error = Exception("test exception")
        line = "ns test"
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        await test_util.assert_exception_async(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_raises_error_from_roster_set(self):
        error = Exception("test exception")
        line = "ns test"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["GHI", "ABC@rack1", "DEF@rack2"]}
        }
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        await test_util.assert_exception_async(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    async def test_warn_returns_false(self):
        line = "ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["GHI", "ABC@rack1", "DEF@rack2"]}
        }

        await self.controller.execute(line.split())

        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI, ABC@rack1, DEF@rack2"
        )
        self.cluster_mock.info_roster_set.assert_not_called()
        self.cluster_mock.info_namespace_statistics.assert_called_once()

    async def test_warn_returns_true(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = True
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"strong-consistency": "true"}
        }
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["GHI", "ABC@rack1", "DEF@rack2"]}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        await self.controller.execute(line.split())

        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI, ABC@rack1, DEF@rack2"
        )
        self.cluster_mock.info_roster_set.assert_called_once()
        self.cluster_mock.info_namespace_statistics.assert_called_once()
