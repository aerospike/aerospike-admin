from lib.base_controller import ShellException
import unittest
from mock import MagicMock, patch

from lib.live_cluster.client.info import ASProtocolError, ASResponse
from lib.live_cluster.manage_controller import (
    ManageACLCreateRoleController,
    ManageACLCreateUserController,
    ManageACLQuotasRoleController,
)
from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController
from test.unit import util as test_util


class ManageACLCreateUserControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = LiveClusterRootController()
        self.controller = ManageACLCreateUserController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLCreateUserController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.mods = {"like": [], "with": [], "for": [], "line": []}

        self.addCleanup(patch.stopall)

    def test_no_roles_and_no_password(self):
        getpass_mock = patch("lib.live_cluster.manage_controller.getpass").start()
        getpass_mock.return_value = "pass"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(["test-user"])

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", [], nodes=["principal"]
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created user test-user."
        )

    def test_with_roles_and_password(self):
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(
            ["test-user", "password", "pass", "roles", "role1", "role2", "role3"]
        )

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", ["role1", "role2", "role3"], nodes=["principal"]
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created user test-user."
        )

    def test_with_role_and_password(self):
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(
            ["test-user", "password", "pass", "role", "role1", "role2", "role3"]
        )

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", ["role1", "role2", "role3"], nodes=["principal"]
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created user test-user."
        )

    def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASProtocolError(ASResponse.USER_ALREADY_EXISTS, "test-message")
        log_message = "test-message : User already exists."
        line = "test-user password pass"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {"principal_ip": as_error}

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", [], nodes=["principal"]
        )
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

    def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "test-user password pass"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {"principal_ip": as_error}

        test_util.assert_exception(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", [], nodes=["principal"]
        )
        self.view_mock.print_result.assert_not_called()


class ManageACLCreateRoleControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = LiveClusterRootController()
        self.controller = ManageACLCreateRoleController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLCreateRoleController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.mods = {"like": [], "with": [], "for": [], "line": []}

        self.cluster_mock.info_build_version.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def test_logs_error_when_server_does_not_support_quotas(self):
        log_message = "'read' and 'write' modifiers are not supported on aerospike versions <= 5.5"
        line = "test-role priv test-priv read 100 write 200"
        self.cluster_mock.info_build_version.side_effect = [
            {"principal": "5.5.0.0"},
            {"principal": "5.5.9.9"},
        ]
        self.cluster_mock.get_expected_principal.side_effect = ["principal"] * 2
        self.cluster_mock.admin_create_role.side_effect = [
            {"principal_ip": ASResponse.OK}
        ] * 2

        for _ in range(2):
            self.controller.execute(line.split())
            self.logger_mock.warning.assert_called_with(log_message)

    def test_with_only_privilege(self):
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_privilege_with_namespace(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_privilege_and_namespace_and_set(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns set test-set"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns.test-set"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_privilege_and_set_logs_error(self):
        self.controller.execute_help = MagicMock()
        line = "test-role priv test-priv set test-set"

        self.controller.execute(line.split())

        self.logger_mock.error.assert_called_with(
            "A set must be accompanied by a namespace."
        )

    def test_with_privilege_and_allowlist(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns set test-set allow 3.3.3.3 4.4.4.4"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns.test-set"],
            whitelist=["3.3.3.3", "4.4.4.4"],
            read_quota=None,
            write_quota=None,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_privilege_and_read_and_write_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns set test-set read 111 write 222"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns.test-set"],
            whitelist=[],
            read_quota=111,
            write_quota=222,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_privilege_and_allowlist_and_read_and_write_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv test-priv ns test-ns set test-set allow 3.3.3.3 4.4.4.4 read 111 write 222"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["test-priv.test-ns.test-set"],
            whitelist=["3.3.3.3", "4.4.4.4"],
            read_quota=111,
            write_quota=222,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_read_privilege_only(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }

        line = "test-role priv read"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["read"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_write_privilege_only(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }

        line = "test-role priv write"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["write"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_conflicting_write_privilege_and_write_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv write write 111"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["write"],
            whitelist=[],
            read_quota=None,
            write_quota=111,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_conflicting_read_privilege_and_read_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv read read 111"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["read"],
            whitelist=[],
            read_quota=111,
            write_quota=None,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_with_conflicting_read_privilege_and_write_quota(self):
        self.cluster_mock.admin_create_role.return_value = {
            "principal_ip": ASResponse.OK
        }
        line = "test-role priv read write 111"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["read"],
            whitelist=[],
            read_quota=None,
            write_quota=111,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_called_with(
            "Successfully created role test-role."
        )

    def test_logs_error_when_quotas_are_not_int(self):
        log_message = "Quotas must be integers."
        line = "test-role priv write write 100a read 100"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_not_called()
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

        line = "test-role priv write write 100 read 100a"

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_not_called()
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

    def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASProtocolError(ASResponse.ROLE_ALREADY_EXISTS, "test-message")
        log_message = "test-message : Role already exists."
        line = "test-role priv sys-admin"
        self.cluster_mock.admin_create_role.return_value = {"principal_ip": as_error}

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["sys-admin"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes=["principal"],
        )
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

    def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "test-role priv sys-admin"
        self.cluster_mock.admin_create_role.return_value = {"principal_ip": as_error}

        test_util.assert_exception(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.admin_create_role.assert_called_with(
            "test-role",
            privileges=["sys-admin"],
            whitelist=[],
            read_quota=None,
            write_quota=None,
            nodes=["principal"],
        )
        self.view_mock.print_result.assert_not_called()


class ManageACLRateLimitControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = LiveClusterRootController()
        self.controller = ManageACLQuotasRoleController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLQuotasRoleController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.mods = {"like": [], "with": [], "for": [], "line": []}

        self.cluster_mock.info_build_version.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def test_logs_error_when_server_does_not_support_quotas(self):
        log_message = "'manage quotas' is not supported on aerospike versions <= 5.5"
        line = "role test-role read 100 write 200"
        self.cluster_mock.info_build_version.side_effect = [
            {"principal": "5.5.0.0"},
            {"principal": "5.5.9.9"},
        ]
        self.cluster_mock.get_expected_principal.side_effect = ["principal"] * 2
        self.cluster_mock.admin_set_quotas.side_effect = [
            {"principal_ip": ASResponse.OK}
        ] * 2

        for _ in range(2):
            self.controller.execute(line.split())
            self.logger_mock.error.assert_called_with(log_message)

    def test_logs_error_with_read_and_write_not_provided(self):
        log_message = "'read' or 'write' is required."

        self.controller.execute(["role", "test-role"])

        self.logger_mock.error.assert_called_with(log_message)

    def test_success_with_read_and_write(self):
        log_message = "Successfully set quotas for role test-role."
        line = "role test-role read 100 write 200"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=200, nodes=["principal"]
        )
        self.view_mock.print_result.assert_called_with(log_message)

    def test_success_with_just_read(self):
        log_message = "Successfully set quota for role test-role."
        line = "role test-role read 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=None, nodes=["principal"]
        )
        self.view_mock.print_result.assert_called_with(log_message)

    def test_success_with_just_write(self):
        log_message = "Successfully set quota for role test-role."
        line = "role test-role write 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=None, write_quota=100, nodes=["principal"]
        )
        self.view_mock.print_result.assert_called_with(log_message)

    def test_correct_call_with_conflicting_read_role_and_read_quota(self):
        line = "role read read 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "read", read_quota=100, write_quota=None, nodes=["principal"]
        )

    def test_correct_call_with_conflicting_write_role_and_write_quota(self):
        line = "role write write 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "write", read_quota=None, write_quota=100, nodes=["principal"]
        )

    def test_correct_call_with_conflicting_write_role_and_read_quota(self):
        line = "role write read 100"
        self.cluster_mock.admin_set_quotas.return_value = {
            "principal_ip": ASResponse.OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "write", read_quota=100, write_quota=None, nodes=["principal"]
        )

    def test_logs_error_when_quotas_are_not_int(self):
        log_message = "Quotas must be integers."
        line = "role test-role write 100a read 100"

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_not_called()
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

        line = "role test-role write 100 read 100a"

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_not_called()
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

    def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASProtocolError(ASResponse.RATE_QUOTA_EXCEEDED, "test-message")
        log_message = "test-message : Rate quota exceeded."
        line = "role test-role write 100 read 100"
        self.cluster_mock.admin_set_quotas.return_value = {"principal_ip": as_error}

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=100, nodes=["principal"]
        )
        self.logger_mock.error.assert_called_with(log_message)
        self.view_mock.print_result.assert_not_called()

    def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "role test-role write 100 read 100"
        self.cluster_mock.admin_set_quotas.return_value = {"principal_ip": as_error}

        test_util.assert_exception(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=100, nodes=["principal"]
        )
        self.view_mock.print_result.assert_not_called()
