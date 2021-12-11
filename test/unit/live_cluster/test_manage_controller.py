from lib.live_cluster.client import (
    ASINFO_RESPONSE_OK,
    ASInfoClusterStableError,
    ASInfoError,
)
from lib.base_controller import ShellException
import unittest
from mock import MagicMock, patch
from mock.mock import call

from lib.live_cluster.client import ASProtocolError, ASResponse
from lib.live_cluster.manage_controller import (
    ManageACLCreateRoleController,
    ManageACLCreateUserController,
    ManageACLQuotasRoleController,
    ManageConfigController,
    ManageConfigLeafController,
    ManageJobsKillAllScansController,
    ManageJobsKillTridController,
    ManageQuiesceController,
    ManageReclusterController,
    ManageReviveController,
    ManageRosterAddController,
    ManageRosterLeafCommandController,
    ManageRosterRemoveController,
    ManageRosterStageNodesController,
    ManageRosterStageObservedController,
    ManageTruncateController,
)
from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController
from test.unit import util as test_util


class ManageACLCreateUserControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageACLCreateUserController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLCreateUserController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

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
        line = "test-user password pass"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        self.cluster_mock.admin_create_user.return_value = {"principal_ip": as_error}

        self.controller.execute(line.split())

        self.cluster_mock.admin_create_user.assert_called_with(
            "test-user", "pass", [], nodes=["principal"]
        )
        self.logger_mock.error.assert_called_with(as_error)
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
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageACLCreateRoleController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLCreateRoleController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def test_logs_error_when_server_does_not_support_quotas(self):
        log_message = "'read' and 'write' modifiers are not supported on aerospike versions <= 5.5"
        line = "test-role priv test-priv read 100 write 200"
        self.cluster_mock.info_build.side_effect = [
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
        self.logger_mock.error.assert_called_with(as_error)
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


class ManageACLQuotasControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageACLQuotasRoleController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageACLQuotasRoleController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def test_logs_error_when_server_does_not_support_quotas(self):
        log_message = "'manage quotas' is not supported on aerospike versions <= 5.5"
        line = "role test-role read 100 write 200"
        self.cluster_mock.info_build.side_effect = [
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
        line = "role test-role write 100 read 100"
        self.cluster_mock.admin_set_quotas.return_value = {"principal_ip": as_error}

        self.controller.execute(line.split())

        self.cluster_mock.admin_set_quotas.assert_called_with(
            "test-role", read_quota=100, write_quota=100, nodes=["principal"]
        )
        self.logger_mock.error.assert_called_with(as_error)
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


class ManageConfigControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageConfigController()
        ManageConfigLeafController.mods = {}
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageConfigLeafController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageConfigLeafController.prompt_challenge"
        ).start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def test_logging_prompt(self):
        line = (
            "logging file test-file param test-param to test-value with 1.1.1.1 2.2.2.2"
        )
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change logging context test-param to test-value for file test-file"
        )
        self.cluster_mock.info_set_config_logging.assert_not_called()

    def test_logging_success(self):
        line = (
            "logging file test-file param test-param to test-value with 1.1.1.1 2.2.2.2"
        )
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_logging.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_logging.assert_called_once_with(
            "test-file", "test-param", "test-value", nodes=["1.1.1.1", "2.2.2.2"]
        )
        title = "Set Logging Context test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_service_prompt(self):
        line = "service param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change service param test-param to test-value"
        )
        self.cluster_mock.info_set_config_service.assert_not_called()

    def test_service_success(self):
        line = "service param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_service.return_value = resp
        mods = {
            "with": ["1.1.1.1", "2.2.2.2"],
            "param": [],
            "to": [],
            "line": [],
        }

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_service.assert_called_once_with(
            "test-param", "test-value", nodes=["1.1.1.1", "2.2.2.2"]
        )
        title = "Set Service Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **mods
        )

    def test_network_subcontext_required(self):
        line = "network param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with("Subcontext required.")
        self.cluster_mock.info_set_config_network.assert_not_called()

    def test_network_prompt(self):
        line = "network sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change network sub-context param test-param to test-value"
        )
        self.cluster_mock.info_set_config_network.assert_not_called()

    def test_network_success(self):
        line = "network sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_network.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_network.assert_called_once_with(
            "test-param", "test-value", "sub-context", nodes=["1.1.1.1", "2.2.2.2"]
        )
        title = "Set Network Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_security_prompt_with_subcontext(self):
        line = (
            "security sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        )
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change security sub-context param test-param to test-value"
        )
        self.cluster_mock.info_set_config_security.assert_not_called()

    def test_security_prompt(self):
        line = "security param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change security param test-param to test-value"
        )
        self.cluster_mock.info_set_config_security.assert_not_called()

    def test_security_success(self):
        line = (
            "security sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        )
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_security.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_security.assert_called_once_with(
            "test-param", "test-value", "sub-context", nodes=["1.1.1.1", "2.2.2.2"]
        )
        title = "Set Security Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_namespace_prompt_with_subcontext(self):
        line = "namespace test-ns sub-context param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change namespace test-ns sub-context param test-param to test-value"
        )
        self.cluster_mock.info_set_config_namespace.assert_not_called()

    def test_namespace_prompt(self):
        line = "namespace test-ns param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change namespace test-ns param test-param to test-value"
        )
        self.cluster_mock.info_set_config_namespace.assert_not_called()

    def test_namespace_success(self):
        line = "namespace test-ns sub-context param rack-id to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_namespace.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_namespace.assert_called_once_with(
            "rack-id",
            "test-value",
            "test-ns",
            subcontext="sub-context",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set Namespace Param rack-id to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )
        self.view_mock.print_result.assert_called_once_with(
            'Run "manage recluster" for your changes to rack-id to take affect.'
        )

    def test_namespace_success_with_pair(self):
        line = "namespace test-ns sub-context param compression-level to test-value with 1.1.1.1 2.2.2.2"

        self.controller.execute(line.split())

        self.view_mock.print_result.assert_called_once_with(
            'The parameter "enable-compression" must also be set.'
        )

    def test_set_prompt(self):
        line = "namespace test-ns set test-set param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change namespace test-ns set test-set param test-param to test-value"
        )
        self.cluster_mock.info_set_config_namespace.assert_not_called()

    def test_set_success(self):
        line = "namespace test-ns set test-set param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_namespace.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_namespace.assert_called_once_with(
            "test-param",
            "test-value",
            "test-ns",
            set_="test-set",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set Namespace Set Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_XDR_prompt(self):
        line = "xdr param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change XDR param test-param to test-value"
        )
        self.cluster_mock.info_set_config_xdr.assert_not_called()

    def test_XDR_success(self):
        line = "xdr param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr.assert_called_once_with(
            "test-param",
            "test-value",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set XDR Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_XDR_create_dc_prompt(self):
        line = "xdr create dc test-dc with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Create XDR DC test-dc")
        self.cluster_mock.info_set_config_xdr_create_dc.assert_not_called()

    def test_XDR_create_dc_success(self):
        line = "xdr create dc test-dc with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_create_dc.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_create_dc.assert_called_once_with(
            "test-dc",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Create XDR DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_XDR_delete_dc_prompt(self):
        line = "xdr delete dc test-dc with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Delete XDR DC test-dc")
        self.cluster_mock.info_set_config_xdr_delete_dc.assert_not_called()

    def test_XDR_delete_dc_success(self):
        line = "xdr delete dc test-dc with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_delete_dc.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_delete_dc.assert_called_once_with(
            "test-dc",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Delete XDR DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_XDR_dc_prompt(self):
        line = "xdr dc test-dc param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change XDR DC test-dc param test-param to test-value"
        )
        self.cluster_mock.info_set_config_xdr.assert_not_called()

    def test_XDR_dc_success(self):
        line = "xdr dc test-dc param auth-user to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr.assert_called_once_with(
            "auth-user",
            "test-value",
            dc="test-dc",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set XDR DC Param auth-user to test-value"
        self.view_mock.print_info_responses(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )
        self.view_mock.print_result.assert_called_once_with(
            'The parameter "auth-password-file" must also be set.'
        )

    def test_XDR_dc_add_node_prompt(self):
        line = "xdr dc test-dc add node 3.3.3.3 with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Add node 3.3.3.3 to DC test-dc")
        self.cluster_mock.info_set_config_xdr_add_node.assert_not_called()

    def test_XDR_dc_add_node_success(self):
        line = "xdr dc test-dc add node 3.3.3.3 with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_add_node.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_add_node.assert_called_once_with(
            "test-dc",
            "3.3.3.3",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Add XDR Node 3.3.3.3 to DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_XDR_dc_remove_node_prompt(self):
        line = "xdr dc test-dc remove node 3.3.3.3 with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Remove node 3.3.3.3 from DC test-dc")
        self.cluster_mock.info_set_config_xdr_remove_node.assert_not_called()

    def test_XDR_dc_remove_node_success(self):
        line = "xdr dc test-dc remove node 3.3.3.3 with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_remove_node.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_remove_node.assert_called_once_with(
            "test-dc",
            "3.3.3.3",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Remove XDR Node 3.3.3.3 from DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_XDR_dc_add_namespace_prompt(self):
        line = "xdr dc test-dc add namespace test-env with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("Add namespace test-env to DC test-dc")
        self.cluster_mock.info_set_config_xdr_add_namespace.assert_not_called()

    def test_XDR_dc_add_namespace_with_rewind_prompt(self):
        line = "xdr dc test-dc add namespace test-env rewind all with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Add namespace test-env to DC test-dc with rewind all"
        )
        self.cluster_mock.info_set_config_xdr_add_namespace.assert_not_called()

    def test_XDR_dc_add_namespace_success(self):
        line = "xdr dc test-dc add namespace test-ns with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_add_namespace.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_add_namespace.assert_called_once_with(
            "test-dc",
            "test-ns",
            None,
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Add XDR Namespace test-ns to DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_XDR_dc_remove_namespace_prompt(self):
        line = "xdr dc test-dc remove namespace test-ns with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Remove namespace test-ns from DC test-dc"
        )
        self.cluster_mock.info_set_config_xdr_remove_namespace.assert_not_called()

    def test_XDR_dc_remove_namespace_success(self):
        line = "xdr dc test-dc remove namespace test-ns with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr_remove_namespace.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr_remove_namespace.assert_called_once_with(
            "test-dc",
            "test-ns",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Remove XDR Namespace test-ns from DC test-dc"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )

    def test_XDR_dc_namespace_prompt(self):
        line = "xdr dc test-dc namespace test-ns param test-param to test-value with 1.1.1.1 2.2.2.2"
        self.prompt_mock.return_value = False
        ManageConfigLeafController.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "Change XDR DC test-dc namespace test-ns param test-param to test-value"
        )
        self.cluster_mock.info_set_config_xdr.assert_not_called()

    def test_XDR_dc_namespace_success(self):
        line = "xdr dc test-dc namespace test-ns param test-param to test-value with 1.1.1.1 2.2.2.2"
        resp = {"1.1.1.1": ASINFO_RESPONSE_OK, "2.2.2.2": "ASInfoConfigError"}
        self.cluster_mock.info_set_config_xdr.return_value = resp

        self.controller.execute(line.split())

        self.cluster_mock.info_set_config_xdr.assert_called_once_with(
            "test-param",
            "test-value",
            dc="test-dc",
            namespace="test-ns",
            nodes=["1.1.1.1", "2.2.2.2"],
        )
        title = "Set XDR Namespace Param test-param to test-value"
        self.view_mock.print_info_responses.assert_called_once_with(
            title, resp, self.cluster_mock, **ManageConfigLeafController.mods
        )


class ManageTruncateControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageTruncateController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageTruncateController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageTruncateController.prompt_challenge"
        ).start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def test_parse_lut_with_incorrect_before_len(self):
        self.controller.mods = {"before": ["12344352"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual(
            'Last update time must be followed by "unix-epoch" or "iso-8601".',
            error,
        )

        self.controller.mods = {"before": ["12344352", "unix-epoch", "extra"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual(
            'Last update time must be followed by "unix-epoch" or "iso-8601".',
            error,
        )

    def test_parse_lut_with_incorrect_epoch_format(self):
        self.controller.mods = {"before": ["12345v6789", "unix-epoch"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual("Invalid unix-epoch format.", error)

    def test_parse_lut_with_date_too_new(self):
        self.controller.mods = {"before": ["12345678900", "unix-epoch"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNotNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual("Date provided is too far in the future.", error)

        self.controller.mods = {"before": ["2483-05-30T04:26:40Z", "iso-8601"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNotNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual("Date provided is too far in the future.", error)

    def test_parse_lut_with_date_too_old(self):
        self.controller.mods = {"before": ["123456789", "unix-epoch"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNotNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual("Date provided is too far in the past.", error)

        self.controller.mods = {"before": ["1970-05-30T04:26:40Z", "iso-8601"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNotNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual("Date provided is too far in the past.", error)

    def test_parse_lut_with_incorrect_iso_format(self):
        self.controller.mods = {"before": ["123", "iso-8601"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual("Invalid iso-8601 format.", error)

    def test_parse_lut_with_iso_without_timezone(self):
        self.controller.mods = {"before": ["2020-05-04T04:20:40", "iso-8601"]}

        lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

        self.assertIsNotNone(lut_datetime)
        self.assertIsNone(lut_epoch_time)
        self.assertEqual("iso-8601 format must contain a timezone.", error)

    def test_parse_lut_iso_gives_correct_epoch_time(self):
        input_output = [
            ("2021-05-04T22:44:05Z", "1620168245000000000"),
            ("2021-05-04T22:44:05-07:00", "1620193445000000000"),
            ("2021-05-04T23:54:30.123456+00:00", "1620172470123456000"),
            ("2021-05-04T22:54:30.123456-01:00", "1620172470123456000"),
            ("2021-05-04T00:54:30.123456+01:00", "1620086070123456000"),
            ("20210503T195430.123456-0400", "1620086070123456000"),
            ("2021-05-04T11:40:34.100-12:00", "1620171634100000000"),
        ]

        for input, output in input_output:
            self.controller.mods = {"before": [input, "iso-8601"]}
            lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

            self.logger_mock.error.assert_not_called()
            self.assertEqual(lut_epoch_time, output)
            self.assertFalse(error)

    def test_parse_lut_epoch_gives_correct_epoch_time(self):
        input_output = [
            ("1234567899", "1234567899000000000"),
            ("1234567899.123456789", "1234567899123456789"),
            ("1234567899.123", "1234567899123000000"),
        ]

        for input, output in input_output:
            self.controller.mods = {"before": [input, "unix-epoch"]}
            lut_datetime, lut_epoch_time, error = self.controller._parse_lut()

            self.logger_mock.error.assert_not_called()
            self.assertEqual(lut_epoch_time, output)
            self.assertFalse(error)

    def test_get_namespace_master_objects(self):
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

        master_objects = self.controller._get_namespace_master_objects("test-ns")

        self.cluster_mock.info_namespace_statistics.assert_called_with(
            "test-ns", nodes="all"
        )
        self.assertEqual(master_objects, str(33 + 44 + 55))

    def test_get_set_master_objects(self):
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

        master_objects = self.controller._get_set_master_objects("test-ns", "test-set")

        self.cluster_mock.info_set_statistics.assert_called_with(
            "test-ns", "test-set", nodes="all"
        )
        self.assertEqual(master_objects, str((11 + 55 + 66) // 11))

    def test_returns_on_lut_error(self):
        line = "ns test before 123456789 unix-epoch"

        self.controller.execute(line.split())

        self.logger_mock.error.assert_called_with(
            "Date provided is too far in the past."
        )
        self.cluster_mock.info_truncate.assert_not_called()

    @patch(
        "lib.live_cluster.manage_controller.ManageTruncateController._get_namespace_master_objects"
    )
    def test_prompts_error_without_lut(self, _get_namespace_master_objects_mock):
        _get_namespace_master_objects_mock.return_value = 50
        self.controller.warn = True
        self.prompt_mock.side_effect = lambda x: False
        line = "ns test"

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You're about to truncate up to 50 records from namespace test"
        )

    @patch(
        "lib.live_cluster.manage_controller.ManageTruncateController._get_set_master_objects"
    )
    def test_prompts_error_without_lut_or_set(self, _get_set_master_objects_mock):
        _get_set_master_objects_mock.return_value = 60
        self.controller.warn = True
        self.prompt_mock.side_effect = lambda x: False

        line = "ns test set test-set"

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You're about to truncate up to 60 records from set test-set for namespace test"
        )

    @patch(
        "lib.live_cluster.manage_controller.ManageTruncateController._get_set_master_objects"
    )
    def test_prompts_error_with_lut(self, _get_set_master_objects_mock):
        _get_set_master_objects_mock.return_value = 60
        self.controller.warn = True
        self.prompt_mock.side_effect = lambda x: False

        line = "ns test set test-set before 1620690614 unix-epoch"

        self.controller.execute(line.split())

        # Fails with pytest when you add -s
        self.prompt_mock.assert_called_with(
            "You're about to truncate up to 60 records from set test-set for namespace test with LUT before 23:50:14.000000 UTC on May 10, 2021"
        )

    def test_success_with_no_set(self):
        self.cluster_mock.info_truncate.return_value = {"principal": "not an error"}
        line = "ns test before 1620690614 unix-epoch"

        self.controller.execute(line.split())

        self.cluster_mock.info_truncate.assert_called_with(
            "test", None, "1620690614000000000", nodes="principal"
        )
        self.logger_mock.error.assert_not_called()
        self.view_mock.print_result.assert_called_with(
            "Successfully started truncation for namespace test"
        )

    def test_success_with_set(self):
        self.cluster_mock.info_truncate.return_value = {"principal": "not an error"}
        line = "ns test set test-set before 1620690614 unix-epoch --no-warn"

        self.controller.execute(line.split())

        self.cluster_mock.info_truncate.assert_called_with(
            "test", "test-set", "1620690614000000000", nodes="principal"
        )
        self.logger_mock.error.assert_not_called()
        self.view_mock.print_result.assert_called_with(
            "Successfully started truncation for set test-set of namespace test"
        )

    def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASInfoError("An error message", "test-resp")
        line = "ns test set test-set before 1620690614 unix-epoch --no-warn"
        self.cluster_mock.info_truncate.return_value = {"principal_ip": as_error}

        self.controller.execute(line.split())

        self.cluster_mock.info_truncate.assert_called_with(
            "test", "test-set", "1620690614000000000", nodes="principal"
        )
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "ns test set test-set before 1620690614 unix-epoch --no-warn"
        self.cluster_mock.info_truncate.return_value = {"principal_ip": as_error}

        test_util.assert_exception(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.info_truncate.assert_called_with(
            "test", "test-set", "1620690614000000000", nodes="principal"
        )
        self.view_mock.print_result.assert_not_called()


class ManageTruncateUndoControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageTruncateController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageTruncateController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageTruncateController.prompt_challenge"
        ).start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def test_warn_prompt_and_return(self):
        self.controller.warn = True
        self.prompt_mock.return_value = False
        line = "ns test undo"

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with("")
        self.cluster_mock.info_truncate_undo.assert_not_called()

    def test_success_with_ns(self):
        line = "undo ns test"
        self.cluster_mock.info_truncate_undo.return_value = {
            "principal-ip": ASINFO_RESPONSE_OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.info_truncate_undo.assert_called_once_with(
            "test", None, nodes="principal"
        )
        self.view_mock.print_result.assert_called_once_with(
            "Successfully triggered undoing truncation for namespace test on next cold restart"
        )

    def test_success_with_set(self):
        line = "undo ns test set test-set"
        self.cluster_mock.info_truncate_undo.return_value = {
            "principal-ip": ASINFO_RESPONSE_OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.info_truncate_undo.assert_called_once_with(
            "test", "test-set", nodes="principal"
        )
        self.view_mock.print_result.assert_called_once_with(
            "Successfully triggered undoing truncation for set test-set of namespace test on next cold restart"
        )

    def test_logs_error_when_asprotocol_error_returned(self):
        as_error = ASInfoError("An error message", "test-resp")
        line = "ns test set test-set undo"
        self.cluster_mock.info_truncate_undo.return_value = {"principal_ip": as_error}

        self.controller.execute(line.split())

        self.cluster_mock.info_truncate_undo.assert_called_with(
            "test", "test-set", nodes="principal"
        )
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = "undo ns test set test-set"
        self.cluster_mock.info_truncate_undo.return_value = {"principal_ip": as_error}

        test_util.assert_exception(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.info_truncate_undo.assert_called_with(
            "test", "test-set", nodes="principal"
        )
        self.view_mock.print_result.assert_not_called()


class ManageReclusterControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageReclusterController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageReclusterController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

        self.cluster_mock.info_build.return_value = {"principal": "5.6.0.0"}
        self.cluster_mock.get_expected_principal.return_value = "principal"

        self.addCleanup(patch.stopall)

    def test_success(self):
        line = ""
        self.cluster_mock.info_recluster.return_value = {
            "principal-ip": ASINFO_RESPONSE_OK
        }

        self.controller.execute(line.split())

        self.cluster_mock.info_recluster.assert_called_once_with(nodes="principal")
        self.view_mock.print_result.assert_called_once_with(
            "Successfully started recluster"
        )

    def test_logs_error_when_asinfo_error_returned(self):
        as_error = ASInfoError("An error message", "test-resp")
        line = ""
        self.cluster_mock.info_recluster.return_value = {"principal_ip": as_error}

        self.controller.execute(line.split())

        self.cluster_mock.info_recluster.assert_called_with(nodes="principal")
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.print_result.assert_not_called()

    def test_raises_exception_when_exception_returned(self):
        as_error = IOError("test-message")
        line = ""
        self.cluster_mock.info_recluster.return_value = {"principal_ip": as_error}

        test_util.assert_exception(
            self, ShellException, "test-message", self.controller.execute, line.split()
        )

        self.cluster_mock.info_recluster.assert_called_with(nodes="principal")
        self.view_mock.print_result.assert_not_called()


class ManageQuiesceControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageQuiesceController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageQuiesceController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    def test_success(self):
        line = "with 1.1.1.1"
        self.cluster_mock.info_quiesce.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}
        mods = {"with": ["1.1.1.1"], "undo": [], "line": []}

        self.controller.execute(line.split())

        self.cluster_mock.info_quiesce.assert_called_once_with(nodes=["1.1.1.1"])
        self.view_mock.print_info_responses.assert_called_once_with(
            "Quiesce Nodes", {"1.1.1.1": ASINFO_RESPONSE_OK}, self.cluster_mock, **mods
        )
        self.view_mock.print_result.assert_called_once_with(
            'Run "manage recluster" for your changes to take affect.'
        )

    def test_success_with_undo(self):
        line = "with 1.1.1.1 2.2.2.2 undo"
        self.cluster_mock.info_quiesce_undo.return_value = {
            "1.1.1.1": ASINFO_RESPONSE_OK
        }
        mods = {"with": ["1.1.1.1", "2.2.2.2"], "undo": [], "line": []}

        self.controller.execute(line.split())

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
            'Run "manage recluster for your changes to take affect.'
        )


class ManageReviveControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageReviveController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.prompt_challenge"
        ).start()

        self.addCleanup(patch.stopall)

    def test_success(self):
        line = "ns test"
        self.cluster_mock.info_revive.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

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
            'Run "manage recluster" for your changes to take affect.'
        )

    def test_warn_prompt_returns_false(self):
        line = "ns test"
        self.prompt_mock.return_value = False
        self.controller.warn = True

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "You are about to revive namespace test"
        )

    def test_warn_prompt_returns_true(self):
        line = "ns test"
        self.prompt_mock.return_value = True
        self.controller.warn = True
        self.cluster_mock.info_revive.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_once_with(
            "You are about to revive namespace test"
        )
        self.cluster_mock.info_revive.assert_called_once()


class ManageJobsKillTridControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageJobsKillTridController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillTridController.cluster"
        ).start()
        self.getter_mock = patch(
            "lib.live_cluster.manage_controller.GetJobsController"
        ).start()
        self.controller.getter = self.getter_mock
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillTridController.prompt_challenge"
        ).start()

        self.addCleanup(patch.stopall)

    def test_kill_trids(self):
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

        self.controller.execute(trids)

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

    def test_kill_same_trid_on_multiple_hosts(self):
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

        self.controller.execute(trids)

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

    def test_kill_trids_warn(self):
        trids = ["123", "789", "101", "456"]
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.controller._kill_trid = MagicMock()
        self.getter_mock.get_all.return_value = {
            "scan": {
                "1.1.1.1": {
                    "123": {"trid": "123"},
                }
            },
        }

        self.controller.execute(trids)

        self.prompt_mock.assert_called_with(
            "You're about to kill the following transactions: 123, 789, 101, 456"
        )
        self.controller._kill_trid.assert_not_called()


class ManageJobsKillAllControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageJobsKillAllScansController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillAllScansController.cluster"
        ).start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageJobsKillAllScansController.prompt_challenge"
        ).start()
        self.addCleanup(patch.stopall)

    def test_kill_all_scans(self):
        module = "scan"
        self.cluster_mock.info_scan_abort_all.return_value = {"1.1.1.1": "ok"}

        self.controller.execute(module.split())

        self.cluster_mock.info_scan_abort_all.assert_called_with(nodes="all")

    def test_kill_all_warn(self):
        module = "scans"
        self.controller.warn = True
        self.prompt_mock.return_value = False

        self.controller.execute(module.split())

        self.prompt_mock.assert_called_with(
            "You're about to kill all scan jobs on all nodes."
        )
        self.cluster_mock.info_scan_abort_all.assert_not_called()


class ManageRosterLeafCommandControllerTest(unittest.TestCase):
    def setUp(self):
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController.cluster"
        ).start()
        self.controller = ManageRosterLeafCommandController(self.cluster_mock)
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()

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
                    "3.3.3.3": ASInfoClusterStableError("", "foo"),
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
                    "The cluster is unstable. It is advised that you do not manage the roster. Run 'info network' for more information."
                )

        test_util.assert_exception(
            self,
            ASInfoError,
            None,
            self.controller._check_and_log_cluster_stable,
            {
                "1.1.1.1": "ABC",
                "2.2.2.2": "ABC",
                "3.3.3.3": ASInfoError("", "foo"),
            },
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


class ManageRosterAddControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageRosterAddController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
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

    def test_success(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": []}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["GHI", "ABC@rack1", "DEF@rack2"], nodes="principal"
        )
        self.view_mock.print_result.assert_any_call(
            "Node(s) successfully added to pending-roster."
        )
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take affect.'
        )

    def test_logs_error_from_roster(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        error = ASInfoError("blah", "error::foo")
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    def test_logs_error_from_roster_set(self):
        error = ASInfoError("blah", "error::foo")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": []}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    def test_raises_error_from_roster(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        test_util.assert_exception(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    def test_raises_error_from_roster_set(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": []}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        test_util.assert_exception(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    def test_warn_returns_false(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": ["foo"]}
        }

        self.controller.execute(line.split())

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

    def test_warn_returns_true(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = True
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["GHI"], "observed_nodes": ["bar"]}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

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


class ManageRosterRemoveControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageRosterRemoveController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster"
        ).start()
        self.check_and_log_cluster_stable_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController._check_and_log_cluster_stable"
        ).start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.prompt_challenge"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()

    def test_success(self):
        line = "nodes ABC ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["ABC", "DEF"], "observed_nodes": []}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["DEF"], nodes="principal"
        )
        self.view_mock.print_result.assert_any_call(
            "Node(s) successfully removed from pending-roster."
        )
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take affect.'
        )

    def test_logs_error_from_roster(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test  --no-warn"
        error = ASInfoError("blah", "error::foo")
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    def test_logs_error_from_roster_set(self):
        error = ASInfoError("blah", "error::foo")
        line = "nodes ABC@rack1 DEF@rack2 ns test  --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["ABC@rack1", "DEF@rack2", "GHI"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    def test_logs_error_when_node_not_in_pending(self):
        line = "nodes GHI ns test"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"pending_roster": ["ABC", "DEF"], "observed_nodes": []}
        }
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "CDEF"}
        self.prompt_mock.return_value = False
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

        self.logger_mock.warning.assert_any_call(
            "The following nodes are not in the pending-roster: {}", "GHI"
        )
        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "CDEF"}
        )
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    def test_raises_error_from_roster(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        test_util.assert_exception(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    def test_raises_error_from_roster_set(self):
        error = Exception("test exception")
        line = "nodes ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["GHI", "ABC@rack1", "DEF@rack2"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        test_util.assert_exception(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    def test_warn_returns_false(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["ABC@rack1", "DEF@rack2", "GHI"],
                "observed_nodes": [],
            }
        }

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI"
        )
        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.cluster_mock.info_roster_set.assert_not_called()

    def test_warn_returns_true(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = True
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "pending_roster": ["ABC@rack1", "DEF@rack2", "GHI"],
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI"
        )
        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.cluster_mock.info_roster_set.assert_called_once()


class ManageRosterStageNodesControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageRosterStageNodesController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
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

    def test_success(self):
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC@rack1", "DEF@rack2"], nodes="principal"
        )
        self.view_mock.print_result.assert_any_call("Pending roster successfully set.")
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take affect.'
        )

    def test_logs_error_from_roster_set(self):
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        error = ASInfoError("blah", "error::foo")
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC@rack1", "DEF@rack2"], nodes="principal"
        )

        self.logger_mock.error.assert_called_once_with(error)
        self.view_mock.print_result.assert_not_called()

    def test_raises_error_from_roster_set(self):
        error = Exception("test exception")
        line = "ABC@rack1 DEF@rack2 ns test --no-warn"
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": [],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        test_util.assert_exception(
            self, Exception, "test exception", self.controller.execute, line.split()
        )

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC@rack1", "DEF@rack2"], nodes="principal"
        )
        self.logger_mock.error.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    def test_warn_returns_false(self):
        line = "ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": [],
            }
        }

        self.controller.execute(line.split())

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

    def test_warn_returns_true(self):
        line = "ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = True
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {
                "observed_nodes": ["jar"],
            }
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

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


class ManageRosterStageObservedControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        patch("lib.live_cluster.live_cluster_root_controller.Cluster").start()
        self.root_controller = await LiveClusterRootController()
        self.controller = ManageRosterStageObservedController()
        self.cluster_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.cluster"
        ).start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.prompt_mock = patch(
            "lib.live_cluster.manage_controller.ManageLeafCommandController.prompt_challenge"
        ).start()
        self.check_and_log_cluster_stable_mock = patch(
            "lib.live_cluster.manage_controller.ManageRosterLeafCommandController._check_and_log_cluster_stable"
        ).start()
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    def test_success(self):
        line = "ns test"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["ABC", "DEF"]}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC", "DEF"], nodes="principal"
        )
        self.view_mock.print_result.assert_any_call(
            "Pending roster now contains observed nodes."
        )
        self.view_mock.print_result.assert_any_call(
            'Run "manage recluster" for your changes to take affect.'
        )

    def test_logs_error_from_roster(self):
        line = "ns test"
        error = ASInfoError("blah", "error::foo")
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        self.controller.execute(line.split())

        self.logger_mock.error.assert_called_once_with(error)
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    def test_logs_error_from_roster_set(self):
        line = "ns test"
        error = ASInfoError("blah", "error::foo")
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["ABC", "DEF"]}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        self.controller.execute(line.split())

        self.cluster_mock.info_roster_set.assert_called_once_with(
            "test", ["ABC", "DEF"], nodes="principal"
        )
        self.logger_mock.error.assert_called_once_with(error)
        self.view_mock.print_result.assert_not_called()

    def test_raises_error_from_roster(self):
        error = Exception("test exception")
        line = "ns test"
        self.cluster_mock.info_roster.return_value = {"1.1.1.1": error}

        test_util.assert_exception(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_not_called()
        self.view_mock.print_result.assert_not_called()

    def test_raises_error_from_roster_set(self):
        error = Exception("test exception")
        line = "ns test"
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["GHI", "ABC@rack1", "DEF@rack2"]}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": error}

        test_util.assert_exception(
            self, Exception, "test exception", self.controller.execute, line.split()
        )
        self.logger_mock.error.assert_not_called()
        self.cluster_mock.info_roster_set.assert_called_once()
        self.view_mock.print_result.assert_not_called()

    def test_warn_returns_false(self):
        line = "ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = False
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["GHI", "ABC@rack1", "DEF@rack2"]}
        }

        self.controller.execute(line.split())

        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI, ABC@rack1, DEF@rack2"
        )
        self.cluster_mock.info_roster_set.assert_not_called()

    def test_warn_returns_true(self):
        line = "nodes ABC@rack1 DEF@rack2 ns test"
        self.controller.warn = True
        self.prompt_mock.return_value = True
        self.cluster_mock.info_cluster_stable.return_value = {"1.1.1.1": "ABCDEF"}
        self.cluster_mock.info_roster.return_value = {
            "1.1.1.1": {"observed_nodes": ["GHI", "ABC@rack1", "DEF@rack2"]}
        }
        self.cluster_mock.info_roster_set.return_value = {"1.1.1.1": ASINFO_RESPONSE_OK}

        self.controller.execute(line.split())

        self.check_and_log_cluster_stable_mock.assert_called_once_with(
            {"1.1.1.1": "ABCDEF"}
        )
        self.prompt_mock.assert_called_with(
            "You are about to set the pending-roster for namespace test to: GHI, ABC@rack1, DEF@rack2"
        )
        self.cluster_mock.info_roster_set.assert_called_once()
