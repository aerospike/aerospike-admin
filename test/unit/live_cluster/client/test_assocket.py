import socket
import unittest2 as unittest
from mock import patch

from test.unit import util
from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client import ASProtocolError, ASResponse
from lib.utils.constants import AuthMode


class ASSocketTestConnect(unittest.TestCase):
    def setUp(self) -> None:
        self.as_socket = ASSocket(
            "1.2.3.4",
            999,
            "tls-name",
            "test-user",
            "test-password",
            AuthMode.INTERNAL,
            False,
        )

        socket_module_mock = patch("socket.socket").start()
        self.socket_mock = socket_module_mock.return_value
        self.as_socket.sock = self.socket_mock

    @patch("socket.socket")
    @patch("socket.getaddrinfo")
    def test_can_connect(self, getaddrinfo_mock, socket_module_mock):
        getaddrinfo_mock.return_value = [
            ("family1", "socktype1", "proto1", "canonname1", "sockaddr1"),
            ("family2", "socktype2", "proto2", "canonname2", "sockaddr2"),
        ]

        self.assertTrue(self.as_socket.connect())

        socket_module_mock.assert_called_with("family1", socket.SOCK_STREAM)
        socket_mock = socket_module_mock.return_value
        socket_mock.connect.assert_called_with("sockaddr1")
        self.assertEqual(self.as_socket.sock, socket_mock)

    @patch("socket.socket")
    @patch("socket.getaddrinfo")
    @patch("lib.live_cluster.client.assocket.SSL.Connection")
    def test_can_connect_with_ssl_context(
        self, ssl_connect_mock, getaddrinfo_mock, socket_module_mock
    ):
        self.as_socket.ssl_context = True
        getaddrinfo_mock.return_value = [
            ("family1", "socktype1", "proto1", "canonname1", "sockaddr1"),
            ("family2", "socktype2", "proto2", "canonname2", "sockaddr2"),
        ]

        self.assertTrue(self.as_socket.connect())

        socket_module_mock.assert_called_with("family1", socket.SOCK_STREAM)
        socket_mock = socket_module_mock.return_value
        socket_mock.settimeout.assert_called_with(self.as_socket._timeout)
        ssl_connect_mock.assert_called_with(True, socket_mock)
        socket_mock = ssl_connect_mock.return_value
        socket_mock.connect.assert_called_with("sockaddr1")
        socket_mock.set_app_data.assert_called_with("tls-name")
        socket_mock.do_handshake.assert_called_once()
        self.assertEqual(self.as_socket.sock, socket_mock)

    @patch("lib.live_cluster.client.assocket.info")
    def test_is_connected_returns_false(self, info_mock):
        info_mock.return_value = -1

        self.assertFalse(self.as_socket.is_connected())

        info_mock.side_effect = Exception()

        self.assertFalse(self.as_socket.is_connected())

        self.sock = None

        self.assertFalse(self.as_socket.is_connected())

    @patch("lib.live_cluster.client.assocket.login")
    def test_login_returns_true(self, login_mock):
        login_mock.return_value = ASResponse.OK, "token", "expiration"

        self.assertTrue(self.as_socket.login())
        login_mock.assert_called_with(
            self.socket_mock,
            self.as_socket.user,
            self.as_socket.password,
            self.as_socket.auth_mode,
        )

        self.as_socket.user = None

        self.assertTrue(self.as_socket.login())

    @patch("lib.live_cluster.client.assocket.login")
    def test_login_returns_false(self, login_mock):
        self.as_socket.sock = None

        self.assertFalse(self.as_socket.login())

    @patch("lib.live_cluster.client.assocket.login")
    def test_login_raises_exception(self, login_mock):
        login_mock.return_value = ASResponse.NOT_AUTHENTICATED, "token", "expiration"

        util.assert_exception(
            self,
            ASProtocolError,
            None,
            self.as_socket.login,
        )

        login_mock.assert_called_with(
            self.socket_mock,
            self.as_socket.user,
            self.as_socket.password,
            self.as_socket.auth_mode,
        )

    @patch("lib.live_cluster.client.assocket.authenticate_old")
    @patch("lib.live_cluster.client.assocket.authenticate_new")
    def test_authenticate_returns_true(self, new_mock, old_mock):
        new_mock.return_value = ASResponse.OK

        self.assertTrue(self.as_socket.authenticate("token"))

        new_mock.assert_called_with(
            self.socket_mock, self.as_socket.user, "token", "INTERNAL"
        )

        old_mock.return_value = ASResponse.OK

        self.assertTrue(self.as_socket.authenticate(None))

        old_mock.assert_called_with(
            self.socket_mock, self.as_socket.user, self.as_socket.password
        )

        self.as_socket.user = None

        self.assertTrue(self.as_socket.authenticate(None))
        self.assertTrue(self.as_socket.authenticate("token"))

    @patch("lib.live_cluster.client.assocket.authenticate_old")
    @patch("lib.live_cluster.client.assocket.authenticate_new")
    def test_authenticate_returns_false(self, new_mock, old_mock):
        new_mock.return_value = ASResponse.NOT_AUTHENTICATED

        self.assertFalse(self.as_socket.authenticate("token"))

        new_mock.assert_called_with(
            self.socket_mock, self.as_socket.user, "token", "INTERNAL"
        )
        self.socket_mock.close.assert_called_once()

        old_mock.return_value = ASResponse.NOT_WHITELISTED
        self.socket_mock.reset_mock()

        self.assertFalse(self.as_socket.authenticate(None))

        old_mock.assert_called_with(
            self.socket_mock, self.as_socket.user, self.as_socket.password
        )
        self.socket_mock.close.assert_called_once()

        self.as_socket.sock = None

        self.assertFalse(self.as_socket.authenticate(None))
        self.assertFalse(self.as_socket.authenticate("token"))

    @patch("lib.live_cluster.client.assocket.info")
    def test_is_connected_returns_true(self, info_mock):
        info_mock.return_value = "abc"

        self.assertTrue(self.as_socket.is_connected())

    def socket_security_test(self, func, args, mock, error_response, expected_message):
        mock.return_value = ASResponse.OK

        self.assertIsNone(func(*args))

        mock.assert_called_with(self.socket_mock, *args)

        mock.return_value = error_response

        util.assert_exception(self, ASProtocolError, expected_message, func, *args)

    @patch("lib.live_cluster.client.assocket.create_user")
    def test_create_user(self, mock):
        args = ("foo", "pass", ["role1", "role2"])
        self.socket_security_test(
            self.as_socket.create_user,
            args,
            mock,
            ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL,
            "Failed to create user : No credential or bad credential.",
        )

    @patch("lib.live_cluster.client.assocket.drop_user")
    def test_delete_user(self, mock):
        args = ("foo",)
        self.socket_security_test(
            self.as_socket.delete_user,
            args,
            mock,
            ASResponse.NO_USER_OR_UNRECOGNIZED_USER,
            "Failed to delete user : No user or unrecognized user.",
        )

    @patch("lib.live_cluster.client.assocket.set_password")
    def test_set_password(self, mock):
        args = ("foo", "pass")
        self.socket_security_test(
            self.as_socket.set_password,
            args,
            mock,
            ASResponse.NO_USER_OR_UNRECOGNIZED_USER,
            "Failed to set password : No user or unrecognized user.",
        )

    @patch("lib.live_cluster.client.assocket.change_password")
    def test_change_password(self, mock):
        args = ("foo", "old", "new")
        self.socket_security_test(
            self.as_socket.change_password,
            args,
            mock,
            ASResponse.NO_PASSWORD_OR_BAD_PASSWORD,
            "Failed to change password : No password or bad password.",
        )

    @patch("lib.live_cluster.client.assocket.grant_roles")
    def test_grant_roles(self, mock):
        args = ("bar", ["abc", "cde"])
        self.socket_security_test(
            self.as_socket.grant_roles,
            args,
            mock,
            ASResponse.NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES,
            "Failed to grant roles : No privileges or unrecognized privileges.",
        )

    @patch("lib.live_cluster.client.assocket.revoke_roles")
    def test_revoke_roles(self, mock):
        args = ("bar", ["abc", "cde"])
        self.socket_security_test(
            self.as_socket.revoke_roles,
            args,
            mock,
            ASResponse.UNKNOWN_SERVER_ERROR,
            "Failed to revoke roles : Unknown server error.",
        )

    @patch("lib.live_cluster.client.assocket.query_users")
    def test_query_users(self, mock):
        mock.return_value = ASResponse.OK, {"a": 1234}
        args = ()

        self.assertDictEqual(self.as_socket.query_users(*args), {"a": 1234})

        mock.assert_called_with(self.socket_mock, *args)

        mock.return_value = ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, {"a": 1234}

        util.assert_exception(
            self,
            ASProtocolError,
            "Failed to query users : No credential or bad credential.",
            self.as_socket.query_users,
            *args
        )

    @patch("lib.live_cluster.client.assocket.query_user")
    def test_query_user(self, mock):
        mock.return_value = ASResponse.OK, {"a": 1234}
        args = ("a-user",)

        self.assertDictEqual(self.as_socket.query_user(*args), {"a": 1234})

        mock.assert_called_with(self.socket_mock, *args)

        mock.return_value = ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, {"a": 1234}

        util.assert_exception(
            self,
            ASProtocolError,
            "Failed to query user : No credential or bad credential.",
            self.as_socket.query_user,
            *args
        )

    @patch("lib.live_cluster.client.assocket.create_role")
    def test_create_role(self, mock):
        args = ("bar", ["abc", "cde"], ["3.3.3.3"], 111, 222)
        self.socket_security_test(
            self.as_socket.create_role,
            args,
            mock,
            ASResponse.NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES,
            "Failed to create role : No privileges or unrecognized privileges.",
        )

    @patch("lib.live_cluster.client.assocket.delete_role")
    def test_delete_role(self, mock):
        args = ("bar",)
        self.socket_security_test(
            self.as_socket.delete_role,
            args,
            mock,
            ASResponse.NO_ROLE_OR_INVALID_ROLE,
            "Failed to delete role : No role or invalid role.",
        )

    @patch("lib.live_cluster.client.assocket.add_privileges")
    def test_add_privileges(self, mock):
        args = ("role", ["priv1", "priv2"])
        self.socket_security_test(
            self.as_socket.add_privileges,
            args,
            mock,
            ASResponse.NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES,
            "Failed to grant privilege : No privileges or unrecognized privileges.",
        )

    @patch("lib.live_cluster.client.assocket.delete_privileges")
    def test_delete_privileges(self, mock):
        args = ("role", ["priv1", "priv2"])
        self.socket_security_test(
            self.as_socket.delete_privileges,
            args,
            mock,
            ASResponse.NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES,
            "Failed to revoke privilege : No privileges or unrecognized privileges.",
        )

    @patch("lib.live_cluster.client.assocket.set_whitelist")
    def test_set_whitelist(self, mock):
        args = ("role", ["3.3.3.3", "2.2.2.2"])
        self.socket_security_test(
            self.as_socket.set_whitelist,
            args,
            mock,
            ASResponse.BAD_WHITELIST,
            "Failed to set allowlist : Bad whitelist.",
        )

    @patch("lib.live_cluster.client.assocket.delete_whitelist")
    def test_delete_whitelist(self, mock):
        args = ("role",)
        self.socket_security_test(
            self.as_socket.delete_whitelist,
            args,
            mock,
            ASResponse.BAD_WHITELIST,
            "Failed to delete allowlist : Bad whitelist.",
        )

    @patch("lib.live_cluster.client.assocket.query_roles")
    def test_query_roles(self, mock):
        mock.return_value = ASResponse.OK, {"a": 1234}
        args = ()

        self.assertDictEqual(self.as_socket.query_roles(*args), {"a": 1234})

        mock.assert_called_with(self.socket_mock, *args)

        mock.return_value = ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, {"a": 1234}

        util.assert_exception(
            self,
            ASProtocolError,
            "Failed to query roles : No credential or bad credential.",
            self.as_socket.query_roles,
            *args
        )

    @patch("lib.live_cluster.client.assocket.query_role")
    def test_query_role(self, mock):
        mock.return_value = ASResponse.OK, {"a": 1234}
        args = ("a-user",)

        self.assertDictEqual(self.as_socket.query_role(*args), {"a": 1234})

        mock.assert_called_with(self.socket_mock, *args)

        mock.return_value = ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, {"a": 1234}

        util.assert_exception(
            self,
            ASProtocolError,
            "Failed to query role : No credential or bad credential.",
            self.as_socket.query_role,
            *args
        )
