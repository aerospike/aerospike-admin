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

import asyncio
import contextlib
import select
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, Mock, patch

from lib.live_cluster.client import ASProtocolError, ASResponse
from lib.live_cluster.client.assocket import SSL, ASSocket
from lib.live_cluster.client.ssl_context import SSLContext
from lib.utils.constants import AuthMode
from test.unit import util
from test.unit.secret_agent import pki


async def _hang(*args, **kwargs):
    await asyncio.Event().wait()


class ASSocketFailureTest(unittest.IsolatedAsyncioTestCase):
    """TOOLS-4644: a failure says which step failed and why."""

    IPV6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 999, 0, 0))
    IPV4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 999))

    async def asyncSetUp(self) -> None:
        self.as_socket = ASSocket(
            "1.2.3.4",
            999,
            "tls-name",
            "test-user",
            "test-password",
            AuthMode.INTERNAL,
            None,
            timeout=0.05,
        )

    def _patched(self, tls=False):
        stack = contextlib.ExitStack()
        near, far = socket.socketpair()
        stack.callback(near.close)
        stack.callback(far.close)
        sock = stack.enter_context(patch("socket.socket")).return_value
        tls_sock = stack.enter_context(
            patch("lib.live_cluster.client.assocket._AsyncioSSLConnectionAdapter")
        ).return_value
        tls_sock.fileno.return_value = near.fileno()
        loop = stack.enter_context(patch("asyncio.get_event_loop")).return_value
        stack.enter_context(
            patch(
                "asyncio.open_connection",
                AsyncMock(return_value=(AsyncMock(), AsyncMock())),
            )
        )
        loop.getaddrinfo = AsyncMock(return_value=[self.IPV4])
        loop.sock_connect = AsyncMock()
        self.as_socket.ssl_context = Mock() if tls else None

        return stack, sock, tls_sock, loop

    async def test_refused_connect_raises_the_os_error(self):
        stack, sock, _, loop = self._patched()
        refused = ConnectionRefusedError(61, "Connect call failed ('1.2.3.4', 999)")
        loop.sock_connect.side_effect = refused

        with stack, self.assertRaises(ConnectionRefusedError) as cm:
            await self.as_socket.connect()

        self.assertIs(cm.exception, refused)
        sock.close.assert_called_once()

    async def test_connect_timeout_names_the_step(self):
        """Raised as a ConnectionError, not a TimeoutError, so the node is still
        marked not alive."""
        stack, sock, _, loop = self._patched()
        loop.sock_connect.side_effect = _hang

        with stack, self.assertRaises(ConnectionError) as cm:
            await self.as_socket.connect()

        self.assertEqual(str(cm.exception), "connect timed out after 0.05s")
        self.assertNotIsInstance(cm.exception, TimeoutError)
        sock.close.assert_called_once()

    async def test_tls_handshake_failure_names_the_step(self):
        for error, reason in (
            (
                SSL.Error([("SSL routines", "", "certificate verify failed")]),
                "TLS handshake failed: [('SSL routines', '', 'certificate verify failed')]",
            ),
            (
                Exception("Wrong tls_name 'tls-name'"),
                "TLS handshake failed: Wrong tls_name 'tls-name'",
            ),
            (SSL.WantReadError(), "TLS handshake timed out after 0.05s"),
        ):
            with self.subTest(reason=reason):
                stack, _, tls_sock, _ = self._patched(tls=True)
                tls_sock.do_handshake.side_effect = error

                with stack, self.assertRaises(ConnectionError) as cm:
                    await self.as_socket.connect()

                self.assertEqual(str(cm.exception), reason)
                self.assertNotIsInstance(cm.exception, TimeoutError)
                tls_sock.close.assert_called_once()

    async def test_tries_every_address_before_failing(self):
        stack, _, _, loop = self._patched()
        loop.getaddrinfo.return_value = [self.IPV6, self.IPV4]
        loop.sock_connect.side_effect = [
            ConnectionRefusedError(61, "Connect call failed ('::1', 999, 0, 0)"),
            None,
        ]

        with stack:
            self.assertTrue(await self.as_socket.connect())

        self.assertEqual(loop.sock_connect.await_count, 2)

    async def test_raises_the_last_error_when_every_address_fails(self):
        stack, _, _, loop = self._patched()
        loop.getaddrinfo.return_value = [self.IPV6, self.IPV4]
        last = ConnectionRefusedError(61, "Connect call failed ('1.2.3.4', 999)")
        loop.sock_connect.side_effect = [
            ConnectionRefusedError(61, "Connect call failed ('::1', 999, 0, 0)"),
            last,
        ]

        with stack, self.assertRaises(ConnectionRefusedError) as cm:
            await self.as_socket.connect()

        self.assertIs(cm.exception, last)

    async def test_timeout_after_connect_names_the_step(self):
        """Still a TimeoutError, so a slow reply does not mark the node dead
        (TOOLS-3596)."""
        self.as_socket.sock = Mock()
        self.as_socket.reader = AsyncMock()
        self.as_socket.writer = AsyncMock()

        for step, target, call in (
            ("login", "login", lambda: self.as_socket.login()),
            (
                "authenticate",
                "authenticate_with_token",
                lambda: self.as_socket.authenticate("token"),
            ),
            ("info", "info", lambda: self.as_socket.info("build")),
        ):
            with self.subTest(step=step), patch(
                f"lib.live_cluster.client.assocket.{target}",
                AsyncMock(side_effect=_hang),
            ):
                with self.assertRaises(asyncio.TimeoutError) as cm:
                    await call()

                self.assertEqual(str(cm.exception), f"{step} timed out after 0.05s")


class ASSocketTestConnect(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
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
        self.as_socket.reader = AsyncMock()
        self.as_socket.writer = AsyncMock()
        self.info_mock = patch("lib.live_cluster.client.assocket.info").start()

        # warnings.filterwarnings("error", category=RuntimeWarning)

        self.addCleanup(patch.stopall)

    async def test_settimeout_updates_timeout(self):
        """TOOLS-3596: settimeout applies to subsequent operations on the socket so a
        pooled connection honors a timeout raised after it was created."""
        self.as_socket.settimeout(9)

        self.assertEqual(self.as_socket._timeout, 9)

    @patch("socket.socket")
    @patch("asyncio.open_connection", new_callable=AsyncMock)
    @patch("asyncio.get_event_loop")
    async def test_can_connect(
        self,
        event_loop_mock,
        open_connection_mock,
        socket_module_mock,
    ):
        open_connection_mock.return_value = AsyncMock(), AsyncMock()
        event_loop_mock.return_value.sock_connect = AsyncMock()
        event_loop_mock.return_value.getaddrinfo = AsyncMock()
        event_loop_mock.return_value.getaddrinfo.return_value = [
            ("family1", "socktype1", "proto1", "canonname1", "sockaddr1"),
            ("family2", "socktype2", "proto2", "canonname2", "sockaddr2"),
        ]

        self.assertTrue(await self.as_socket.connect())

        socket_module_mock.assert_called_with("family1", socket.SOCK_STREAM)
        socket_mock = socket_module_mock.return_value
        event_loop_mock.return_value.sock_connect.assert_called_with(
            socket_mock, "sockaddr1"
        )
        self.assertEqual(self.as_socket.sock, socket_mock)

    @patch("socket.socket")
    @patch("lib.live_cluster.client.assocket._AsyncioSSLConnectionAdapter")
    @patch("asyncio.open_connection", new_callable=AsyncMock)
    @patch("asyncio.get_event_loop")
    async def test_can_connect_with_ssl_context(
        self,
        event_loop_mock,
        open_connection_mock,
        ssl_connect_mock,
        socket_module_mock,
    ):
        open_connection_mock.return_value = AsyncMock(), AsyncMock()
        event_loop_mock.return_value.sock_connect = AsyncMock()
        self.as_socket.ssl_context = True
        event_loop_mock.return_value.getaddrinfo = AsyncMock()
        event_loop_mock.return_value.getaddrinfo.return_value = [
            ("family1", "socktype1", "proto1", "canonname1", "sockaddr1"),
            ("family2", "socktype2", "proto2", "canonname2", "sockaddr2"),
        ]

        self.assertTrue(await self.as_socket.connect())

        socket_module_mock.assert_called_with("family1", socket.SOCK_STREAM)
        socket_mock = socket_module_mock.return_value
        ssl_connect_mock.assert_called_with(True, socket_mock)
        wrapped_socket_mock = ssl_connect_mock.return_value
        event_loop_mock.return_value.sock_connect.assert_called_with(
            wrapped_socket_mock, "sockaddr1"
        )
        wrapped_socket_mock.set_app_data.assert_called_with("tls-name")
        wrapped_socket_mock.do_handshake.assert_called_once()
        self.assertEqual(self.as_socket.sock, wrapped_socket_mock)

    @patch("lib.live_cluster.client.assocket.login")
    async def test_login_returns_true(self, login_mock):
        login_mock.return_value = ASResponse.OK, "token", "expiration"
        self.as_socket.credential = b"hash"

        self.assertTrue(await self.as_socket.login())
        login_mock.assert_called_with(
            self.as_socket.reader,
            self.as_socket.writer,
            self.as_socket.user,
            self.as_socket.password,
            b"hash",
            self.as_socket.auth_mode,
        )

        self.as_socket.user = None

        self.assertTrue(await self.as_socket.login())

    @patch("lib.live_cluster.client.assocket.login")
    async def test_login_sends_credential_given_at_construction(self, login_mock):
        login_mock.return_value = ASResponse.OK, "token", "expiration"
        as_socket = ASSocket(
            "1.2.3.4",
            999,
            "tls-name",
            "test-user",
            "test-password",
            AuthMode.INTERNAL,
            False,
            credential=b"hash",
        )
        as_socket.sock = self.socket_mock
        as_socket.reader = AsyncMock()
        as_socket.writer = AsyncMock()

        self.assertTrue(await as_socket.login())

        login_mock.assert_called_with(
            as_socket.reader,
            as_socket.writer,
            "test-user",
            "test-password",
            b"hash",
            AuthMode.INTERNAL,
        )

    async def test_login_returns_false(self):
        self.as_socket.sock = None

        self.assertFalse(await self.as_socket.login())

    @patch("lib.live_cluster.client.assocket.login")
    async def test_login_raises_exception(self, login_mock):
        login_mock.return_value = ASResponse.NOT_AUTHENTICATED, "token", "expiration"
        self.as_socket.credential = b"hash"

        await util.assert_exception_async(
            self,
            ASProtocolError,
            None,
            self.as_socket.login,
        )

        login_mock.assert_called_with(
            self.as_socket.reader,
            self.as_socket.writer,
            self.as_socket.user,
            self.as_socket.password,
            b"hash",
            self.as_socket.auth_mode,
        )

    @patch(
        "lib.live_cluster.client.assocket.authenticate_with_token",
        new_callable=AsyncMock,
    )
    async def test_authenticate_returns_true(self, token_mock):
        token_mock.return_value = ASResponse.OK

        self.assertTrue(await self.as_socket.authenticate("token"))

        token_mock.assert_called_with(
            self.as_socket.reader,
            self.as_socket.writer,
            self.as_socket.user,
            "token",
            "INTERNAL",
        )

        self.as_socket.user = None

        self.assertTrue(await self.as_socket.authenticate(None))
        self.assertTrue(await self.as_socket.authenticate("token"))

    @patch(
        "lib.live_cluster.client.assocket.authenticate_with_token",
        new_callable=AsyncMock,
    )
    async def test_authenticate_without_token_sends_nothing(self, token_mock):
        """Login returns no token when security is disabled, so there is nothing to
        authenticate with."""
        self.assertTrue(await self.as_socket.authenticate(None))

        token_mock.assert_not_called()

    @patch(
        "lib.live_cluster.client.assocket.authenticate_with_token",
        new_callable=AsyncMock,
    )
    async def test_authenticate_returns_false(self, token_mock):
        token_mock.return_value = ASResponse.NOT_AUTHENTICATED
        self.as_socket.sock = None

        self.assertFalse(await self.as_socket.authenticate("token"))

        token_mock.assert_not_called()

    @patch(
        "lib.live_cluster.client.assocket.authenticate_with_token",
        new_callable=AsyncMock,
    )
    async def test_authenticate_raises_not_authenticated(self, token_mock):
        token_mock.return_value = ASResponse.NOT_AUTHENTICATED

        with self.assertRaises(ASProtocolError):
            await self.as_socket.authenticate("token")

        token_mock.assert_called_with(
            self.as_socket.reader,
            self.as_socket.writer,
            self.as_socket.user,
            "token",
            "INTERNAL",
        )

    async def socket_security_test(
        self, func, args, mock, error_response, expected_message
    ):
        mock.return_value = ASResponse.OK

        self.assertEqual(await func(*args), ASResponse.OK)

        mock.assert_called_with(self.as_socket.reader, self.as_socket.writer, *args)

        mock.return_value = error_response

        await util.assert_exception_async(
            self, ASProtocolError, expected_message, func, *args
        )

    @patch("lib.live_cluster.client.assocket.create_user", new_callable=AsyncMock)
    async def test_create_user(self, mock):
        args = ("foo", "pass", ["role1", "role2"])
        await self.socket_security_test(
            self.as_socket.create_user,
            args,
            mock,
            ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL,
            "Failed to create user : No credential or bad credential.",
        )

    @patch("lib.live_cluster.client.assocket.drop_user", new_callable=AsyncMock)
    async def test_delete_user(self, mock):
        args = ("foo",)
        await self.socket_security_test(
            self.as_socket.delete_user,
            args,
            mock,
            ASResponse.NO_USER_OR_UNRECOGNIZED_USER,
            "Failed to delete user : No user or unrecognized user.",
        )

    @patch("lib.live_cluster.client.assocket.set_password", new_callable=AsyncMock)
    async def test_set_password(self, mock):
        args = ("foo", "pass")
        await self.socket_security_test(
            self.as_socket.set_password,
            args,
            mock,
            ASResponse.NO_USER_OR_UNRECOGNIZED_USER,
            "Failed to set password : No user or unrecognized user.",
        )

    @patch("lib.live_cluster.client.assocket.change_password", new_callable=AsyncMock)
    async def test_change_password(self, mock):
        args = ("foo", "old", "new")
        await self.socket_security_test(
            self.as_socket.change_password,
            args,
            mock,
            ASResponse.NO_PASSWORD_OR_BAD_PASSWORD,
            "Failed to change password : No password or bad password.",
        )

    @patch("lib.live_cluster.client.assocket.grant_roles", new_callable=AsyncMock)
    async def test_grant_roles(self, mock):
        args = ("bar", ["abc", "cde"])
        await self.socket_security_test(
            self.as_socket.grant_roles,
            args,
            mock,
            ASResponse.NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES,
            "Failed to grant roles : No privileges or unrecognized privileges.",
        )

    @patch("lib.live_cluster.client.assocket.revoke_roles", new_callable=AsyncMock)
    async def test_revoke_roles(self, mock):
        args = ("bar", ["abc", "cde"])
        await self.socket_security_test(
            self.as_socket.revoke_roles,
            args,
            mock,
            ASResponse.UNKNOWN_SERVER_ERROR,
            "Failed to revoke roles : Unknown server error.",
        )

    @patch("lib.live_cluster.client.assocket.query_users", new_callable=AsyncMock)
    async def test_query_users(self, mock):
        mock.return_value = ASResponse.OK, {"a": 1234}
        args = ()

        self.assertDictEqual(await self.as_socket.query_users(*args), {"a": 1234})

        mock.assert_called_with(self.as_socket.reader, self.as_socket.writer, *args)

        mock.return_value = ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, {"a": 1234}

        await util.assert_exception_async(
            self,
            ASProtocolError,
            "Failed to query users : No credential or bad credential.",
            self.as_socket.query_users,
            *args,
        )

    @patch("lib.live_cluster.client.assocket.query_user", new_callable=AsyncMock)
    async def test_query_user(self, mock):
        mock.return_value = ASResponse.OK, {"a": 1234}
        args = ("a-user",)

        self.assertDictEqual(await self.as_socket.query_user(*args), {"a": 1234})

        mock.assert_called_with(self.as_socket.reader, self.as_socket.writer, *args)

        mock.return_value = ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, {"a": 1234}

        await util.assert_exception_async(
            self,
            ASProtocolError,
            "Failed to query user : No credential or bad credential.",
            self.as_socket.query_user,
            *args,
        )

    @patch("lib.live_cluster.client.assocket.create_role", new_callable=AsyncMock)
    async def test_create_role(self, mock):
        args = ("bar", ["abc", "cde"], ["3.3.3.3"], 111, 222)
        await self.socket_security_test(
            self.as_socket.create_role,
            args,
            mock,
            ASResponse.NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES,
            "Failed to create role : No privileges or unrecognized privileges.",
        )

    @patch("lib.live_cluster.client.assocket.delete_role", new_callable=AsyncMock)
    async def test_delete_role(self, mock):
        args = ("bar",)
        await self.socket_security_test(
            self.as_socket.delete_role,
            args,
            mock,
            ASResponse.NO_ROLE_OR_INVALID_ROLE,
            "Failed to delete role : No role or invalid role.",
        )

    @patch("lib.live_cluster.client.assocket.add_privileges", new_callable=AsyncMock)
    async def test_add_privileges(self, mock):
        args = ("role", ["priv1", "priv2"])
        await self.socket_security_test(
            self.as_socket.add_privileges,
            args,
            mock,
            ASResponse.NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES,
            "Failed to grant privilege : No privileges or unrecognized privileges.",
        )

    @patch("lib.live_cluster.client.assocket.delete_privileges", new_callable=AsyncMock)
    async def test_delete_privileges(self, mock):
        args = ("role", ["priv1", "priv2"])
        await self.socket_security_test(
            self.as_socket.delete_privileges,
            args,
            mock,
            ASResponse.NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES,
            "Failed to revoke privilege : No privileges or unrecognized privileges.",
        )

    @patch("lib.live_cluster.client.assocket.set_whitelist", new_callable=AsyncMock)
    async def test_set_whitelist(self, mock):
        args = ("role", ["3.3.3.3", "2.2.2.2"])
        await self.socket_security_test(
            self.as_socket.set_whitelist,
            args,
            mock,
            ASResponse.BAD_WHITELIST,
            "Failed to set allowlist : Bad whitelist.",
        )

    @patch("lib.live_cluster.client.assocket.delete_whitelist", new_callable=AsyncMock)
    async def test_delete_whitelist(self, mock):
        args = ("role",)
        await self.socket_security_test(
            self.as_socket.delete_whitelist,
            args,
            mock,
            ASResponse.BAD_WHITELIST,
            "Failed to delete allowlist : Bad whitelist.",
        )

    @patch("lib.live_cluster.client.assocket.query_roles", new_callable=AsyncMock)
    async def test_query_roles(self, mock):
        mock.return_value = ASResponse.OK, {"a": 1234}
        args = ()

        self.assertDictEqual(await self.as_socket.query_roles(*args), {"a": 1234})

        mock.assert_called_with(self.as_socket.reader, self.as_socket.writer, *args)

        mock.return_value = ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, {"a": 1234}

        await util.assert_exception_async(
            self,
            ASProtocolError,
            "Failed to query roles : No credential or bad credential.",
            self.as_socket.query_roles,
            *args,
        )

    @patch("lib.live_cluster.client.assocket.query_role", new_callable=AsyncMock)
    async def test_query_role(self, mock):
        mock.return_value = ASResponse.OK, {"a": 1234}
        args = ("a-user",)

        self.assertDictEqual(await self.as_socket.query_role(*args), {"a": 1234})

        mock.assert_called_with(self.as_socket.reader, self.as_socket.writer, *args)

        mock.return_value = ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, {"a": 1234}

        await util.assert_exception_async(
            self,
            ASProtocolError,
            "Failed to query role : No credential or bad credential.",
            self.as_socket.query_role,
            *args,
        )


class ASSocketTLSHandshakeTest(unittest.IsolatedAsyncioTestCase):
    """The TLS handshake waits for the socket, rather than retrying on a timer."""

    async def asyncSetUp(self):
        self.near, self.far = socket.socketpair()
        self.near.setblocking(False)
        self.addCleanup(self.near.close)
        self.addCleanup(self.far.close)

        self.tls = MagicMock()
        self.tls.fileno.side_effect = self.near.fileno
        self.as_socket = ASSocket(
            "1.2.3.4", 999, "tls-name", None, None, AuthMode.INTERNAL, True, timeout=2
        )

        patch("socket.socket").start()
        patch.object(self.as_socket, "_wrap_socket", return_value=self.tls).start()
        patch.object(asyncio.get_running_loop(), "sock_connect", AsyncMock()).start()
        self.addCleanup(patch.stopall)

    async def connect(self):
        return await self.as_socket._create_socket_for_addrinfo(
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 999))
        )

    def peer_has_spoken(self):
        try:
            return self.near.recv(1, socket.MSG_PEEK) != b""
        except BlockingIOError:
            return False

    async def test_waits_for_the_peer_instead_of_polling(self):
        def do_handshake():
            if not self.peer_has_spoken():
                raise SSL.WantReadError()

        self.tls.do_handshake.side_effect = do_handshake
        asyncio.get_running_loop().call_later(0.2, self.far.send, b"x")

        self.assertIs(await self.connect(), self.tls)
        self.assertEqual(
            self.tls.do_handshake.call_count,
            2,
            "the handshake was retried while the peer had sent nothing",
        )

    async def test_waits_for_room_to_write(self):
        self.tls.do_handshake.side_effect = [SSL.WantWriteError(), None]

        self.assertIs(await self.connect(), self.tls)
        self.assertEqual(self.tls.do_handshake.call_count, 2)

    async def test_gives_up_when_the_peer_never_answers(self):
        self.as_socket.settimeout(0.2)
        self.tls.do_handshake.side_effect = SSL.WantReadError()

        with self.assertRaises(ConnectionError) as cm:
            await self.connect()

        self.assertEqual(str(cm.exception), "TLS handshake timed out after 0.2s")
        self.tls.close.assert_called_once()


class ASSocketReuseTest(unittest.IsolatedAsyncioTestCase):
    """Whether a pooled socket can be reused. Checked without a request, unless it
    sat idle long enough for a drop to go unseen."""

    async def asyncSetUp(self):
        self.near, self.far = socket.socketpair()
        self.addCleanup(self.near.close)
        self.addCleanup(self.far.close)

        self.as_socket = ASSocket(
            "1.2.3.4", 999, None, None, None, AuthMode.INTERNAL, None
        )
        self.as_socket.sock = self.near
        self.as_socket.reader = asyncio.StreamReader()
        self.as_socket.writer = MagicMock(spec=asyncio.StreamWriter)
        self.as_socket.writer.is_closing.return_value = False
        self.info_mock = patch(
            "lib.live_cluster.client.assocket.info", AsyncMock(return_value="A0")
        ).start()
        self.addCleanup(patch.stopall)

    def used(self, seconds_ago):
        self.as_socket.last_used = time.time() - seconds_ago

    async def test_recently_used_socket_is_reused_without_a_request(self):
        self.used(0)

        self.assertTrue(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()

    async def test_socket_the_server_closed_is_not_reused(self):
        self.used(0)
        self.far.close()

        self.assertFalse(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()

    async def test_socket_with_unread_bytes_is_not_reused(self):
        self.used(0)
        self.far.send(b"x")

        self.assertFalse(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()

    async def test_socket_whose_stream_ended_is_not_reused(self):
        self.used(0)
        self.as_socket.reader.feed_eof()

        self.assertFalse(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()

    async def test_socket_whose_writer_is_closing_is_not_reused(self):
        self.used(0)
        self.as_socket.writer.is_closing.return_value = True

        self.assertFalse(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()

    async def test_socket_whose_reader_failed_is_not_reused(self):
        self.used(0)
        self.as_socket.reader.set_exception(SSL.ZeroReturnError())

        self.assertFalse(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()

    async def test_socket_last_used_after_now_is_checked_with_a_request(self):
        """A wall-clock step back puts last_used in the future."""
        self.used(-3600)

        self.assertTrue(await self.as_socket.is_connected())
        self.info_mock.assert_awaited_once()
        self.assertEqual(self.info_mock.await_args.args[2], "node")

    async def test_socket_idle_for_long_is_checked_with_a_request(self):
        self.used(3600)

        self.assertTrue(await self.as_socket.is_connected())
        self.info_mock.assert_awaited_once()
        self.assertEqual(self.info_mock.await_args.args[2], "node")

    async def test_socket_idle_for_long_that_does_not_answer_is_not_reused(self):
        self.used(3600)
        self.info_mock.return_value = None

        self.assertFalse(await self.as_socket.is_connected())

        self.info_mock.side_effect = Exception()

        self.assertFalse(await self.as_socket.is_connected())

    async def test_socket_never_returned_to_the_pool_is_checked_with_a_request(self):
        self.assertTrue(await self.as_socket.is_connected())
        self.info_mock.assert_awaited_once()

    async def test_without_a_socket_is_not_reused(self):
        self.used(0)
        self.as_socket.sock = None

        self.assertFalse(await self.as_socket.is_connected())


class ASSocketTLSReuseTest(unittest.IsolatedAsyncioTestCase):
    """Whether a pooled socket can be reused, on a real TLS connection to a server
    that answers once and then closes when told to."""

    async def asyncSetUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        certs = pki.generate(tmp.name)

        listener = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(listener.close)
        self.close_requested = threading.Event()
        self.server_closed = threading.Event()
        server = threading.Thread(
            target=self.serve, args=(listener, certs.server_context()), daemon=True
        )
        server.start()
        self.addCleanup(server.join, 5)
        self.addCleanup(self.close_requested.set)

        self.as_socket = ASSocket(
            "127.0.0.1",
            listener.getsockname()[1],
            "127.0.0.1",
            None,
            None,
            AuthMode.INTERNAL,
            SSLContext(enable_tls=True, cafile=certs.ca_file).ctx,
        )
        self.assertTrue(await self.as_socket.connect())
        self.addAsyncCleanup(self.as_socket.close)

        self.as_socket.writer.write(b"ping")
        await self.as_socket.writer.drain()
        self.assertEqual(await self.as_socket.reader.readexactly(4), b"ping")
        self.as_socket.last_used = time.time()

        self.info_mock = patch(
            "lib.live_cluster.client.assocket.info", AsyncMock(return_value="A0")
        ).start()
        self.addCleanup(patch.stopall)

    def serve(self, listener, ctx):
        conn, _ = listener.accept()

        with ctx.wrap_socket(conn, server_side=True) as tls:
            tls.sendall(tls.recv(4))
            self.close_requested.wait(5)
            tls.setblocking(False)

            try:
                tls.unwrap()
            except OSError:
                pass

        self.server_closed.set()

    def close_from_server(self):
        self.close_requested.set()
        self.assertTrue(self.server_closed.wait(5))

    async def test_idle_socket_is_reused_without_a_request(self):
        self.assertTrue(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()

    async def test_socket_closed_while_the_loop_was_blocked_is_not_reused(self):
        """The stream flags only change when the loop runs, so only the poll sees it."""
        self.close_from_server()
        readable, _, _ = select.select([self.as_socket.sock], [], [], 5)
        self.assertTrue(readable)

        self.assertFalse(self.as_socket.writer.is_closing())
        self.assertFalse(self.as_socket.reader.at_eof())
        self.assertIsNone(self.as_socket.reader.exception())
        self.assertFalse(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()

    async def test_socket_the_server_closed_is_not_reused(self):
        self.close_from_server()

        with self.assertRaises(SSL.ZeroReturnError):
            await asyncio.wait_for(self.as_socket.reader.read(1), 5)

        self.assertTrue(self.as_socket.writer.is_closing())
        self.assertFalse(await self.as_socket.is_connected())
        self.info_mock.assert_not_called()
