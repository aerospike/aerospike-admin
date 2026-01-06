import asyncio
import unittest
import asyncssh
import unittest
from mock import AsyncMock, MagicMock, call, patch

from lib.live_cluster.ssh import (
    FileTransfer,
    SSHConnection,
    SSHConnectionConfig,
    SSHConnectionError,
    SSHConnectionFactory,
    SSHError,
    SSHNonZeroExitCodeError,
    SSHTimeoutError,
)


class SSHConnectionTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._conn = MagicMock(
            spec=asyncssh.SSHClientConnection,
        )
        self._conn.get_extra_info.return_value = "1.1.1.1:3000"
        self._conn.run = AsyncMock()

        self.conn = SSHConnection(self._conn)

    async def test_run(self):
        self._conn.run.return_value = MagicMock("asyncssh.SSHClientProcess")
        await self.conn.run("cmd")
        self._conn.run.assert_called_once_with("cmd", check=True, timeout=10)

    async def test_max_sessions(self):
        count = 0
        max_sessions = 0

        async def conn_side_effect(*args, **kwargs):
            nonlocal count
            nonlocal max_sessions
            count += 1
            await asyncio.sleep(0.1)
            max_sessions = max(max_sessions, count)
            count -= 1
            return AsyncMock(spec=asyncssh.SSHClientProcess)

        self._conn.run.side_effect = conn_side_effect

        await asyncio.gather(*[self.conn.run("cmd") for _ in range(100)])

        self.assertTrue(max_sessions == self.conn._max_sessions_sem._value)

    async def test_run_timeout(self):
        self._conn.run.side_effect = asyncssh.TimeoutError(
            None, None, None, None, None, None, "Timeout", "Timeout"
        )
        with self.assertRaises(SSHTimeoutError):
            await self.conn.run("cmd")
        self._conn.run.assert_called_once_with("cmd", check=True, timeout=10)

    async def test_run_non_zero_exit_code(self):
        self._conn.run.side_effect = asyncssh.ProcessError(
            None,
            None,
            None,
            None,
            None,
            None,
            "Non-zero exit code",
            "Non-zero exit code",
        )
        with self.assertRaises(SSHNonZeroExitCodeError):
            await self.conn.run("cmd")
        self._conn.run.assert_called_once_with("cmd", check=True, timeout=10)

    async def test_run_generic_error(self):
        self._conn.run.side_effect = asyncssh.Error(0, "Generic error")
        with self.assertRaises(SSHError):
            await self.conn.run("cmd")
        self._conn.run.assert_called_once_with("cmd", check=True, timeout=10)

    async def test_close(self):
        await self.conn.close()
        self._conn.close.assert_called_once_with()
        self._conn.wait_closed.assert_called_once_with()

    async def test_aenter(self):
        self.conn.close = AsyncMock()
        async with self.conn as conn:
            self.assertEqual(conn, self.conn)
        self.conn.close.assert_called_once_with()


class SSHConnectionConfigTest(unittest.IsolatedAsyncioTestCase):
    def test_init(self):
        self.config = SSHConnectionConfig(8080, "user", "pass", "key", "key_pwd")
        self.assertEqual(self.config.port, 8080)
        self.assertEqual(self.config.username, "user")
        self.assertEqual(self.config.password, "pass")
        self.assertEqual(self.config.private_key, "key")
        self.assertEqual(self.config.private_key_pwd, "key_pwd")


class MockSSHConnection:
    pass


class TestSSHConnectionFactory(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.mock_connect = patch("asyncssh.connect", AsyncMock()).start()
        self.mock_connect.return_value = MockSSHConnection()

        self.addCleanup(patch.stopall)

    async def test_create_connection_successful(self):
        factory = SSHConnectionFactory()
        connection = await factory.create_connection("example.com")

        self.assertIsInstance(connection, SSHConnection)
        self.assertIsInstance(connection._conn, MockSSHConnection)

    async def test_create_connection_disconnect_error(self):
        self.mock_connect.side_effect = asyncssh.DisconnectError(1, "test")

        factory = SSHConnectionFactory()
        with self.assertRaises(SSHConnectionError):
            await factory.create_connection("example.com")

    async def test_create_connection_other_error(self):
        self.mock_connect.side_effect = Exception("test")

        factory = SSHConnectionFactory()
        with self.assertRaises(Exception):
            await factory.create_connection("example.com")

    async def test_close_last_factory(self):
        factory = SSHConnectionFactory()
        await factory.create_connection("example.com")

        self.assertNotIn("example.com", SSHConnectionFactory.semaphore_host_dict)

    async def test_close_multiple_factories(self):
        factory1 = SSHConnectionFactory()
        factory2 = SSHConnectionFactory()
        count = 0

        async def side_effect(*args, **kwargs):
            nonlocal count

            count += 1
            self.assertEqual(
                count, SSHConnectionFactory.semaphore_host_dict["example.com"].count
            )
            await asyncio.sleep(0.1)

            return MockSSHConnection()

        self.mock_connect.side_effect = side_effect

        await asyncio.gather(
            factory1.create_connection("example.com"),
            factory2.create_connection("example.com"),
        )

        self.assertNotIn("example.com", SSHConnectionFactory.semaphore_host_dict)

    async def test_max_startups(self):
        count = 0
        max_sessions = 0

        async def connect_side_effect(*args, **kwargs):
            nonlocal count
            nonlocal max_sessions
            count += 1
            await asyncio.sleep(0.1)
            max_sessions = max(max_sessions, count)
            count -= 1
            return MockSSHConnection()

        self.mock_connect.side_effect = connect_side_effect
        factory = SSHConnectionFactory(max_startups=10)

        await asyncio.gather(
            *[factory.create_connection("example.com") for _ in range(100)]
        )

        self.assertTrue(max_sessions == 10)

    async def test_create_connection_with_config(self):
        self.mock_connect.return_value = MockSSHConnection()
        factory = SSHConnectionFactory(
            # "example.com",
            ssh_config=SSHConnectionConfig(
                8080, "user", "pass", private_key_pwd="key_pwd"
            ),
        )
        connection = await factory.create_connection("example.com")

        self.assertIsInstance(connection, SSHConnection)
        self.assertIsInstance(connection._conn, MockSSHConnection)
        self.assertEqual(factory.opts.port, 8080)
        self.assertEqual(factory.opts.username, "user")
        self.assertEqual(factory.opts.password, "pass")
        self.assertEqual(factory.opts.passphrase, "key_pwd")


class TestFileTransfer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.src_conn = AsyncMock(SSHConnection)
        self.src_conn._conn = AsyncMock(asyncssh.SSHClientConnection)
        self.src_conn._conn.start_sftp_client = MagicMock()
        self.src_conn._conn.start_sftp_client.return_value = AsyncMock(
            asyncssh.SFTPClient
        )
        self.sftp_session = AsyncMock()
        self.sftp_session.__aenter__ = AsyncMock()
        self.sftp_session.get = AsyncMock(return_value=None)
        self.src_conn.start_sftp_client.return_value.__aenter__.return_value = (
            self.sftp_session
        )
        self.mkdirs = patch("os.makedirs").start()

        self.addCleanup(patch.stopall)

    def test_create_error_handler(self):
        errors = []
        error_handler = FileTransfer.create_error_handler(errors)

        error = Exception("Test error")
        error_handler(error)

        self.assertEqual(errors, [error])

    async def test_remote_to_local_successful_transfer(self):
        paths = [("remote_path", "local_path")]

        errors = await FileTransfer.remote_to_local(paths, self.src_conn)

        self.assertEqual(errors, [])
        self.sftp_session.get.assert_called_once_with(
            ["remote_path"], "local_path", recurse=True, preserve=True
        )

    async def test_remote_to_local_multiple_paths(self):
        paths = [
            ("remote_path1", "local_path1"),
            ("remote_path2", "local_path2"),
        ]

        # sftp_session.get = AsyncMock(return_value=None)

        errors = await FileTransfer.remote_to_local(paths, self.src_conn)

        self.assertEqual(errors, [])
        self.sftp_session.get.assert_has_calls(
            [
                call(
                    ["remote_path1"],
                    "local_path1",
                    recurse=True,
                    preserve=True,
                ),
                call(
                    ["remote_path2"],
                    "local_path2",
                    recurse=True,
                    preserve=True,
                ),
            ]
        )

    async def test_remote_to_local_some_errors(self):
        paths = [
            ("remote_path1", "local_path1"),
            ("remote_path2", "local_path2"),
        ]

        self.sftp_session.get.side_effect = [Exception("Test error"), None]

        errors = await FileTransfer.remote_to_local(
            paths, self.src_conn, return_exceptions=True
        )

        self.assertEqual(len(errors), 1)
        self.sftp_session.get.assert_has_calls(
            [
                call(
                    ["remote_path1"],
                    "local_path1",
                    recurse=True,
                    preserve=True,
                ),
                call(
                    ["remote_path2"],
                    "local_path2",
                    recurse=True,
                    preserve=True,
                ),
            ]
        )

    async def test_remote_to_local_raises_first_exception(self):
        paths = [
            ("remote_path1", "local_path1"),
            ("remote_path2", "local_path2"),
        ]

        self.sftp_session.get.side_effect = [Exception("Test error"), None]

        with self.assertRaises(Exception):
            await FileTransfer.remote_to_local(paths, self.src_conn)
