import asyncio
import datetime
import unittest
from asyncio.subprocess import Process
from unittest.mock import AsyncMock, MagicMock, call, patch
from lib.live_cluster.client.node import Node

from lib.live_cluster.logfile_downloader import (
    _LogInfo,
    _RemoteLogInfo,
    LogFileDownloader,
    LogFileDownloaderException,
)
from lib.live_cluster.ssh import SSHConnection, SSHConnectionFactory, SSHError


class LogInfoTest(unittest.TestCase):
    def test_init(self):
        log_info = _LogInfo("orig")
        self.assertEqual(log_info.original_src, "orig")
        self.assertEqual(log_info.local_destination, "")
        self.assertFalse(log_info.skip)


class RemoteLogInfoTest(unittest.TestCase):
    def test_init(self):
        log_info = _RemoteLogInfo("orig")
        self.assertEqual(log_info.original_src, "orig")
        self.assertEqual(log_info.local_destination, "")
        self.assertFalse(log_info.skip)
        self.assertEqual(log_info.tmp_src, "")


class MockNode:
    id = 0

    def __init__(self, ip: str, port: int, logs: list[str], localhost=False):
        self.ip = ip
        self.port = port
        self.logs = logs
        self.localhost = localhost
        self.node_id = MockNode.id
        MockNode.id += 1

    def is_localhost(self):
        return self.localhost

    async def info_logs_ids(self):
        return self.logs


class MockCluster:
    def __init__(self, nodes: list[MockNode]):
        self.nodes = nodes

    def get_nodes(self, nodes):
        return self.nodes


class LocalLogFileDownloaderNoExcHandlerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.node_mock = MockNode(
            "1.1.1.1", 3000, ["stderr", "log2.log"], localhost=True
        )
        self.cluster_mock = MockCluster([self.node_mock])
        patch("os.path.exists", MagicMock(return_value=False)).start()
        self.makedirs_mock = patch("os.makedirs", MagicMock()).start()
        self.shell_cmd_mock = patch(
            "lib.utils.util.async_shell_command", AsyncMock()
        ).start()

        self.path_gen_func = MagicMock(side_effect=self.path_gen_func_side_effect)

    def tearDown(self) -> None:
        MockNode.id = 0

    def path_gen_func_side_effect(self, node, log) -> str:
        if log == "stderr":
            log = log + ".log"
        return "path/" + str(node.node_id) + log

    def return_error_for_cmd(self, err_cmd):
        def shell_cmd_side_effect(cmd):
            p = MagicMock(Process)
            if cmd.startswith(err_cmd):
                p.returncode = 1
                p.stderr = MagicMock()
                p.stdout = MagicMock()
                p.stderr.read = AsyncMock()
                p.stdout.read = AsyncMock()
                p.stderr.read.return_value = b"error"
                p.stdout.read.return_value = b"output"
            else:
                p.returncode = 0

            return p

        return shell_cmd_side_effect

    async def test_download_local_node(self):
        self.shell_cmd_mock.return_value.returncode = 0

        await LogFileDownloader(self.cluster_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.makedirs_mock.assert_has_calls(
            [call("path", exist_ok=True), call("path", exist_ok=True)]
        )
        self.shell_cmd_mock.assert_has_calls(
            [
                call(
                    f"journalctl -u aerospike -a -o cat --since '1 day ago' | grep GMT > path/0stderr.log"
                ),
                call(f"gzip -c path/0stderr.log > path/0stderr.log.gz"),
                call(f"gzip -c log2.log > path/0log2.log.gz"),
            ]
        )

    async def test_local_node_fails_on_journald(self):
        self.shell_cmd_mock.side_effect = self.return_error_for_cmd("journalctl")
        self.shell_cmd_mock.return_value.returncode = 1

        with self.assertRaises(LogFileDownloaderException) as context:
            await LogFileDownloader(self.cluster_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.makedirs_mock.assert_has_calls([call("path", exist_ok=True)])
        self.shell_cmd_mock.assert_has_calls(
            [
                call(
                    f"journalctl -u aerospike -a -o cat --since '1 day ago' | grep GMT > path/0stderr.log"
                ),
            ]
        )

    async def test_local_node_fails_on_compression(self):
        self.shell_cmd_mock.side_effect = self.return_error_for_cmd("gzip")
        self.shell_cmd_mock.return_value.returncode = 1

        with self.assertRaises(LogFileDownloaderException) as context:
            await LogFileDownloader(self.cluster_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.makedirs_mock.assert_has_calls([call("path", exist_ok=True)])
        self.shell_cmd_mock.assert_has_calls(
            [
                call(
                    f"journalctl -u aerospike -a -o cat --since '1 day ago' | grep GMT > path/0stderr.log"
                ),
                call(f"gzip -c path/0stderr.log > path/0stderr.log.gz"),
                call(f"gzip -c log2.log > path/0log2.log.gz"),
            ]
        )

    async def test_local_node_fails_on_journald_with_handler(self):
        self.shell_cmd_mock.side_effect = self.return_error_for_cmd("journalctl")
        self.shell_cmd_mock.return_value.returncode = 1

        def error_handler_side_effect(node: Node, exc: Exception):
            pass

        error_handler = MagicMock(side_effect=error_handler_side_effect)

        await LogFileDownloader(self.cluster_mock, SSHConnectionFactory(), exception_handler=error_handler).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.makedirs_mock.assert_has_calls([call("path", exist_ok=True)])
        self.shell_cmd_mock.assert_has_calls(
            [
                call(
                    f"journalctl -u aerospike -a -o cat --since '1 day ago' | grep GMT > path/0stderr.log"
                ),
                call(f"gzip -c log2.log > path/0log2.log.gz"),
            ]
        )

        self.assertEqual(error_handler.call_count, 1)
        self.assertEqual(error_handler.call_args_list[0][0][1], self.node_mock)
        self.assertIsInstance(
            error_handler.call_args_list[0][0][0], LogFileDownloaderException
        )
        self.assertEqual(
            str(error_handler.call_args_list[0][0][0]),
            "(1.1.1.1:3000) Failed to generate log file from local console log: error",
        )

    async def test_local_node_fails_on_compression_with_handler(self):
        self.shell_cmd_mock.side_effect = self.return_error_for_cmd("gzip")
        self.shell_cmd_mock.return_value.returncode = 1

        def error_handler_side_effect(exc: Exception, node: Node):
            pass

        error_handler = MagicMock(side_effect=error_handler_side_effect)

        await LogFileDownloader(self.cluster_mock, SSHConnectionFactory(), exception_handler=error_handler).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.makedirs_mock.assert_has_calls([call("path", exist_ok=True)])
        self.shell_cmd_mock.assert_has_calls(
            [
                call(
                    f"journalctl -u aerospike -a -o cat --since '1 day ago' | grep GMT > path/0stderr.log"
                ),
                call(f"gzip -c path/0stderr.log > path/0stderr.log.gz"),
                call(f"gzip -c log2.log > path/0log2.log.gz"),
            ]
        )

        self.assertEqual(error_handler.call_count, 2)

        for call_ in error_handler.call_args_list:
            self.assertEqual(call_[0][1], self.node_mock)
            self.assertIsInstance(call_[0][0], LogFileDownloaderException)
            self.assertTrue(
                "(1.1.1.1:3000) Failed to compress "
                in str(error_handler.call_args_list[0][0][0])
            )


class RemoteLogFileDownloadersTest(unittest.IsolatedAsyncioTestCase):
    def path_gen_func_side_effect(self, node, log) -> str:
        if log == "stderr":
            log = log + ".log"
        return "path/" + str(node.node_id) + log

    def return_error_for_cmd(self, err_cmd, raise_on_error=True):
        def conn_run_side_effect(cmd):
            p = MagicMock(Process)

            if err_cmd and cmd.startswith(err_cmd):
                if raise_on_error:
                    raise SSHError(f"{err_cmd} error")
                p.returncode = 1
                p.stderr = f"{err_cmd} error"
            else:
                p.returncode = 0

            return p

        return conn_run_side_effect

    async def asyncSetUp(self) -> None:
        self.datatime_mock = patch(
            "lib.live_cluster.logfile_downloader.datetime"
        ).start()
        self.datatime_mock.now.return_value.strftime.return_value = "time_prefix"
        self.node_mock = MockNode(
            "1.1.1.1", 3000, ["stderr", "log2.log"], localhost=False
        )
        self.cluster_mock = MockCluster([self.node_mock])
        self.factory_mock = MagicMock(SSHConnectionFactory)
        self.conn_mock = AsyncMock(SSHConnection)
        self.factory_mock.create_connection.return_value = self.conn_mock
        self.conn_mock.__aenter__.return_value = self.conn_mock
        self.sftp_mock = AsyncMock()
        self.conn_mock.start_sftp_client.return_value.__aenter__.return_value = (
            self.sftp_mock
        )
        self.path_gen_func = MagicMock(side_effect=self.path_gen_func_side_effect)
        self.file_transfer_mock = patch(
            "lib.live_cluster.logfile_downloader.FileTransfer",
        ).start()
        self.file_transfer_mock.remote_to_local = AsyncMock(return_value=[])

    def tearDown(self) -> None:
        MockNode.id = 0

    async def test_download_remote_node(self):
        self.conn_mock.run.side_effect = self.return_error_for_cmd(None)

        await LogFileDownloader(self.cluster_mock, self.factory_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.conn_mock.run.assert_has_calls(
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
                call(
                    f"gzip -c /tmp/time_prefix/0/stderr.log > /tmp/time_prefix/0/stderr.log.gz"
                ),
                call(f"gzip -c log2.log > /tmp/time_prefix/0/log2.log.gz"),
            ]
        )
        self.file_transfer_mock.remote_to_local.assert_called_once_with(
            [
                ("/tmp/time_prefix/0/stderr.log.gz", "path/0stderr.log.gz"),
                ("/tmp/time_prefix/0/log2.log.gz", "path/0log2.log.gz"),
            ],
            self.conn_mock,
            return_exceptions=False,
        )
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")

    async def test_remote_node_journalctl_fails(self):
        self.conn_mock.run.side_effect = self.return_error_for_cmd("journalctl")

        with self.assertRaises(SSHError) as context:
            await LogFileDownloader(self.cluster_mock, self.factory_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.conn_mock.run.assert_has_calls(
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
            ]
        )
        self.file_transfer_mock.assert_not_called()
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")

    async def test_remote_node_gzip_fails(self):
        self.conn_mock.run.side_effect = self.return_error_for_cmd("gzip")

        with self.assertRaises(SSHError) as context:
            await LogFileDownloader(self.cluster_mock, self.factory_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.conn_mock.run.assert_has_calls(
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
                call(
                    f"gzip -c /tmp/time_prefix/0/stderr.log > /tmp/time_prefix/0/stderr.log.gz"
                ),
                call(f"gzip -c log2.log > /tmp/time_prefix/0/log2.log.gz"),
            ]
        )
        self.file_transfer_mock.assert_not_called()
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")

    async def test_remote_node_transfer_raises(self):
        self.file_transfer_mock.remote_to_local = AsyncMock(side_effect=Exception("0"))

        self.conn_mock.run.side_effect = self.return_error_for_cmd(None)

        with self.assertRaises(Exception) as exc:
            await LogFileDownloader(self.cluster_mock, self.factory_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.conn_mock.run.assert_has_calls(
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
                call(
                    f"gzip -c /tmp/time_prefix/0/stderr.log > /tmp/time_prefix/0/stderr.log.gz"
                ),
                call(f"gzip -c log2.log > /tmp/time_prefix/0/log2.log.gz"),
            ]
        )
        self.file_transfer_mock.remote_to_local.assert_called_once_with(
            [
                ("/tmp/time_prefix/0/stderr.log.gz", "path/0stderr.log.gz"),
                ("/tmp/time_prefix/0/log2.log.gz", "path/0log2.log.gz"),
            ],
            self.conn_mock,
            return_exceptions=False,
        )
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")
        self.assertEqual(str(exc.exception), "0")

    async def test_remote_node_journalctl_fails_with_non_zero(self):
        self.conn_mock.run.side_effect = self.return_error_for_cmd(
            "journalctl", raise_on_error=False
        )

        with self.assertRaises(LogFileDownloaderException) as context:
            await LogFileDownloader(self.cluster_mock, self.factory_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.conn_mock.run.assert_has_calls(
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
            ]
        )
        self.file_transfer_mock.assert_not_called()
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")
        self.assertEqual(
            str(context.exception),
            "(1.1.1.1:3000) Failed to copy journald to /tmp/time_prefix/0/stderr.log: journalctl error",
        )

    async def test_remote_node_gzip_fails_with_non_zero(self):
        self.conn_mock.run.side_effect = self.return_error_for_cmd(
            "gzip", raise_on_error=False
        )

        with self.assertRaises(LogFileDownloaderException) as context:
            await LogFileDownloader(self.cluster_mock, self.factory_mock).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.conn_mock.run.assert_has_calls(
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
                call(
                    f"gzip -c /tmp/time_prefix/0/stderr.log > /tmp/time_prefix/0/stderr.log.gz"
                ),
                call(f"gzip -c log2.log > /tmp/time_prefix/0/log2.log.gz"),
            ]
        )
        self.file_transfer_mock.assert_not_called()
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")
        self.assertEqual(
            str(context.exception),
            "(1.1.1.1:3000) Failed to compress /tmp/time_prefix/0/stderr.log: gzip error",
        )

    async def test_remote_node_journalctl_fails_with_handler(self):
        def error_handler_side_effect(node: Node, exc: Exception):
            pass

        error_handler = MagicMock(side_effect=error_handler_side_effect)

        self.conn_mock.run.side_effect = self.return_error_for_cmd("journalctl")

        await LogFileDownloader(self.cluster_mock, self.factory_mock, error_handler).download(self.path_gen_func)  # type: ignore

        self.assertEqual(
            self.path_gen_func.mock_calls,
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")],
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.assertEqual(
            self.conn_mock.run.mock_calls,
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
                call(f"gzip -c log2.log > /tmp/time_prefix/0/log2.log.gz"),
            ],
        )
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")
        self.file_transfer_mock.remote_to_local.assert_called_once_with(
            [
                ("/tmp/time_prefix/0/log2.log.gz", "path/0log2.log.gz"),
            ],
            self.conn_mock,
            return_exceptions=True,
        )

        self.assertEqual(error_handler.call_count, 1)

        for call_ in error_handler.call_args_list:
            self.assertEqual(call_[0][1], self.node_mock)
            self.assertIsInstance(call_[0][0], SSHError)
            self.assertTrue(
                "journalctl error" in str(error_handler.call_args_list[0][0][0])
            )

    async def test_remote_node_gzip_fails_with_handler(self):
        def error_handler_side_effect(node: Node, exc: Exception):
            pass

        error_handler = MagicMock(side_effect=error_handler_side_effect)
        err_count = 0

        def conn_run_side_effect(cmd):
            nonlocal err_count
            if cmd.startswith("gzip") and err_count < 1:
                err_count += 1
                raise SSHError(f"gzip error")
            else:
                p = MagicMock(Process)
                p.returncode = 0
                return p

        self.conn_mock.run.side_effect = conn_run_side_effect

        await LogFileDownloader(self.cluster_mock, self.factory_mock, error_handler).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.assertEqual(
            self.conn_mock.run.mock_calls,
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
                call(
                    f"gzip -c /tmp/time_prefix/0/stderr.log > /tmp/time_prefix/0/stderr.log.gz"
                ),
                call(f"gzip -c log2.log > /tmp/time_prefix/0/log2.log.gz"),
            ],
        )
        self.file_transfer_mock.remote_to_local.assert_called_once_with(
            [
                ("/tmp/time_prefix/0/log2.log.gz", "path/0log2.log.gz"),
            ],
            self.conn_mock,
            return_exceptions=True,
        )
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")

        self.assertEqual(error_handler.call_count, 1)

        for call_ in error_handler.call_args_list:
            self.assertEqual(call_[0][1], self.node_mock)
            self.assertIsInstance(call_[0][0], SSHError)
            self.assertTrue("gzip error" in str(error_handler.call_args_list[0][0][0]))

    async def test_remote_node_transfer_fails_with_handler(self):
        self.file_transfer_mock.remote_to_local = AsyncMock(
            return_value=[Exception("0"), None, Exception("1")]
        )

        def error_handler_side_effect(exc: Exception, node: Node):
            pass

        error_handler = MagicMock(side_effect=error_handler_side_effect)

        self.conn_mock.run.side_effect = self.return_error_for_cmd(None)

        await LogFileDownloader(self.cluster_mock, self.factory_mock, error_handler).download(self.path_gen_func)  # type: ignore

        self.path_gen_func.assert_has_calls(
            [call(self.node_mock, "stderr"), call(self.node_mock, "log2.log")]
        )
        self.sftp_mock.makedirs.assert_called_once_with("/tmp/time_prefix/0/")
        self.assertEqual(
            self.conn_mock.run.mock_calls,
            [
                call(
                    f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > /tmp/time_prefix/0/stderr.log'
                ),
                call(
                    f"gzip -c /tmp/time_prefix/0/stderr.log > /tmp/time_prefix/0/stderr.log.gz"
                ),
                call(f"gzip -c log2.log > /tmp/time_prefix/0/log2.log.gz"),
            ],
        )
        self.file_transfer_mock.remote_to_local.assert_called_once_with(
            [
                ("/tmp/time_prefix/0/stderr.log.gz", "path/0stderr.log.gz"),
                ("/tmp/time_prefix/0/log2.log.gz", "path/0log2.log.gz"),
            ],
            self.conn_mock,
            return_exceptions=True,
        )
        self.sftp_mock.rmtree.assert_called_once_with("/tmp/time_prefix/0/")

        self.assertEqual(error_handler.call_count, 2)

        for call_ in error_handler.call_args_list:
            self.assertEqual(call_[0][1], self.node_mock)
            self.assertIsInstance(call_[0][0], Exception)
