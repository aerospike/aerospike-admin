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

import time
from pytest import PytestUnraisableExceptionWarning
from mock import AsyncMock, Mock, patch, create_autospec
from mock.mock import call
from lib.live_cluster import ssh
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.collectlogs_controller import CollectlogsController

import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import asynctest


class CollectLogsControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        patch(
            "lib.live_cluster.collectlogs_controller.time.gmtime", autospec=True
        ).start().return_value = time.gmtime(1693259247)
        patch(
            "lib.live_cluster.collectlogs_controller.os.makedirs", autospec=True
        ).start().return_value = True
        fh_mock = Mock()
        patch(
            "lib.live_cluster.collectlogs_controller.logging.FileHandler", autospec=True
        ).start().return_value = fh_mock

        def setLevel_side_effect(level):
            fh_mock.level = level

        fh_mock.setLevel.side_effect = setLevel_side_effect

        self.controller = CollectlogsController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.logger_mock = patch(
            "lib.live_cluster.collectlogs_controller.logger"
        ).start()
        self.controller.mods = (
            {}
        )  # For some reason they are being polluted from other tests
        self.mods = {}

        self.addCleanup(patch.stopall)

    async def test_flags(self):
        line = "--enable-ssh --ssh-user user --ssh-pwd pwd --ssh-port 22 --ssh-key key --ssh-key-pwd key-pwd --output-prefix prefix"
        self.controller._gather_logs = AsyncMock()

        await self.controller.execute(line.split())

        self.controller._gather_logs.assert_called_once_with(
            "/tmp/prefix_collect_logs_20230828_214727/20230828_214727_",
            True,
            "user",
            "pwd",
            "key",
            "key-pwd",
            22,
        )

    async def test_gather_logs_returns_error(self):
        line = ""
        exc = Exception("test")
        self.controller._gather_logs = AsyncMock(side_effect=exc)
        archive_dir = patch(
            "lib.live_cluster.collectlogs_controller.common.archive_dir",
            autospec=True,
        ).start()
        summary_mock = patch(
            "lib.live_cluster.collectlogs_controller.common.print_collect_summary",
            autospec=True,
        ).start()

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_with(exc)
        archive_dir.assert_not_called()
        summary_mock.assert_not_called()

    async def test_archive_returns_unsuccessful(self):
        line = ""
        self.controller._gather_logs = AsyncMock()
        archive_dir = patch(
            "lib.live_cluster.collectlogs_controller.common.archive_dir",
            autospec=True,
        ).start()
        summary_mock = patch(
            "lib.live_cluster.collectlogs_controller.common.print_collect_summary",
            autospec=True,
        ).start()
        archive_dir.return_value = ("log_archive", False)

        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_with(
            "Failed to archive collectinfo logs. See earlier errors for more details."
        )
        summary_mock.assert_not_called()

    async def test_successfully_gather_logs(self):
        downloader_mock = None
        factory_mock = None
        self.controller.teardown_loggers = Mock()
        archive_dir = patch(
            "lib.live_cluster.collectlogs_controller.common.archive_dir",
            autospec=True,
        ).start()
        summary_mock = patch(
            "lib.live_cluster.collectlogs_controller.common.print_collect_summary",
            autospec=True,
        ).start()

        archive_dir.return_value = ("log_archive", True)

        class MockLogFileDownloader:
            def __init__(self, cluster, factory, exception_handler):
                nonlocal downloader_mock
                self.cluster = cluster
                self.factory = factory
                self.handler = exception_handler
                downloader_mock = self

            async def download(self, func):
                mock_node = Mock()
                mock_node.node_id = "node1"
                func(mock_node, "filename")

        class MockSSHConnectionFactory:
            def __init__(self, config):
                nonlocal factory_mock
                self.config = config
                factory_mock = self

        patch(
            "lib.live_cluster.collectlogs_controller.ssh.SSHConnectionFactory",
            MockSSHConnectionFactory,
        ).start()
        patch(
            "lib.live_cluster.collectlogs_controller.LogFileDownloader",
            MockLogFileDownloader,
        ).start()

        line = "--enable-ssh --ssh-user user --ssh-pwd pwd --ssh-port 22"
        await self.controller.execute(line.split())

        self.logger_mock.info.assert_called_with(
            "Successfully downloaded logs from all nodes."
        )
        self.assertEqual(self.cluster_mock, downloader_mock.cluster)  # type: ignore
        self.assertEqual(factory_mock, downloader_mock.factory)  # type: ignore
        archive_dir.assert_called_once_with("/tmp/collect_logs_20230828_214727")
        summary_mock.assert_called_once_with("log_archive")
        self.controller.teardown_loggers.assert_called_once()

    async def test_cannot_create_connection(self):
        self.controller.teardown_loggers = Mock()
        archive_dir = patch(
            "lib.live_cluster.collectlogs_controller.common.archive_dir",
            autospec=True,
        ).start()
        summary_mock = patch(
            "lib.live_cluster.collectlogs_controller.common.print_collect_summary",
            autospec=True,
        ).start()
        archive_dir.return_value = ("log_archive", True)

        class MockSSHConnectionFactory:
            def __init__(self, config):
                self.config = config
                raise FileNotFoundError("Could not create connection")

        patch(
            "lib.live_cluster.collectlogs_controller.ssh.SSHConnectionFactory",
            MockSSHConnectionFactory,
        ).start()

        line = "--enable-ssh --ssh-user user --ssh-pwd pwd --ssh-port 22"
        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_with(
            "Could not create SSH connection: Could not create connection"
        )

        archive_dir.assert_not_called()
        summary_mock.assert_not_called()
        self.controller.teardown_loggers.assert_called_once()

    async def test_fails_to_connect_to_some_nodes(self):
        self.controller.teardown_loggers = Mock()
        archive_dir = patch(
            "lib.live_cluster.collectlogs_controller.common.archive_dir",
            autospec=True,
        ).start()
        summary_mock = patch(
            "lib.live_cluster.collectlogs_controller.common.print_collect_summary",
            autospec=True,
        ).start()
        self.cluster_mock.get_nodes.return_value = [Mock(), Mock()]

        archive_dir.return_value = ("log_archive", True)

        class MockLogFileDownloader:
            def __init__(self, cluster, factory, exception_handler):
                self.cluster = cluster
                self.factory = factory
                self.handler = exception_handler

                exception_handler(ssh.SSHConnectionError("test"), Mock())

            async def download(self, func):
                mock_node = Mock()
                mock_node.node_id = "node1"
                func(mock_node, "filename")

        patch(
            "lib.live_cluster.collectlogs_controller.ssh.SSHConnectionFactory",
            autospec=True,
        ).start()
        patch(
            "lib.live_cluster.collectlogs_controller.LogFileDownloader",
            MockLogFileDownloader,
        ).start()

        line = "--enable-ssh --ssh-user user --ssh-pwd pwd --ssh-port 22"
        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_with(
            "Failed to download logs from some nodes."
        )
        archive_dir.assert_called_once_with("/tmp/collect_logs_20230828_214727")
        summary_mock.assert_called_once_with("log_archive")
        self.controller.teardown_loggers.assert_called_once()

    async def test_no_downloads_because_ssh_disabled(self):
        self.controller.teardown_loggers = Mock()
        archive_dir = patch(
            "lib.live_cluster.collectlogs_controller.common.archive_dir",
            autospec=True,
        ).start()
        summary_mock = patch(
            "lib.live_cluster.collectlogs_controller.common.print_collect_summary",
            autospec=True,
        ).start()
        self.cluster_mock.get_nodes.return_value = [Mock(), Mock()]
        archive_dir.return_value = ("log_archive", True)
        patch(
            "lib.live_cluster.collectlogs_controller.ssh.SSHConnectionFactory",
            autospec=True,
        ).start()
        patch(
            "lib.live_cluster.collectlogs_controller.LogFileDownloader",
            autospec=True,
        ).start()

        line = "--ssh-user user --ssh-pwd pwd --ssh-port 22"
        await self.controller.execute(line.split())

        self.logger_mock.error.assert_called_with(
            "No logs were downloaded. Use --enable-ssh to download logs from remote nodes."
        )
        archive_dir.assert_not_called()
        summary_mock.assert_not_called()
        self.controller.teardown_loggers.assert_called_once()
