import asynctest
from mock import AsyncMock, patch
from mock.mock import call

from asadm import AerospikeShell
from lib.live_cluster.client import Cluster
from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController
from lib.utils import async_object


class AerospikeShellTest(asynctest.TestCase):
    async def test_live_cluster_init_successful(self):
        class ClusterMock:
            def get_live_nodes(*args, **kwargs):
                return [("1.1.1.1", 3000, None)]

            def get_visibility_error_nodes(*args, **kwargs):
                return ["2.2.2.2:3000"]

            async def get_down_nodes(*args, **kwargs):
                return ["3.3.3.3:3000"]

            def __str__(self):
                return "Online: 1.1.1.1:3000"

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",  # Target class to patch
            MockLiveClusterRootController,  # Mocked class
        ).start()
        mock_logger = patch(
            "asadm.logger", autospec=True  # Target class to patch  # Mocked class
        ).start()
        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = True
        self.addCleanup(patch.stopall)
        shell = await AerospikeShell("test-version", seeds=[("1.1.1.1", 3000, None)])  # type: ignore
        self.assertEqual(shell.intro, "Online: 1.1.1.1:3000\n")
        mock_logger.warning.assert_has_calls(
            [
                call(
                    "Some nodes are unable to connect to other nodes in the cluster. 2.2.2.2:3000"
                ),
                call(
                    "Some nodes have become unreachable by other nodes in the cluster. Check their peers lists: 3.3.3.3:3000"
                ),
                call(
                    "This cluster is currently in stop writes. Run `show stop-writes` for more details."
                ),
            ]
        )

    async def test_live_cluster_init_fails_with_no_live_nodes(self):
        class ClusterMock:
            def get_live_nodes(*args, **kwargs):
                return []

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()
        mock_logger = patch("asadm.logger", autospec=True).start()
        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = True
        self.addCleanup(patch.stopall)
        shell = await AerospikeShell("test-version", seeds=[("1.1.1.1", 3000, None)])  # type: ignore
        self.assertFalse(shell.connected)
        mock_logger.error.assert_called_once_with(
            "Not able to connect any cluster with [('1.1.1.1', 3000, None)]."
        )
