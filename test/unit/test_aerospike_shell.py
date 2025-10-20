from asadm import AerospikeShell
import asadm

import asynctest
import asyncio
from mock import AsyncMock, Mock, patch
from mock.mock import call
from lib.utils import async_object
from lib.utils.constants import AdminMode


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
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()
        mock_logger = patch("asadm.logger", autospec=True).start()
        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = True
        patch(
            "readline.write_history_file",
            Mock(),
        ).start()  # Need to override or test will fail in github actions where user is root
        patch(
            "readline.read_history_file",
            Mock(),
        ).start()  # Need to override or test will fail in github actions where user is root
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

    async def test_admin_port_visual_cue_prompt_switching(self):
        """Test admin port visual cue functionality - prompt switching based on admin nodes"""

        class ClusterMock:
            def has_admin_nodes(self):
                return True

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()
        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = False
        patch("readline.write_history_file", Mock()).start()
        patch("readline.read_history_file", Mock()).start()
        self.addCleanup(patch.stopall)

        shell = await AerospikeShell("test-version", seeds=[("1.1.1.1", 3000, None)])

        # Test admin node detection
        self.assertTrue(shell._has_admin_nodes())

        # Test default prompt uses ADMIN prompt when admin nodes present
        with patch.object(shell, "set_prompt") as mock_set_prompt:
            shell.set_default_prompt()
            mock_set_prompt.assert_called_once_with("ADMIN> ", "green")

        # Test privileged prompt uses ADMIN+ prompt when admin nodes present
        with patch.object(shell, "set_prompt") as mock_set_prompt:
            shell.set_privaliged_prompt()
            mock_set_prompt.assert_called_once_with("ADMIN+> ", "red")

    async def test_admin_port_visual_cue_no_admin_nodes(self):
        """Test admin port visual cue functionality - regular prompts when no admin nodes"""

        class ClusterMock:
            def has_admin_nodes(self):
                return False

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()
        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = False
        patch("readline.write_history_file", Mock()).start()
        patch("readline.read_history_file", Mock()).start()
        self.addCleanup(patch.stopall)

        shell = await AerospikeShell("test-version", seeds=[("1.1.1.1", 3000, None)])

        # Test no admin node detection
        self.assertFalse(shell._has_admin_nodes())

        # Test default prompt uses regular prompt when no admin nodes
        with patch.object(shell, "set_prompt") as mock_set_prompt:
            shell.set_default_prompt()
            mock_set_prompt.assert_called_once_with("Admin> ", "green")

        # Test privileged prompt uses regular prompt when no admin nodes
        with patch.object(shell, "set_prompt") as mock_set_prompt:
            shell.set_privaliged_prompt()
            mock_set_prompt.assert_called_once_with("Admin+> ", "red")

    async def test_admin_port_visual_cue_error_handling(self):
        """Test admin port visual cue functionality - error handling in _has_admin_nodes"""

        class ClusterMock:
            def has_admin_nodes(self):
                raise Exception("Connection error")

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()
        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = False
        patch("readline.write_history_file", Mock()).start()
        patch("readline.read_history_file", Mock()).start()
        self.addCleanup(patch.stopall)

        shell = await AerospikeShell("test-version", seeds=[("1.1.1.1", 3000, None)])

        # Test error handling returns False
        self.assertFalse(shell._has_admin_nodes())

        # Test fallback to regular prompt on error
        with patch.object(shell, "set_prompt") as mock_set_prompt:
            shell.set_default_prompt()
            mock_set_prompt.assert_called_once_with("Admin> ", "green")

    async def test_history_file_read_failure_fallback_to_write(self):
        """Test that when history file can't be read, it tries to write and handles write failure gracefully"""

        class ClusterMock:
            def get_live_nodes(*args, **kwargs):
                return [("1.1.1.1", 3000, None)]

            def get_visibility_error_nodes(*args, **kwargs):
                return []

            async def get_down_nodes(*args, **kwargs):
                return []

            def __str__(self):
                return "Online: 1.1.1.1:3000"

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()

        # Mock readline functions to simulate read-only filesystem
        mock_read_history = patch("readline.read_history_file").start()
        mock_write_history = patch("readline.write_history_file").start()

        # Simulate read failure followed by write failure (read-only filesystem)
        mock_read_history.side_effect = FileNotFoundError("History file not found")
        mock_write_history.side_effect = PermissionError("Read-only filesystem")

        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = False

        self.addCleanup(patch.stopall)

        # Should not raise exception despite filesystem errors
        shell = await AerospikeShell("test-version", seeds=[("1.1.1.1", 3000, None)])
        self.assertTrue(shell.connected)

        # Verify both read and write were attempted
        mock_read_history.assert_called_once()
        mock_write_history.assert_called_once()

    async def test_history_file_save_on_exit_handles_permission_error(self):
        """Test that history file save on exit handles PermissionError gracefully"""

        class ClusterMock:
            def get_live_nodes(*args, **kwargs):
                return [("1.1.1.1", 3000, None)]

            def get_visibility_error_nodes(*args, **kwargs):
                return []

            async def get_down_nodes(*args, **kwargs):
                return []

            def __str__(self):
                return "Online: 1.1.1.1:3000"

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()

        # Mock readline functions
        patch("readline.read_history_file").start()
        mock_write_history = patch("readline.write_history_file").start()
        mock_get_history_length = patch("readline.get_current_history_length").start()

        # Simulate having history to save but write fails due to read-only filesystem
        mock_get_history_length.return_value = 5
        mock_write_history.side_effect = PermissionError("Read-only filesystem")

        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = False

        self.addCleanup(patch.stopall)

        shell = await AerospikeShell("test-version", seeds=[("1.1.1.1", 3000, None)])

        # Should not raise exception when exiting despite write failure
        result = await shell.do_exit("")
        self.assertTrue(result)

        # Verify write was attempted
        mock_write_history.assert_called_once()

    async def test_execute_mode_skips_history_operations(self):
        """Test that execute mode skips all history file operations"""

        class ClusterMock:
            def get_live_nodes(*args, **kwargs):
                return [("1.1.1.1", 3000, None)]

            def get_visibility_error_nodes(*args, **kwargs):
                return []

            async def get_down_nodes(*args, **kwargs):
                return []

            def __str__(self):
                return "Online: 1.1.1.1:3000"

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()

        # Mock readline functions
        mock_read_history = patch("readline.read_history_file").start()
        mock_write_history = patch("readline.write_history_file").start()
        mock_get_history_length = patch("readline.get_current_history_length").start()

        mock_get_history_length.return_value = 5

        patch(
            "asadm.AerospikeShell.active_stop_writes",
            AsyncMock(),
        ).start().return_value = False

        self.addCleanup(patch.stopall)

        # Create shell in execute mode
        shell = await AerospikeShell(
            "test-version", seeds=[("1.1.1.1", 3000, None)], execute_only_mode=True
        )

        # Exit in execute mode
        result = await shell.do_exit("")
        self.assertTrue(result)

        # Verify no history operations were attempted in execute mode
        mock_read_history.assert_not_called()
        mock_write_history.assert_not_called()


class AdminHomeDirTest(asynctest.TestCase):
    """Test ADMIN_HOME directory creation behavior"""

    def test_admin_home_creation_success_in_interactive_mode(self):
        """Test that ADMIN_HOME is created successfully in interactive mode"""
        with patch("sys.argv", ["asadm.py"]):
            with patch("asadm.conf.get_cli_args") as mock_get_cli_args:
                mock_args = Mock()
                mock_args.execute = None  # Interactive mode
                mock_args.debug = False
                mock_args.help = False
                mock_args.version = False
                mock_args.no_color = False
                mock_args.pmap = False
                mock_args.collectinfo = False
                mock_args.log_analyser = False
                mock_args.json = False
                mock_get_cli_args.return_value = mock_args

                with patch("os.path.isdir") as mock_isdir:
                    mock_isdir.return_value = False  # Directory doesn't exist

                    with patch("os.makedirs") as mock_makedirs:
                        with patch("asadm.conf.loadconfig") as mock_loadconfig:
                            mock_loadconfig.return_value = (mock_args, [])

                            with patch("asadm.AerospikeShell") as mock_shell:
                                mock_shell.return_value = AsyncMock()
                                mock_shell.return_value.connected = False

                                # This should attempt to create ADMIN_HOME
                                try:
                                    asyncio.run(asadm.main())
                                except SystemExit:
                                    pass  # Expected due to no connection

                                # Verify makedirs was called
                                mock_makedirs.assert_called_once()

    def test_admin_home_creation_failure_logs_warning(self):
        """Test that ADMIN_HOME creation failure logs appropriate warning"""
        with patch("sys.argv", ["asadm.py"]):
            with patch("asadm.conf.get_cli_args") as mock_get_cli_args:
                mock_args = Mock()
                mock_args.execute = None  # Interactive mode
                mock_args.debug = False
                mock_args.help = False
                mock_args.version = False
                mock_args.no_color = False
                mock_args.pmap = False
                mock_args.collectinfo = False
                mock_args.log_analyser = False
                mock_args.json = False
                mock_get_cli_args.return_value = mock_args

                with patch("os.path.isdir") as mock_isdir:
                    mock_isdir.return_value = False  # Directory doesn't exist

                    with patch("os.makedirs") as mock_makedirs:
                        mock_makedirs.side_effect = PermissionError(
                            "Read-only filesystem"
                        )

                        with patch("asadm.logger") as mock_logger:
                            with patch("asadm.conf.loadconfig") as mock_loadconfig:
                                mock_loadconfig.return_value = (mock_args, [])

                                with patch("asadm.AerospikeShell") as mock_shell:
                                    mock_shell.return_value = AsyncMock()
                                    mock_shell.return_value.connected = False

                                    # This should attempt to create ADMIN_HOME and log warning
                                    try:
                                        asyncio.run(asadm.main())
                                    except SystemExit:
                                        pass  # Expected due to no connection

                                    # Verify warning was logged
                                    mock_logger.warning.assert_called()
                                    warning_calls = mock_logger.warning.call_args_list
                                    self.assertTrue(
                                        any(
                                            "Cannot create history directory"
                                            in str(call)
                                            for call in warning_calls
                                        )
                                    )

    def test_admin_home_skipped_in_execute_mode(self):
        """Test that ADMIN_HOME creation is skipped in execute mode"""
        with patch("sys.argv", ["asadm.py", "-e", "help"]):
            with patch("asadm.conf.get_cli_args") as mock_get_cli_args:
                mock_args = Mock()
                mock_args.execute = "help"  # Execute mode
                mock_args.debug = False
                mock_args.help = False
                mock_args.version = False
                mock_args.no_color = False
                mock_args.pmap = False
                mock_args.collectinfo = False
                mock_args.log_analyser = False
                mock_args.json = False
                mock_get_cli_args.return_value = mock_args

                with patch("os.path.isdir") as mock_isdir:
                    with patch("os.makedirs") as mock_makedirs:
                        with patch("asadm.conf.loadconfig") as mock_loadconfig:
                            mock_loadconfig.return_value = (mock_args, [])

                            with patch("asadm.AerospikeShell") as mock_shell:
                                mock_shell.return_value = AsyncMock()
                                mock_shell.return_value.connected = False

                                # This should skip ADMIN_HOME creation
                                try:
                                    asyncio.run(asadm.main())
                                except SystemExit:
                                    pass  # Expected due to no connection

                                # Verify makedirs was never called
                                mock_makedirs.assert_not_called()
                                # isdir should also not be called since we skip the whole block
                                mock_isdir.assert_not_called()
