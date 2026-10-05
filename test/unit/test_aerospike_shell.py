from asadm import AerospikeShell
import asadm

import asyncio
import io
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch, call
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from lib.base_controller import ShellException
from lib.utils import async_object
from lib.utils.constants import AdminMode


class AerospikeShellTest(unittest.IsolatedAsyncioTestCase):
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

            def get_parked_nodes(*args, **kwargs):
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

    async def test_live_cluster_init_succeeds_with_only_a_parked_node(self):
        """
        TOOLS-3976 - a node parked by checkpoint-save is not alive, but it still
        serves checkpoint-status. Bailing out here made 'manage checkpoint status'
        impossible to run against the one node it exists to poll.
        """
        parked = Mock()
        parked.key = "1.1.1.1:3000"

        class ClusterMock:
            def get_live_nodes(*args, **kwargs):
                return []

            def get_parked_nodes(*args, **kwargs):
                return [parked]

            def __str__(self):
                return "Offline: 1.1.1.1:3000"

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()
        mock_logger = patch("asadm.logger", autospec=True).start()
        patch(
            "readline.read_history_file",
            Mock(),
        ).start()
        self.addCleanup(patch.stopall)

        shell = await AerospikeShell(  # type: ignore
            "test-version",
            seeds=[("1.1.1.1", 3000, None)],
            execute_only_mode=True,
        )

        self.assertTrue(shell.connected)
        mock_logger.error.assert_not_called()
        self.assertIn("Parked by checkpoint-save", mock_logger.warning.call_args[0][0])

    async def test_live_cluster_init_succeeds_with_only_a_parked_node_interactively(
        self,
    ):
        """
        Every startup diagnostic fans out through the Cluster, which refuses the call
        when no node is live. Interactively that raised out of __init__ and killed the
        session with a traceback - the one session 'manage checkpoint status' needs.
        The mock has none of the diagnostic methods, so reaching any of them fails.
        """
        parked = Mock()
        parked.key = "1.1.1.1:3000"

        class ClusterMock:
            def get_live_nodes(*args, **kwargs):
                return []

            def get_parked_nodes(*args, **kwargs):
                return [parked]

            def has_admin_nodes(*args, **kwargs):
                return False

            def __str__(self):
                return "Offline: 1.1.1.1:3000"

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                self.cluster = ClusterMock()

        patch(
            "asadm.LiveClusterRootController",
            MockLiveClusterRootController,
        ).start()
        mock_logger = patch("asadm.logger", autospec=True).start()
        patch("readline.read_history_file", Mock()).start()
        patch("readline.write_history_file", Mock()).start()
        self.addCleanup(patch.stopall)

        shell = await AerospikeShell(  # type: ignore
            "test-version",
            seeds=[("1.1.1.1", 3000, None)],
        )

        self.assertTrue(shell.connected)
        mock_logger.error.assert_not_called()
        mock_logger.critical.assert_not_called()
        self.assertIn("Offline: 1.1.1.1:3000", shell.intro)
        self.assertIn("Parked by checkpoint-save", mock_logger.warning.call_args[0][0])

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


class AdminHomeDirTest(unittest.IsolatedAsyncioTestCase):
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
                mock_args.log_analyzer = False
                mock_args.json = False
                mock_args.user = None
                mock_args.tls_enable = False
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
                mock_args.log_analyzer = False
                mock_args.json = False
                mock_args.user = None
                mock_args.tls_enable = False
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
                mock_args.log_analyzer = False
                mock_args.json = False
                mock_args.user = None
                mock_args.tls_enable = False
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


class CleanLineTest(unittest.TestCase):
    """Bare instance skips the async cluster-connect setup."""

    def clean(self, line):
        shell = object.__new__(AerospikeShell)
        return AerospikeShell.clean_line(shell, line)

    def test_single_command(self):
        self.assertEqual(self.clean("show config"), [["show", "config"]])

    def test_extra_whitespace_collapsed(self):
        self.assertEqual(self.clean("  show    config  "), [["show", "config"]])

    def test_empty_and_whitespace_only(self):
        self.assertEqual(self.clean(""), [])
        self.assertEqual(self.clean("   "), [])

    def test_semicolon_with_spaces_splits(self):
        self.assertEqual(
            self.clean("show config ; show statistics"),
            [["show", "config"], ["show", "statistics"]],
        )

    def test_semicolon_without_spaces_splits(self):
        self.assertEqual(
            self.clean("show config;show statistics"),
            [["show", "config"], ["show", "statistics"]],
        )

    def test_leading_and_trailing_semicolons_ignored(self):
        self.assertEqual(self.clean(";show config;"), [["show", "config"]])

    def test_multiple_consecutive_semicolons(self):
        self.assertEqual(
            self.clean("show config ;; show statistics"),
            [["show", "config"], ["show", "statistics"]],
        )

    def test_quoted_semicolon_embedded_in_token_is_literal(self):
        self.assertEqual(self.clean("info 'a;b'"), [["info", "a;b"]])
        self.assertEqual(self.clean("info foo';'bar"), [["info", "foo;bar"]])

    def test_standalone_quoted_semicolon_still_splits(self):
        """Known limitation: posix shlex strips quotes before we see the token."""
        self.assertEqual(self.clean("info ';'"), [["info"]])
        self.assertEqual(self.clean('info ";"'), [["info"]])
        self.assertEqual(self.clean(r"info \;"), [["info"]])
        self.assertEqual(
            self.clean("grep -s ';' statistics"), [["grep", "-s"], ["statistics"]]
        )

    def test_unterminated_quote_raises_shell_exception(self):
        with self.assertRaises(ShellException) as cm:
            self.clean("show 'unterminated")

        self.assertIn("Check that quotes are balanced", str(cm.exception))

    def test_unterminated_quote_error_omits_command(self):
        """The raw line may carry a password, so it never reaches stderr."""
        with self.assertRaises(ShellException) as cm:
            self.clean("manage acl create user bob password 'hunter2")

        self.assertNotIn("hunter2", str(cm.exception))


class PrecmdDispatchTest(unittest.IsolatedAsyncioTestCase):
    def make_shell(self):
        shell = object.__new__(AerospikeShell)
        shell.commands = set(asadm.TERMINATOR_COMMANDS) | {"cake"}
        shell.execute_only_mode = False
        shell.ctrl = Mock()
        shell.ctrl.execute = AsyncMock(return_value="")
        shell.onecmd = AsyncMock(return_value=None)
        return shell

    async def test_ctrl_command_routes_to_execute(self):
        shell = self.make_shell()
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            result = await shell.precmd("info network")
        self.assertEqual(result, "")
        shell.ctrl.execute.assert_called_once_with(["info", "network"])
        shell.onecmd.assert_not_called()

    async def test_do_command_routes_to_onecmd(self):
        shell = self.make_shell()
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            result = await shell.precmd("cake")
        self.assertEqual(result, "")
        shell.onecmd.assert_awaited_once_with("cake")
        shell.ctrl.execute.assert_not_called()

    async def test_exit_returns_line_without_inline_dispatch(self):
        shell = self.make_shell()
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            result = await shell.precmd("exit")
        self.assertEqual(result, "exit")
        shell.onecmd.assert_not_called()

    async def test_multiple_commands_all_run(self):
        shell = self.make_shell()
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            result = await shell.precmd("cake ; info network ; cake")
        self.assertEqual(result, "")
        self.assertEqual(shell.onecmd.await_args_list, [call("cake"), call("cake")])
        shell.ctrl.execute.assert_called_once_with(["info", "network"])

    async def test_exit_after_command_stops_and_skips_rest(self):
        shell = self.make_shell()
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            result = await shell.precmd("cake ; exit ; info network")
        self.assertEqual(result, "exit")
        shell.onecmd.assert_awaited_once_with("cake")
        shell.ctrl.execute.assert_not_called()

    async def test_ctrl_execute_failure_is_logged_and_batch_continues(self):
        shell = self.make_shell()
        shell.ctrl.execute = AsyncMock(side_effect=[Exception("boom"), ""])
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            with patch("asadm.logger") as mock_logger:
                result = await shell.precmd("info network ; info statistics")
        self.assertEqual(result, "")
        self.assertEqual(shell.ctrl.execute.await_count, 2)
        mock_logger.error.assert_called_once()

    async def test_inline_do_command_failure_is_logged_and_batch_continues(self):
        shell = self.make_shell()
        shell.onecmd = AsyncMock(side_effect=Exception("boom"))
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            with patch("asadm.logger") as mock_logger:
                result = await shell.precmd("cake ; info network")
        self.assertEqual(result, "")
        mock_logger.error.assert_called_once()
        shell.ctrl.execute.assert_called_once_with(["info", "network"])

    async def test_cancel_reraises_keyboard_interrupt_in_execute_mode(self):
        shell = self.make_shell()
        shell.execute_only_mode = True
        shell.ctrl.execute = AsyncMock(side_effect=asyncio.CancelledError)
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            with self.assertRaises(KeyboardInterrupt):
                await shell.precmd("info network")

    async def test_cancel_is_swallowed_in_interactive_mode(self):
        shell = self.make_shell()
        shell.execute_only_mode = False
        shell.ctrl.execute = AsyncMock(side_effect=asyncio.CancelledError)
        with patch("asadm.asyncio.get_event_loop", return_value=Mock()):
            result = await shell.precmd("info network")
        self.assertEqual(result, "")


class CmdloopTest(unittest.IsolatedAsyncioTestCase):
    async def test_single_command_reraises_keyboard_interrupt(self):
        func = AsyncMock(side_effect=KeyboardInterrupt)
        with self.assertRaises(KeyboardInterrupt):
            await asadm.cmdloop(Mock(), func, (), False, True)
        func.assert_awaited_once()

    async def test_single_command_reraises_system_exit(self):
        func = AsyncMock(side_effect=SystemExit)
        with self.assertRaises(SystemExit):
            await asadm.cmdloop(Mock(), func, (), False, True)
        func.assert_awaited_once()

    async def test_normal_completion_runs_once(self):
        func = AsyncMock(return_value=None)
        await asadm.cmdloop(Mock(), func, ("line",), False, False)
        func.assert_awaited_once_with("line")

    async def test_interactive_retries_and_sets_intro(self):
        func = AsyncMock(side_effect=[KeyboardInterrupt(), None])
        shell = Mock()
        await asadm.cmdloop(shell, func, (), False, False)
        self.assertEqual(func.await_count, 2)
        self.assertIn(
            "To exit asadm utility please run the 'exit' command", shell.intro
        )

    async def test_interactive_retry_is_iterative_not_recursive(self):
        func = AsyncMock(side_effect=[KeyboardInterrupt()] * 2000 + [None])
        await asadm.cmdloop(Mock(), func, (), False, False)
        self.assertEqual(func.await_count, 2001)


class ExecuteModeDoubleRunTest(unittest.IsolatedAsyncioTestCase):
    """The duplicate onecmd call lived in main(), upstream of cmdloop, so only
    driving main()'s execute path catches a double dispatch."""

    def _make_args(self):
        return SimpleNamespace(
            execute="cake",
            debug=False,
            help=False,
            version=False,
            no_color=False,
            pmap=False,
            collectinfo=False,
            log_analyzer=False,
            json=False,
            asinfo_mode=False,
            services_alumni=False,
            services_alternate=False,
            tls_enable=False,
            auth=None,
            profile=False,
            out_file=None,
            user=None,
            password=None,
            log_path=None,
            single_node=False,
            enable=False,
            timeout=5,
        )

    async def test_do_command_dispatched_exactly_once(self):
        args = self._make_args()
        shell = AsyncMock()
        shell.connected = True
        shell._has_admin_nodes = Mock(return_value=False)
        shell.precmd = AsyncMock(return_value="")
        shell.onecmd = AsyncMock(return_value=None)
        shell.close = AsyncMock()

        async def make_shell(*a, **k):
            return shell

        with patch("asadm.conf.get_cli_args", return_value=args), patch(
            "asadm.conf.loadconfig", return_value=(args, [("1.1.1.1", 3000, None)])
        ), patch("asadm.parse_tls_input", return_value=None), patch(
            "asadm.AerospikeShell", side_effect=make_shell
        ), patch(
            "os.path.isfile", return_value=False
        ):
            with self.assertRaises(SystemExit):
                await asadm.main()

        shell.onecmd.assert_awaited_once_with("")

    async def test_emptyline_is_noop(self):
        """Stock cmd.Cmd re-runs lastcmd on a blank line; the override must stay."""
        shell = object.__new__(AerospikeShell)
        shell.lastcmd = "info network"
        shell.onecmd = Mock()
        self.assertIsNone(shell.emptyline())
        shell.onecmd.assert_not_called()


class PasswordSourceStartupTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"AS_PASS": "s3cr3t", "KP": "kp-s3cr3t"})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("ASADM_TEST_UNSET", None)

    def _make_args(self, **overrides):
        args = SimpleNamespace(
            execute="info",
            debug=False,
            help=False,
            version=False,
            no_color=False,
            pmap=False,
            collectinfo=False,
            log_analyzer=False,
            json=False,
            asinfo_mode=False,
            services_alumni=False,
            services_alternate=False,
            tls_enable=False,
            tls_keyfile=None,
            tls_keyfile_password=None,
            auth=None,
            profile=False,
            out_file=None,
            user="admin",
            password="env:AS_PASS",
            log_path=None,
            line_separator=False,
            single_node=False,
            enable=False,
            timeout=5,
        )
        args.__dict__.update(overrides)
        return args

    async def _run_main(self, args):
        shell = AsyncMock()
        shell.connected = False
        shell.close = AsyncMock()
        shell_cls = Mock(side_effect=AsyncMock(return_value=shell))
        tls = Mock(return_value=None)
        asinfo = AsyncMock()

        with patch("asadm.conf.get_cli_args", return_value=args), patch(
            "asadm.conf.loadconfig", return_value=(args, [("1.1.1.1", 3000, None)])
        ), patch("asadm.parse_tls_input", tls), patch(
            "asadm.AerospikeShell", shell_cls
        ), patch(
            "asadm.execute_asinfo_commands", asinfo
        ), patch(
            "os.path.isfile", return_value=False
        ), patch(
            "asadm.logger"
        ) as logger:
            with self.assertRaises(SystemExit) as cm:
                await asadm.main()

        return cm.exception.code, logger, tls, shell_cls, asinfo

    async def test_resolution_error_exits_before_connecting(self):
        args = self._make_args(password="env:ASADM_TEST_UNSET")

        code, logger, tls, shell_cls, _ = await self._run_main(args)

        self.assertEqual(code, 1)
        logger.critical.assert_called_once()
        err = logger.critical.call_args[0][0]
        self.assertEqual(
            str(err),
            "--password: environment variable ASADM_TEST_UNSET is not set or empty",
        )
        tls.assert_not_called()
        shell_cls.assert_not_called()

    async def test_keyfile_resolution_error_exits_before_connecting(self):
        args = self._make_args(
            tls_enable=True,
            tls_keyfile="/k.pem",
            tls_keyfile_password="b64:not base64",
        )

        code, logger, tls, shell_cls, _ = await self._run_main(args)

        self.assertEqual(code, 1)
        self.assertEqual(
            str(logger.critical.call_args[0][0]),
            "--tls-keyfile-password: invalid base64 in b64: value",
        )
        tls.assert_not_called()
        shell_cls.assert_not_called()

    async def test_resolved_values_reach_tls_and_shell(self):
        args = self._make_args(
            tls_enable=True, tls_keyfile="/k.pem", tls_keyfile_password="env:KP"
        )

        _, logger, tls, shell_cls, _ = await self._run_main(args)

        logger.critical.assert_not_called()
        self.assertEqual(tls.call_args[0][0].tls_keyfile_password, "kp-s3cr3t")
        self.assertEqual(shell_cls.call_args.kwargs["password"], "s3cr3t")

    async def test_asinfo_mode_gets_resolved_password(self):
        args = self._make_args(asinfo_mode=True)

        code, _, _, _, asinfo = await self._run_main(args)

        self.assertEqual(code, 0)
        self.assertEqual(asinfo.call_args.kwargs["password"], "s3cr3t")

    async def test_asinfo_mode_resolves_with_an_analyzer_flag(self):
        """Mixing modes is only logged, and asinfo still connects."""
        for mode in ("collectinfo", "log_analyzer"):
            with self.subTest(mode=mode):
                args = self._make_args(asinfo_mode=True, **{mode: True})

                code, _, _, _, asinfo = await self._run_main(args)

                self.assertEqual(code, 0)
                self.assertEqual(asinfo.call_args.kwargs["password"], "s3cr3t")

    async def test_analyzer_modes_do_not_resolve(self):
        for mode in ("collectinfo", "log_analyzer"):
            with self.subTest(mode=mode):
                args = self._make_args(password="env:ASADM_TEST_UNSET", **{mode: True})

                _, logger, _, shell_cls, _ = await self._run_main(args)

                logger.critical.assert_not_called()
                self.assertEqual(
                    shell_cls.call_args.kwargs["password"], "env:ASADM_TEST_UNSET"
                )


class PromptedPasswordNotParsedTest(unittest.IsolatedAsyncioTestCase):
    """A value typed at the prompt or read from stdin is the password itself."""

    def setUp(self):
        env = patch.dict(os.environ, {"AS_PASS": "s3cr3t"})
        env.start()
        self.addCleanup(env.stop)

    def _stdin(self, tty, line=""):
        stdin = Mock()
        stdin.isatty.return_value = tty
        stdin.readline.return_value = line
        return patch("sys.stdin", stdin)

    async def _shell_password(self):
        seen = {}

        class MockLiveClusterRootController(async_object.AsyncObject):
            async def __init__(self, *args, **kwargs):
                seen["password"] = args[2]
                self.cluster = Mock()
                self.cluster.get_live_nodes.return_value = []
                self.cluster.get_parked_nodes.return_value = []

        with patch(
            "asadm.LiveClusterRootController", MockLiveClusterRootController
        ), patch("asadm.logger"):
            await AerospikeShell(
                "test-version",
                seeds=[("1.1.1.1", 3000, None)],
                user="admin",
                password=asadm.conf.DEFAULTPASSWORD,
                execute_only_mode=True,
            )

        return seen["password"]

    async def test_shell_stdin_password_is_literal(self):
        with self._stdin(False, "env:AS_PASS\n"):
            self.assertEqual(await self._shell_password(), "env:AS_PASS")

    async def test_shell_getpass_password_is_literal(self):
        with self._stdin(True), patch(
            "asadm.getpass.getpass", return_value="b64:czNjcjN0"
        ):
            self.assertEqual(await self._shell_password(), "b64:czNjcjN0")

    async def test_asinfo_stdin_password_is_literal(self):
        assock = Mock()
        assock.connect = AsyncMock(return_value=False)

        with self._stdin(False, "file:/etc/hosts\n"), patch(
            "asadm.ASSocket", return_value=assock
        ) as assock_cls, patch("asadm.logger"):
            await asadm.execute_asinfo_commands(
                None,
                ("1.1.1.1", 3000, None),
                user="admin",
                password=asadm.conf.DEFAULTPASSWORD,
            )

        self.assertEqual(assock_cls.call_args[0][4], "file:/etc/hosts")

    def test_tls_keyfile_stdin_password_is_literal(self):
        args = SimpleNamespace(
            collectinfo=False,
            log_analyzer=False,
            tls_enable=True,
            tls_cafile=None,
            tls_capath=None,
            tls_keyfile="/k.pem",
            tls_keyfile_password=asadm.conf.DEFAULTPASSWORD,
            tls_certfile=None,
            tls_protocols=None,
            tls_cipher_suite=None,
            tls_crl_check=False,
            tls_crl_check_all=False,
        )

        with self._stdin(False, "env:AS_PASS\n"), patch(
            "asadm.SSLContext"
        ) as ssl_context:
            asadm.parse_tls_input(args)

        self.assertEqual(
            ssl_context.call_args.kwargs["keyfile_password"], "env:AS_PASS"
        )


class LogAnalyzerSkipsTlsTest(unittest.IsolatedAsyncioTestCase):
    """-l never connects, so a TLS keyfile in astools.conf must not be loaded or prompted for."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)
        env = patch.dict(os.environ, {"KP": "kp-s3cr3t"})
        env.start()
        self.addCleanup(env.stop)

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.keyfile = self.write(
            "key.pem",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(b"kp-s3cr3t"),
            ).decode(),
        )

    def write(self, name, content):
        path = os.path.join(self.tmpdir.name, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    async def _run_log_analyzer(self, config, *argv):
        conf_path = self.write("astools.conf", config)
        shell = AsyncMock()
        shell.connected = True
        shell._has_admin_nodes = Mock(return_value=False)
        shell_cls = Mock(side_effect=AsyncMock(return_value=shell))
        stdin = Mock()
        stdin.isatty.return_value = True
        sys_argv = ["asadm", "--only-config-file", conf_path, "-l", "-f"]
        sys_argv += [self.tmpdir.name, "-e", "info", *argv]

        with patch("sys.argv", sys_argv), patch("sys.stdin", stdin), patch(
            "sys.stderr", io.StringIO()
        ), patch("asadm.getpass.getpass") as getpass_mock, patch(
            "asadm.AerospikeShell", shell_cls
        ), patch(
            "asadm.logger"
        ) as logger:
            with self.assertRaises(SystemExit):
                await asadm.main()

        logger.error.assert_not_called()
        getpass_mock.assert_not_called()
        stdin.readline.assert_not_called()
        shell_cls.assert_called_once()
        self.assertIsNone(shell_cls.call_args.kwargs["ssl_context"])
        self.assertEqual(shell_cls.call_args.kwargs["mode"], AdminMode.LOG_ANALYZER)

    async def test_keyfile_password_source_in_config(self):
        await self._run_log_analyzer(
            "[cluster]\ntls-enable = true\n"
            'tls-keyfile = "{}"\n'
            'tls-keyfile-password = "env:KP"\n'.format(self.keyfile)
        )

    async def test_bare_keyfile_password_does_not_prompt(self):
        await self._run_log_analyzer(
            '[cluster]\ntls-enable = true\ntls-keyfile = "{}"\n'.format(self.keyfile),
            "--tls-keyfile-password",
        )


if __name__ == "__main__":
    unittest.main()
