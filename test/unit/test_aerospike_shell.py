from asadm import AerospikeShell
import asadm

import asyncio
import unittest
from unittest.mock import AsyncMock, Mock, patch, call
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
    """clean_line does not touch instance state, so exercise it directly on a
    bare instance to avoid the async cluster-connect setup."""

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
        """An unquoted ';' separates commands even without surrounding
        whitespace - ';' was removed from the lexer wordchars."""
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

    def test_quoted_semicolon_is_literal(self):
        """A quoted ';' stays inside its token and does not split the command."""
        self.assertEqual(self.clean("info 'a;b'"), [["info", "a;b"]])

    def test_unterminated_quote_raises_shell_exception(self):
        with self.assertRaises(ShellException):
            self.clean("show 'unterminated")


class PrecmdDispatchTest(unittest.IsolatedAsyncioTestCase):
    """precmd routes do_* commands through onecmd and everything else through
    ctrl.execute, running every command in a multi-command line."""

    def make_shell(self):
        shell = object.__new__(AerospikeShell)
        shell.commands = {"exit", "quit", "EOF", "cake"}
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


class CmdloopTest(unittest.IsolatedAsyncioTestCase):
    """Module-level cmdloop re-raises interrupts in single-command (execute)
    mode and retries func, resetting shell.intro, in interactive mode."""

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


if __name__ == "__main__":
    unittest.main()
