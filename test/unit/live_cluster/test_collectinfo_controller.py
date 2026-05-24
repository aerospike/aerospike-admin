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
import unittest
import warnings
from unittest.mock import AsyncMock, Mock, patch, create_autospec

from pytest import PytestUnraisableExceptionWarning

from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.types import ASNoNodesError
from lib.live_cluster.collectinfo_controller import CollectinfoController
from lib.live_cluster.live_cluster_command_controller import (
    LiveClusterCommandController,
)
from lib.view.terminal import terminal


class CollectinfoControllerTest(unittest.IsolatedAsyncioTestCase):
    """Tests for CollectinfoController._run_collectinfo error-handling paths.

    The preflight check is the only branch exercised here — full collectinfo
    execution requires SSH/cluster fixtures and is covered by e2e tests.
    """

    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

        # `_run_collectinfo` calls `terminal.enable_color(False)`, which mutates
        # module-level globals in `lib.view.terminal.terminal`. Snapshot the
        # current `color_enabled` state and restore it on teardown so we do not
        # pollute downstream tests (notably test_view.py and
        # test_base_controller.py) that depend on the original terminal state.
        original_color_enabled = terminal.color_enabled

        def _restore_terminal_color():
            terminal.enable_color(original_color_enabled)

        self.addCleanup(_restore_terminal_color)

        # Freeze time so collectinfo path generation is deterministic.
        patch(
            "lib.live_cluster.collectinfo_controller.time.gmtime", autospec=True
        ).start().return_value = time.gmtime(1693259247)

        # Stub out the path-creation helper so _run_collectinfo does not touch
        # disk during the preflight.
        path_info_mock = Mock()
        path_info_mock.cf_dir = "/tmp/test_collectinfo"
        path_info_mock.files_prefix = "20230828_214727_"
        patch(
            "lib.live_cluster.collectinfo_controller.common.get_collectinfo_path",
            autospec=True,
        ).start().return_value = path_info_mock

        self.controller = CollectinfoController()
        # setup_loggers / teardown_loggers touch real log handlers; bypass them.
        self.controller.setup_loggers = Mock()
        self.controller.teardown_loggers = Mock()

        # Inject a mocked cluster on the LiveClusterCommandController class
        # attribute (that's where the controller looks it up). Restore the
        # original value on teardown so we don't pollute downstream tests
        # that rely on the unset/default class-level `cluster`.
        self._original_cluster = LiveClusterCommandController.cluster
        self.cluster_mock = create_autospec(Cluster)
        LiveClusterCommandController.cluster = self.cluster_mock

        def _restore_cluster():
            LiveClusterCommandController.cluster = self._original_cluster

        self.addCleanup(_restore_cluster)

        self.logger_mock = patch(
            "lib.live_cluster.collectinfo_controller.logger"
        ).start()

        self.addCleanup(patch.stopall)

    async def test_preflight_short_circuits_on_no_nodes(self):
        """When cluster.get_nodes() returns an empty list, _run_collectinfo
        must log the ASNoNodesError remediation message and return without
        starting the snapshot loop."""
        self.cluster_mock.get_nodes.return_value = []
        self.controller._dump_collectinfo_json = AsyncMock()

        await self.controller._run_collectinfo(
            ssh_user=None,
            ssh_pwd=None,
            ssh_port=None,
            ssh_key=None,
            ssh_key_pwd=None,
            snp_count=1,
            wait_time=0,
            ignore_errors=False,
        )

        # The expensive snapshot path must NOT run.
        self.controller._dump_collectinfo_json.assert_not_called()

        # logger.error was called with an ASNoNodesError instance whose
        # message carries actionable remediation.
        error_calls = self.logger_mock.error.call_args_list
        no_nodes_calls = [
            c for c in error_calls if c.args and isinstance(c.args[0], ASNoNodesError)
        ]
        self.assertEqual(
            len(no_nodes_calls),
            1,
            f"expected exactly one ASNoNodesError log, got: {error_calls!r}",
        )
        message = str(no_nodes_calls[0].args[0])
        self.assertIn("Cannot reach any Aerospike nodes", message)
        self.assertIn("Try", message)

    async def test_no_nodes_mid_run_is_handled_cleanly(self):
        """Mid-run case: preflight passes (nodes are alive at the start) but
        the cluster client raises ASNoNodesError later during the actual
        snapshot — e.g. because the cluster went away between preflight and
        the deeper info call. The dedicated `except ASNoNodesError` handler
        must catch it, log the same clean error, and return without falling
        into the generic `--ignore-errors`-aware Exception branch (which
        would otherwise produce a misleading 'Aborting collectinfo...' line
        for what is the same root cause)."""
        self.cluster_mock.get_nodes.return_value = [Mock(), Mock()]
        deep_error = ASNoNodesError()
        self.controller._dump_collectinfo_json = AsyncMock(side_effect=deep_error)

        await self.controller._run_collectinfo(
            ssh_user=None,
            ssh_pwd=None,
            ssh_port=None,
            ssh_key=None,
            ssh_key_pwd=None,
            snp_count=1,
            wait_time=0,
            ignore_errors=False,
        )

        # Exactly one error was logged — the ASNoNodesError itself. No
        # 'Aborting collectinfo. To bypass use --ignore-errors.' follow-up
        # line, because that belongs to the generic handler that we are
        # specifically bypassing for this case.
        error_calls = self.logger_mock.error.call_args_list
        self.assertEqual(
            len(error_calls),
            1,
            f"expected a single error log for mid-run ASNoNodesError, got: {error_calls!r}",
        )
        self.assertIs(error_calls[0].args[0], deep_error)

    async def test_no_nodes_mid_run_aborts_even_with_ignore_errors(self):
        """The mid-run handler must return regardless of --ignore-errors,
        for the same reason as preflight: there is no usable partial
        bundle when the cluster goes away."""
        self.cluster_mock.get_nodes.return_value = [Mock(), Mock()]
        self.controller._dump_collectinfo_json = AsyncMock(side_effect=ASNoNodesError())
        # Tripwires for the downstream summary/health phases that should
        # NEVER run when collectinfo bailed out.
        self.controller._dump_collectinfo_ascollectinfo = AsyncMock()
        self.controller._dump_collectinfo_summary = AsyncMock()
        self.controller._dump_collectinfo_health = AsyncMock()

        await self.controller._run_collectinfo(
            ssh_user=None,
            ssh_pwd=None,
            ssh_port=None,
            ssh_key=None,
            ssh_key_pwd=None,
            snp_count=1,
            wait_time=0,
            ignore_errors=True,
        )

        self.controller._dump_collectinfo_ascollectinfo.assert_not_called()
        self.controller._dump_collectinfo_summary.assert_not_called()
        self.controller._dump_collectinfo_health.assert_not_called()

    async def test_preflight_short_circuits_regardless_of_ignore_errors(self):
        """--ignore-errors must NOT cause collectinfo to continue past a
        no-nodes preflight: there is no partial bundle worth producing."""
        self.cluster_mock.get_nodes.return_value = []
        self.controller._dump_collectinfo_json = AsyncMock()
        # If preflight wrongly fell through to summary/health/etc., these
        # would be reached; assert they aren't.
        self.controller._dump_collectinfo_ascollectinfo = AsyncMock()
        self.controller._dump_collectinfo_summary = AsyncMock()
        self.controller._dump_collectinfo_health = AsyncMock()

        await self.controller._run_collectinfo(
            ssh_user=None,
            ssh_pwd=None,
            ssh_port=None,
            ssh_key=None,
            ssh_key_pwd=None,
            snp_count=1,
            wait_time=0,
            ignore_errors=True,
        )

        self.controller._dump_collectinfo_json.assert_not_called()
        self.controller._dump_collectinfo_ascollectinfo.assert_not_called()
        self.controller._dump_collectinfo_summary.assert_not_called()
        self.controller._dump_collectinfo_health.assert_not_called()

    async def test_preflight_passes_when_nodes_present(self):
        """Sanity check the negative: when nodes exist, preflight does not
        short-circuit and _dump_collectinfo_json is invoked. We let
        _dump_collectinfo_json raise a generic exception so the existing
        except-Exception handler returns cleanly without dragging the test
        through the downstream summary/health code paths."""
        self.cluster_mock.get_nodes.return_value = [Mock(), Mock()]
        sentinel = RuntimeError("stop after preflight")
        self.controller._dump_collectinfo_json = AsyncMock(side_effect=sentinel)

        await self.controller._run_collectinfo(
            ssh_user=None,
            ssh_pwd=None,
            ssh_port=None,
            ssh_key=None,
            ssh_key_pwd=None,
            snp_count=1,
            wait_time=0,
            ignore_errors=False,
        )

        self.controller._dump_collectinfo_json.assert_awaited_once()
        # And the generic handler logged the underlying error (not ASNoNodesError).
        error_calls = self.logger_mock.error.call_args_list
        self.assertTrue(
            any(c.args and c.args[0] is sentinel for c in error_calls),
            f"expected the sentinel exception to reach logger.error, got: {error_calls!r}",
        )
        self.assertFalse(
            any(c.args and isinstance(c.args[0], ASNoNodesError) for c in error_calls),
            "preflight should not have flagged ASNoNodesError when nodes exist",
        )


if __name__ == "__main__":
    unittest.main()
