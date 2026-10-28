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

import asyncio
import unittest
import warnings
from unittest.mock import AsyncMock, MagicMock, call, create_autospec, patch

from lib.base_controller import ShellException
from lib.health.health_checker import HealthChecker
from lib.live_cluster.health_check_controller import HealthCheckController
from lib.view.view import CliView

CLUSTER_INFO_METHODS = (
    "info_statistics",
    "info_all_namespace_statistics",
    "info_all_set_statistics",
    "info_bin_statistics",
    "info_XDR_statistics",
    "info_all_dc_statistics",
    "info_udf_list",
    "info_service_list",
    "info_peers_flat_list",
    "info_get_config",
    "info_xdr_config",
    "info_xdr_dcs_config",
    "info_racks",
    "info_get_originalconfig",
    "info",
    "info_health_outliers",
    "info_system_statistics",
)


class HealthCheckControllerTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.enterContext(warnings.catch_warnings())
        warnings.filterwarnings("error", category=RuntimeWarning)
        HealthCheckController.last_snapshot_collection_time = 0
        HealthCheckController.last_snapshot_count = 0
        self.controller = HealthCheckController()
        self.cluster_mock = self.controller.cluster = MagicMock()
        for method in CLUSTER_INFO_METHODS:
            setattr(self.cluster_mock, method, AsyncMock(return_value={}))
        self.health_checker_mock = self.controller.health_checker = create_autospec(
            HealthChecker
        )
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.nodes = []
        self.controller.mods = {}


class HealthCheckControllerDeprecationTest(HealthCheckControllerTestCase):
    async def test_default_warns_deprecated_and_still_runs(self):
        with self.assertLogs(
            "lib.live_cluster.health_check_controller", level="WARNING"
        ) as cm:
            await self.controller._do_default(["-s", "0"])

        self.assertTrue(any("deprecated" in msg for msg in cm.output))
        self.health_checker_mock.execute.assert_called_once()
        self.view_mock.print_health_output.assert_called_once()


class HealthCheckControllerSnapshotSleepTest(HealthCheckControllerTestCase):
    async def test_sleep_between_snapshots_yields_the_event_loop(self):
        """time.sleep here stalled every in-flight request on the loop. There is no
        wait after the last snapshot."""
        with patch("asyncio.sleep", AsyncMock()) as async_sleep_mock, patch(
            "time.sleep"
        ) as time_sleep_mock:
            await self.controller._do_default(["-n", "2", "-s", "3"])

        self.assertEqual(
            [c for c in async_sleep_mock.await_args_list if c == call(3.0)],
            [call(3.0)],
        )
        time_sleep_mock.assert_not_called()

    async def test_interrupt_during_the_wait_cancels_at_once(self):
        real_sleep = asyncio.sleep
        waiting = asyncio.Event()

        async def sleep(delay, *args, **kwargs):
            if delay == 30.0:
                waiting.set()

            return await real_sleep(delay, *args, **kwargs)

        with patch("asyncio.sleep", sleep):
            task = asyncio.create_task(
                self.controller._do_default(["-n", "2", "-s", "30"])
            )
            await asyncio.wait_for(waiting.wait(), 5)
            task.cancel()

            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 1)

        self.health_checker_mock.execute.assert_not_called()


class HealthCheckControllerSnapshotIntervalTest(HealthCheckControllerTestCase):
    """time.sleep rejected these. asyncio.sleep returns at once for a negative
    interval and never for a huge one."""

    async def test_negative_interval_is_rejected(self):
        with self.assertRaises(ShellException):
            await self.controller._do_default(["-s", "-1"])

        self.cluster_mock.info_statistics.assert_not_awaited()

    async def test_zero_interval_is_rejected(self):
        """0 is left on the line as a query source and fails later with a
        misleading error."""
        with self.assertRaisesRegex(ShellException, "between 1 and"):
            await self.controller._do_default(["-s", "0"])

        self.cluster_mock.info_statistics.assert_not_awaited()

    async def test_huge_interval_is_rejected(self):
        with self.assertRaises(ShellException):
            await asyncio.wait_for(
                self.controller._do_default(["-s", "99999999999"]), 5
            )

        self.cluster_mock.info_statistics.assert_not_awaited()
