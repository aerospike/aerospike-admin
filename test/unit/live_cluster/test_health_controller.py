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

import unittest
import warnings
from unittest.mock import AsyncMock, MagicMock, create_autospec

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


class HealthCheckControllerDeprecationTest(unittest.IsolatedAsyncioTestCase):
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

    async def test_default_warns_deprecated_and_still_runs(self):
        with self.assertLogs(
            "lib.live_cluster.health_check_controller", level="WARNING"
        ) as cm:
            await self.controller._do_default(["-s", "0"])

        self.assertTrue(any("deprecated" in msg for msg in cm.output))
        self.health_checker_mock.execute.assert_called_once()
        self.view_mock.print_health_output.assert_called_once()
