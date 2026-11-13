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
from unittest.mock import AsyncMock, create_autospec, patch

from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.summary_controller import SummaryController
from lib.view.view import CliView


class SummaryControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.controller = SummaryController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)

        for method in (
            "info",
            "info_version",
            "info_statistics",
            "info_all_namespace_statistics",
            "info_all_dc_statistics",
            "info_get_config",
            "info_feature_key",
        ):
            setattr(self.cluster_mock, method, AsyncMock(return_value={}))

        self.cluster_mock.info_system_statistics = AsyncMock(
            return_value={
                "1.1.1.1": {
                    "lsb": {"description": "Ubuntu 24.04"},
                    "uname": {"kernel_release": "6.8.0"},
                }
            }
        )
        self.controller.view = create_autospec(CliView)
        self.create_summary = patch(
            "lib.live_cluster.summary_controller.common.create_summary"
        ).start()
        self.addCleanup(patch.stopall)

    async def test_os_and_kernel_come_from_one_system_statistics_call(self):
        await self.controller.execute(
            [
                "--enable-ssh",
                "--ssh-user",
                "admin",
                "--ssh-key",
                "/keys/id",
                "--ssh-port",
                "2222",
            ]
        )

        self.cluster_mock.info_system_statistics.assert_awaited_once()
        kwargs = self.cluster_mock.info_system_statistics.await_args.kwargs
        self.assertCountEqual(kwargs["commands"], ["lsb", "uname"])
        self.assertEqual(kwargs["ssh_user"], "admin")
        self.assertEqual(kwargs["ssh_key"], "/keys/id")
        self.assertEqual(kwargs["ssh_port"], 2222)
        self.assertTrue(kwargs["enable_ssh"])

    async def test_os_version_carries_the_kernel(self):
        await self.controller.execute([])

        metadata = self.create_summary.call_args.kwargs["metadata"]
        self.assertEqual(
            metadata["os_version"]["1.1.1.1"]["description"], "Ubuntu 24.04 (6.8.0)"
        )
