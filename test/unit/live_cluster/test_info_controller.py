# Copyright 2025 Aerospike, Inc.
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
from unittest.mock import AsyncMock, create_autospec, patch

from pytest import PytestUnraisableExceptionWarning

from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.get_controller import (
    GetConfigController,
    GetStatisticsController,
)
from lib.live_cluster.info_controller import InfoController
from lib.view.view import CliView


class InfoControllerMemoryTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = InfoController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.stat_getter_mock = self.controller.stat_getter = create_autospec(
            GetStatisticsController
        )
        self.config_getter_mock = self.controller.config_getter = create_autospec(
            GetConfigController
        )
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.mods = {}
        self.addCleanup(patch.stopall)

    async def test_do_memory_calls_getters_and_view(self):
        stats = {
            "1.1.1.1": {
                "system_free_mem_kbytes": "8000000",
                "system_free_mem_pct": "52",
                "host_free_mem_kbytes": "8000000",
                "host_free_mem_pct": "52",
                "heap_allocated_kbytes": "500000",
                "heap_active_kbytes": "520000",
                "heap_mapped_kbytes": "600000",
                "heap_efficiency_pct": "83",
                "system_thp_mem_kbytes": "0",
            }
        }
        configs = {"1.1.1.1": {"cgroup-mem-tracking": "false"}}
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "index_used_bytes": "1024",
                    "sindex_used_bytes": "2048",
                    "set_index_used_bytes": "0",
                    "index_shmem_alloc_bytes": "4096",
                    "storage-engine": "memory",
                    "data_used_bytes": "9000",
                },
                "bar": {
                    "index_used_bytes": "512",
                    "sindex_used_bytes": "256",
                    "set_index_used_bytes": "128",
                },
            }
        }
        mods = {"with": [], "line": []}

        builds = {"1.1.1.1": "8.1.3"}
        self.stat_getter_mock.get_service.return_value = stats
        self.config_getter_mock.get_service.return_value = configs
        self.stat_getter_mock.get_namespace.return_value = ns_stats
        self.cluster_mock.info_build = AsyncMock(return_value=builds)
        self.controller.mods = mods

        await self.controller.execute(["memory"])

        self.stat_getter_mock.get_service.assert_called_once_with(nodes="all")
        self.config_getter_mock.get_service.assert_called_once_with(nodes="all")
        self.stat_getter_mock.get_namespace.assert_called_once_with(nodes="all")
        self.cluster_mock.info_build.assert_called_once_with(nodes="all")

        call_args = self.view_mock.info_memory.call_args
        self.assertEqual(call_args.args[0], stats)
        self.assertEqual(call_args.args[1], configs)
        ns_agg = call_args.args[2]
        self.assertEqual(ns_agg["1.1.1.1"]["index_used_bytes"], "1536")
        self.assertEqual(ns_agg["1.1.1.1"]["sindex_used_bytes"], "2304")
        self.assertEqual(ns_agg["1.1.1.1"]["set_index_used_bytes"], "128")
        self.assertEqual(ns_agg["1.1.1.1"]["shmem_alloc_bytes"], "4096")
        self.assertEqual(ns_agg["1.1.1.1"]["data_in_memory_used_bytes"], "9000")
        self.assertEqual(call_args.kwargs["builds"], builds)

    async def test_do_memory_with_node_filter(self):
        stats = {"1.2.3.4": {}}
        configs = {"1.2.3.4": {"cgroup-mem-tracking": "true"}}
        ns_stats = {
            "1.2.3.4": {
                "test": {
                    "index_used_bytes": "0",
                    "sindex_used_bytes": "0",
                    "set_index_used_bytes": "0",
                }
            }
        }
        mods = {"with": ["1.2.3.4"], "line": []}

        self.stat_getter_mock.get_service.return_value = stats
        self.config_getter_mock.get_service.return_value = configs
        self.stat_getter_mock.get_namespace.return_value = ns_stats
        self.cluster_mock.info_build = AsyncMock(return_value={"1.2.3.4": "8.1.3"})
        self.controller.mods = mods
        self.controller.nodes = ["1.2.3.4"]

        await self.controller.execute(["memory", "with", "1.2.3.4"])

        self.stat_getter_mock.get_service.assert_called_once_with(nodes=["1.2.3.4"])
        self.config_getter_mock.get_service.assert_called_once_with(nodes=["1.2.3.4"])
        self.stat_getter_mock.get_namespace.assert_called_once_with(nodes=["1.2.3.4"])
        self.cluster_mock.info_build.assert_called_once_with(nodes=["1.2.3.4"])
