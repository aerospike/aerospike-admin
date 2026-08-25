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

from parameterized import parameterized
from pytest import PytestUnraisableExceptionWarning

from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.get_controller import (
    GetConfigController,
    GetStatisticsController,
)
from lib.base_controller import ShellException
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
        self.logger_mock = patch("lib.live_cluster.info_controller.logger").start()
        self.controller.mods = {}
        self.addCleanup(patch.stopall)

    def set_cluster(self, builds, edition="Aerospike Enterprise Edition"):
        self.cluster_mock.info_build = AsyncMock(return_value=builds)
        self.cluster_mock.info = AsyncMock(
            return_value={node: edition for node in builds}
        )
        self.cluster_mock.get_node_names.return_value = {
            node: "node-" + node for node in builds
        }

    def warnings(self):
        return [c[0][0] % c[0][1:] for c in self.logger_mock.warning.call_args_list]

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

        self.stat_getter_mock.get_service.return_value = stats
        self.config_getter_mock.get_service.return_value = configs
        self.stat_getter_mock.get_namespace.return_value = ns_stats
        self.set_cluster({"1.1.1.1": "8.1.3"})
        self.controller.mods = {"with": [], "line": []}

        await self.controller.execute(["memory"])

        self.stat_getter_mock.get_service.assert_called_once_with(nodes="all")
        self.config_getter_mock.get_service.assert_called_once_with(nodes="all")
        self.stat_getter_mock.get_namespace.assert_called_once_with(nodes="all")
        self.cluster_mock.info_build.assert_called_once_with(nodes="all")
        self.cluster_mock.info.assert_called_once_with("edition", nodes="all")

        call_args = self.view_mock.info_memory.call_args
        self.assertEqual(call_args.args[0], stats)
        self.assertEqual(call_args.args[1], configs)
        self.assertIs(call_args.args[3], self.cluster_mock)
        ns_agg = call_args.args[2]
        self.assertEqual(ns_agg["1.1.1.1"]["index_used_bytes"], "1536")
        self.assertEqual(ns_agg["1.1.1.1"]["sindex_used_bytes"], "2304")
        self.assertEqual(ns_agg["1.1.1.1"]["set_index_used_bytes"], "128")
        self.assertEqual(ns_agg["1.1.1.1"]["shmem_alloc_bytes"], "4096")
        self.assertEqual(ns_agg["1.1.1.1"]["data_in_memory_used_bytes"], "9000")
        self.assertEqual(call_args.kwargs["builds"], {"1.1.1.1": "8.1.3"})
        self.assertEqual(self.warnings(), [])

    async def test_do_memory_with_node_filter(self):
        stats = {"1.2.3.4": {}}
        configs = {"1.2.3.4": {"cgroup-mem-tracking": "true"}}
        ns_stats = {"1.2.3.4": {"test": {"index_used_bytes": "0"}}}

        self.stat_getter_mock.get_service.return_value = stats
        self.config_getter_mock.get_service.return_value = configs
        self.stat_getter_mock.get_namespace.return_value = ns_stats
        self.set_cluster({"1.2.3.4": "8.1.3"})
        self.controller.mods = {"with": [], "line": []}

        await self.controller.execute(["memory", "with", "1.2.3.4"])

        self.stat_getter_mock.get_service.assert_called_once_with(nodes=["1.2.3.4"])
        self.config_getter_mock.get_service.assert_called_once_with(nodes=["1.2.3.4"])
        self.stat_getter_mock.get_namespace.assert_called_once_with(nodes=["1.2.3.4"])
        self.cluster_mock.info_build.assert_called_once_with(nodes=["1.2.3.4"])

        call_args = self.view_mock.info_memory.call_args
        self.assertEqual(call_args.kwargs["with"], ["1.2.3.4"])
        self.assertIs(call_args.args[3], self.cluster_mock)

    async def _run_memory_line(self, line, builds=None):
        node = "1.1.1.1"
        self.stat_getter_mock.get_service.return_value = {node: {}}
        self.config_getter_mock.get_service.return_value = {node: {}}
        self.stat_getter_mock.get_namespace.return_value = {node: {}}
        self.set_cluster(builds if builds is not None else {node: "8.1.3"})
        self.controller.mods = {"with": [], "for": [], "line": []}

        await self.controller.execute(line)

        return self.view_mock.info_memory.call_args

    async def test_do_memory_verbose_flag_parsed_from_line(self):
        call_args = await self._run_memory_line(["memory", "--verbose"])
        self.assertTrue(call_args.kwargs["verbose"])

    async def test_do_memory_verbose_defaults_off(self):
        call_args = await self._run_memory_line(["memory"])
        self.assertFalse(call_args.kwargs["verbose"])

    async def _run_memory_with_edition(self, edition):
        node = "1.1.1.1"
        ns_stats = {
            node: {
                "test": {
                    "storage-engine": "memory",
                    "index_shmem_alloc_bytes": "100",
                    "data_total_bytes": "500",
                }
            }
        }

        self.stat_getter_mock.get_service.return_value = {node: {}}
        self.config_getter_mock.get_service.return_value = {node: {}}
        self.stat_getter_mock.get_namespace.return_value = ns_stats
        self.set_cluster(
            {node: "8.1.3"}, edition="Aerospike {} Edition".format(edition)
        )
        self.controller.mods = {"with": [], "for": [], "line": []}

        await self.controller.execute(["memory"])

        return self.view_mock.info_memory.call_args.args[2][node]

    async def test_do_memory_community_does_not_fold_data_into_shmem(self):
        ns_agg = await self._run_memory_with_edition("Community")

        self.assertEqual(ns_agg["shmem_alloc_bytes"], "100")
        self.assertEqual(ns_agg["data_alloc_bytes"], "500")

    async def test_do_memory_enterprise_folds_data_into_shmem(self):
        ns_agg = await self._run_memory_with_edition("Enterprise")

        self.assertEqual(ns_agg["shmem_alloc_bytes"], "600")
        self.assertEqual(ns_agg["data_alloc_bytes"], "500")

    async def test_do_memory_unreadable_edition_does_not_fold(self):
        node = "1.1.1.1"
        self.stat_getter_mock.get_service.return_value = {node: {}}
        self.config_getter_mock.get_service.return_value = {node: {}}
        self.stat_getter_mock.get_namespace.return_value = {
            node: {
                "test": {
                    "storage-engine": "memory",
                    "index_shmem_alloc_bytes": "100",
                    "data_total_bytes": "500",
                }
            }
        }
        self.cluster_mock.info_build = AsyncMock(return_value={node: "8.1.3"})
        self.cluster_mock.info = AsyncMock(return_value={node: Exception("timeout")})
        self.cluster_mock.get_node_names.return_value = {node: "node1"}
        self.controller.mods = {"with": [], "for": [], "line": []}

        await self.controller.execute(["memory"])

        ns_agg = self.view_mock.info_memory.call_args.args[2][node]
        self.assertEqual(ns_agg["shmem_alloc_bytes"], "100")

    @parameterized.expand(
        [
            (
                "mixed_cluster",
                {"1.1.1.1": "8.1.3", "2.2.2.2": "8.1.2"},
                ["node-2.2.2.2"],
            ),
            ("all_old", {"1.1.1.1": "8.1.2"}, ["node-1.1.1.1"]),
            ("missing", {"1.1.1.1": None}, ["node-1.1.1.1"]),
            ("empty", {"1.1.1.1": ""}, ["node-1.1.1.1"]),
            (
                "exception",
                {"1.1.1.1": Exception("connection refused")},
                ["node-1.1.1.1"],
            ),
            ("unparseable", {"1.1.1.1": "not-a-version"}, ["node-1.1.1.1"]),
        ]
    )
    async def test_do_memory_warns_once_naming_the_unsupported_nodes(
        self, _name, builds, expected_nodes
    ):
        await self._run_memory_line(["memory"], builds=builds)

        warnings_logged = self.warnings()
        self.assertEqual(len(warnings_logged), 1)
        self.assertIn("Allocation figures require server 8.1.3", warnings_logged[0])

        for node_name in expected_nodes:
            self.assertIn(node_name, warnings_logged[0])

        if _name == "mixed_cluster":
            self.assertNotIn("node-1.1.1.1", warnings_logged[0])

        self.view_mock.info_memory.assert_called_once()

    async def test_do_memory_warning_stays_short_on_a_large_cluster(self):
        nodes = [
            "10-128-32-%d.datadog-agent.opentelemetry.svc.cluster.local:3000" % i
            for i in range(14)
        ]
        await self._run_memory_line(
            ["memory"], builds={node: "8.1.1" for node in nodes}
        )

        warning = self.warnings()[0]

        self.assertIn("all 14 nodes", warning)
        self.assertNotIn(nodes[0], warning)
        self.assertLess(len(warning), 200, warning)

    async def test_do_memory_warning_names_the_stragglers_mid_upgrade(self):
        builds = {"10.0.0.%d" % i: ("8.1.3" if i > 1 else "8.1.1") for i in range(14)}
        await self._run_memory_line(["memory"], builds=builds)

        warning = self.warnings()[0]

        self.assertIn("node-10.0.0.0", warning)
        self.assertIn("node-10.0.0.1", warning)
        self.assertNotIn("all 14 nodes", warning)

    @parameterized.expand(
        [
            ("all_supported", {"1.1.1.1": "8.1.3", "2.2.2.2": "8.2.0"}),
            ("no_nodes", {}),
        ]
    )
    async def test_do_memory_stays_quiet_when_no_node_is_unsupported(
        self, _name, builds
    ):
        await self._run_memory_line(["memory"], builds=builds)

        self.assertEqual(self.warnings(), [])
        self.view_mock.info_memory.assert_called_once()

    async def test_do_memory_hands_the_view_unfiltered_builds(self):
        error = Exception("connection refused")
        call_args = await self._run_memory_line(
            ["memory"], builds={"1.1.1.1": "8.1.3", "2.2.2.2": error}
        )

        self.assertEqual(
            call_args.kwargs["builds"], {"1.1.1.1": "8.1.3", "2.2.2.2": error}
        )

    async def test_do_memory_rejects_for_modifier(self):
        self.controller.mods = {"with": [], "for": ["test"], "line": []}

        with self.assertRaises(ShellException):
            await self.controller.execute(["memory", "for", "test"])

        self.view_mock.info_memory.assert_not_called()
