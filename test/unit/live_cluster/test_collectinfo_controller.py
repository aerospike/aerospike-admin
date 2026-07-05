# Copyright 2024-2025 Aerospike, Inc.
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

import logging
import unittest
from unittest import mock
from unittest.mock import AsyncMock, MagicMock, patch

from lib.live_cluster.collectinfo_controller import (
    CollectinfoController,
    COLLECTINFO_NODE_TIMEOUT,
)

LOGGER_NAME = "lib.live_cluster.collectinfo_controller"


class BuildDumpMapTest(unittest.TestCase):
    """Tests for CollectinfoController._build_dump_map (TOOLS-3596).

    The merge must iterate over the union of node keys across every section map, not just
    ``as_map``, so a node whose statistics/config calls all failed in the first burst is
    still included in the snapshot via the sections that did succeed.
    """

    def setUp(self):
        self.controller = CollectinfoController()
        self.empty = {}

    def _build(
        self,
        expected,
        as_map,
        sys_map,
        meta_map,
        histogram_map=None,
        latency_map=None,
        pmap_map=None,
        acl_map=None,
        user_agents_map=None,
        masking_map=None,
    ):
        return self.controller._build_dump_map(
            expected,
            as_map,
            sys_map,
            meta_map,
            histogram_map if histogram_map is not None else {},
            latency_map if latency_map is not None else {},
            pmap_map,
            acl_map if acl_map is not None else {},
            user_agents_map if user_agents_map is not None else {},
            masking_map if masking_map is not None else {},
        )

    def test_node_absent_from_as_map_is_still_included(self):
        # Node "A" returned full stats. Node "B" lost all stats/config (absent from as_map)
        # but its metadata and system-stat calls succeeded.
        as_map = {"A": {"statistics": {"s": 1}, "config": {"c": 1}}}
        sys_map = {"A": {"sys": 1}, "B": {"sys": 2}}
        meta_map = {"A": {"asd_build": "8.0"}, "B": {"asd_build": "8.0"}}

        dump_map = self._build({"A", "B"}, as_map, sys_map, meta_map)

        # The previously-dropped node is now present.
        self.assertIn("B", dump_map)
        self.assertEqual(dump_map["B"]["as_stat"], {"meta_data": {"asd_build": "8.0"}})
        self.assertEqual(dump_map["B"]["sys_stat"], {"sys": 2})

        # The fully-successful node is unchanged.
        self.assertEqual(dump_map["A"]["as_stat"]["statistics"], {"s": 1})
        self.assertEqual(dump_map["A"]["as_stat"]["config"], {"c": 1})
        self.assertEqual(dump_map["A"]["as_stat"]["meta_data"], {"asd_build": "8.0"})
        self.assertEqual(dump_map["A"]["sys_stat"], {"sys": 1})

    def test_all_sections_attach_under_the_right_keys(self):
        # Every section map carries data for node "A" so each attach branch is exercised.
        as_map = {"A": {"statistics": {"s": 1}}}
        sys_map = {"A": {"sys": 1}}
        meta_map = {"A": {"asd_build": "8.0"}}
        histogram_map = {"A": {"ttl": {"h": 1}}}
        latency_map = {"A": {"read": {"l": 1}}}
        pmap_map = {"A": {"p": 1}}
        acl_map = {"A": {"users": {}}}
        user_agents_map = {"A": [{"agent": "x"}]}
        masking_map = {"A": [{"rule": "y"}]}

        dump_map = self._build(
            {"A"},
            as_map,
            sys_map,
            meta_map,
            histogram_map=histogram_map,
            latency_map=latency_map,
            pmap_map=pmap_map,
            acl_map=acl_map,
            user_agents_map=user_agents_map,
            masking_map=masking_map,
        )

        as_stat = dump_map["A"]["as_stat"]
        self.assertEqual(as_stat["statistics"], {"s": 1})
        self.assertEqual(as_stat["meta_data"], {"asd_build": "8.0"})
        self.assertEqual(as_stat["histogram"], {"ttl": {"h": 1}})
        self.assertEqual(as_stat["latency"], {"read": {"l": 1}})
        self.assertEqual(as_stat["pmap"], {"p": 1})
        self.assertEqual(as_stat["acl"], {"users": {}})
        self.assertEqual(as_stat["user_agents"], [{"agent": "x"}])
        self.assertEqual(as_stat["masking"], [{"rule": "y"}])
        self.assertEqual(dump_map["A"]["sys_stat"], {"sys": 1})

    def test_node_only_in_pmap_is_included(self):
        # pmap is gathered separately and is the only optional map that can be None.
        as_map = {"A": {"statistics": {"s": 1}}}
        pmap_map = {"B": {"p": 1}}

        dump_map = self._build(
            {"A", "B"}, as_map, self.empty, self.empty, pmap_map=pmap_map
        )

        self.assertIn("B", dump_map)
        self.assertEqual(dump_map["B"]["as_stat"], {"pmap": {"p": 1}})

    def test_node_with_no_data_anywhere_is_included_and_warned(self):
        # "A" produced data; expected node "C" produced nothing in any section map. The
        # snapshot must still contain "C" (with an empty as_stat) and warn about it.
        as_map = {"A": {"statistics": {"s": 1}}}

        with self.assertLogs(LOGGER_NAME, level="WARNING") as cm:
            dump_map = self._build({"A", "C"}, as_map, self.empty, self.empty)

        self.assertIn("A", dump_map)
        self.assertIn("C", dump_map)
        self.assertEqual(dump_map["C"]["as_stat"], {})
        self.assertTrue(
            any("no Aerospike data" in msg and "C" in msg for msg in cm.output),
            cm.output,
        )

    def test_node_with_only_sys_stat_is_included_and_warned(self):
        # A node reachable over SSH but whose every info call failed has sys_stat data
        # and an empty as_stat; it is kept but warned about.
        as_map = {"A": {"statistics": {"s": 1}}}
        sys_map = {"A": {"sys": 1}, "B": {"sys": 2}}

        with self.assertLogs(LOGGER_NAME, level="WARNING") as cm:
            dump_map = self._build({"A", "B"}, as_map, sys_map, self.empty)

        self.assertEqual(dump_map["B"]["as_stat"], {})
        self.assertEqual(dump_map["B"]["sys_stat"], {"sys": 2})
        self.assertTrue(
            any("no Aerospike data" in msg and "B" in msg for msg in cm.output),
            cm.output,
        )

    def test_no_warning_when_all_expected_nodes_present(self):
        as_map = {"A": {"statistics": {"s": 1}}}
        meta_map = {"B": {"asd_build": "8.0"}}

        logger = logging.getLogger(LOGGER_NAME)
        with mock.patch.object(logger, "warning") as warn_mock:
            dump_map = self._build({"A", "B"}, as_map, self.empty, meta_map)

        warn_mock.assert_not_called()
        self.assertEqual(set(dump_map), {"A", "B"})


class GetCollectinfoDataJsonTest(unittest.IsolatedAsyncioTestCase):
    """Tests for the async orchestration in _get_collectinfo_data_json (TOOLS-3596).

    Verifies the union merge end-to-end and that the "expected" node set used for the
    missing-node warning comes from the same alive+selected node selection the info calls
    used (self.cluster.get_nodes(self.nodes))."""

    async def asyncSetUp(self):
        self.controller = CollectinfoController()
        self.controller.nodes = "all"

        node_a = MagicMock()
        node_a.key = "A"
        node_b = MagicMock()
        node_b.key = "B"

        self.controller.cluster = MagicMock()
        self.controller.cluster.get_nodes.return_value = [node_a, node_b]
        self.controller.cluster.info_system_statistics = AsyncMock(
            return_value={"A": {"sys": 1}}
        )

        # Node "B" lost statistics/config (absent from as_map) but answered metadata.
        patches = {
            "_get_as_cluster_name": "testcluster",
            "_get_as_data_json": {"A": {"statistics": {"s": 1}}},
            "_get_as_metadata": {"A": {"asd_build": "8.0"}, "B": {"asd_build": "8.0"}},
            "_get_as_histograms": {},
            "_get_as_latency": {},
            "_get_as_access_control_list": {},
            "_get_as_user_agents": {},
            "_get_as_masking_rules": {},
        }
        for name, ret in patches.items():
            patch.object(
                CollectinfoController, name, AsyncMock(return_value=ret)
            ).start()
        self.addCleanup(patch.stopall)

    async def test_union_snapshot_and_expected_nodes_from_get_nodes(self):
        result = await self.controller._get_collectinfo_data_json(enable_ssh=False)

        self.assertIn("testcluster", result)
        dump_map = result["testcluster"]

        # B was absent from as_map yet still lands in the snapshot via metadata.
        self.assertEqual(set(dump_map), {"A", "B"})
        self.assertEqual(dump_map["B"]["as_stat"], {"meta_data": {"asd_build": "8.0"}})
        self.assertEqual(dump_map["A"]["as_stat"]["statistics"], {"s": 1})

        # Expected-node set is derived from the queried selection, not all cluster nodes.
        self.controller.cluster.get_nodes.assert_called_once_with("all")


class RunCollectinfoTimeoutTest(unittest.IsolatedAsyncioTestCase):
    """Tests for the collectinfo-only per-node timeout override in _run_collectinfo
    (TOOLS-3596): the timeout is raised for the run and always restored afterwards."""

    async def asyncSetUp(self):
        self.controller = CollectinfoController()
        self.controller.nodes = "all"
        self.controller.asadm_version = "test-version"

        self.controller.cluster = MagicMock()
        self.controller.cluster.is_localhost_a_node.return_value = False

        # Neutralize the heavy collaborators so only the timeout wiring is under test.
        patch.object(CollectinfoController, "setup_loggers").start()
        patch.object(CollectinfoController, "teardown_loggers").start()
        patch.object(
            CollectinfoController, "_dump_collectinfo_json", AsyncMock()
        ).start()
        patch.object(
            CollectinfoController, "_dump_collectinfo_ascollectinfo", AsyncMock()
        ).start()
        patch.object(
            CollectinfoController, "_dump_collectinfo_summary", AsyncMock()
        ).start()
        patch.object(
            CollectinfoController, "_dump_collectinfo_health", AsyncMock()
        ).start()

        cf_info = MagicMock()
        cf_info.cf_dir = "/tmp/collectinfo_test"
        cf_info.files_prefix = "prefix_"

        patch(
            "lib.live_cluster.collectinfo_controller.common.get_collectinfo_path",
            return_value=cf_info,
        ).start()
        patch(
            "lib.live_cluster.collectinfo_controller.common.archive_dir",
            return_value=("/tmp/collectinfo_test.tgz", True),
        ).start()
        patch(
            "lib.live_cluster.collectinfo_controller.common.print_collectinfo_failed_cmds"
        ).start()
        patch(
            "lib.live_cluster.collectinfo_controller.common.print_collect_summary"
        ).start()
        patch("lib.live_cluster.collectinfo_controller.terminal").start()
        patch(
            "lib.live_cluster.collectinfo_controller.CollectinfoRootController"
        ).start()
        self.addCleanup(patch.stopall)

    async def _run(self):
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

    async def test_raises_then_restores_default_timeout(self):
        self.controller.cluster._timeout = 1

        await self._run()

        calls = self.controller.cluster.set_timeout.call_args_list
        # Raised to the collectinfo default at the start...
        self.assertEqual(calls[0], mock.call(COLLECTINFO_NODE_TIMEOUT))
        # ...and restored to the original in the finally.
        self.assertEqual(calls[-1], mock.call(1))

    async def test_does_not_lower_explicit_larger_timeout(self):
        self.controller.cluster._timeout = 10

        await self._run()

        # max(10, 5) == 10, so the timeout is never touched: no raise, no restore.
        self.controller.cluster.set_timeout.assert_not_called()

    async def test_restores_timeout_even_when_teardown_fails(self):
        """The restore must run before teardown so a teardown failure cannot leak the
        elevated timeout into subsequent interactive use."""
        self.controller.cluster._timeout = 1
        CollectinfoController.teardown_loggers.side_effect = OSError("disk full")

        with self.assertRaises(OSError):
            await self._run()

        calls = self.controller.cluster.set_timeout.call_args_list
        self.assertEqual(calls[-1], mock.call(1))


if __name__ == "__main__":
    unittest.main()
