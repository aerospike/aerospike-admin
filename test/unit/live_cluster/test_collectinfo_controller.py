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
from lib.view.sheet.render import get_style_json, set_style_json

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

    def test_dump_map_node_order_is_stable(self):
        # ascinfo.json ordering must not depend on set-iteration order.
        as_map = {"B": {"statistics": {"s": 1}}, "A": {"statistics": {"s": 2}}}
        meta_map = {"C": {"asd_build": "8.0"}}

        dump_map = self._build({"A", "B", "C"}, as_map, self.empty, meta_map)

        self.assertEqual(list(dump_map), ["A", "B", "C"])

    def test_no_warning_when_all_expected_nodes_present(self):
        as_map = {"A": {"statistics": {"s": 1}}}
        meta_map = {"B": {"asd_build": "8.0"}}

        logger = logging.getLogger(LOGGER_NAME)
        with mock.patch.object(logger, "warning") as warn_mock:
            dump_map = self._build({"A", "B"}, as_map, self.empty, meta_map)

        warn_mock.assert_not_called()
        self.assertEqual(set(dump_map), {"A", "B"})

    def test_node_with_only_seeded_empty_sections_is_warned(self):
        """TOOLS-3596: a fully-failed node has a truthy but empty as_stat (empty-string
        meta plus locally derived node_names/ip plus seeded empty sections); the no-data
        warning must still fire."""
        as_map = {
            "A": {"statistics": {"s": 1}},
            "B": {"statistics": {}, "config": {}},
        }
        meta_map = {
            "A": {"asd_build": "8.0"},
            "B": {
                "asd_build": "",
                "node_id": "",
                "node_names": "B-name",
                "ip": "2.2.2.2:3000",
            },
        }

        with self.assertLogs(LOGGER_NAME, level="WARNING") as cm:
            dump_map = self._build(
                {"A", "B"},
                as_map,
                self.empty,
                meta_map,
                histogram_map={"B": {}},
                latency_map={"B": {}},
                user_agents_map={"B": []},
            )

        self.assertIn("B", dump_map)
        self.assertTrue(
            any("no Aerospike data for 1 node(s): B" in msg for msg in cm.output),
            cm.output,
        )


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


class NoDataWarningProductionShapeTest(unittest.IsolatedAsyncioTestCase):
    """TOOLS-3596: a reachable node whose every info call fails must still trigger the
    no-data warning.

    Collection runs through the real _get_as_metadata/_get_as_histograms/_get_as_latency/
    _get_as_user_agents with only the cluster info calls mocked, so the section maps carry
    the shapes production produces: empty-string meta values, locally derived ip and
    node_names, and seeded-empty histogram/latency/user_agents sections."""

    async def asyncSetUp(self):
        self.controller = CollectinfoController()
        self.controller.nodes = "all"

        node_a = MagicMock()
        node_a.key = "A"
        node_b = MagicMock()
        node_b.key = "B"

        failed = TimeoutError("info call timed out")

        def ok_and_failed(a_value):
            return AsyncMock(return_value={"A": a_value, "B": failed})

        cluster = MagicMock()
        cluster.get_nodes.return_value = [node_a, node_b]
        cluster.get_node_names.return_value = {"A": "A-name", "B": "B-name"}
        cluster.info_system_statistics = AsyncMock(return_value={"A": {"sys": 1}})
        cluster.info_build = ok_and_failed("8.0.0.0")
        cluster.info_version = ok_and_failed(
            "Aerospike Enterprise Edition build 8.0.0.0"
        )
        cluster.info_node = ok_and_failed("A1")
        cluster.info_ip_port = AsyncMock(
            return_value={"A": "1.1.1.1:3000", "B": "2.2.2.2:3000"}
        )
        cluster.info_service_list = ok_and_failed([("1.1.1.1", 3000, None)])
        cluster.info_peers_flat_list = ok_and_failed([("1.1.1.1", 3000, None)])
        cluster.info_udf_list = ok_and_failed({})
        cluster.info_health_outliers = ok_and_failed({})
        cluster.info_best_practices = ok_and_failed([])
        cluster.info_feature_key = ok_and_failed({"asdb-compression": "true"})
        cluster.info_release = ok_and_failed(
            {"edition": "Aerospike Enterprise Edition"}
        )
        cluster.info_scan_show = ok_and_failed({})
        cluster.info_query_show = ok_and_failed({})
        cluster.info_jobs = ok_and_failed({})
        cluster.info_histogram = ok_and_failed("0,1,2")
        cluster.info_latencies = ok_and_failed({"read": {}})
        cluster.info_user_agents = ok_and_failed([{"user-agent": "x", "count": "1"}])
        self.controller.cluster = cluster

        patches = {
            "_get_as_cluster_name": "testcluster",
            "_get_as_data_json": {
                "A": {"statistics": {"s": 1}},
                "B": {"statistics": {}, "config": {}},
            },
            "_get_as_access_control_list": {},
            "_get_as_masking_rules": {},
        }
        for name, ret in patches.items():
            patch.object(
                CollectinfoController, name, AsyncMock(return_value=ret)
            ).start()
        self.addCleanup(patch.stopall)

    async def test_reachable_node_with_all_failed_info_calls_is_warned(self):
        with self.assertLogs(LOGGER_NAME, level="WARNING") as cm:
            result = await self.controller._get_collectinfo_data_json(enable_ssh=False)

        dump_map = result["testcluster"]
        self.assertEqual(set(dump_map), {"A", "B"})

        b_as_stat = dump_map["B"]["as_stat"]
        self.assertEqual(b_as_stat["meta_data"]["ip"], "2.2.2.2:3000")
        self.assertEqual(b_as_stat["meta_data"]["node_names"], "B-name")
        self.assertEqual(b_as_stat["meta_data"]["node_id"], "")
        self.assertEqual(b_as_stat["meta_data"]["asd_build"], "")
        self.assertEqual(b_as_stat["histogram"], {})
        self.assertEqual(b_as_stat["user_agents"], [])

        self.assertTrue(
            any("no Aerospike data for 1 node(s): B" in msg for msg in cm.output),
            cm.output,
        )

    async def test_healthy_node_with_empty_optional_sections_is_not_warned(self):
        self.controller.cluster.get_nodes.return_value = [
            n for n in self.controller.cluster.get_nodes.return_value if n.key == "A"
        ]

        logger = logging.getLogger(LOGGER_NAME)
        with mock.patch.object(logger, "warning") as warn_mock:
            result = await self.controller._get_collectinfo_data_json(enable_ssh=False)

        warn_mock.assert_not_called()
        self.assertIn("A", result["testcluster"])


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


class DiagnosticInfoCaptureTest(unittest.IsolatedAsyncioTestCase):
    """Which commands reach ascollectinfo.log and summary.log, and that a
    failing one does not take the rest of the bundle with it."""

    async def asyncSetUp(self):
        self.controller = CollectinfoController()
        self.controller.nodes = "all"
        self.controller.collectinfo_root_controller = MagicMock()

        async def info(cmd, *args, **kwargs):
            if cmd in self.fail_on:
                raise Exception("boom: " + cmd)

            if cmd == "build":
                return {"A": "8.1.3.0"}

            return {"A": "test"}

        self.controller.cluster = MagicMock()
        self.controller.cluster.info = info

        self.captured = []
        self.fail_on = set()

        async def capture(filename, func, param=None):
            name = " ".join(param or [])
            self.captured.append(name)

            if name in self.fail_on:
                raise Exception("boom: " + name)

        def write_output(filename, param, content):
            self.captured.append(" ".join(param))

        patch.object(
            CollectinfoController,
            "_collectinfo_capture_and_write_to_file",
            AsyncMock(side_effect=capture),
        ).start()
        patch.object(
            CollectinfoController, "_parse_namespace", MagicMock(return_value=[])
        ).start()
        patch.object(
            CollectinfoController,
            "_write_func_output_to_file",
            MagicMock(side_effect=write_output),
        ).start()
        patch("lib.live_cluster.collectinfo_controller.util.write_to_file").start()
        patch("lib.live_cluster.collectinfo_controller.InfoController").start()
        patch("lib.live_cluster.collectinfo_controller.ShowController").start()
        patch("lib.live_cluster.collectinfo_controller.FeaturesController").start()
        self.addCleanup(patch.stopall)

    async def test_ascollectinfo_captures_verbose_memory(self):
        await self.controller._dump_collectinfo_ascollectinfo("prefix_", "header\n")

        self.assertIn("memory -v", self.captured)

    async def test_summary_captures_memory(self):
        await self.controller._dump_collectinfo_summary("prefix_", "header\n")

        self.assertIn("memory", self.captured)

    async def test_one_failed_info_command_does_not_drop_the_rest(self):
        self.fail_on = {"network"}

        await self.controller._dump_collectinfo_ascollectinfo("prefix_", "header\n")

        self.assertIn("network", self.captured)
        self.assertIn("memory -v", self.captured)
        self.assertIn("release", self.captured)

    async def test_one_failed_show_command_does_not_drop_the_rest(self):
        self.fail_on = {"config"}

        await self.controller._dump_collectinfo_ascollectinfo("prefix_", "header\n")

        self.assertIn("config", self.captured)
        self.assertIn("statistics sindex", self.captured)
        self.assertIn("features", self.captured)

    async def test_one_failed_summary_command_does_not_drop_the_rest(self):
        self.fail_on = {"memory"}

        await self.controller._dump_collectinfo_summary("prefix_", "header\n")

        self.assertIn("memory", self.captured)
        self.assertIn("sindex", self.captured)

    async def test_one_failed_features_command_does_not_drop_the_rest(self):
        self.fail_on = {"features"}

        await self.controller._dump_collectinfo_ascollectinfo("prefix_", "header\n")

        self.assertIn("features", self.captured)
        self.assertIn("connection", self.captured)

    async def test_failed_features_controller_does_not_drop_the_rest(self):
        with patch(
            "lib.live_cluster.collectinfo_controller.FeaturesController",
            MagicMock(side_effect=Exception("boom")),
        ):
            await self.controller._dump_collectinfo_ascollectinfo("prefix_", "header\n")

        self.assertNotIn("features", self.captured)
        self.assertIn("connection", self.captured)

    async def test_one_failed_asinfo_command_does_not_drop_the_rest(self):
        self.fail_on = {"connection"}

        await self.controller._dump_collectinfo_ascollectinfo("prefix_", "header\n")

        self.assertNotIn("connection", self.captured)
        self.assertIn("service-clear-std", self.captured)
        self.assertIn("roster:", self.captured)


class CaptureParamTest(unittest.IsolatedAsyncioTestCase):
    async def test_default_param_does_not_accumulate_across_calls(self):
        controller = CollectinfoController()
        controller.nodes = ["1.1.1.1"]
        recorded = []

        def noop(line):
            pass

        with patch.object(
            CollectinfoController,
            "_write_func_output_to_file",
            MagicMock(
                side_effect=lambda filename, param, content: recorded.append(param)
            ),
        ):
            await controller._collectinfo_capture_and_write_to_file("f", noop)
            await controller._collectinfo_capture_and_write_to_file("f", noop)

        self.assertEqual(recorded, [["with", "1.1.1.1"], ["with", "1.1.1.1"]])

    async def test_caller_list_is_not_mutated(self):
        controller = CollectinfoController()
        controller.nodes = ["1.1.1.1"]
        param = ["memory", "-v"]

        def noop(line):
            pass

        with patch.object(CollectinfoController, "_write_func_output_to_file"):
            await controller._collectinfo_capture_and_write_to_file("f", noop, param)

        self.assertEqual(param, ["memory", "-v"])


class CaptureStyleJsonTest(unittest.IsolatedAsyncioTestCase):
    """The sheet json style is disabled around the render rather than around the
    write, so a bundle captured under --json still carries tables."""

    def setUp(self):
        self.controller = CollectinfoController()
        self.controller.nodes = "all"
        self.addCleanup(set_style_json, get_style_json())
        set_style_json(True)

    async def test_render_sees_json_style_disabled(self):
        seen = []

        def render(line):
            seen.append(get_style_json())

        with patch.object(CollectinfoController, "_write_func_output_to_file"):
            await self.controller._collectinfo_capture_and_write_to_file("f", render)

        self.assertEqual(seen, [False])
        self.assertTrue(get_style_json())

    async def test_style_json_restored_when_render_raises(self):
        def render(line):
            raise Exception("boom")

        with self.assertRaises(Exception):
            await self.controller._collectinfo_capture_and_write_to_file("f", render)

        self.assertTrue(get_style_json())


if __name__ == "__main__":
    unittest.main()
