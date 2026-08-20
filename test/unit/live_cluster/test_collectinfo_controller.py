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

import asyncio
import json
import logging
import unittest
from unittest import mock
from unittest.mock import AsyncMock, MagicMock, patch

from lib.live_cluster.client.types import (
    ASInfoError,
    ASInfoNotAuthenticatedError,
    ASInfoResponseError,
    ASProtocolConnectionError,
    ASProtocolError,
    ASResponse,
)
from lib.collectinfo_analyzer.collectinfo_handler.collectinfo_diagnostics import (
    CollectinfoDiagnostics,
)
from lib.live_cluster.client.node import Node
from lib.live_cluster.collectinfo_controller import (
    CollectinfoController,
    COLLECTINFO_NODE_TIMEOUT,
    _classify_exception,
    _node_error_entries,
    _record_node_error,
)
from lib.utils import constants

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
        self.controller.cluster.aliases = {}
        self.controller.cluster.get_down_nodes = AsyncMock(return_value=[])
        self.controller.cluster.get_visibility_error_nodes = MagicMock(return_value=[])
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
        result, _ = await self.controller._get_collectinfo_data_json(enable_ssh=False)

        self.assertIn("testcluster", result)
        dump_map = result["testcluster"]

        # B was absent from as_map yet still lands in the snapshot via metadata.
        self.assertEqual(set(dump_map), {"A", "B"})
        self.assertEqual(dump_map["B"]["as_stat"], {"meta_data": {"asd_build": "8.0"}})
        self.assertEqual(dump_map["A"]["as_stat"]["statistics"], {"s": 1})

        # Expected-node set is derived from the queried selection, not all cluster nodes.
        self.controller.cluster.get_nodes.assert_called_once_with("all")

    async def test_a_sysinfo_failure_is_recorded_and_the_bundle_still_written(self):
        """One unreachable host used to abort the whole collection. The failure is
        recorded and that node's sys_stat left empty instead."""
        self.controller.cluster.info_system_statistics = AsyncMock(
            return_value={"A": {"sys": 1}, "B": OSError("ssh refused")}
        )

        with self.assertLogs(LOGGER_NAME, level="WARNING") as cm:
            result, snapshot_meta = await self.controller._get_collectinfo_data_json(
                enable_ssh=True
            )

        dump_map = result["testcluster"]
        self.assertEqual(dump_map["B"]["sys_stat"], {})
        self.assertEqual(dump_map["A"]["sys_stat"], {"sys": 1})
        self.assertEqual(
            snapshot_meta["nodes"]["B"]["errors"][0]["section"],
            constants.CollectinfoSection.SYSINFO,
        )
        self.assertEqual(
            snapshot_meta["nodes"]["B"]["errors"][0]["error_class"],
            constants.CollectinfoErrorClass.UNREACHABLE,
        )
        self.assertTrue(any("system statistics" in msg for msg in cm.output), cm.output)


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
        cluster.aliases = {}
        cluster.get_down_nodes = AsyncMock(return_value=[])
        cluster.get_visibility_error_nodes = MagicMock(return_value=[])
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
            result, _ = await self.controller._get_collectinfo_data_json(
                enable_ssh=False
            )

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
            result, _ = await self.controller._get_collectinfo_data_json(
                enable_ssh=False
            )

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


class ClassifyExceptionTest(unittest.TestCase):
    """TOOLS-4135: per-node failures are classified by our own mapping, not by
    async_return_exceptions, which has no 'corrupt' branch."""

    def test_timeout_wins_over_oserror(self):
        """asyncio.TimeoutError subclasses OSError on 3.11+."""
        self.assertEqual(
            _classify_exception(asyncio.TimeoutError()),
            constants.CollectinfoErrorClass.TIMEOUT,
        )

    def test_auth_errors(self):
        self.assertEqual(
            _classify_exception(ASInfoNotAuthenticatedError("m", "r")),
            constants.CollectinfoErrorClass.AUTH,
        )
        self.assertEqual(
            _classify_exception(ASProtocolConnectionError(ASResponse.OK, "m")),
            constants.CollectinfoErrorClass.AUTH,
        )

    def test_oserror_is_unreachable(self):
        self.assertEqual(
            _classify_exception(ConnectionRefusedError()),
            constants.CollectinfoErrorClass.UNREACHABLE,
        )

    def test_asinfo_error_is_corrupt(self):
        self.assertEqual(
            _classify_exception(ASInfoError("m", "bad response")),
            constants.CollectinfoErrorClass.CORRUPT,
        )
        self.assertEqual(
            _classify_exception(ASInfoResponseError("m", "bad response")),
            constants.CollectinfoErrorClass.CORRUPT,
        )

    def test_anything_else_is_other(self):
        self.assertEqual(
            _classify_exception(ValueError("nope")),
            constants.CollectinfoErrorClass.OTHER,
        )

    def test_security_disabled_acl_is_unsupported(self):
        """A security-disabled cluster rejects every ACL call. Nothing was lost, so
        it must not be reported as a collection failure on every node."""
        for response in (
            ASResponse.SECURITY_NOT_ENABLED,
            ASResponse.SECURITY_NOT_SUPPORTED,
        ):
            self.assertEqual(
                _classify_exception(
                    ASProtocolError(response, "Failed to query users"),
                    constants.CollectinfoSection.ACL,
                ),
                constants.CollectinfoErrorClass.UNSUPPORTED,
                response,
            )

    def test_optional_sections_missing_from_the_server_are_unsupported(self):
        """user-agents and masking-show are recent; older servers answer with an
        error response, which is not a corrupt response."""
        for section in (
            constants.CollectinfoSection.USER_AGENTS,
            constants.CollectinfoSection.MASKING,
        ):
            self.assertEqual(
                _classify_exception(
                    ASInfoResponseError("Failed to get user agents", "unknown command"),
                    section,
                ),
                constants.CollectinfoErrorClass.UNSUPPORTED,
                section,
            )

    def test_required_sections_still_report_a_bad_response(self):
        self.assertEqual(
            _classify_exception(
                ASInfoResponseError("m", "bad response"),
                constants.CollectinfoSection.STATISTICS,
            ),
            constants.CollectinfoErrorClass.CORRUPT,
        )

    def test_a_timeout_on_an_optional_section_is_still_a_timeout(self):
        self.assertEqual(
            _classify_exception(
                asyncio.TimeoutError("late"), constants.CollectinfoSection.USER_AGENTS
            ),
            constants.CollectinfoErrorClass.TIMEOUT,
        )

    def test_auth_failure_is_not_mistaken_for_an_absent_section(self):
        """Both auth types subclass a type the unsupported check looks for
        (ASInfoNotAuthenticatedError under ASInfoResponseError,
        ASProtocolConnectionError under ASProtocolError), so an expired session on
        an optional section must not be swallowed as a missing section."""
        self.assertEqual(
            _classify_exception(
                ASProtocolConnectionError(ASResponse.SECURITY_NOT_ENABLED, "m"),
                constants.CollectinfoSection.ACL,
            ),
            constants.CollectinfoErrorClass.AUTH,
        )

        for section in (
            constants.CollectinfoSection.USER_AGENTS,
            constants.CollectinfoSection.MASKING,
        ):
            self.assertEqual(
                _classify_exception(
                    ASInfoNotAuthenticatedError("m", "security error"), section
                ),
                constants.CollectinfoErrorClass.AUTH,
                section,
            )


class OlderServerMetadataTest(unittest.IsolatedAsyncioTestCase):
    """A healthy cluster running a supported older server must collect cleanly.

    Three of the twelve metadata sub-calls depend on the server's version or
    edition: `release` needs 8.1.1, `best-practices` needs 5.7, and `feature-key`
    is Enterprise-only from 7.1. All three are called ungated, so a healthy 8.0
    cluster fails them on every node. Recording that under the shared `metadata`
    label made the analyzer report a broken collection for the whole cluster.
    """

    async def _real_release_exception(self, build):
        """The exception asadm's own version gate produces, not a hand-written one."""

        class _NodeStub:
            ip = "1.1.1.1"
            port = 3000

            async def info_build(self):
                return build

        return await Node.info_release(_NodeStub())

    async def test_release_version_gate_is_recorded_as_unsupported(self):
        exception = await self._real_release_exception("8.0.0.5")

        self.assertIsInstance(exception, ASInfoError)
        self.assertNotIsInstance(exception, ASInfoResponseError)

        controller = CollectinfoController()
        controller.nodes = "all"
        cluster = MagicMock()
        cluster.get_node_names.return_value = {"A": "A-name"}
        cluster.info_build = AsyncMock(return_value={"A": "8.0.0.5"})
        cluster.info_version = AsyncMock(return_value={"A": "Enterprise 8.0.0.5"})
        cluster.info_node = AsyncMock(return_value={"A": "A1"})
        cluster.info_ip_port = AsyncMock(return_value={"A": "1.1.1.1:3000"})
        cluster.info_service_list = AsyncMock(return_value={"A": []})
        cluster.info_peers_flat_list = AsyncMock(return_value={"A": []})
        cluster.info_udf_list = AsyncMock(return_value={"A": {}})
        cluster.info_health_outliers = AsyncMock(return_value={"A": {}})
        cluster.info_best_practices = AsyncMock(
            return_value={
                "A": ASInfoResponseError(
                    "Failed to get best practices", "ERROR:4:unrecognized command"
                )
            }
        )
        cluster.info_feature_key = AsyncMock(
            return_value={
                "A": ASInfoResponseError(
                    "Failed to get feature-key", "ERROR:4:enterprise only"
                )
            }
        )
        cluster.info_release = AsyncMock(return_value={"A": exception})
        cluster.info_scan_show = AsyncMock(return_value={"A": {}})
        cluster.info_query_show = AsyncMock(return_value={"A": {}})
        cluster.info_jobs = AsyncMock(return_value={"A": {}})
        controller.cluster = cluster

        ledger = {}
        await controller._get_as_metadata(ledger=ledger)

        self.assertEqual(
            sorted(ledger["A"]),
            sorted(
                [
                    (
                        constants.CollectinfoSection.BEST_PRACTICES,
                        constants.CollectinfoErrorClass.UNSUPPORTED,
                    ),
                    (
                        constants.CollectinfoSection.FEATURE_KEY,
                        constants.CollectinfoErrorClass.UNSUPPORTED,
                    ),
                    (
                        constants.CollectinfoSection.RELEASE,
                        constants.CollectinfoErrorClass.UNSUPPORTED,
                    ),
                ]
            ),
        )

    async def test_a_timeout_on_an_optional_call_stays_under_metadata(self):
        """The retry pass selects nodes by section name and re-queries all twelve
        sub-calls, so a transient failure of one of these must keep the metadata
        label or it would never be retried."""
        controller = CollectinfoController()
        result_map = {"A": {}}
        ledger = {}

        controller._check_for_exception_and_set(
            {"A": asyncio.TimeoutError("late")},
            "release",
            "A",
            result_map,
            ledger,
            optional_section=constants.CollectinfoSection.RELEASE,
        )

        self.assertEqual(
            list(ledger["A"]),
            [
                (
                    constants.CollectinfoSection.METADATA,
                    constants.CollectinfoErrorClass.TIMEOUT,
                )
            ],
        )

    async def test_the_analyzer_stays_quiet_about_those_sections(self):
        exception = await self._real_release_exception("8.0.0.5")
        ledger = {}
        _record_node_error(ledger, "A", constants.CollectinfoSection.RELEASE, exception)

        diagnostics = CollectinfoDiagnostics(
            log_handler=MagicMock(),
            snapshot=MagicMock(),
            timestamp="ts",
            meta={
                "snapshots": [
                    {
                        "timestamp": "ts",
                        "nodes": {"A": {"errors": _node_error_entries(ledger, "A")}},
                    }
                ]
            },
        )

        self.assertIsNone(diagnostics._check_node_collection_errors())

    async def test_a_real_failure_of_those_sections_is_still_reported(self):
        ledger = {}
        _record_node_error(
            ledger,
            "A",
            constants.CollectinfoSection.RELEASE,
            asyncio.TimeoutError("late"),
        )

        diagnostics = CollectinfoDiagnostics(
            log_handler=MagicMock(),
            snapshot=MagicMock(),
            timestamp="ts",
            meta={
                "snapshots": [
                    {
                        "timestamp": "ts",
                        "nodes": {"A": {"errors": _node_error_entries(ledger, "A")}},
                    }
                ]
            },
        )

        warning = diagnostics._check_node_collection_errors()

        self.assertIsNotNone(warning)
        self.assertIn("release", warning.table_lines[0])


class RecordNodeErrorTest(unittest.TestCase):
    def test_records_message_and_class(self):
        ledger = {}
        _record_node_error(ledger, "A", "statistics", asyncio.TimeoutError("late"))

        entry = ledger["A"][("statistics", constants.CollectinfoErrorClass.TIMEOUT)]
        self.assertEqual(entry["section"], "statistics")
        self.assertEqual(entry["error_class"], constants.CollectinfoErrorClass.TIMEOUT)
        self.assertEqual(entry["recovered_on_retry"], False)

    def test_dedupes_per_node_section_and_class(self):
        ledger = {}
        for _ in range(3):
            _record_node_error(ledger, "A", "metadata", asyncio.TimeoutError("late"))

        self.assertEqual(len(ledger["A"]), 1)

    def test_distinct_classes_for_same_section_are_kept(self):
        ledger = {}
        _record_node_error(ledger, "A", "metadata", asyncio.TimeoutError("late"))
        _record_node_error(ledger, "A", "metadata", ConnectionRefusedError("gone"))

        self.assertEqual(len(ledger["A"]), 2)

    def test_missing_ledger_or_section_is_a_noop(self):
        _record_node_error(None, "A", "metadata", ValueError("x"))

        ledger = {}
        _record_node_error(ledger, "A", None, ValueError("x"))
        _record_node_error(ledger, "", "metadata", ValueError("x"))

        self.assertEqual(ledger, {})

    def test_exception_with_no_message_falls_back_to_class_name(self):
        ledger = {}
        _record_node_error(ledger, "A", "config", asyncio.TimeoutError())

        entry = ledger["A"][("config", constants.CollectinfoErrorClass.TIMEOUT)]
        self.assertEqual(entry["message"], "TimeoutError")


class LedgerPlumbingTest(unittest.TestCase):
    """The scrub sites must record the exception before replacing it with {} / ""."""

    def setUp(self):
        self.controller = CollectinfoController()

    def test_remove_exception_from_section_output_records(self):
        data = {"service": {"A": ConnectionRefusedError("gone"), "B": {"s": 1}}}
        ledger = {}

        self.controller._remove_exception_from_section_output(
            data, constants.CollectinfoSection.STATISTICS, ledger
        )

        self.assertEqual(data["service"]["A"], {})
        self.assertEqual(
            list(ledger["A"]),
            [
                (
                    constants.CollectinfoSection.STATISTICS,
                    constants.CollectinfoErrorClass.UNREACHABLE,
                )
            ],
        )
        self.assertNotIn("B", ledger)

    def test_check_for_exception_and_set_records_metadata_section(self):
        result_map = {"A": {}}
        ledger = {}

        self.controller._check_for_exception_and_set(
            {"A": asyncio.TimeoutError("late")}, "asd_build", "A", result_map, ledger
        )

        self.assertEqual(result_map["A"]["asd_build"], "")
        self.assertIn(
            (
                constants.CollectinfoSection.METADATA,
                constants.CollectinfoErrorClass.TIMEOUT,
            ),
            ledger["A"],
        )


class DetectNodeDiscrepanciesTest(unittest.IsolatedAsyncioTestCase):
    def _controller(self, aliases=None):
        controller = CollectinfoController()
        controller.nodes = "all"
        controller.cluster = MagicMock()
        controller.cluster.aliases = aliases if aliases is not None else {}
        controller.cluster.get_down_nodes = AsyncMock(return_value=["9.9.9.9:3000"])
        controller.cluster.get_visibility_error_nodes = MagicMock(
            return_value=["1.1.1.1:3000"]
        )
        return controller

    def _node(self, key, node_id="ID", localhost=False):
        node = MagicMock()
        node.key = key
        node.node_id = node_id
        node.localhost = localhost
        return node

    async def test_awaits_down_nodes_and_does_not_await_visibility(self):
        controller = self._controller()
        node = self._node("1.1.1.1:3000")
        dump_map = {"1.1.1.1:3000": {"as_stat": {"statistics": {"s": 1}}}}

        meta = await controller._detect_node_discrepancies(
            [node], dump_map, {}, enable_ssh=False
        )

        controller.cluster.get_down_nodes.assert_awaited_once()
        controller.cluster.get_visibility_error_nodes.assert_called_once_with()
        self.assertEqual(meta["discrepancies"]["cluster_down_nodes"], ["9.9.9.9:3000"])
        self.assertEqual(
            meta["discrepancies"]["visibility_error_nodes"], ["1.1.1.1:3000"]
        )

    async def test_responded_and_dropped_nodes(self):
        controller = self._controller()
        nodes = [self._node("A"), self._node("B")]
        dump_map = {
            "A": {"as_stat": {"statistics": {"s": 1}}},
            "B": {"as_stat": {}},
        }
        ledger = {}
        _record_node_error(ledger, "B", "statistics", asyncio.TimeoutError("late"))

        meta = await controller._detect_node_discrepancies(
            nodes, dump_map, ledger, enable_ssh=False
        )

        self.assertEqual(meta["expected_nodes"], ["A", "B"])
        self.assertEqual(meta["responded_nodes"], ["A"])
        self.assertEqual(meta["no_data_nodes"], ["B"])
        self.assertEqual(
            meta["discrepancies"]["dropped_during_collection"],
            [{"node_key": "B", "reason": "timed out"}],
        )
        self.assertTrue(meta["nodes"]["A"]["responded"])
        self.assertFalse(meta["nodes"]["B"]["responded"])
        self.assertEqual(len(meta["nodes"]["B"]["errors"]), 1)

    async def test_peer_advertised_under_alias_is_not_reported_missing(self):
        """A multi-homed cluster seeded via one address while peers advertise another
        must not produce a permanent false 'missing node' entry."""
        controller = self._controller(aliases={"10.0.0.2:3000": "2.2.2.2:3000"})
        nodes = [self._node("1.1.1.1:3000"), self._node("2.2.2.2:3000")]
        dump_map = {
            "1.1.1.1:3000": {
                "as_stat": {
                    "statistics": {"s": 1},
                    "meta_data": {
                        "services": [
                            ("10.0.0.2", 3000, None),
                            ("9.9.9.9", 3000, None),
                        ]
                    },
                }
            },
            "2.2.2.2:3000": {"as_stat": {"statistics": {"s": 1}}},
        }

        meta = await controller._detect_node_discrepancies(
            nodes, dump_map, {}, enable_ssh=False
        )

        missing = meta["discrepancies"]["missing_from_collection"]
        self.assertEqual([entry["node_key"] for entry in missing], ["9.9.9.9:3000"])

    async def test_ipv6_peer_key_format(self):
        controller = self._controller()
        node = self._node("A")
        dump_map = {
            "A": {
                "as_stat": {
                    "statistics": {"s": 1},
                    "meta_data": {"services": [("fe80::1", 3000, None)]},
                }
            }
        }

        meta = await controller._detect_node_discrepancies(
            [node], dump_map, {}, enable_ssh=False
        )

        self.assertEqual(
            [e["node_key"] for e in meta["discrepancies"]["missing_from_collection"]],
            ["[fe80::1]:3000"],
        )

    async def test_scrubbed_services_string_is_ignored(self):
        """A failed services call is scrubbed to "" by _check_for_exception_and_set."""
        controller = self._controller()
        node = self._node("A")
        dump_map = {
            "A": {"as_stat": {"statistics": {"s": 1}, "meta_data": {"services": ""}}}
        }

        meta = await controller._detect_node_discrepancies(
            [node], dump_map, {}, enable_ssh=False
        )

        self.assertEqual(meta["discrepancies"]["missing_from_collection"], [])

    async def test_sysinfo_source(self):
        controller = self._controller()
        local = self._node("L", localhost=True)
        remote = self._node("R")
        failed = self._node("F")
        dump_map = {
            "L": {"as_stat": {"statistics": {"s": 1}}, "sys_stat": {"uname": {"n": 1}}},
            "R": {"as_stat": {"statistics": {"s": 1}}, "sys_stat": {"uname": {"n": 1}}},
            "F": {"as_stat": {"statistics": {"s": 1}}, "sys_stat": {}},
        }

        meta = await controller._detect_node_discrepancies(
            [local, remote, failed], dump_map, {}, enable_ssh=True
        )

        self.assertEqual(meta["nodes"]["L"]["sysinfo_source"], "local")
        self.assertEqual(meta["nodes"]["R"]["sysinfo_source"], "ssh")
        self.assertEqual(meta["nodes"]["F"]["sysinfo_source"], "none")

    async def test_sysinfo_source_is_none_for_a_swallowed_ssh_failure(self):
        """_get_remote_host_system_statistics logs a mid-run SSHError and returns
        without raising, so no ledger entry exists; the empty sys_stat is the only
        evidence and meta must not claim 'ssh'."""
        controller = self._controller()
        remote = self._node("R")
        dump_map = {"R": {"as_stat": {"statistics": {"s": 1}}}}

        meta = await controller._detect_node_discrepancies(
            [remote], dump_map, {}, enable_ssh=True
        )

        self.assertEqual(meta["nodes"]["R"]["sysinfo_source"], "none")

    async def test_sysinfo_source_none_without_ssh(self):
        controller = self._controller()
        remote = self._node("R")
        dump_map = {"R": {"as_stat": {"statistics": {"s": 1}}}}

        meta = await controller._detect_node_discrepancies(
            [remote], dump_map, {}, enable_ssh=False
        )

        self.assertEqual(meta["nodes"]["R"]["sysinfo_source"], "none")

    async def test_live_call_failure_degrades_to_detection_error(self):
        """Diagnostics must never break the bundle they diagnose."""
        controller = self._controller()
        controller.cluster.get_down_nodes = AsyncMock(side_effect=OSError("no route"))
        node = self._node("A")
        dump_map = {"A": {"as_stat": {"statistics": {"s": 1}}}}

        meta = await controller._detect_node_discrepancies(
            [node], dump_map, {}, enable_ssh=False
        )

        self.assertEqual(meta["discrepancies"], {"detection_error": "no route"})
        self.assertEqual(meta["responded_nodes"], ["A"])


class RetryTimedOutNodesTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.controller = CollectinfoController()
        self.controller.nodes = "all"
        self.controller.cluster = MagicMock()

    async def test_no_retry_without_timeouts(self):
        ledger = {}
        _record_node_error(ledger, "B", "statistics", ConnectionRefusedError("gone"))

        with patch.object(
            CollectinfoController, "_get_as_data_json", AsyncMock()
        ) as as_mock:
            await self.controller._retry_timed_out_nodes(
                ledger,
                as_map={},
                meta_map={},
                histogram_map={},
                latency_map={},
                user_agents_map={},
            )

        as_mock.assert_not_called()

    async def test_retry_is_scoped_to_timed_out_nodes_and_merges(self):
        ledger = {}
        _record_node_error(ledger, "B", "statistics", asyncio.TimeoutError("late"))
        _record_node_error(ledger, "B", "config", asyncio.TimeoutError("late"))
        as_map = {"A": {"statistics": {"s": 1}, "config": {"c": 1}}}

        with patch.object(
            CollectinfoController,
            "_get_as_data_json",
            AsyncMock(return_value={"B": {"statistics": {"s": 2}, "config": {"c": 2}}}),
        ) as as_mock:
            await self.controller._retry_timed_out_nodes(
                ledger,
                as_map=as_map,
                meta_map={},
                histogram_map={},
                latency_map={},
                user_agents_map={},
            )

        as_mock.assert_awaited_once_with(nodes=["B"])
        self.assertEqual(as_map["B"], {"statistics": {"s": 2}, "config": {"c": 2}})
        self.assertEqual(as_map["A"], {"statistics": {"s": 1}, "config": {"c": 1}})
        self.assertTrue(
            ledger["B"][
                (
                    constants.CollectinfoSection.STATISTICS,
                    constants.CollectinfoErrorClass.TIMEOUT,
                )
            ]["recovered_on_retry"]
        )

    async def test_empty_retry_result_leaves_error_unrecovered(self):
        ledger = {}
        _record_node_error(ledger, "B", "latency", asyncio.TimeoutError("late"))
        latency_map = {}

        with patch.object(
            CollectinfoController, "_get_as_latency", AsyncMock(return_value={"B": {}})
        ):
            await self.controller._retry_timed_out_nodes(
                ledger,
                as_map={},
                meta_map={},
                histogram_map={},
                latency_map=latency_map,
                user_agents_map={},
            )

        self.assertEqual(latency_map, {})
        self.assertFalse(
            ledger["B"][
                (
                    constants.CollectinfoSection.LATENCY,
                    constants.CollectinfoErrorClass.TIMEOUT,
                )
            ]["recovered_on_retry"]
        )

    async def test_retry_keeps_metadata_the_first_pass_collected(self):
        """A node is retried when any one of its metadata calls timed out, and the
        retry re-queries all twelve. Overwriting the whole entry would drop the
        node_id and services the first pass already had (TOOLS-3596)."""
        ledger = {}
        _record_node_error(ledger, "B", "metadata", asyncio.TimeoutError("late"))
        meta_map = {
            "B": {
                "node_id": "BB1",
                "services": [["2.2.2.2", 3000, None]],
                "asd_build": "",
            }
        }

        with patch.object(
            CollectinfoController,
            "_get_as_metadata",
            AsyncMock(
                return_value={
                    "B": {"node_id": "", "services": "", "asd_build": "8.0.0.0"}
                }
            ),
        ):
            await self.controller._retry_timed_out_nodes(
                ledger,
                as_map={},
                meta_map=meta_map,
                histogram_map={},
                latency_map={},
                user_agents_map={},
            )

        self.assertEqual(meta_map["B"]["node_id"], "BB1")
        self.assertEqual(meta_map["B"]["services"], [["2.2.2.2", 3000, None]])
        self.assertEqual(meta_map["B"]["asd_build"], "8.0.0.0")

    async def test_retry_keeps_statistics_subsections_the_first_pass_collected(self):
        """statistics and config each hold eight independently collected subsections,
        so a retry that recovers one returns the others empty."""
        ledger = {}
        _record_node_error(ledger, "B", "statistics", asyncio.TimeoutError("late"))
        as_map = {
            "B": {
                "statistics": {
                    "service": {"uptime": "10"},
                    "namespace": {"test": {"objects": "5"}},
                },
                "config": {"service": {"proto-fd-max": "15000"}},
            }
        }

        with patch.object(
            CollectinfoController,
            "_get_as_data_json",
            AsyncMock(
                return_value={
                    "B": {
                        "statistics": {"service": {"uptime": "20"}, "namespace": {}},
                        "config": {},
                    }
                }
            ),
        ):
            await self.controller._retry_timed_out_nodes(
                ledger,
                as_map=as_map,
                meta_map={},
                histogram_map={},
                latency_map={},
                user_agents_map={},
            )

        self.assertEqual(
            as_map["B"]["statistics"]["namespace"], {"test": {"objects": "5"}}
        )
        self.assertEqual(as_map["B"]["statistics"]["service"], {"uptime": "20"})
        self.assertEqual(as_map["B"]["config"], {"service": {"proto-fd-max": "15000"}})

    async def test_retry_keeps_histograms_the_first_pass_collected(self):
        ledger = {}
        _record_node_error(ledger, "B", "histogram", asyncio.TimeoutError("late"))
        histogram_map = {"B": {"ttl": {"raw": "1"}}}

        with patch.object(
            CollectinfoController,
            "_get_as_histograms",
            AsyncMock(return_value={"B": {"objsz": {"raw": "2"}}}),
        ):
            await self.controller._retry_timed_out_nodes(
                ledger,
                as_map={},
                meta_map={},
                histogram_map=histogram_map,
                latency_map={},
                user_agents_map={},
            )

        self.assertEqual(
            histogram_map["B"], {"ttl": {"raw": "1"}, "objsz": {"raw": "2"}}
        )

    async def test_retry_replaces_whole_node_values(self):
        """latency is a whole-node value, not a dict of independently collected
        keys, so there is nothing to merge into."""
        ledger = {}
        _record_node_error(ledger, "B", "latency", asyncio.TimeoutError("late"))
        latency_map = {"B": []}

        with patch.object(
            CollectinfoController,
            "_get_as_latency",
            AsyncMock(return_value={"B": [{"read": 1}]}),
        ):
            await self.controller._retry_timed_out_nodes(
                ledger,
                as_map={},
                meta_map={},
                histogram_map={},
                latency_map=latency_map,
                user_agents_map={},
            )

        self.assertEqual(latency_map["B"], [{"read": 1}])

    async def test_retry_exception_is_swallowed(self):
        ledger = {}
        _record_node_error(ledger, "B", "metadata", asyncio.TimeoutError("late"))

        with patch.object(
            CollectinfoController,
            "_get_as_metadata",
            AsyncMock(side_effect=OSError("still down")),
        ):
            await self.controller._retry_timed_out_nodes(
                ledger,
                as_map={},
                meta_map={},
                histogram_map={},
                latency_map={},
                user_agents_map={},
            )

        self.assertFalse(
            ledger["B"][
                (
                    constants.CollectinfoSection.METADATA,
                    constants.CollectinfoErrorClass.TIMEOUT,
                )
            ]["recovered_on_retry"]
        )


class CollectinfoMetaTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.controller = CollectinfoController()
        self.controller.nodes = "all"
        self.controller.asadm_version = "9.9.9"
        self.controller.asadm_build = "deadbeef"
        self.controller.cluster = MagicMock()
        self.controller.cluster._timeout = 5
        self.controller.cluster.get_seed_nodes.return_value = [
            ("2.2.2.2", 3000, None),
            ("1.1.1.1", 3000, "tls-name"),
        ]

    def test_meta_shape_and_deterministic_seed_order(self):
        meta = self.controller._build_collectinfo_meta(
            [{"timestamp": "ts"}],
            start_ts="start",
            snp_count=2,
            wait_time=5,
            enable_ssh=True,
            requested_timeout=1,
            effective_timeout=5,
            output_prefix="pre",
            asconfig_file="/etc/aerospike/aerospike.conf",
            ignore_errors=False,
        )

        self.assertEqual(
            meta["meta_format_version"], constants.COLLECTINFO_META_FORMAT_VERSION
        )
        self.assertEqual(meta["bundle"]["asadm_version"], "9.9.9")
        self.assertEqual(meta["bundle"]["asadm_build"], "deadbeef")
        self.assertEqual(
            meta["bundle"]["ascinfo_schema"], constants.COLLECTINFO_ASCINFO_SCHEMA
        )
        self.assertEqual(
            [seed["addr"] for seed in meta["collection"]["seeds"]],
            ["1.1.1.1", "2.2.2.2"],
        )
        self.assertEqual(meta["collection"]["flags"]["enable_ssh"], True)
        self.assertEqual(meta["collection"]["flags"]["node_selection"], "all")
        self.assertEqual(meta["collection"]["flags"]["effective_node_timeout_sec"], 5)
        self.assertEqual(meta["collection"]["flags"]["requested_node_timeout_sec"], 1)
        self.assertEqual(meta["collection"]["snapshot_count"], 2)
        self.assertEqual(meta["snapshots"], [{"timestamp": "ts"}])

    def test_node_selection_records_a_subset_collection(self):
        """`collectinfo with <nodes>` is a supported partial collection. Without this
        the excluded nodes look like nodes asadm failed to reach."""
        self.controller.nodes = ["2.2.2.2:3000", "1.1.1.1:3000"]

        meta = self.controller._build_collectinfo_meta(
            [{"timestamp": "ts"}],
            start_ts="start",
            snp_count=1,
            wait_time=0,
            enable_ssh=False,
            requested_timeout=1,
            effective_timeout=5,
            output_prefix="",
            asconfig_file="",
            ignore_errors=False,
        )

        self.assertEqual(
            meta["collection"]["flags"]["node_selection"],
            ["1.1.1.1:3000", "2.2.2.2:3000"],
        )

    def test_effective_timeout_comes_from_the_caller_not_cluster_state(self):
        """The value is the raised collectinfo timeout, which the caller knows; it
        must not depend on when the timeout happens to be restored."""
        self.controller.cluster._timeout = 99

        meta = self.controller._build_collectinfo_meta(
            [{"timestamp": "ts"}],
            start_ts="start",
            snp_count=1,
            wait_time=0,
            enable_ssh=False,
            requested_timeout=1,
            effective_timeout=5,
            output_prefix="",
            asconfig_file="",
            ignore_errors=False,
        )

        self.assertEqual(meta["collection"]["flags"]["effective_node_timeout_sec"], 5)

    def test_meta_is_json_serializable(self):
        ledger = {}
        _record_node_error(ledger, "A", "statistics", asyncio.TimeoutError("late"))
        snapshot_meta = {
            "timestamp": "ts",
            "nodes": {"A": {"errors": _node_error_entries(ledger, "A")}},
        }

        meta = self.controller._build_collectinfo_meta(
            [snapshot_meta],
            start_ts="start",
            snp_count=1,
            wait_time=0,
            enable_ssh=False,
            requested_timeout=1,
            effective_timeout=5,
            output_prefix="",
            asconfig_file="",
            ignore_errors=False,
        )

        json.dumps(meta)

    def test_meta_write_failure_does_not_raise(self):
        with patch.object(
            CollectinfoController,
            "_build_collectinfo_meta",
            side_effect=ValueError("boom"),
        ):
            with self.assertLogs(LOGGER_NAME, level="WARNING") as cm:
                self.controller._dump_collectinfo_meta(
                    "/tmp/does-not-matter_",
                    [],
                    start_ts="start",
                    snp_count=1,
                    wait_time=0,
                    enable_ssh=False,
                    requested_timeout=1,
                    effective_timeout=5,
                    output_prefix="",
                    asconfig_file="",
                    ignore_errors=False,
                )

        self.assertTrue(
            any(constants.COLLECTINFO_META_FILENAME in msg for msg in cm.output),
            cm.output,
        )

    async def test_ascinfo_is_written_even_when_meta_fails(self):
        """A meta bug must never cost the user their ascinfo.json."""
        writes = []

        patch.object(
            CollectinfoController,
            "_get_collectinfo_data_json",
            AsyncMock(return_value=({"cluster": {}}, {"expected_nodes": []})),
        ).start()
        patch.object(
            CollectinfoController,
            "_build_collectinfo_meta",
            side_effect=ValueError("boom"),
        ).start()
        patch.object(
            CollectinfoController,
            "_dump_in_json_file",
            side_effect=lambda name, dump: writes.append(name),
        ).start()
        self.addCleanup(patch.stopall)

        await self.controller._dump_collectinfo_json(
            "/tmp/prefix_",
            False,
            None,
            None,
            None,
            None,
            None,
            1,
            0,
        )

        self.assertEqual(writes, ["/tmp/prefix_ascinfo.json"])


if __name__ == "__main__":
    unittest.main()
