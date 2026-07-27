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

import copy
import logging
import time
import unittest
from unittest.mock import MagicMock

from lib.collectinfo_analyzer.collectinfo_handler.collectinfo_diagnostics import (
    BundleWarning,
    CollectinfoDiagnostics,
    DiagSeverity,
    emit_to_log,
    render_banner,
)
from lib.collectinfo_analyzer.collectinfo_handler.collectinfo_log import (
    _CollectinfoSnapshot,
)

TS = "2026-07-20 10:00:00 UTC"

HEALTHY_NODE = {
    "as_stat": {
        "statistics": {
            "service": {
                "cluster_size": "1",
                "cluster_integrity": "true",
                "cluster_is_member": "true",
                "cluster_key": "KEY1",
                "cluster_principal": "BB1",
            },
            "namespace": {},
        },
        "config": {"service": {"proto-fd-max": "15000"}, "namespace": {}},
        "meta_data": {
            "node_id": "BB1",
            "asd_build": "8.0.0.0",
            "edition": "Aerospike Enterprise Edition",
            "ip": "1.1.1.1:3000",
            "node_names": "host1",
        },
    },
    "sys_stat": {"uname": {"nodename": "host1"}},
}


def make_snapshot(nodes, cluster_name="prod", timestamp=TS):
    return _CollectinfoSnapshot(
        cluster_name, timestamp, copy.deepcopy(nodes), "ascinfo.json"
    )


def make_log_handler(
    scanned_version="", bundle_files=("sysinfo.log",), snapshot_count=1
):
    handler = MagicMock()
    handler.collector_asadm_version.return_value = scanned_version
    handler._scan_bundle_for_asadm_version.return_value = scanned_version
    handler.bundle_snapshot_count = snapshot_count
    handler._iter_bundle_files.side_effect = lambda suffixes: [
        file for file in bundle_files if file.endswith(tuple(suffixes))
    ]
    return handler


def diagnostics(nodes=None, meta=None, running_version="5.0.2", **handler_kwargs):
    nodes = {"1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE)} if nodes is None else nodes
    return CollectinfoDiagnostics(
        log_handler=make_log_handler(**handler_kwargs),
        snapshot=make_snapshot(nodes),
        timestamp=TS,
        running_version=running_version,
        meta=meta,
    )


def categories(warnings):
    return [warning.category for warning in warnings]


def find(warnings, category):
    for warning in warnings:
        if warning.category == category:
            return warning
    return None


def meta_with(discrepancies=None, nodes=None, asadm_version="5.0.2"):
    return {
        "meta_format_version": 1,
        "bundle": {"asadm_version": asadm_version, "asadm_build": "abc"},
        "collection": {"flags": {"enable_ssh": False}},
        "snapshots": [
            {
                "timestamp": TS,
                "cluster_name": "prod",
                "expected_nodes": ["1.1.1.1:3000"],
                "responded_nodes": ["1.1.1.1:3000"],
                "no_data_nodes": [],
                "nodes": nodes or {},
                "discrepancies": discrepancies
                or {
                    "missing_from_collection": [],
                    "dropped_during_collection": [],
                    "cluster_down_nodes": [],
                    "visibility_error_nodes": [],
                },
            }
        ],
    }


class CollectorVersionTest(unittest.TestCase):
    def test_meta_version_is_preferred_over_log_scan(self):
        diag = diagnostics(meta=meta_with(asadm_version="4.1.0"), scanned_version="1.0")

        warning = find(diag.analyze(), "collector-version-older")

        self.assertIsNotNone(warning)
        self.assertIn("4.1.0", warning.title)
        self.assertIn("5.0.2", warning.title)

    def test_log_scan_fallback_when_no_meta(self):
        diag = diagnostics(scanned_version="2.9.0")

        warning = find(diag.analyze(), "collector-version-older")

        self.assertIsNotNone(warning)
        self.assertIn("2.9.0", warning.title)

    def test_newer_collector(self):
        diag = diagnostics(meta=meta_with(asadm_version="6.0.0"))

        warning = find(diag.analyze(), "collector-version-newer")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.WARNING)

    def test_matching_version_is_info(self):
        diag = diagnostics(meta=meta_with(asadm_version="5.0.2"))

        warning = find(diag.analyze(), "collector-version-match")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)

    def test_unknown_version_warns(self):
        """No version anywhere usually means a much older asadm, so it is a warning
        rather than a neutral 'unknown'."""
        diag = diagnostics()

        warning = find(diag.analyze(), "collector-version-unknown")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.WARNING)
        self.assertIn("much older asadm", " ".join(warning.lines))

    def test_version_is_stated_plainly_when_it_matches(self):
        diag = diagnostics(meta=meta_with(asadm_version="5.0.2"))

        warning = find(diag.analyze(), "collector-version-match")

        self.assertEqual(warning.title, "Collected by asadm 5.0.2")
        self.assertEqual(warning.lines, [])

    def test_development_version_is_not_compared(self):
        diag = diagnostics(
            meta=meta_with(asadm_version="2.1.0"), running_version="development"
        )

        warning = find(diag.analyze(), "collector-version-unparsed")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)


class DroppedAndMissingNodesTest(unittest.TestCase):
    def test_meta_discrepancies_are_authoritative(self):
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [
                    {"node_key": "9.9.9.9:3000", "reason": "seen in peers of A"}
                ],
                "dropped_during_collection": [
                    {"node_key": "3.3.3.3:3000", "reason": "timed out"}
                ],
                "cluster_down_nodes": ["9.9.9.9:3000"],
                "visibility_error_nodes": ["1.1.1.1:3000"],
            }
        )

        warning = find(diagnostics(meta=meta).analyze(), "dropped-or-missing-nodes")

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("3.3.3.3:3000", body)
        self.assertIn("9.9.9.9:3000", body)
        self.assertNotIn("inferred", body)

    def test_no_warning_when_meta_reports_clean_collection(self):
        warnings = diagnostics(meta=meta_with()).analyze()

        self.assertIsNone(find(warnings, "dropped-or-missing-nodes"))

    def test_detection_error_is_surfaced(self):
        meta = meta_with(discrepancies={"detection_error": "no route to host"})

        warning = find(
            diagnostics(meta=meta).analyze(), "node-discrepancy-detection-failed"
        )

        self.assertIsNotNone(warning)
        self.assertIn("no route to host", " ".join(warning.lines))

    def test_old_bundle_cluster_size_heuristic(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["statistics"]["service"]["cluster_size"] = "3"

        warning = find(
            diagnostics(nodes={"1.1.1.1:3000": node}).analyze(),
            "dropped-or-missing-nodes",
        )

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("cluster_size of 3", body)
        self.assertIn("may be missing 2 nodes", body)
        self.assertIn("inferred", body)

    def test_old_bundle_peer_heuristic_uses_triples(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["services"] = [
            ["1.1.1.1", 3000, None],
            ["2.2.2.2", 3000, None],
        ]

        warning = find(
            diagnostics(nodes={"1.1.1.1:3000": node}).analyze(),
            "dropped-or-missing-nodes",
        )

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("2.2.2.2:3000", body)
        self.assertNotIn("1.1.1.1:3000", body)

    def test_old_bundle_integrity_heuristic(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["statistics"]["service"]["cluster_integrity"] = "false"

        warning = find(
            diagnostics(nodes={"1.1.1.1:3000": node}).analyze(),
            "dropped-or-missing-nodes",
        )

        self.assertIsNotNone(warning)
        self.assertIn("cluster_integrity was false", " ".join(warning.lines))


class SysinfoCoverageTest(unittest.TestCase):
    def _nodes(self, with_sysinfo, without_sysinfo):
        nodes = {}

        for index in range(with_sysinfo + without_sysinfo):
            node = copy.deepcopy(HEALTHY_NODE)
            node["as_stat"]["meta_data"]["node_id"] = "BB%d" % (index,)

            if index >= with_sysinfo:
                del node["sys_stat"]

            nodes["10.0.0.%d:3000" % (index,)] = node

        return nodes

    def test_silent_when_every_node_has_sysinfo(self):
        warnings = diagnostics(meta=meta_with()).analyze()

        self.assertIsNone(find(warnings, "missing-sysinfo"))
        self.assertIsNone(find(warnings, "partial-sysinfo"))

    def test_no_node_has_sysinfo_is_a_warning(self):
        """The ticket's case: collected from a host outside the cluster, so nothing
        host-level was captured at all."""
        warning = find(
            diagnostics(
                nodes=self._nodes(with_sysinfo=0, without_sysinfo=3), meta=meta_with()
            ).analyze(),
            "missing-sysinfo",
        )

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.WARNING)
        body = " ".join(warning.lines)
        self.assertIn("any of the 3 nodes", body)
        self.assertIn("--enable-ssh", body)

    def test_one_node_of_many_is_the_ordinary_local_collect(self):
        """A plain collect covers exactly the node asadm ran on, so this is
        information rather than a fault."""
        warning = find(
            diagnostics(
                nodes=self._nodes(with_sysinfo=1, without_sysinfo=26), meta=meta_with()
            ).analyze(),
            "partial-sysinfo",
        )

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)
        self.assertEqual(warning.title, "System information covers 1 of 27 nodes")
        body = " ".join(warning.lines)
        self.assertIn("10.0.0.0:3000", body)
        self.assertIn("The other 26 nodes have no host-level data", body)
        self.assertIn("--enable-ssh", body)

    def test_partial_coverage_is_not_reported_as_missing(self):
        warnings = diagnostics(
            nodes=self._nodes(with_sysinfo=1, without_sysinfo=2), meta=meta_with()
        ).analyze()

        self.assertIsNone(find(warnings, "missing-sysinfo"))

    def test_no_bundle_sysinfo_files(self):
        warning = find(
            diagnostics(
                nodes=self._nodes(with_sysinfo=0, without_sysinfo=1),
                meta=meta_with(),
                bundle_files=(),
            ).analyze(),
            "missing-sysinfo",
        )

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("no sysinfo.log", body)
        self.assertIn("only ever collected when asadm runs on a cluster node", body)

    def test_aerospike_conf_alone_counts_as_local_collection(self):
        warnings = diagnostics(
            meta=meta_with(), bundle_files=("aerospike.conf",)
        ).analyze()

        self.assertIsNone(find(warnings, "missing-sysinfo"))
        self.assertIsNone(find(warnings, "partial-sysinfo"))


class NodeCollectionErrorsTest(unittest.TestCase):
    def test_unrecovered_errors_produce_a_table(self):
        meta = meta_with(
            nodes={
                "1.1.1.1:3000": {
                    "node_id": "BB1",
                    "responded": True,
                    "sysinfo_source": "local",
                    "errors": [
                        {
                            "section": "latency",
                            "error_class": "timeout",
                            "message": "late",
                            "recovered_on_retry": False,
                        }
                    ],
                }
            }
        )

        warning = find(diagnostics(meta=meta).analyze(), "node-collection-errors")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.WARNING)
        self.assertIsNotNone(warning.table)
        self.assertIn("latency", warning.table)
        self.assertIn("1.1.1.1:3000", warning.table)

    def test_fully_recovered_errors_are_info_only(self):
        meta = meta_with(
            nodes={
                "1.1.1.1:3000": {
                    "errors": [
                        {
                            "section": "latency",
                            "error_class": "timeout",
                            "message": "late",
                            "recovered_on_retry": True,
                        }
                    ]
                }
            }
        )

        warning = find(diagnostics(meta=meta).analyze(), "node-collection-errors")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)
        self.assertIsNone(warning.table)

    def test_no_meta_means_no_error_check(self):
        warnings = diagnostics().analyze()

        self.assertIsNone(find(warnings, "node-collection-errors"))


class ZeroAndPartialNodesTest(unittest.TestCase):
    def test_zero_nodes_short_circuits(self):
        diag = diagnostics(nodes={})

        warnings = diag.analyze()

        self.assertEqual(
            categories(warnings), ["collector-version-unknown", "no-usable-nodes"]
        )

    def test_all_nodes_empty_short_circuits(self):
        diag = diagnostics(
            nodes={"1.1.1.1:3000": {"as_stat": {}}, "2.2.2.2:3000": {"as_stat": {}}},
            meta=meta_with(),
        )

        warnings = diag.analyze()

        self.assertEqual(categories(warnings)[-1], "no-usable-nodes")
        self.assertIsNone(find(warnings, "partial-nodes"))

    def test_partial_node_is_reported(self):
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": {
                "as_stat": {"meta_data": {"node_id": "BB2", "asd_build": "8.0.0.0"}}
            },
        }

        warning = find(
            diagnostics(nodes=nodes, meta=meta_with()).analyze(), "partial-nodes"
        )

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("Missing statistics: 2.2.2.2:3000", body)
        self.assertIn("Missing config: 2.2.2.2:3000", body)


class BundleShapeTest(unittest.TestCase):
    def test_multiple_snapshots_is_reported(self):
        warning = find(
            diagnostics(meta=meta_with(), snapshot_count=3).analyze(),
            "multiple-snapshots",
        )

        self.assertIsNotNone(warning)
        self.assertIn("3 snapshots", warning.title)

    def test_single_snapshot_is_silent(self):
        warnings = diagnostics(meta=meta_with()).analyze()

        self.assertIsNone(find(warnings, "multiple-snapshots"))

    def test_stale_bundle_is_reported(self):
        old_ts = time.strftime(
            "%Y-%m-%d %H:%M:%S UTC", time.gmtime(time.time() - 30 * 86400)
        )
        diag = CollectinfoDiagnostics(
            log_handler=make_log_handler(),
            snapshot=make_snapshot(
                {"1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE)}, timestamp=old_ts
            ),
            timestamp=old_ts,
            running_version="5.0.2",
            meta=None,
        )

        warning = find(diag.analyze(), "stale-bundle")

        self.assertIsNotNone(warning)
        self.assertIn("30 days old", warning.title)

    def test_fresh_bundle_is_silent(self):
        fresh_ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        diag = CollectinfoDiagnostics(
            log_handler=make_log_handler(),
            snapshot=make_snapshot(
                {"1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE)}, timestamp=fresh_ts
            ),
            timestamp=fresh_ts,
            running_version="5.0.2",
        )

        self.assertIsNone(find(diag.analyze(), "stale-bundle"))

    def test_unparseable_timestamp_is_silent(self):
        diag = diagnostics()
        diag.timestamp = "not a timestamp"

        self.assertIsNone(find(diag.analyze(), "stale-bundle"))


class CuratedAnomalyTest(unittest.TestCase):
    def _with_service_stats(self, **stats):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["statistics"]["service"].update(stats)
        return {"1.1.1.1:3000": node}

    def _with_ns_stats(self, **stats):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["statistics"]["namespace"] = {
            "test": {"service": stats, "set": {}, "bin": {}, "sindex": {}}
        }
        return {"1.1.1.1:3000": node}

    def test_stop_writes_flag(self):
        nodes = self._with_ns_stats(stop_writes="true")

        warning = find(diagnostics(nodes=nodes).analyze(), "stop-writes")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.ERROR)
        self.assertIn("show stop-writes", " ".join(warning.lines))

    def test_clock_skew_stop_writes_flag(self):
        nodes = self._with_ns_stats(clock_skew_stop_writes="true")

        self.assertIsNotNone(find(diagnostics(nodes=nodes).analyze(), "stop-writes"))

    def test_no_stop_writes_is_silent(self):
        self.assertIsNone(find(diagnostics().analyze(), "stop-writes"))

    def test_orphan_node_and_split_cluster(self):
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": copy.deepcopy(HEALTHY_NODE),
        }
        nodes["2.2.2.2:3000"]["as_stat"]["statistics"]["service"].update(
            {
                "cluster_is_member": "false",
                "cluster_key": "KEY2",
                "cluster_principal": "BB2",
                "cluster_size": "2",
            }
        )
        nodes["2.2.2.2:3000"]["as_stat"]["meta_data"]["node_id"] = "BB2"

        warning = find(diagnostics(nodes=nodes).analyze(), "cluster-state")

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("orphan", body)
        self.assertIn("distinct cluster keys", body)
        self.assertIn("distinct cluster principals", body)
        self.assertIn("disagree on cluster_size", body)

    def test_healthy_cluster_state_is_silent(self):
        self.assertIsNone(find(diagnostics().analyze(), "cluster-state"))

    def test_migrations(self):
        nodes = self._with_ns_stats(migrate_partitions_remaining="42")

        warning = find(diagnostics(nodes=nodes).analyze(), "migrations")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)
        self.assertIn("42", warning.title)

    def test_zero_migrations_is_silent(self):
        nodes = self._with_ns_stats(migrate_partitions_remaining="0")

        self.assertIsNone(find(diagnostics(nodes=nodes).analyze(), "migrations"))

    def test_mixed_builds_and_editions(self):
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": copy.deepcopy(HEALTHY_NODE),
        }
        nodes["2.2.2.2:3000"]["as_stat"]["meta_data"].update(
            {
                "node_id": "BB2",
                "asd_build": "7.2.0.0",
                "edition": "Aerospike Community Edition",
            }
        )

        warning = find(diagnostics(nodes=nodes).analyze(), "mixed-server-versions")

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("7.2.0.0", body)
        self.assertIn("8.0.0.0", body)
        self.assertIn("editions", body)

    def test_uniform_build_is_silent(self):
        self.assertIsNone(find(diagnostics().analyze(), "mixed-server-versions"))

    def test_best_practices_from_meta_data(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["best_practices"] = ["min-avail-pct"]

        warning = find(
            diagnostics(nodes={"1.1.1.1:3000": node}).analyze(), "best-practices"
        )

        self.assertIsNotNone(warning)
        self.assertIn("show best-practices", " ".join(warning.lines))

    def test_best_practices_fallback_to_service_stat(self):
        nodes = self._with_service_stats(failed_best_practices="true")

        self.assertIsNotNone(find(diagnostics(nodes=nodes).analyze(), "best-practices"))

    def test_empty_best_practices_list_is_silent(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["best_practices"] = []

        self.assertIsNone(
            find(diagnostics(nodes={"1.1.1.1:3000": node}).analyze(), "best-practices")
        )

    def test_health_outliers(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["health"] = {"outlier": "device_write_q"}

        warning = find(
            diagnostics(nodes={"1.1.1.1:3000": node}).analyze(), "health-outliers"
        )

        self.assertIsNotNone(warning)
        self.assertIn("health -v", " ".join(warning.lines))

    def test_dead_and_unavailable_partitions(self):
        nodes = self._with_ns_stats(dead_partitions="4", unavailable_partitions="2")

        warning = find(diagnostics(nodes=nodes).analyze(), "partition-availability")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.ERROR)
        body = " ".join(warning.lines)
        self.assertIn("dead_partitions", body)
        self.assertIn("unavailable_partitions", body)

    def test_zero_partitions_is_silent(self):
        nodes = self._with_ns_stats(dead_partitions="0", unavailable_partitions="0")

        self.assertIsNone(
            find(diagnostics(nodes=nodes).analyze(), "partition-availability")
        )

    def test_clock_skew(self):
        nodes = self._with_service_stats(cluster_clock_skew_ms="4000")

        warning = find(diagnostics(nodes=nodes).analyze(), "clock-skew")

        self.assertIsNotNone(warning)
        self.assertIn("4000 ms", warning.title)

    def test_small_clock_skew_is_silent(self):
        nodes = self._with_service_stats(cluster_clock_skew_ms="12")

        self.assertIsNone(find(diagnostics(nodes=nodes).analyze(), "clock-skew"))


class CheckIsolationTest(unittest.TestCase):
    def test_one_failing_check_does_not_break_the_rest(self):
        diag = diagnostics(meta=meta_with(asadm_version="4.0.0"))
        diag._check_cluster_state = MagicMock(side_effect=ValueError("boom"))

        warnings = diag.analyze()

        self.assertIsNotNone(find(warnings, "collector-version-older"))

    def test_snapshot_raising_on_every_accessor_is_survivable(self):
        broken = MagicMock()
        broken.get_data.side_effect = ValueError("boom")
        broken.get_node_names.side_effect = ValueError("boom")
        broken.nodes_without_as_stat.side_effect = ValueError("boom")

        diag = CollectinfoDiagnostics(
            log_handler=make_log_handler(),
            snapshot=broken,
            timestamp=TS,
            running_version="5.0.2",
        )

        warnings = diag.analyze()

        self.assertEqual(
            categories(warnings), ["collector-version-unknown", "no-usable-nodes"]
        )


class RenderTest(unittest.TestCase):
    def test_empty_warnings_render_to_empty_string(self):
        self.assertEqual(render_banner([]), "")

    def test_banner_contains_title_lines_and_table(self):
        warnings = [
            BundleWarning(
                category="c",
                severity=DiagSeverity.WARNING,
                title="A title",
                lines=["a detail"],
                table="a table",
            )
        ]

        banner = render_banner(warnings, use_color=False)

        self.assertIn("Collectinfo Bundle Diagnostics", banner)
        self.assertIn("WARNING: A title", banner)
        self.assertIn("a detail", banner)
        self.assertIn("a table", banner)

    def test_emit_to_log_maps_severity_to_level(self):
        warnings = [
            BundleWarning("a", DiagSeverity.ERROR, "err", ["detail"]),
            BundleWarning("b", DiagSeverity.WARNING, "warn"),
            BundleWarning("c", DiagSeverity.INFO, "info"),
        ]
        log = MagicMock(spec=logging.Logger)

        emit_to_log(warnings, log)

        log.error.assert_called_once_with("err detail")
        log.warning.assert_called_once_with("warn")
        log.info.assert_called_once_with("info")

    def test_emit_to_log_with_no_warnings_is_silent(self):
        log = MagicMock(spec=logging.Logger)

        emit_to_log([], log)

        log.warning.assert_not_called()

    def test_severity_colors(self):
        """The color constants are read off the submodule: the package re-exports
        them by value at import time, so the package-level copies stay empty."""
        from lib.view.terminal import terminal as terminal_module

        was_enabled = terminal_module.color_enabled
        terminal_module.enable_color(True)
        self.addCleanup(terminal_module.enable_color, was_enabled)

        banner = render_banner(
            [
                BundleWarning("a", DiagSeverity.INFO, "an info"),
                BundleWarning("b", DiagSeverity.WARNING, "a warning"),
                BundleWarning("c", DiagSeverity.ERROR, "an error"),
            ]
        )

        self.assertIn("\x1b[%sm%s" % (terminal_module.fgblue, "INFO: an info"), banner)
        self.assertIn(
            "\x1b[%sm%s" % (terminal_module.fgyellow, "WARNING: a warning"), banner
        )
        self.assertIn("\x1b[%sm%s" % (terminal_module.fgred, "ERROR: an error"), banner)

    def test_banner_omits_the_version_line_the_intro_already_prints(self):
        warnings = [
            BundleWarning(
                category="collector-version-match",
                severity=DiagSeverity.INFO,
                title="Collected by asadm 5.0.2",
            )
        ]

        self.assertEqual(render_banner(warnings, use_color=False), "")

    def test_banner_keeps_an_actionable_version_warning(self):
        warnings = [
            BundleWarning(
                category="collector-version-older",
                severity=DiagSeverity.WARNING,
                title="Collected by asadm 1.0.0, older than this asadm 5.0.2",
            )
        ]

        self.assertIn("older than this asadm", render_banner(warnings, use_color=False))

    def test_emit_to_log_keeps_the_version_line(self):
        """Execute mode has no intro, so the log path must still carry provenance."""
        warnings = [
            BundleWarning(
                category="collector-version-match",
                severity=DiagSeverity.INFO,
                title="Collected by asadm 5.0.2",
            )
        ]
        log = MagicMock(spec=logging.Logger)

        emit_to_log(warnings, log)

        log.info.assert_called_once_with("Collected by asadm 5.0.2")


class SnapshotHelperTest(unittest.TestCase):
    def test_has_sys_data(self):
        node_without = copy.deepcopy(HEALTHY_NODE)
        del node_without["sys_stat"]
        node_empty = copy.deepcopy(HEALTHY_NODE)
        node_empty["sys_stat"] = {}

        snapshot = make_snapshot(
            {
                "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
                "2.2.2.2:3000": node_without,
                "3.3.3.3:3000": node_empty,
            }
        )

        self.assertTrue(snapshot.has_sys_data("1.1.1.1:3000"))
        self.assertFalse(snapshot.has_sys_data("2.2.2.2:3000"))
        self.assertFalse(snapshot.has_sys_data("3.3.3.3:3000"))
        self.assertFalse(snapshot.has_sys_data("nope:3000"))

    def test_nodes_without_as_stat_ignores_locally_derived_meta(self):
        degraded = {
            "as_stat": {
                "statistics": {},
                "config": {},
                "meta_data": {
                    "node_id": "",
                    "asd_build": "",
                    "node_names": "host2",
                    "ip": "2.2.2.2:3000",
                },
            }
        }
        snapshot = make_snapshot(
            {
                "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
                "2.2.2.2:3000": degraded,
            }
        )

        self.assertEqual(snapshot.nodes_without_as_stat(), ["2.2.2.2:3000"])

    def test_advertised_peers_from_triples(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["services"] = [
            ["2.2.2.2", 3000, None],
            ["fe80::1", 3000, "tls"],
        ]
        snapshot = make_snapshot({"1.1.1.1:3000": node})

        self.assertEqual(
            snapshot.get_advertised_peers(),
            {"1.1.1.1:3000": ["2.2.2.2:3000", "[fe80::1]:3000"]},
        )

    def test_advertised_peers_from_legacy_string(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["services"] = "2.2.2.2:3000;3.3.3.3:3000"
        snapshot = make_snapshot({"1.1.1.1:3000": node})

        self.assertEqual(
            snapshot.get_advertised_peers(),
            {"1.1.1.1:3000": ["2.2.2.2:3000", "3.3.3.3:3000"]},
        )

    def test_scrubbed_services_yields_no_peers(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["services"] = ""
        snapshot = make_snapshot({"1.1.1.1:3000": node})

        self.assertEqual(snapshot.get_advertised_peers(), {})

    def test_own_endpoints(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["endpoints"] = [["1.1.1.1", 3000, None]]
        snapshot = make_snapshot({"1.1.1.1:3000": node})

        self.assertEqual(
            snapshot.get_own_endpoints(), {"1.1.1.1:3000": ["1.1.1.1:3000"]}
        )


if __name__ == "__main__":
    unittest.main()
