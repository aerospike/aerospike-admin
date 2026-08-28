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
import io
import time
import unittest
from unittest.mock import MagicMock

from lib.collectinfo_analyzer.collectinfo_handler.collectinfo_diagnostics import (
    BundleWarning,
    CollectinfoDiagnostics,
    DiagSeverity,
    print_banner,
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


class FakeLogHandler:
    """Explicit double carrying exactly the members the diagnostics use.

    A MagicMock answers every attribute, so a renamed handler method would keep
    every test green while the production lookup silently broke.
    """

    def __init__(
        self, scanned_version="", bundle_files=("sysinfo.log",), snapshot_count=1
    ):
        self._scanned_version = scanned_version
        self._bundle_files = tuple(bundle_files)
        self.bundle_snapshot_count = snapshot_count

    def collector_asadm_version(self):
        return self._scanned_version

    def bundle_files(self, suffixes):
        return [file for file in self._bundle_files if file.endswith(tuple(suffixes))]


def make_log_handler(
    scanned_version="", bundle_files=("sysinfo.log",), snapshot_count=1
):
    return FakeLogHandler(
        scanned_version=scanned_version,
        bundle_files=bundle_files,
        snapshot_count=snapshot_count,
    )


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


def meta_with(
    discrepancies=None, nodes=None, asadm_version="5.0.2", no_data_nodes=None
):
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
                "no_data_nodes": no_data_nodes or [],
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

    def test_a_version_with_a_non_numeric_tail_is_still_compared(self):
        """LooseVersion raises TypeError ordering '2.a' against '5.0.2', which used
        to lose the finding entirely. Only the numeric segments are compared."""
        diag = diagnostics(meta=meta_with(asadm_version="2.a"))

        warning = find(diag.analyze(), "collector-version-older")

        self.assertIsNotNone(warning)
        self.assertEqual(
            warning.title, "Collected by asadm 2.a, older than this asadm 5.0.2"
        )

    def test_a_version_with_no_numbers_at_all_is_stated_plainly(self):
        diag = diagnostics(meta=meta_with(asadm_version="unknown-build"))

        warning = find(diag.analyze(), "collector-version-unparsed")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.title, "Collected by asadm unknown-build")

    def test_a_release_candidate_matches_its_release(self):
        """An RC collects the same sections as its release, and advising an upgrade
        to a pre-release build is worse than saying nothing."""
        diag = diagnostics(
            meta=meta_with(asadm_version="5.0.2-rc1"), running_version="5.0.2"
        )

        warnings = diag.analyze()

        self.assertIsNone(find(warnings, "collector-version-newer"))
        self.assertIsNone(find(warnings, "collector-version-older"))
        warning = find(warnings, "collector-version-match")
        self.assertIsNotNone(warning)
        self.assertEqual(warning.title, "Collected by asadm 5.0.2-rc1")

    def test_a_newer_release_candidate_is_still_newer(self):
        diag = diagnostics(
            meta=meta_with(asadm_version="6.0.0-rc1"), running_version="5.0.2"
        )

        self.assertIsNotNone(find(diag.analyze(), "collector-version-newer"))


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

    def test_detection_error_still_reports_no_data_nodes(self):
        """no_data_nodes is written before reconciliation runs, so it survives a
        detection failure and the dropped node does not vanish from diagnostics."""
        meta = meta_with(
            discrepancies={"detection_error": "no route to host"},
            no_data_nodes=["2.2.2.2:3000"],
        )

        warning = find(
            diagnostics(meta=meta).analyze(), "node-discrepancy-detection-failed"
        )

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("2.2.2.2:3000", body)
        self.assertIn("returned no data", body)

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

    def test_broken_integrity_is_reported_once_by_cluster_state(self):
        """cluster_integrity belongs to the cluster-state finding; reporting it in the
        missing-node heuristic too would state the same fact twice in one banner."""
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["statistics"]["service"]["cluster_integrity"] = "false"

        warnings = diagnostics(nodes={"1.1.1.1:3000": node}).analyze()

        cluster_state = find(warnings, "cluster-state")
        self.assertIsNotNone(cluster_state)
        self.assertIn("cluster_integrity is false", " ".join(cluster_state.lines))

        missing = find(warnings, "dropped-or-missing-nodes")
        if missing is not None:
            self.assertNotIn("cluster_integrity", " ".join(missing.lines))

    def test_peer_visibility_is_separate_from_missing_nodes(self):
        """Down and visibility-error nodes were collected fine; it is the cluster's
        view of them that is broken, so they are not 'missing from the bundle'."""
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [],
                "dropped_during_collection": [],
                "cluster_down_nodes": ["9.9.9.9:3000"],
                "visibility_error_nodes": ["1.1.1.1:3000"],
            }
        )

        warnings = diagnostics(meta=meta).analyze()

        self.assertIsNone(find(warnings, "dropped-or-missing-nodes"))
        visibility = find(warnings, "peer-visibility")
        self.assertIsNotNone(visibility)
        body = " ".join(visibility.lines)
        self.assertIn("9.9.9.9:3000", body)
        self.assertIn("1.1.1.1:3000", body)

    def test_peer_visibility_needs_meta(self):
        """Not derivable from a bundle, so old bundles get no claim either way."""
        self.assertIsNone(find(diagnostics().analyze(), "peer-visibility"))

    def test_alternate_addresses_of_collected_nodes_are_not_unseen_peers(self):
        """A multi-homed cluster advertises peers on its heartbeat addresses, which
        are not the addresses asadm connected to."""
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["endpoints"] = [["10.0.0.1", 3000, None]]
        node["as_stat"]["meta_data"]["services"] = [["10.0.0.1", 3000, None]]

        warning = find(
            diagnostics(nodes={"1.1.1.1:3000": node}).analyze(),
            "dropped-or-missing-nodes",
        )

        self.assertIsNone(warning)

    def test_a_subset_collection_is_not_reported_as_missing_nodes(self):
        """`collectinfo with <nodes>` leaves the rest of the cluster advertised in the
        collected nodes' peer lists; that is the user's choice, not a defect."""
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [
                    {"node_key": "9.9.9.9:3000", "reason": "seen in peers of A"}
                ],
                "dropped_during_collection": [],
                "cluster_down_nodes": [],
                "visibility_error_nodes": [],
            }
        )
        meta["collection"]["flags"]["node_selection"] = ["1.1.1.1:3000"]

        warnings = diagnostics(meta=meta).analyze()

        self.assertIsNone(find(warnings, "dropped-or-missing-nodes"))
        selection = find(warnings, "partial-node-selection")
        self.assertIsNotNone(selection)
        self.assertEqual(selection.severity, DiagSeverity.INFO)
        self.assertIn("9.9.9.9:3000", " ".join(selection.lines))

    def test_a_subset_collection_still_reports_nodes_that_returned_nothing(self):
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [
                    {"node_key": "9.9.9.9:3000", "reason": "seen in peers of A"}
                ],
                "dropped_during_collection": [
                    {"node_key": "3.3.3.3:3000", "reason": "timed out"}
                ],
                "cluster_down_nodes": [],
                "visibility_error_nodes": [],
            }
        )
        meta["collection"]["flags"]["node_selection"] = ["1.1.1.1:3000", "3.3.3.3:3000"]

        warning = find(diagnostics(meta=meta).analyze(), "dropped-or-missing-nodes")

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("3.3.3.3:3000", body)
        self.assertNotIn("9.9.9.9:3000", body)

    def test_a_full_collection_reports_no_selection_finding(self):
        meta = meta_with()
        meta["collection"]["flags"]["node_selection"] = "all"

        self.assertIsNone(
            find(diagnostics(meta=meta).analyze(), "partial-node-selection")
        )

    def test_meta_for_another_snapshot_falls_back_to_heuristics(self):
        """Two bundles under one path are a supported input. Reporting one bundle's
        reconciliation against the other's snapshot is the false claim these checks
        exist to remove."""
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [
                    {"node_key": "9.9.9.9:3000", "reason": "seen in peers of A"}
                ],
                "dropped_during_collection": [
                    {"node_key": "3.3.3.3:3000", "reason": "timed out"}
                ],
                "cluster_down_nodes": [],
                "visibility_error_nodes": [],
            }
        )
        meta["snapshots"][0]["timestamp"] = "2026-01-01 00:00:00 UTC"
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["statistics"]["service"]["cluster_size"] = "2"

        diag = diagnostics(nodes={"1.1.1.1:3000": node}, meta=meta)
        warnings = diag.analyze()

        self.assertFalse(diag.has_meta())
        warning = find(warnings, "dropped-or-missing-nodes")
        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("inferred", body)
        self.assertNotIn("3.3.3.3:3000", body)
        self.assertNotIn("9.9.9.9:3000", body)


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

    def test_one_node_of_many_is_the_ordinary_local_collect_and_stays_silent(self):
        """A plain collect covers exactly the node asadm ran on. That is the
        documented behaviour, not a gap, and a finding that fires on every
        ordinary bundle trains readers to skip the banner."""
        warnings = diagnostics(
            nodes=self._nodes(with_sysinfo=1, without_sysinfo=26), meta=meta_with()
        ).analyze()

        self.assertIsNone(find(warnings, "partial-sysinfo"))
        self.assertIsNone(find(warnings, "missing-sysinfo"))

    def test_partial_coverage_beyond_one_node_is_informational(self):
        warning = find(
            diagnostics(
                nodes=self._nodes(with_sysinfo=2, without_sysinfo=2), meta=meta_with()
            ).analyze(),
            "partial-sysinfo",
        )

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)
        self.assertEqual(warning.title, "System information covers 2 of 4 nodes")
        body = " ".join(warning.lines)
        self.assertIn("`health` cannot run its system checks", body)
        self.assertIn("`summary` reports no OS version", body)

    def test_ssh_collection_with_gaps_is_a_warning(self):
        """--enable-ssh promised full coverage, so a node with no sysinfo means
        SSH to it failed; that is the surprising case worth warning about."""
        meta = meta_with()
        meta["collection"]["flags"]["enable_ssh"] = True

        warning = find(
            diagnostics(
                nodes=self._nodes(with_sysinfo=1, without_sysinfo=2), meta=meta
            ).analyze(),
            "partial-sysinfo",
        )

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.WARNING)
        self.assertIn("--enable-ssh", warning.title)
        self.assertIn("2 of 3 nodes", warning.title)
        body = " ".join(warning.lines)
        self.assertIn("SSH to those hosts failed", body)
        self.assertIn("`health` cannot run its system checks", body)

    def test_partial_coverage_is_not_reported_as_missing(self):
        warnings = diagnostics(
            nodes=self._nodes(with_sysinfo=1, without_sysinfo=2), meta=meta_with()
        ).analyze()

        self.assertIsNone(find(warnings, "missing-sysinfo"))

    def test_full_coverage_with_missing_host_files_is_reported_on_its_own(self):
        """Every responder has sysinfo, so there is no coverage gap to describe; only
        the two host files are absent."""
        warning = find(
            diagnostics(
                nodes=self._nodes(with_sysinfo=2, without_sysinfo=0),
                meta=meta_with(),
                bundle_files=(),
            ).analyze(),
            "missing-sysinfo-files",
        )

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)
        self.assertNotIn("other 0", " ".join(warning.lines))

    def test_dropped_nodes_are_not_counted_as_sysinfo_gaps(self):
        """A node that returned nothing is reported as dropped; counting it here too
        would blame sysinfo for a node that answered no calls at all."""
        nodes = self._nodes(with_sysinfo=1, without_sysinfo=0)
        nodes["10.0.0.9:3000"] = {"as_stat": {}}

        warnings = diagnostics(nodes=nodes, meta=meta_with()).analyze()

        self.assertIsNone(find(warnings, "partial-sysinfo"))
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

    def test_unsupported_sections_are_not_reported_as_failures(self):
        """ACL on a security-disabled cluster, and user-agents or masking on an older
        server, record a section that never existed rather than data that was lost."""
        meta = meta_with(
            nodes={
                "1.1.1.1:3000": {
                    "errors": [
                        {
                            "section": "acl",
                            "error_class": "unsupported",
                            "message": "Security not enabled.",
                            "recovered_on_retry": False,
                        },
                        {
                            "section": "user_agents",
                            "error_class": "unsupported",
                            "message": "unknown command",
                            "recovered_on_retry": False,
                        },
                    ]
                }
            }
        )

        self.assertIsNone(
            find(diagnostics(meta=meta).analyze(), "node-collection-errors")
        )

    def test_unsupported_sections_are_not_counted_as_recovered(self):
        """Filtering them out must not leave them looking like retried errors."""
        meta = meta_with(
            nodes={
                "1.1.1.1:3000": {
                    "errors": [
                        {
                            "section": "acl",
                            "error_class": "unsupported",
                            "message": "Security not enabled.",
                            "recovered_on_retry": False,
                        },
                        {
                            "section": "latency",
                            "error_class": "timeout",
                            "message": "late",
                            "recovered_on_retry": False,
                        },
                    ]
                }
            }
        )

        warning = find(diagnostics(meta=meta).analyze(), "node-collection-errors")

        self.assertIsNotNone(warning)
        self.assertIn("latency", warning.table)
        self.assertNotIn("acl", warning.table)
        self.assertNotIn("recovered on retry", " ".join(warning.lines))


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
        self.assertIn("No statistics for: 2.2.2.2:3000", body)
        self.assertIn("No config for: 2.2.2.2:3000", body)

    def test_fully_empty_node_is_not_also_reported_as_partial(self):
        """An empty node is already reported as dropped or missing; listing it here
        too would put one node in three findings."""
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": {"as_stat": {}},
        }

        warnings = diagnostics(nodes=nodes, meta=meta_with()).analyze()

        self.assertIsNone(find(warnings, "partial-nodes"))

    def test_old_bundle_reports_empty_nodes_as_partial(self):
        """Without meta there is no dropped record and no heuristic can see an empty
        node, so this finding is the only place it can surface."""
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": {"as_stat": {}},
        }

        warning = find(diagnostics(nodes=nodes).analyze(), "partial-nodes")

        self.assertIsNotNone(warning)
        self.assertIn(
            "No Aerospike data at all for: 2.2.2.2:3000", " ".join(warning.lines)
        )


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
        self.assertEqual(warning.severity, DiagSeverity.INFO)
        self.assertIn("collected 30 days ago", warning.title)

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
        self.assertIn("cluster_is_member is false", body)
        self.assertIn("2 cluster keys", body)
        self.assertIn("2 principals", body)
        self.assertIn("2 cluster sizes", body)

    def test_disagreement_allows_for_a_cluster_re_forming_mid_collection(self):
        """Nodes are queried over several seconds, so differing cluster keys are not
        proof of a split."""
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": copy.deepcopy(HEALTHY_NODE),
        }
        nodes["2.2.2.2:3000"]["as_stat"]["statistics"]["service"]["cluster_key"] = "K2"
        nodes["2.2.2.2:3000"]["as_stat"]["meta_data"]["node_id"] = "BB2"

        warning = find(diagnostics(nodes=nodes).analyze(), "cluster-state")

        self.assertIn(
            "re-formed while the bundle was being collected", " ".join(warning.lines)
        )

    def test_healthy_cluster_state_is_silent(self):
        self.assertIsNone(find(diagnostics().analyze(), "cluster-state"))

    def test_migrations_report_nodes_not_a_summed_partition_count(self):
        """The node count comes from the service statistic
        migrate_partitions_remaining (per node, both directions, so a cross-node
        total would be a number no command can reproduce); the per-namespace
        detail comes from the namespace-level tx/rx pair, which is the only shape
        real namespace statistics have."""
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": copy.deepcopy(HEALTHY_NODE),
        }

        for node in nodes.values():
            node["as_stat"]["statistics"]["service"][
                "migrate_partitions_remaining"
            ] = "42"
            node["as_stat"]["statistics"]["namespace"] = {
                "test": {
                    "service": {
                        "migrate_tx_partitions_remaining": "30",
                        "migrate_rx_partitions_remaining": "12",
                    },
                    "set": {},
                    "bin": {},
                    "sindex": {},
                }
            }

        warning = find(diagnostics(nodes=nodes).analyze(), "migrations")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)
        self.assertEqual(warning.title, "Migrations were in progress on 2 nodes")
        body = " ".join(warning.lines)
        self.assertIn("test=42", body)
        self.assertNotIn("84", body)

    def test_migrations_ignore_the_service_stat_name_at_namespace_level(self):
        """No server writes migrate_partitions_remaining into namespace
        statistics; a check keyed on that shape can never fire on a real
        bundle."""
        nodes = self._with_ns_stats(migrate_partitions_remaining="200")

        self.assertIsNone(find(diagnostics(nodes=nodes).analyze(), "migrations"))

    def test_zero_migrations_is_silent(self):
        nodes = self._with_ns_stats(
            migrate_tx_partitions_remaining="0", migrate_rx_partitions_remaining="0"
        )
        nodes["1.1.1.1:3000"]["as_stat"]["statistics"]["service"][
            "migrate_partitions_remaining"
        ] = "0"

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

    def test_edition_only_mix_is_not_called_a_version_mix(self):
        """Same build on every node; only the edition differs, so the title must not
        claim more than one server version."""
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": copy.deepcopy(HEALTHY_NODE),
        }
        nodes["2.2.2.2:3000"]["as_stat"]["meta_data"].update(
            {"node_id": "BB2", "edition": "Aerospike Community Edition"}
        )

        warning = find(diagnostics(nodes=nodes).analyze(), "mixed-server-versions")

        self.assertIsNotNone(warning)
        self.assertEqual(
            warning.title, "Cluster is running more than one server edition"
        )
        self.assertIn("not supported with mixed editions", " ".join(warning.lines))

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
        body = " ".join(warning.lines)
        self.assertIn("show statistics", body)
        self.assertNotIn("health -v", body)

    def test_a_node_with_no_outliers_is_not_an_outlier(self):
        """The server answers health-outliers with an empty string, which
        Node.info_health_outliers turns into a placeholder entry rather than {}.
        Reading that as a finding fires on essentially every bundle."""
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["health"] = {"outlier0": {}}

        self.assertIsNone(
            find(diagnostics(nodes={"1.1.1.1:3000": node}).analyze(), "health-outliers")
        )

    def test_a_populated_outlier_dict_is_still_reported(self):
        node = copy.deepcopy(HEALTHY_NODE)
        node["as_stat"]["meta_data"]["health"] = {
            "outlier0": {"reason": "device_write_q", "confidence": "high"}
        }

        warning = find(
            diagnostics(nodes={"1.1.1.1:3000": node}).analyze(), "health-outliers"
        )

        self.assertIsNotNone(warning)
        self.assertIn("device_write_q", " ".join(warning.lines))

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

    def test_clock_skew_with_no_governing_threshold_uses_the_constant(self):
        nodes = self._with_service_stats(cluster_clock_skew_ms="4000")

        warning = find(diagnostics(nodes=nodes).analyze(), "clock-skew")

        self.assertIsNotNone(warning)
        self.assertIn("4.0 s", warning.title)

    def test_small_clock_skew_is_silent(self):
        nodes = self._with_service_stats(cluster_clock_skew_ms="12")

        self.assertIsNone(find(diagnostics(nodes=nodes).analyze(), "clock-skew"))

    def _strong_consistency_nodes(self, skew_ms, stop_writes_sec="20"):
        nodes = self._with_service_stats(
            cluster_clock_skew_ms=skew_ms,
            cluster_clock_skew_stop_writes_sec=stop_writes_sec,
        )
        nodes["1.1.1.1:3000"]["as_stat"]["config"]["namespace"] = {
            "test": {"service": {"strong-consistency": "true"}}
        }
        return nodes

    def test_clock_skew_below_three_quarters_of_the_sc_threshold_is_silent(self):
        """The trigger scales to the cluster's own stop-writes point, matching the
        health checks: 4 s of skew against a 20 s threshold is not a warning."""
        nodes = self._strong_consistency_nodes(skew_ms="4000")

        self.assertIsNone(find(diagnostics(nodes=nodes).analyze(), "clock-skew"))

    def test_clock_skew_approaching_the_sc_threshold_states_it(self):
        nodes = self._strong_consistency_nodes(skew_ms="16000")

        warning = find(diagnostics(nodes=nodes).analyze(), "clock-skew")

        self.assertIsNotNone(warning)
        self.assertIn("16.0 s", warning.title)
        body = " ".join(warning.lines)
        self.assertIn("Writes stop at 20 s of skew", body)
        self.assertIn("cluster_clock_skew_stop_writes_sec", body)

    def test_clock_skew_past_the_sc_threshold_says_writes_were_refused(self):
        nodes = self._strong_consistency_nodes(skew_ms="27000")

        warning = find(diagnostics(nodes=nodes).analyze(), "clock-skew")

        self.assertIsNotNone(warning)
        self.assertIn("past the 20 s stop-writes threshold", " ".join(warning.lines))

    def test_clock_skew_disagreeing_thresholds_use_the_lowest(self):
        """Each node stops writes at its own configured value, so the cluster
        stops at the lowest one; quoting the most forgiving value understates
        the risk."""
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": copy.deepcopy(HEALTHY_NODE),
        }
        nodes["1.1.1.1:3000"]["as_stat"]["statistics"]["service"].update(
            {
                "cluster_clock_skew_ms": "9000",
                "cluster_clock_skew_stop_writes_sec": "10",
            }
        )
        nodes["2.2.2.2:3000"]["as_stat"]["statistics"]["service"].update(
            {
                "cluster_clock_skew_ms": "9000",
                "cluster_clock_skew_stop_writes_sec": "30",
            }
        )
        nodes["1.1.1.1:3000"]["as_stat"]["config"]["namespace"] = {
            "test": {"service": {"strong-consistency": "true"}}
        }

        warning = find(diagnostics(nodes=nodes).analyze(), "clock-skew")

        self.assertIsNotNone(warning)
        self.assertIn("10 s", " ".join(warning.lines))

    def test_clock_skew_ap_cluster_with_nsup_uses_the_fixed_limit(self):
        """A pure-AP cluster stops writes at a fixed 40 s (with nsup enabled), so
        a 5.2 s skew is nowhere near actionable and the configured SC threshold
        does not apply."""
        nodes = self._with_service_stats(
            cluster_clock_skew_ms="5200", cluster_clock_skew_stop_writes_sec="20"
        )
        nodes["1.1.1.1:3000"]["as_stat"]["config"]["namespace"] = {
            "test": {"service": {"strong-consistency": "false", "nsup-period": "120"}}
        }

        self.assertIsNone(find(diagnostics(nodes=nodes).analyze(), "clock-skew"))

    def test_clock_skew_ap_cluster_past_the_fixed_limit_warns(self):
        nodes = self._with_service_stats(cluster_clock_skew_ms="41000")
        nodes["1.1.1.1:3000"]["as_stat"]["config"]["namespace"] = {
            "test": {"service": {"strong-consistency": "false", "nsup-period": "120"}}
        }

        warning = find(diagnostics(nodes=nodes).analyze(), "clock-skew")

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("past the 40 s stop-writes threshold", body)
        self.assertIn("AP namespaces with nsup enabled", body)


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


class HealthyProductionBundleTest(unittest.TestCase):
    """A clean bundle must produce a quiet banner.

    Every other fixture here is hand-written, which is how three false positives
    shipped: what a real cluster returns does not look like an idealized dict. A
    healthy node's health-outliers call comes back as {"outlier0": {}}, a
    security-disabled cluster records an unsupported ACL error on every node, and a
    plain collect captures system statistics for one node only. Anything that fires
    against this fixture fires against most real bundles.
    """

    NODES = ("1.1.1.1:3000", "2.2.2.2:3000", "3.3.3.3:3000")

    def setUp(self):
        self.timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

    def _bundle(self):
        nodes = {}

        for index, node_key in enumerate(self.NODES):
            addr = node_key.split(":")[0]
            nodes[node_key] = {
                "as_stat": {
                    "statistics": {
                        "service": {
                            "cluster_size": "3",
                            "cluster_integrity": "true",
                            "cluster_is_member": "true",
                            "cluster_key": "8A2C1F0E4B",
                            "cluster_principal": "BB1",
                            "failed_best_practices": "false",
                            "cluster_clock_skew_ms": "0",
                            "cluster_clock_skew_stop_writes_sec": "20",
                            "migrate_partitions_remaining": "0",
                        },
                        "namespace": {
                            "test": {
                                "service": {
                                    "stop_writes": "false",
                                    "clock_skew_stop_writes": "false",
                                    "dead_partitions": "0",
                                    "unavailable_partitions": "0",
                                    "migrate_tx_partitions_remaining": "0",
                                    "migrate_rx_partitions_remaining": "0",
                                },
                                "set": {},
                                "bin": {},
                                "sindex": {},
                            }
                        },
                    },
                    "config": {
                        "service": {"proto-fd-max": "15000"},
                        "namespace": {"test": {"service": {"replication-factor": "2"}}},
                    },
                    "meta_data": {
                        "node_id": "BB%d" % (index + 1,),
                        "asd_build": "8.0.0.0",
                        "edition": "Aerospike Enterprise Edition build 8.0.0.0",
                        "ip": node_key,
                        "node_names": "host%d" % (index + 1,),
                        "health": {"outlier0": {}},
                        "best_practices": [],
                        "endpoints": [[addr, 3000, None]],
                        "services": [
                            [peer.split(":")[0], 3000, None]
                            for peer in self.NODES
                            if peer != node_key
                        ],
                        "udf": {},
                        "jobs": {},
                    },
                }
            }

        nodes[self.NODES[0]]["sys_stat"] = {"uname": {"nodename": "host1"}}

        meta = {
            "meta_format_version": 1,
            "bundle": {"asadm_version": "5.0.2", "asadm_build": "abc123"},
            "collection": {
                "flags": {"enable_ssh": False, "node_selection": "all"},
            },
            "snapshots": [
                {
                    "timestamp": self.timestamp,
                    "expected_nodes": list(self.NODES),
                    "responded_nodes": list(self.NODES),
                    "no_data_nodes": [],
                    "nodes": {
                        node_key: {
                            "node_id": "BB%d" % (index + 1,),
                            "responded": True,
                            "sysinfo_source": "local" if index == 0 else "none",
                            "errors": [
                                {
                                    "section": "acl",
                                    "error_class": "unsupported",
                                    "message": "Failed to query users : Security not "
                                    "enabled.",
                                    "recovered_on_retry": False,
                                },
                                {
                                    "section": "user_agents",
                                    "error_class": "unsupported",
                                    "message": "Failed to get user agents : unknown "
                                    "command.",
                                    "recovered_on_retry": False,
                                },
                            ],
                        }
                        for index, node_key in enumerate(self.NODES)
                    },
                    "discrepancies": {
                        "missing_from_collection": [],
                        "dropped_during_collection": [],
                        "cluster_down_nodes": [],
                        "visibility_error_nodes": [],
                    },
                }
            ],
        }

        return nodes, meta

    def _warnings(self):
        nodes, meta = self._bundle()
        return CollectinfoDiagnostics(
            log_handler=make_log_handler(
                bundle_files=("sysinfo.log", "aerospike.conf")
            ),
            snapshot=make_snapshot(nodes, timestamp=self.timestamp),
            timestamp=self.timestamp,
            running_version="5.0.2",
            meta=meta,
        ).analyze()

    def test_nothing_is_flagged_as_a_problem(self):
        flagged = [
            (warning.category, warning.title)
            for warning in self._warnings()
            if warning.severity is not DiagSeverity.INFO
        ]

        self.assertEqual(flagged, [])

    def test_provenance_is_the_only_finding(self):
        """One-node sysinfo coverage is the documented shape of a plain collect,
        so nothing but the version line survives on a clean bundle."""
        self.assertEqual(
            sorted(categories(self._warnings())),
            ["collector-version-match"],
        )

    def test_the_interactive_banner_is_quiet(self):
        """The intro already states the collector version, so a clean bundle
        prints no banner at all, with no findings filtered out to make it so."""
        banner = render_banner(self._warnings(), use_color=False)

        self.assertEqual(banner, "")
        self.assertNotIn("WARNING", banner)
        self.assertNotIn("ERROR", banner)


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

    def test_print_banner_writes_every_severity_with_its_label(self):
        """Execute mode used to route these through the logger, which dropped INFO
        below its level and set the exit code on ERROR."""
        warnings = [
            BundleWarning("a", DiagSeverity.ERROR, "err", ["detail"]),
            BundleWarning("b", DiagSeverity.WARNING, "warn"),
            BundleWarning("c", DiagSeverity.INFO, "info"),
        ]
        stream = io.StringIO()

        print_banner(warnings, stream)
        out = stream.getvalue()

        self.assertIn("ERROR: err", out)
        self.assertIn("detail", out)
        self.assertIn("WARNING: warn", out)
        self.assertIn("INFO: info", out)

    def test_print_banner_with_no_warnings_is_silent(self):
        stream = io.StringIO()

        print_banner([], stream)

        self.assertEqual(stream.getvalue(), "")

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

    def test_findings_render_most_severe_first(self):
        """The banner is often redirected or scrolled off a small terminal, so a
        data-loss ERROR must not render below an INFO note."""
        warnings = [
            BundleWarning("a", DiagSeverity.INFO, "an info"),
            BundleWarning("b", DiagSeverity.WARNING, "a warning"),
            BundleWarning("c", DiagSeverity.ERROR, "an error"),
        ]

        banner = render_banner(warnings, use_color=False)

        self.assertLess(banner.index("ERROR: an error"), banner.index("a warning"))
        self.assertLess(banner.index("WARNING: a warning"), banner.index("an info"))

    def test_severity_sort_is_stable_within_a_severity(self):
        warnings = [
            BundleWarning("a", DiagSeverity.WARNING, "first warning"),
            BundleWarning("b", DiagSeverity.WARNING, "second warning"),
        ]

        banner = render_banner(warnings, use_color=False)

        self.assertLess(banner.index("first warning"), banner.index("second warning"))

    def test_title_carries_severity_counts(self):
        warnings = [
            BundleWarning("a", DiagSeverity.ERROR, "an error"),
            BundleWarning("b", DiagSeverity.WARNING, "a warning"),
            BundleWarning("c", DiagSeverity.WARNING, "another warning"),
            BundleWarning("d", DiagSeverity.INFO, "an info"),
        ]

        banner = render_banner(warnings, use_color=False)

        self.assertIn(
            "Collectinfo Bundle Diagnostics (1 error, 2 warnings, 1 info)", banner
        )

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

    def test_print_banner_keeps_the_version_line(self):
        """Execute mode prints no intro, so this path must still carry provenance."""
        warnings = [
            BundleWarning(
                category="collector-version-match",
                severity=DiagSeverity.INFO,
                title="Collected by asadm 5.0.2",
            )
        ]
        stream = io.StringIO()

        print_banner(warnings, stream)

        self.assertIn("Collected by asadm 5.0.2", stream.getvalue())


class MetaFormatVersionTest(unittest.TestCase):
    def test_current_format_is_silent(self):
        warnings = diagnostics(meta=meta_with()).analyze()

        self.assertIsNone(find(warnings, "meta-format-newer"))

    def test_newer_format_is_reported_and_still_read(self):
        """A v2 meta parsed as v1 must not silently read as a clean collection."""
        meta = meta_with(asadm_version="5.0.2")
        meta["meta_format_version"] = 2

        warnings = diagnostics(meta=meta).analyze()

        warning = find(warnings, "meta-format-newer")
        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.WARNING)
        self.assertIn("v2", warning.title)
        self.assertIn("v1", warning.title)
        self.assertIsNotNone(find(warnings, "collector-version-match"))

    def test_no_meta_is_silent(self):
        self.assertIsNone(find(diagnostics().analyze(), "meta-format-newer"))


class NodeSelectionTest(unittest.TestCase):
    def test_count_comes_from_expected_nodes_not_the_selector_list(self):
        """One prefix wildcard can resolve to many nodes, so counting selector
        strings announces a 3-node bundle as a 1-node collection."""
        meta = meta_with()
        meta["collection"]["flags"]["node_selection"] = ["1.*"]
        meta["snapshots"][0]["expected_nodes"] = [
            "1.1.1.1:3000",
            "1.1.1.2:3000",
            "1.1.1.3:3000",
        ]

        warning = find(diagnostics(meta=meta).analyze(), "partial-node-selection")

        self.assertIsNotNone(warning)
        self.assertEqual(
            warning.title, "Collection was limited to 3 nodes by `collectinfo with`"
        )

    def test_a_requested_node_that_was_never_collected_is_a_warning(self):
        """The selection fix stops blaming excluded nodes; it must not also cover
        a node the user explicitly asked for and did not get."""
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [
                    {"node_key": "9.9.9.9:3000", "reason": "seen in peers of A"}
                ],
                "dropped_during_collection": [],
                "cluster_down_nodes": [],
                "visibility_error_nodes": [],
            }
        )
        meta["collection"]["flags"]["node_selection"] = ["1.1.1.1", "9.9.9.9"]

        warning = find(diagnostics(meta=meta).analyze(), "partial-node-selection")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.WARNING)
        body = " ".join(warning.lines)
        self.assertIn("requested", body)
        self.assertIn("9.9.9.9:3000", body)

    def test_a_selector_for_one_node_does_not_claim_a_longer_address(self):
        """`1.1.1.1` must not substring-match `11.1.1.1:3000`: promoting a
        deliberately excluded node to 'requested but never collected' is the
        false claim this check exists to remove."""
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [
                    {"node_key": "11.1.1.1:3000", "reason": "seen in peers of A"}
                ],
                "dropped_during_collection": [],
                "cluster_down_nodes": [],
                "visibility_error_nodes": [],
            }
        )
        meta["collection"]["flags"]["node_selection"] = ["1.1.1.1"]

        warning = find(diagnostics(meta=meta).analyze(), "partial-node-selection")

        self.assertIsNotNone(warning)
        self.assertEqual(warning.severity, DiagSeverity.INFO)
        self.assertNotIn("requested", " ".join(warning.lines))

    def test_duplicate_snapshot_timestamps_use_the_last_entry(self):
        """Sub-second snapshots share a timestamp and the writer keeps the last
        snapshot's data, so the last meta entry is the one that describes it."""
        meta = meta_with()
        stale = copy.deepcopy(meta["snapshots"][0])
        stale["no_data_nodes"] = ["9.9.9.9:3000"]
        stale["discrepancies"]["dropped_during_collection"] = [
            {"node_key": "9.9.9.9:3000", "reason": "timed out"}
        ]
        meta["snapshots"].insert(0, stale)

        warnings = diagnostics(meta=meta).analyze()

        self.assertIsNone(find(warnings, "dropped-or-missing-nodes"))

    def test_single_node_collection_is_stated_and_not_read_as_missing_nodes(self):
        """--single-node stops the crawl at the seed while the seed still
        advertises every peer; that is the user's choice, not a defect."""
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [
                    {"node_key": "9.9.9.9:3000", "reason": "seen in peers of A"}
                ],
                "dropped_during_collection": [],
                "cluster_down_nodes": [],
                "visibility_error_nodes": [],
            }
        )
        meta["collection"]["flags"]["node_selection"] = "all"
        meta["collection"]["flags"]["only_connect_seed"] = True

        warnings = diagnostics(meta=meta).analyze()

        self.assertIsNone(find(warnings, "dropped-or-missing-nodes"))
        selection = find(warnings, "partial-node-selection")
        self.assertIsNotNone(selection)
        self.assertEqual(selection.severity, DiagSeverity.INFO)
        self.assertIn("--single-node", selection.title)


class ListTruncationTest(unittest.TestCase):
    def test_dropped_node_list_names_how_many_are_hidden(self):
        dropped = [
            {"node_key": "10.1.0.%d:3000" % (index,), "reason": "timed out"}
            for index in range(12)
        ]
        meta = meta_with(
            discrepancies={
                "missing_from_collection": [],
                "dropped_during_collection": dropped,
                "cluster_down_nodes": [],
                "visibility_error_nodes": [],
            }
        )

        warning = find(diagnostics(meta=meta).analyze(), "dropped-or-missing-nodes")

        self.assertIsNotNone(warning)
        body = "\n".join(warning.lines)
        self.assertIn("12 nodes were connected to", body)
        self.assertIn("and 2 more; the full list is in collectinfo_meta.json", body)


class AggregatedErrorFindingsTest(unittest.TestCase):
    def _two_nodes_with_ns_stats(self, **stats):
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": copy.deepcopy(HEALTHY_NODE),
        }

        for node in nodes.values():
            node["as_stat"]["statistics"]["namespace"] = {
                "test": {"service": dict(stats), "set": {}, "bin": {}, "sindex": {}}
            }

        return nodes

    def test_stop_writes_aggregates_by_namespace_with_a_node_denominator(self):
        nodes = self._two_nodes_with_ns_stats(stop_writes="true")

        warning = find(diagnostics(nodes=nodes).analyze(), "stop-writes")

        self.assertIsNotNone(warning)
        self.assertIn("test (2 of 2 nodes)", " ".join(warning.lines))

    def test_partition_counts_aggregate_by_namespace_with_the_worst_node(self):
        nodes = self._two_nodes_with_ns_stats(dead_partitions="4")
        nodes["2.2.2.2:3000"]["as_stat"]["statistics"]["namespace"]["test"]["service"][
            "dead_partitions"
        ] = "12"

        warning = find(diagnostics(nodes=nodes).analyze(), "partition-availability")

        self.assertIsNotNone(warning)
        body = " ".join(warning.lines)
        self.assertIn("test 16 across 2 nodes", body)
        self.assertIn("worst 2.2.2.2:3000 = 12", body)


class ZeroUsableNodesSetComparisonTest(unittest.TestCase):
    def test_a_malformed_node_entry_does_not_condemn_the_healthy_ones(self):
        """nodes_without_as_stat counts a node whose whole value is {} while
        get_node_names skips it, so a count comparison can declare a bundle
        empty while naming its healthy nodes."""
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": {},
            "3.3.3.3:3000": {},
        }

        warnings = diagnostics(nodes=nodes).analyze()

        self.assertIsNone(find(warnings, "no-usable-nodes"))


class BestPracticesMixedBundleTest(unittest.TestCase):
    def test_nodes_without_metadata_still_count_via_the_service_stat(self):
        """One node's collected metadata must not hide another node's violation
        when that node's best-practices call failed during collection."""
        nodes = {
            "1.1.1.1:3000": copy.deepcopy(HEALTHY_NODE),
            "2.2.2.2:3000": copy.deepcopy(HEALTHY_NODE),
        }
        nodes["1.1.1.1:3000"]["as_stat"]["meta_data"]["best_practices"] = ["rmem-max"]
        nodes["2.2.2.2:3000"]["as_stat"]["meta_data"]["best_practices"] = ""
        nodes["2.2.2.2:3000"]["as_stat"]["statistics"]["service"][
            "failed_best_practices"
        ] = "true"
        nodes["2.2.2.2:3000"]["as_stat"]["meta_data"]["node_id"] = "BB2"

        warning = find(diagnostics(nodes=nodes).analyze(), "best-practices")

        self.assertIsNotNone(warning)
        self.assertIn("2 nodes are violating", warning.title)
        body = " ".join(warning.lines)
        self.assertIn("1.1.1.1:3000", body)
        self.assertIn("2.2.2.2:3000", body)
        self.assertIn("rmem-max", body)


class NodeErrorTableTest(unittest.TestCase):
    def _meta_with_errors(self, node_count):
        return meta_with(
            nodes={
                "10.0.0.%d:3000"
                % (index,): {
                    "node_id": "BB%d" % (index,),
                    "responded": True,
                    "sysinfo_source": "none",
                    "errors": [
                        {
                            "section": "latency",
                            "error_class": "timeout",
                            "message": "late",
                            "recovered_on_retry": False,
                        }
                    ],
                }
                for index in range(node_count)
            }
        )

    def test_the_error_column_reads_as_prose_not_a_class_name(self):
        warning = find(
            diagnostics(meta=self._meta_with_errors(1)).analyze(),
            "node-collection-errors",
        )

        self.assertIsNotNone(warning)
        self.assertIn("timed out", warning.table)

    def test_the_table_is_capped_and_says_where_the_rest_lives(self):
        warning = find(
            diagnostics(meta=self._meta_with_errors(14)).analyze(),
            "node-collection-errors",
        )

        self.assertIsNotNone(warning)
        self.assertIn("Showing 10 of 14 affected nodes", " ".join(warning.lines))
        self.assertIn("collectinfo_meta.json", " ".join(warning.lines))
        self.assertEqual(len(warning.table_lines), 10)

    def test_the_table_is_not_rendered_as_json_under_json_mode(self):
        """The banner is prose; under --json the sheet renderer would embed a
        JSON document inside it, so the plain-text rows are used instead."""
        from lib.view.sheet.render import get_style_json, set_style_json

        was_json = get_style_json()
        set_style_json(True)
        self.addCleanup(set_style_json, was_json)

        warning = find(
            diagnostics(meta=self._meta_with_errors(1)).analyze(),
            "node-collection-errors",
        )

        self.assertIsNotNone(warning)
        self.assertIsNone(warning.table)
        banner = render_banner([warning], use_color=False, skip_redundant=False)
        self.assertNotIn('"groups"', banner)
        self.assertIn("10.0.0.0:3000", banner)


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
