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
"""Startup diagnostics for a collectinfo bundle.

Customers routinely collect with one asadm and analyze with another. Anything the
analyzing asadm expects but the collecting asadm never wrote is simply absent, and
until now nothing said so. These checks run once at analyzer startup and surface
provenance (who collected the bundle, when, with which flags), collection integrity
(nodes that were expected but never landed, per-node section failures, missing
sysinfo), and a curated set of high-signal cluster anomalies that are otherwise only
reachable through on-demand commands.

Every check degrades to silence rather than raising: a bundle that cannot be fully
diagnosed must still be analyzable.
"""

import calendar
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from lib.utils import common, constants, util, version
from lib.view import terminal
from lib.view.sheet import Field, Projectors, Sheet, render as sheet_render

logger = logging.getLogger(__name__)

BANNER_TITLE = "Collectinfo Bundle Diagnostics"
BANNER_REDUNDANT_CATEGORIES = frozenset(
    ("collector-version-match", "collector-version-unparsed")
)
BUNDLE_STALE_DAYS = 7
CLOCK_SKEW_WARN_MS = 1000
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S UTC"
_NUMERIC_VERSION_RE = re.compile(r"^\d+(\.\d+)*")


class DiagSeverity(Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


@dataclass
class BundleWarning:
    category: str
    severity: DiagSeverity
    title: str
    lines: list[str] = field(default_factory=list)
    table: str | None = None
    table_lines: list[str] = field(default_factory=list)
    """Plain-text equivalent of `table`, for the log-based execute-mode path."""


node_errors_sheet = Sheet(
    (
        Field("Node", Projectors.String("node_names", None)),
        Field("Sections", Projectors.String("data", "sections")),
        Field("Error", Projectors.String("data", "reason")),
    ),
    from_source=("data", "node_names"),
)


def _is_comparable_version(value: str) -> bool:
    return bool(value) and bool(_NUMERIC_VERSION_RE.match(str(value).strip()))


def _to_int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except Exception:
        return None


def _is_false(value: Any) -> bool:
    return str(value).strip().lower() in ("false", "no", "0")


def _is_true(value: Any) -> bool:
    return str(value).strip().lower() in ("true", "yes", "1")


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    if count == 1:
        return singular
    return plural if plural is not None else singular + "s"


def _summarize(items, limit: int = 6) -> str:
    items = list(items)

    if len(items) <= limit:
        return ", ".join(str(item) for item in items)

    shown = ", ".join(str(item) for item in items[:limit])
    return "%s (and %d more)" % (shown, len(items) - limit)


class CollectinfoDiagnostics:
    def __init__(
        self,
        log_handler,
        snapshot,
        timestamp: str,
        running_version: str = "",
        meta: dict[str, Any] | None = None,
    ):
        self.log_handler = log_handler
        self.snapshot = snapshot
        self.timestamp = timestamp
        self.running_version = running_version or ""
        self.meta = meta or {}
        self._snapshot_meta: dict[str, Any] | None = None

    ###########################################################################
    # Data access. Every accessor tolerates a partial or malformed bundle.

    def _data(self, type_, stanza="") -> dict[str, Any]:
        try:
            return self.snapshot.get_data(type=type_, stanza=stanza) or {}
        except Exception:
            return {}

    def _service_stats(self) -> dict[str, Any]:
        return self._data("statistics", constants.STAT_SERVICE)

    def _ns_stats(self) -> dict[str, Any]:
        return self._data("statistics", constants.STAT_NAMESPACE)

    def _meta_data(self) -> dict[str, Any]:
        return self._data("meta_data")

    def _node_names(self) -> dict[str, str]:
        try:
            return self.snapshot.get_node_names() or {}
        except Exception:
            return {}

    def _nodes_without_as_stat(self) -> list[str]:
        try:
            return self.snapshot.nodes_without_as_stat() or []
        except Exception:
            return []

    def snapshot_meta(self) -> dict[str, Any]:
        """The meta entry for the snapshot being analyzed, if the bundle has one."""
        if self._snapshot_meta is not None:
            return self._snapshot_meta

        self._snapshot_meta = {}
        snapshots = self.meta.get("snapshots")

        if not isinstance(snapshots, list) or not snapshots:
            return self._snapshot_meta

        for entry in snapshots:
            if isinstance(entry, dict) and entry.get("timestamp") == self.timestamp:
                self._snapshot_meta = entry
                return self._snapshot_meta

        last = snapshots[-1]

        if isinstance(last, dict):
            self._snapshot_meta = last

        return self._snapshot_meta

    def has_meta(self) -> bool:
        return bool(self.meta.get("snapshots")) or bool(self.meta.get("bundle"))

    ###########################################################################

    def analyze(self) -> list[BundleWarning]:
        warnings: list[BundleWarning] = []

        for check in (
            self._check_collector_version,
            self._check_zero_usable_nodes,
        ):
            self._run(check, warnings)

        if any(w.category == "no-usable-nodes" for w in warnings):
            return warnings

        for check in (
            self._check_dropped_or_missing_nodes,
            self._check_missing_sysinfo,
            self._check_node_collection_errors,
            self._check_empty_and_partial_nodes,
            self._check_multiple_snapshots,
            self._check_bundle_age,
            self._check_stop_writes,
            self._check_cluster_state,
            self._check_migrations,
            self._check_mixed_server_versions,
            self._check_best_practices,
            self._check_health_outliers,
            self._check_partition_availability,
            self._check_clock_skew,
        ):
            self._run(check, warnings)

        return warnings

    def _run(self, check, warnings: list[BundleWarning]) -> None:
        try:
            result = check()
        except Exception as e:
            logger.debug(
                "Diagnostic %s failed: %s",
                getattr(check, "__name__", check),
                e,
                exc_info=True,
            )
            return

        if result:
            warnings.append(result)

    ###########################################################################
    # Collection integrity and provenance.

    def _collector_version(self) -> str:
        bundle = self.meta.get("bundle") or {}
        meta_version = str(bundle.get("asadm_version") or "").strip()

        if meta_version:
            return meta_version

        try:
            return (self.log_handler.collector_asadm_version() or "").strip()
        except Exception:
            return ""

    def _check_collector_version(self) -> BundleWarning | None:
        """Always state which asadm collected the bundle.

        Old bundles carry no metadata file but every asadm since 2017 echoed
        'asadm version <v>' into ascollectinfo.log, so the version is recoverable
        for effectively any bundle. A mismatch with the running asadm gets one
        extra sentence; the version itself is the point.
        """
        collector = self._collector_version()
        running = self.running_version

        if not collector:
            return BundleWarning(
                category="collector-version-unknown",
                severity=DiagSeverity.WARNING,
                title="Collected by an unknown asadm version",
                lines=[
                    "Neither the bundle metadata nor the collection logs record a "
                    "version, which usually means a much older asadm. Sections this "
                    "asadm expects may never have been collected, and nodes that "
                    "timed out may have been dropped without a trace."
                ],
            )

        if not _is_comparable_version(collector) or not _is_comparable_version(running):
            return BundleWarning(
                category="collector-version-unparsed",
                severity=DiagSeverity.INFO,
                title="Collected by asadm %s" % (collector,),
                lines=[],
            )

        collected = version.LooseVersion(collector)
        analyzing = version.LooseVersion(running)

        if collected < analyzing:
            return BundleWarning(
                category="collector-version-older",
                severity=DiagSeverity.WARNING,
                title="Collected by asadm %s, older than this asadm %s"
                % (collector, running),
                lines=[
                    "Sections added since %s are absent, and older asadm versions "
                    "could drop nodes that timed out. Re-collect with asadm %s for a "
                    "complete bundle." % (collector, running)
                ],
            )

        if collected > analyzing:
            return BundleWarning(
                category="collector-version-newer",
                severity=DiagSeverity.WARNING,
                title="Collected by asadm %s, newer than this asadm %s"
                % (collector, running),
                lines=[
                    "This asadm may not render every section the bundle contains. "
                    "Upgrade to asadm %s to analyze it fully." % (collector,)
                ],
            )

        return BundleWarning(
            category="collector-version-match",
            severity=DiagSeverity.INFO,
            title="Collected by asadm %s" % (collector,),
            lines=[],
        )

    def _check_zero_usable_nodes(self) -> BundleWarning | None:
        node_names = self._node_names()

        if not node_names:
            return BundleWarning(
                category="no-usable-nodes",
                severity=DiagSeverity.ERROR,
                title="Bundle contains no nodes",
                lines=["No node data could be read from this bundle."],
            )

        empty_nodes = set(self._nodes_without_as_stat())

        if empty_nodes and len(empty_nodes) >= len(node_names):
            return BundleWarning(
                category="no-usable-nodes",
                severity=DiagSeverity.ERROR,
                title="Bundle contains no Aerospike data for any of its %d nodes"
                % (len(node_names),),
                lines=[
                    "Every node in the snapshot has an empty as_stat. The "
                    "collection could not reach the cluster.",
                    "Nodes: %s" % (_summarize(sorted(node_names)),),
                ],
            )

        return None

    def _check_dropped_or_missing_nodes(self) -> BundleWarning | None:
        if self.has_meta():
            return self._check_dropped_from_meta()

        return self._check_dropped_from_heuristics()

    def _check_dropped_from_meta(self) -> BundleWarning | None:
        snapshot_meta = self.snapshot_meta()
        discrepancies = snapshot_meta.get("discrepancies") or {}
        lines: list[str] = []

        detection_error = discrepancies.get("detection_error")

        if detection_error:
            return BundleWarning(
                category="node-discrepancy-detection-failed",
                severity=DiagSeverity.WARNING,
                title="Node reconciliation did not complete during collection",
                lines=[
                    "Reason: %s" % (detection_error,),
                    "Dropped or missing nodes cannot be confirmed for this bundle.",
                ],
            )

        dropped = discrepancies.get("dropped_during_collection") or []
        missing = discrepancies.get("missing_from_collection") or []
        down = discrepancies.get("cluster_down_nodes") or []
        visibility = discrepancies.get("visibility_error_nodes") or []
        expected = snapshot_meta.get("expected_nodes") or []
        responded = snapshot_meta.get("responded_nodes") or []

        if dropped:
            lines.append(
                "%d expected %s returned no Aerospike data:"
                % (len(dropped), _plural(len(dropped), "node"))
            )
            for entry in dropped[:10]:
                lines.append(
                    "  %s (%s)"
                    % (entry.get("node_key", "unknown"), entry.get("reason", "unknown"))
                )

        if missing:
            lines.append(
                "%d %s advertised by the cluster but never collected:"
                % (len(missing), _plural(len(missing), "node"))
            )
            for entry in missing[:10]:
                lines.append(
                    "  %s (%s)"
                    % (entry.get("node_key", "unknown"), entry.get("reason", "unknown"))
                )

        if down:
            lines.append(
                "Unreachable by their peers at collection time: %s"
                % (_summarize(down),)
            )

        if visibility:
            lines.append(
                "Could not see the rest of the cluster at collection time: %s"
                % (_summarize(visibility),)
            )

        if not lines:
            return None

        if expected and responded:
            lines.append(
                "Collected %d of %d expected nodes." % (len(responded), len(expected))
            )

        return BundleWarning(
            category="dropped-or-missing-nodes",
            severity=DiagSeverity.WARNING,
            title="Cluster nodes are missing from this bundle",
            lines=lines,
        )

    def _check_dropped_from_heuristics(self) -> BundleWarning | None:
        """Infer missing nodes for bundles collected before TOOLS-4135.

        Old bundles carry no record of what was expected, so every statement here
        is a proxy and is phrased as such.
        """
        present = set(self._node_names())
        service_stats = self._service_stats()
        lines: list[str] = []

        cluster_sizes = {
            size
            for size in (
                _to_int(stats.get("cluster_size"))
                for stats in service_stats.values()
                if isinstance(stats, dict)
            )
            if size is not None
        }

        if cluster_sizes and max(cluster_sizes) > len(present):
            lines.append(
                "Nodes report a cluster_size of %d but only %d %s present, so this "
                "bundle may be missing %d %s."
                % (
                    max(cluster_sizes),
                    len(present),
                    _plural(len(present), "node is", "nodes are"),
                    max(cluster_sizes) - len(present),
                    _plural(max(cluster_sizes) - len(present), "node"),
                )
            )

        try:
            advertised = self.snapshot.get_advertised_peers() or {}
        except Exception:
            advertised = {}

        peer_keys: set[str] = set()

        for keys in advertised.values():
            peer_keys.update(keys)

        unseen = sorted(peer_keys - present)

        if unseen:
            lines.append(
                "Advertised as cluster peers but not present in the bundle: %s. "
                "These may be uncollected nodes or alternate addresses of "
                "collected ones." % (_summarize(unseen),)
            )

        broken_integrity = sorted(
            node
            for node, stats in service_stats.items()
            if isinstance(stats, dict) and _is_false(stats.get("cluster_integrity"))
        )

        if broken_integrity:
            lines.append(
                "cluster_integrity was false on %s, so the cluster may have been "
                "split when this bundle was collected."
                % (_summarize(broken_integrity),)
            )

        if not lines:
            return None

        lines.append(
            "This bundle predates collection-time node reconciliation, so these "
            "are inferred rather than recorded."
        )

        return BundleWarning(
            category="dropped-or-missing-nodes",
            severity=DiagSeverity.WARNING,
            title="This bundle may be missing cluster nodes",
            lines=lines,
        )

    def _check_missing_sysinfo(self) -> BundleWarning | None:
        """Report sysinfo coverage.

        asadm gathers system statistics locally for the node it runs on, and over SSH
        for the rest only when --enable-ssh is passed. So a bundle covering exactly
        one node is the ordinary outcome of a plain collect and is reported as
        information; a bundle covering none means collectinfo ran off-cluster and
        nothing host-level was captured at all, which is the case worth warning about.
        """
        node_names = self._node_names()

        if not node_names:
            return None

        with_sysinfo = []
        without_sysinfo = []

        for node in sorted(node_names):
            try:
                if self.snapshot.has_sys_data(node):
                    with_sysinfo.append(node)
                else:
                    without_sysinfo.append(node)
            except Exception:
                continue

        has_sysinfo_files = self._bundle_has_files(("sysinfo.log", "aerospike.conf"))

        if not without_sysinfo and has_sysinfo_files:
            return None

        if not with_sysinfo:
            lines = [
                "No host-level data was captured for any of the %d nodes, so "
                "`summary`, `info network`, and `health` cannot report on CPU, "
                "memory, disks, or the OS." % (len(node_names),),
                "collectinfo gathers system statistics locally for the node it runs "
                "on and over SSH for every other node, so this bundle was collected "
                "from a host that is not an Aerospike node, without --enable-ssh.",
            ]

            if not has_sysinfo_files:
                lines.append(
                    "The bundle also has no sysinfo.log and no aerospike.conf, which "
                    "are only ever collected when asadm runs on a cluster node."
                )

            return BundleWarning(
                category="missing-sysinfo",
                severity=DiagSeverity.WARNING,
                title="No system information in this bundle",
                lines=lines,
            )

        lines = [
            "Captured for %s. The other %d %s no host-level data: %s."
            % (
                _summarize(with_sysinfo),
                len(without_sysinfo),
                _plural(len(without_sysinfo), "node has", "nodes have"),
                _summarize(without_sysinfo),
            ),
            "Expected unless collectinfo was run with --enable-ssh, which is what "
            "lets it collect system statistics from nodes it is not running on.",
        ]

        if not has_sysinfo_files:
            lines.append("The bundle has no sysinfo.log and no aerospike.conf either.")

        return BundleWarning(
            category="partial-sysinfo",
            severity=DiagSeverity.INFO,
            title="System information covers %d of %d nodes"
            % (len(with_sysinfo), len(node_names)),
            lines=lines,
        )

    def _bundle_has_files(self, suffixes: tuple[str, ...]) -> bool:
        iter_files = getattr(self.log_handler, "_iter_bundle_files", None)

        if iter_files is None:
            return True

        try:
            return bool(iter_files(suffixes))
        except Exception:
            return True

    def _check_node_collection_errors(self) -> BundleWarning | None:
        nodes_meta = (
            (self.snapshot_meta().get("nodes") or {}) if self.has_meta() else {}
        )

        if not nodes_meta:
            return None

        rows: dict[str, dict[str, str]] = {}
        node_names: dict[str, str] = {}
        recovered = 0

        for node_key, node_meta in sorted(nodes_meta.items()):
            errors = (node_meta or {}).get("errors") or []
            unrecovered = [
                error for error in errors if not error.get("recovered_on_retry")
            ]
            recovered += len(errors) - len(unrecovered)

            if not unrecovered:
                continue

            sections = sorted({str(error.get("section", "?")) for error in unrecovered})
            reasons = sorted(
                {str(error.get("error_class", "?")) for error in unrecovered}
            )
            rows[node_key] = {
                "sections": ", ".join(sections),
                "reason": ", ".join(reasons),
            }
            node_names[node_key] = node_key

        if not rows:
            if recovered:
                return BundleWarning(
                    category="node-collection-errors",
                    severity=DiagSeverity.INFO,
                    title="%d transient collection %s recovered on retry"
                    % (recovered, _plural(recovered, "error")),
                    lines=[],
                )
            return None

        table = None

        try:
            table = sheet_render(
                node_errors_sheet,
                "Per-node collection errors",
                dict(data=rows, node_names=node_names),
                common=dict(principal="", self_node=""),
            )
        except Exception as e:
            logger.debug("Could not render node error table: %s", e, exc_info=True)

        table_lines = [
            "  %s: %s (%s)" % (node_key, row["sections"], row["reason"])
            for node_key, row in rows.items()
        ]
        lines = []

        if recovered:
            lines.append(
                "%d further %s recovered on retry."
                % (recovered, _plural(recovered, "error"))
            )

        return BundleWarning(
            category="node-collection-errors",
            severity=DiagSeverity.WARNING,
            title="Some sections failed to collect on %d %s"
            % (len(rows), _plural(len(rows), "node")),
            lines=lines,
            table=table,
            table_lines=table_lines,
        )

    def _check_empty_and_partial_nodes(self) -> BundleWarning | None:
        node_names = self._node_names()
        empty_nodes = [
            node for node in self._nodes_without_as_stat() if node in node_names
        ]
        statistics = self._data("statistics")
        configs = self._data("config")

        no_statistics = sorted(
            node
            for node in node_names
            if node not in empty_nodes and not util.has_content(statistics.get(node))
        )
        no_config = sorted(
            node
            for node in node_names
            if node not in empty_nodes and not util.has_content(configs.get(node))
        )

        lines = []

        if empty_nodes:
            lines.append(
                "Present but empty (no Aerospike data at all): %s."
                % (_summarize(sorted(empty_nodes)),)
            )

        if no_statistics:
            lines.append("Missing statistics: %s." % (_summarize(no_statistics),))

        if no_config:
            lines.append("Missing config: %s." % (_summarize(no_config),))

        if not lines:
            return None

        lines.append(
            "Commands that read these sections will show these nodes as blank."
        )

        return BundleWarning(
            category="partial-nodes",
            severity=DiagSeverity.WARNING,
            title="Some nodes are only partially represented",
            lines=lines,
        )

    def _check_multiple_snapshots(self) -> BundleWarning | None:
        count = getattr(self.log_handler, "bundle_snapshot_count", 0) or 0

        if count <= 1:
            return None

        return BundleWarning(
            category="multiple-snapshots",
            severity=DiagSeverity.INFO,
            title="Bundle holds %d snapshots; analyzing the newest only" % (count,),
            lines=["Analyzing snapshot %s." % (self.timestamp,)],
        )

    def _check_bundle_age(self) -> BundleWarning | None:
        try:
            collected = time.strptime(self.timestamp, TIMESTAMP_FORMAT)
        except Exception:
            return None

        age_days = (time.time() - calendar.timegm(collected)) / 86400

        if age_days < BUNDLE_STALE_DAYS:
            return None

        return BundleWarning(
            category="stale-bundle",
            severity=DiagSeverity.WARNING,
            title="Bundle is %d days old" % (int(age_days),),
            lines=[
                "Collected %s. The cluster's current state may differ entirely."
                % (self.timestamp,)
            ],
        )

    ###########################################################################
    # Curated anomalies. One line each, pointing at the command that has detail.

    def _check_stop_writes(self) -> BundleWarning | None:
        stop_writes = common.create_stop_writes_summary(
            self._service_stats(),
            self._ns_stats(),
            self._data("config", constants.CONFIG_NAMESPACE),
            self._data("statistics", constants.STAT_SETS),
            self._data("config", constants.CONFIG_SET),
        )
        flagged = self._namespaces_flagging_stop_writes()

        if not common.active_stop_writes(stop_writes) and not flagged:
            return None

        lines = []

        if flagged:
            lines.append(
                "Namespaces reporting stop-writes: %s." % (_summarize(flagged),)
            )

        lines.append("Run `show stop-writes` for the triggering metrics.")

        return BundleWarning(
            category="stop-writes",
            severity=DiagSeverity.ERROR,
            title="This cluster was in stop-writes when the bundle was collected",
            lines=lines,
        )

    def _namespaces_flagging_stop_writes(self) -> list[str]:
        """Namespaces whose own stop_writes flag was set.

        The derived summary only reports triggers whose usage and threshold metrics
        are both present in the bundle; the server's own flag catches the rest.
        """
        flagged = set()

        for node, ns_data in self._ns_stats().items():
            if not isinstance(ns_data, dict):
                continue

            for ns, stats in ns_data.items():
                if not isinstance(stats, dict):
                    continue

                if _is_true(stats.get("stop_writes")) or _is_true(
                    stats.get("clock_skew_stop_writes")
                ):
                    flagged.add("%s/%s" % (node, ns))

        return sorted(flagged)

    def _check_cluster_state(self) -> BundleWarning | None:
        service_stats = self._service_stats()

        if not service_stats:
            return None

        lines = []
        broken_integrity = sorted(
            node
            for node, stats in service_stats.items()
            if isinstance(stats, dict) and _is_false(stats.get("cluster_integrity"))
        )
        orphans = sorted(
            node
            for node, stats in service_stats.items()
            if isinstance(stats, dict) and _is_false(stats.get("cluster_is_member"))
        )
        cluster_keys = {
            stats.get("cluster_key")
            for stats in service_stats.values()
            if isinstance(stats, dict) and stats.get("cluster_key")
        }
        principals = {
            stats.get("cluster_principal")
            for stats in service_stats.values()
            if isinstance(stats, dict) and stats.get("cluster_principal")
        }
        cluster_sizes = {
            size
            for size in (
                _to_int(stats.get("cluster_size"))
                for stats in service_stats.values()
                if isinstance(stats, dict)
            )
            if size is not None
        }

        if broken_integrity:
            lines.append(
                "cluster_integrity is false on: %s." % (_summarize(broken_integrity),)
            )

        if orphans:
            lines.append(
                "Not a member of the cluster (orphan): %s." % (_summarize(orphans),)
            )

        if len(cluster_keys) > 1:
            lines.append(
                "%d distinct cluster keys are present, which means the cluster was "
                "split: %s." % (len(cluster_keys), _summarize(sorted(cluster_keys)))
            )

        if len(principals) > 1:
            lines.append(
                "%d distinct cluster principals are present: %s."
                % (len(principals), _summarize(sorted(principals)))
            )

        if len(cluster_sizes) > 1:
            lines.append(
                "Nodes disagree on cluster_size: %s."
                % (_summarize(sorted(cluster_sizes)),)
            )

        if not lines:
            return None

        lines.append("Run `info network` for the per-node view.")

        return BundleWarning(
            category="cluster-state",
            severity=DiagSeverity.WARNING,
            title="Cluster membership was unhealthy at collection time",
            lines=lines,
        )

    def _check_migrations(self) -> BundleWarning | None:
        remaining = 0

        for ns_data in self._ns_stats().values():
            if not isinstance(ns_data, dict):
                continue

            for stats in ns_data.values():
                if not isinstance(stats, dict):
                    continue

                value = _to_int(stats.get("migrate_partitions_remaining"))

                if value and value > 0:
                    remaining += value

        if not remaining:
            return None

        return BundleWarning(
            category="migrations",
            severity=DiagSeverity.INFO,
            title="Migrations were in progress (%d partitions remaining)"
            % (remaining,),
            lines=[
                "Object counts, storage usage, and per-node balance in this bundle "
                "are transient. Run `info namespace` for the per-namespace view."
            ],
        )

    def _check_mixed_server_versions(self) -> BundleWarning | None:
        builds = set()
        editions = set()

        for node_meta in self._meta_data().values():
            if not isinstance(node_meta, dict):
                continue

            build = node_meta.get("asd_build")
            edition = node_meta.get("edition")

            if build:
                builds.add(str(build))

            if edition:
                editions.add(str(edition))

        lines = []

        if len(builds) > 1:
            lines.append("Server builds present: %s." % (_summarize(sorted(builds)),))

        if len(editions) > 1:
            lines.append(
                "Server editions present: %s." % (_summarize(sorted(editions)),)
            )

        if not lines:
            return None

        lines.append(
            "Expected during a rolling upgrade; otherwise a misconfiguration. Run "
            "`summary` for the per-node breakdown."
        )

        return BundleWarning(
            category="mixed-server-versions",
            severity=DiagSeverity.WARNING,
            title="Cluster is running more than one server version",
            lines=lines,
        )

    def _check_best_practices(self) -> BundleWarning | None:
        failing_nodes = set()

        for node, node_meta in self._meta_data().items():
            if not isinstance(node_meta, dict):
                continue

            practices = node_meta.get(constants.METADATA_PRACTICES)

            if practices and not isinstance(practices, str):
                failing_nodes.add(node)

        if not failing_nodes:
            for node, stats in self._service_stats().items():
                if isinstance(stats, dict) and _is_true(
                    stats.get("failed_best_practices")
                ):
                    failing_nodes.add(node)

        if not failing_nodes:
            return None

        return BundleWarning(
            category="best-practices",
            severity=DiagSeverity.WARNING,
            title="%d %s violating Aerospike best-practices"
            % (len(failing_nodes), _plural(len(failing_nodes), "node is", "nodes are")),
            lines=[
                "Nodes: %s." % (_summarize(sorted(failing_nodes)),),
                "Run `show best-practices` for the violated checks.",
            ],
        )

    def _check_health_outliers(self) -> BundleWarning | None:
        outlier_nodes = {}

        for node, node_meta in self._meta_data().items():
            if not isinstance(node_meta, dict):
                continue

            health = node_meta.get("health")

            if health and not isinstance(health, str):
                outlier_nodes[node] = health

        if not outlier_nodes:
            return None

        return BundleWarning(
            category="health-outliers",
            severity=DiagSeverity.WARNING,
            title="The server flagged %d %s as a health outlier"
            % (len(outlier_nodes), _plural(len(outlier_nodes), "node")),
            lines=[
                "Nodes: %s." % (_summarize(sorted(outlier_nodes)),),
                "Run `health -v` for the full analysis.",
            ],
        )

    def _check_partition_availability(self) -> BundleWarning | None:
        dead = {}
        unavailable = {}

        for node, ns_data in self._ns_stats().items():
            if not isinstance(ns_data, dict):
                continue

            for ns, stats in ns_data.items():
                if not isinstance(stats, dict):
                    continue

                dead_count = _to_int(stats.get("dead_partitions"))
                unavailable_count = _to_int(stats.get("unavailable_partitions"))

                if dead_count:
                    dead["%s/%s" % (node, ns)] = dead_count

                if unavailable_count:
                    unavailable["%s/%s" % (node, ns)] = unavailable_count

        if not dead and not unavailable:
            return None

        lines = []

        if dead:
            lines.append(
                "dead_partitions is non-zero on: %s."
                % (
                    _summarize(
                        "%s=%d" % (key, val) for key, val in sorted(dead.items())
                    ),
                )
            )

        if unavailable:
            lines.append(
                "unavailable_partitions is non-zero on: %s."
                % (
                    _summarize(
                        "%s=%d" % (key, val) for key, val in sorted(unavailable.items())
                    ),
                )
            )

        lines.append(
            "Strong-consistency namespaces are missing data or cannot serve reads "
            "for those partitions. Run `health -v` and check the roster."
        )

        return BundleWarning(
            category="partition-availability",
            severity=DiagSeverity.ERROR,
            title="Partitions were dead or unavailable at collection time",
            lines=lines,
        )

    def _check_clock_skew(self) -> BundleWarning | None:
        worst = 0

        for stats in self._service_stats().values():
            if not isinstance(stats, dict):
                continue

            skew = _to_int(stats.get("cluster_clock_skew_ms"))

            if skew and skew > worst:
                worst = skew

        if worst < CLOCK_SKEW_WARN_MS:
            return None

        return BundleWarning(
            category="clock-skew",
            severity=DiagSeverity.WARNING,
            title="Intra-cluster clock skew reached %d ms" % (worst,),
            lines=[
                "Strong consistency and expiration depend on synchronized clocks. "
                "Check NTP on every node."
            ],
        )


###############################################################################
# Rendering.


_SEVERITY_COLOR = {
    DiagSeverity.INFO: terminal.fg_blue,
    DiagSeverity.WARNING: terminal.fg_yellow,
    DiagSeverity.ERROR: terminal.fg_red,
}


def render_banner(warnings: list[BundleWarning], use_color: bool = True) -> str:
    """Build the interactive-intro banner.

    Returns a string rather than printing: the log handler's __str__ is the only
    caller and it has no view to print through. The intro already prints a
    'Collected by' line, so a version finding with nothing to act on is dropped here
    instead of repeating it.
    """
    warnings = [
        warning
        for warning in warnings
        if warning.category not in BANNER_REDUNDANT_CATEGORIES
    ]

    if not warnings:
        return ""

    def colorize(severity: DiagSeverity, text: str) -> str:
        if not use_color:
            return text

        return _SEVERITY_COLOR[severity]() + text + terminal.fg_clear()

    out = [
        "",
        (
            BANNER_TITLE
            if not use_color
            else terminal.bold() + BANNER_TITLE + terminal.unbold()
        ),
    ]

    for warning in warnings:
        out.append(
            " %s"
            % colorize(
                warning.severity,
                "%s: %s" % (warning.severity.value, warning.title),
            )
        )

        for line in warning.lines:
            out.append("   %s" % (line,))

        if warning.table:
            out.append(warning.table.rstrip("\n"))
        else:
            for line in warning.table_lines:
                out.append("   %s" % (line,))

    out.append("")

    return "\n".join(out) + "\n"


def emit_to_log(warnings: list[BundleWarning], log: logging.Logger) -> None:
    """Re-emit the banner through the logger for --execute mode.

    The log formatter already colors and prefixes by level, so the message text
    must stay plain.
    """
    if not warnings:
        return

    for warning in warnings:
        message = warning.title
        detail = list(warning.lines) + list(warning.table_lines)

        if detail:
            message += " " + " ".join(line.strip() for line in detail)

        if warning.severity is DiagSeverity.ERROR:
            log.error(message)
        elif warning.severity is DiagSeverity.WARNING:
            log.warning(message)
        else:
            log.info(message)
