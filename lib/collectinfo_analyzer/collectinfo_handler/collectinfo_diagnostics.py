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
import sys
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


def _numeric_version(value: str) -> str | None:
    """The leading numeric segments of a version string, or None if it has none.

    Comparisons use only these so a pre-release orders as its release:
    LooseVersion makes 2.23.0-rc1 newer than 2.23.0 because the longer component
    list wins, which would advise upgrading to a release candidate. It also
    refuses to order mixed int/str components at all, raising TypeError, and an
    RC collects the same sections as its release either way.
    """
    match = _NUMERIC_VERSION_RE.match(str(value or "").strip())

    return match.group(0) if match else None


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
        """The meta entry for the snapshot being analyzed, if the bundle has one.

        Only an exact timestamp match counts. A meta describing some other snapshot
        would report its expected nodes, dropped nodes, and per-node errors against
        this one, which is the false 'nodes are missing' claim these checks exist to
        remove. No match means no meta, and the heuristics take over.
        """
        if self._snapshot_meta is not None:
            return self._snapshot_meta

        self._snapshot_meta = {}
        snapshots = self.meta.get("snapshots")

        if not isinstance(snapshots, list) or not snapshots:
            return self._snapshot_meta

        for entry in snapshots:
            if isinstance(entry, dict) and entry.get("timestamp") == self.timestamp:
                self._snapshot_meta = entry
                break

        return self._snapshot_meta

    def has_meta(self) -> bool:
        """Whether collection-time metadata is available for the analyzed snapshot.

        Keyed off the snapshot entry rather than the file: a meta that describes a
        different snapshot must not suppress the heuristic checks that would still
        say something true about this one.
        """
        return bool(self.snapshot_meta())

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
            self._check_node_selection,
            self._check_dropped_or_missing_nodes,
            self._check_peer_visibility,
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

        unparsed = BundleWarning(
            category="collector-version-unparsed",
            severity=DiagSeverity.INFO,
            title="Collected by asadm %s" % (collector,),
            lines=[],
        )
        collected_numeric = _numeric_version(collector)
        analyzing_numeric = _numeric_version(running)

        if collected_numeric is None or analyzing_numeric is None:
            return unparsed

        try:
            collected = version.LooseVersion(collected_numeric)
            analyzing = version.LooseVersion(analyzing_numeric)
            is_older, is_newer = collected < analyzing, collected > analyzing
        except Exception:
            return unparsed

        if is_older:
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

        if is_newer:
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
                    "asadm connected to these nodes but every information call "
                    "failed, so no command can report anything: %s."
                    % (_summarize(sorted(node_names)),),
                    "Re-collect from a host that can reach the cluster, raising "
                    "--timeout if the nodes are slow to respond.",
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
            lines.append("Reason: %s" % (detection_error,))

            no_data = snapshot_meta.get("no_data_nodes") or []

            if no_data:
                lines.append(
                    "Recorded before reconciliation failed: %d %s connected to "
                    "but returned no data: %s."
                    % (
                        len(no_data),
                        _plural(len(no_data), "node was", "nodes were"),
                        _summarize(sorted(no_data)),
                    )
                )

            lines.append(
                "Nodes advertised by the cluster but never collected cannot be "
                "confirmed for this bundle."
            )

            return BundleWarning(
                category="node-discrepancy-detection-failed",
                severity=DiagSeverity.WARNING,
                title="Node reconciliation did not complete during collection",
                lines=lines,
            )

        dropped = discrepancies.get("dropped_during_collection") or []
        missing = discrepancies.get("missing_from_collection") or []
        expected = snapshot_meta.get("expected_nodes") or []
        responded = snapshot_meta.get("responded_nodes") or []

        if self._collected_node_subset() is not None:
            missing = []

        if not dropped and not missing:
            return None

        if expected and responded:
            lines.append(
                "Collected %d of %d nodes asadm was connected to."
                % (len(responded), len(expected))
            )

        if dropped:
            lines.append(
                "%d %s connected to but returned no data, so %s absent from every "
                "command below:"
                % (
                    len(dropped),
                    _plural(len(dropped), "node was", "nodes were"),
                    _plural(len(dropped), "it is", "they are"),
                )
            )
            for entry in dropped[:10]:
                lines.append(
                    "  %s (%s)"
                    % (entry.get("node_key", "unknown"), entry.get("reason", "unknown"))
                )

        if missing:
            lines.append(
                "%d %s advertised as a cluster peer but never collected, so asadm "
                "never connected to %s:"
                % (
                    len(missing),
                    _plural(len(missing), "node was", "nodes were"),
                    _plural(len(missing), "it", "them"),
                )
            )
            for entry in missing[:10]:
                lines.append(
                    "  %s (%s)"
                    % (entry.get("node_key", "unknown"), entry.get("reason", "unknown"))
                )

        return BundleWarning(
            category="dropped-or-missing-nodes",
            severity=DiagSeverity.WARNING,
            title="Cluster nodes are missing from this bundle",
            lines=lines,
        )

    def _collected_node_subset(self) -> list[str] | None:
        """The node list the collection was limited to, or None if it collected all.

        Recorded from TOOLS-4135 onward. Older bundles return None, which is the
        same answer as a full collection: neither can be told apart from the data.
        """
        flags = (self.meta.get("collection") or {}).get("flags") or {}
        selection = flags.get("node_selection")

        if isinstance(selection, (list, tuple)) and selection:
            return [str(node) for node in selection]

        return None

    def _check_node_selection(self) -> BundleWarning | None:
        """A deliberately partial collection, stated so it is not read as a fault.

        `collectinfo with <nodes>` collects only the nodes named. Every other
        cluster node is then advertised in the collected nodes' peer lists and
        present nowhere else, which is indistinguishable from a node asadm could
        not reach unless the selection itself is recorded.
        """
        subset = self._collected_node_subset()

        if subset is None:
            return None

        lines = ["Requested: %s." % (_summarize(subset),)]
        excluded = sorted(
            entry.get("node_key", "unknown")
            for entry in (self.snapshot_meta().get("discrepancies") or {}).get(
                "missing_from_collection"
            )
            or []
        )

        if excluded:
            lines.append(
                "%d other cluster %s never contacted, so %s absent from every "
                "command below: %s."
                % (
                    len(excluded),
                    _plural(len(excluded), "node was", "nodes were"),
                    _plural(len(excluded), "it is", "they are"),
                    _summarize(excluded),
                )
            )

        return BundleWarning(
            category="partial-node-selection",
            severity=DiagSeverity.INFO,
            title="Collection was limited to %d %s"
            % (len(subset), _plural(len(subset), "node")),
            lines=lines,
        )

    def _check_peer_visibility(self) -> BundleWarning | None:
        """Peer-visibility problems recorded live at collection time.

        Separate from the missing-node finding: these nodes were collected fine, it
        is the cluster's own view of them that was broken. This is the offline
        equivalent of the live-mode startup warnings, and it cannot be recomputed
        from a bundle, so it is only available for bundles that recorded it.
        """
        if not self.has_meta():
            return None

        discrepancies = self.snapshot_meta().get("discrepancies") or {}
        down = discrepancies.get("cluster_down_nodes") or []
        visibility = discrepancies.get("visibility_error_nodes") or []
        lines = []

        if down:
            lines.append(
                "Named in other nodes' peer lists but unreachable by them: %s."
                % (_summarize(down),)
            )

        if visibility:
            lines.append(
                "Could not see every other node in the cluster: %s."
                % (_summarize(visibility),)
            )

        if not lines:
            return None

        lines.append(
            "Recorded live while collecting, so it reflects the cluster at that "
            "moment. Check heartbeat configuration and the network between them."
        )

        return BundleWarning(
            category="peer-visibility",
            severity=DiagSeverity.WARNING,
            title="Nodes could not see each other at collection time",
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

        unseen = sorted(peer_keys - self._known_endpoints(present))

        if unseen:
            lines.append(
                "Advertised as cluster peers but not present in the bundle: %s. "
                "These may be uncollected nodes or alternate addresses of "
                "collected ones." % (_summarize(unseen),)
            )

        if not lines:
            return None

        lines.append(
            "This bundle predates collection-time node reconciliation, so these "
            "are inferred from the collected data rather than recorded."
        )

        return BundleWarning(
            category="dropped-or-missing-nodes",
            severity=DiagSeverity.WARNING,
            title="This bundle may be missing cluster nodes",
            lines=lines,
        )

    def _known_endpoints(self, present: set[str]) -> set[str]:
        """Every address the collected nodes are reachable at, not just their keys.

        A node's key is the address asadm connected to, while peers advertise
        whichever address their heartbeat mesh uses. Without folding in each
        collected node's own endpoints, a multi-homed cluster (seeded via localhost
        or FQDN while peers advertise internal IPs) reports every peer as missing.
        The collection-side counterpart does the same hop through cluster.aliases.
        """
        known = set(present)

        try:
            own = self.snapshot.get_own_endpoints() or {}
        except Exception:
            return known

        for node_key, endpoints in own.items():
            if node_key in present:
                known.update(endpoints)

        return known

    def _check_missing_sysinfo(self) -> BundleWarning | None:
        """Report sysinfo coverage.

        asadm gathers system statistics locally for the node it runs on, and over SSH
        for the rest only when --enable-ssh is passed. So a bundle covering exactly
        one node is the ordinary outcome of a plain collect and is reported as
        information; a bundle covering none means collectinfo ran off-cluster and
        nothing host-level was captured at all, which is the case worth warning about.

        Nodes that returned no data at all are excluded from both counts: they are
        already reported as dropped, and their missing sysinfo is a consequence of
        that rather than a separate finding.
        """
        node_names = self._node_names()

        if not node_names:
            return None

        empty_nodes = set(self._nodes_without_as_stat())
        responded = [node for node in sorted(node_names) if node not in empty_nodes]

        if not responded:
            return None

        with_sysinfo = []
        without_sysinfo = []

        for node in responded:
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
                "`summary` and `info network` cannot report on CPU, memory, "
                "disks, or the OS." % (len(responded),),
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

        if not without_sysinfo:
            return BundleWarning(
                category="missing-sysinfo-files",
                severity=DiagSeverity.INFO,
                title="Bundle has no sysinfo.log or aerospike.conf",
                lines=[
                    "System statistics were captured for every node that responded, "
                    "but the two host files asadm writes only when it runs on a "
                    "cluster node are absent."
                ],
            )

        lines = [
            "Captured for %s. No host-level data for the other %s: %s."
            % (
                _summarize(with_sysinfo),
                (
                    "node"
                    if len(without_sysinfo) == 1
                    else "%d nodes" % (len(without_sysinfo),)
                ),
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
            % (len(with_sysinfo), len(responded)),
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
        """Sections that failed to collect, per node.

        Entries classed as unsupported are dropped: they record a section this
        cluster never had (ACL on a security-disabled cluster, user-agents or
        masking on an older server) rather than data that was lost. They stay in
        the meta for debugging, but reporting them would fire on most bundles.
        """
        nodes_meta = (
            (self.snapshot_meta().get("nodes") or {}) if self.has_meta() else {}
        )

        if not nodes_meta:
            return None

        rows: dict[str, dict[str, str]] = {}
        node_names: dict[str, str] = {}
        recovered = 0

        for node_key, node_meta in sorted(nodes_meta.items()):
            errors = [
                error
                for error in ((node_meta or {}).get("errors") or [])
                if error.get("error_class")
                != constants.CollectinfoErrorClass.UNSUPPORTED
            ]
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
                    lines=["Nothing is missing from this bundle as a result."],
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
        lines = [
            "Those sections are empty for those nodes, so commands reading them show "
            "no rows rather than reporting an error."
        ]

        if recovered:
            lines.append(
                "%d further %s recovered on retry; nothing is missing as a result."
                % (recovered, _plural(recovered, "error"))
            )

        return BundleWarning(
            category="node-collection-errors",
            severity=DiagSeverity.WARNING,
            title="Collection failed for some sections on %d %s"
            % (len(rows), _plural(len(rows), "node")),
            lines=lines,
            table=table,
            table_lines=table_lines,
        )

    def _check_empty_and_partial_nodes(self) -> BundleWarning | None:
        """Nodes that answered some calls but not all.

        Fully empty nodes are excluded when the bundle's meta recorded them, since
        the dropped-node finding already reports them and repeating them here would
        put the same node in three separate findings. Old bundles carry no such
        record and none of the heuristics can see an empty node (it is present, so
        neither cluster_size nor the peer list disagrees), so for them the empty
        nodes are reported here instead.
        """
        node_names = self._node_names()
        empty_nodes = set(self._nodes_without_as_stat())
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

        if not self.has_meta():
            present_empty = sorted(node for node in empty_nodes if node in node_names)

            if present_empty:
                lines.append(
                    "No Aerospike data at all for: %s." % (_summarize(present_empty),)
                )

        if no_statistics:
            lines.append("No statistics for: %s." % (_summarize(no_statistics),))

        if no_config:
            lines.append("No config for: %s." % (_summarize(no_config),))

        if not lines:
            return None

        lines.append(
            "`show statistics` and `show config` will render those nodes blank."
        )

        return BundleWarning(
            category="partial-nodes",
            severity=DiagSeverity.WARNING,
            title="Some nodes answered only part of the collection",
            lines=lines,
        )

    def _check_multiple_snapshots(self) -> BundleWarning | None:
        count = getattr(self.log_handler, "bundle_snapshot_count", 0) or 0

        if count <= 1:
            return None

        return BundleWarning(
            category="multiple-snapshots",
            severity=DiagSeverity.INFO,
            title="Bundle holds %d snapshots; only the newest is analyzed" % (count,),
            lines=[
                "Showing %s. The older snapshots are in ascinfo.json but no command "
                "reads them, so any change between snapshots is invisible here."
                % (self.timestamp,)
            ],
        )

    def _check_bundle_age(self) -> BundleWarning | None:
        """Age is a fact about the bundle, not a fault, so it stays informational."""
        try:
            collected = time.strptime(self.timestamp, TIMESTAMP_FORMAT)
        except Exception:
            return None

        age_days = int((time.time() - calendar.timegm(collected)) / 86400)

        if age_days < BUNDLE_STALE_DAYS:
            return None

        return BundleWarning(
            category="stale-bundle",
            severity=DiagSeverity.INFO,
            title="Bundle was collected %d days ago" % (age_days,),
            lines=[
                "Everything below describes the cluster as of %s, not as it is now."
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
                "cluster_is_member is false, so these nodes had formed no cluster of "
                "their own: %s." % (_summarize(orphans),)
            )

        disagreements = []

        if len(cluster_keys) > 1:
            disagreements.append(
                "%d cluster keys (%s)"
                % (len(cluster_keys), _summarize(sorted(cluster_keys)))
            )

        if len(principals) > 1:
            disagreements.append(
                "%d principals (%s)" % (len(principals), _summarize(sorted(principals)))
            )

        if len(cluster_sizes) > 1:
            disagreements.append(
                "%d cluster sizes (%s)"
                % (len(cluster_sizes), _summarize(sorted(cluster_sizes)))
            )

        if disagreements:
            lines.append(
                "Nodes do not agree on the cluster they are in: %s."
                % (", ".join(disagreements),)
            )
            lines.append(
                "That is a split cluster, or a cluster that re-formed while the "
                "bundle was being collected. `info network` shows which nodes agree."
            )
        elif lines:
            lines.append("Run `info network` for the per-node view.")

        if not lines:
            return None

        return BundleWarning(
            category="cluster-state",
            severity=DiagSeverity.WARNING,
            title="Cluster membership was unhealthy at collection time",
            lines=lines,
        )

    def _check_migrations(self) -> BundleWarning | None:
        """Report which nodes were migrating, not a summed partition count.

        migrate_partitions_remaining is per node and counts both incoming and
        outgoing partitions, so a total across nodes double counts the same work and
        would be a number the user cannot reconcile with any command.
        """
        migrating: dict[str, int] = {}
        node_count = 0

        for ns_data in self._ns_stats().values():
            if not isinstance(ns_data, dict):
                continue

            node_migrating = False

            for ns, stats in ns_data.items():
                if not isinstance(stats, dict):
                    continue

                value = _to_int(stats.get("migrate_partitions_remaining"))

                if value and value > 0:
                    migrating[ns] = max(migrating.get(ns, 0), value)
                    node_migrating = True

            if node_migrating:
                node_count += 1

        if not migrating:
            return None

        return BundleWarning(
            category="migrations",
            severity=DiagSeverity.INFO,
            title="Migrations were in progress on %d %s"
            % (node_count, _plural(node_count, "node")),
            lines=[
                "Namespaces migrating (most partitions remaining on any one node): "
                "%s."
                % (
                    _summarize(
                        "%s=%d" % (ns, count) for ns, count in sorted(migrating.items())
                    ),
                ),
                "Object counts, storage usage, and per-node balance in this bundle "
                "are mid-flight. Run `info namespace` for the per-namespace view.",
            ],
        )

    def _check_mixed_server_versions(self) -> BundleWarning | None:
        """Flag mixed builds and mixed editions separately.

        The raw meta_data 'edition' value is a full version string
        ("Aerospike Enterprise Edition build 8.1.1.0"), so it is read through the
        snapshot's edition stanza, which reduces it to Enterprise / Community /
        Federal. Reading it raw would report the build twice under two names.
        """
        builds = {
            str(node_meta["asd_build"])
            for node_meta in self._meta_data().values()
            if isinstance(node_meta, dict) and node_meta.get("asd_build")
        }
        editions = {
            str(edition)
            for edition in self._data("meta_data", "edition").values()
            if edition and str(edition) != "N/E"
        }

        lines = []

        if len(builds) > 1:
            lines.append("Server builds present: %s." % (_summarize(sorted(builds)),))

        if len(editions) > 1:
            lines.append(
                "Server editions present: %s. A cluster is not supported with mixed "
                "editions." % (_summarize(sorted(editions)),)
            )

        if not lines:
            return None

        if len(builds) > 1 and len(editions) <= 1:
            lines.append(
                "Expected mid rolling upgrade; otherwise the cluster is running "
                "unintended versions. Run `summary` for the per-node breakdown."
            )
        else:
            lines.append("Run `summary` for the per-node breakdown.")

        return BundleWarning(
            category="mixed-server-versions",
            severity=DiagSeverity.WARNING,
            title=(
                "Cluster is running more than one server version"
                if len(builds) > 1
                else "Cluster is running more than one server edition"
            ),
            lines=lines,
        )

    def _check_best_practices(self) -> BundleWarning | None:
        """Practices the server itself reports as violated.

        meta_data.best_practices holds the list of violated check names; the service
        statistic failed_best_practices is the fallback for bundles collected before
        that key was stored, and is only a boolean.
        """
        failing_nodes = set()
        practice_names = set()

        for node, node_meta in self._meta_data().items():
            if not isinstance(node_meta, dict):
                continue

            practices = node_meta.get(constants.METADATA_PRACTICES)

            if practices and not isinstance(practices, str):
                failing_nodes.add(node)
                practice_names.update(str(practice) for practice in practices)

        if not failing_nodes:
            for node, stats in self._service_stats().items():
                if isinstance(stats, dict) and _is_true(
                    stats.get("failed_best_practices")
                ):
                    failing_nodes.add(node)

        if not failing_nodes:
            return None

        lines = ["Nodes: %s." % (_summarize(sorted(failing_nodes)),)]

        if practice_names:
            lines.append("Violated: %s." % (_summarize(sorted(practice_names)),))

        lines.append(
            "The server evaluates these at startup, so they persist until the "
            "underlying configuration is fixed. Run `show best-practices` for the "
            "per-node breakdown."
        )

        return BundleWarning(
            category="best-practices",
            severity=DiagSeverity.WARNING,
            title="%d %s violating Aerospike best-practices"
            % (len(failing_nodes), _plural(len(failing_nodes), "node is", "nodes are")),
            lines=lines,
        )

    def _check_health_outliers(self) -> BundleWarning | None:
        """Outliers the server's own health-outliers command reported.

        Net-new consumption for the analyzer: the data was already in every bundle
        under meta_data.health but no command read it.

        A node with no outliers still carries a placeholder entry: the server
        returns an empty string, and Node.info_health_outliers turns that into
        {"outlier0": {}} rather than {}. Only entries that actually hold something
        count, otherwise every healthy node reads as an outlier.
        """
        outlier_nodes = {}
        reasons = set()

        for node, node_meta in self._meta_data().items():
            if not isinstance(node_meta, dict):
                continue

            health = node_meta.get("health")

            if isinstance(health, str) or not util.has_content(health):
                continue

            outlier_nodes[node] = health

            if isinstance(health, dict):
                for outlier in health.values():
                    if isinstance(outlier, dict):
                        reason = outlier.get("reason") or outlier.get("confidence")

                        if reason:
                            reasons.add(str(reason))

        if not outlier_nodes:
            return None

        lines = ["Nodes: %s." % (_summarize(sorted(outlier_nodes)),)]

        if reasons:
            lines.append("Reported as: %s." % (_summarize(sorted(reasons)),))

        lines.append(
            "The server compares each node against its peers, so an outlier is "
            "usually a node behaving differently from the rest. Compare the flagged "
            "nodes with `show statistics`."
        )

        return BundleWarning(
            category="health-outliers",
            severity=DiagSeverity.WARNING,
            title="The server flagged %d %s as a health outlier"
            % (len(outlier_nodes), _plural(len(outlier_nodes), "node")),
            lines=lines,
        )

    def _check_partition_availability(self) -> BundleWarning | None:
        """Dead and unavailable partitions mean data loss or unreadable data.

        The server emits both stats for every namespace but they are only ever
        non-zero under strong consistency, so the namespace's strong-consistency
        config decides the wording rather than being assumed.
        """
        dead: dict[str, int] = {}
        unavailable: dict[str, int] = {}
        namespaces = set()

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
                    namespaces.add(ns)

                if unavailable_count:
                    unavailable["%s/%s" % (node, ns)] = unavailable_count
                    namespaces.add(ns)

        if not dead and not unavailable:
            return None

        lines = []

        if dead:
            lines.append(
                "dead_partitions (data lost, no copy left in the cluster): %s."
                % (
                    _summarize(
                        "%s=%d" % (key, val) for key, val in sorted(dead.items())
                    ),
                )
            )

        if unavailable:
            lines.append(
                "unavailable_partitions (data exists but cannot be read or written): "
                "%s."
                % (
                    _summarize(
                        "%s=%d" % (key, val) for key, val in sorted(unavailable.items())
                    ),
                )
            )

        if self._strong_consistency_namespaces() & namespaces:
            lines.append(
                "Run `show roster`: for a strong-consistency namespace this usually "
                "means the roster no longer covers every partition."
            )
        else:
            lines.append(
                "These are normally zero outside strong consistency. Check the "
                "namespace configuration."
            )

        return BundleWarning(
            category="partition-availability",
            severity=DiagSeverity.ERROR,
            title="Partitions were dead or unavailable at collection time",
            lines=lines,
        )

    def _strong_consistency_namespaces(self) -> set[str]:
        strong = set()

        for ns_data in self._data("config", constants.CONFIG_NAMESPACE).values():
            if not isinstance(ns_data, dict):
                continue

            for ns, config in ns_data.items():
                if isinstance(config, dict) and _is_true(
                    config.get("strong-consistency")
                ):
                    strong.add(ns)

        return strong

    def _check_clock_skew(self) -> BundleWarning | None:
        """Compare measured skew against the cluster's own stop-writes threshold.

        A bare millisecond figure means little on its own, so where the server
        reports cluster_clock_skew_stop_writes_sec the warning states the point at
        which writes stop. That threshold only governs strong-consistency
        namespaces (AP namespaces use a fixed 40 s, and only with nsup enabled), so
        the line is omitted when the cluster has none.
        """
        worst = 0
        threshold_sec = None

        for stats in self._service_stats().values():
            if not isinstance(stats, dict):
                continue

            skew = _to_int(stats.get("cluster_clock_skew_ms"))

            if skew and skew > worst:
                worst = skew

            configured = _to_int(stats.get("cluster_clock_skew_stop_writes_sec"))

            if configured:
                threshold_sec = max(threshold_sec or 0, configured)

        if worst < CLOCK_SKEW_WARN_MS:
            return None

        lines = [
            "Strong consistency, expiration, and truncate all depend on "
            "synchronized clocks. Check NTP on every node."
        ]

        if threshold_sec and self._strong_consistency_namespaces():
            lines.insert(
                0,
                "Strong-consistency namespaces stop taking writes at %d ms "
                "(cluster_clock_skew_stop_writes_sec is %d)."
                % (threshold_sec * 1000, threshold_sec),
            )

        return BundleWarning(
            category="clock-skew",
            severity=DiagSeverity.WARNING,
            title="Clock skew between nodes reached %d ms" % (worst,),
            lines=lines,
        )


###############################################################################
# Rendering.


_SEVERITY_COLOR = {
    DiagSeverity.INFO: terminal.fg_blue,
    DiagSeverity.WARNING: terminal.fg_yellow,
    DiagSeverity.ERROR: terminal.fg_red,
}


def render_banner(
    warnings: list[BundleWarning],
    use_color: bool = True,
    skip_redundant: bool = True,
) -> str:
    """Build the diagnostics banner.

    Returns a string rather than printing: the log handler's __str__ is the only
    interactive caller and it has no view to print through. The interactive intro
    already prints a 'Collected by' line, so a version finding with nothing to act
    on is dropped by default. Execute mode has no intro and passes
    skip_redundant=False to keep provenance.
    """
    if skip_redundant:
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


def print_banner(warnings: list[BundleWarning], stream=None) -> None:
    """Write the banner to stderr for --execute mode, which prints no intro.

    Deliberately not routed through asadm's logger. Diagnostics describe the
    bundle, not the command the user ran, and BaseLogger.error sets the process
    exit code, so an unhealthy cluster in the bundle would fail an otherwise
    successful command. The logger's WARNING level filter would also drop every
    INFO finding, including the provenance line. stderr keeps stdout parseable for
    a mode built to be scripted, and is colored only when it is a terminal: the
    global color state follows stdout, which says nothing about a redirected stderr.
    """
    stream = sys.stderr if stream is None else stream
    banner = render_banner(
        warnings,
        use_color=bool(getattr(stream, "isatty", bool)()),
        skip_redundant=False,
    )

    if not banner:
        return

    try:
        print(banner, end="", file=stream)
    except Exception as e:
        logger.debug("Could not print the diagnostics banner: %s", e)
