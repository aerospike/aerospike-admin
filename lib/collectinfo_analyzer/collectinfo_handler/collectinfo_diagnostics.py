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
nothing in the analyzer reported it. These checks run once at analyzer startup and surface
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
from typing import TYPE_CHECKING, Any, cast

from lib.utils import common, constants, util, version
from lib.utils.logger import BaseLogger
from lib.view import terminal
from lib.view.sheet import Field, Projectors, Sheet, render as sheet_render
from lib.view.sheet.render import get_style_json
from lib.view.terminal import terminal as terminal_state

if TYPE_CHECKING:
    from .collectinfo_log import _CollectinfoSnapshot
    from .log_handler import CollectinfoLogHandler

logger = cast(BaseLogger, logging.getLogger(__name__))
"""Importing lib.utils.logger above installs BaseLogger as the logger class, so
this module's logger matches production no matter who imports it first. That is
what gives the exit-code regression test teeth: BaseLogger.error sets the process
exit code, which is exactly what the banner must never do."""

BANNER_TITLE = "Collectinfo Bundle Diagnostics"
BANNER_REDUNDANT_CATEGORIES = frozenset(
    ("collector-version-match", "collector-version-unparsed")
)
BUNDLE_STALE_DAYS = 7
CLOCK_SKEW_WARN_MS = 1000
AP_NSUP_CLOCK_SKEW_STOP_WRITES_MS = 40000
NODE_LIST_LIMIT = 10
TIMESTAMP_FORMAT = constants.COLLECTINFO_TIMESTAMP_FORMAT
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
    """Plain-text rows, used when the sheet renderer is unavailable or unusable."""


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


def _selector_matches(selector: str, node_key: str) -> bool:
    """Whether a `collectinfo with` selector plausibly names this node key.

    Selectors may be IPs, FQDNs, node IDs, or prefix wildcards, while node keys
    are ip:port, so this is a heuristic that must only ever promote a finding's
    severity, never suppress one. It matches an exact key, a bare address (the
    key with its port stripped), or a non-empty wildcard prefix; a substring
    test would let a selector for 1.1.1.1 claim 11.1.1.1:3000 was requested.
    """
    selector = str(selector)

    if selector.endswith("*"):
        prefix = selector.rstrip("*")
        return bool(prefix) and node_key.startswith(prefix)

    return node_key == selector or node_key.startswith(selector + ":")


def _node_sort_key(node_key: str) -> list[tuple[int, Any]]:
    """Numeric ordering for node keys, so 10.0.0.2 sorts before 10.0.0.10.

    String sort puts .10 before .2, which makes every truncated sample an
    artifact of the dotted-quad spelling rather than the lowest-numbered nodes.
    Each part is tagged so hostnames and numbers never compare directly.
    """
    return [
        (0, int(part)) if part.isdigit() else (1, part)
        for part in re.split(r"[.:\[\]]+", str(node_key))
        if part
    ]


def _sorted_nodes(nodes) -> list[str]:
    return sorted(nodes, key=_node_sort_key)


def _format_partition_counts(per_ns: dict[str, dict[str, int]]) -> str:
    """One complete clause per namespace: total, node spread, and worst node."""
    parts = []

    for ns in sorted(per_ns):
        nodes = per_ns[ns]
        worst = max(nodes, key=lambda node: nodes[node])
        parts.append(
            "%s %d across %d %s (worst %s = %d)"
            % (
                ns,
                sum(nodes.values()),
                len(nodes),
                _plural(len(nodes), "node"),
                worst,
                nodes[worst],
            )
        )

    return _summarize(parts)


class CollectinfoDiagnostics:
    def __init__(
        self,
        log_handler: "CollectinfoLogHandler",
        snapshot: "_CollectinfoSnapshot",
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

    def _collection_flags(self) -> dict[str, Any]:
        """The flags recorded at collection time, or {} for a bundle without them."""
        flags = (self.meta.get("collection") or {}).get("flags")

        return flags if isinstance(flags, dict) else {}

    def snapshot_meta(self) -> dict[str, Any]:
        """The meta entry for the snapshot being analyzed, if the bundle has one.

        Only an exact timestamp match counts. A meta describing some other snapshot
        would report its expected nodes, dropped nodes, and per-node errors against
        this one, which is the false 'nodes are missing' claim these checks exist to
        remove. No match means no meta, and the heuristics take over.

        The last match wins: sub-second snapshots can share a timestamp, and the
        writer keeps the last snapshot's data under that key.
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
            self._check_meta_format_version,
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

    def _check_meta_format_version(self) -> BundleWarning | None:
        """A meta written by a newer asadm is read best-effort, and this says so.

        Unknown fields are ignored and absent fields mean 'not recorded', so the
        fields this asadm understands are still used rather than the file being
        rejected. Without this finding, detail recorded in a newer format would
        silently read as a clean collection.
        """
        if not self.meta:
            return None

        format_version = _to_int(self.meta.get("meta_format_version"))

        if (
            format_version is None
            or format_version <= constants.COLLECTINFO_META_FORMAT_VERSION
        ):
            return None

        return BundleWarning(
            category="meta-format-newer",
            severity=DiagSeverity.WARNING,
            title="Bundle metadata is format v%d; this asadm understands v%d"
            % (format_version, constants.COLLECTINFO_META_FORMAT_VERSION),
            lines=[
                "The fields this asadm knows are still read, but collection "
                "detail added in newer formats is not reported here. Upgrade "
                "asadm to see everything the bundle recorded."
            ],
        )

    def _check_zero_usable_nodes(self) -> BundleWarning | None:
        """Compare the empty set against the named set as sets.

        nodes_without_as_stat and get_node_names apply different guards to a
        malformed node entry, so comparing their counts can declare a bundle
        empty while naming its healthy nodes. Intersecting first keeps both the
        verdict and the node list inside one node universe.
        """
        node_names = self._node_names()

        if not node_names:
            return BundleWarning(
                category="no-usable-nodes",
                severity=DiagSeverity.ERROR,
                title="Bundle contains no nodes",
                lines=["No node data could be read from this bundle."],
            )

        present = set(node_names)
        empty_nodes = set(self._nodes_without_as_stat()) & present

        if empty_nodes and empty_nodes == present:
            return BundleWarning(
                category="no-usable-nodes",
                severity=DiagSeverity.ERROR,
                title="Bundle contains no Aerospike data for any of its %d nodes"
                % (len(node_names),),
                lines=[
                    "asadm connected to these nodes but every information call "
                    "failed, so no command can report anything: %s."
                    % (_summarize(_sorted_nodes(empty_nodes)),),
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

        if self._collected_node_subset() is not None or self._collection_flags().get(
            "only_connect_seed"
        ):
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
            for entry in dropped[:NODE_LIST_LIMIT]:
                lines.append(
                    "  %s (%s)"
                    % (entry.get("node_key", "unknown"), entry.get("reason", "unknown"))
                )

            if len(dropped) > NODE_LIST_LIMIT:
                lines.append(
                    "  (and %d more; the full list is in %s)"
                    % (
                        len(dropped) - NODE_LIST_LIMIT,
                        constants.COLLECTINFO_META_FILENAME,
                    )
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
            for entry in missing[:NODE_LIST_LIMIT]:
                lines.append(
                    "  %s (%s)"
                    % (entry.get("node_key", "unknown"), entry.get("reason", "unknown"))
                )

            if len(missing) > NODE_LIST_LIMIT:
                lines.append(
                    "  (and %d more; the full list is in %s)"
                    % (
                        len(missing) - NODE_LIST_LIMIT,
                        constants.COLLECTINFO_META_FILENAME,
                    )
                )

        return BundleWarning(
            category="dropped-or-missing-nodes",
            severity=DiagSeverity.WARNING,
            title="Cluster nodes are missing from this bundle",
            lines=lines,
        )

    def _collected_node_subset(self) -> list[str] | None:
        """The node list the collection was limited to, or None if it collected all.

        Only bundles carrying collectinfo_meta.json (meta_format_version 1 and
        later) record it. Older bundles return None, which is the same answer as a
        full collection: neither can be told apart from the data.
        """
        selection = self._collection_flags().get("node_selection")

        if isinstance(selection, (list, tuple)) and selection:
            return [str(node) for node in selection]

        return None

    def _check_node_selection(self) -> BundleWarning | None:
        """A deliberately partial collection, stated so it is not read as a fault.

        `collectinfo with <nodes>` collects only the nodes named, and
        --single-node stops the cluster crawl at the seed. Every other cluster
        node is then advertised in the collected nodes' peer lists and present
        nowhere else, which is indistinguishable from a node asadm could not
        reach unless the scope itself is recorded.

        The node count comes from the meta's expected_nodes rather than the
        selector list: a selector may be a prefix wildcard that resolves to many
        nodes. A requested node that was never collected is promoted back to a
        warning; the match between selectors and node keys is a heuristic
        (selectors may be node IDs, FQDNs, or bare IPs), so it only ever
        promotes, never suppresses.
        """
        subset = self._collected_node_subset()

        if subset is None:
            if self._collection_flags().get("only_connect_seed"):
                return BundleWarning(
                    category="partial-node-selection",
                    severity=DiagSeverity.INFO,
                    title="Collection was limited to the seed node by --single-node",
                    lines=[
                        "Peers advertised by the seed were deliberately not "
                        "contacted, so every command below shows the seed node "
                        "only."
                    ],
                )

            return None

        expected = self.snapshot_meta().get("expected_nodes") or []
        count = len(expected) or len(subset)
        lines = ["Requested: %s." % (_summarize(subset),)]
        excluded = sorted(
            entry.get("node_key", "unknown")
            for entry in (self.snapshot_meta().get("discrepancies") or {}).get(
                "missing_from_collection"
            )
            or []
        )
        requested_missing = [
            key
            for key in excluded
            if any(_selector_matches(sel, key) for sel in subset)
        ]
        other_missing = [key for key in excluded if key not in requested_missing]

        if requested_missing:
            lines.append(
                "%d requested %s never collected: %s."
                % (
                    len(requested_missing),
                    _plural(len(requested_missing), "node was", "nodes were"),
                    _summarize(requested_missing),
                )
            )

        if other_missing:
            lines.append(
                "%d other cluster %s never contacted, so %s absent from every "
                "command below: %s."
                % (
                    len(other_missing),
                    _plural(len(other_missing), "node was", "nodes were"),
                    _plural(len(other_missing), "it is", "they are"),
                    _summarize(other_missing),
                )
            )

        return BundleWarning(
            category="partial-node-selection",
            severity=(DiagSeverity.WARNING if requested_missing else DiagSeverity.INFO),
            title="Collection was limited to %d %s by `collectinfo with`"
            % (count, _plural(count, "node")),
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
        """Infer missing nodes for bundles that carry no collectinfo_meta.json.

        Such bundles record nothing about what was expected, so every statement
        here is a proxy and is phrased as such.
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

        unseen = _sorted_nodes(peer_keys - self._known_endpoints(present))

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
        """Report sysinfo coverage only when it differs from what was requested.

        asadm gathers system statistics locally for the node it runs on, and over
        SSH for the rest only when --enable-ssh is passed. A plain collect
        covering at most one node is therefore the documented outcome, not a gap,
        and stays silent; a finding that fires on every ordinary bundle would
        train readers to skip the whole banner. What is worth saying:

        - --enable-ssh was requested and some nodes still have no sysinfo, which
          means SSH to them failed during collection.
        - No node has sysinfo at all: collectinfo ran off-cluster without SSH.

        For bundles with no recorded flags the same inference applies: exactly
        one covered node is the ordinary shape and stays silent.

        Nodes that returned no data at all are excluded from both counts: they
        are already reported as dropped, and their missing sysinfo is a
        consequence of that rather than a separate finding.
        """
        node_names = self._node_names()

        if not node_names:
            return None

        empty_nodes = set(self._nodes_without_as_stat())
        responded = [
            node for node in _sorted_nodes(node_names) if node not in empty_nodes
        ]

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
        enable_ssh = bool(self._collection_flags().get("enable_ssh"))

        if enable_ssh and without_sysinfo:
            recorded_none = set(
                self._nodes_with_sysinfo_source(constants.SysinfoSource.NONE)
            )
            ssh_failed = _sorted_nodes(recorded_none & set(without_sysinfo)) or list(
                without_sysinfo
            )

            return BundleWarning(
                category="partial-sysinfo",
                severity=DiagSeverity.WARNING,
                title=(
                    "--enable-ssh was used but system information is missing "
                    "for %d of %d nodes" % (len(without_sysinfo), len(responded))
                ),
                lines=[
                    "No host-level data for %s. SSH to those hosts failed "
                    "during collection." % (_summarize(_sorted_nodes(ssh_failed)),),
                    "`health` cannot run its system checks for them and "
                    "`summary` reports no OS version.",
                ],
            )

        if not without_sysinfo and has_sysinfo_files is not False:
            return None

        if not with_sysinfo:
            lines = [
                "No host-level data was captured for any of the %d nodes, so "
                "`health` cannot run its system checks and `summary` reports "
                "no OS version." % (len(responded),),
                "collectinfo gathers system statistics locally for the node it runs "
                "on and over SSH for every other node, so this bundle was collected "
                "from a host that is not an Aerospike node, without --enable-ssh.",
            ]

            if has_sysinfo_files is False:
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

        if len(with_sysinfo) <= 1:
            return None

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
            "`health` cannot run its system checks for the uncovered nodes and "
            "`summary` reports no OS version for them.",
        ]

        if has_sysinfo_files is False:
            lines.append("The bundle has no sysinfo.log and no aerospike.conf either.")

        return BundleWarning(
            category="partial-sysinfo",
            severity=DiagSeverity.INFO,
            title="System information covers %d of %d nodes"
            % (len(with_sysinfo), len(responded)),
            lines=lines,
        )

    def _nodes_with_sysinfo_source(self, source: str) -> list[str]:
        """Node keys whose recorded sysinfo_source matches, from the meta."""
        nodes_meta = (
            (self.snapshot_meta().get("nodes") or {}) if self.has_meta() else {}
        )

        return sorted(
            node_key
            for node_key, node_meta in nodes_meta.items()
            if isinstance(node_meta, dict) and node_meta.get("sysinfo_source") == source
        )

    def _bundle_has_files(self, suffixes: tuple[str, ...]) -> bool | None:
        """Whether the bundle holds any file with these suffixes; None if unknown.

        'Unknown' is a real third state: folding a failed walk into True would
        make a check whose job is to report absence assert presence forever.
        """
        try:
            return bool(self.log_handler.bundle_files(suffixes))
        except Exception as e:
            logger.debug("Could not enumerate bundle files: %s", e, exc_info=True)
            return None

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
                {
                    constants.COLLECTINFO_ERROR_CLASS_REASON.get(
                        str(error.get("error_class", "")),
                        str(error.get("error_class", "?")),
                    )
                    for error in unrecovered
                }
            )
            rows[node_key] = {
                "sections": ", ".join(sections),
                "reason": ", ".join(reasons),
            }

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

        shown = dict(list(rows.items())[:NODE_LIST_LIMIT])
        table = self._render_node_errors_table(shown)
        table_lines = [
            "  %s: %s (%s)" % (node_key, row["sections"], row["reason"])
            for node_key, row in shown.items()
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

        if len(rows) > len(shown):
            lines.append(
                "Showing %d of %d affected nodes; the full list and the error "
                "messages are in %s inside the bundle."
                % (len(shown), len(rows), constants.COLLECTINFO_META_FILENAME)
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

    def _render_node_errors_table(self, rows: dict[str, dict[str, str]]) -> str | None:
        """Render the per-node error table, or None to use the plain-text rows.

        Skipped under --json: the sheet renderer consults the global style flag,
        which would embed a JSON document inside the banner's prose. The banner
        is a human artifact regardless of the output mode.

        Rendered with color disabled: the global palette follows stdout, which
        says nothing about the stream the banner lands on, so a colored table
        would carry raw escapes into a redirected stderr.
        """
        if get_style_json():
            return None

        was_color_enabled = terminal_state.color_enabled
        terminal_state.enable_color(False)

        try:
            return sheet_render(
                node_errors_sheet,
                "Per-node collection errors",
                dict(data=rows, node_names={key: key for key in rows}),
                common=dict(principal="", self_node=""),
            )
        except Exception as e:
            logger.debug("Could not render node error table: %s", e, exc_info=True)
            return None
        finally:
            terminal_state.enable_color(was_color_enabled)

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

        no_statistics = _sorted_nodes(
            node
            for node in node_names
            if node not in empty_nodes and not util.has_content(statistics.get(node))
        )
        no_config = _sorted_nodes(
            node
            for node in node_names
            if node not in empty_nodes and not util.has_content(configs.get(node))
        )

        lines = []

        if not self.has_meta():
            present_empty = _sorted_nodes(
                node for node in empty_nodes if node in node_names
            )

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
        count = self.log_handler.bundle_snapshot_count or 0

        if count <= 1:
            return None

        return BundleWarning(
            category="multiple-snapshots",
            severity=DiagSeverity.INFO,
            title="Bundle holds %d snapshots; diagnostics describe only the newest"
            % (count,),
            lines=[
                "These findings are computed from %s. Commands may render the "
                "other snapshots too, so their output can describe a different "
                "moment than this banner." % (self.timestamp,)
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
            totals = self._namespace_node_counts()
            parts = [
                "%s (%d of %d %s)"
                % (
                    ns,
                    len(nodes),
                    totals.get(ns, len(nodes)),
                    _plural(totals.get(ns, len(nodes)), "node"),
                )
                for ns, nodes in sorted(flagged.items())
            ]
            lines.append("Namespaces in stop-writes: %s." % (_summarize(parts),))

        lines.append("Run `show stop-writes` for the triggering metrics.")

        return BundleWarning(
            category="stop-writes",
            severity=DiagSeverity.ERROR,
            title="This cluster was in stop-writes when the bundle was collected",
            lines=lines,
        )

    def _namespaces_flagging_stop_writes(self) -> dict[str, set[str]]:
        """Nodes flagging stop_writes, per namespace.

        The derived summary only reports triggers whose usage and threshold metrics
        are both present in the bundle; the server's own flag catches the rest.
        Aggregated by namespace so the finding stays complete at any cluster size:
        a flat node/namespace pair list truncates on exactly the clusters where
        the blast radius matters most.
        """
        flagged: dict[str, set[str]] = {}

        for node, ns_data in self._ns_stats().items():
            if not isinstance(ns_data, dict):
                continue

            for ns, stats in ns_data.items():
                if not isinstance(stats, dict):
                    continue

                if _is_true(stats.get("stop_writes")) or _is_true(
                    stats.get("clock_skew_stop_writes")
                ):
                    flagged.setdefault(ns, set()).add(node)

        return flagged

    def _namespace_node_counts(self) -> dict[str, int]:
        """How many nodes carry each namespace, the denominator for per-ns claims."""
        counts: dict[str, int] = {}

        for ns_data in self._ns_stats().values():
            if not isinstance(ns_data, dict):
                continue

            for ns, stats in ns_data.items():
                if isinstance(stats, dict):
                    counts[ns] = counts.get(ns, 0) + 1

        return counts

    def _check_cluster_state(self) -> BundleWarning | None:
        service_stats = self._service_stats()

        if not service_stats:
            return None

        lines = []
        broken_integrity = _sorted_nodes(
            node
            for node, stats in service_stats.items()
            if isinstance(stats, dict) and _is_false(stats.get("cluster_integrity"))
        )
        orphans = _sorted_nodes(
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

        The node count comes from the service statistic
        migrate_partitions_remaining, which is per node and counts both incoming
        and outgoing partitions; a total across nodes would double count the same
        work and be a number the user cannot reconcile with any command. The
        per-namespace detail comes from the namespace-level
        migrate_tx/rx_partitions_remaining pair, because the service-level name
        does not exist in namespace statistics.
        """
        migrating: dict[str, int] = {}
        node_count = 0
        ns_node_count = 0

        for stats in self._service_stats().values():
            if not isinstance(stats, dict):
                continue

            if (_to_int(stats.get("migrate_partitions_remaining")) or 0) > 0:
                node_count += 1

        for ns_data in self._ns_stats().values():
            if not isinstance(ns_data, dict):
                continue

            node_migrating = False

            for ns, stats in ns_data.items():
                if not isinstance(stats, dict):
                    continue

                remaining = (
                    _to_int(stats.get("migrate_tx_partitions_remaining")) or 0
                ) + (_to_int(stats.get("migrate_rx_partitions_remaining")) or 0)

                if remaining > 0:
                    migrating[ns] = max(migrating.get(ns, 0), remaining)
                    node_migrating = True

            if node_migrating:
                ns_node_count += 1

        node_count = node_count or ns_node_count

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
        statistic failed_best_practices is only a boolean but exists on every node,
        so it backstops both bundles collected before the metadata key was stored
        and individual nodes whose best-practices call failed during collection.
        The two sources are unioned per node: gating the fallback on the whole
        bundle would let one node's metadata hide every other node's violation.
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

        for node, stats in self._service_stats().items():
            if isinstance(stats, dict) and _is_true(stats.get("failed_best_practices")):
                failing_nodes.add(node)

        if not failing_nodes:
            return None

        lines = ["Nodes: %s." % (_summarize(_sorted_nodes(failing_nodes)),)]

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

        lines = ["Nodes: %s." % (_summarize(_sorted_nodes(outlier_nodes)),)]

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

        Aggregated per namespace with a node count and the worst node, so the
        line answers 'which namespaces, and how widespread' at any cluster size
        instead of truncating a node/namespace pair list.
        """
        dead: dict[str, dict[str, int]] = {}
        unavailable: dict[str, dict[str, int]] = {}
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
                    dead.setdefault(ns, {})[node] = dead_count
                    namespaces.add(ns)

                if unavailable_count:
                    unavailable.setdefault(ns, {})[node] = unavailable_count
                    namespaces.add(ns)

        if not dead and not unavailable:
            return None

        lines = []

        if dead:
            lines.append(
                "dead_partitions (data lost, no copy left in the cluster): %s."
                % (_format_partition_counts(dead),)
            )

        if unavailable:
            lines.append(
                "unavailable_partitions (data exists but cannot be read or written): "
                "%s." % (_format_partition_counts(unavailable),)
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
        """Warn relative to the cluster's own stop-writes threshold.

        Strong-consistency namespaces stop taking writes at
        cluster_clock_skew_stop_writes_sec; AP namespaces stop at a fixed 40 s,
        and only with nsup enabled. The trigger is three quarters of whichever
        threshold governs this cluster, matching the rule the health checks use,
        so the warning fires when skew is approaching the point where something
        actually happens rather than at an absolute constant. A cluster where
        neither threshold applies falls back to that constant. When nodes
        disagree on the configured value the lowest wins, because that is the
        node that stops writes first.
        """
        worst = 0
        configured_sec: list[int] = []

        for stats in self._service_stats().values():
            if not isinstance(stats, dict):
                continue

            skew = _to_int(stats.get("cluster_clock_skew_ms"))

            if skew and skew > worst:
                worst = skew

            configured = _to_int(stats.get("cluster_clock_skew_stop_writes_sec"))

            if configured:
                configured_sec.append(configured)

        strong_consistency = bool(self._strong_consistency_namespaces())
        threshold_ms = None

        if strong_consistency and configured_sec:
            threshold_ms = min(configured_sec) * 1000
        elif self._nsup_enabled_ap_namespaces():
            threshold_ms = AP_NSUP_CLOCK_SKEW_STOP_WRITES_MS

        trigger = CLOCK_SKEW_WARN_MS if threshold_ms is None else threshold_ms * 3 // 4

        if worst < trigger:
            return None

        lines = [
            "Strong consistency, expiration, and truncate all depend on "
            "synchronized clocks. Check NTP on every node."
        ]

        if threshold_ms:
            source = (
                "cluster_clock_skew_stop_writes_sec"
                if strong_consistency and configured_sec
                else "the fixed limit for AP namespaces with nsup enabled"
            )

            if worst >= threshold_ms:
                lines.insert(
                    0,
                    "That is past the %d s stop-writes threshold (%s), so writes "
                    "were being refused." % (threshold_ms // 1000, source),
                )
            else:
                lines.insert(
                    0,
                    "Writes stop at %d s of skew (%s)."
                    % (threshold_ms // 1000, source),
                )

        return BundleWarning(
            category="clock-skew",
            severity=DiagSeverity.WARNING,
            title="Clock skew between nodes reached %.1f s" % (worst / 1000.0,),
            lines=lines,
        )

    def _nsup_enabled_ap_namespaces(self) -> set[str]:
        namespaces = set()

        for ns_data in self._data("config", constants.CONFIG_NAMESPACE).values():
            if not isinstance(ns_data, dict):
                continue

            for ns, config in ns_data.items():
                if not isinstance(config, dict):
                    continue

                if _is_true(config.get("strong-consistency")):
                    continue

                if (_to_int(config.get("nsup-period")) or 0) > 0:
                    namespaces.add(ns)

        return namespaces


###############################################################################
# Rendering.


_SEVERITY_COLOR = {
    DiagSeverity.INFO: terminal.fg_blue,
    DiagSeverity.WARNING: terminal.fg_yellow,
    DiagSeverity.ERROR: terminal.fg_red,
}

_SEVERITY_ORDER = {
    DiagSeverity.ERROR: 0,
    DiagSeverity.WARNING: 1,
    DiagSeverity.INFO: 2,
}


def _banner_title(warnings: list[BundleWarning]) -> str:
    """The banner title with per-severity counts, so a reader who scrolled past
    the top knows whether anything above was worse than what they see."""
    counts = {severity: 0 for severity in _SEVERITY_ORDER}

    for warning in warnings:
        counts[warning.severity] += 1

    labels = {
        DiagSeverity.ERROR: "error",
        DiagSeverity.WARNING: "warning",
        DiagSeverity.INFO: "info",
    }
    parts = [
        "%d %s"
        % (
            counts[severity],
            (
                labels[severity]
                if severity is DiagSeverity.INFO
                else _plural(counts[severity], labels[severity])
            ),
        )
        for severity in _SEVERITY_ORDER
        if counts[severity]
    ]

    if not parts:
        return BANNER_TITLE

    return "%s (%s)" % (BANNER_TITLE, ", ".join(parts))


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

    Findings render most severe first (a stable sort, so registration order still
    breaks ties): the banner is often redirected or scrolled off an 80x24
    terminal, and a data-loss ERROR must not sit below a best-practices note.
    """
    if skip_redundant:
        warnings = [
            warning
            for warning in warnings
            if warning.category not in BANNER_REDUNDANT_CATEGORIES
        ]

    if not warnings:
        return ""

    warnings = sorted(warnings, key=lambda warning: _SEVERITY_ORDER[warning.severity])

    def colorize(severity: DiagSeverity, text: str) -> str:
        if not use_color:
            return text

        return _SEVERITY_COLOR[severity]() + text + terminal.fg_clear()

    title = _banner_title(warnings)
    out = [
        "",
        (title if not use_color else terminal.bold() + title + terminal.unbold()),
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
