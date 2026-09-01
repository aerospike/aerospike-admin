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
import copy
import logging
import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable

from lib.utils import common, constants, util, version
from lib.view import terminal
from lib.view.diagnostics_view import render_node_errors_table

if TYPE_CHECKING:
    from .collectinfo_log import _CollectinfoSnapshot
    from .log_handler import CollectinfoLogHandler

logger = logging.getLogger(__name__)
"""Debug only. This module never logs at a level that sets the process exit code:
diagnostics describe the collected cluster, not the command the user ran. It also
imports nothing from lib.utils.logger, which would pull lib.live_cluster.client
and OpenSSL into the analyzer's import graph."""

BANNER_TITLE = "Collectinfo Bundle Diagnostics"
BANNER_REDUNDANT_CATEGORIES = frozenset(
    ("collector-version-match", "collector-version-unparsed")
)
FATAL_DIAGNOSTIC_CATEGORIES = frozenset(("no-usable-nodes",))
"""Findings that mean no command reading this bundle can answer anything, so
--execute exits non-zero. Deliberately just the one: every other finding
describes the collected cluster's health, which is not the command's failure."""
BUNDLE_STALE_DAYS = 7
CLOCK_SKEW_WARN_MS = 1000
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


def _describe_thresholds(namespaces: dict[str, dict[str, Any]]) -> list[str]:
    """ "ns (40 s)" per namespace, so the reader sees which limit applies where."""
    return [
        "%s (%d s)" % (ns, namespaces[ns]["threshold"] // 1000)
        for ns in sorted(namespaces)
    ]


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


def _dict_entries(entries: Any) -> list[dict[str, Any]]:
    """The dict entries of a meta list, tolerating a list that is not one."""
    if not isinstance(entries, list):
        return []

    return [entry for entry in entries if isinstance(entry, dict)]


def _dropped_entry_cause(entry: dict[str, Any]) -> str:
    """Why a node returned no data, composed from the class the bundle recorded.

    Falls back to the prose a pre-error_class bundle stored, so older bundles
    still render.
    """
    error_class = str(entry.get("error_class") or "").strip()

    if error_class:
        return constants.COLLECTINFO_ERROR_CLASS_REASON.get(error_class, error_class)

    return str(entry.get("reason") or "").strip() or "returned no data"


def _missing_entry_cause(entry: dict[str, Any]) -> str:
    advertised_by = str(entry.get("advertised_by") or "").strip()

    if advertised_by:
        return "advertised by %s" % advertised_by

    return str(entry.get("reason") or "").strip() or "not collected"


def _node_list_lines(
    entries: list[dict[str, Any]], cause: Callable[[dict[str, Any]], str]
) -> list[str]:
    """One indented line per node, numerically sorted and truncated."""
    entries = sorted(
        entries, key=lambda entry: _node_sort_key(str(entry.get("node_key", "")))
    )
    lines = [
        "  %s (%s)" % (entry.get("node_key", "unknown"), cause(entry))
        for entry in entries[:NODE_LIST_LIMIT]
    ]

    if len(entries) > NODE_LIST_LIMIT:
        lines.append(
            "  (and %d more; the full list is in %s)"
            % (len(entries) - NODE_LIST_LIMIT, constants.COLLECTINFO_META_FILENAME)
        )

    return lines


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
        self.meta = meta if isinstance(meta, dict) else {}
        self._snapshot_meta: dict[str, Any] | None = None
        self._failed_checks: list[str] = []
        self._data_cache: dict[tuple[str, str], dict[str, Any]] = {}
        self._cached_node_names: dict[str, str] | None = None
        self._cached_empty_nodes: list[str] | None = None
        self._cached_stop_writes: list[Any] | None = None

    ###########################################################################
    # Data access. Every accessor tolerates a partial or malformed bundle.

    def _data(self, type_, stanza="") -> dict[str, Any]:
        """One snapshot stanza, read once per (type, stanza).

        get_data deep-copies what it returns, and a dozen checks read the same
        stanzas: without this, analyze() re-copies every node's jobs listing and
        namespace statistics once per reader, which dominated time-to-prompt on a
        100-node bundle.

        The cached object is shared, so a caller that hands it to something which
        merges into its arguments must copy first. If a nodes= argument is ever
        added here it has to join the cache key.
        """
        key = (type_, stanza)

        if key not in self._data_cache:
            try:
                self._data_cache[key] = (
                    self.snapshot.get_data(type=type_, stanza=stanza) or {}
                )
            except Exception:
                self._data_cache[key] = {}

        return self._data_cache[key]

    def _service_stats(self) -> dict[str, Any]:
        return self._data("statistics", constants.STAT_SERVICE)

    def _ns_stats(self) -> dict[str, Any]:
        return self._data("statistics", constants.STAT_NAMESPACE)

    def _node_names(self) -> dict[str, str]:
        if self._cached_node_names is None:
            try:
                self._cached_node_names = self.snapshot.get_node_names() or {}
            except Exception:
                self._cached_node_names = {}

        return self._cached_node_names

    def _nodes_without_as_stat(self) -> list[str]:
        if self._cached_empty_nodes is None:
            try:
                self._cached_empty_nodes = self.snapshot.nodes_without_as_stat() or []
            except Exception:
                self._cached_empty_nodes = []

        return self._cached_empty_nodes

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
        """Every finding this bundle supports, plus an account of what could not run.

        The banner is a claim about the bundle, so a check that crashed has to be
        visible: without it the banner prints its counts as though every check
        ran, which is a false claim of completeness.
        """
        warnings: list[BundleWarning] = []
        self._failed_checks = []

        for check in (
            self._check_collector_version,
            self._check_meta_format_version,
            self._check_zero_usable_nodes,
        ):
            self._run(check, warnings)

        if any(w.category == "no-usable-nodes" for w in warnings):
            self._append_incomplete_warning(warnings)
            return warnings

        for check in (
            self._check_collection_aborted,
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

        self._append_incomplete_warning(warnings)

        return warnings

    def _run(self, check, warnings: list[BundleWarning]) -> None:
        name = getattr(check, "__name__", str(check))

        try:
            result = check()
        except Exception as e:
            self._failed_checks.append(name)
            logger.debug("Diagnostic %s failed: %s", name, e, exc_info=True)
            return

        if result:
            warnings.append(result)

    def _append_incomplete_warning(self, warnings: list[BundleWarning]) -> None:
        if not self._failed_checks:
            return

        checks = [
            name.removeprefix("_check_").replace("_", " ")
            for name in self._failed_checks
        ]

        warnings.append(
            BundleWarning(
                category="diagnostics-incomplete",
                severity=DiagSeverity.WARNING,
                title="%s %s could not be run against this bundle"
                % (len(checks), _plural(len(checks), "check")),
                lines=[
                    "Could not run: %s." % ", ".join(checks),
                    "The findings below are what the remaining checks found; they "
                    "are not a complete account of this bundle. Run with --debug "
                    "for the failure.",
                ],
            )
        )

    ###########################################################################
    # Collection integrity and provenance.

    def _collector_version(self) -> str:
        bundle = self.meta.get("bundle")
        bundle = bundle if isinstance(bundle, dict) else {}
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

    def _bundle_meta_seen(self) -> bool:
        """Whether the bundle carries a metadata file at all, joined or not."""
        try:
            return bool(getattr(self.log_handler, "bundle_meta_seen", False))
        except Exception:
            return False

    def _bundle_meta_format_version(self) -> int:
        """The highest meta_format_version any of the bundle's metas declared.

        Read off the handler rather than the joined meta: a meta this asadm could
        not join is exactly the case the version finding exists for, and the
        joined meta is {} for it.
        """
        try:
            return (
                _to_int(getattr(self.log_handler, "bundle_meta_format_version", 0)) or 0
            )
        except Exception:
            return 0

    def _check_meta_format_version(self) -> BundleWarning | None:
        """A meta written by a newer asadm is read best-effort, and this says so.

        Unknown fields are ignored and absent fields mean 'not recorded', so the
        fields this asadm understands are still used rather than the file being
        rejected. Without this finding, detail recorded in a newer format would
        silently read as a clean collection.

        Driven off every meta the bundle holds, not the one that joined to this
        snapshot: a newer format is free to rename the fields the join reads, so
        gating on a successful join would silence the finding in precisely the
        case it describes.
        """
        if not self._bundle_meta_seen():
            return None

        format_version = self._bundle_meta_format_version()

        if format_version > constants.COLLECTINFO_META_FORMAT_VERSION:
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

        if not self.has_meta():
            return BundleWarning(
                category="meta-unreadable",
                severity=DiagSeverity.WARNING,
                title="Bundle metadata could not be matched to the analyzed snapshot",
                lines=[
                    "The bundle carries %s, but nothing in it describes the "
                    "snapshot being analyzed (%s), so the collection-time account "
                    "of expected nodes, dropped nodes and per-node errors is "
                    "unavailable."
                    % (constants.COLLECTINFO_META_FILENAME, self.timestamp),
                    "The findings below are inferred from the collected data. This "
                    "is a broken or mismatched metadata file, not an old bundle.",
                ],
            )

        return None

    def _check_collection_aborted(self) -> BundleWarning | None:
        """The collector recorded that this run did not finish.

        Written by the collector in a finally, so a bundle that died partway says
        so instead of looking like a complete one. Everything else below
        describes what did land.
        """
        collection = self.meta.get("collection")

        if not isinstance(collection, dict) or not collection.get("aborted"):
            return None

        snapshots = self.meta.get("snapshots")
        collected = len(snapshots) if isinstance(snapshots, list) else 0
        requested = _to_int(collection.get("snapshot_count"))
        lines = [
            "Whatever had been collected was still archived, but sections and "
            "nodes the run had not reached are absent rather than empty."
        ]

        if requested:
            lines.insert(
                0,
                "%d of %d requested %s completed."
                % (collected, requested, _plural(requested, "snapshot")),
            )

        return BundleWarning(
            category="collection-aborted",
            severity=DiagSeverity.WARNING,
            title="Collection did not finish",
            lines=lines,
        )

    def _check_zero_usable_nodes(self) -> BundleWarning | None:
        """The bundle holds no Aerospike data for any node, so no command can
        report anything.

        The one finding that stops analyze() early: every check after this one
        describes cluster state read from data this bundle does not have.

        The verdict compares sets, not counts: nodes_without_as_stat and
        get_node_names apply different guards to a malformed node entry, so
        counts can declare a bundle empty while naming its healthy nodes.
        Intersecting first keeps the verdict and the node list in one universe.
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
        """What the bundle itself recorded about nodes it did not collect.

        A recorded detection_error means the live peer reconciliation did not
        finish, so the missing-node half is unknown. The dropped half is computed
        from the collected data and is still there, so it is still reported: an
        incomplete reconciliation must not hide the nodes the bundle plainly
        recorded as returning nothing.
        """
        snapshot_meta = self.snapshot_meta()
        discrepancies = snapshot_meta.get("discrepancies") or {}
        lines: list[str] = []

        detection_error = discrepancies.get("detection_error")
        dropped = _dict_entries(discrepancies.get("dropped_during_collection"))

        if detection_error and not dropped:
            dropped = [
                {"node_key": node_key}
                for node_key in _sorted_nodes(snapshot_meta.get("no_data_nodes") or [])
            ]
        missing = _dict_entries(discrepancies.get("missing_from_collection"))
        peer_query_failed = _sorted_nodes(
            discrepancies.get("down_detection_failed_nodes") or []
        )
        expected = snapshot_meta.get("expected_nodes") or []
        responded = snapshot_meta.get("responded_nodes") or []

        if self._collected_node_subset() is not None or self._collection_flags().get(
            "only_connect_seed"
        ):
            missing = []

        if (
            not dropped
            and not missing
            and not detection_error
            and not peer_query_failed
        ):
            return None

        if detection_error:
            lines.append(
                "Node reconciliation did not complete during collection (%s), so "
                "nodes advertised by the cluster but never collected cannot be "
                "confirmed for this bundle." % (detection_error,)
            )

        if peer_query_failed:
            lines.append(
                "Peer queries failed on %d %s during collection (%s), so the "
                "down-node reconciliation is incomplete: the recorded down-node "
                "list may miss nodes those nodes knew about."
                % (
                    len(peer_query_failed),
                    _plural(len(peer_query_failed), "node"),
                    _summarize(peer_query_failed),
                )
            )

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
            lines.extend(_node_list_lines(dropped, _dropped_entry_cause))

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
            lines.extend(_node_list_lines(missing, _missing_entry_cause))

        if not dropped and not missing:
            return BundleWarning(
                category="node-discrepancy-detection-failed",
                severity=DiagSeverity.WARNING,
                title="Node reconciliation did not complete during collection",
                lines=lines,
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
            "These are inferred from the collected data rather than read from "
            "collection metadata, so they name candidates rather than facts."
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
        train readers to skip the whole banner.

        The cases, in order: SSH was requested and the meta records nodes it
        failed on; no node has host data at all; coverage is the ordinary
        one-node shape, where only the absence of the host files is worth a word;
        and finally genuine partial coverage.
        """
        coverage = self._sysinfo_coverage()

        if coverage is None:
            return None

        responded, with_sysinfo, without_sysinfo = coverage
        has_files = self._bundle_has_files(("sysinfo.log", "aerospike.conf"))
        flags = self._collection_flags()

        if without_sysinfo and flags.get("enable_ssh"):
            gap = self._ssh_sysinfo_gap(responded, without_sysinfo)

            if gap is not None:
                return gap

        if not with_sysinfo:
            return self._no_sysinfo_finding(responded, has_files, flags)

        if not without_sysinfo or len(with_sysinfo) <= 1:
            if has_files is False:
                return self._missing_sysinfo_files_finding(with_sysinfo, responded)

            return None

        return self._partial_sysinfo_finding(
            responded, with_sysinfo, without_sysinfo, has_files
        )

    def _sysinfo_coverage(self) -> tuple[list[str], list[str], list[str]] | None:
        """Responded nodes, split by whether the bundle holds host data for them.

        Nodes that returned no data at all are excluded from every count: they
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

        with_sysinfo: list[str] = []
        without_sysinfo: list[str] = []

        for node in responded:
            try:
                has_sys_data = self.snapshot.has_sys_data(node)
            except Exception:
                continue

            if has_sys_data:
                with_sysinfo.append(node)
            else:
                without_sysinfo.append(node)

        return responded, with_sysinfo, without_sysinfo

    def _ssh_sysinfo_gap(
        self, responded: list[str], without_sysinfo: list[str]
    ) -> BundleWarning | None:
        """Nodes --enable-ssh was meant to cover and the meta says it did not.

        Only nodes whose recorded sysinfo_source is 'none' are named: claiming
        SSH failure for a node the meta says nothing about would assert a cause
        from no evidence. With no such node this returns None and the ordinary
        coverage findings describe the bundle instead.
        """
        recorded_none = set(
            self._nodes_with_sysinfo_source(constants.SysinfoSource.NONE)
        )
        ssh_failed = _sorted_nodes(recorded_none & set(without_sysinfo))

        if not ssh_failed:
            return None

        return BundleWarning(
            category="ssh-sysinfo-gap",
            severity=DiagSeverity.WARNING,
            title=(
                "--enable-ssh was used but system information is missing "
                "for %d of %d nodes" % (len(ssh_failed), len(responded))
            ),
            lines=[
                "No host-level data for %s. SSH to those hosts failed during "
                "collection." % (_summarize(ssh_failed),),
                "Nothing in the bundle describes their OS, CPU, memory, disks or "
                "network settings, and `summary` reports no OS version for them.",
            ],
        )

    def _no_sysinfo_finding(
        self, responded: list[str], has_files: bool | None, flags: dict[str, Any]
    ) -> BundleWarning:
        """No host data for any node.

        The cause is stated as fact only when the bundle recorded the flag that
        proves it. A bundle collected before flags were recorded looks identical
        whether SSH was never asked for or was asked for and failed everywhere,
        so it gets both possibilities rather than the wrong one.
        """
        lines = [
            "No host-level data was captured for any of the %d nodes, so nothing "
            "in the bundle describes their OS, CPU, memory, disks or network "
            "settings and `summary` reports no OS version." % (len(responded),),
        ]
        preamble = (
            "collectinfo gathers system statistics locally for the node it runs "
            "on and over SSH for every other node, so "
        )

        if "enable_ssh" not in flags:
            lines.append(
                preamble + "this bundle was either collected from a host that is "
                "not an Aerospike node without --enable-ssh, or collected with "
                "--enable-ssh and SSH failed for every node. This bundle records "
                "no collection flags, so the two cannot be told apart."
            )
        elif flags.get("enable_ssh"):
            lines.append(
                preamble + "--enable-ssh was requested and SSH reached no node, "
                "and collectinfo did not run on a cluster node either."
            )
        else:
            lines.append(
                preamble + "this bundle was collected from a host that is not an "
                "Aerospike node, without --enable-ssh."
            )

        if has_files is False:
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

    def _missing_sysinfo_files_finding(
        self, with_sysinfo: list[str], responded: list[str]
    ) -> BundleWarning:
        """The host files are absent even though a node's sysinfo was captured.

        Reported for one covered node as well as for full coverage: nothing else
        covers sysinfo.log and aerospike.conf, so a bundle collected on a cluster
        node whose file writes failed would otherwise say nothing at all.
        """
        covered = (
            "every node that responded"
            if len(with_sysinfo) == len(responded)
            else "%s" % (_summarize(with_sysinfo),)
        )

        return BundleWarning(
            category="missing-sysinfo-files",
            severity=DiagSeverity.INFO,
            title="Bundle has no sysinfo.log or aerospike.conf",
            lines=[
                "System statistics were captured for %s, but the two host files "
                "asadm writes only when it runs on a cluster node are absent."
                % (covered,)
            ],
        )

    def _partial_sysinfo_finding(
        self,
        responded: list[str],
        with_sysinfo: list[str],
        without_sysinfo: list[str],
        has_files: bool | None,
    ) -> BundleWarning:
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
            "Nothing describes the uncovered nodes' OS, CPU, memory, disks or "
            "network settings, and `summary` reports no OS version for them.",
        ]

        if has_files is False:
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

        Every shape is guarded: the meta can come from a bundle this asadm did
        not write, and a crash here would take the whole banner's completeness
        with it.
        """
        nodes_meta = (
            (self.snapshot_meta().get("nodes") or {}) if self.has_meta() else {}
        )

        if not isinstance(nodes_meta, dict) or not nodes_meta:
            return None

        rows: dict[str, dict[str, str]] = {}
        recovered = 0
        has_subsection_failures = False
        has_empty_sections = False
        has_partial_sections = False

        for node_key, node_meta in sorted(nodes_meta.items()):
            node_errors = (
                node_meta.get("errors") if isinstance(node_meta, dict) else None
            )
            errors = [
                error
                for error in (node_errors if isinstance(node_errors, list) else [])
                if isinstance(error, dict)
                and error.get("error_class")
                != constants.CollectinfoErrorClass.UNSUPPORTED
            ]
            unrecovered = [
                error for error in errors if not error.get("recovered_on_retry")
            ]
            recovered += len(errors) - len(unrecovered)

            if not unrecovered:
                continue

            # The ledger keys entries by (section, error_class, detail) precisely
            # so one failed sub-call stays distinguishable from a whole section:
            # collapsing to the section here would claim "statistics is empty"
            # over a bundle that plainly holds service statistics.
            labels = set()

            for error in unrecovered:
                section = str(error.get("section", "?"))
                detail = str(error.get("detail") or "")

                if detail:
                    has_subsection_failures = True
                    labels.add("%s/%s" % (section, detail))
                elif util.has_content(self._data(section).get(node_key)):
                    has_partial_sections = True
                    labels.add("%s (partial)" % (section,))
                else:
                    has_empty_sections = True
                    labels.add(section)

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
                "sections": ", ".join(sorted(labels)),
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

        shown = {
            node_key: rows[node_key]
            for node_key in _sorted_nodes(rows)[:NODE_LIST_LIMIT]
        }
        table = render_node_errors_table(shown)
        table_lines = [
            "  %s: %s (%s)" % (node_key, row["sections"], row["reason"])
            for node_key, row in shown.items()
        ]
        lines = []

        if has_empty_sections:
            lines.append(
                "Sections named alone are empty for those nodes: commands reading "
                "them show no rows rather than reporting an error."
            )

        if has_partial_sections:
            lines.append(
                "Sections marked (partial) still hold data for those nodes, so "
                "treat them as incomplete rather than empty."
            )

        if has_subsection_failures:
            lines.append(
                "An entry like statistics/namespace means only that subsection is "
                "missing or incomplete; the rest of its section was collected."
            )

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
                "These findings are computed from %s, and so is every command: the "
                "older snapshots stay in the bundle but nothing renders them."
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

    def _stop_writes_summary(self) -> list[Any]:
        """The per-node per-namespace stop-writes view `show stop-writes` uses.

        Computed once and shared: two checks read it and it walks every namespace
        on every node.

        The namespace and set statistics are deep-copied first:
        create_stop_writes_summary deep-merges the matching config into each of
        them in place, and _data hands out the one cached stanza every other
        check reads. The configs and the service statistics are only read.
        """
        if self._cached_stop_writes is None:
            self._cached_stop_writes = common.create_stop_writes_summary(
                self._service_stats(),
                copy.deepcopy(self._ns_stats()),
                self._data("config", constants.CONFIG_NAMESPACE),
                copy.deepcopy(self._data("statistics", constants.STAT_SETS)),
                self._data("config", constants.CONFIG_SET),
            )

        return self._cached_stop_writes

    def _check_stop_writes(self) -> BundleWarning | None:
        stop_writes = self._stop_writes_summary()
        flagged = self._namespaces_flagging_stop_writes()

        if not common.active_stop_writes(stop_writes) and not flagged:
            return None

        lines = []

        if flagged:
            totals = self._nodes_per_namespace()
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

    def _nodes_per_namespace(self) -> dict[str, int]:
        """How many nodes carry each namespace, the denominator for per-ns claims.

        Not to be confused with a count of migrating or flagged nodes: this is
        every node whose statistics hold the namespace at all."""
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

        Either source is enough to fire. Statistics are collected per subsection,
        so a bundle whose namespace call failed while the service call succeeded
        is a shape the collector actively produces; withholding the finding until
        both are present hides migrations the bundle plainly recorded. The
        namespace list is detail, not the trigger.
        """
        migrating: dict[str, int] = {}
        nodes_by_service_stat = 0
        nodes_by_ns_stats = 0

        for stats in self._service_stats().values():
            if not isinstance(stats, dict):
                continue

            if (_to_int(stats.get("migrate_partitions_remaining")) or 0) > 0:
                nodes_by_service_stat += 1

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
                nodes_by_ns_stats += 1

        if not nodes_by_service_stat and not migrating:
            return None

        node_count = nodes_by_service_stat or nodes_by_ns_stats
        lines = []

        if migrating:
            lines.append(
                "Namespaces migrating (most partitions remaining on any one node): "
                "%s."
                % (
                    _summarize(
                        "%s=%d" % (ns, count) for ns, count in sorted(migrating.items())
                    ),
                )
            )
        else:
            lines.append(
                "The per-namespace migration statistics are not in this bundle, so "
                "which namespaces were migrating cannot be read from it."
            )

        lines.append(
            "Object counts, storage usage, and per-node balance in this bundle "
            "are mid-flight. Run `info namespace` for the per-namespace view."
        )

        return BundleWarning(
            category="migrations",
            severity=DiagSeverity.INFO,
            title="Migrations were in progress on %d %s"
            % (node_count, _plural(node_count, "node")),
            lines=lines,
        )

    def _check_mixed_server_versions(self) -> BundleWarning | None:
        """Flag mixed builds and mixed editions separately.

        The raw meta_data 'edition' value is a full version string
        ("Aerospike Enterprise Edition build 8.1.1.0"), so it is read through the
        snapshot's edition stanza, which reduces it to Enterprise / Community /
        Federal. Reading it raw would report the build twice under two names.
        """
        builds = {
            str(build)
            for build in self._data("meta_data", "asd_build").values()
            if build and not isinstance(build, (dict, list))
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

        practices_by_node = self._data("meta_data", constants.METADATA_PRACTICES)

        for node, practices in practices_by_node.items():
            if practices and not isinstance(practices, (str, dict)):
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

        for node, health in self._data("meta_data", "health").items():
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

    def _clock_skew_stop_writes_entries(self) -> dict[str, dict[str, Any]]:
        """The per-namespace clock-skew stop-writes view, worst node per namespace.

        Which threshold governs a namespace - the configured
        cluster_clock_skew_stop_writes_sec under strong consistency, or the fixed
        40 s for an AP namespace with nsup enabled - is decided per node per
        namespace by common.create_stop_writes_summary, the same computation
        `show stop-writes` reports. The lowest threshold and the highest skew win:
        that is the namespace that stops writes first.
        """
        worst: dict[str, dict[str, Any]] = {}

        for node_entries in self._stop_writes_summary().values():
            if not isinstance(node_entries, dict):
                continue

            for entry in node_entries.values():
                if not isinstance(entry, dict):
                    continue

                if entry.get("metric") != "cluster_clock_skew_ms":
                    continue

                namespace = str(entry.get("namespace") or "")
                threshold = _to_int(entry.get("metric_threshold"))
                usage = _to_int(entry.get("metric_usage"))

                if not namespace or threshold is None or usage is None:
                    continue

                current = worst.get(namespace)

                if current is None:
                    worst[namespace] = {
                        "threshold": threshold,
                        "usage": usage,
                        "stop_writes": bool(entry.get("stop_writes")),
                    }
                    continue

                current["threshold"] = min(current["threshold"], threshold)
                current["usage"] = max(current["usage"], usage)
                current["stop_writes"] = current["stop_writes"] or bool(
                    entry.get("stop_writes")
                )

        return worst

    def _check_clock_skew(self) -> BundleWarning | None:
        """Warn relative to the thresholds this cluster actually applies.

        Clock skew is cluster-wide but its consequence is not: writes stop per
        namespace, and only for a strong-consistency namespace or an AP namespace
        with nsup enabled. So the affected namespaces and their thresholds are
        named, and "writes were being refused" is only said where the server's own
        stop_writes flag says so.

        This fires alongside the stop-writes finding on purpose when skew is the
        cause: that one is an ERROR about the cluster refusing writes, this is a
        WARNING about the clocks that caused it, and the fix is different.
        """
        namespaces = self._clock_skew_stop_writes_entries()

        if not namespaces:
            return self._check_clock_skew_without_thresholds()

        worst = max(entry["usage"] for entry in namespaces.values())
        refusing = {
            ns: entry
            for ns, entry in namespaces.items()
            if entry["stop_writes"] or entry["usage"] >= entry["threshold"]
        }
        approaching = {
            ns: entry
            for ns, entry in namespaces.items()
            if ns not in refusing and entry["usage"] * 4 >= entry["threshold"] * 3
        }

        if not refusing and not approaching:
            return None

        lines = []

        if refusing:
            lines.append(
                "Past the stop-writes threshold for %s, so writes were being "
                "refused there." % (_summarize(_describe_thresholds(refusing)),)
            )

        if approaching:
            lines.append(
                "Approaching the stop-writes threshold for %s."
                % (_summarize(_describe_thresholds(approaching)),)
            )

        lines.append(
            "Strong consistency, expiration, and truncate all depend on "
            "synchronized clocks. Check NTP on every node."
        )

        return BundleWarning(
            category="clock-skew",
            severity=DiagSeverity.WARNING,
            title="Clock skew between nodes reached %.1f s" % (worst / 1000.0,),
            lines=lines,
        )

    def _check_clock_skew_without_thresholds(self) -> BundleWarning | None:
        """Skew with no stop-writes threshold recorded anywhere in the bundle.

        A namespace only gets a clock-skew stop-writes entry when it reports
        clock_skew_stop_writes, so an older server, or a bundle whose namespace
        statistics failed to collect, leaves nothing to compare against. The skew
        itself is still worth reporting; what it would cost is not stated.
        """
        worst = 0

        for stats in self._service_stats().values():
            if not isinstance(stats, dict):
                continue

            skew = _to_int(stats.get("cluster_clock_skew_ms")) or 0
            worst = max(worst, skew)

        if worst < CLOCK_SKEW_WARN_MS:
            return None

        return BundleWarning(
            category="clock-skew",
            severity=DiagSeverity.WARNING,
            title="Clock skew between nodes reached %.1f s" % (worst / 1000.0,),
            lines=[
                "This bundle records no clock-skew stop-writes threshold for any "
                "namespace, so how close that is to refusing writes cannot be "
                "read from it.",
                "Strong consistency, expiration, and truncate all depend on "
                "synchronized clocks. Check NTP on every node.",
            ],
        )


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
