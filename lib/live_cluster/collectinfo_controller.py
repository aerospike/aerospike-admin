# Copyright 2023-2025 Aerospike, Inc.
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
import copy
import functools
import json
import logging
from os import path
import pprint
import shutil
import socket
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, NamedTuple
from lib.live_cluster.client.node import Node
from lib.live_cluster.client.types import (
    ASInfoError,
    ASInfoNotAuthenticatedError,
    ASProtocolConnectionError,
    ASProtocolError,
    ASResponse,
)
from lib.live_cluster import ssh
from lib.live_cluster.logfile_downloader import LogFileDownloader
from lib.utils.types import NodeDict

from lib.view.sheet.render import get_style_json, set_style_json
from lib.view.terminal import terminal
from lib.utils import common, constants, util, version
from lib.live_cluster.constants import SSH_MODIFIER_HELP, SSH_MODIFIER_USAGE
from lib.utils.logger import LogFormatter, stderr_log_handler, logger as g_logger
from lib.base_controller import (
    BaseController,
    CommandHelp,
    ModifierHelp,
    ShellException,
)
from lib.collectinfo_analyzer.collectinfo_root_controller import (
    CollectinfoRootController,
)
from lib.live_cluster.get_controller import (
    GetStatisticsController,
    GetConfigController,
    GetAclController,
    GetLatenciesController,
    GetPmapController,
    GetJobsController,
    GetUserAgentsController,
    GetMaskingRulesController,
)

from .live_cluster_command_controller import LiveClusterCommandController
from .features_controller import FeaturesController
from .info_controller import InfoController
from .show_controller import ShowController

logger = logging.getLogger(__name__)

# The default 1s per-node timeout is too tight for the high-fanout parallel bursts that
# collectinfo issues, causing transient timeouts that drop nodes from the bundle. Raise it
# for the duration of a collectinfo run only (TOOLS-3596). An explicit larger --timeout is
# still honored.
COLLECTINFO_NODE_TIMEOUT = 5

SNAPSHOT_TIMESTAMP_RETRIES = 3


class SnapshotTimestamp(NamedTuple):
    """observed is the clock value when the key was allocated; the two differ
    only when the key is synthetic because the clock stopped advancing."""

    timestamp: str
    observed: str


NodeErrorEntry = dict[str, Any]
NodeErrorLedger = dict[str, dict[tuple[str, str, str], NodeErrorEntry]]

_ERROR_CLASS_SEVERITY = (
    constants.CollectinfoErrorClass.UNREACHABLE,
    constants.CollectinfoErrorClass.AUTH,
    constants.CollectinfoErrorClass.TIMEOUT,
    constants.CollectinfoErrorClass.CORRUPT,
    constants.CollectinfoErrorClass.OTHER,
)

_SECURITY_DISABLED_RESPONSES = frozenset(
    (
        ASResponse.SECURITY_NOT_ENABLED,
        ASResponse.SECURITY_NOT_SUPPORTED,
    )
)


def _is_unsupported(exc: Exception, optional: bool = False) -> bool:
    """Whether the call does not exist on this cluster rather than having failed.

    A security-disabled cluster rejects every ACL call; that case is covered by
    the protocol-response branch below, whatever the call was, which is why acl
    needs no flag. `optional` marks the calls whose availability depends on the
    server's version or edition instead: `release` needs 8.1.1, `best-practices`
    needs 5.7, `feature-key` is Enterprise-only from 7.1, and user-agents and
    masking-show are recent additions. None of that means data was lost, so none
    of it should be reported as a collection failure.

    A flag rather than a section name: which call it was is already recorded as
    the ledger entry's detail, and error_class 'unsupported' already says the
    cluster does not have it. Moving the entry to a section named after the
    feature made two facts out of one and left the ledger with sections no
    reader of the bundle could enumerate.

    Any ASInfoError counts for an optional call rather than only a well-formed
    error response, because an absent command surfaces in three different shapes:
    a client-side version gate (plain ASInfoError), an "unrecognized command"
    response on server 7.1+ (ASInfoResponseError), and an empty response on older
    servers (ASInfoError again). Distinguishing them by message text would mean
    tracking server strings; the cost is that a genuinely malformed response for
    an optional call goes unreported, which beats warning on every bundle.

    Authentication failures are excluded explicitly. Both auth exception types sit
    under a type this checks for (ASInfoNotAuthenticatedError under
    ASInfoResponseError, ASProtocolConnectionError under ASProtocolError), and an
    absent call must never absorb a failure the user has to act on.
    """
    if isinstance(exc, (ASInfoNotAuthenticatedError, ASProtocolConnectionError)):
        return False

    if isinstance(exc, ASProtocolError):
        return exc.as_response in _SECURITY_DISABLED_RESPONSES

    return optional and isinstance(exc, ASInfoError)


def _classify_exception(exc: Exception, optional: bool = False) -> str:
    """Map a per-node info-call exception to a stable error_class string.

    asyncio.TimeoutError subclasses OSError on 3.11+, and
    ASInfoNotAuthenticatedError subclasses ASInfoError, so the order of these
    checks is load bearing. Classification is done here rather than read off
    async_return_exceptions because that decorator has no 'corrupt' branch.

    Unsupported comes first: an absent section reaches us as the same
    ASInfoResponseError an unusable response would, and as an ASProtocolError
    that would otherwise fall through to 'other'.

    FileNotFoundError is excluded from the OSError branch: it means a local file
    such as an SSH key path was wrong, and 'unreachable' would blame the remote
    host for an operator-side mistake.

    The SSH types are classified explicitly because none of them is an OSError: a
    host that cannot be reached over SSH would otherwise be recorded as 'other',
    which tells the reader nothing and makes it the only unreachable host in the
    bundle that does not say so. SSHTimeoutError comes first, being an SSHError
    itself, and it is the one SSH failure a retry can recover.
    """
    if _is_unsupported(exc, optional):
        return constants.CollectinfoErrorClass.UNSUPPORTED

    if isinstance(exc, (asyncio.TimeoutError, ssh.SSHTimeoutError)):
        return constants.CollectinfoErrorClass.TIMEOUT

    if isinstance(exc, (ASInfoNotAuthenticatedError, ASProtocolConnectionError)):
        return constants.CollectinfoErrorClass.AUTH

    if isinstance(exc, FileNotFoundError):
        return constants.CollectinfoErrorClass.OTHER

    if isinstance(exc, ssh.SSHError):
        return constants.CollectinfoErrorClass.UNREACHABLE

    if isinstance(exc, OSError):
        return constants.CollectinfoErrorClass.UNREACHABLE

    if isinstance(exc, ASInfoError):
        return constants.CollectinfoErrorClass.CORRUPT

    return constants.CollectinfoErrorClass.OTHER


def _describe_exception(exc: Exception) -> str:
    """A human-readable cause that is never empty.

    str(TimeoutError()) is "", which would otherwise reach the operator as a
    blank error line.
    """
    return str(exc) or type(exc).__name__


def _record_node_error(
    ledger: NodeErrorLedger | None,
    node_key: str | None,
    section: str | None,
    exc: Exception,
    detail: str | None = None,
    optional: bool = False,
) -> None:
    """Record a per-node section failure, de-duped per (node, section, class, detail).

    section is always the bundle stanza the data would have landed in, so the set
    of sections a reader can see is the set of stanzas. detail names the sub-call
    within it (a metadata call, a statistics subsection, a histogram). Without
    detail, one entry covers many independent sub-calls: a second failing
    sub-call would be swallowed by the de-dupe, and the retry could not tell
    which sub-call it actually recovered.

    optional says this sub-call's command depends on the server's version or
    edition, which is what turns its failure into error_class 'unsupported'.
    """
    if ledger is None or not node_key or not section:
        return

    error_class = _classify_exception(exc, optional)
    entry_key = (section, error_class, detail or "")
    node_entry = ledger.setdefault(node_key, {})

    if entry_key in node_entry:
        return

    entry: NodeErrorEntry = {
        "section": section,
        "error_class": error_class,
        "message": _describe_exception(exc),
        "recovered_on_retry": False,
    }

    if detail:
        entry["detail"] = detail

    node_entry[entry_key] = entry


_INFO_CALL_SUBSECTIONS = {
    "info_statistics": constants.STAT_SERVICE,
    "info_namespace_statistics": constants.STAT_NAMESPACE,
    "info_all_namespace_statistics": constants.STAT_NAMESPACE,
    "info_all_set_statistics": constants.STAT_SETS,
    "info_bin_statistics": constants.STAT_BINS,
    "info_sindex": constants.STAT_SINDEX,
    "info_sindex_statistics": constants.STAT_SINDEX,
    "info_XDR_statistics": constants.STAT_XDR,
    "info_all_dc_statistics": constants.STAT_DC,
    "info_all_xdr_namespaces_statistics": constants.STAT_XDR_NS,
    "info_logging_config": constants.CONFIG_LOGGING,
    "info_xdr_config": constants.CONFIG_XDR,
    "info_xdr_dcs_config": constants.CONFIG_DC,
    "info_xdr_namespaces_config": constants.CONFIG_XDR_NS,
    "info_get_xdr_filter": constants.CONFIG_XDR_FILTER,
    "info_roster": constants.CONFIG_ROSTER,
    "info_racks": constants.CONFIG_RACKS,
    "info_rack_ids": constants.CONFIG_RACK_IDS,
}
"""The bundle subsection each info call fills, for calls made below a subsection.

`info_get_config` is absent because it fills four of them and says which in its
`stanza` argument. A call missing from here is named by its own method instead:
a new getter's failures are then recorded under a detail nobody chose, which is
worse than a good name and much better than silence.

`info_all_set_statistics` serves both the statistics and the config getter - the
server returns set stats and set config in one response - so a node that fails
it is recorded under both sections, which is what the bundle actually loses.
"""

_ALWAYS_SERVED_INFO_CALLS = frozenset({"info_statistics", "info_namespaces"})
"""Calls whose failure always means data the bundle should have is missing.

Everything else is recorded as an optional call, so an ASInfoError from it is
classified 'unsupported' rather than as lost data. That is not laxity: a
namespace, set, sindex, datacenter or roster call legitimately errors on a node
that does not have the thing being asked about, and a heterogeneous cluster
would otherwise report a corrupt bundle on every collection. What the flag does
not swallow is every failure a reader has to act on - a timeout, an unreachable
host, a rejected login - because those are classified before it is consulted.

`info_get_config` is decided by stanza rather than listed here: every server
serves service and network, while security legitimately errors on a
security-disabled or Community Edition cluster.
"""

_ALWAYS_SERVED_CONFIG_STANZAS = frozenset(
    {constants.CONFIG_SERVICE, constants.CONFIG_NETWORK}
)


def _info_call_detail(method_name: str, kwargs: dict[str, Any]) -> str:
    if method_name == "info_get_config":
        return str(kwargs.get("stanza") or "")

    return _INFO_CALL_SUBSECTIONS.get(
        method_name, method_name.removeprefix("info_").lower()
    )


def _info_call_is_optional(method_name: str, kwargs: dict[str, Any]) -> bool:
    if method_name == "info_get_config":
        return kwargs.get("stanza") not in _ALWAYS_SERVED_CONFIG_STANZAS

    return method_name not in _ALWAYS_SERVED_INFO_CALLS


def _record_info_call_error(
    ledger: NodeErrorLedger,
    section: str,
    method_name: str,
    kwargs: dict[str, Any],
    node_key: str,
    exc: Exception,
) -> None:
    """Ledger one per-node info-call failure seen inside a section's collection."""
    _record_node_error(
        ledger,
        node_key,
        section,
        exc,
        detail=_info_call_detail(method_name, kwargs),
        optional=_info_call_is_optional(method_name, kwargs),
    )


class _ErrorRecordingCluster:
    """A cluster that ledgers the per-node failures a getter is about to drop.

    The getters keep whole-node exceptions only for the subsections a consumer
    inspects - `service` and `network` - and drop the ones nested deeper, because
    an Exception reaching ascinfo.json would break every reader of it. The
    fan-out call's own result is where those failures are all still visible, so
    collectinfo hands its getters a cluster that reads them off there. Nothing
    about the data the getter returns changes.

    Wrapping rather than a flag on each getter: a getter fills one bundle
    subsection out of one to four info calls, several of them per namespace or
    per datacenter, and there is no place in its return value to put the failure
    of a call that another namespace answered.

    Delegates by __getattr__, which is how Cluster dispatches these calls in the
    first place, so a getter added later is covered without being told to be.
    """

    def __init__(self, cluster, section: str, ledger: NodeErrorLedger):
        self._cluster = cluster
        self._section = section
        self._ledger = ledger

    def __getattr__(self, name: str):
        attr = getattr(self._cluster, name)

        if not name.startswith("info_") or not callable(attr):
            return attr

        async def recording_call(*args, **kwargs):
            result = await attr(*args, **kwargs)
            self._record(name, kwargs, result)

            return result

        return recording_call

    def _record(self, method_name: str, kwargs: dict[str, Any], result) -> None:
        if not isinstance(result, dict):
            return

        for node_key, value in result.items():
            if isinstance(value, Exception):
                _record_info_call_error(
                    self._ledger, self._section, method_name, kwargs, node_key, value
                )


def _retry_reported_failure(
    retry_ledger: NodeErrorLedger, node_key: str, section: str, detail: str
) -> bool:
    """Did the retry pass record its own failure for this same sub-call?

    Matching on (section, detail) regardless of error class is what stops a
    changed class from laundering a failure: a metadata call that timed out on the
    first pass and came back 'unsupported' on the retry is still a sub-call that
    produced nothing. A failure keeps the section of the stanza it belongs to
    whatever its class, so the pair is stable across passes.

    The section is part of the match rather than the detail alone: 'service' is a
    detail under both statistics and config, and a config failure says nothing
    about whether the statistics sub-call recovered.
    """
    for entry_section, _, entry_detail in retry_ledger.get(node_key, {}):
        if entry_section == section and entry_detail == detail:
            return True

    return False


def _mark_error_recovered(
    ledger: NodeErrorLedger,
    retry_ledger: NodeErrorLedger,
    node_key: str,
    section: str,
    attempted: bool,
) -> None:
    """Mark this section's timeout entries recovered after a retry.

    Recovery is decided on positive evidence, never on absence. `attempted` says
    the retry's output carries this node at all, which is the only proof the
    sub-call ran: every getter iterates the responses it received, so a node that
    was never reached is simply missing from the result and would otherwise be
    indistinguishable from one that answered.

    Given the sub-call ran, it recovered unless the retry recorded its own
    failure for it. The value itself is not consulted: udf answers {}, health
    answers {"outlier0": {}} and best_practices answers [] on a healthy node, so
    requiring content would report a fully successful retry as a permanent
    failure and warn about a node where nothing is missing.
    """
    if not attempted:
        return

    for entry_key, entry in ledger.get(node_key, {}).items():
        entry_section, error_class, detail = entry_key

        if (
            entry_section != section
            or error_class != constants.CollectinfoErrorClass.TIMEOUT
        ):
            continue

        if not _retry_reported_failure(retry_ledger, node_key, section, detail):
            entry["recovered_on_retry"] = True


def _merge_ledgers(ledger: NodeErrorLedger, retry_ledger: NodeErrorLedger) -> None:
    """Fold the retry pass's own failures into the collection ledger.

    Entries the first pass already holds are left alone: theirs is the record the
    recovery decision was just made against, and re-recording would drop the
    recovered flag.
    """
    for node_key, entries in retry_ledger.items():
        node_entry = ledger.setdefault(node_key, {})

        for entry_key, entry in entries.items():
            node_entry.setdefault(entry_key, entry)


def _node_error_entries(ledger: NodeErrorLedger, node_key: str) -> list[NodeErrorEntry]:
    return [copy.deepcopy(entry) for entry in ledger.get(node_key, {}).values()]


def _severe_error_class(ledger: NodeErrorLedger, node_key: str) -> str:
    """The most severe error class a node recorded, or "" if none of them count.

    _ERROR_CLASS_SEVERITY is ordered worst first and holds no entry for
    'unsupported': a section this cluster does not have explains nothing about why
    the node returned nothing, so such a ledger entry falls through.

    Read off the entries rather than their keys, and skip the ones a retry
    recovered: a timeout that the retry filled in is not why the node ended up
    with no data.
    """
    classes = {
        entry["error_class"]
        for entry in ledger.get(node_key, {}).values()
        if entry.get("error_class") and not entry.get("recovered_on_retry")
    }

    for error_class in _ERROR_CLASS_SEVERITY:
        if error_class in classes:
            return error_class

    return ""


def _merge_retried_value(target: dict, key: str, value) -> bool:
    """Merge one retried value into target[key], never overwriting content with nothing.

    Recurses so a nested section can be filled in independently: a node's
    statistics hold eight subsections collected by separate info calls, and the
    retry that recovers one of them returns the others empty. A value the retry
    did collect still wins, so a peer list the cluster has since shortened is
    replaced rather than merged element-wise.

    The guard is narrow on purpose. Only a value with nothing in it landing on a
    slot that already holds content is refused (TOOLS-3596: the retry re-queries
    every sub-call for the node, so it returns empty for the ones it failed on).
    An empty-but-real answer - udf's {}, best_practices' [] on a healthy node -
    still lands in an empty slot, because that is the answer.

    Reports whether the retry filled a slot that previously held nothing. That is
    a data fact for callers; whether an error recovered is decided by
    _mark_error_recovered off the retry's own ledger, not off this.
    """
    if value is None:
        return False

    existing = target.get(key)

    if isinstance(value, dict) and isinstance(existing, dict):
        return any(
            [
                _merge_retried_value(existing, sub_key, sub_value)
                for sub_key, sub_value in value.items()
            ]
        )

    if not util.has_content(value) and util.has_content(existing):
        return False

    filled = not util.has_content(existing)
    target[key] = value

    return filled


@dataclass(frozen=True)
class CollectionContext:
    """What one collectinfo run was asked to do, built once in _run_collectinfo.

    Everything here is provenance: it decides how the cluster is queried and is
    recorded verbatim in the bundle's metadata. Passed as one value rather than
    threaded positionally through four functions, where the same thirteen
    arguments were re-listed each time and ssh_port sat in a different position
    in two of them.
    """

    enable_ssh: bool = False
    ssh_user: str | None = None
    ssh_pwd: str | None = None
    ssh_key: str | None = None
    ssh_key_pwd: str | None = None
    ssh_port: int | None = None
    snp_count: int = 1
    wait_time: int = 0
    requested_timeout: int | None = None
    effective_timeout: int | None = None
    output_prefix: str = ""
    asconfig_file: str = ""
    ignore_errors: bool = False


class _RetryableSection(NamedTuple):
    """One row of the retry table: what to re-query and where its output goes.

    merge_section is the ledger section the output's failures were recorded
    under, and is None for the getter that returns statistics and config
    together: that one merges per section rather than as a whole node value.
    """

    ledger_sections: tuple[str, ...]
    getter: Callable[..., Any]
    merge_section: str | None
    target: dict


class _RetryRow(NamedTuple):
    """A _RetryableSection with the nodes that need it and its in-flight call."""

    nodes: list[str]
    merge_section: str | None
    target: dict
    coro: Any


def _timed_out_nodes(ledger: NodeErrorLedger) -> dict[str, set[str]]:
    """Map node key -> sections that failed with a timeout, for the retry pass."""
    timed_out: dict[str, set[str]] = {}

    for node_key, entries in ledger.items():
        sections = {
            section
            for section, error_class, _ in entries
            if error_class == constants.CollectinfoErrorClass.TIMEOUT
        }
        if sections:
            timed_out[node_key] = sections

    return timed_out


@CommandHelp(
    "Collects cluster info, aerospike conf file for local node and system stats from all nodes if remote server credentials provided. If credentials are not available then it will collect system stats from local node only.",
    usage=f"[-n <num-snapshots>] [-s <sleep>] [{SSH_MODIFIER_USAGE}] [--output-prefix <prefix>] [--asconfig-file <path>]",
    modifiers=(
        ModifierHelp("-n", "Number of snapshots.", default="1"),
        ModifierHelp(
            "-s", "Sleep time in seconds between each snapshot.", default="5 sec"
        ),
        *SSH_MODIFIER_HELP,
        ModifierHelp("--output-prefix", "Output directory name prefix."),
        ModifierHelp(
            "--asconfig-file",
            "Aerospike config file path to collect.",
            default="/etc/aerospike/aerospike.conf",
        ),
    ),
    short_msg="Collects cluster info, system stats, and aerospike conf file for local node",
)
class CollectinfoController(LiveClusterCommandController):
    get_pmap = False

    def __init__(self):
        self.modifiers = set(["with"])
        self.collectinfo_root_controller = None

    def _collect_local_file(self, src, dest_dir):
        logger.info("Copying file %s to %s" % (src, dest_dir))
        try:
            shutil.copy2(src, dest_dir)
        except Exception as e:
            raise e

    async def _collectinfo_capture_and_write_to_file(
        self, filename: str, func: Callable, param: list[str] = []
    ):
        if self.nodes and isinstance(self.nodes, list):
            param += ["with"] + self.nodes

        o = await util.capture_stdout(func, param[:])

        self._write_func_output_to_file(filename, func, param, o)

    def _write_func_output_to_file(
        self, filename: str, func: Callable, param: list[str], content: str
    ):
        name = ""
        sep = constants.COLLECTINFO_SEPERATOR

        old_style_json = get_style_json()
        set_style_json(False)

        try:
            name = func.__name__
        except Exception as e:
            pass

        if param:
            sep += " ".join(param) + "\n"

        util.write_to_file(filename, sep + str(content))

        set_style_json(old_style_json)

    def _write_version(self, line):
        print("asadm version " + str(self.asadm_version))

    def _parse_namespace(self, namespace_data):
        """
        This method will return set of namespaces present given namespace data
        @param namespace_data: should be a form of dict returned by info protocol for namespace.
        """
        namespaces = set()

        for _value in namespace_data.values():
            for ns in _value.split(";"):
                namespaces.add(ns)
        return namespaces

    ###########################################################################
    # Functions for dumping json

    def _restructure_set_section(self, stats):
        for node, node_data in stats.items():
            if constants.STAT_SETS not in node_data.keys():
                continue

            for key, val in node_data[constants.STAT_SETS].items():
                ns_name = key[0]
                setname = key[1]

                if ns_name not in node_data[constants.STAT_NAMESPACE]:
                    continue

                ns = node_data[constants.STAT_NAMESPACE][ns_name]

                if constants.STAT_SETS not in ns.keys():
                    ns[constants.STAT_SETS] = {}

                ns[constants.STAT_SETS][setname] = copy.deepcopy(val)

            del node_data[constants.STAT_SETS]

    def _restructure_sindex_section(self, stats):
        # Due to new server feature namespace add/remove with rolling restart,
        # there is possibility that different nodes will have different namespaces and
        # old sindex info available for node which does not have namespace for that sindex.

        for node, node_data in stats.items():
            if "sindex" not in node_data.keys():
                continue

            for key, val in node_data["sindex"].items():
                key_list = key.split()
                ns_name = key_list[0]
                sindex_name = key_list[2]

                if ns_name not in node_data["namespace"]:
                    continue

                ns = node_data["namespace"][ns_name]

                if "sindex" not in ns.keys():
                    ns["sindex"] = {}

                ns["sindex"][sindex_name] = copy.deepcopy(val)

            del node_data["sindex"]

    def _restructure_bin_section(self, stats):
        for node, node_data in stats.items():
            if "bin" not in node_data.keys():
                continue
            for ns_name, val in node_data["bin"].items():
                if ns_name not in node_data["namespace"]:
                    continue

                ns = node_data["namespace"][ns_name]
                ns["bin"] = copy.deepcopy(val)

            del node_data["bin"]

    def _init_stat_ns_subsection(self, data):
        for node, node_data in data.items():
            if "namespace" not in node_data.keys():
                continue
            ns_map = node_data["namespace"]
            for ns, data in ns_map.items():
                ns_map[ns]["set"] = {}
                ns_map[ns]["bin"] = {}
                ns_map[ns]["sindex"] = {}

    def _restructure_ns_section(self, data):
        for node, node_data in data.items():
            if "namespace" not in node_data.keys():
                continue
            ns_map = node_data["namespace"]
            for ns, data in ns_map.items():
                stat = {}
                stat[ns] = {}
                stat[ns]["service"] = data
                ns_map[ns] = stat[ns]

    def _remove_exception_from_section_output(
        self,
        data,
        section_label: str | None = None,
        ledger: NodeErrorLedger | None = None,
    ):
        """Replace per-node exceptions with {} and record them in the ledger.

        The subsection names this can record are the ones the getter kept whole
        node values for: `service` and `network` for config, `service` for
        statistics, `users` and `roles` for acl. Everything nested deeper - a
        namespace, a set, a sindex, an xdr datacenter - has its failures dropped
        by the getters a level below, and is recorded by the
        _ErrorRecordingCluster the getter was handed instead. Both paths ledger
        the same (section, class, detail) key, so a service failure seen by both
        is one entry.
        """
        for section in data:
            for node in data[section]:
                if isinstance(data[section][node], Exception):
                    _record_node_error(
                        ledger, node, section_label, data[section][node], detail=section
                    )
                    data[section][node] = {}

    async def _get_as_cluster_name(self) -> str:
        cluster_names = await self.cluster.info("cluster-name")

        # Get the cluster name and add one more level in map
        cluster_name = "null"

        # Cluster name.
        for node in cluster_names:
            if (
                not isinstance(cluster_names[node], Exception)
                and cluster_names[node] != "null"
            ):
                cluster_name = cluster_names[node]
                break

        return cluster_name

    def _cluster_for_section(self, section: str, ledger):
        """The cluster a section's getter should query.

        With a ledger to record into, an _ErrorRecordingCluster, so the failures
        the getter drops below the subsection level are still recorded. Without
        one - nothing to record into - the cluster itself.
        """
        if ledger is None:
            return self.cluster

        return _ErrorRecordingCluster(self.cluster, section, ledger)

    async def _get_as_data_json(self, nodes=None, ledger=None):
        as_map = {}
        nodes = self.nodes if nodes is None else nodes
        section = constants.CollectinfoSection
        stat_getter = GetStatisticsController(
            self._cluster_for_section(section.STATISTICS, ledger)
        )
        config_getter = GetConfigController(
            self._cluster_for_section(section.CONFIG, ledger)
        )

        stats, config = await asyncio.gather(
            stat_getter.get_all(nodes=nodes, keep_exceptions=True),
            config_getter.get_all(nodes=nodes, keep_exceptions=True),
        )

        self._remove_exception_from_section_output(
            stats, constants.CollectinfoSection.STATISTICS, ledger
        )
        self._remove_exception_from_section_output(
            config, constants.CollectinfoSection.CONFIG, ledger
        )

        # flip key to get node ids in upper level and sections inside them.
        # {'namespace': {'ip1': {'test': {}}, 'ip2': {'test': {}}}} -->
        # {'ip1':{'namespace': {'test': {}}}, 'ip2': {'namespace': {'test': {}}}}
        new_stats = util.flip_keys(stats)
        new_config = util.flip_keys(config)

        # Create a new service level for all ns stats.
        # {'namespace': 'test': {<stats>}} -->
        # {'namespace': 'test': {'service': {<stats>}}}
        self._restructure_ns_section(new_stats)
        # ns stats would have set and bin data too, service level will
        # consolidate its service stats and put sets, sindex, bin stats
        # in namespace section
        self._init_stat_ns_subsection(new_stats)
        self._restructure_set_section(new_stats)
        self._restructure_sindex_section(new_stats)
        self._restructure_bin_section(new_stats)
        # No config for sindex, bin
        self._restructure_ns_section(new_config)
        self._restructure_set_section(new_config)

        as_map["statistics"] = new_stats
        as_map["config"] = new_config

        new_as_map = util.flip_keys(as_map)

        return new_as_map

    def _check_for_exception_and_set(
        self,
        data,
        section_name,
        nodeid,
        result_map,
        ledger: NodeErrorLedger | None = None,
        optional: bool = False,
    ):
        """Store one metadata sub-call's result, recording a failure in the ledger.

        Every failure is recorded under the metadata section, named by the
        sub-call that failed, so the retry pass - which re-queries every sub-call
        for a node that timed out - keeps finding them. A sub-call whose command
        depends on the server's version or edition passes optional=True, which
        classifies its absence as 'unsupported' rather than as lost data.
        """
        if nodeid in data:
            if not isinstance(data[nodeid], Exception):
                result_map[nodeid][section_name] = data[nodeid]
            else:
                _record_node_error(
                    ledger,
                    nodeid,
                    constants.CollectinfoSection.METADATA,
                    data[nodeid],
                    detail=section_name,
                    optional=optional,
                )
                result_map[nodeid][section_name] = ""

    async def _get_as_metadata(self, nodes=None, ledger=None):
        metamap = {}
        nodes = self.nodes if nodes is None else nodes
        (
            builds,
            editions,
            node_ids,
            ips,
            endpoints,
            services,
            udf_data,
            health_outliers,
            best_practices,
            jobs,
            feature_keys,
            release_info,
        ) = await asyncio.gather(
            self.cluster.info_build(nodes=nodes),
            self.cluster.info_version(nodes=nodes),
            self.cluster.info_node(nodes=nodes),
            self.cluster.info_ip_port(nodes=nodes),
            self.cluster.info_service_list(nodes=nodes),
            self.cluster.info_peers_flat_list(nodes=nodes),
            self.cluster.info_udf_list(nodes=nodes),
            self.cluster.info_health_outliers(nodes=nodes),
            self.cluster.info_best_practices(nodes=nodes),
            GetJobsController(self.cluster).get_all(flip=True, nodes=nodes),
            self.cluster.info_feature_key(nodes=nodes),
            self.cluster.info_release(nodes=nodes),
        )
        node_names = self.cluster.get_node_names()

        for nodeid in builds:
            metamap[nodeid] = {}
            self._check_for_exception_and_set(
                builds, "asd_build", nodeid, metamap, ledger
            )
            self._check_for_exception_and_set(
                editions, "edition", nodeid, metamap, ledger
            )
            self._check_for_exception_and_set(
                node_ids, "node_id", nodeid, metamap, ledger
            )
            self._check_for_exception_and_set(ips, "ip", nodeid, metamap, ledger)
            self._check_for_exception_and_set(
                endpoints, "endpoints", nodeid, metamap, ledger
            )
            self._check_for_exception_and_set(
                services, "services", nodeid, metamap, ledger
            )
            self._check_for_exception_and_set(udf_data, "udf", nodeid, metamap, ledger)
            self._check_for_exception_and_set(
                health_outliers, "health", nodeid, metamap, ledger
            )
            self._check_for_exception_and_set(
                best_practices,
                "best_practices",
                nodeid,
                metamap,
                ledger,
                optional=True,
            )
            self._check_for_exception_and_set(
                node_names, "node_names", nodeid, metamap, ledger
            )
            self._check_for_exception_and_set(jobs, "jobs", nodeid, metamap, ledger)
            self._check_for_exception_and_set(
                feature_keys,
                "feature-key",
                nodeid,
                metamap,
                ledger,
                optional=True,
            )
            self._check_for_exception_and_set(
                release_info,
                "release",
                nodeid,
                metamap,
                ledger,
                optional=True,
            )
        return metamap

    async def _get_as_histograms(self, nodes=None, ledger=None):
        histogram_map = {}
        nodes = self.nodes if nodes is None else nodes
        hist_list = [
            ("ttl", "ttl", False),
            ("objsz", "objsz", False),
            ("objsz", "object-size", True),
        ]
        hist_dumps = await asyncio.gather(
            *[
                self.cluster.info_histogram(
                    hist[0],
                    logarithmic=hist[2],
                    raw_output=True,
                    nodes=nodes,
                )
                for hist in hist_list
            ]
        )

        for hist, hist_dump in zip(hist_list, hist_dumps):
            for node in hist_dump:
                if node not in histogram_map:
                    histogram_map[node] = {}

                if isinstance(hist_dump[node], Exception):
                    _record_node_error(
                        ledger,
                        node,
                        constants.CollectinfoSection.HISTOGRAM,
                        hist_dump[node],
                        detail=hist[1],
                    )
                    continue

                if not hist_dump[node]:
                    continue

                histogram_map[node][hist[1]] = hist_dump[node]

        return histogram_map

    async def _get_as_latency(self, nodes=None, ledger=None):
        nodes = self.nodes if nodes is None else nodes
        latency_getter = GetLatenciesController(self.cluster)
        latencies_data = await latency_getter.get_all(
            nodes, buckets=17, exponent_increment=1, verbose=1, keep_exceptions=True
        )
        latency_map = {}

        for node in latencies_data:
            if node not in latency_map:
                latency_map[node] = {}

            if isinstance(latencies_data[node], Exception):
                _record_node_error(
                    ledger,
                    node,
                    constants.CollectinfoSection.LATENCY,
                    latencies_data[node],
                )
                continue

            if not latencies_data[node]:
                continue

            latency_map[node] = latencies_data[node]

        return latency_map

    async def _get_as_pmap(self):
        getter = GetPmapController(self.cluster)
        return await getter.get_pmap(nodes=self.nodes)

    async def _get_as_access_control_list(
        self, ledger=None
    ) -> NodeDict[dict[str, dict[str, Any]]]:
        """Collect users and roles for the nodes this collection is scoped to.

        Scoped like every other section: `collectinfo with <nodes>` is a
        supported way to collect part of a cluster, and querying the whole
        cluster here recorded ACL failures for nodes the bundle says nothing
        else about.
        """
        users_getter = GetAclController(self.cluster)
        users_map = await users_getter.get_all(nodes=self.nodes)
        self._remove_exception_from_section_output(
            users_map, constants.CollectinfoSection.ACL, ledger
        )
        users_map = util.flip_keys(users_map)
        return users_map

    async def _get_as_user_agents(
        self, nodes=None, ledger=None
    ) -> NodeDict[list[dict[str, str]]]:
        """Collect user agents data from all nodes"""
        nodes = self.nodes if nodes is None else nodes
        user_agents_getter = GetUserAgentsController(self.cluster)
        user_agents_data = await user_agents_getter.get_user_agents(nodes=nodes)
        user_agents_map = {}

        for node in user_agents_data:
            if node not in user_agents_map:
                user_agents_map[node] = []

            if isinstance(user_agents_data[node], Exception):
                _record_node_error(
                    ledger,
                    node,
                    constants.CollectinfoSection.USER_AGENTS,
                    user_agents_data[node],
                    optional=True,
                )
                continue

            if not user_agents_data[node]:
                continue

            user_agents_map[node] = user_agents_data[node]

        return user_agents_map

    async def _get_as_masking_rules(
        self, ledger=None
    ) -> NodeDict[list[dict[str, str]]]:
        """Collect masking rules data from principal node"""
        masking_getter = GetMaskingRulesController(self.cluster)
        masking_data = await masking_getter.get_masking_rules(nodes="principal")
        masking_map = {}

        for node in masking_data:
            if isinstance(masking_data[node], Exception):
                _record_node_error(
                    ledger,
                    node,
                    constants.CollectinfoSection.MASKING,
                    masking_data[node],
                    optional=True,
                )
                continue

            if not masking_data[node]:
                continue

            masking_map[node] = masking_data[node]

        return masking_map

    @staticmethod
    def _sysinfo_query_kwargs(context: CollectionContext) -> dict[str, Any]:
        """The SSH context every sysinfo query has to be made with.

        Shared by the first pass and the retry: a retry made without it collects
        nothing for every node but the local one, which would then be recorded as
        a permanent failure.
        """
        return {
            "enable_ssh": context.enable_ssh,
            "ssh_user": context.ssh_user,
            "ssh_pwd": context.ssh_pwd,
            "ssh_key": context.ssh_key,
            "ssh_key_pwd": context.ssh_key_pwd,
            "ssh_port": context.ssh_port,
        }

    async def _get_as_sysinfo(
        self, *, context: CollectionContext, nodes=None, ledger=None
    ) -> dict[str, Any]:
        """Re-query host statistics for the nodes whose sysinfo timed out.

        Records what failed again into the given ledger but does not repeat
        _record_sysinfo_errors' escalation: that decides a failed collection from
        how much of the cluster failed, and this pass only ever holds the nodes
        that already failed once.
        """
        nodes = self.nodes if nodes is None else nodes
        sys_map = await self.cluster.info_system_statistics(
            nodes=nodes, **self._sysinfo_query_kwargs(context)
        )
        self._record_sysinfo_failures(sys_map, ledger)

        return sys_map

    @staticmethod
    def _record_sysinfo_failures(
        sys_map: dict[str, Any], ledger: NodeErrorLedger | None
    ) -> dict[str, Exception]:
        """Ledger every per-node sysinfo failure and blank the node's entry.

        Blanking is unconditional: an Exception left in sys_map would be written
        into the bundle's sys_stat, where nothing downstream expects one.
        """
        failed = {}

        for node_key, value in sys_map.items():
            if isinstance(value, Exception):
                _record_node_error(
                    ledger, node_key, constants.CollectinfoSection.SYSINFO, value
                )
                failed[node_key] = value
                sys_map[node_key] = {}

        return failed

    def _record_sysinfo_errors(
        self, sys_map: dict[str, Any], ledger: NodeErrorLedger
    ) -> None:
        """Record per-node sysinfo failures and keep the collection going.

        A node's sysinfo failure must not abort the run: the failure is recorded
        in the meta and that node's sys_stat is left empty, because every other
        node's data, and the analyzer's account of what is missing, are worth
        more than nothing at all.

        A failure that hits every node is different: the bundle would carry no
        host data at all, which is a failed collection rather than a degraded
        one. So is a FileNotFoundError, because a bad local key path fails
        identically for every node before any network I/O, whichever nodes
        happen to have answered first.

        Both are reported with logger.error rather than raised. The module logger
        is a BaseLogger, so error() sets exit code 2 - which is what a CI run
        with bad credentials needs to see - while a raise would escape
        _get_collectinfo_data_json before ascinfo.json and the metadata are
        written, throwing away every snapshot already collected.
        """
        failed = self._record_sysinfo_failures(sys_map, ledger)

        if not failed:
            return

        described = ", ".join(
            "%s (%s)" % (node_key, _describe_exception(exc))
            for node_key, exc in sorted(failed.items())
        )

        file_not_found = next(
            (exc for exc in failed.values() if isinstance(exc, FileNotFoundError)),
            None,
        )

        if file_not_found is not None or len(failed) == len(sys_map):
            logger.error(
                "Failed to collect system statistics for %d of %d node(s): %s. The "
                "bundle is still written, but it carries no host-level data for "
                "those nodes.",
                len(failed),
                len(sys_map),
                described,
            )
            return

        logger.warning(
            "Failed to collect system statistics for %d node(s): %s. The bundle is "
            "still written; those nodes carry no host-level data.",
            len(failed),
            described,
        )

    async def _get_collectinfo_data_json(self, context: CollectionContext):
        logger.debug("Collectinfo data to store in collectinfo_*.json")

        # The set of nodes we are about to query (alive + selected). Captured before the
        # collection bursts: a node that fails every call or dies mid-run must still be
        # accounted for in the dump and the no-data warning (TOOLS-3596).
        queried_nodes = self.cluster.get_nodes(self.nodes)
        expected_node_keys = {node.key for node in queried_nodes}

        node_errors: NodeErrorLedger = {}

        # Split operations into batches to reduce socket contention and timeouts
        # Batch 1: Core data collection (most resource intensive)
        (
            cluster_name,
            as_map,
            meta_map,
            sys_map,
        ) = await asyncio.gather(
            self._get_as_cluster_name(),
            self._get_as_data_json(ledger=node_errors),
            self._get_as_metadata(ledger=node_errors),
            self.cluster.info_system_statistics(
                nodes=self.nodes, **self._sysinfo_query_kwargs(context)
            ),
        )

        # Batch 2: Histograms and latency data
        (
            histogram_map,
            latency_map,
        ) = await asyncio.gather(
            self._get_as_histograms(ledger=node_errors),
            self._get_as_latency(ledger=node_errors),
        )

        # Batch 3: Security and auxiliary data (lighter operations)
        (
            acl_map,
            user_agents_map,
            masking_map,
        ) = await asyncio.gather(
            self._get_as_access_control_list(ledger=node_errors),
            self._get_as_user_agents(ledger=node_errors),
            self._get_as_masking_rules(ledger=node_errors),
        )

        self._record_sysinfo_errors(sys_map, node_errors)

        await self._retry_timed_out_nodes(
            node_errors,
            context=context,
            as_map=as_map,
            meta_map=meta_map,
            sys_map=sys_map,
            histogram_map=histogram_map,
            latency_map=latency_map,
            user_agents_map=user_agents_map,
        )

        pmap_map = None

        if CollectinfoController.get_pmap:
            pmap_map = await self._get_as_pmap()

        dump_map = self._build_dump_map(
            expected_node_keys=expected_node_keys,
            as_map=as_map,
            sys_map=sys_map,
            meta_map=meta_map,
            histogram_map=histogram_map,
            latency_map=latency_map,
            pmap_map=pmap_map,
            acl_map=acl_map,
            user_agents_map=user_agents_map,
            masking_map=masking_map,
        )

        snapshot_meta: dict[str, Any] = {"cluster_name": cluster_name}
        snapshot_meta.update(
            await self._detect_node_discrepancies(
                queried_nodes, dump_map, node_errors, context.enable_ssh
            )
        )

        snp_map = {}
        snp_map[cluster_name] = dump_map
        return snp_map, snapshot_meta

    async def _retry_timed_out_nodes(
        self,
        ledger: NodeErrorLedger,
        context: CollectionContext,
        as_map,
        meta_map,
        sys_map,
        histogram_map,
        latency_map,
        user_agents_map,
    ) -> None:
        """Re-query only the nodes/sections that timed out, once.

        A transient timeout during a high-fanout burst must not silently drop a
        node's section from the bundle. The retry runs exactly once and is
        timeout-only: an unreachable or unauthenticated node will not recover and
        re-querying it just doubles collection time. acl and masking are excluded
        because their getters are not node-scoped.

        sysinfo is included and is the one section whose re-query needs the
        collection's own SSH context, without which the retry would collect
        nothing for any node but the local one. An SSH timeout is exactly the
        failure a second attempt recovers, and a node that loses sysinfo loses
        every host-level fact the bundle has about it.

        The retry gets a ledger of its own, folded into the collection's at the
        end. That is what makes recovery decidable: an entry recovered when the
        retry reached the node and recorded no failure of its own for that
        sub-call, and a retry that failed again - with the same error class or a
        different one - is still recorded rather than invisible.
        """
        if not constants.COLLECTINFO_RETRY_TIMED_OUT_SECTIONS:
            return

        timed_out = _timed_out_nodes(ledger)

        if not timed_out:
            return

        def nodes_for(*sections: str) -> list[str]:
            return sorted(
                node_key
                for node_key, failed in timed_out.items()
                if failed.intersection(sections)
            )

        section = constants.CollectinfoSection
        retry_ledger: NodeErrorLedger = {}
        retryable = (
            _RetryableSection(
                ledger_sections=(section.STATISTICS, section.CONFIG),
                getter=self._get_as_data_json,
                merge_section=None,
                target=as_map,
            ),
            _RetryableSection(
                ledger_sections=(section.METADATA,),
                getter=self._get_as_metadata,
                merge_section=section.METADATA,
                target=meta_map,
            ),
            _RetryableSection(
                ledger_sections=(section.HISTOGRAM,),
                getter=self._get_as_histograms,
                merge_section=section.HISTOGRAM,
                target=histogram_map,
            ),
            _RetryableSection(
                ledger_sections=(section.LATENCY,),
                getter=self._get_as_latency,
                merge_section=section.LATENCY,
                target=latency_map,
            ),
            _RetryableSection(
                ledger_sections=(section.USER_AGENTS,),
                getter=self._get_as_user_agents,
                merge_section=section.USER_AGENTS,
                target=user_agents_map,
            ),
            _RetryableSection(
                ledger_sections=(section.SYSINFO,),
                getter=functools.partial(self._get_as_sysinfo, context=context),
                merge_section=section.SYSINFO,
                target=sys_map,
            ),
        )

        retries = [
            _RetryRow(
                nodes=nodes,
                merge_section=row.merge_section,
                target=row.target,
                coro=row.getter(nodes=nodes, ledger=retry_ledger),
            )
            for row in retryable
            if (nodes := nodes_for(*row.ledger_sections))
        ]

        if not retries:
            return

        logger.info(
            "Retrying %d node(s) whose collectinfo sections timed out.",
            len(timed_out),
        )

        retry_coros = [row.coro for row in retries]
        results = await asyncio.gather(*retry_coros, return_exceptions=True)

        for row, result in zip(retries, results):
            if isinstance(result, BaseException):
                logger.debug(
                    "Retry of %s for %s failed: %s",
                    row.merge_section or "statistics and config",
                    ", ".join(row.nodes),
                    result,
                )
                continue

            if row.merge_section is None:
                self._merge_retried_as_map(
                    ledger, retry_ledger, row.nodes, result, row.target
                )
                continue

            self._merge_retried_section(
                ledger, retry_ledger, row.nodes, result, row.merge_section, row.target
            )

        _merge_ledgers(ledger, retry_ledger)

    def _merge_retried_section(
        self,
        ledger: NodeErrorLedger,
        retry_ledger: NodeErrorLedger,
        nodes: list[str],
        retried,
        section: str,
        target,
    ) -> None:
        """Fold a retry's output into what the first pass already collected.

        A node is retried when any one of its sections timed out, and the retry
        re-queries all of them, so its output is not a superset of the first pass's.
        Assigning it wholesale would drop whatever the retry itself failed on, which
        for metadata means losing node_id, services, or endpoints that were already
        collected (TOOLS-3596).

        A node key missing from the retry's output means the retry never reached
        it: every getter iterates the responses it received, not the nodes it was
        asked for.
        """
        for node_key in nodes:
            _merge_retried_value(target, node_key, retried.get(node_key))
            _mark_error_recovered(
                ledger, retry_ledger, node_key, section, node_key in retried
            )

    def _merge_retried_as_map(
        self,
        ledger: NodeErrorLedger,
        retry_ledger: NodeErrorLedger,
        nodes: list[str],
        retried,
        as_map,
    ) -> None:
        """Fold retried statistics and config into the first pass, per subsection.

        Each of these sections is a dict of independently collected subsections
        (service, namespace, sets, sindex, xdr, ...), any of which can fail on its
        own. Replacing the whole section would lose every subsection the retry
        failed on but the first pass had.

        Both sections are collected by one getter, so a node present in its
        output was reached for both.
        """
        sections = (
            constants.CollectinfoSection.STATISTICS,
            constants.CollectinfoSection.CONFIG,
        )

        for node_key in nodes:
            attempted = node_key in retried
            node_data = retried.get(node_key) or {}

            for section in sections:
                target = as_map.setdefault(node_key, {})
                _merge_retried_value(target, section, node_data.get(section))
                _mark_error_recovered(
                    ledger, retry_ledger, node_key, section, attempted
                )

    async def _detect_node_discrepancies(
        self,
        queried_nodes: list[Node],
        dump_map: dict[str, Any],
        node_errors: NodeErrorLedger,
        enable_ssh: bool,
    ) -> dict[str, Any]:
        """Reconcile what was expected against what landed in the snapshot.

        Runs while the cluster is still connected, which is the only time the live
        peers/visibility/down-node views are available. Diagnostics must never break
        the bundle they describe, so a failure here degrades to a detection_error
        entry instead of propagating into the collection abort path.

        What is computed from the collected data - which nodes returned nothing,
        and why - is recorded before the live calls run, so one hung
        get_down_nodes costs only the peer reconciliation it is needed for rather
        than the whole account.

        A node that recorded an error without being in the queried set still gets
        an entry: a section whose getter is not node-scoped can fail for a node
        the collection never asked about, and dropping it would leave the failure
        recorded nowhere.
        """
        expected_node_keys = sorted({node.key for node in queried_nodes})
        responded_nodes: list[str] = []
        no_data_nodes: list[str] = []
        nodes_meta: dict[str, Any] = {}

        for node_key in expected_node_keys:
            as_stat = (dump_map.get(node_key) or {}).get("as_stat", {})

            if util.as_stat_has_aerospike_data(as_stat):
                responded_nodes.append(node_key)
            else:
                no_data_nodes.append(node_key)

        responded_set = set(responded_nodes)

        for node in queried_nodes:
            as_stat = (dump_map.get(node.key) or {}).get("as_stat", {})
            node_id = (as_stat.get("meta_data") or {}).get("node_id") or node.node_id

            nodes_meta[node.key] = {
                "node_id": node_id,
                "responded": node.key in responded_set,
                "sysinfo_source": self._sysinfo_source(node, dump_map, enable_ssh),
                "errors": _node_error_entries(node_errors, node.key),
            }

        for node_key in sorted(set(node_errors) - set(nodes_meta)):
            nodes_meta[node_key] = {
                "node_id": "",
                "responded": False,
                "sysinfo_source": constants.SysinfoSource.NONE,
                "errors": _node_error_entries(node_errors, node_key),
            }

        snapshot_meta: dict[str, Any] = {
            "expected_nodes": expected_node_keys,
            "responded_nodes": responded_nodes,
            "no_data_nodes": no_data_nodes,
            "nodes": nodes_meta,
        }

        discrepancies: dict[str, Any] = {
            "dropped_during_collection": [
                {
                    "node_key": node_key,
                    "error_class": _severe_error_class(node_errors, node_key),
                }
                for node_key in no_data_nodes
            ],
        }
        snapshot_meta["discrepancies"] = discrepancies

        try:
            visibility_error_nodes = self.cluster.get_visibility_error_nodes()
            discrepancies["visibility_error_nodes"] = sorted(
                visibility_error_nodes or []
            )
        except Exception as e:
            logger.warning("Failed to detect peer visibility errors: %s", e)
            logger.debug(traceback.format_exc())

        try:
            down_result = await self.cluster.get_down_nodes_detailed()
        except Exception as e:
            logger.warning("Failed to detect collectinfo node discrepancies: %s", e)
            logger.debug(traceback.format_exc())
            discrepancies["detection_error"] = str(e)

            return snapshot_meta

        discrepancies["cluster_down_nodes"] = sorted(down_result.down_nodes)

        if down_result.failed_nodes:
            discrepancies["down_detection_failed_nodes"] = sorted(
                down_result.failed_nodes
            )

        if self.cluster.only_connect_seed:
            discrepancies["missing_from_collection"] = []

            return snapshot_meta

        down = set(down_result.down_nodes)
        discrepancies["missing_from_collection"] = [
            entry
            for entry in self._detect_missing_from_collection(
                queried_nodes, dump_map, set(expected_node_keys)
            )
            if entry["node_key"] not in down
        ]

        return snapshot_meta

    def _detect_missing_from_collection(
        self,
        queried_nodes: list[Node],
        dump_map: dict[str, Any],
        expected_node_keys: set[str],
    ) -> list[dict[str, str]]:
        """Peers advertised by collected nodes that were never collected themselves.

        Peer keys are canonicalized through cluster.aliases first. Without that hop a
        multi-homed cluster (seeded via localhost or FQDN while peers advertise
        internal IPs) reports every peer as missing, and that false claim gets baked
        permanently into the bundle.

        Each entry records which collected node advertised the peer, as a node key
        rather than a sentence, so the reader owns the wording.

        The caller skips this entirely under --single-node (the crawl stops at the
        seed while the seed's info response still advertises every peer, so
        'missing' would be meaningless) and subtracts the cluster's own down-node
        list, so a departed alumni node is reported once, as down, rather than as a
        node asadm failed to reach.
        """
        aliases = self.cluster.aliases or {}
        missing: dict[str, dict[str, str]] = {}

        for node in queried_nodes:
            as_stat = (dump_map.get(node.key) or {}).get("as_stat", {})
            peers = (as_stat.get("meta_data") or {}).get("services")

            if not peers or isinstance(peers, str):
                continue

            for peer in peers:
                try:
                    peer_key = Node.create_key(peer[0], peer[1])
                except Exception:
                    continue

                peer_key = aliases.get(peer_key, peer_key)

                if peer_key in expected_node_keys or peer_key in missing:
                    continue

                missing[peer_key] = {
                    "node_key": peer_key,
                    "advertised_by": node.key,
                }

        return [missing[key] for key in sorted(missing)]

    def _sysinfo_source(
        self, node: Node, dump_map: dict[str, Any], enable_ssh: bool
    ) -> str:
        """Where this node's sys_stat actually came from.

        Keyed off the collected data rather than the flags: a mid-collection SSH
        failure is logged and swallowed by _get_remote_host_system_statistics without
        raising, so trusting enable_ssh alone would claim 'ssh' for a node whose
        sys_stat is empty.
        """
        if not util.has_content((dump_map.get(node.key) or {}).get("sys_stat")):
            return constants.SysinfoSource.NONE

        if node.is_localhost():
            return constants.SysinfoSource.LOCAL

        if enable_ssh:
            return constants.SysinfoSource.SSH

        return constants.SysinfoSource.NONE

    def _build_dump_map(
        self,
        expected_node_keys,
        as_map,
        sys_map,
        meta_map,
        histogram_map,
        latency_map,
        pmap_map,
        acl_map,
        user_agents_map,
        masking_map,
    ):
        """
        Merge the per-section maps into the per-node collectinfo dump.

        Iterates over the union of the queried nodes and every section map's keys rather
        than just ``as_map`` (statistics + config). A node whose stats/config calls all
        failed in the first parallel burst is absent from ``as_map`` but must still land
        in ``ascinfo.json`` (TOOLS-3596); it gets an empty ``as_stat`` that any surviving
        sections attach to. Seeding with ``expected_node_keys`` guarantees every queried
        node appears in the snapshot even if it produced no data anywhere.
        """
        all_nodes = set().union(
            expected_node_keys,
            as_map,
            sys_map,
            meta_map,
            histogram_map,
            latency_map,
            acl_map,
            user_agents_map,
            masking_map,
            pmap_map or {},
        )

        dump_map = {}

        # Sorted so the ascinfo.json node ordering is stable across runs.
        for node in sorted(all_nodes):
            dump_map[node] = {}
            dump_map[node]["as_stat"] = as_map.get(node, {})
            if node in sys_map:
                dump_map[node]["sys_stat"] = sys_map[node]
            if node in meta_map:
                dump_map[node]["as_stat"]["meta_data"] = meta_map[node]

            if node in histogram_map:
                dump_map[node]["as_stat"]["histogram"] = histogram_map[node]

            if node in latency_map:
                dump_map[node]["as_stat"]["latency"] = latency_map[node]

            if pmap_map and node in pmap_map:
                dump_map[node]["as_stat"]["pmap"] = pmap_map[node]

            # ACL requests only go to principal therefor we are storing it only
            # for the principal
            if node in acl_map:
                dump_map[node]["as_stat"]["acl"] = acl_map[node]

            if node in user_agents_map:
                dump_map[node]["as_stat"]["user_agents"] = user_agents_map[node]

            if node in masking_map:
                dump_map[node]["as_stat"]["masking"] = masking_map[node]

        no_data_nodes = [
            node
            for node in expected_node_keys
            if not util.as_stat_has_aerospike_data(dump_map[node]["as_stat"])
        ]
        if no_data_nodes:
            logger.warning(
                "collectinfo captured no Aerospike data for %d node(s): %s. Re-running "
                "with a larger --timeout may help.",
                len(no_data_nodes),
                ", ".join(sorted(no_data_nodes)),
            )

        return dump_map

    def _dump_in_json_file(self, complete_name, dump):
        """Write one bundle file as JSON, falling back to pprint.

        Exception values cannot reach here, which is what makes json.dumps safe:
        every per-node failure is recorded in the error ledger and replaced with
        {} upstream. The fallback exists for anything else json cannot encode.
        """
        try:
            json_dump = json.dumps(dump, indent=2, separators=(",", ":"))
            self._dump_collectinfo_file(complete_name, json_dump)
        except Exception:
            pretty_json = pprint.pformat(dump, indent=1)
            logger.debug(pretty_json)
            raise

    async def _dump_collectinfo_json(
        self, as_logfile_prefix, context: CollectionContext
    ):
        """Collect every snapshot and write ascinfo.json and the metadata sidecar.

        Both files are written in a finally: a run that dies partway still
        archives whatever it collected, and the metadata records that it did not
        finish. Without it an aborted bundle is indistinguishable from one
        collected before the metadata file existed, and the analyzer's heuristics
        then describe a truncated bundle as an old one.
        """
        snpshots: dict[str, Any] = {}
        snapshot_metas: dict[str, Any] = {}
        start_ts = time.strftime(constants.COLLECTINFO_TIMESTAMP_FORMAT, time.gmtime())
        aborted = True

        try:
            for i in range(context.snp_count):
                snp_timestamp, observed_timestamp = await self._next_snapshot_timestamp(
                    snpshots
                )
                logger.info(
                    "Data collection for Snapshot: " + str(i + 1) + " in progress..."
                )

                snpshots[snp_timestamp], snapshot_meta = (
                    await self._get_collectinfo_data_json(context)
                )
                snapshot_meta["timestamp"] = snp_timestamp

                if observed_timestamp != snp_timestamp:
                    snapshot_meta["timestamp_adjusted"] = True
                    snapshot_meta["observed_timestamp"] = observed_timestamp

                snapshot_metas[snp_timestamp] = snapshot_meta

                logger.info("Data collection for Snapshot " + str(i + 1) + " finished.")

                await asyncio.sleep(context.wait_time)

            aborted = False
        finally:
            if snpshots:
                self._dump_in_json_file(
                    as_logfile_prefix + constants.COLLECTINFO_DATA_FILENAME, snpshots
                )

            self._dump_collectinfo_meta(
                as_logfile_prefix,
                list(snapshot_metas.values()),
                start_ts=start_ts,
                context=context,
                aborted=aborted,
            )

    async def _next_snapshot_timestamp(
        self, snpshots: dict[str, Any]
    ) -> "SnapshotTimestamp":
        """A snapshot timestamp no earlier snapshot in this run is using.

        The timestamp is the key of both the snapshot data and its meta, and it
        has second resolution: with `-s 0` two snapshots can land in the same
        second, and the second one would overwrite the first's data while both
        metas survived, leaving the analyzer describing data the bundle does not
        contain. Waiting for the next second keeps every snapshot addressable.

        Bounded, and never blocks the collection: a clock that does not advance
        (frozen, or stepped backwards mid-run) would otherwise hold the run here
        forever. After the retries a synthetic timestamp one second past the
        newest existing snapshot is allocated instead: overwriting an earlier
        snapshot would silently lose it while the metadata still described the
        collection as complete. The observed clock value is kept alongside so the
        synthetic key is disclosed in the meta.
        """
        timestamp = time.strftime(constants.COLLECTINFO_TIMESTAMP_FORMAT, time.gmtime())

        for _ in range(SNAPSHOT_TIMESTAMP_RETRIES):
            if timestamp not in snpshots:
                return SnapshotTimestamp(timestamp, timestamp)

            await asyncio.sleep(1)
            timestamp = time.strftime(
                constants.COLLECTINFO_TIMESTAMP_FORMAT, time.gmtime()
            )

        if timestamp in snpshots:
            newest = max(
                datetime.strptime(ts, constants.COLLECTINFO_TIMESTAMP_FORMAT)
                for ts in snpshots
            )
            allocated = (newest + timedelta(seconds=1)).strftime(
                constants.COLLECTINFO_TIMESTAMP_FORMAT
            )
            logger.warning(
                "Snapshot timestamp %s is still in use after waiting; recording "
                "this snapshot as %s instead.",
                timestamp,
                allocated,
            )

            return SnapshotTimestamp(allocated, timestamp)

        return SnapshotTimestamp(timestamp, timestamp)

    def _dump_collectinfo_meta(
        self,
        as_logfile_prefix,
        snapshot_metas,
        start_ts,
        context: CollectionContext,
        aborted=False,
    ) -> None:
        """Write the provenance/diagnostics sidecar.

        Guarded end-to-end: a bug in the metadata must never abort a collection or
        trip the --ignore-errors path. ascinfo.json is already written by this point
        and is deliberately outside this guard.
        """
        try:
            meta = self._build_collectinfo_meta(
                snapshot_metas,
                start_ts=start_ts,
                context=context,
                aborted=aborted,
            )
            self._dump_in_json_file(
                as_logfile_prefix + constants.COLLECTINFO_META_FILENAME, meta
            )
        except Exception as e:
            logger.warning(
                "Failed to write %s: %s", constants.COLLECTINFO_META_FILENAME, e
            )
            logger.debug(traceback.format_exc())

    def _node_selection(self) -> str | list[str]:
        """What the collection was scoped to, as recorded in the bundle.

        `collectinfo with <nodes>` is a supported way to collect part of a cluster.
        Without recording it, the nodes the user deliberately excluded are
        indistinguishable from nodes asadm failed to reach: they appear in the
        collected nodes' peer lists and nowhere else.
        """
        if isinstance(self.nodes, (list, tuple, set)):
            return sorted(str(node) for node in self.nodes)

        return str(self.nodes)

    def _build_collectinfo_meta(
        self,
        snapshot_metas,
        start_ts,
        context: CollectionContext,
        aborted=False,
    ) -> dict[str, Any]:
        """Assemble collectinfo_meta.json, the bundle's provenance sidecar.

        This file is a persistent format read by other asadm versions, so its
        compatibility contract is: readers ignore unknown keys, an absent key
        means 'not recorded' (never 'clean'), and
        constants.COLLECTINFO_META_FORMAT_VERSION bumps only on a change an
        older reader would misinterpret. The analyzer warns, and keeps reading,
        when it meets a newer version.
        """
        seeds = [
            {"addr": seed[0], "port": seed[1], "tls_name": seed[2]}
            for seed in sorted(
                self.cluster.get_seed_nodes(), key=lambda s: (str(s[0]), str(s[1]))
            )
        ]

        try:
            host = socket.gethostname()
        except Exception:
            host = ""

        return {
            "meta_format_version": constants.COLLECTINFO_META_FORMAT_VERSION,
            "bundle": {
                "asadm_version": str(self.asadm_version),
                "asadm_build": str(self.asadm_build),
                "generated_by": constants.COLLECTINFO_GENERATED_BY,
            },
            "collection": {
                "host": host,
                "aborted": bool(aborted),
                "start_ts_utc": start_ts,
                "end_ts_utc": time.strftime(
                    constants.COLLECTINFO_TIMESTAMP_FORMAT, time.gmtime()
                ),
                "snapshot_count": context.snp_count,
                "flags": {
                    "enable_ssh": bool(context.enable_ssh),
                    "node_selection": self._node_selection(),
                    "only_connect_seed": bool(self.cluster.only_connect_seed),
                    "use_services_alumni": bool(self.cluster.use_services_alumni),
                    "use_services_alt": bool(self.cluster.use_services_alt),
                    "effective_node_timeout_sec": context.effective_timeout,
                    "requested_node_timeout_sec": context.requested_timeout,
                    "sleep_between_snapshots_sec": context.wait_time,
                    "output_prefix": context.output_prefix,
                    "asconfig_file": context.asconfig_file,
                    "ignore_errors": bool(context.ignore_errors),
                },
                "seeds": seeds,
            },
            "snapshots": snapshot_metas,
        }

    def _dump_collectinfo_file(self, filename: str, dump: str):
        logger.info("Dumping collectinfo %s.", filename)

        try:
            util.write_to_file(filename, dump)
        except Exception as e:
            logger.warning("Failed to write file {}: {}", filename, str(e))
            raise

    ###########################################################################
    # Functions for dumping pretty print files

    async def _dump_collectinfo_ascollectinfo(
        self, as_logfile_prefix, file_header
    ) -> None:
        ####### Dignostic info ########
        file = "ascollectinfo.log"
        complete_filename = as_logfile_prefix + file
        logger.info(f"Capturing pretty print output for {file} . . .")

        try:
            dignostic_info_params = [
                "network",
                "namespace",
                "set",
                "xdr",
                "dc",
                "sindex",
                "release",
            ]

            dignostic_features_params = ["features"]

            dignostic_show_params = [
                "config",
                "config xdr",
                "config dc",
                "config cluster",
                "distribution",
                "distribution eviction",
                "distribution object_size -b",
                "latencies -v -e 1 -b 17",
                "statistics",
                "statistics xdr",
                "statistics dc",
                "statistics sindex",
            ]

            if CollectinfoController.get_pmap:
                dignostic_show_params.append("pmap")

            dignostic_aerospike_info_commands = [
                "connection",
                "service-clear-std",
                "service-clear-alt",
                "service-tls-std",
                "service-tls-alt",
                "peers-clear-std",
                "peers-clear-alt",
                "peers-tls-std",
                "peers-tls-alt",
                "alumni-clear-std",
                "alumni-tls-std",
                "alumni-clear-alt",
                "alumni-tls-alt",
                "peers-generation",
                "roster:",
            ]

            as_version = asyncio.create_task(self.cluster.info("build"))
            namespaces = asyncio.create_task(self.cluster.info("namespaces"))

            # find version
            try:
                as_version = await as_version
                as_version = as_version.popitem()[1]
            except Exception:
                as_version = None

            if isinstance(as_version, Exception):
                as_version = None

            # find all namespaces
            try:
                namespaces = self._parse_namespace(await namespaces)
            except Exception:
                namespaces = []

            # add hist-dump or histogram command to collect list

            hist_list = ["ttl", "object-size", "object-size-linear"]
            hist_dump_info_str = "histogram:namespace=%s;type=%s"

            try:
                if version.LooseVersion(as_version) < version.LooseVersion("4.2.0"):
                    # histogram command introduced in 4.2.0
                    # use hist-dump command for older versions
                    hist_list = ["ttl", "objsz"]
                    hist_dump_info_str = "hist-dump:ns=%s;hist=%s"
            except Exception:  # probably failed to get build version, node may be down
                pass

            for ns in namespaces:
                for hist in hist_list:
                    dignostic_aerospike_info_commands.append(
                        hist_dump_info_str % (ns, hist)
                    )

            util.write_to_file(complete_filename, file_header)

            # All these calls to collectinfo_content must happen synchronously because they
            # capture std output.
            try:
                await self._collectinfo_capture_and_write_to_file(
                    complete_filename, self._write_version
                )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                info_controller = InfoController()
                for info_param in dignostic_info_params:
                    logger.info(
                        f"Capturing output of command 'info {info_param}' and writing to {file}"
                    )
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename, info_controller, info_param.split()
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                show_controller = ShowController()
                for show_param in dignostic_show_params:
                    logger.info(
                        f"Capturing output of command 'show {show_param}' for {file}"
                    )
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename, show_controller, show_param.split()
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                features_controller = FeaturesController()
                for cmd in dignostic_features_params:
                    logger.info(
                        f"Capturing output of command '{cmd}' and writing to {file}"
                    )
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename, features_controller, cmd.split()
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                for cmd in dignostic_aerospike_info_commands:
                    logger.info(
                        f"Capturing output of asinfo command '{cmd}' and writing to {file}"
                    )
                    result = await self.cluster.info(cmd)
                    self._write_func_output_to_file(
                        complete_filename, self.cluster.info, [cmd], result
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))
        except Exception as e:
            util.write_to_file(complete_filename, str(e))
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.debug(traceback.format_exc())
            raise

        logger.info(f"Finished capturing pretty print output for {file}.")

    async def _dump_collectinfo_summary(self, as_logfile_prefix: str, fileHeader: str):
        complete_filename = as_logfile_prefix + "summary.log"

        try:
            util.write_to_file(complete_filename, fileHeader)

            summary_params = ["summary"]
            summary_info_params = ["network", "namespace", "set", "xdr", "dc", "sindex"]

            try:
                await self._collectinfo_capture_and_write_to_file(
                    complete_filename, self._write_version
                )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            if self.collectinfo_root_controller is None:
                logger.critical("Collectinfo root controller is not initialized.")
                return

            try:
                for summary_param in summary_params:
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename,
                        self.collectinfo_root_controller.execute,
                        summary_param.split(),
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                info_controller = InfoController()
                for info_param in summary_info_params:
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename, info_controller, info_param.split()
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

        except Exception as e:
            util.write_to_file(complete_filename, str(e))
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.debug(traceback.format_exc())
            raise

    async def _dump_collectinfo_health(self, as_logfile_prefix: str, fileHeader: str):
        if self.collectinfo_root_controller is None:
            logger.critical("Collectinfo root controller is not initialized.")
            return

        complete_filename = as_logfile_prefix + "health.log"

        health_params = ["health -v"]

        try:
            util.write_to_file(complete_filename, fileHeader)

            for health_param in health_params:
                await self._collectinfo_capture_and_write_to_file(
                    complete_filename,
                    self.collectinfo_root_controller.execute,
                    health_param.split(),
                )
        except Exception as e:
            util.write_to_file(complete_filename, str(e))
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.debug(traceback.format_exc())
            raise

    async def _dump_collectinfo_sysinfo(self, as_logfile_prefix: str, fileHeader: str):
        complete_filename = as_logfile_prefix + "sysinfo.log"

        # getting service port to use in ss/netstat command
        port = 3000
        try:
            _, port, _ = self.cluster.get_seed_nodes()[0]
        except Exception:
            port = 3000

        try:
            self.failed_cmds = common.collect_sys_info(
                port=port, file_header=fileHeader, outfile=complete_filename
            )
        except Exception as e:
            util.write_to_file(complete_filename, str(e))
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.debug(traceback.format_exc())
            raise

    async def _dump_collectinfo_aerospike_conf(
        self, as_logfile_prefix: str, conf_path: str | None = None
    ):
        """
        Gets the static aerospike.conf if available.
        """
        complete_filename = as_logfile_prefix + "aerospike.conf"

        if not conf_path:
            conf_path = "/etc/aerospike/aerospike.conf"

        try:
            self._collect_local_file(conf_path, complete_filename)
        except Exception as e:
            logger.debug(traceback.format_exc())
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.warning(str(e))
            util.write_to_file(complete_filename, str(e))

    def setup_loggers(self, individual_file_prefix: str):
        debug_file = individual_file_prefix + "collectinfo_debug.log"
        self.debug_output_handler = logging.FileHandler(debug_file)
        self.debug_output_handler.setLevel(logging.DEBUG)
        self.debug_output_handler.setFormatter(LogFormatter())
        self.loggers: list[logging.Logger | logging.Handler] = [
            g_logger,
            stderr_log_handler,
            logging.getLogger(Node.__module__),
            logging.getLogger(common.__name__),
            logging.getLogger(LogFileDownloader.__module__),
        ]
        self.old_levels = [logger.level for logger in self.loggers]

        g_logger.setLevel(logging.DEBUG)

        for logger in self.loggers[1:]:
            # Only set the level to INFO if it is not already set to DEBUG or INFO.
            if logger.level > logging.INFO:
                logger.setLevel(logging.INFO)

        g_logger.addHandler(self.debug_output_handler)

    def teardown_loggers(self):
        g_logger.removeHandler(self.debug_output_handler)
        for logger, level in zip(self.loggers, self.old_levels):
            logger.setLevel(level)

        # TODO: clean up log levels

    ###########################################################################
    # Collectinfo caller functions

    async def _run_collectinfo(
        self,
        ssh_user: str | None,
        ssh_pwd: str | None,
        ssh_port: int | None,
        ssh_key: str | None,
        ssh_key_pwd: str | None,
        snp_count: int,
        wait_time: int,
        ignore_errors: bool,
        enable_ssh: bool = False,
        output_prefix: str = "",
        config_path: str = "",
    ):
        # JSON collectinfo snapshot count check
        if snp_count < 1:
            logger.error("Wrong collectinfo snapshot count")
            return

        timestamp = time.gmtime()
        cf_path_info = common.get_collectinfo_path(
            timestamp,
            output_prefix=output_prefix,
        )
        individual_file_prefix = path.join(
            cf_path_info.cf_dir,
            cf_path_info.files_prefix,
        )
        ignore_errors_msg = "Aborting collectinfo. To bypass use --ignore-errors."

        # Raise the per-node timeout for the collectinfo run to avoid transient timeouts
        # dropping nodes from the bundle (TOOLS-3596). Never lower an explicit larger
        # --timeout. Computed before the try so the finally can always restore.
        original_timeout = self.cluster._timeout
        collectinfo_timeout = max(original_timeout, COLLECTINFO_NODE_TIMEOUT)

        try:
            # Coloring might writes extra characters to file, to avoid it we need to disable terminal coloring
            self.setup_loggers(individual_file_prefix)
            terminal.enable_color(False)

            if collectinfo_timeout != original_timeout:
                logger.debug(
                    "Raising per-node timeout to %ss for collectinfo",
                    collectinfo_timeout,
                )
                self.cluster.set_timeout(collectinfo_timeout)

            file_header = time.strftime("%Y-%m-%d %H:%M:%S UTC\n", timestamp)
            self.failed_cmds = []

            # A failed collection still reaches the archive step: the json dump
            # preserves every collected snapshot and the aborted meta in its
            # finally, and evidence left only in the working directory never
            # reaches the operator. Only the derived outputs are skipped, since
            # they would be built from data known to be incomplete.
            collection_aborted = False

            try:
                await self._dump_collectinfo_json(
                    individual_file_prefix,
                    CollectionContext(
                        enable_ssh=enable_ssh,
                        ssh_user=ssh_user,
                        ssh_pwd=ssh_pwd,
                        ssh_key=ssh_key,
                        ssh_key_pwd=ssh_key_pwd,
                        ssh_port=ssh_port,
                        snp_count=snp_count,
                        wait_time=wait_time,
                        requested_timeout=original_timeout,
                        effective_timeout=collectinfo_timeout,
                        output_prefix=output_prefix,
                        asconfig_file=config_path,
                        ignore_errors=ignore_errors,
                    ),
                )
            except FileNotFoundError as e:
                logger.error(ShellException(_describe_exception(e)))
                logger.error(
                    "Failed to open a local file needed by the collection. Archiving what was collected."
                )
                collection_aborted = True
            except Exception as e:
                logger.error(_describe_exception(e))
                logger.debug(traceback.format_exc())
                if not ignore_errors:
                    logger.error(ignore_errors_msg)
                    collection_aborted = True

            if not collection_aborted:
                # Must happen after json dump and before summary and health. The json data is used
                # to generate the summary and health output.
                live_version = BaseController.asadm_version
                live_build = BaseController.asadm_build

                try:
                    self.collectinfo_root_controller = CollectinfoRootController(
                        asadm_version=self.asadm_version,
                        clinfo_path=cf_path_info.cf_dir,
                        asadm_build=self.asadm_build,
                    )

                    coroutines = [
                        self._dump_collectinfo_ascollectinfo(
                            individual_file_prefix, file_header
                        ),
                        self._dump_collectinfo_summary(
                            individual_file_prefix, file_header
                        ),
                        self._dump_collectinfo_health(
                            individual_file_prefix, file_header
                        ),
                    ]

                    if self.cluster.is_localhost_a_node():
                        coroutines.append(
                            self._dump_collectinfo_sysinfo(
                                individual_file_prefix, file_header
                            )
                        )
                        coroutines.append(
                            self._dump_collectinfo_aerospike_conf(
                                individual_file_prefix, config_path
                            )
                        )
                    else:
                        logger.info(
                            "Localhost is not an Aerospike node. Skipping sysinfo.log and aerospike.conf collection."
                        )

                    for c in coroutines:
                        try:
                            await c
                        except:
                            # close remaining coroutines.  An error will be raised if they are not
                            # awaited.
                            for c in coroutines:
                                c.close()

                            if not ignore_errors:
                                logger.error(ignore_errors_msg)
                                collection_aborted = True
                                break
                finally:
                    # CollectinfoRootController stores the version and build on
                    # BaseController, so building one mid-session overwrites the live
                    # session's.
                    BaseController.asadm_version = live_version
                    BaseController.asadm_build = live_build

            common.print_collectinfo_failed_cmds(self.failed_cmds)

            # Archive collectinfo directory
            cf_archive_path, success = common.archive_dir(cf_path_info.cf_dir)

            if success:
                if collection_aborted:
                    logger.warning(
                        "The collection did not complete. The archive holds the "
                        "snapshots collected before the failure, and its metadata "
                        "records the collection as aborted."
                    )
                common.print_collect_summary(
                    cf_archive_path,
                )
            else:
                logger.error(
                    "Failed to archive collectinfo logs. See earlier errors for more details."
                )
        finally:
            # Best-effort restore before teardown (in-flight sockets may briefly retain the
            # raised timeout); wrapped so a failure here cannot skip teardown (TOOLS-3596).
            try:
                if collectinfo_timeout != original_timeout:
                    self.cluster.set_timeout(original_timeout)
            finally:
                self.teardown_loggers()
                terminal.enable_color(True)

    async def _do_default(self, line):
        snp_count = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-n",
            return_type=int,
            default=1,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        wait_time = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-t",
            return_type=int,
            default=5,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        enable_ssh = util.check_arg_and_delete_from_mods(
            line=line,
            arg="--enable-ssh",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_user = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-user",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_pwd = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-pwd",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_port = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-port",
            return_type=int,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_key = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-key",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_key_pwd = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-key-pwd",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        output_prefix = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--output-prefix",
            return_type=str,
            default="",
            modifiers=self.modifiers,
            mods=self.mods,
        )
        output_prefix = util.strip_string(output_prefix)

        config_path = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--asconfig-file",
            return_type=str,
            default="",
            modifiers=self.modifiers,
            mods=self.mods,
        )
        config_path = util.strip_string(config_path)

        ignore_errors = util.check_arg_and_delete_from_mods(
            line=line,
            arg="--ignore-errors",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        if line:
            logger.error("Unrecognized option(s): {}".format(", ".join(line)))

        await self._run_collectinfo(
            ssh_user,
            ssh_pwd,
            ssh_port,
            ssh_key,
            ssh_key_pwd,
            snp_count,
            wait_time,
            ignore_errors,
            enable_ssh=enable_ssh,
            output_prefix=output_prefix,
            config_path=config_path,
        )
