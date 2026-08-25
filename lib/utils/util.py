# Copyright 2017-2025 Aerospike, Inc.
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
from asyncio.subprocess import Process
import base64
from collections import defaultdict
import copy
import functools
import inspect
import io
import math
import re
import shlex
import socket
import subprocess
import sys
import logging
from lib.utils import constants, version
from time import time
from typing import (
    Any,
    Awaitable,
    Callable,
    Generator,
    Generic,
    Iterable,
    Literal,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

logger = logging.getLogger(__name__)


def callable(func, *args, **kwargs):
    """
    Save a function call for later. Useful for saving functions that print output.
    """
    return lambda: func(*args, **kwargs)


def shell_command(command) -> tuple[str, str]:
    """
    command is a list of ['cmd','arg1','arg2',...] or a single shell command string

    If command has one element, it's treated as a shell command string (may contain pipes, redirects, etc.)
    If command has multiple elements, each element is quoted and joined with spaces
    """
    if len(command) == 1:
        # Single shell command string - pass directly to bash without additional quoting
        cmd_str = command[0]
    else:
        # Multiple arguments - quote each and join
        cmd_str = " ".join(shlex.quote(part) for part in command)

    command = ["bash", "-c", cmd_str]
    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
    except Exception:
        return "", "error"
    else:
        return bytes_to_str(out), bytes_to_str(err)


async def async_shell_command(command: str) -> Process | None:
    """
    command is a list of ['cmd','arg1','arg2',...]
    """

    try:
        p = await asyncio.create_subprocess_exec(
            "bash",
            *["-c", f"{command}"],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        await p.wait()
        return p
    except Exception:
        logger.debug("Error running command: %s", command)
        return None


async def capture_stdout(func, *args, **kwargs):
    """
    Redirecting the stdout to use the output elsewhere
    """

    sys.stdout.flush()
    old = sys.stdout

    try:
        capturer = io.StringIO()
        sys.stdout = capturer

        if inspect.iscoroutinefunction(func):
            await func(*args, **kwargs)
        else:
            tmp_output = func(*args, **kwargs)

            if inspect.iscoroutine(tmp_output):
                tmp_output = await tmp_output

        output = capturer.getvalue()
    finally:
        sys.stdout = old

    return output


def capture_stderr(func, *args, **kwargs):
    """
    Redirecting the stderr to use the output elsewhere
    """

    sys.stderr.flush()
    old = sys.stderr
    capturer = io.StringIO()
    sys.stderr = capturer

    func(*args, **kwargs)

    output = capturer.getvalue()
    sys.stderr = old
    return output


def compile_likes(likes):
    if likes is None:
        likes = []

    likes = ["(" + like.translate(str.maketrans("", "", "'\"")) + ")" for like in likes]
    likes = "|".join(likes)
    likes = re.compile(likes)
    return likes


def filter_list(
    ilist: Iterable[str], pattern_list: Iterable[str] | None
) -> Iterable[str] | filter:
    if not ilist or not pattern_list:
        return ilist
    likes = compile_likes(pattern_list)
    return filter(likes.search, ilist)


def clear_val_from_list_in_dict(keys, d, val):
    for key in keys:
        if key in d and val in d[key]:
            d[key].remove(val)


ReturnType = TypeVar("ReturnType")
DefaultType = TypeVar("DefaultType")


def fetch_argument(
    line, arg, default: DefaultType
) -> Union[tuple[Literal[True], str], tuple[Literal[False], DefaultType]]:
    success = True
    try:
        if arg in line:
            i = line.index(arg)
            val = line[i + 1]
            return success, val
    except Exception:
        pass
    return not success, default


def _fetch_line_clear_dict(
    line, arg, return_type: Type[ReturnType], default: DefaultType, keys, d
) -> Union[DefaultType, ReturnType]:
    if not line:
        return default
    try:
        success, _val = fetch_argument(line, arg, default)
        if _val is not None:
            val = return_type(_val)
        else:
            val = None

        if success and keys and d:
            clear_val_from_list_in_dict(keys, d, arg)
            clear_val_from_list_in_dict(keys, d, _val)

    except Exception:
        val = default
    return val


def get_arg_and_delete_from_mods(
    line, arg, return_type: Type[ReturnType], default: DefaultType, modifiers, mods
) -> Union[DefaultType, ReturnType]:
    try:
        val = _fetch_line_clear_dict(
            line=line,
            arg=arg,
            return_type=return_type,
            default=default,
            keys=modifiers,
            d=mods,
        )

        line.remove(arg)

        if val:
            line.remove(str(val))
    except Exception:
        val = default
    return val


def check_arg_and_delete_from_mods(line, arg, default, modifiers, mods):
    try:
        if arg in line:
            val = True
            clear_val_from_list_in_dict(modifiers, mods, arg)
            line.remove(arg)
        else:
            val = False
    except Exception:
        val = default
    return val


CMD_FILE_SINGLE_LINE_COMMENT_START = "//"
CMD_FILE_MULTI_LINE_COMMENT_START = "/*"
CMD_FILE_MULTI_LINE_COMMENT_END = "*/"


def parse_commands(file_or_queries, command_end_char=";", is_file=True):
    commands = ""
    try:
        commented = False
        if is_file:
            lines = open(file_or_queries, "r").readlines()
        else:
            lines = file_or_queries.split("\n")

        for line in lines:
            if not line or not line.strip():
                continue
            line = line.strip()
            if commented:
                if line.endswith(CMD_FILE_MULTI_LINE_COMMENT_END):
                    commented = False
                continue
            if line.startswith(CMD_FILE_SINGLE_LINE_COMMENT_START):
                continue
            if line.startswith(CMD_FILE_MULTI_LINE_COMMENT_START):
                if not line.endswith(CMD_FILE_MULTI_LINE_COMMENT_END):
                    commented = True
                continue
            try:
                if line.endswith(command_end_char):
                    line = line.replace("\n", "")
                else:
                    line = line.replace("\n", " ")
                commands = commands + line
            except Exception:
                commands = line
    except Exception:
        pass
    return commands


def parse_queries(file, delimiter=";", is_file=True):
    queries_str = parse_commands(file, is_file=is_file)
    if queries_str:
        return queries_str.split(delimiter)
    else:
        return []


def set_value_in_dict(d, key, value):
    if (
        d is None
        or not isinstance(d, dict)
        or not key
        or (not value and value != 0 and value is not False)
        or isinstance(value, Exception)
    ):
        return

    d[key] = value


@overload
def _cast(value: str, return_type: None) -> Tuple[str, Literal[True]]:
    pass


@overload
def _cast(value: str, return_type: Type[bool]) -> Tuple[bool, bool]:
    pass


@overload
def _cast(
    value: str, return_type: Type[ReturnType]
) -> Tuple[Union[ReturnType, None], bool]:
    pass


def _cast(
    value: str, return_type: Union[Type[ReturnType], None, Type[bool]] = str
) -> Union[
    Tuple[Union[ReturnType, None], bool], Tuple[str, Literal[True]], Tuple[bool, bool]
]:
    """
    Function takes value and data type to cast.
    Returns result of casting and success status
    """

    if not return_type or value is None:
        return value, True

    try:
        if return_type == bool and isinstance(value, str):
            if value.lower() == "false":
                return False, True
            if value.lower() == "true":
                return True, True
    except Exception:
        pass

    try:
        return return_type(value), True
    except Exception:
        pass

    return None, False


def get_value_from_dict(
    d, keys, default_value: DefaultType = None, return_type: Type[ReturnType] = None
) -> Union[DefaultType, ReturnType]:
    """
    Function takes dictionary and keys to find values inside dictionary.
    Returns value of first matching key from keys which is available in d else returns default_value
    """

    if not isinstance(keys, tuple) and not isinstance(keys, list):
        keys = (keys,)

    for key in keys:
        if key in d:
            val, success = _cast(d[key], return_type=return_type)
            if success:
                return val

            return default_value
    return default_value


def get_values_from_dict(
    d, re_keys, return_type: Type[ReturnType] = str
) -> list[ReturnType]:
    """
    Function takes dictionary and regular expressions for keys to find values inside dictionary.
    Returns list of values for all matching keys with any of regular expression keys else returns empty list
    """

    values = []
    if not re_keys or not d or not isinstance(d, dict):
        return values

    if not isinstance(re_keys, tuple) and not isinstance(re_keys, list):
        re_keys = (re_keys,)

    keys = filter_list(d.keys(), re_keys)

    for key in keys:
        val, success = _cast(d[key], return_type=return_type)
        if success:
            values.append(val)
            continue

        values.append(d[key])

    return values


def strip_string(search_str):
    return search_str.strip().strip("'\"")


def flip_keys(orig_data):
    """
    Flips a two level nested dictionary.
    Example:
    {key1: {key2: value, key3: value}} => {key2: {key1: value}, {key3: value}}
    """
    new_data = {}
    for key1, data1 in orig_data.items():
        if isinstance(data1, Exception):
            continue

        for key2, data2 in data1.items():
            if key2 not in new_data:
                new_data[key2] = {}

            new_data[key2][key1] = data2

    return new_data


MAX_STAT_BYTES = 1 << 70
CGROUP_MEMORY_NO_LIMIT_THRESHOLD = 1 << 62


def int_or_zero(value):
    """
    Coerce a raw server value to a bounded int, zero when it is not usable.

    Hex-looking strings such as '9E0123456789' parse as scientific notation and
    overflow to inf, and CPython accepts integer literals up to its digit limit,
    so a result outside +/-MAX_STAT_BYTES is rejected as unusable and returns
    zero, which every caller already treats as stat absent.
    """
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = float(value)
        except (TypeError, ValueError, OverflowError):
            return 0

        if math.isinf(parsed) or math.isnan(parsed):
            return 0

        parsed = int(parsed)

    if not -MAX_STAT_BYTES <= parsed <= MAX_STAT_BYTES:
        return 0

    return parsed


def summarize_nodes(names, total, limit=3):
    """
    Render a node list for a warning without spilling a paragraph.

    A cluster-wide problem only needs its shape stated: on a 14 node cluster
    every FQDN comes to about 1.2 KB of one-line warning to say 'all of them'.
    The per-node answer already lives in the table's Build column, so the
    warning names nodes only while the list is short enough to act on.
    """
    names = sorted(names)

    if len(names) <= limit:
        return ", ".join(names)

    if total and len(names) >= total:
        return "all %d nodes" % total

    return "%s and %d more" % (", ".join(names[:limit]), len(names) - limit)


def cgroup_limit_or_zero(value):
    """
    Normalize cgroup_memory_limit_bytes to a usable limit, else zero.

    An uncapped cgroup reports either 'max' (v2), a negative value, or a
    near-int64 sentinel (v1), and CGROUP_MEMORY_NO_LIMIT_THRESHOLD catches every
    one of those without reference to anything else. Any other value the kernel
    reports is a measurement and is reported as given, even when it exceeds host
    RAM: that is a real misconfiguration the operator needs to see, and the only
    yardstick asadm could check it against is its own estimated host total.
    """
    limit = int_or_zero(value)

    if not 0 < limit < CGROUP_MEMORY_NO_LIMIT_THRESHOLD:
        return 0

    return limit


_DEVICE_BACKINGS = ("pmem", "flash")
_NS_MEMORY_USED_KEYS = {
    "index_used_bytes": "index-type",
    "sindex_used_bytes": "sindex-type",
    "set_index_used_bytes": None,
}
_NS_MEMORY_ALLOC_KEYS = {
    "shmem_alloc_bytes": ("index_shmem_alloc_bytes", "sindex_shmem_alloc_bytes"),
    "pi_alloc_bytes": ("index_shmem_alloc_bytes",),
    "si_alloc_bytes": ("sindex_shmem_alloc_bytes",),
    "set_alloc_bytes": ("set_index_alloc_bytes",),
}
_NS_MEMORY_ALLOC_ARENA_SOURCES = (
    "pi_alloc_bytes",
    "si_alloc_bytes",
    "set_alloc_bytes",
)
_NS_MEMORY_ALLOC_TOTAL_SOURCES = _NS_MEMORY_ALLOC_ARENA_SOURCES + ("data_alloc_bytes",)
_NS_MEMORY_USED_TOTAL_SOURCES = tuple(_NS_MEMORY_USED_KEYS) + (
    "data_in_memory_used_bytes",
)


def _accumulate_ns_memory(totals, ns_data, fold_data_into_shmem):
    """
    Add one namespace's RAM-backed memory stats into a node's running totals.

    _NS_MEMORY_USED_KEYS maps each used stat to the config key naming its
    backing, or None when the stat is always RAM backed. index_used_bytes and
    sindex_used_bytes were consolidated across backings in 7.0, so a flash or
    pmem arena reports through the same stat and has to be skipped by backing.
    _NS_MEMORY_ALLOC_KEYS maps each aggregated key to the stats summed into it.
    """
    for key, backing_key in _NS_MEMORY_USED_KEYS.items():
        if key not in ns_data:
            continue

        if backing_key and ns_data.get(backing_key, "shmem") in _DEVICE_BACKINGS:
            continue

        totals[key] += int_or_zero(ns_data[key])

    for out_key, src_keys in _NS_MEMORY_ALLOC_KEYS.items():
        for src_key in src_keys:
            if src_key in ns_data:
                totals[out_key] += int_or_zero(ns_data[src_key])

    if ns_data.get("storage-engine") != "memory":
        return

    if "data_total_bytes" in ns_data:
        data_total = int_or_zero(ns_data["data_total_bytes"])
        totals["data_alloc_bytes"] += data_total

        if fold_data_into_shmem:
            totals["shmem_alloc_bytes"] += data_total

    if "data_used_bytes" in ns_data:
        totals["data_in_memory_used_bytes"] += int_or_zero(ns_data["data_used_bytes"])


def _accumulate_stop_writes_threshold(totals, ns_data):
    """
    Track the lowest stop-writes-sys-memory-pct across a node's namespaces.

    The server evaluates the threshold per namespace against one node-wide
    system memory pct (nsup.c eval_stop_writes), so the namespace configured
    lowest is the first to refuse writes and is the node-level threshold.
    """
    if "stop-writes-sys-memory-pct" not in ns_data:
        return

    pct = int_or_zero(ns_data["stop-writes-sys-memory-pct"])

    if not 0 < pct <= 100:
        return

    current = totals.get("stop_writes_sys_memory_pct")
    totals["stop_writes_sys_memory_pct"] = pct if current is None else min(current, pct)


def aggregate_ns_memory_stats(ns_stats, editions=None):
    """
    Aggregate namespace-level memory stats into per-node totals.

    Only keys the server actually reported for a node are emitted, so columns
    collapse on server versions that predate a stat rather than showing a
    misleading zero.

    Args:
        ns_stats: {node: {namespace: {stat_name: value}}}
        editions: {node: shortform edition} from convert_edition_to_shortform.
            Enterprise and Federal reserve storage-engine=memory data in shmem
            upfront, so data_total_bytes is folded into shmem_alloc_bytes.
            Community allocates that data from the process heap, where
            heap_allocated_bytes already counts it, so folding it would double
            count. An unknown edition does not fold: silently overstating
            allocation is the failure an operator cannot detect.

    Only RAM-backed allocations are aggregated, on both the alloc and the used
    side. index-type and sindex-type pmem and flash arenas live on devices, not
    in memory, and are reported by 'info namespace' against their own capacity.

    The component keys are not additive with the process heap: set index stages
    are always heap allocated, and so is memory-engine data on Community.

    total_alloc_bytes needs at least one 8.1.3 arena stat behind it.
    data_alloc_bytes comes from data_total_bytes, which exists since 7.0, so
    publishing a total from it alone renders a memory-engine node's Total Alloc
    below its Total Used in the same row.

    Returns:
        {node: {stat_name: str}}. Possible keys: index_used_bytes,
        sindex_used_bytes, set_index_used_bytes, data_in_memory_used_bytes,
        shmem_alloc_bytes, pi_alloc_bytes, si_alloc_bytes, set_alloc_bytes,
        data_alloc_bytes, total_alloc_bytes, total_used_bytes,
        stop_writes_sys_memory_pct.
    """
    editions = editions or {}
    result = {}

    for node, namespaces in ns_stats.items():
        if not isinstance(namespaces, dict):
            continue

        fold_data_into_shmem = editions.get(node) in (
            constants.EDITION_ENTERPRISE,
            constants.EDITION_FEDERAL,
        )
        totals = defaultdict(int)

        for ns_data in namespaces.values():
            if not isinstance(ns_data, dict):
                continue

            _accumulate_ns_memory(totals, ns_data, fold_data_into_shmem)
            _accumulate_stop_writes_threshold(totals, ns_data)

        for total_key, source_keys, required_keys in (
            (
                "total_alloc_bytes",
                _NS_MEMORY_ALLOC_TOTAL_SOURCES,
                _NS_MEMORY_ALLOC_ARENA_SOURCES,
            ),
            ("total_used_bytes", _NS_MEMORY_USED_TOTAL_SOURCES, None),
        ):
            present = [key for key in source_keys if key in totals]

            if not present:
                continue

            if required_keys and not any(key in totals for key in required_keys):
                continue

            totals[total_key] = sum(totals[key] for key in present)

        result[node] = {key: str(value) for key, value in totals.items()}

    return result


def node_reports_memory_alloc_stats(build):
    """
    Whether a build reports the 8.1.3 memory allocation statistics.

    An unreadable build counts as not reporting: publishing an allocation total
    for a node whose arenas are unknown overstates what asadm actually knows.
    """
    if not build or isinstance(build, Exception):
        return False

    try:
        return version.LooseVersion(str(build)) >= version.LooseVersion(
            constants.SERVER_MEMORY_ALLOC_STATS_FIRST_VERSION
        )
    except Exception:
        return False


def nodes_missing_memory_alloc_stats(builds):
    """
    The nodes in a build map that do not report the 8.1.3 allocation stats.

    One predicate for the headline gate, the verbose gate, and the warning, so
    a node whose Allocated Total is suppressed is always a node the warning
    names. An unreadable build lands here too: it is a node asadm cannot vouch
    for, not a node it knows is old.
    """
    return [
        node
        for node, build in (builds or {}).items()
        if not node_reports_memory_alloc_stats(build)
    ]


def derive_memory_headline(stats, configs, ns_agg, builds=None, nodes=None):
    """
    Build the per-node rows behind the 'info memory' headline table.

    Args:
        stats: per-node service stats, already through derive_memory_stats
        configs: per-node service configs
        ns_agg: output of aggregate_ns_memory_stats
        builds: {node: build}, used to decide which nodes report allocation
            stats at all. Omit to treat every node as reporting them.
        nodes: restrict to these nodes, defaults to every node in stats

    A row only carries a value its inputs support. capacity_bytes is the
    tracked cgroup limit, an exact figure the kernel measured, or where the
    node runs under no cgroup at all, the proven lower bound from
    derive_memory_stats, since the server publishes no total-memory stat.
    Either is safe to divide alloc_pct by: the limit is exact, and the bound
    understates capacity so the pct reads high rather than low.

    A cgroup limit that exists but is not tracked yields no capacity at all.
    The bound comes from system_free_mem_pct, which the server computes against
    host memory while tracking is off, so it would describe RAM this process
    cannot reach and divide alloc_pct down towards zero on the very node a
    cgroup is squeezing. The untracked limit is reported to the caller instead,
    and the operator is pointed at cgroup-mem-tracking.

    The allocation total is omitted when the node's namespace stats never
    arrived or its build predates the allocation stats, since heap alone would
    render as an authoritative total that understates the node by whatever its
    index arenas hold.

    Shmem is gated with the total it belongs to. On a pre-8.1.3 memory-engine
    node the arenas are unknown but the folded data reservation is not, so a
    populated Shmem cell would render a partial figure as a complete one and
    let the operator reconstruct the suppressed total by addition. Heap stays
    visible: it is real information on any version.

    Returns:
        (headline rows, nodes capped by an untracked cgroup, nodes whose
        namespace stats are missing)
    """
    headline = {}
    untracked_limits = []
    missing_ns_stats = []

    for node in stats if nodes is None else nodes:
        node_stats = stats.get(node)

        if not isinstance(node_stats, dict):
            continue

        node_configs = configs.get(node)

        if not isinstance(node_configs, dict):
            node_configs = {}

        agg = ns_agg.get(node)
        ns_known = isinstance(agg, dict)

        if not ns_known:
            missing_ns_stats.append(node)
            agg = {}

        alloc_known = builds is None or node_reports_memory_alloc_stats(
            builds.get(node)
        )

        cgroup_tracked = (
            str(node_configs.get("cgroup-mem-tracking", "")).lower() == "true"
        )
        cgroup_limit = int_or_zero(
            node_stats.get("cgroup_memory_limit_effective_bytes")
        )
        capacity = cgroup_limit if cgroup_tracked else 0

        if capacity <= 0 and cgroup_limit <= 0:
            capacity = int_or_zero(node_stats.get("system_total_mem_min_bytes"))

        if cgroup_limit > 0 and not cgroup_tracked:
            untracked_limits.append(node)

        shmem = max(0, int_or_zero(agg.get("shmem_alloc_bytes")))
        heap = max(0, int_or_zero(node_stats.get("heap_allocated_bytes")))
        allocated = shmem + heap
        row = {}

        if capacity > 0:
            row["capacity_bytes"] = str(capacity)

        if heap > 0:
            row["allocated_heap_bytes"] = str(heap)

        if ns_known and alloc_known:
            if shmem > 0:
                row["allocated_shmem_bytes"] = str(shmem)

            if allocated > 0:
                row["allocated_bytes"] = str(allocated)

                if heap > 0:
                    row["allocated_heap_pct"] = str(heap * 100 / allocated)

                if capacity > 0:
                    row["alloc_pct"] = str(allocated * 100 / capacity)

        if "system_free_mem_pct" in node_stats:
            row["free_pct"] = node_stats["system_free_mem_pct"]

        if "stop_writes_sys_memory_pct" in agg:
            row["stop_writes_sys_memory_pct"] = agg["stop_writes_sys_memory_pct"]

        headline[node] = row

    return headline, untracked_limits, missing_ns_stats


def derive_memory_stats(stats):
    """
    Add derived memory keys to per-node service stats (mutates and returns).

    Converts kbyte stats to bytes so byte converters render the right
    magnitude, normalizes the cgroup limit, and divides the two cgroup byte
    counts the server reports into a pct. A derived key is only added when its
    inputs are present and valid, so absent columns collapse on older servers.

    system_total_mem_min_bytes is a proven lower bound on total memory, not an
    estimate of it. The server computes system_free_mem_pct as an integer
    division (cf/src/os.c, both the /proc/meminfo and the cgroup paths), so

        free * 100 / (pct + 1)  <  total  <=  free * 100 / pct

    and the left side cannot exceed the truth whatever the rounding hid. Taking
    it understates capacity, which overstates utilisation: a pressure signal
    that errs pessimistic. The upper bound is the one that must never be used,
    since it flatters the node exactly when free pct is small.

    The system pair is used rather than the host pair because it is what the
    server tracks against: cgroup-aware when cgroup-mem-tracking is on, host
    memory otherwise, and present since before 8.1.1 where host_free_mem_pct
    is not.
    """
    kb_to_bytes = {
        "system_free_mem_kbytes": "system_free_mem_bytes",
        "host_free_mem_kbytes": "host_free_mem_bytes",
        "heap_allocated_kbytes": "heap_allocated_bytes",
        "heap_active_kbytes": "heap_active_bytes",
        "heap_mapped_kbytes": "heap_mapped_bytes",
        "system_thp_mem_kbytes": "system_thp_mem_bytes",
    }

    for node_stats in stats.values():
        if not isinstance(node_stats, dict):
            continue

        for src, dst in kb_to_bytes.items():
            if src in node_stats:
                node_stats[dst] = str(int_or_zero(node_stats[src]) * 1024)

        free_kbytes = int_or_zero(node_stats.get("system_free_mem_kbytes"))
        free_pct = int_or_zero(node_stats.get("system_free_mem_pct"))

        if free_kbytes > 0 and 0 < free_pct <= 100:
            node_stats["system_total_mem_min_bytes"] = str(
                free_kbytes * 1024 * 100 // (free_pct + 1)
            )

        if "cgroup_memory_limit_bytes" in node_stats:
            limit = cgroup_limit_or_zero(node_stats["cgroup_memory_limit_bytes"])

            if limit > 0:
                node_stats["cgroup_memory_limit_effective_bytes"] = str(limit)

                if "cgroup_memory_used_bytes" in node_stats:
                    used = int_or_zero(node_stats["cgroup_memory_used_bytes"])
                    node_stats["cgroup_memory_used_pct"] = str(used * 100 / limit)

    return stats


def first_key_to_upper(data):
    if not data or not isinstance(data, dict):
        return data
    updated_dict = {}
    for k, v in data.items():
        updated_dict[k.upper()] = v
    return updated_dict


# TODO: Remove duplications or extra steps
# TODO: Organize parse flow
def restructure_sys_data(content, cmd):
    if not content:
        return {}
    if cmd == "meminfo":
        pass
    elif cmd in ["free-m", "top"]:
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "iostat":
        try:
            for n in content.keys():
                c = content[n]
                c = c["iostats"][-1]
                if "device_stat" in c:
                    d_s = {}
                    for d in c["device_stat"]:
                        d_s[d["Device"]] = d
                    c["device_stat"] = d_s
                content[n] = c
        except Exception as e:
            print(e)
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "interrupts":
        try:
            for n in content.keys():
                try:
                    interrupt_list = content[n]["device_interrupts"]
                except Exception:
                    continue
                new_interrrupt_dict = {}
                for i in interrupt_list:
                    new_interrrupt = {}
                    itype = i["interrupt_type"]
                    iid = i["interrupt_id"]
                    idev = i["device_name"]
                    new_interrrupt[idev] = i["interrupts"]
                    if itype not in new_interrrupt_dict:
                        new_interrrupt_dict[itype] = {}
                    if iid not in new_interrrupt_dict[itype]:
                        new_interrrupt_dict[itype][iid] = {}
                    new_interrrupt_dict[itype][iid].update(
                        copy.deepcopy(new_interrrupt)
                    )
                content[n]["device_interrupts"] = new_interrrupt_dict
        except Exception as e:
            print(e)
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "df":
        try:
            for n in content.keys():
                try:
                    file_system_list = content[n]["Filesystems"]
                except Exception:
                    continue
                new_df_dict = {}
                for fs in file_system_list:
                    name = fs["name"]
                    if name not in new_df_dict:
                        new_df_dict[name] = {}
                    new_df_dict[name].update(copy.deepcopy(fs))

                content[n] = new_df_dict
        except Exception:
            pass

    elif cmd == "scheduler":
        try:
            for n in content.keys():
                c = content[n]
                c = c["scheduler_stat"]
                sch = {}
                for d_info in c:
                    sch[d_info["device"]] = {}
                    sch[d_info["device"]]["scheduler"] = d_info["scheduler"]

                content[n] = sch
        except Exception:
            pass

    return content


def get_value_from_second_level_of_dict(
    data: dict[Any, str],
    keys: Iterable[str],
    default_value: DefaultType = None,
    return_type: Type[ReturnType] = str,
) -> dict[str, Union[ReturnType, DefaultType]]:
    """
    Function takes dictionary and subkeys to find values inside all keys of dictionary.
    Returns dictionary containing key and value of input keys
    """

    res_dict = {}
    if not data or isinstance(data, Exception):
        return res_dict

    for _k in data:
        if not data[_k] or isinstance(data[_k], Exception):
            continue

        res_dict[_k] = get_value_from_dict(
            data[_k], keys, default_value=default_value, return_type=return_type
        )

    return res_dict


def get_values_from_second_level_of_dict(
    data, re_keys, return_type: Type[ReturnType] = str
) -> dict[str, ReturnType]:
    """
    Function takes dictionary and regular expression subkeys to find values inside all keys of dictionary.
    Returns dictionary containing key and all values for matching input keys
    """

    res_dict = {}
    if not data or isinstance(data, Exception):
        return res_dict

    for _k in data:
        if not data[_k] or isinstance(data[_k], Exception):
            continue

        res_dict[_k] = get_values_from_dict(data[_k], re_keys, return_type=return_type)

    return res_dict


def get_nested_value_from_dict(
    data: dict[str, Any],
    keys: list[str],
    default_value=None,
    return_type: Type[ReturnType] = str,
) -> Union[ReturnType, None]:
    """
    Given a list of keys, returns the nested value in a dict.
    """
    ref = data
    for key in keys:
        temp_ref = get_value_from_dict(ref, key)

        if not temp_ref:
            return default_value

        ref = temp_ref

    val, success = _cast(ref, return_type)

    if success:
        return val

    return default_value


def deep_merge_dicts(dict_to, dict_from):
    """
    Function takes dictionaries to merge

    Merge dict_from to dict_to and returns dict_to
    """

    if not dict_to and not dict_from:
        return dict_to

    if not dict_to:
        return dict_from

    if not isinstance(dict_to, dict):
        return dict_to

    if not dict_from or not isinstance(dict_from, dict):
        # either dict_from is None/empty or is last value whose key matched
        # already, so no need to add
        return dict_to

    for _key in dict_from.keys():
        if _key not in dict_to:
            dict_to[_key] = dict_from[_key]
        else:
            dict_to[_key] = deep_merge_dicts(dict_to[_key], dict_from[_key])

    return dict_to


def add_dicts(d1, d2):
    """
    Function takes two dictionaries and merges those to one dictionary by adding values for same key.
    """

    if not d2:
        return d1

    for _k in d2:
        if _k in d1:
            d1[_k] += d2[_k]
        else:
            d1[_k] = d2[_k]

    return d1


def filter_exceptions(data: Any):
    """
    Takes a dict or list and removes all values that are exceptions
    """
    if isinstance(data, dict):
        for _k in list(data.keys()):
            if isinstance(data[_k], Exception):
                # Any exceptions here are likely unexpected; log them so the missing data
                # is diagnosable (e.g. from collectinfo_debug.log). TOOLS-3596.
                logger.debug("Failed to get data for %r due to error: %r", _k, data[_k])
                del data[_k]
            else:
                filter_exceptions(data[_k])
    elif isinstance(data, list):
        for val in data:
            filter_exceptions(val)

    return data


def has_content(value: Any) -> bool:
    """
    Recursively report whether a value holds any non-empty leaf. Empty containers,
    empty strings, and None count as no content; any other scalar counts as content.
    """
    if isinstance(value, dict):
        return any(has_content(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(has_content(v) for v in value)
    if isinstance(value, str):
        return value != ""
    return value is not None


def pct_to_value(data, d_pct):
    """
    Function takes dictionary with base value, and dictionary with percentage and converts percentage to value.
    """

    if not data or not d_pct:
        return data

    out_map = {}
    for _k in data:
        if _k not in d_pct:
            continue

        out_map[_k] = (float(data[_k]) / 100.0) * float(d_pct[_k])

    return out_map


def mbytes_to_bytes(data):
    if not data:
        return data

    if isinstance(data, int) or isinstance(data, float):
        return data * 1048576

    if isinstance(data, dict):
        for _k in data.keys():
            data[_k] = copy.deepcopy(mbytes_to_bytes(data[_k]))
        return data

    return data


def find_delimiter_in(value):
    """Find a good delimiter to split the value by"""

    for d in [";", ":", ","]:
        if d in value:
            return d

    return ";"


def convert_edition_to_shortform(edition: str) -> str:
    """Convert edition to shortform: Enterprise, Community, Federal, or N/E"""
    edition_lower = edition.lower()

    if "enterprise" in edition_lower:
        return constants.EDITION_ENTERPRISE
    elif "community" in edition_lower:
        return constants.EDITION_COMMUNITY
    elif "federal" in edition_lower:
        return constants.EDITION_FEDERAL

    return constants.EDITION_UNKNOWN


def write_to_file(file, data):
    f = open(str(file), "a")
    f.write(str(data))
    return f.close()


def is_valid_ip_port(key):
    """
    It returns True if key matches with either "IP:port" or "[ipv6]:port" format.
    """

    if not key or ":" not in key:
        return False

    key = key.strip()
    split = key.split(":")
    if "]:" in key:
        # IPv6 address
        split = key.split("]:")

    if len(split) < 2 or ("]" not in key and len(split) != 2):
        return False

    address, port = split[0], split[1]

    try:
        int(port)
    except Exception:
        return False

    address = address.strip()

    if address.startswith("["):
        address = address[1:]

    if _is_valid_ipv4_address(address) or _is_valid_ipv6_address(address):
        return True

    return False


def _is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count(".") == 3
    except socket.error:  # not a valid address
        return False

    return True


def _is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def is_str(data):
    return isinstance(data, str)


def bytes_to_str(data: Union[bytes, str]) -> str:
    if isinstance(data, str):
        return data

    return data.decode("utf-8")


def str_to_bytes(data: Union[bytes, str]) -> bytes:
    if isinstance(data, bytes):
        return data

    return str.encode(data, "utf-8")


ItemsType = TypeVar("ItemsType")


def find_most_frequent(
    list_: Iterable[ItemsType],
) -> Union[None, ItemsType]:
    count = {}
    most_freq = None

    for size in list_:
        if size not in count:
            count[size] = 1
        else:
            count[size] += 1

    max_count = 0

    for val, count in count.items():
        if count > max_count:
            max_count = count
            most_freq = val

    return most_freq


AwaitableType = TypeVar("AwaitableType")
AwaitableReturnType = TypeVar("AwaitableReturnType")


class async_cached(Generic[AwaitableType]):
    """
    Doesn't support lists, dicts and other unhashables
    Also doesn't support kwargs for reasons above.
    """

    class _CacheableCoroutine(Generic[AwaitableReturnType]):
        """
        Allow a coroutine to be awaited multipul times. The lock makes sure multiple
        methods do not call await on the coroutine.
        """

        result: AwaitableReturnType

        def __init__(self, co: Awaitable[AwaitableReturnType]):
            self._co = co
            self._done = False
            self._lock = asyncio.Lock()
            self._raised = False

        def __await__(self) -> Generator[Any, None, AwaitableReturnType]:
            yield from self._lock.acquire().__await__()
            try:
                if not self._done:
                    self.result = yield from self._co.__await__()
                    self._done = True
                    return self.result
                elif isinstance(self.result, Exception):
                    raise self.result
                else:
                    return self.result
            except Exception as e:
                self.result = e  # redundant in the case of re-raising the exception
                self._done = True
                self._raised = True
                raise
            finally:
                self._lock.release()

        def raised(self) -> bool:
            return self._raised

    def __init__(self, func: Callable[..., Awaitable[AwaitableType]], ttl=0.5):
        self.func = func
        self.ttl = ttl
        self.cache = {}

    def __setitem__(self, key, value: _CacheableCoroutine):
        self.cache[key] = (value, time() + self.ttl)

    def __getitem__(self, key) -> Awaitable[AwaitableType]:
        if key in self.cache:
            # This effectively clear the key if the coroutine raises an exception.
            if not self.cache[key][0].raised():
                value, eol = self.cache[key]
                if eol > time():
                    logger.debug("return cached %s: %s", key[1:], value)
                    return value

        self[key] = self._CacheableCoroutine(self.func(*key))
        return self.cache[key][0]

    def __call__(self, *args, **kwargs):
        if "disable_cache" in kwargs and kwargs["disable_cache"]:
            return self.func(*args)
        return self[args]

    def __repr__(self):
        """Return the function's docstring."""
        return self.func.__doc__

    def __get__(self, obj, objtype):
        """Support instance methods."""
        return functools.partial(self.__call__, obj)


def is_valid_base64(data: Union[str, bytes]) -> None:
    """
    Validates if the given data is valid base64 encoding.

    Args:
        data: String or bytes to validate as base64

    Raises:
        ValueError: If the data is not valid base64 encoding.
    """
    if not data:
        raise ValueError("Invalid base64 encoding: empty data")

    try:
        if isinstance(data, str):
            data = data.encode("utf-8")
        base64.b64decode(data, validate=True)
    except (base64.binascii.Error, ValueError):
        raise ValueError("Invalid base64 encoding")
    except Exception as e:
        logger.debug("Error validating base64: %s", e)
        raise ValueError("Invalid base64 encoding")


def is_valid_aerospike_name(name: str, object_type: str) -> bool:
    """
    Validate that a name follows Aerospike naming conventions.

    Valid names can include only Latin lowercase and uppercase letters with
    no diacritical marks (a-z, A-Z), digits 0-9, underscores (_), hyphens (-), and dollar signs ($).

    This applies to roles, users, namespaces, sets, bins, UDFs, and other Aerospike objects.

    Args:
        name: The name to validate
        object_type: Type of object for error messages (e.g., "role", "user", "namespace")

    Returns:
        bool: True if the name is valid, False otherwise
    """
    if not name:
        logger.error("%s name cannot be empty", object_type.capitalize())
        return False

    pattern = r"^[a-zA-Z0-9_\-$]+$"
    if not re.match(pattern, name):
        # Find all illegal characters
        illegal_chars = set(re.findall(r"[^a-zA-Z0-9_\-$]", name))
        logger.error(
            "Invalid %s name '%s': contains illegal characters: %s. "
            "Names can only contain letters (a-z, A-Z), digits (0-9), underscores (_), hyphens (-), and dollar signs ($)",
            object_type,
            name,
            ", ".join(f"'{char}'" for char in sorted(illegal_chars)),
        )
        return False

    return True


def is_valid_role_name(role_name: str) -> bool:
    """
    Validate that a role name follows Aerospike naming conventions.

    This is a convenience wrapper around is_valid_aerospike_name() for role names.

    Args:
        role_name: The role name to validate

    Returns:
        bool: True if the role name is valid, False otherwise
    """
    return is_valid_aerospike_name(role_name, "role")


async def check_version_support(
    feature_versions: dict[str, str], builds: dict[str, str]
) -> dict[str, bool]:
    """
    Check which features are supported across all nodes in the cluster.
    Single pass optimization.

    Args:
        feature_versions: Dictionary mapping feature names to their minimum required versions
        builds: Dictionary mapping node identifiers to their build versions

    Returns:
        Dictionary mapping feature names to boolean support status (True if supported, False if not)

    Example:
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0",
            "blob_indexing": "6.0.0"
        }
        builds = {
            "node1": "6.1.0",
            "node2": "5.8.0",
            "node3": "6.2.0"
        }
        result = await check_version_support(feature_versions, builds)
        # Returns: {"cdt_indexing": True, "expression_indexing": True, "blob_indexing": False}
    """
    # Convert version strings to LooseVersion objects once
    min_versions = {
        feature: version.LooseVersion(min_version)
        for feature, min_version in feature_versions.items()
    }

    # if no builds, return False for all features
    if not builds:
        return {feature: False for feature in feature_versions.keys()}

    # find the minimum build version across all nodes
    min_build_version = min(version.LooseVersion(build) for build in builds.values())

    # Check all features against the minimum build version
    return {
        feature: min_build_version >= min_version
        for feature, min_version in min_versions.items()
    }


def normalize_masking_rule_data(rule):
    """Normalize masking rule data from API response.

    Args:
        rule (dict): Raw masking rule data from API

    Returns:
        dict: Normalized rule data with consistent field names

    Example:
        Input dict from API response:
        {
            "namespace": "test",
            "set": "demo",
            "bin": "credit_card",
            "type": "string",
            "function": "redact",
            "position": "0",
            "length": "3"
        }

        Output normalized dict:
        {
            "ns": "test",
            "set": "demo",
            "bin": "credit_card",
            "type": "string",
            "function": "redact position 0 length 3"
        }
    """
    processed_rule = {}

    # Normalize field names (handle both "ns"/"namespace")
    processed_rule["ns"] = rule.get("ns") or rule.get("namespace", "")
    processed_rule["set"] = rule.get("set", "")
    processed_rule["bin"] = rule.get("bin", "")
    processed_rule["type"] = rule.get("type", "")

    # Parse the function string to display it properly
    # Handle both "func" and "function" field names
    func_name = rule.get("function")

    if func_name:
        # Build complete function string dynamically from rule parameters
        result = func_name

        # Add all function parameters except the core fields
        core_fields = {"ns", "namespace", "set", "bin", "type", "function"}
        for key, value in rule.items():
            if key not in core_fields and value is not None:
                result += f" {key} {value}"

        processed_rule["function"] = result
    else:
        processed_rule["function"] = ""

    return processed_rule
