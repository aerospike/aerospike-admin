# Copyright 2013-2025 Aerospike, Inc.
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

from datetime import datetime
import itertools
from typing import Iterable, Literal, Union
from lib.live_cluster.client.types import ASInfoError
from lib.view.sheet.decleration import (
    ComplexAggregator,
    EntryData,
    NoEntryException,
    FieldSorter,
)
from lib.live_cluster.client.node import ASINFO_RESPONSE_OK, ASInfoResponseError
from lib.view.sheet import (
    Aggregators,
    Converters,
    DynamicFieldOrder,
    DynamicFields,
    Field,
    FieldAlignment,
    FieldType,
    Formatters,
    Projectors,
    Sheet,
    SheetStyle,
    Subgroup,
    TitleField,
)

#
# Projectors.
#


def project_build(b, v):
    if "community" in v.lower():
        return "C-" + b

    if "enterprise" in v.lower():
        return "E-" + b

    if "federal" in v.lower():
        return "F-" + b

    return b


def project_xdr_free_dlog(s):
    return int(s.replace("%", ""))


def project_xdr_req_shipped_success(s, rs, esc, ess):
    if s is not None:
        return s

    return rs - esc - ess


def project_xdr_req_shipped_errors(s, esc, ess):
    if s is not None:
        return s

    return esc + ess


def _ignore_zero(num: int):
    if num == 0:
        raise NoEntryException("Ignoring zero")

    return num


def _ignore_null(s: str):
    if s.lower() == "null":
        raise NoEntryException("Ignoring 'null'")

    return s


#
# Aggregator helpers
#


def weighted_avg(values: Iterable[float], weights: Iterable[float]):
    """
    Computes the average of multiple percentage points. Remember: used/total = percent or percent * total = used
    Let's assume each entry has three pieces of info (used amount, total amount available, percent). To compute
    the average of percents we can use sum(used for each element) / sum(total for each element) or because
    percent * total = used we can do sum(percent * total for each element) / sum(total for each element).
    """
    weights_total = 0.0
    values_total = 0.0
    itr = 0

    for v, w in zip(values, weights):
        weighted_value = v * w
        values_total += weighted_value
        weights_total += w
        itr += 1

    if itr == 0:
        # Prevents us from printing zero if there are no elements to average.
        return None

    if not weights_total:
        return 0.0

    return values_total / weights_total


#
# Common fields.
#

node_field = Field(
    "Node",
    Projectors.String("node_names", None),
    formatters=(
        Formatters.green_alert(
            lambda edata: edata.record["Node ID"] == edata.common["principal"]
        ),
    ),
)
hidden_node_id_field = Field(
    "Node ID", Projectors.String("node_ids", None), hidden=True
)
namespace_field = Field(
    "Namespace", Projectors.String("ns_stats", None, for_each_key=True)
)
#
# Templates.
#

info_network_sheet = Sheet(
    (
        node_field,
        Field(
            "Node ID",
            Projectors.String("node_ids", None),
            converter=(
                lambda edata: (
                    "*" + edata.value
                    if edata.value == edata.common["principal"]
                    else edata.value
                )
            ),
            formatters=(
                Formatters.green_alert(
                    lambda edata: edata.record["Node ID"] == edata.common["principal"]
                ),
            ),
            align=FieldAlignment.right,
        ),
        Field("IP", Projectors.String("hosts", None)),
        Field(
            "Build",
            Projectors.Func(
                FieldType.string,
                project_build,
                Projectors.String("builds", None),
                Projectors.String("versions", None),
            ),
        ),
        Field(
            "Migrations",
            Projectors.Number("stats", "migrate_partitions_remaining"),
            converter=Converters.scientific_units,
            formatters=(Formatters.yellow_alert(lambda edata: edata.value != 0.0),),
        ),
        Subgroup(
            "Cluster",
            (
                Field(
                    "Size",
                    Projectors.Number("stats", "cluster_size"),
                    formatters=(
                        Formatters.red_alert(
                            lambda edata: str(edata.value)
                            != edata.common["common_size"]
                        ),
                    ),
                ),
                Field(
                    "Key",
                    Projectors.String("stats", "cluster_key"),
                    align=FieldAlignment.right,
                    formatters=(
                        Formatters.red_alert(
                            lambda edata: str(edata.value) != edata.common["common_key"]
                        ),
                    ),
                ),
                Field(
                    "Integrity",
                    Projectors.Boolean("stats", "cluster_integrity"),
                    formatters=(Formatters.red_alert(lambda edata: not edata.value),),
                ),
                Field(
                    "Principal",
                    Projectors.String("stats", "paxos_principal"),
                    align=FieldAlignment.right,
                    formatters=(
                        Formatters.red_alert(
                            lambda edata: str(edata.value)
                            != edata.common["common_principal"]
                        ),
                    ),
                ),
            ),
        ),
        Field("Client Conns", Projectors.Number("stats", "client_connections")),
        Field(
            "Uptime",
            Projectors.Number("stats", "uptime"),
            converter=Converters.time_seconds,
        ),
    ),
    from_source=(
        "node_names",
        "node_ids",
        "hosts",
        "builds",
        "versions",
        "stats",
    ),
    order_by=FieldSorter("Node"),
)


def create_usage_weighted_avg(type: str):
    def usage_weighted_avg(edatas: list[EntryData]):
        pcts: map[float] = map(lambda edata: edata.value, edatas)
        weights: map[float] = map(lambda edata: edata.record[type]["Total"], edatas)
        return weighted_avg(pcts, weights)

    return usage_weighted_avg


info_namespace_usage_sheet = Sheet(
    (
        namespace_field,
        node_field,
        hidden_node_id_field,
        Field(
            "Evictions",
            Projectors.Number("ns_stats", "evicted_objects", "evicted-objects"),
            converter=Converters.scientific_units,
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Stop Writes",
            Projectors.Boolean("ns_stats", "stop_writes", "stop-writes"),
            formatters=(Formatters.red_alert(lambda edata: edata.value),),
        ),
        Subgroup(
            "System Memory",
            (
                Field(
                    "Avail%", Projectors.Percent("service_stats", "system_free_mem_pct")
                ),
                Field(
                    "Evict%",
                    Projectors.Percent("ns_stats", "evict-sys-memory-pct"),
                ),
            ),
        ),
        Subgroup(
            "Primary Index",
            (
                Field("Type", Projectors.String("ns_stats", "index-type")),
                Field(
                    "Total",
                    Projectors.Number(
                        "ns_stats",
                        "index-type.mounts-budget",  # Added in 7.0 if mounts is present must have higher precedence
                        "indexes-memory-budget",  # Added in 7.1 for memory only
                        "index-type.mounts-size-limit",
                    ),
                    hidden=True,
                ),
                Field(
                    "Used",
                    Projectors.Number(
                        "ns_stats",
                        "index_used_bytes",  # flash, pmem, and memory metrics were consolidated in 7.0
                        "index_flash_used_bytes", # pre 7.0
                        "index_pmem_used_bytes", # pre 7.0
                        "memory_used_index_bytes", # pre 7.0
                    ),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Used%",
                    Projectors.Any(
                        FieldType.number,
                        Projectors.Func(
                            FieldType.number,
                            lambda pct: pct / 100.0,  # Convert percentage (0-100) to ratio (0-1)
                            Projectors.Float("ns_stats", "index_mounts_used_pct"),  # flash, pmem, and memory metrics were consolidated in 7.0
                        ),
                        Projectors.Div( # pre 7.0
                            Projectors.Number(
                                "ns_stats",
                                "index_flash_used_bytes",
                                "index_pmem_used_bytes",
                            ),
                            Projectors.Number(
                                "ns_stats",
                                "index-type.mounts-size-limit",
                            ),
                        ),
                    ),
                    converter=Converters.ratio_to_pct,
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Primary Index"),
                        converter=Converters.ratio_to_pct,
                    ),
                    formatters=(
                        Formatters.yellow_alert(
                            lambda edata: edata.value * 100
                            >= edata.record["Primary Index"]["Evict%"]
                            and edata.record["Primary Index"]["Evict%"] != 0
                        ),
                    ),
                ),
                Field(
                    "Evict%",
                    Projectors.Number(
                        "ns_stats",
                        "evict-indexes-memory-pct",  # Added in 7.1 for memory only
                        "index-type.evict-mounts-pct",  # Added in 7.0 for flash and pmem
                        "index-type.mounts-high-water-pct",
                    ),
                    converter=Converters.pct,
                ),
            ),
        ),
        Subgroup(
            "Secondary Index",
            (
                Field("Type", Projectors.String("ns_stats", "sindex-type")),
                Field(
                    "Total",
                    Projectors.Number(
                        "ns_stats",
                        "sindex-type.mounts-budget",  # Added in 7.0
                        "indexes-memory-budget",  # Added in 7.1 for memory only, accounts for sindex also for in memory
                        "sindex-type.mounts-size-limit",
                    ),
                    hidden=True,
                ),
                Field(
                    "Used",
                    Projectors.Number(
                        "ns_stats",
                        "sindex_used_bytes",  # flash, pmem, and memory metrics were consolidated in 7.0
                        "sindex_flash_used_bytes", # pre 7.0
                        "sindex_pmem_used_bytes", # pre 7.0
                        "memory_used_sindex_bytes", # pre 7.0
                    ),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Used%",
                    Projectors.Any(
                        FieldType.number,
                        Projectors.Func(
                            FieldType.number,
                            lambda pct: pct / 100.0,  # Convert percentage (0-100) to ratio (0-1)
                            Projectors.Float("ns_stats", "sindex_mounts_used_pct"),  # flash, pmem, and memory metrics were consolidated in 7.0
                        ),
                        Projectors.Div( # pre 7.0
                            Projectors.Number(
                                "ns_stats",
                                "sindex_flash_used_bytes",
                                "sindex_pmem_used_bytes",
                            ),
                            Projectors.Number(
                                "ns_stats",
                                "sindex-type.mounts-size-limit",
                            ),
                        ),
                    ),
                    converter=Converters.ratio_to_pct,
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Secondary Index"),
                        converter=Converters.ratio_to_pct,
                    ),
                    formatters=(
                        Formatters.yellow_alert(
                            lambda edata: edata.value * 100
                            >= edata.record["Secondary Index"]["Evict%"]
                            and edata.record["Secondary Index"]["Evict%"] != 0
                        ),
                    ),
                ),
                Field(
                    "Evict%",
                    Projectors.Number(
                        "ns_stats",
                        "sindex-type.evict-mounts-pct",  # Added in 7.0
                        "sindex-type.mounts-high-water-pct",
                    ),
                ),
            ),
        ),
        Subgroup(
            "Storage Engine",
            (
                Field("Type", Projectors.String("ns_stats", "storage-engine")),
                Field(
                    "Total",
                    Projectors.Number(
                        "ns_stats",
                        "data_total_bytes",
                        "device_total_bytes",
                        "pmem_total_bytes",
                        "total-bytes-disk",
                    ),
                    hidden=True,
                ),
                Field(
                    "Used",
                    Projectors.Number(
                        "ns_stats",
                        "data_used_bytes",
                        "device_used_bytes",
                        "pmem_used_bytes",
                        "used-bytes-disk",
                    ),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Used%",
                    Projectors.Div(
                        Projectors.Number(
                            "ns_stats",
                            "data_used_bytes",
                            "device_used_bytes",
                            "pmem_used_bytes",
                            "used-bytes-disk",
                        ),
                        Projectors.Number(
                            "ns_stats",
                            "data_total_bytes",
                            "device_total_bytes",
                            "pmem_total_bytes",
                            "total-bytes-disk",
                        ),
                    ),
                    converter=Converters.ratio_to_pct,
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Storage Engine"),
                        converter=Converters.ratio_to_pct,
                    ),
                    formatters=(
                        Formatters.red_alert(
                            lambda edata: edata.value * 100
                            >= edata.record["Storage Engine"]["Evict%"]
                            and edata.record["Storage Engine"]["Evict%"] != 0
                            or (
                                edata.value * 100
                                >= edata.record["Storage Engine"]["Used Stop%"]
                            )
                        ),
                    ),
                ),
                Field(
                    "Evict%",
                    Projectors.Number(
                        "ns_stats",
                        "storage-engine.evict-used-pct",
                        "high-water-disk-pct",
                    ),
                    converter=Converters.pct,
                ),
                Field(
                    "Used Stop%",
                    Projectors.Number(
                        "ns_stats", "storage-engine.stop-writes-used-pct"
                    ),
                    converter=Converters.pct,
                ),
                Field(
                    "Avail%",
                    Projectors.Number(
                        "ns_stats",
                        "data_avail_pct",
                        "device_available_pct",
                        "pmem_available_pct",
                        "available_pct",
                    ),
                    converter=Converters.pct,
                    formatters=(
                        Formatters.red_alert(
                            lambda edata: edata.value
                            <= edata.record["Storage Engine"]["Avail Stop%"]
                        ),
                    ),
                ),
                Field(
                    "Avail Stop%",
                    Projectors.Number(
                        "ns_stats", "storage-engine.stop-writes-avail-pct"
                    ),
                    converter=Converters.pct,
                ),
            ),
        ),
        # Memory was unified in pindex, sindex, and storage-engine in 7.0. This will
        # only be displayed if the cluster is running 6.4 or earlier.
        Subgroup(
            "Memory",
            (
                Field(
                    "Total",
                    Projectors.Number("ns_stats", "memory-size", "total-bytes-memory"),
                    hidden=True,
                ),
                Field(
                    "Used",
                    Projectors.Number(
                        "ns_stats", "memory_used_bytes", "used-bytes-memory"
                    ),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Used%",
                    Projectors.Div(
                        Projectors.Number(
                            "ns_stats", "memory_used_bytes", "used-bytes-memory"
                        ),
                        Projectors.Number(
                            "ns_stats", "memory-size", "total-bytes-memory"
                        ),
                    ),
                    converter=Converters.ratio_to_pct,
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Memory"),
                        converter=Converters.ratio_to_pct,
                    ),
                    formatters=(
                        Formatters.yellow_alert(
                            lambda edata: edata.value * 100
                            > edata.record["Memory"]["HWM%"]
                            and edata.record["Memory"]["HWM%"] != 0
                        ),
                    ),
                ),
                Field(
                    "HWM%",
                    Projectors.Number("ns_stats", "high-water-memory-pct"),
                    converter=Converters.pct,
                ),
                Field(
                    "Stop%",
                    Projectors.Number("ns_stats", "stop-writes-pct"),
                    converter=Converters.pct,
                ),
            ),
        ),
        # Replaced by "Storage Engine" in 7.0. This will
        # only be displayed if the cluster is running 6.4 or earlier.
    ),
    from_source=("node_ids", "node_names", "ns_stats", "service_stats"),
    for_each="ns_stats",
    group_by=("Namespace"),
    order_by=FieldSorter("Node"),
)

info_namespace_object_sheet = Sheet(
    (
        namespace_field,
        node_field,
        hidden_node_id_field,
        Field("Rack ID", Projectors.Number("ns_stats", "rack-id")),
        Field(
            "Repl Factor",
            Projectors.Number(
                "ns_stats",
                "effective_replication_factor",  # introduced post 3.15.0.1
                "replication-factor",
                "repl-factor",
            ),
        ),
        Field(
            "Expirations",
            Projectors.Number("ns_stats", "expired_objects", "expired-objects"),
            converter=Converters.scientific_units,
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Total Records",
            Projectors.Sum(
                Projectors.Number("ns_stats", "master_objects", "master-objects"),
                Projectors.Number("ns_stats", "master_tombstones"),
                Projectors.Number("ns_stats", "prole_objects", "prole-objects"),
                Projectors.Number("ns_stats", "prole_tombstones"),
                Projectors.Number("ns_stats", "non_replica_objects"),
                Projectors.Number("ns_stats", "non_replica_tombstones"),
            ),
            converter=Converters.scientific_units,
            aggregator=Aggregators.sum(),
        ),
        Subgroup(
            "Objects",
            (
                Field(
                    "Master",
                    Projectors.Number("ns_stats", "master_objects", "master-objects"),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Prole",
                    Projectors.Number("ns_stats", "prole_objects", "prole-objects"),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Non-Replica",
                    Projectors.Number("ns_stats", "non_replica_objects"),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
        Subgroup(
            "Tombstones",
            (
                Field(
                    "Master",
                    Projectors.Number("ns_stats", "master_tombstones"),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Prole",
                    Projectors.Number("ns_stats", "prole_tombstones"),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Non-Replica",
                    Projectors.Number("ns_stats", "non_replica_tombstones"),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
        Subgroup(
            "Pending Migrates",
            (
                Field(
                    "Tx",
                    Projectors.Number(
                        "ns_stats",
                        "migrate_tx_partitions_remaining",
                        "migrate-tx-partitions-remaining",
                    ),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Rx",
                    Projectors.Number(
                        "ns_stats",
                        "migrate_rx_partitions_remaining",
                        "migrate-rx-partitions-remaining",
                    ),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
    ),
    from_source=("node_ids", "node_names", "ns_stats"),
    for_each="ns_stats",
    group_by=("Namespace"),
    order_by=FieldSorter("Node"),
)


def set_index_projector(enable_index, index_populating):
    if not enable_index:
        return "No"

    if index_populating:
        return "Building"

    # enable_index and not index_populating
    return "Yes"


info_set_sheet = Sheet(
    (
        Field("Namespace", Projectors.String("set_stats", 0, for_each_key=True)),
        Field("Set", Projectors.String("set_stats", 1, for_each_key=True)),
        node_field,
        hidden_node_id_field,
        Field("Set Delete", Projectors.Boolean("set_stats", "deleting", "set-delete")),
        Field(
            "Storage Engine Used",
            Projectors.Number("set_stats", "data_used_bytes"),  # New in server 7.0
            converter=Converters.byte,
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Memory Used",
            Projectors.Number(
                "set_stats", "memory_data_bytes", "n-bytes-memory"
            ),  # Unified into data_used_bytes in 7.0
            converter=Converters.byte,
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Disk Used",
            Projectors.Number(
                "set_stats", "device_data_bytes", "n-bytes-device"
            ),  # Unified into data_used_bytes in 7.0
            converter=Converters.byte,
            aggregator=Aggregators.sum(),
        ),
        Subgroup(
            "Size Quota",
            (
                Field(
                    "Total",
                    Projectors.Number(
                        "set_stats",
                        "stop-writes-size",
                    ),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Used%",
                    Projectors.Div(
                        Projectors.Any(
                            FieldType.number,
                            Projectors.Number("set_stats", "data_used_bytes"),
                            Projectors.Func(
                                FieldType.number,
                                lambda m_data, d_data: (
                                    d_data if m_data == 0 else m_data
                                ),
                                Projectors.Number(
                                    "set_stats",
                                    "memory_data_bytes",
                                    "n-bytes-memory",  # Unified into data_used_bytes in 7.0
                                ),
                                Projectors.Number(
                                    "set_stats",
                                    "device_data_bytes",
                                    "n-bytes-device",  # Unified into data_used_bytes in 7.0
                                ),
                            ),
                        ),
                        Projectors.Number("set_stats", "stop-writes-size"),
                    ),
                    converter=Converters.ratio_to_pct,
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Size Quota"),
                        converter=Converters.ratio_to_pct,
                    ),
                    formatters=(
                        Formatters.red_alert(lambda edata: edata.value * 100 >= 90.0),
                        Formatters.yellow_alert(
                            lambda edata: edata.value * 100 >= 75.0
                        ),
                    ),
                ),
            ),
        ),
        Field(
            "Total Records",
            Projectors.Number("set_stats", "objects", "n_objects"),
            converter=Converters.scientific_units,
            aggregator=Aggregators.sum(),
        ),
        Subgroup(
            "Records Quota",
            (
                Field(
                    "Total",
                    Projectors.Number("set_stats", "stop-writes-count"),
                ),
                Field(
                    "Used%",
                    Projectors.Div(
                        Projectors.Number(
                            "set_stats",
                            "objects",
                        ),
                        Projectors.Number("set_stats", "stop-writes-count"),
                    ),
                    converter=Converters.ratio_to_pct,
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Records Quota"),
                        converter=Converters.ratio_to_pct,
                    ),
                    formatters=(
                        Formatters.red_alert(lambda edata: edata.value * 100 >= 90.0),
                        Formatters.yellow_alert(
                            lambda edata: edata.value * 100 >= 75.0
                        ),
                    ),
                ),
            ),
        ),
        Field("Disable Eviction", Projectors.Boolean("set_stats", "disable-eviction")),
        Field("Set Enable XDR", Projectors.String("set_stats", "set-enable-xdr")),
        Field(
            "Set Index",
            Projectors.Func(
                FieldType.string,
                set_index_projector,
                Projectors.Boolean("set_stats", "enable-index"),
                Projectors.Boolean("set_stats", "index_populating"),
            ),
        ),
    ),
    from_source=("node_ids", "node_names", "set_stats"),
    for_each="set_stats",
    group_by=("Namespace", "Set"),
    order_by=FieldSorter("Node"),
)

info_old_xdr_sheet = Sheet(
    (
        Field("XDR Enabled", Projectors.Boolean("xdr_enable", None), hidden=True),
        node_field,
        hidden_node_id_field,
        Field("Build", Projectors.String("builds", None)),
        Field(
            "Data Shipped",
            Projectors.Number(
                "xdr_stats",
                "xdr_ship_bytes",
                "esmt_bytes_shipped",
                "esmt-bytes-shipped",
            ),
            converter=Converters.byte,
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Free DLog%",
            Projectors.Func(
                FieldType.number,
                project_xdr_free_dlog,
                Projectors.String(
                    "xdr_stats", "dlog_free_pct", "free-dlog-pct", "free_dlog_pct"
                ),
            ),
            converter=Converters.pct,
        ),
        Field(
            "Lag (sec)",
            Projectors.Number("xdr_stats", "xdr_timelag", "timediff_lastship_cur_secs"),
            converter=Converters.time_seconds,
            formatters=(Formatters.red_alert(lambda edata: edata.value >= 300),),
        ),
        Subgroup(
            "Records",
            (
                Field(
                    "Outstanding",
                    Projectors.Number(
                        "xdr_stats",
                        "xdr_ship_outstanding_objects",
                        "stat_recs_outstanding",
                    ),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Shipped Success",
                    Projectors.Func(
                        FieldType.number,
                        project_xdr_req_shipped_success,
                        Projectors.Number(
                            "xdr_stats", "xdr_ship_success", "stat_recs_shipped_ok"
                        ),
                        Projectors.Number(
                            "xdr_stats", "stat_recs_shipped", "stat-recs-shipped"
                        ),
                        Projectors.Number(
                            "xdr_stats", "err_ship_client", "error-ship-client"
                        ),
                        Projectors.Number(
                            "xdr_stats", "err_ship_server", "err-ship-server"
                        ),
                    ),
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Shipped Errors",
                    Projectors.Func(
                        FieldType.number,
                        project_xdr_req_shipped_errors,
                        Projectors.Number("xdr_stats", "stat_recs_ship_errors"),
                        Projectors.Number(
                            "xdr_stats",
                            "err_ship_client",
                            "err-ship-client",
                            "xdr_ship_source_error",
                        ),
                        Projectors.Number(
                            "xdr_stats",
                            "err_ship_server",
                            "err-ship-server",
                            "xdr_ship_destination_error",
                        ),
                    ),
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
        Field(
            "Throughput",
            Projectors.Number("xdr_stats", "xdr_throughput", "cur_throughput"),
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Avg Latency (ms)",
            Projectors.Number("xdr_stats", "xdr_ship_latency_avg", "latency_avg_ship"),
        ),
        Field(
            "XDR Uptime",  # obsolete since 3.11.1.1
            Projectors.Number("xdr_stats", "xdr_uptime", "xdr-uptime"),
            converter=Converters.time_seconds,
        ),
    ),
    from_source=("xdr_enable", "node_ids", "node_names", "builds", "xdr_stats"),
    where=lambda record: record["XDR Enabled"],
    order_by=FieldSorter("Node"),
)

info_dc_sheet = Sheet(
    (
        node_field,
        hidden_node_id_field,
        Field("DC", Projectors.String("dc_stats", "dc-name", "DC_Name")),
        Field("DC Type", Projectors.String("dc_stats", "dc-type")),
        Field("DC Size", Projectors.Number("dc_stats", "xdr_dc_size", "dc_size")),
        Field("Namespaces", Projectors.String("dc_stats", "namespaces")),
        Field(
            "Lag",
            Projectors.Number(
                "dc_stats", "xdr_dc_timelag", "xdr-dc-timelag", "dc_timelag"
            ),
            converter=Converters.time_seconds,
        ),
        Field(
            "Records Shipped",
            Projectors.Number(
                "dc_stats",
                "xdr_dc_remote_ship_ok",
                "dc_remote_ship_ok",
                "dc_recs_shipped_ok",
                "dc_ship_success",
            ),
        ),
        Field(
            "Avg Latency (ms)",
            Projectors.Number(
                "dc_stats",
                "latency_avg_ship_ema",
                "dc_latency_avg_ship",
                "dc_latency_avg_ship_ema",
                "dc_ship_latency_avg",
            ),
        ),
        Field(
            "Status",
            Projectors.Number("dc_stats", "xdr_dc_state", "xdr-dc-state", "dc_state"),
        ),
    ),
    from_source=("node_ids", "node_names", "dc_stats"),
    for_each="dc_stats",
    where=lambda record: record["DC"],
    group_by=("DC", "Namespaces"),
    order_by=FieldSorter("Node"),
)

info_xdr_sheet = Sheet(
    (
        Field("XDR Enabled", Projectors.Boolean("xdr_enable", None), hidden=True),
        node_field,
        hidden_node_id_field,
        Field("Success", Projectors.Number("xdr_stats", "success")),
        Subgroup(
            "Retry",
            (
                Field(
                    "Connection Reset",
                    Projectors.Number("xdr_stats", "retry_conn_reset"),
                ),
                Field("Destination", Projectors.Number("xdr_stats", "retry_dest")),
            ),
        ),
        Field(
            "Recoveries Pending",
            Projectors.Number("xdr_stats", "recoveries_pending"),
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Lag (hh:mm:ss)",
            Projectors.Number("xdr_stats", "lag"),
            converter=Converters.time_seconds,
        ),
        Field(
            "Avg Latency (ms)",
            Projectors.Number("xdr_stats", "latency_ms"),
            aggregator=Aggregators.max(),
        ),
        Field("Throughput (rec/s)", Projectors.Number("xdr_stats", "throughput")),
    ),
    from_source=("xdr_enable", "node_ids", "node_names", "xdr_stats"),
    where=lambda record: record["XDR Enabled"],
    order_by=FieldSorter("Node"),
)


def sindex_state_converter(edata):
    state = edata.value

    if state == "WO":
        return "Write-Only"

    if state == "RW":
        return "Read-Write"

    return state


info_sindex_sheet = Sheet(
    (
        Field("Index Name", Projectors.String("sindex_stats", "indexname")),
        Field("Namespace", Projectors.String("sindex_stats", "ns")),
        Field("Set", Projectors.String("sindex_stats", "set")),
        node_field,
        hidden_node_id_field,
        Field("Bin", Projectors.String("sindex_stats", "bins", "bin")),
        Field("Num Bins", Projectors.Number("sindex_stats", "num_bins")),
        Field("Bin Type", Projectors.String("sindex_stats", "type")),
        Field(
            "State",
            Projectors.String("sindex_stats", "state"),
            converter=sindex_state_converter,
        ),  # new
        Field("Sync State", Projectors.String("sindex_stats", "sync_state")),  # old
        Field(
            "Keys",
            Projectors.Any(
                # added 6.1
                FieldType.number,
                Projectors.Div(
                    Projectors.Number("sindex_stats", "entries"),
                    Projectors.Number("sindex_stats", "entries_per_bval"),
                ),
                # removed 6.0
                Projectors.Number("sindex_stats", "keys"),
            ),
            converter=Converters.scientific_units,
        ),
        Subgroup(
            "Entries",
            (
                Field(
                    "Total",
                    Projectors.Number("sindex_stats", "entries", "objects"),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Avg Per Rec",
                    Projectors.Number("sindex_stats", "entries_per_rec"),  # added 6.1
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Avg Per Bin Val",
                    Projectors.Any(
                        FieldType.number,
                        Projectors.Number(
                            "sindex_stats", "entries_per_bval"
                        ),  # added 6.1
                        Projectors.Div(
                            Projectors.Number("sindex_stats", "entries"),
                            Projectors.Number("sindex_stats", "keys"),  # removed 6.0
                        ),
                    ),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
        Subgroup(
            "Storage",
            (
                Field("Type", Projectors.String("sindex_stats", "sindex-type")),
                Field(
                    "Used",
                    Projectors.Any(
                        FieldType.number,
                        Projectors.Number(
                            "sindex_stats", "used_bytes", "memory_used"
                        ),  # memory_used renamed in 6.3 to be more generic
                        Projectors.Sum(
                            # removed in 6.0
                            Projectors.Number("sindex_stats", "ibtr_memory_used"),
                            Projectors.Number("sindex_stats", "nbtr_memory_used"),
                        ),
                    ),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
        Field(
            "Context",
            Projectors.Func(
                FieldType.string,
                _ignore_null,
                Projectors.String("sindex_stats", "context"),
            ),
        ),
        Field(
            "Expression",
            Projectors.Func(
                FieldType.string,
                _ignore_null,
                Projectors.String("sindex_stats", "exp"),
            ),
        ),
        Subgroup(
            "Queries",
            (
                Field(
                    "Requests",
                    Projectors.Any(
                        FieldType.number,
                        # query_basic_* added 5.7, removed in 6.0
                        Projectors.Sum(
                            Projectors.Number("sindex_stats", "query_basic_complete"),
                            Projectors.Number("sindex_stats", "query_basic_error"),
                            Projectors.Number("sindex_stats", "query_basic_abort"),
                        ),
                        # removed in 5.7
                        Projectors.Number("sindex_stats", "query_reqs"),
                    ),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Avg Num Recs",
                    Projectors.Number(
                        "sindex_stats",
                        "query_basic_avg_rec_count",  # query_basic_* added 5.7, removed 6.0
                        "query_avg_rec_count",  # removed in 5.7
                    ),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
        Subgroup(
            "Updates",
            (
                Field(
                    "Writes",
                    # write_success removed in 6.0
                    Projectors.Number(
                        "sindex_stats", "write_success", "stat_write_success"
                    ),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Deletes",
                    # delete_success removed in 6.0
                    Projectors.Number(
                        "sindex_stats", "delete_success", "stat_delete_success"
                    ),
                    converter=Converters.scientific_units,
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
    ),
    from_source=(
        "node_ids",
        "node_names",
        "sindex_stats",
    ),
    for_each=("sindex_stats"),
    group_by=("Namespace", "Set"),
    order_by=(FieldSorter("Index Name"), FieldSorter("Node")),
)

show_distribution_sheet = Sheet(
    tuple(
        itertools.chain(
            [TitleField("Node", Projectors.String("node_names", None))],
            [
                Field("{}%".format(pct), Projectors.Number("histogram", i))
                for i, pct in enumerate(range(10, 110, 10))
            ],
        )
    ),
    from_source=("node_names", "histogram"),
    order_by=FieldSorter("Node"),
)


def extract_value_from_dict(key: str):
    def extract_value(dict):
        if key not in dict:
            raise NoEntryException(f"{key} not found dict")

        return dict[key]

    return extract_value


def _storage_type_display_name(storage_type: str, field_title: str, subgroup: bool):
    title = ""

    if not subgroup:
        title = (
            " ".join(val[0].upper() + val[1:] for val in storage_type.split("_"))
            + " "
            + field_title
        )
    else:
        title = field_title

    return title


def create_summary_total(
    source: str, storage_type: str, subgroup=False, display_name: str | None = None
):
    if display_name is None:
        title = _storage_type_display_name(storage_type, "Total", subgroup)
    else:
        title = _storage_type_display_name(display_name, "Total", subgroup)

    return Field(
        title,
        Projectors.Func(
            FieldType.number,
            extract_value_from_dict("total"),
            Projectors.Identity(source, storage_type),
        ),
        converter=Converters.byte,
    )


def create_summary_used(
    source: str, storage_type: str, subgroup=False, display_name: str | None = None
):
    if display_name is None:
        title = _storage_type_display_name(storage_type, "Used", subgroup)
    else:
        title = _storage_type_display_name(display_name, "Used", subgroup)

    return Field(
        title,
        Projectors.Func(
            FieldType.number,
            extract_value_from_dict("used"),
            Projectors.Identity(source, storage_type),
        ),
        converter=Converters.byte,
    )


def create_summary_used_pct(
    source: str, storage_type: str, subgroup=False, display_name: str | None = None
):
    if display_name is None:
        title = _storage_type_display_name(storage_type, "Used%", subgroup)
    else:
        title = _storage_type_display_name(display_name, "Used%", subgroup)

    return Field(
        title,
        Projectors.Func(
            FieldType.number,
            extract_value_from_dict("used_pct"),
            Projectors.Identity(source, storage_type),
        ),
        converter=Converters.pct,
    )


def create_summary_avail(
    source: str, storage_type: str, subgroup=False, display_name: str | None = None
):
    if display_name is None:
        title = _storage_type_display_name(storage_type, "Avail", subgroup)
    else:
        title = _storage_type_display_name(display_name, "Avail", subgroup)

    return Field(
        title,
        Projectors.Func(
            FieldType.number,
            extract_value_from_dict("avail"),
            Projectors.Identity(source, storage_type),
        ),
        converter=Converters.byte,
    )


def create_summary_avail_pct(
    source: str, storage_type: str, subgroup=False, display_name: str | None = None
):
    if display_name is None:
        title = _storage_type_display_name(storage_type, "Avail%", subgroup)
    else:
        title = _storage_type_display_name(display_name, "Avail%", subgroup)

    return Field(
        title,
        Projectors.Func(
            FieldType.number,
            extract_value_from_dict("avail_pct"),
            Projectors.Identity(source, storage_type),
        ),
        converter=Converters.pct,
    )


def _extract_from_dict_and_convert_datetime(key: str):
    extract_value = extract_value_from_dict(key)

    def extract_and_convert_value(d: dict):
        dtime: Union[datetime, None] = extract_value(d)

        if dtime is None:
            return dtime

        return dtime.isoformat()

    return extract_and_convert_value


summary_cluster_sheet = Sheet(
    (
        Field(
            "Migrations",
            Projectors.String("cluster_dict", "migrations_in_progress"),
            formatters=(
                Formatters.red_alert(lambda edata: edata.value),
                Formatters.green_alert(lambda edata: not edata.value),
            ),
        ),
        Field(
            "Cluster Name",
            Projectors.Identity("cluster_dict", "cluster_name"),
            converter=Converters.list_to_comma_sep_str,
        ),
        Field(
            "Server Version",
            Projectors.Identity("cluster_dict", "server_version"),
            converter=Converters.list_to_comma_sep_str,
        ),
        Field(
            "OS Version",
            Projectors.Identity("cluster_dict", "os_version"),
            converter=Converters.list_to_comma_sep_str,
        ),
        Field(
            "Cluster Size",
            Projectors.Identity("cluster_dict", "cluster_size"),
            converter=Converters.list_to_comma_sep_str,
        ),
        # Subgroup(
        #     "Devices",
        #     (
        Field("Devices Total", Projectors.Number("cluster_dict", "device_count")),
        Field(
            "Devices Per-Node",
            Projectors.Number("cluster_dict", "device_count_per_node"),
        ),
        Field(
            "Devices Equal Across Nodes",
            Projectors.Boolean("cluster_dict", "device_count_same_across_nodes"),
            formatters=(Formatters.red_alert(lambda edata: not edata.value),),
        ),
        # ),
        # ),
        # Subgroup(
        #     "Memory",
        #     (
        create_summary_total(
            "cluster_dict",
            "memory_data_and_indexes",
            display_name="Memory (Data + Indexes)",
        ),
        create_summary_used(
            "cluster_dict",
            "memory_data_and_indexes",
            display_name="Memory (Data + Indexes)",
        ),
        create_summary_used_pct(
            "cluster_dict",
            "memory_data_and_indexes",
            display_name="Memory (Data + Indexes)",
        ),
        create_summary_avail(
            "cluster_dict",
            "memory_data_and_indexes",
            display_name="Memory (Data + Indexes)",
        ),
        create_summary_avail_pct(
            "cluster_dict",
            "memory_data_and_indexes",
            display_name="Memory (Data + Indexes)",
        ),
        #      ),
        # ),
        # Subgroup(
        #     "Shmem Index", # Sindex added to shmem in EE by default in 6.1. However,
        #     this will only be displayed in 7.0. Pre 7.0 includes shmem index metrics
        #     as apart of memory metrics.
        #     (
        create_summary_used("cluster_dict", "shmem_index"),
        #     ),
        # ),
        # Subgroup(
        #     "Pmem Index",
        #     (
        create_summary_total("cluster_dict", "pmem_index"),
        create_summary_used("cluster_dict", "pmem_index"),
        create_summary_used_pct("cluster_dict", "pmem_index"),
        create_summary_avail("cluster_dict", "pmem_index"),
        create_summary_avail_pct("cluster_dict", "pmem_index"),
        #     ),
        # ),
        # Subgroup(
        #     "Flash Index",
        #     (
        create_summary_total("cluster_dict", "flash_index"),
        create_summary_used("cluster_dict", "flash_index"),
        create_summary_used_pct("cluster_dict", "flash_index"),
        create_summary_avail("cluster_dict", "flash_index"),
        create_summary_avail_pct("cluster_dict", "flash_index"),
        #     ),
        # ),
        # Subgroup(
        #     "Memory",
        #     (
        create_summary_total("cluster_dict", "memory"),
        create_summary_used("cluster_dict", "memory"),
        create_summary_used_pct("cluster_dict", "memory"),
        create_summary_avail("cluster_dict", "memory"),
        create_summary_avail_pct("cluster_dict", "memory"),
        #      ),
        # ),
        # Subgroup(
        #     "Device",
        #     (
        create_summary_total("cluster_dict", "device"),
        create_summary_used("cluster_dict", "device"),
        create_summary_used_pct("cluster_dict", "device"),
        create_summary_avail("cluster_dict", "device"),
        create_summary_avail_pct("cluster_dict", "device"),
        #     ),
        # ),
        # Subgroup(
        #     "Pmem",
        #     (
        create_summary_total("cluster_dict", "pmem"),
        create_summary_used("cluster_dict", "pmem"),
        create_summary_used_pct("cluster_dict", "pmem"),
        create_summary_avail("cluster_dict", "pmem"),
        create_summary_avail_pct("cluster_dict", "pmem"),
        #     ),
        # ),
        Field(
            "Replication Factors",
            Projectors.Func(
                FieldType.string,
                lambda v: ",".join(map(str, v)),
                Projectors.Identity("cluster_dict", "repl_factor"),
            ),
            align=FieldAlignment.right,
        ),
        Field(
            "Cache Read%",
            Projectors.Percent("cluster_dict", "cache_read_pct"),
            converter=Converters.pct,
        ),
        Field(
            "Master Objects",
            Projectors.Number("cluster_dict", "master_objects"),
            Converters.scientific_units,
        ),
        Field(
            "Compression Ratio", Projectors.Float("cluster_dict", "compression_ratio")
        ),
        Field(
            "License Usage Latest",
            Projectors.Func(
                FieldType.number,
                extract_value_from_dict("latest"),
                Projectors.Identity("cluster_dict", "license_data"),
            ),
            converter=Converters.byte,
        ),
        Field(
            "License Usage Latest Time",
            Projectors.Func(
                FieldType.string,
                _extract_from_dict_and_convert_datetime("latest_time"),
                Projectors.Identity("cluster_dict", "license_data"),
            ),
            converter=Converters.byte,
        ),
        Field(
            "License Usage Min",
            Projectors.Func(
                FieldType.number,
                extract_value_from_dict("min"),
                Projectors.Identity("cluster_dict", "license_data"),
            ),
            converter=Converters.byte,
        ),
        Field(
            "License Usage Max",
            Projectors.Func(
                FieldType.number,
                extract_value_from_dict("max"),
                Projectors.Identity("cluster_dict", "license_data"),
            ),
            converter=Converters.byte,
        ),
        Field(
            "License Usage Avg",
            Projectors.Func(
                FieldType.number,
                extract_value_from_dict("avg"),
                Projectors.Identity("cluster_dict", "license_data"),
            ),
            converter=Converters.byte,
        ),
        # Subgroup(
        #     "Namespaces",
        #     (
        Field("Namespaces Active", Projectors.Number("cluster_dict", "active_ns")),
        Field("Namespaces Total", Projectors.Number("cluster_dict", "ns_count")),
        #     ),
        # ),
        Field(
            "Active Features",
            Projectors.Identity("cluster_dict", "active_features"),
            converter=Converters.list_to_comma_sep_str,
        ),
    ),
    from_source="cluster_dict",
    default_style=SheetStyle.rows,
)

summary_namespace_sheet = Sheet(
    (
        Field(
            "Namespace",
            Projectors.String("ns_stats", None, for_each_key=True),
            formatters=(
                Formatters.red_alert(lambda edata: edata.record["active_migrations"]),
            ),
        ),
        Field(
            "active_migrations",
            Projectors.Boolean("ns_stats", "migrations_in_progress"),
            hidden=True,
        ),
        Subgroup(
            "Drives",
            (
                Field("Total", Projectors.Number("ns_stats", "devices_total")),
                Field("Per-Node", Projectors.Number("ns_stats", "devices_per_node")),
            ),
        ),
        Subgroup(
            "Memory (Data + Indexes)",
            (
                create_summary_total(
                    "ns_stats", "memory_data_and_indexes", subgroup=True
                ),
                create_summary_used(
                    "ns_stats", "memory_data_and_indexes", subgroup=True
                ),
                create_summary_used_pct(
                    "ns_stats", "memory_data_and_indexes", subgroup=True
                ),
                create_summary_avail(
                    "ns_stats", "memory_data_and_indexes", subgroup=True
                ),
                create_summary_avail_pct(
                    "ns_stats", "memory_data_and_indexes", subgroup=True
                ),
            ),
        ),
        Subgroup(
            "Pmem Index",
            (
                create_summary_total("ns_stats", "pmem_index", subgroup=True),
                create_summary_used_pct("ns_stats", "pmem_index", subgroup=True),
                create_summary_avail_pct("ns_stats", "pmem_index", subgroup=True),
            ),
        ),
        Subgroup(
            "Flash Index",
            (
                create_summary_total("ns_stats", "flash_index", subgroup=True),
                create_summary_used_pct("ns_stats", "flash_index", subgroup=True),
                create_summary_avail_pct("ns_stats", "flash_index", subgroup=True),
            ),
        ),
        Subgroup(
            "Memory",
            (
                create_summary_total("ns_stats", "memory", subgroup=True),
                create_summary_used_pct("ns_stats", "memory", subgroup=True),
                create_summary_avail_pct("ns_stats", "memory", subgroup=True),
            ),
        ),
        Subgroup(
            "Device",
            (
                create_summary_total("ns_stats", "device", subgroup=True),
                create_summary_used_pct("ns_stats", "device", subgroup=True),
                create_summary_avail_pct("ns_stats", "device", subgroup=True),
            ),
        ),
        Subgroup(
            "Pmem",
            (
                create_summary_total("ns_stats", "pmem", subgroup=True),
                create_summary_used_pct("ns_stats", "pmem", subgroup=True),
                create_summary_avail_pct("ns_stats", "pmem", subgroup=True),
            ),
        ),
        Field(
            "Replication Factors",
            Projectors.Func(
                FieldType.string,
                lambda v: ",".join(map(str, v)),
                Projectors.Identity("ns_stats", "repl_factor"),
            ),
            align=FieldAlignment.right,
        ),
        Field(
            "Cache Read%",
            Projectors.Percent("ns_stats", "cache_read_pct"),
            converter=Converters.pct,
        ),
        Field(
            "Master Objects",
            Projectors.Number("ns_stats", "master_objects"),
            Converters.scientific_units,
        ),
        Field("Compression Ratio", Projectors.Float("ns_stats", "compression_ratio")),
        Subgroup(
            "License Usage",
            (
                Field(
                    "Latest",
                    Projectors.Func(
                        FieldType.number,
                        extract_value_from_dict("latest"),
                        Projectors.Identity("ns_stats", "license_data"),
                    ),
                    converter=Converters.byte,
                ),
                Field(
                    "Latest Time",
                    Projectors.Func(
                        FieldType.number,
                        _extract_from_dict_and_convert_datetime("latest_time"),
                        Projectors.Identity("ns_stats", "license_data"),
                    ),
                    converter=Converters.byte,
                ),
                Field(
                    "Min",
                    Projectors.Func(
                        FieldType.number,
                        extract_value_from_dict("min"),
                        Projectors.Identity("ns_stats", "license_data"),
                    ),
                    converter=Converters.byte,
                ),
                Field(
                    "Max",
                    Projectors.Func(
                        FieldType.number,
                        extract_value_from_dict("max"),
                        Projectors.Identity("ns_stats", "license_data"),
                    ),
                    converter=Converters.byte,
                ),
                Field(
                    "Avg",
                    Projectors.Func(
                        FieldType.number,
                        extract_value_from_dict("avg"),
                        Projectors.Identity("ns_stats", "license_data"),
                    ),
                    converter=Converters.byte,
                ),
            ),
        ),
    ),
    from_source="ns_stats",
    for_each="ns_stats",
    group_by="Namespace",
    order_by=FieldSorter("Namespace"),
)

show_pmap_sheet = Sheet(
    (
        Field("Namespace", Projectors.String("pmap", None, for_each_key=True)),
        node_field,
        hidden_node_id_field,
        Field("Cluster Key", Projectors.Number("pmap", "cluster_key")),
        Subgroup(
            "Partitions",
            (
                Field(
                    "Primary",
                    Projectors.Number("pmap", "master_partition_count"),
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Secondary",
                    Projectors.Number("pmap", "prole_partition_count"),
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Unavailable",
                    Projectors.Number("pmap", "unavailable_partitions"),
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Dead",
                    Projectors.Number("pmap", "dead_partitions"),
                    aggregator=Aggregators.sum(),
                ),
            ),
        ),
    ),
    from_source=("node_names", "node_ids", "pmap"),
    for_each="pmap",
    group_by="Namespace",
    order_by=FieldSorter("Node"),
)


def numeric_sum_aggregator_selector(key, is_numeric):
    if is_numeric:
        return Aggregators.sum()


show_config_sheet = Sheet(
    (
        node_field,
        hidden_node_id_field,
        DynamicFields(
            "data",
            required=True,
            order=DynamicFieldOrder.ascending,
            aggregator_selector=numeric_sum_aggregator_selector,
        ),
    ),
    from_source=("node_names", "data", "node_ids"),
    order_by=FieldSorter("Node"),
    default_style=SheetStyle.rows,
)

show_xdr_ns_sheet = Sheet(
    (
        Field("Datacenter", Projectors.String("data", None, for_each_key=True)),
        node_field,
        hidden_node_id_field,
        DynamicFields(
            "data",
            required=True,
            order=DynamicFieldOrder.ascending,
            aggregator_selector=numeric_sum_aggregator_selector,
        ),
    ),
    from_source=("node_names", "data", "node_ids"),
    group_by=("Datacenter"),
    order_by=(FieldSorter("Datacenter"), FieldSorter("Node")),
    default_style=SheetStyle.rows,
    for_each=["data"],
)


show_xdr_ns_sheet_by_dc = Sheet(
    (
        Field("Namespace", Projectors.String("data", None, for_each_key=True)),
        node_field,
        hidden_node_id_field,
        DynamicFields("data", required=True, order=DynamicFieldOrder.ascending),
    ),
    from_source=("node_names", "data", "node_ids"),
    group_by=("Namespace"),
    order_by=(FieldSorter("Namespace"), FieldSorter("Node")),
    default_style=SheetStyle.rows,
    for_each=["data"],
)

show_xdr_filters = Sheet(
    (
        Field("Namespace", Projectors.String("data", 1, for_each_key=True)),
        Field("Datacenter", Projectors.String("data", 0, for_each_key=True)),
        Field(
            "Base64 Expression", Projectors.String("data", "b64-exp"), allow_diff=True
        ),
        Field("Expression", Projectors.String("data", "exp"), allow_diff=True),
    ),
    from_source=("data"),
    for_each="data",
    group_by=("Namespace"),
    order_by=(FieldSorter("Namespace"), FieldSorter("Datacenter")),
    default_style=SheetStyle.columns,
)


show_mapping_to_ip_sheet = Sheet(
    (
        Field("Node ID", Projectors.String("mapping", 0)),
        Field("IP", Projectors.String("mapping", 1)),
    ),
    from_source="mapping",
    order_by=FieldSorter("Node ID"),
)

show_mapping_to_id_sheet = Sheet(
    (
        Field("IP", Projectors.String("mapping", 0)),
        Field("Node ID", Projectors.String("mapping", 1)),
    ),
    from_source="mapping",
    order_by=FieldSorter("IP"),
)

show_object_distribution_sheet = Sheet(
    (
        TitleField("Node", Projectors.String("node_names", None)),
        DynamicFields("histogram", required=True, order=DynamicFieldOrder.source),
    ),
    from_source=("node_names", "histogram"),
    order_by=FieldSorter("Node"),
)


def latency_weighted_avg(edatas: list[EntryData]):
    weights: map[float] = map(lambda edata: edata.record["ops/sec"], edatas)
    pcts = [data.value for data in edatas]
    return weighted_avg(pcts, weights)


weightedAvgAggregator = ComplexAggregator(
    latency_weighted_avg, converter=Converters.round(2)
)


def latency_aggregator_selector(key, is_numeric):
    if key == "ops/sec":
        return Aggregators.sum(converter=Converters.round(2))

    if key != "Time Span":
        return weightedAvgAggregator


def latency_projector_selector(key):
    return Projectors.Float


show_latency_sheet = Sheet(
    (
        Field("Namespace", Projectors.String("histogram", 0, for_each_key=True)),
        Field("Histogram", Projectors.String("histogram", 1, for_each_key=True)),
        TitleField("Node", Projectors.String("node_names", None)),
        DynamicFields(
            "histogram",
            required=True,
            order=DynamicFieldOrder.source,
            projector_selector=latency_projector_selector,
            aggregator_selector=latency_aggregator_selector,
        ),
    ),
    from_source=("node_names", "histogram"),
    for_each="histogram",
    group_by=("Namespace", "Histogram"),
    order_by=FieldSorter("Node"),
)


def stop_writes_converter_selector(edata: EntryData):
    if "Metric" not in edata.record:
        return None

    metric = edata.record["Metric"]
    val = ""

    if "pct" in metric:
        if "avail" in metric:
            val = Converters.pct(edata, invert=True)
            val = "(inverted) " + val
            return val

        return Converters.pct(edata)
    if "bytes" in metric:
        return Converters.byte(edata)
    if "_ms" in metric:
        return Converters.time_milliseconds(edata)

    return Converters.scientific_units(edata)


class StopWritesUsagePctProjector(Projectors.Number):
    def __init__(self, source, *keys, **kwargs):
        """
        Keyword Arguments:
        invert -- False by default, if True will return 100 - value.
        """
        super().__init__(source, *keys, **kwargs)
        self.invert = kwargs.get("invert", False)

    def do_project(self, sheet, sources):
        data = sources.get("stop_writes", ((), {}))[1]
        val = super().do_project(sheet, sources)

        if "metric" in data and "avail" in data["metric"]:
            val = 100 - val

        return _ignore_zero(val)


sw_row_yellow_format = (
    Formatters.yellow_alert(lambda edata: edata.record["Stop-Writes"] == True),
)
sw_val_red_format = (
    Formatters.red_alert(lambda edata: edata.record["Usage%"] >= 0.90),  # 90%
)
sw_val_yellow_format = (
    Formatters.yellow_alert(lambda edata: edata.record["Usage%"] >= 0.75),  # 75%
)

show_stop_writes_sheet = Sheet(
    (
        Field(
            "key",
            Projectors.String("stop_writes", None, for_each_key=True),
            hidden=True,
        ),
        Field(
            "Config",
            Projectors.String("stop_writes", "config"),
            formatters=sw_row_yellow_format,
        ),
        Field(
            "Namespace",
            Projectors.String("stop_writes", "namespace"),
            formatters=sw_row_yellow_format,
        ),
        Field(
            "Set",
            Projectors.String("stop_writes", "set"),
            formatters=sw_row_yellow_format,
        ),
        Field(
            "Node",
            Projectors.String("node_names", None),
            formatters=sw_row_yellow_format,
        ),
        Field(
            "Stop-Writes",
            Projectors.Boolean("stop_writes", "stop_writes"),
            formatters=sw_val_red_format + sw_row_yellow_format,
        ),
        Field(
            "Metric",
            Projectors.String("stop_writes", "metric"),
            formatters=sw_row_yellow_format,
        ),
        Field(
            "Usage%",
            Projectors.Div(
                StopWritesUsagePctProjector("stop_writes", "metric_usage"),
                StopWritesUsagePctProjector("stop_writes", "metric_threshold"),
            ),
            converter=Converters.ratio_to_pct,
            formatters=sw_val_red_format + sw_val_yellow_format + sw_row_yellow_format,
        ),
        Field(
            "Usage",
            Projectors.Number("stop_writes", "metric_usage"),
            converter=stop_writes_converter_selector,
            formatters=sw_row_yellow_format,
        ),
        Field(
            "Threshold",
            Projectors.Func(
                FieldType.number,
                _ignore_zero,
                Projectors.Number("stop_writes", "metric_threshold"),
            ),
            converter=stop_writes_converter_selector,
            formatters=sw_row_yellow_format,
        ),
    ),
    from_source=("node_names", "stop_writes"),
    for_each="stop_writes",
    order_by=(FieldSorter("Usage%"), FieldSorter("Metric")),
)


def turn_empty_to_none(ls):
    if not ls:
        raise NoEntryException("List is empty")

    return ls


show_users = Sheet(
    (
        Field("User", Projectors.String("data", None, for_each_key=True)),
        Field(
            "Roles",
            Projectors.Func(
                FieldType.undefined,
                turn_empty_to_none,
                Projectors.Identity("data", "roles"),
            ),
            Converters.list_to_comma_sep_str,
            align=FieldAlignment.right,
        ),
        Subgroup(
            "Read",
            (
                Field(
                    "Quota",
                    Projectors.Func(
                        FieldType.undefined,
                        extract_value_from_dict("quota"),
                        Projectors.Identity("data", "read-info"),
                    ),
                ),
            ),
        ),
        Subgroup(
            "Write",
            (
                Field(
                    "Quota",
                    Projectors.Func(
                        FieldType.undefined,
                        extract_value_from_dict("quota"),
                        Projectors.Identity("data", "write-info"),
                    ),
                ),
            ),
        ),
        Field(
            "Auth Mode",
            Projectors.Func(
                FieldType.string,
                turn_empty_to_none,
                Projectors.Identity("data", "auth-mode"),
            ),
            align=FieldAlignment.right,
        ),
    ),
    from_source="data",
    for_each="data",
    order_by=FieldSorter("User"),
)


def create_quota_weighted_avg(type: str):
    """
    A simple averaging would work fine since all nodes likely have the same quota. Although,
    there is a slight chance they do not.
    """

    def usage_weighted_avg(edatas: list[EntryData]):
        pcts: map[float] = map(lambda edata: edata.value, edatas)
        weights: map[float] = map(lambda edata: edata.record[type]["Quota"], edatas)

        if not weights:
            return None

        return weighted_avg(pcts, weights)

    return usage_weighted_avg


def create_quota_tps_subgroup(
    type: Literal["Read"] | Literal["Write"],
    key: Literal["read-info"] | Literal["write-info"],
):
    return Subgroup(
        type,
        (
            Field(
                "Quota",
                Projectors.Func(
                    FieldType.number,
                    extract_value_from_dict("quota"),
                    Projectors.Identity("data", key),
                ),
                converter=Converters.scientific_units,
                aggregator=Aggregators.sum(converter=Converters.scientific_units),
            ),
            Field(
                "Usage%",
                Projectors.Div(
                    Projectors.Sum(
                        Projectors.Func(
                            FieldType.number,
                            extract_value_from_dict("single-record-tps"),
                            Projectors.Identity("data", key),
                        ),
                        Projectors.Func(
                            FieldType.number,
                            extract_value_from_dict("scan-query-rps-limited"),
                            Projectors.Identity("data", key),
                        ),
                    ),
                    Projectors.Func(
                        FieldType.number,
                        lambda x: _ignore_zero(extract_value_from_dict("quota")(x)),
                        Projectors.Identity("data", key),
                    ),
                ),
                converter=Converters.ratio_to_pct,
                aggregator=ComplexAggregator(
                    create_quota_weighted_avg(type), converter=Converters.ratio_to_pct
                ),
                formatters=(
                    Formatters.red_alert(lambda edata: edata.value * 100 >= 90.0),
                    Formatters.yellow_alert(lambda edata: edata.value * 100 >= 75.0),
                ),
            ),
            Field(
                "Single Record TPS",
                Projectors.Func(
                    FieldType.number,
                    extract_value_from_dict("single-record-tps"),
                    Projectors.Identity("data", key),
                ),
                converter=Converters.scientific_units,
                aggregator=Aggregators.sum(converter=Converters.scientific_units),
            ),
            # TODO: Support for Subgroups to have Subgroups to have PI/SI Query be a
            # subgroup of Write
            Field(
                "PI/SI Query Limited RPS",
                Projectors.Func(
                    FieldType.number,
                    extract_value_from_dict("scan-query-rps-limited"),
                    Projectors.Identity("data", key),
                ),
                converter=Converters.scientific_units,
                aggregator=Aggregators.sum(converter=Converters.scientific_units),
            ),
            Field(
                "PI/SI Query Limitless",
                Projectors.Func(
                    FieldType.number,
                    extract_value_from_dict("scan-query-limitless"),
                    Projectors.Identity("data", key),
                ),
                converter=Converters.scientific_units,
                aggregator=Aggregators.sum(converter=Converters.scientific_units),
            ),
        ),
    )


show_users_stats = Sheet(
    (
        Field("User", Projectors.String("data", None, for_each_key=True)),
        node_field,
        Field(
            "Connections",
            Projectors.Number("data", "connections"),
            converter=Converters.scientific_units,
            aggregator=Aggregators.sum(converter=Converters.scientific_units),
        ),
        create_quota_tps_subgroup("Read", "read-info"),
        create_quota_tps_subgroup("Write", "write-info"),
    ),
    from_source=("data", "node_names"),
    for_each="data",
    order_by=(FieldSorter("User"), FieldSorter("Node")),
    group_by="User",
)

show_roles = Sheet(
    (
        Field("Role", Projectors.String("data", None, for_each_key=True)),
        Field(
            "Privileges",
            Projectors.Func(
                FieldType.string,
                turn_empty_to_none,
                Projectors.Identity("data", "privileges"),
            ),
            Converters.list_to_comma_sep_str,
            align=FieldAlignment.right,
        ),
        Field(
            "Allowlist",
            Projectors.Func(
                FieldType.string,
                turn_empty_to_none,
                Projectors.Identity("data", "whitelist"),
            ),
            Converters.list_to_comma_sep_str,
            align=FieldAlignment.right,
        ),
        Subgroup(
            "Quotas",
            (
                Field("Read", Projectors.String("data", "read-quota")),
                Field("Write", Projectors.String("data", "write-quota")),
            ),
        ),
    ),
    from_source="data",
    for_each="data",
    order_by=FieldSorter("Role"),
)

show_udfs = Sheet(
    (
        Field("Filename", Projectors.String("data", None, for_each_key=True)),
        Field(
            "Hash",
            Projectors.String("data", "hash"),
        ),
        Field("Type", Projectors.String("data", "type")),
    ),
    from_source="data",
    for_each="data",
    order_by=FieldSorter("Filename"),
)

show_sindex = Sheet(
    (
        Field("Index Name", Projectors.String("data", "indexname")),
        Field("Namespace", Projectors.String("data", "ns")),
        Field("Set", Projectors.String("data", "set")),
        Field("Bin", Projectors.Number("data", "bins", "bin")),
        Field("Bin Type", Projectors.String("data", "type")),
        Field("Index Type", Projectors.String("data", "indextype")),
        Field("State", Projectors.String("data", "state")),
        Field(
            "Context",
            Projectors.Func(
                "string", _ignore_null, Projectors.String("data", "context")
            ),
        ),
        Field(
            "Expression",
            Projectors.Func(
                "string", _ignore_null, Projectors.String("data", "exp")
            ),
        ),
    ),
    from_source=("data"),
    group_by=("Namespace", "Set"),
    order_by=(FieldSorter("Index Name"), FieldSorter("Namespace"), FieldSorter("Set")),
)


def roster_null_to_empty_list_converter(edata):
    val = edata.value

    if isinstance(val, list) and len(val) == 1 and val[0] == "null":
        edata.value = []

    return Converters.list_to_comma_sep_str(edata)


show_roster = Sheet(
    (
        node_field,
        Field(
            "Node ID",
            Projectors.String("node_ids", None),
            converter=(
                lambda edata: (
                    "*" + edata.value
                    if edata.value == edata.common["principal"]
                    else edata.value
                )
            ),
            formatters=(
                Formatters.green_alert(
                    lambda edata: edata.record["Node ID"] == edata.common["principal"]
                ),
            ),
            align=FieldAlignment.left,
        ),
        Field("Namespace", Projectors.String("data", None, for_each_key=True)),
        Field(
            "Current Roster",
            Projectors.Identity("data", "roster"),
            roster_null_to_empty_list_converter,
            allow_diff=True,
        ),
        Field(
            "Pending Roster",
            Projectors.Identity("data", "pending_roster"),
            roster_null_to_empty_list_converter,
            allow_diff=True,
        ),
        Field(
            "Observed Nodes",
            Projectors.Identity("data", "observed_nodes"),
            roster_null_to_empty_list_converter,
            allow_diff=True,
        ),
    ),
    from_source=("data", "node_names", "node_ids"),
    for_each="data",
    group_by=("Namespace"),
    order_by=(FieldSorter("Node ID"), FieldSorter("Namespace")),
)


def ok_or_list(resp):
    if isinstance(resp, Exception):
        raise resp
    if not resp:
        return ASINFO_RESPONSE_OK

    return ", ".join(resp)


show_best_practices = Sheet(
    (
        node_field,
        hidden_node_id_field,
        Field(
            "Response",
            Projectors.Func(
                FieldType.string, ok_or_list, Projectors.Identity("data", None)
            ),
            formatters=(
                Formatters.green_alert(lambda edata: edata.value == ASINFO_RESPONSE_OK),
                Formatters.red_alert(lambda edata: edata.value != ASINFO_RESPONSE_OK),
            ),
        ),
    ),
    from_source=("data", "node_names", "node_ids"),
)


def jobs_converter_selector(key):
    if "recs" in key or "rps" in key or "pids" in key:
        return Converters.scientific_units

    if "bytes" in key:
        return Converters.byte

    if "timeout" in key or "time" in key:
        return Converters.time_milliseconds

    return None


show_jobs = Sheet(
    (
        hidden_node_id_field,
        node_field,
        Field("Namespace", Projectors.String("data", "ns")),
        Field("Module", Projectors.String("data", "module")),
        Field("Type", Projectors.String("data", "job-type")),
        Field(
            "Progress%",
            Projectors.Percent("data", "job-progress"),
            converter=Converters.pct,
            formatters=(
                Formatters.yellow_alert(lambda edata: edata.value != 100.0),
                Formatters.green_alert(lambda edata: edata.value == 100.0),
            ),
        ),
        Field("Transaction ID", Projectors.Number("data", "trid")),
        Field(
            "Time Since Done",
            Projectors.Number("data", "time-since-done"),
            converter=Converters.time_milliseconds,
        ),
        DynamicFields("data", converter_selector=jobs_converter_selector),
    ),
    from_source=("data", "node_names", "node_ids"),
    for_each="data",
    group_by=("Namespace", "Module", "Type"),
    order_by=(
        FieldSorter("Progress%"),
        FieldSorter("Time Since Done"),
        FieldSorter("Node"),
    ),
    default_style=SheetStyle.rows,
)

show_racks = Sheet(
    (
        Field("Namespace", Projectors.String("data", 0, for_each_key=True)),
        Field("Rack ID", Projectors.Number("data", 1, for_each_key=True)),
        Field(
            "Nodes",
            Projectors.Identity("data", "nodes"),
            Converters.list_to_comma_sep_str,
        ),
    ),
    from_source=("data"),
    for_each="data",
    group_by=("Namespace"),
    order_by=FieldSorter(("Rack ID")),
)

kill_jobs = Sheet(
    (
        hidden_node_id_field,
        node_field,
        Field("Transaction ID", Projectors.Number("data", "trid")),
        Field("Namespace", Projectors.String("data", "ns")),
        Field("Module", Projectors.String("data", "module")),
        Field("Type", Projectors.String("data", "job-type")),
        Field(
            "Response",
            Projectors.String("data", "response"),
            formatters=(
                Formatters.green_alert(lambda edata: edata.value == ASINFO_RESPONSE_OK),
                Formatters.red_alert(lambda edata: edata.value != ASINFO_RESPONSE_OK),
            ),
        ),
    ),
    from_source=("data", "node_names", "node_ids"),
    group_by=("Namespace", "Module", "Type"),
    default_style=SheetStyle.columns,
    for_each="data",
)

grep_count_sheet = Sheet(
    (
        TitleField("Node", Projectors.String("node_ids", "node")),
        DynamicFields("data", required=True, order=DynamicFieldOrder.source),
    ),
    from_source=("node_ids", "data"),
    order_by=FieldSorter("Node"),
    default_style=SheetStyle.rows,
)

grep_count_sheet = Sheet(
    (
        TitleField("Node", Projectors.String("node_ids", "node")),
        DynamicFields(
            "data.count_result", required=True, order=DynamicFieldOrder.source
        ),
    ),
    from_source=("node_ids", "data"),
    order_by=FieldSorter("Node"),
    default_style=SheetStyle.rows,
)


def format_asinfo_error(msg: str):
    """Shortens strings of the form
    "Failed to set XDR configuration parameter period-ms to 1000 : Unknown error occurred."
    to "Unknown error occurred"
    """
    if msg.lower().startswith(ASINFO_RESPONSE_OK):
        return msg

    try:
        reason: str = msg.split(":")[1]
        reason = reason.strip(" .")
    except IndexError:
        return msg

    return reason


node_info_responses = Sheet(
    (
        node_field,
        Field(
            "Response",
            Projectors.Func(
                FieldType.string,
                format_asinfo_error,
                Projectors.Exception("data", None, filter_exc=[ASInfoError]),
            ),
            formatters=(
                Formatters.green_alert(
                    lambda edata: edata.value.startswith(ASINFO_RESPONSE_OK)
                ),
                Formatters.red_alert(
                    lambda edata: not edata.value.startswith(ASINFO_RESPONSE_OK)
                ),
            ),
        ),
    ),
    from_source=("data", "node_names"),
    order_by=FieldSorter("Node"),
    default_style=SheetStyle.columns,
)

# TODO
# grep_diff_sheet = Sheet(
#     (TitleField('Node', Projectors.String('node_ids', 'node')),
#      DynamicFields('data.Total', required=True,
#                    order=DynamicFieldOrder.source),
#      DynamicFields('data.Diff', required=True,
#                    order=DynamicFieldOrder.source)),
#     from_source=('node_ids', 'data'),
#     group_by='Node'
# )

# TODO
# summary_list_sheet = Sheet(
#     (Field('No', Projectors.Number('no', 'no')),
#      Field('Item', Projectors.String('summary', 'item')),
#      Field('Value', Projectors.String('summary', 'value'))),
#     from_source=('no', 'summary'),
#     order_by='No'
# )

# User Agents Sheet
user_agents_sheet = Sheet(
    (
        Field("Node", Projectors.String("data", "node")),
        Field("Client Version", Projectors.String("data", "client_version")),
        Field("App ID", Projectors.String("data", "app_id")), 
        Field(
            "Count", 
            Projectors.Number("data", "count"),
        ),
    ),
    from_source=("data",),
    order_by=(FieldSorter("Node"), FieldSorter("Client Version")),
)

# MRT Monitor metrics template
info_transactions_monitors_sheet = Sheet(
    (
        namespace_field,
        node_field,
        hidden_node_id_field,
        # Monitor Counts
        Field(
            "Count",
            Projectors.Number("ns_stats", "mrt_monitors"),
            converter=Converters.scientific_units,
            formatters=(
                Formatters.red_alert(lambda edata: edata.value > 0.9 * edata.record["stop-writes-count"] and edata.record["stop-writes-count"] > 0),
                Formatters.yellow_alert(lambda edata: edata.value > 0.7 * edata.record["stop-writes-count"] and edata.record["stop-writes-count"] > 0),
            ),
        ),
        Field(
            "Active",
            Projectors.Number("ns_stats", "mrt_monitors_active"),
            converter=Converters.scientific_units,
            formatters=(
                Formatters.yellow_alert(lambda edata: edata.value > 0),
            ),
        ),
        Field(
            "Tombstones",
            Projectors.Number("ns_stats", "mrt_monitor_roll_tombstone_creates"),
            converter=Converters.scientific_units,
        ),
        Field(
            "Storage",
            Projectors.Number("ns_stats", "pseudo_mrt_monitor_used_bytes"),
            converter=Converters.byte,
            formatters=(
                Formatters.red_alert(lambda edata: edata.value > 0.9 * edata.record["stop-writes-size"] and edata.record["stop-writes-size"] > 0),
                Formatters.yellow_alert(lambda edata: edata.value > 0.7 * edata.record["stop-writes-size"] and edata.record["stop-writes-size"] > 0),
            ),
        ),
        # For Color Alerts at Count and Storage
        Field(
            "stop-writes-count",
            Projectors.Number("ns_stats", "stop-writes-count"),
            hidden=True,
        ),
        Field(
            "stop-writes-size",
            Projectors.Number("ns_stats", "stop-writes-size"),
            hidden=True,
        ),
        # Monitor Roll Back Metrics
        Subgroup(
            "Monitor Roll Back",
            (
                Field(
                    "Success",
                    Projectors.Number("ns_stats", "mrt_monitor_roll_back_success"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Error",
                    Projectors.Number("ns_stats", "mrt_monitor_roll_back_error"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Timeout",
                    Projectors.Number("ns_stats", "mrt_monitor_roll_back_timeout"),
                    converter=Converters.scientific_units,
                ),
            ),
        ),
        # Monitor Roll Forward Metrics
        Subgroup(
            "Monitor Roll Forward",
            (
                Field(
                    "Success",
                    Projectors.Number("ns_stats", "mrt_monitor_roll_forward_success"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Error",
                    Projectors.Number("ns_stats", "mrt_monitor_roll_forward_error"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Timeout",
                    Projectors.Number("ns_stats", "mrt_monitor_roll_forward_timeout"),
                    converter=Converters.scientific_units,
                ),
            ),
        ),
    ),
    from_source=("node_ids", "node_names", "ns_stats"),
    for_each="ns_stats",
    group_by=("Namespace"),
    order_by=FieldSorter("Node"),
)

# MRT Provisionals metrics template
info_transactions_provisionals_sheet = Sheet(
    (
        namespace_field,
        node_field,
        hidden_node_id_field,
        # Provisionals Count
        Field(
            "Provisionals",
            Projectors.Number("ns_stats", "mrt_provisionals"),
            converter=Converters.scientific_units,
        ),
        # Transaction Blocking
        Field(
            "Transaction Blocked",
            Projectors.Number("ns_stats", "fail_mrt_blocked"),
            converter=Converters.scientific_units,
        ),
        Field(
            "Version Mismatch",
            Projectors.Number("ns_stats", "fail_mrt_version_mismatch"),
            converter=Converters.scientific_units,
        ),
        # Verify Read Metrics
        Subgroup(
            "Verify Read",
            (
                Field(
                    "Success",
                    Projectors.Number("ns_stats", "mrt_verify_read_success"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Error",
                    Projectors.Number("ns_stats", "mrt_verify_read_error"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Timeout",
                    Projectors.Number("ns_stats", "mrt_verify_read_timeout"),
                    converter=Converters.scientific_units,
                ),
            ),
        ),
        # Roll Back Metrics
        Subgroup(
            "Roll Back",
            (
                Field(
                    "Success",
                    Projectors.Number("ns_stats", "mrt_roll_back_success"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Error",
                    Projectors.Number("ns_stats", "mrt_roll_back_error"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Timeout",
                    Projectors.Number("ns_stats", "mrt_roll_back_timeout"),
                    converter=Converters.scientific_units,
                ),
            ),
        ),
        # Roll Forward Metrics
        Subgroup(
            "Roll Forward",
            (
                Field(
                    "Success",
                    Projectors.Number("ns_stats", "mrt_roll_forward_success"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Error",
                    Projectors.Number("ns_stats", "mrt_roll_forward_error"),
                    converter=Converters.scientific_units,
                ),
                Field(
                    "Timeout",
                    Projectors.Number("ns_stats", "mrt_roll_forward_timeout"),
                    converter=Converters.scientific_units,
                ),
            ),
        ),
    ),
    from_source=("node_ids", "node_names", "ns_stats"),
    for_each="ns_stats",
    group_by=("Namespace"),
    order_by=FieldSorter("Node"),
)
