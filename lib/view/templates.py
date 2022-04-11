# Copyright 2013-2019 Aerospike, Inc.
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

import itertools
from unicodedata import numeric
from lib.view.sheet.decleration import ComplexAggregator, EntryData
from lib.live_cluster.client.node import ASINFO_RESPONSE_OK, ASInfoError
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


#
# Aggregator helpers
#


def weighted_avg(weights: list[numeric], values: list[numeric]):
    total = 0.0
    weighted_avg = 0.0

    for w, v in zip(weights, values):
        weighted_avg += w * v
        total += v

    if not total:
        return 0.0

    weighted_avg /= total
    return weighted_avg


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
                lambda edata: "*" + edata.value
                if edata.value == edata.common["principal"]
                else edata.value
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
    order_by="Node",
)


def create_usage_weighted_avg(type: str):
    def usage_weighted_avg(edatas: EntryData):
        pcts = map(lambda edata: edata.value, edatas)
        byte_values = map(lambda edata: edata.record[type]["Used"], edatas)
        return weighted_avg(pcts, byte_values)

    return usage_weighted_avg


info_namespace_usage_sheet = Sheet(
    (
        namespace_field,
        node_field,
        hidden_node_id_field,
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
        Field(
            "Expirations",
            Projectors.Number("ns_stats", "expired_objects", "expired-objects"),
            converter=Converters.scientific_units,
            aggregator=Aggregators.sum(),
        ),
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
            "Device",
            (
                Field(
                    "Used",
                    Projectors.Number(
                        "ns_stats", "device_used_bytes", "used-bytes-disk"
                    ),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Used%",
                    Projectors.PercentCompute(
                        Projectors.Number("ns_stats", "device_used_bytes"),
                        Projectors.Number("ns_stats", "device_total_bytes"),
                    ),
                    converter=Converters.round(2),
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Device"),
                        converter=Converters.round(2),
                    ),
                    formatters=(
                        Formatters.yellow_alert(
                            lambda edata: edata.value >= edata.record["Device"]["HWM%"]
                            and edata.record["Device"]["HWM%"] != 0
                        ),
                    ),
                ),
                Field("HWM%", Projectors.Number("ns_stats", "high-water-disk-pct")),
                Field(
                    "Avail%",
                    Projectors.Number(
                        "ns_stats", "device_available_pct", "available_pct"
                    ),
                    formatters=(Formatters.red_alert(lambda edata: edata.value < 10),),
                ),
            ),
        ),
        Subgroup(
            "Memory",
            (
                Field(
                    "Used",
                    Projectors.Number("ns_stats", "memory_used_bytes"),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Used%",
                    Projectors.PercentCompute(
                        Projectors.Number("ns_stats", "memory_used_bytes"),
                        Projectors.Number("ns_stats", "memory-size"),
                    ),
                    converter=Converters.round(2),
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Memory"),
                        converter=Converters.round(2),
                    ),
                    formatters=(
                        Formatters.yellow_alert(
                            lambda edata: edata.value > edata.record["Memory"]["HWM%"]
                            and edata.record["Memory"]["HWM%"] != 0
                        ),
                    ),
                ),
                Field("HWM%", Projectors.Number("ns_stats", "high-water-memory-pct")),
                Field("Stop%", Projectors.Number("ns_stats", "stop-writes-pct")),
            ),
        ),
        Subgroup(
            "Primary Index",
            (
                Field("Type", Projectors.String("ns_stats", "index-type")),
                Field(
                    "Used",
                    Projectors.Number(
                        "ns_stats", "index_flash_used_bytes", "index_pmem_used_bytes"
                    ),
                    converter=Converters.byte,
                    aggregator=Aggregators.sum(),
                ),
                Field(
                    "Used%",
                    Projectors.PercentCompute(
                        Projectors.Number(
                            "ns_stats",
                            "index_flash_used_bytes",
                            "index_pmem_used_bytes",
                        ),
                        Projectors.Number("ns_stats", "index-type.mounts-size-limit"),
                    ),
                    converter=Converters.round(2),
                    aggregator=ComplexAggregator(
                        create_usage_weighted_avg("Primary Index"),
                        converter=Converters.round(2),
                    ),
                    formatters=(
                        Formatters.yellow_alert(
                            lambda edata: edata.value
                            >= edata.record["Primary Index"]["HWM%"]
                            and edata.record["Primary Index"]["HWM%"] != 0
                        ),
                    ),
                ),
                Field(
                    "HWM%",
                    Projectors.Number("ns_stats", "index-type.mounts-high-water-pct"),
                ),
            ),
        ),
    ),
    from_source=("node_ids", "node_names", "ns_stats"),
    for_each="ns_stats",
    group_by=("Namespace"),
    order_by="Node",
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
    order_by="Node",
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
            "Mem Used",
            Projectors.Number("set_stats", "memory_data_bytes", "n-bytes-memory"),
            converter=Converters.byte,
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Disk Used",
            Projectors.Number("set_stats", "device_data_bytes"),
            converter=Converters.byte,
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Objects",
            Projectors.Number("set_stats", "objects", "n_objects"),
            converter=Converters.scientific_units,
            aggregator=Aggregators.sum(),
        ),
        Field("Stop Writes Count", Projectors.Number("set_stats", "stop-writes-count")),
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
    order_by="Node",
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
    order_by="Node",
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
    order_by="Node",
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
    order_by="Node",
)


def sindex_state_converter(edata):
    state = edata.value

    if state == "WO":
        return "Write-Only"

    if state == "RW":
        return "Read-Only"

    return state


info_sindex_sheet = Sheet(
    (
        Field("Index Name", Projectors.String("sindex_stats", "indexname")),
        Field("Namespace", Projectors.String("sindex_stats", "ns")),
        Field("Set", Projectors.String("sindex_stats", "set")),
        node_field,
        hidden_node_id_field,
        Field("Bins", Projectors.String("sindex_stats", "bins", "bin")),
        Field("Num Bins", Projectors.Number("sindex_stats", "num_bins")),
        Field("Bin Type", Projectors.String("sindex_stats", "type")),
        Field(
            "State",
            Projectors.String("sindex_stats", "state"),
            converter=sindex_state_converter,
        ),  # new
        Field("Sync State", Projectors.String("sindex_stats", "sync_state")),  # old
        # removed 6.0
        Field("Keys", Projectors.Number("sindex_stats", "keys")),
        Field(
            "Entries",
            Projectors.Number("sindex_stats", "entries", "objects"),
            converter=Converters.scientific_units,
            aggregator=Aggregators.sum(),
        ),
        Field(
            "Memory Used",
            # removed in 6.0
            Projectors.Any(
                FieldType.number,
                Projectors.Number("sindex_stats", "memory_used"),
                Projectors.Sum(
                    Projectors.Number("sindex_stats", "ibtr_memory_used"),
                    Projectors.Number("sindex_stats", "nbtr_memory_used"),
                ),
            ),
            converter=Converters.byte,
            aggregator=Aggregators.sum(),
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
    from_source=("node_ids", "node_names", "sindex_stats"),
    for_each="sindex_stats",
    group_by=("Namespace", "Set"),
    order_by=("Index Name", "Node"),
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
    order_by="Node",
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
                Field("Total", Projectors.Number("ns_stats", "drives_total")),
                Field("Per-Node", Projectors.Number("ns_stats", "drives_per_node")),
            ),
        ),
        Subgroup(
            "Memory",
            (
                Field(
                    "Total",
                    Projectors.Number("ns_stats", "memory_total"),
                    converter=Converters.byte,
                ),
                Field(
                    "Used%",
                    Projectors.Float("ns_stats", "memory_used_pct"),
                    converter=Converters.round(2),
                ),
                Field(
                    "Avail%",
                    Projectors.Float("ns_stats", "memory_avail_pct"),
                    converter=Converters.round(2),
                ),
            ),
        ),
        Subgroup(
            "Pmem Index",
            (
                Field(
                    "Total",
                    Projectors.Number("ns_stats", "pmem_index_total"),
                    converter=Converters.byte,
                ),
                Field(
                    "Used%",
                    Projectors.Float("ns_stats", "pmem_index_used_pct"),
                    converter=Converters.round(2),
                ),
                Field(
                    "Avail%",
                    Projectors.Float("ns_stats", "pmem_index_avail_pct"),
                    converter=Converters.round(2),
                ),
            ),
        ),
        Subgroup(
            "Flash Index",
            (
                Field(
                    "Total",
                    Projectors.Number("ns_stats", "flash_index_total"),
                    converter=Converters.byte,
                ),
                Field(
                    "Used%",
                    Projectors.Float("ns_stats", "flash_index_used_pct"),
                    converter=Converters.round(2),
                ),
                Field(
                    "Avail%",
                    Projectors.Float("ns_stats", "flash_index_avail_pct"),
                    converter=Converters.round(2),
                ),
            ),
        ),
        Subgroup(
            "Device",
            (
                Field(
                    "Total",
                    Projectors.Number("ns_stats", "device_total"),
                    converter=Converters.byte,
                ),
                Field(
                    "Used%",
                    Projectors.Float("ns_stats", "device_used_pct"),
                    converter=Converters.round(2),
                ),
                Field(
                    "Avail%",
                    Projectors.Float("ns_stats", "device_avail_pct"),
                    converter=Converters.round(2),
                ),
            ),
        ),
        Subgroup(
            "Pmem",
            (
                Field(
                    "Total",
                    Projectors.Number("ns_stats", "pmem_total"),
                    converter=Converters.byte,
                ),
                Field(
                    "Used%",
                    Projectors.Float("ns_stats", "pmem_used_pct"),
                    converter=Converters.round(2),
                ),
                Field(
                    "Avail%",
                    Projectors.Float("ns_stats", "pmem_avail_pct"),
                    converter=Converters.round(2),
                ),
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
        Field("Cache Read%", Projectors.Percent("ns_stats", "cache_read_pct")),
        Field(
            "Master Objects",
            Projectors.Number("ns_stats", "master_objects"),
            Converters.scientific_units,
        ),
        Field("Compression Ratio", Projectors.Float("ns_stats", "compression_ratio")),
    ),
    from_source="ns_stats",
    for_each="ns_stats",
    group_by="Namespace",
    order_by="Namespace",
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
    order_by="Node",
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
    order_by="Node",
    default_style=SheetStyle.rows,
)

show_config_xdr_ns_sheet = Sheet(
    (
        node_field,
        hidden_node_id_field,
        Field("Namespace", Projectors.String("data", None, for_each_key=True)),
        DynamicFields("data", required=True, order=DynamicFieldOrder.source),
    ),
    from_source=("node_names", "data", "node_ids"),
    group_by=["Namespace"],
    order_by=["Namespace", "Node"],
    default_style=SheetStyle.rows,
    for_each=["data"],
)

show_mapping_to_ip_sheet = Sheet(
    (
        Field("Node ID", Projectors.String("mapping", 0)),
        Field("IP", Projectors.String("mapping", 1)),
    ),
    from_source="mapping",
    order_by="Node ID",
)

show_mapping_to_id_sheet = Sheet(
    (
        Field("IP", Projectors.String("mapping", 0)),
        Field("Node ID", Projectors.String("mapping", 1)),
    ),
    from_source="mapping",
    order_by="IP",
)

show_object_distribution_sheet = Sheet(
    (
        TitleField("Node", Projectors.String("node_names", None)),
        DynamicFields("histogram", required=True, order=DynamicFieldOrder.source),
    ),
    from_source=("node_names", "histogram"),
    order_by="Node",
)


def latency_weighted_avg(edatas: EntryData):
    pcts = map(lambda edata: edata.value, edatas)
    ops_sec_values = map(lambda edata: edata.record["ops/sec"], edatas)
    return weighted_avg(pcts, ops_sec_values)


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
    order_by="Node",
)


def turn_empty_to_none(ls):
    if not ls:
        return None

    return ls


def extract_value_from_dict(key):
    def extract_value(dict):
        if key not in dict:
            return None

        return dict[key]

    return extract_value


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
        Field(
            "Connections",
            Projectors.String("data", "connections"),
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
                Field(
                    "Single Record TPS",
                    Projectors.Func(
                        FieldType.undefined,
                        extract_value_from_dict("single-record-tps"),
                        Projectors.Identity("data", "read-info"),
                    ),
                ),
                # TODO: Support for Subgroups to have Subgroups to have Scan/Query be a
                # subgroup of Write
                Field(
                    "Scan/Query Limited RPS",
                    Projectors.Func(
                        FieldType.undefined,
                        extract_value_from_dict("scan-query-rps-limited"),
                        Projectors.Identity("data", "read-info"),
                    ),
                ),
                Field(
                    "Scan/Query Limitless",
                    Projectors.Func(
                        FieldType.undefined,
                        extract_value_from_dict("scan-query-limitless"),
                        Projectors.Identity("data", "read-info"),
                    ),
                ),
                #     ),
                # ),
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
                Field(
                    "Single Record TPS",
                    Projectors.Func(
                        FieldType.undefined,
                        extract_value_from_dict("single-record-tps"),
                        Projectors.Identity("data", "write-info"),
                    ),
                ),
                # TODO: Support for Subgroups to have Subgroups to have Scan/Query be a
                # subgroup of Write
                Field(
                    "Scan/Query Limited RPS",
                    Projectors.Func(
                        FieldType.undefined,
                        extract_value_from_dict("scan-query-rps-limited"),
                        Projectors.Identity("data", "write-info"),
                    ),
                ),
                Field(
                    "Scan/Query Limitless",
                    Projectors.Func(
                        FieldType.undefined,
                        extract_value_from_dict("scan-query-limitless"),
                        Projectors.Identity("data", "write-info"),
                    ),
                ),
            ),
        ),
    ),
    from_source="data",
    for_each="data",
    order_by="User",
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
    order_by="Role",
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
    order_by="Filename",
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
    ),
    from_source=("data"),
    group_by=("Namespace", "Set"),
    order_by=("Index Name", "Namespace", "Set"),
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
                lambda edata: "*" + edata.value
                if edata.value == edata.common["principal"]
                else edata.value
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
    order_by=("Node ID", "Namespace"),
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
        Field("Namespace", Projectors.Percent("data", "ns")),
        Field("Module", Projectors.String("data", "module")),
        Field("Type", Projectors.String("data", "job-type")),
        Field(
            "Progress %",
            Projectors.Float("data", "job-progress"),
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
    order_by=("Progress %", "Time Since Done"),
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
    order_by=("Rack ID"),
)

kill_jobs = Sheet(
    (
        hidden_node_id_field,
        node_field,
        Field("Transaction ID", Projectors.Number("data", "trid")),
        Field("Namespace", Projectors.Percent("data", "ns")),
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
    order_by="Node",
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
    order_by="Node",
    default_style=SheetStyle.rows,
)

node_info_responses = Sheet(
    (
        node_field,
        Field(
            "Response",
            Projectors.Exception("data", None, filter_exc=[ASInfoError]),
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
    order_by="Node",
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
