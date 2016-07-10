# Copyright 2013-2016 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import math
from lib.logger import DT_FMT
from lib.logreader import TOTAL_ROW_HEADER, COUNT_RESULT_KEY

from lib.table import Table, Extractors, TitleFormats, Styles
import sys
from cStringIO import StringIO
import re
from lib import terminal
import time
import datetime
from cStringIO import StringIO
import sys
import itertools
from pydoc import pipepager
from lib.util import get_value_from_dict, set_value_in_dict


class CliView(object):
    NO_PAGER, LESS, MORE = range(3)
    pager = NO_PAGER

    @staticmethod
    def compileLikes(likes):
        likes = map(re.escape, likes)
        likes = "|".join(likes)
        likes = re.compile(likes)
        return likes

    @staticmethod
    def print_result(out):
        if type(out) is not str:
            out = str(out)
        if CliView.pager==CliView.LESS:
            pipepager(out, cmd='less -RSX')
        elif CliView.pager==CliView.MORE:
            pipepager(out, cmd='more -d')
        else:
             print out

    @staticmethod
    def print_pager():
        if CliView.pager==CliView.LESS:
            print "LESS"
        elif CliView.pager==CliView.MORE:
            print "MORE"
        else:
             print "NO PAGER"

    @staticmethod
    def infoNetwork(stats, versions, builds, cluster, title_suffix="", **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()
        hosts = cluster.nodes

        title = "Network Information%s"%(title_suffix)
        column_names = ('node'
                        , 'node_id'
                        , 'ip'
                        , 'build'
                        , 'cluster_size'
                        , 'cluster_key'
                        , '_cluster_integrity'
                        , ('_paxos_principal', 'Principal')
                        , ('client_connections', 'Client Conns')
                        , '_uptime')

        t = Table(title, column_names)

        t.addCellAlert('node_id'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addDataSource('_cluster_integrity'
                        , lambda data:
                        True if row['cluster_integrity'] == 'true' else False)
        t.addDataSource('_uptime', Extractors.timeExtractor('uptime'))

        t.addCellAlert('_cluster_integrity'
                       ,lambda data: data['cluster_integrity'] != 'true')

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addDataSource('Enterprise'
                        , lambda data: 'N/E' if data['version'] == 'N/E' else(
                        True if "Enterprise" in data['version'] else False))

        for node_key, n_stats in stats.iteritems():
            if isinstance(n_stats, Exception):
                n_stats = {}

            node = cluster.getNode(node_key)[0]
            row = n_stats
            row['real_node_id'] = node.node_id
            row['node'] = prefixes[node_key]
            row['ip'] = hosts[node_key].sockName(use_fqdn = False)
            row['node_id'] = node.node_id if node.node_id != principal else "*%s"%(node.node_id)
            try:
                paxos_node = cluster.getNode(row['paxos_principal'])[0]
                row['_paxos_principal'] = paxos_node.node_id
            except KeyError:
                # The principal is a node we currently do not know about
                # So return the principal ID
                try:
                    row['_paxos_principal'] = row['paxos_principal']
                except KeyError:
                    pass
            try:
                build = builds[node_key]
                if not isinstance(build, Exception):
                    try:
                        version = versions[node_key]
                        if not isinstance(version, Exception):
                            if 'enterprise' in version.lower():
                                row['build'] = "E-%s"%(str(build))
                            elif 'community' in version.lower():
                                row['build'] = "C-%s"%(str(build))
                            else:
                                row['build'] = build
                    except Exception:
                        pass
            except Exception:
                pass


            t.insertRow(row)

        CliView.print_result(t)

    @staticmethod
    def infoNamespace(stats, cluster, title_suffix="", **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Namespace Information%s"%(title_suffix)
        column_names = ('namespace'
                        , 'node'
                        , ('available_pct', 'Avail%')
                        , ('_evicted_objects', 'Evictions')
                        , ('_master_objects', 'Master Objects')
                        , ('_prole_objects', 'Replica Objects')
                        , 'repl-factor'
                        , 'stop_writes'
                        , ('_migrates', 'Pending Migrates (tx%,rx%)')
                        , ('_used_bytes_disk', 'Disk Used')
                        , ('_used_disk_pct', 'Disk Used%')
                        , ('high-water-disk-pct', 'HWM Disk%')
                        , ('_used_bytes_memory', 'Mem Used')
                        , ('_used_mem_pct', 'Mem Used%')
                        , ('high-water-memory-pct', 'HWM Mem%')
                        , ('stop-writes-pct', 'Stop Writes%'))

        t = Table(title, column_names, sort_by=0)
        t.addDataSource('_evicted_objects'
                        ,Extractors.sifExtractor(('evicted-objects','evicted_objects')))
        t.addDataSource('_used_bytes_disk'
                        ,Extractors.byteExtractor(('used-bytes-disk','device_used_bytes')))
        t.addDataSource('_used_bytes_memory'
                        ,Extractors.byteExtractor(('used-bytes-memory','memory_used_bytes')))

        t.addDataSource('_master_objects'
                        ,Extractors.sifExtractor(('master-objects','master_objects')))

        t.addDataSource('_prole_objects'
                        ,Extractors.sifExtractor(('prole-objects','prole_objects')))

        t.addDataSource('_used_disk_pct'
                        , lambda data: 100 - int(data['free_pct_disk']) if data['free_pct_disk'] is not " " else " ")

        t.addDataSource('_used_mem_pct'
                        , lambda data: 100 - int(data['free_pct_memory']) if data['free_pct_memory'] is not " " else " ")

        t.addCellAlert('available_pct'
                       , lambda data: int(data['available_pct']) <= 10 if data['available_pct'] is not " " else " ")

        t.addCellAlert('stop_writes'
                       , lambda data: data['stop_writes'] != 'false')

        t.addDataSource('_migrates'
                        , lambda data:
                        "(%s,%s)"%(data.get('migrate_tx_partitions_remaining_pct', 'N/E')
                                      , data.get('migrate_rx_partitions_remaining_pct','N/E')))

        t.addCellAlert('_used_mem_pct'
                       , lambda data: (100 - int(data['free_pct_memory'])) >= int(data['high-water-memory-pct']) if data['free_pct_memory'] is not " " else " ")

        t.addCellAlert('_used_disk_pct'
                       , lambda data: (100 - int(data['free_pct_disk'])) >= int(data['high-water-disk-pct']) if data['free_pct_disk'] is not " " else " ")

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addCellAlert('namespace'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('_master_objects'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('_prole_objects'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('_used_bytes_memory'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('_used_bytes_disk'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('_evicted_objects'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('_migrates'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)

        total_res = {}

        # Need to maintain Node column ascending order per namespace. If set sort_by in table, it will affect total rows.
        # So we need to add rows as Nodes ascending order. So need to sort stats.keys as per respective Node value (prefixes[node_key]).
        node_key_list = stats.keys()
        node_column_list = [prefixes[key] for key in node_key_list]
        sorted_node_list = [x for (y,x) in sorted(zip(node_column_list,node_key_list), key=lambda pair: pair[0])]

        for node_key in sorted_node_list:
            n_stats = stats[node_key]
            node = cluster.getNode(node_key)[0]
            if isinstance(n_stats, Exception):
                t.insertRow({'real_node_id':node.node_id
                             , 'node':prefixes[node_key]})
                continue

            for ns, ns_stats in n_stats.iteritems():

                if isinstance(ns_stats, Exception):
                    row = {}
                else:
                    row = ns_stats

                if ns not in total_res:
                    total_res[ns] = {}
                    total_res[ns]["master_objects"] = 0
                    total_res[ns]["prole_objects"] = 0
                    total_res[ns]["used-bytes-memory"] = 0
                    total_res[ns]["used-bytes-disk"] = 0
                    total_res[ns]["evicted_objects"] = 0
                    total_res[ns]["migrate_tx_partitions_remaining"] = 0
                    total_res[ns]["migrate_rx_partitions_remaining"] = 0
                    total_res[ns]["migrate_tx_partitions_initial"] = 0
                    total_res[ns]["migrate_rx_partitions_initial"] = 0
                try:
                    total_res[ns]["master_objects"] += get_value_from_dict(ns_stats,('master-objects','master_objects'),return_type=int)
                except Exception:
                    pass
                try:
                    total_res[ns]["prole_objects"] += get_value_from_dict(ns_stats,('prole-objects','prole_objects'),return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["used-bytes-memory"] += get_value_from_dict(ns_stats,('used-bytes-memory','memory_used_bytes'),return_type=int)
                except Exception:
                    pass
                try:
                    total_res[ns]["used-bytes-disk"] += get_value_from_dict(ns_stats,('used-bytes-disk','device_used_bytes'),return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["evicted_objects"] += get_value_from_dict(ns_stats,('evicted-objects','evicted_objects'),return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["migrate_tx_partitions_remaining"] += get_value_from_dict(ns_stats,('migrate-tx-partitions-remaining','migrate_tx_partitions_remaining'),return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["migrate_rx_partitions_remaining"] += get_value_from_dict(ns_stats,('migrate-rx-partitions-remaining','migrate_rx_partitions_remaining'),return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["migrate_tx_partitions_initial"] += get_value_from_dict(ns_stats,('migrate-tx-partitions-initial','migrate_tx_partitions_initial'),return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["migrate_rx_partitions_initial"] += get_value_from_dict(ns_stats,('migrate-rx-partitions-initial','migrate_rx_partitions_initial'),return_type=int)
                except Exception:
                    pass

                row['namespace'] = ns
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                set_value_in_dict(row,"available_pct",get_value_from_dict(row,('available_pct','device_available_pct')))
                set_value_in_dict(row,"free_pct_disk",get_value_from_dict(row,('free-pct-disk','device_free_pct')))
                set_value_in_dict(row,"free_pct_memory",get_value_from_dict(row,('free-pct-memory','memory_free_pct')))
                set_value_in_dict(row,"stop_writes",get_value_from_dict(row,('stop-writes','stop_writes')))
                try:
                    row["migrate_rx_partitions_remaining_pct"] = "%d"%(math.ceil((get_value_from_dict(ns_stats,('migrate-rx-partitions-remaining','migrate_rx_partitions_remaining'),return_type=float)/get_value_from_dict(ns_stats,('migrate-rx-partitions-initial','migrate_rx_partitions_initial'),return_type=float))*100))
                except Exception:
                    row["migrate_rx_partitions_remaining_pct"] = "0"
                try:
                    row["migrate_tx_partitions_remaining_pct"] = "%d"%(math.ceil((get_value_from_dict(ns_stats,('migrate-tx-partitions-remaining','migrate_tx_partitions_remaining'),return_type=float)/get_value_from_dict(ns_stats,('migrate-tx-partitions-initial','migrate_tx_partitions_initial'),return_type=float))*100))
                except Exception:
                    row["migrate_tx_partitions_remaining_pct"] = "0"
                t.insertRow(row)

        for ns in total_res:
            row = {}
            row['node'] = " "
            row['available_pct'] = " "
            row["repl-factor"] = " "
            row["stop_writes"] = " "
            row["high-water-disk-pct"] = " "
            row["free_pct_disk"] = " "
            row["free_pct_memory"] = " "
            row["high-water-memory-pct"] = " "
            row["stop-writes-pct"] = " "

            row['namespace'] = ns
            row["master_objects"] = str(total_res[ns]["master_objects"])
            row["prole_objects"] = str(total_res[ns]["prole_objects"])
            row["used-bytes-memory"] = str(total_res[ns]["used-bytes-memory"])
            row["used-bytes-disk"] = str(total_res[ns]["used-bytes-disk"])
            row["evicted_objects"] = str(total_res[ns]["evicted_objects"])
            row["migrate_tx_partitions_remaining"] = str(total_res[ns]["migrate_tx_partitions_remaining"])
            row["migrate_rx_partitions_remaining"] = str(total_res[ns]["migrate_rx_partitions_remaining"])

            try:
                row["migrate_rx_partitions_remaining_pct"] = "%d"%(math.ceil((float(total_res[ns]["migrate_rx_partitions_remaining"])/float(total_res[ns]["migrate_rx_partitions_initial"]))*100))
            except Exception:
                row["migrate_rx_partitions_remaining_pct"] = "0"
            try:
                row["migrate_tx_partitions_remaining_pct"] = "%d"%(math.ceil((float(total_res[ns]["migrate_tx_partitions_remaining"])/float(total_res[ns]["migrate_tx_partitions_initial"]))*100))
            except Exception:
                row["migrate_tx_partitions_remaining_pct"] = "0"

            t.insertRow(row)

        CliView.print_result(t)

    @staticmethod
    def infoSet(stats, cluster, title_suffix="", **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Set Information%s"%(title_suffix)
        column_names = ( 'set'
                        , 'namespace'
                        , 'node'
                        , ('_set-delete', 'Set Delete')
                        , ('_n-bytes-memory', 'Mem Used')
                        , ('_n_objects', 'Objects')
                        , 'stop-writes-count'
                        , 'disable-eviction'
                        , 'set-enable-xdr'
                        )

        t = Table(title, column_names, sort_by=1, group_by=0)
        t.addDataSource('_n-bytes-memory'
                        ,Extractors.byteExtractor(('n-bytes-memory','memory_data_bytes')))
        t.addDataSource('_n_objects'
                        ,Extractors.sifExtractor(('n_objects','objects')))

        t.addDataSource('_set-delete'
                        ,lambda data: get_value_from_dict(data,('set-delete','deleting')))

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addCellAlert('set'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('namespace'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('_n-bytes-memory'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)
        t.addCellAlert('_n_objects'
                       ,lambda data: data['node'] is " "
                       , color=terminal.fg_blue)

        total_res = {}

        # Need to maintain Node column ascending order per <set,namespace>. If set sort_by in table, it will affect total rows.
        # So we need to add rows as Nodes ascending order. So need to sort stats.keys as per respective Node value (prefixes[node_key]).
        node_key_list = stats.keys()
        node_column_list = [prefixes[key] for key in node_key_list]
        sorted_node_list = [x for (y,x) in sorted(zip(node_column_list,node_key_list), key=lambda pair: pair[0])]

        for node_key in sorted_node_list:
            s_stats = stats[node_key]
            node = cluster.getNode(node_key)[0]
            if isinstance(s_stats, Exception):
                t.insertRow({'real_node_id':node.node_id
                             , 'node':prefixes[node_key]})
                continue

            for (ns,set), set_stats in s_stats.iteritems():
                if isinstance(set_stats, Exception):
                    row = {}
                else:
                    row = set_stats

                if (ns,set) not in total_res:
                    total_res[(ns,set)] = {}
                    total_res[(ns,set)]["n-bytes-memory"] = 0
                    total_res[(ns,set)]["n_objects"] = 0
                try:
                    total_res[(ns,set)]["n-bytes-memory"] += get_value_from_dict(set_stats, ('n-bytes-memory','memory_data_bytes'), 0, int)
                except Exception:
                    pass
                try:
                    total_res[(ns,set)]["n_objects"] += get_value_from_dict(set_stats, ('n_objects','objects'), 0, int)
                except Exception:
                    pass

                row['set'] = set
                row['namespace'] = ns
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                t.insertRow(row)

        for (ns,set) in total_res:
            row = {}
            row['set'] = set
            row['namespace'] = ns
            row['node'] = " "
            row['set-delete'] = " "
            row['stop-writes-count'] = " "
            row['disable-eviction'] = " "
            row['set-enable-xdr'] = " "

            row['n-bytes-memory'] = str(total_res[(ns,set)]["n-bytes-memory"])
            row["n_objects"] = str(total_res[(ns,set)]["n_objects"])

            t.insertRow(row)

        CliView.print_result(t)

    @staticmethod
    def infoXDR(stats, builds, xdr_enable, cluster, title_suffix="", **ignore):
        if not max(xdr_enable.itervalues()):
            return

        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "XDR Information%s"%(title_suffix)
        column_names = ('node'
                        ,'build'
                        ,('_bytes-shipped', 'Data Shipped')
                        ,'_free-dlog-pct'
                        ,('_lag-secs', 'Lag (sec)')
                        ,'_req-outstanding'
                        ,'_req-shipped-success'
                        ,'_req-shipped-errors'
                        ,('_cur_throughput', 'Cur Throughput')
                        ,('_latency_avg_ship', 'Avg Latency (ms)')
                        ,'_xdr-uptime')

        t = Table(title, column_names, group_by=1)

        t.addDataSource('_xdr-uptime', Extractors.timeExtractor(
            ('xdr-uptime', 'xdr_uptime')))

        t.addDataSource('_bytes-shipped',
                        Extractors.byteExtractor(
                            ('esmt-bytes-shipped', 'esmt_bytes_shipped', 'xdr_ship_bytes')))

        t.addDataSource('_lag-secs',
                        Extractors.timeExtractor('xdr_timelag'))

        t.addDataSource('_req-outstanding',
                        Extractors.sifExtractor(('stat_recs_outstanding', 'xdr_ship_outstanding_objects')))

        t.addDataSource('_req-shipped-errors',
                        Extractors.sifExtractor('stat_recs_ship_errors'))

        t.addDataSource('_req-shipped-success',
                        Extractors.sifExtractor(('stat_recs_shipped_ok', 'xdr_ship_success')))

        t.addDataSource('_cur_throughput',
                        lambda data: get_value_from_dict(data,('cur_throughput', 'xdr_throughput')))

        t.addDataSource('_latency_avg_ship',
                        lambda data: get_value_from_dict(data,('latency_avg_ship', 'xdr_ship_latency_avg')))

        # Highlight red if lag is more than 30 seconds
        t.addCellAlert('_lag-secs'
                       , lambda data: int(data['xdr_timelag']) >= 300)

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        row = None
        for node_key, row in stats.iteritems():
            if isinstance(row, Exception):
                row = {}

            node = cluster.getNode(node_key)[0]
            if xdr_enable[node_key]:
                if row:
                    row['build'] = builds[node_key]
                    set_value_in_dict(row, '_free-dlog-pct', get_value_from_dict(row,('free_dlog_pct','free-dlog-pct','dlog_free_pct')))
                    if row['_free-dlog-pct'].endswith("%"):
                        row['_free-dlog-pct'] = row['_free-dlog-pct'][:-1]

                    set_value_in_dict(row, 'xdr_timelag', get_value_from_dict(row,('xdr_timelag','timediff_lastship_cur_secs')))
                    if not get_value_from_dict(row, ('stat_recs_shipped_ok','xdr_ship_success')):
                        set_value_in_dict(row, 'stat_recs_shipped_ok', str(int(get_value_from_dict(row,('stat_recs_shipped','stat-recs-shipped'),0))
                                              - int(get_value_from_dict(row,('err_ship_client','err-ship-client'),0))
                                              - int(get_value_from_dict(row,('err_ship_server','err-ship-server'),0))))
                    set_value_in_dict(row, 'stat_recs_ship_errors', str(int(get_value_from_dict(row,('err_ship_client','err-ship-client','xdr_ship_source_error'),0))
                                          + int(get_value_from_dict(row,('err_ship_server','err-ship-server','xdr_ship_destination_error'),0))))
                else:
                    row = {}
                    row['node-id'] = node.node_id
                row['real_node_id'] = node.node_id
            else:
                continue

            row['node'] = prefixes[node_key]

            t.insertRow(row)
        CliView.print_result(t)

    @staticmethod
    def infoDC(stats, cluster, title_suffix="", **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "DC Information%s"%(title_suffix)
        column_names = ('node'
                        ,('DC_Name','DC')
                        ,('_xdr_dc_size','DC size')
                        ,'namespaces'
                        ,('_lag-secs', 'Lag (sec)')
                        ,('_xdr_dc_remote_ship_ok', 'Records Shipped')
                        ,('_latency_avg_ship_ema', 'Avg Latency (ms)')
                        ,('_xdr-dc-state', 'Status')
                        )

        t = Table(title, column_names, group_by=1)

        t.addDataSource('_xdr_dc_size'
                        ,lambda data: get_value_from_dict(data,('xdr_dc_size','dc_size')))

        t.addDataSource('_lag-secs'
                        ,Extractors.timeExtractor(('xdr-dc-timelag','xdr_dc_timelag','dc_timelag')))

        t.addDataSource('_xdr_dc_remote_ship_ok'
                        ,lambda data: get_value_from_dict(data,('xdr_dc_remote_ship_ok','dc_remote_ship_ok','dc_recs_shipped_ok','dc_ship_success')))

        t.addDataSource('_latency_avg_ship_ema'
                        ,lambda data: get_value_from_dict(data,('latency_avg_ship_ema','dc_latency_avg_ship','dc_latency_avg_ship_ema','dc_ship_latency_avg')))

        t.addDataSource('_xdr-dc-state'
                        ,lambda data: get_value_from_dict(data,('xdr_dc_state','xdr-dc-state','dc_state')))

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        row = None
        for node_key, dc_stats in stats.iteritems():
            if isinstance(dc_stats, Exception):
                dc_stats = {}
            node = cluster.getNode(node_key)[0]
            for dc, row in dc_stats.iteritems():
                if isinstance(row, Exception):
                    row = {}
                if row:
                    row['real_node_id'] = node.node_id
                    row['node'] = prefixes[node_key]
                    t.insertRow(row)
        CliView.print_result(t)

    @staticmethod
    def infoSIndex(stats, cluster, title_suffix="", **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()
        title = "Secondary Index Information%s"%(title_suffix)
        column_names = ('node'
                        , ('indexname', 'Index Name')
                        , ('indextype', 'Index Type')
                        , ('ns', 'Namespace')
                        , 'set'
                        , ('_bins', 'Bins')
                        , ('_num_bins', 'Num Bins')
                        , ('type', 'Bin Type')
                        , 'state'
                        , 'sync_state'
                        , 'keys'
                        , 'entries'
                        , 'si_accounted_memory'
                        , ('_query_reqs','q')
                        , ('_stat_write_success','w')
                        , ('_stat_delete_success','d')
                        , ('_query_avg_rec_count', 's'))

        t = Table(title, column_names, group_by=1, sort_by=2)
        t.addDataSource('_bins'
                        ,lambda data: get_value_from_dict(data,('bins','bin')))
        t.addDataSource('_num_bins'
                        ,lambda data: get_value_from_dict(data,('num_bins'),default_value=1))
        t.addDataSource('entries'
                        ,Extractors.sifExtractor(('entries','objects')))
        t.addDataSource('_query_reqs'
                        ,Extractors.sifExtractor(('query_reqs')))
        t.addDataSource('_stat_write_success'
                        ,Extractors.sifExtractor(('stat_write_success','write_success')))
        t.addDataSource('_stat_delete_success'
                        ,Extractors.sifExtractor(('stat_delete_success','delete_success')))
        t.addDataSource('_query_avg_rec_count'
                        ,Extractors.sifExtractor(('query_avg_rec_count')))
        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)
        for stat in stats.values():
            for node_key, n_stats in stat.iteritems():
                node = cluster.getNode(node_key)[0]
                if isinstance(n_stats, Exception):
                    row = {}
                else:
                    row = n_stats
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                t.insertRow(row)

        CliView.print_result(t)

    @staticmethod
    def infoString(title, summary):
        if not summary or len(summary.strip())==0:
            return
        if title:
            print "************************** %s **************************" % (title)
        CliView.print_result(summary)

    @staticmethod
    def showDistribution(title
                         , histogram
                         , unit
                         , hist
                         , cluster
                         , like=None
                         , title_suffix="", **ignore):
        prefixes = cluster.getNodeNames()

        likes = CliView.compileLikes(like)

        columns = ["%s%%"%(n) for n in xrange(10,110, 10)]
        percentages = columns[:]
        columns.insert(0, 'node')
        description = "Percentage of records having %s less than or "%(hist) + \
                      "equal to value measured in %s"%(unit)

        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.iteritems():
            if namespace not in namespaces:
                continue

            t = Table("%s - %s in %s%s"%(namespace, title, unit, title_suffix)
                      , columns
                      , description=description)
            for node_id, data in node_data.iteritems():
                percentiles = data['percentiles']
                row = {}
                row['node'] = prefixes[node_id]
                for percent in percentages:
                    row[percent] = percentiles.pop(0)

                t.insertRow(row)

            CliView.print_result(t)

    @staticmethod
    def showObjectDistribution(title
                         , histogram
                         , unit
                         , hist
                         , show_bucket_count
                         , set_bucket_count
                         , cluster
                         , like=None
                         , title_suffix="", loganalyser_mode=False, **ignore):
        prefixes = cluster.getNodeNames()

        likes = CliView.compileLikes(like)

        description = "Number of records having %s in the range "%(hist) + \
                      "measured in %s"%(unit)

        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.iteritems():
            if namespace not in namespaces:
                continue
            columns = []
            for column in node_data["columns"]:
                columns.append((column,column))      # Tuple is required to give specific column display name, otherwise it will print same column name but in title_format (ex. KB -> Kb)
            columns.insert(0, 'node')
            t = Table("%s - %s in %s%s"%(namespace, title, unit, title_suffix)
                      , columns
                      , description=description)
            if not loganalyser_mode:
                for column in columns:
                    if column is not 'node':
                        t.addDataSource(column,Extractors.sifExtractor(column))

            for node_id, data in node_data.iteritems():
                if node_id=="columns":
                    continue

                row = data['values']
                row['node'] = prefixes[node_id]
                t.insertRow(row)

            CliView.print_result(t)
            if set_bucket_count and (len(columns)-1)<show_bucket_count:
                print "%sShowing only %s bucket%s as remaining buckets have zero objects%s\n"%(terminal.fg_green(),(len(columns)-1),"s" if (len(columns)-1)>1 else "",terminal.fg_clear())

    @staticmethod
    def showLatency(latency, cluster, machine_wise_display=False, show_ns_details=False, like=None, **ignore):
        prefixes = cluster.getNodeNames()
        if like:
            likes = CliView.compileLikes(like)
        if not machine_wise_display:
            if like:
                histograms = set(filter(likes.search, latency.keys()))
            else:
                histograms = set(latency.keys())

        for hist_or_node, data in sorted(latency.iteritems()):
            if not machine_wise_display and hist_or_node not in histograms:
                continue
            title = "%s Latency"%(hist_or_node)

            if machine_wise_display:
                if like:
                    histograms = set(filter(likes.search, data.keys()))
                else:
                    histograms = set(data.keys())
            all_columns = set()
            for node_or_hist_id, _data in data.iteritems():
                if machine_wise_display and node_or_hist_id not in histograms:
                    continue

                for ns, ns_data in _data.iteritems():
                    if "columns" not in ns_data or not ns_data["columns"]:
                        continue
                    for column in ns_data["columns"]:
                        if column[0] == '>':
                            column = int(column[1:-2])
                            all_columns.add(column)

            all_columns = [">%sms"%(c) for c in sorted(all_columns)]
            all_columns.insert(0, 'ops/sec')
            all_columns.insert(0, 'Time Span')
            if show_ns_details:
                all_columns.insert(0, 'namespace')
            if machine_wise_display:
                all_columns.insert(0, 'histogram')
            else:
                all_columns.insert(0, 'node')

            t = Table(title, all_columns)
            if show_ns_details:
                for c in all_columns:
                    t.addCellAlert(c, lambda data: data['namespace'] is " ", color=terminal.fg_blue)
            for node_or_hist_id, _data in data.iteritems():
                if machine_wise_display and node_or_hist_id not in histograms:
                    continue

                for ns,type in [i for i in sorted(_data.keys(), key=lambda x:str(x[1])+"-"+str(x[0]))]:
                    if not show_ns_details and type=="namespace":
                        continue
                    ns_data = _data[(ns,type)]

                    if "columns" not in ns_data or not ns_data["columns"]:
                        continue
                    columns = ns_data.pop("columns", None)
                    for _data_item in ns_data["values"]:
                        row = dict(itertools.izip(columns, _data_item))
                        row['namespace'] = ns
                        if machine_wise_display:
                            row['histogram'] = node_or_hist_id
                        else:
                            row['node'] = prefixes[node_or_hist_id]
                        t.insertRow(row)

            CliView.print_result(t)

    @staticmethod
    def showConfig(title, service_configs, cluster, like=None, diff=None, show_total=False, title_every_nth=0, **ignore):
        prefixes = cluster.getNodeNames()
        column_names = set()

        if diff and service_configs:
                config_sets = (set(service_configs[d].iteritems())
                               for d in service_configs if service_configs[d])
                union = set.union(*config_sets)
                # Regenerating generator expression for config_sets.
                config_sets = (set(service_configs[d].iteritems())
                               for d in service_configs if service_configs[d])
                intersection = set.intersection(*config_sets)
                column_names = dict(union - intersection).keys()
        else:
            for config in service_configs.itervalues():
                if isinstance(config, Exception):
                    continue
                column_names.update(config.keys())

        column_names = sorted(column_names)
        if like:
            likes = CliView.compileLikes(like)

            column_names = filter(likes.search, column_names)

        if len(column_names) == 0:
            return ''

        column_names.insert(0, "NODE")

        t = Table(title
                  , column_names
                  , title_format=TitleFormats.noChange
                  , style=Styles.VERTICAL)

        row = None
        if show_total:
            rowTotal = {}
        for node_id, row in service_configs.iteritems():
            if isinstance(row, Exception):
                row = {}

            row['NODE'] = prefixes[node_id]
            t.insertRow(row)

            if show_total:
                for key, val in row.iteritems():
                    if (val.isdigit()):
                        try:
                            rowTotal[key] = rowTotal[key] + int(val)
                        except Exception:
                            rowTotal[key] = int(val)
        if show_total:
            rowTotal['NODE'] = "Total"
            t.insertRow(rowTotal)

        CliView.print_result(t.__str__(horizontal_title_every_nth=title_every_nth))

    @staticmethod
    def showGrepCount(title, grep_result, title_every_nth=0, like=None, diff=None, **ignore):
        column_names = set()
        if grep_result:
            if grep_result[grep_result.keys()[0]]:
                column_names = CliView.sort_list_with_string_and_datetime(grep_result[grep_result.keys()[0]][COUNT_RESULT_KEY].keys())

        if len(column_names) == 0:
            return ''

        column_names.insert(0, "NODE")

        t = Table(title
                  , column_names
                  , title_format=TitleFormats.noChange
                  , style=Styles.VERTICAL)

        row = None
        for file in sorted(grep_result.keys()):
            if isinstance(grep_result[file], Exception):
                row1 = {}
                row2 = {}
            else:
                row1 = grep_result[file]["count_result"]
                row2 = {}
                for key in grep_result[file]["count_result"].keys():
                    row2[key] = "|"

            row1['NODE'] = file

            row2['NODE'] = "|"

            t.insertRow(row1)
            t.insertRow(row2)
        t._need_sort = False
        #print t
        CliView.print_result(t.__str__(horizontal_title_every_nth=2*title_every_nth))

    @staticmethod
    def showGrepDiff(title, grep_result, title_every_nth=0, like=None, diff=None, **ignore):
        column_names = set()

        if grep_result:
            if grep_result[grep_result.keys()[0]]:
                column_names = CliView.sort_list_with_string_and_datetime(grep_result[grep_result.keys()[0]]["value"].keys())

        if len(column_names) == 0:
            return ''

        column_names.insert(0, ".")
        column_names.insert(0, "NODE")

        t = Table(title
                  , column_names
                  , title_format=TitleFormats.noChange
                  , style=Styles.VERTICAL)

        row = None
        for file in sorted(grep_result.keys()):
            if isinstance(grep_result[file], Exception):
                row1 = {}
                row2 = {}
                row3 = {}
            else:
                row1 = grep_result[file]["value"]
                row2 = grep_result[file]["diff"]
                row3 = {}
                for key in grep_result[file]["value"].keys():
                    row3[key] = "|"

            row1['NODE'] = file
            row1['.'] = "Total"

            row2['NODE'] = "."
            row2['.'] = "Diff"

            row3['NODE'] = "|"
            row3['.'] = "|"

            t.insertRow(row1)
            t.insertRow(row2)
            t.insertRow(row3)
        t._need_sort = False
        #print t
        CliView.print_result(t.__str__(horizontal_title_every_nth=title_every_nth*3))

    @staticmethod
    def sort_list_with_string_and_datetime(keys):
        if not keys:
            return keys
        dt_list = []
        remove_list = []
        for key in keys:
            try:
                dt_list.append(datetime.datetime.strptime(key, DT_FMT))
                remove_list.append(key)
            except Exception:
                pass
        for rm_key in remove_list:
            keys.remove(rm_key)
        if keys:
            keys = sorted(keys)
        if dt_list:
            dt_list = [k.strftime(DT_FMT) for k in sorted(dt_list)]
        if keys and not dt_list:
            return keys
        if dt_list and not keys:
            return dt_list
        dt_list.extend(keys)
        return dt_list

    @staticmethod
    def showLogLatency(title, grep_result, title_every_nth=0, like=None, diff=None, **ignore):
        column_names = set()

        # print grep_result[grep_result.keys()[0]]["ops/sec"].keys()
        # print sorted(grep_result[grep_result.keys()[0]]["ops/sec"].keys())
        if grep_result:
            if grep_result[grep_result.keys()[0]]:
                column_names = CliView.sort_list_with_string_and_datetime(grep_result[grep_result.keys()[0]]["ops/sec"].keys())
        if len(column_names) == 0:
            return ''
        column_names.insert(0, ".")
        column_names.insert(0, "NODE")

        # print column_names

        t = Table(title
                  , column_names
                  , title_format=TitleFormats.noChange
                  , style=Styles.VERTICAL)

        row = None
        sub_columns_per_column = 0
        for file in sorted(grep_result.keys()):
            if isinstance(grep_result[file], Exception):
                continue
            else:
                is_first = True
                sub_columns_per_column = len(grep_result[file].keys())
                for key in sorted(grep_result[file].keys()):
                    if key=="ops/sec":
                        continue
                    row = grep_result[file][key]
                    if is_first:
                        row['NODE'] = file
                        is_first = False
                    else:
                        row['NODE'] = "."
                    row['.'] = "%% >%dms"%(key)
                    t.insertRow(row)

                row = grep_result[file]["ops/sec"]
                row['NODE'] = "."
                row['.'] = key
                t.insertRow(row)

                row = {}
                for key in grep_result[file]["ops/sec"].keys():
                    row[key] = "|"

                row['NODE'] = "|"
                row['.'] = "|"
                t.insertRow(row)
        t._need_sort = False
        #print t
        CliView.print_result(t.__str__(horizontal_title_every_nth=title_every_nth*(sub_columns_per_column+1)))

    @staticmethod
    def showStats(*args, **kwargs):
        CliView.showConfig(*args, **kwargs)

    @staticmethod
    def showHealth(*args, **kwargs):
        CliView.showConfig(*args, **kwargs)

    @staticmethod
    def asinfo(results, line_sep, cluster, **kwargs):
        like = set(kwargs['like'])
        for node_id, value in results.iteritems():
            prefix = cluster.getNodeNames()[node_id]
            node = cluster.getNode(node_id)[0]

            print "%s%s (%s) returned%s:"%(terminal.bold()
                                           , prefix
                                           , node.ip
                                           , terminal.reset())

            if isinstance(value, Exception):
                print "%s%s%s"%(terminal.fg_red()
                                , value
                                , terminal.reset())
                print "\n"
            else:
                # most info commands return a semicolon delimited list of key=value.
                # Assuming this is the case here, later we may want to try to detect
                # the format.
                value = value.split(';')
                likes = CliView.compileLikes(like)
                value = filter(likes.search, value)

                if not line_sep:
                    value = [";".join(value)]

                for line in sorted(value):
                    print line
                print

    @staticmethod
    def clusterPMap(pmap_data, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        title = "Partition Map Analysis"
        column_names = ('Node',
                        'Namespace',
                        'Primary Partitions',
                        'Secondary Partitions',
                        'Missing Partitions',
                        'Master Discrepancy Partitions',
                        'Replica Discrepancy Partitions')
        t = Table(title, column_names)
        for node_key, n_stats in pmap_data.iteritems():
            row = {}
            row['Node'] = prefixes[node_key]
            for ns, ns_stats in n_stats.iteritems():
                row['Namespace'] = ns
                row['Primary Partitions'] = ns_stats['pri_index']
                row['Secondary Partitions'] = ns_stats['sec_index']
                row['Missing Partitions'] = ns_stats['missing_part']
                row['Master Discrepancy Partitions'] = ns_stats['master_disc_part']
                row['Replica Discrepancy Partitions'] = ns_stats['replica_disc_part']
                t.insertRow(row)
        CliView.print_result(t)

    @staticmethod
    def clusterQNode(qnode_data, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        title = "QNode Map Analysis"
        column_names = ('Node',
                        'Namespace',
                        'Master QNode Without Data',
                        'Replica QNode Without Data',
                        'Replica QNode With Data',)
        t = Table(title, column_names)
        for node_key, n_stats in qnode_data.iteritems():
            row = {}
            row['Node'] = prefixes[node_key]
            for ns, ns_stats in n_stats.iteritems():
                row['Namespace'] = ns
                row['Master QNode Without Data'] = ns_stats['MQ_without_data']
                row['Replica QNode Without Data'] = ns_stats['RQ_without_data']
                row['Replica QNode With Data'] = ns_stats['RQ_data']
                t.insertRow(row)
        CliView.print_result(t)

    @staticmethod
    def dun(results, cluster, **kwargs):
        for node_id, command_result in results.iteritems():
            prefix = cluster.getNodeNames()[node_id]
            node = cluster.getNode(node_id)[0]

            print "%s%s (%s) returned%s:"%(terminal.bold()
                                           , prefix
                                           , node.ip
                                           , terminal.reset())

            if isinstance(command_result, Exception):
                print "%s%s%s"%(terminal.fg_red()
                                , command_result
                                , terminal.reset())
                print "\n"
            else:
                command, result = command_result
                print "asinfo -v '%s'"%(command)
                print result

    @staticmethod
    def group_output(output):
        i = 0;
        while i < len(output):
            group = output[i]

            if group == '\033':
                i += 1
                while i < len(output):
                    group = group + output[i]
                    if output[i] == 'm':
                        i += 1
                        break
                    i += 1
                yield group
                continue
            else:
                yield group
                i += 1

    @staticmethod
    def peekable(peeked, remaining):
        for val in remaining:
            while peeked:
                yield peeked.pop(0)
            yield val

    @staticmethod
    def watch(ctrl, line):
        diff_highlight = True
        sleep = 2.0
        num_iterations = False

        try:
            sleep = float(line[0])
            line.pop(0)
        except Exception:
            pass
        else:
            try:
                num_iterations = int(line[0])
                line.pop(0)
            except Exception:
                pass

        if "".join(line[0:2]) == "--no-diff":
            diff_highlight = False
            line.pop(0)
            line.pop(0)

        if not terminal.color_enabled:
            diff_highlight = False

        try:
            real_stdout = sys.stdout
            sys.stdout = mystdout = StringIO()
            previous = None
            count = 1
            while True:
                highlight = False
                ctrl.execute(line[:])
                output = mystdout.getvalue()
                mystdout.truncate(0)
                mystdout.seek(0)

                if previous and diff_highlight:
                    result = []
                    prev_iterator = CliView.group_output(previous)
                    next_peeked = []
                    next_iterator = CliView.group_output(output)
                    next_iterator = CliView.peekable(next_peeked, next_iterator)

                    for prev_group in prev_iterator:
                        if '\033' in prev_group:
                            # skip prev escape seq
                            continue

                        for next_group in next_iterator:
                            if '\033' in next_group:
                                # add current escape seq
                                result += next_group
                                continue
                            elif next_group == '\n':
                                if prev_group != '\n':
                                    next_peeked.append(next_group)
                                    break
                                if highlight:
                                    result += terminal.uninverse()
                                    highlight = False
                            elif prev_group == next_group:
                                if highlight:
                                    result += terminal.uninverse()
                                    highlight = False
                            else:
                                if not highlight:
                                    result += terminal.inverse()
                                    highlight = True

                            result += next_group

                            if '\n' == prev_group and '\n' != next_group:
                                continue
                            break

                    for next_group in next_iterator:
                        if next_group == ' ' or next_group == '\n':
                            if highlight:
                                result += terminal.uninverse()
                                highlight = False
                        else:
                            if not highlight:
                                result += terminal.inverse()
                                highlight = True

                        result += next_group

                    if highlight:
                        result += terminal.reset()
                        highlight = False

                    result = "".join(result)
                    previous = output
                else:
                    result = output
                    previous = output

                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime(' %Y-%m-%d %H:%M:%S')
                command = " ".join(line)
                print >> real_stdout, "[%s '%s' sleep: %ss iteration: %s"%(st
                                                                           , command
                                                                           , sleep
                                                                           , count),
                if num_iterations:
                    print >> real_stdout, " of %s"%(num_iterations),
                print >> real_stdout, "]"
                print >> real_stdout, result

                if num_iterations and num_iterations <= count:
                    break

                count += 1
                time.sleep(sleep)

        except (KeyboardInterrupt, SystemExit):
            return
        finally:
            sys.stdout = real_stdout
            print ''
