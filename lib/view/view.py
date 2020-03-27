# Copyright 2013-2018 Aerospike, Inc.
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

import datetime
import itertools
import locale
import sys
import time
import types
from cStringIO import StringIO
from pydoc import pipepager

from lib.health.constants import (AssertLevel, AssertResultKey,
                                  HealthResultCounter, HealthResultType)
from lib.health.util import print_dict
from lib.utils import filesize
from lib.utils.constants import COUNT_RESULT_KEY, DT_FMT
from lib.utils.util import (compile_likes, find_delimiter_in,
                            get_value_from_dict, set_value_in_dict)
from lib.view import terminal
from lib.view.table import Extractors, Styles, Table, TitleFormats

H1_offset = 13
H2_offset = 15
H_width = 80


class CliView(object):
    NO_PAGER, LESS, MORE, SCROLL = range(4)
    pager = NO_PAGER

    @staticmethod
    def print_result(out):
        if type(out) is not str:
            out = str(out)
        if CliView.pager == CliView.LESS:
            pipepager(out, cmd='less -RSX')
        elif CliView.pager == CliView.SCROLL:
            for i in out.split('\n'):
                print i
                time.sleep(.05)
        else:
            print out

    @staticmethod
    def print_pager():
        if CliView.pager == CliView.LESS:
            print "LESS"
        elif CliView.pager == CliView.MORE:
            print "MORE"
        elif CliView.pager == CliView.SCROLL:
            print "SCROLL"
        else:
            print "NO PAGER"

    @staticmethod
    def _get_timestamp_suffix(timestamp):
        if not timestamp:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        return " (%s)"%(str(timestamp))

    @staticmethod
    def info_network(stats, cluster_names, versions, builds, cluster, timestamp="", **ignore):
        prefixes = cluster.get_node_names()
        principal = cluster.get_expected_principal()
        hosts = cluster.nodes

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Network Information%s" % (title_suffix)
        column_names = (
            ('cluster-name', 'Cluster Name'), 'node', 'node_id', 'ip', 'build',
            'cluster_size', ('_migrations', 'Migrations'), 'cluster_key',
            '_cluster_integrity', ('_paxos_principal', 'Principal'),
            'rackaware_mode', ('client_connections', 'Client Conns'), '_uptime'
        )

        t = Table(title, column_names, group_by=0, sort_by=1)

        t.add_data_source('Enterprise', lambda data: 'N/E' if data['version'] == 'N/E' else(
            True if "Enterprise" in data['version'] else False))
        t.add_data_source('_cluster_integrity', lambda data:
                          True if row['cluster_integrity'] == 'true' else False)
        t.add_data_source('_migrations',
                          Extractors.sif_extractor('migrate_partitions_remaining'))
        t.add_data_source('_uptime', Extractors.time_extractor('uptime'))

        t.add_cell_alert('node_id', lambda data: data[
                         'real_node_id'] == principal, color=terminal.fg_green)
        t.add_cell_alert(
            'node', lambda data: data['real_node_id'] == principal, color=terminal.fg_green)
        t.add_cell_alert(
            '_cluster_integrity', lambda data: data['cluster_integrity'] != 'true')

        for node_key, n_stats in stats.iteritems():
            if isinstance(n_stats, Exception):
                n_stats = {}

            node = cluster.get_node(node_key)[0]
            row = n_stats
            row['real_node_id'] = node.node_id
            row['node'] = prefixes[node_key]
            row['ip'] = hosts[node_key].sock_name(use_fqdn=False)
            row['node_id'] = node.node_id if node.node_id != principal else "*%s" % (
                node.node_id)

            try:
                paxos_node = cluster.get_node(row['paxos_principal'])[0]
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
                                row['build'] = "E-%s" % (str(build))
                            elif 'community' in version.lower():
                                row['build'] = "C-%s" % (str(build))
                            else:
                                row['build'] = build
                    except Exception:
                        pass
            except Exception:
                pass

            try:
                cluster_name = cluster_names[node_key]
                if not isinstance(cluster_name, Exception) and cluster_name not in ["null"]:
                    row["cluster-name"] = cluster_name
            except Exception:
                pass

            t.insert_row(row)

        CliView.print_result(t)

    @staticmethod
    def info_namespace_usage(stats, cluster, timestamp="", **ignore):
        prefixes = cluster.get_node_names()
        principal = cluster.get_expected_principal()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Namespace Usage Information%s" % (title_suffix)
        column_names = (
            'namespace', 'node',
            ('_total_records', 'Total Records'),
            ('_expired_and_evicted', 'Expirations,Evictions'), 'stop_writes',
            ('_used_bytes_disk', 'Disk Used'), ('_used_disk_pct', 'Disk Used%'),
            ('high-water-disk-pct', 'HWM Disk%'), ('available_pct', 'Avail%'),
            ('_used_bytes_memory', 'Mem Used'), ('_used_mem_pct', 'Mem Used%'),
            ('high-water-memory-pct', 'HWM Mem%'),
            ('stop-writes-pct', 'Stop Writes%'),
            ('_index_type', 'PI Type'),
            ('_index_used_bytes', 'PI Used'),
            ('index_used_pct', 'PI Used%'), ('index-type.mounts-high-water-pct', 'PI HWM%'),
        )

        t = Table(title, column_names, sort_by=0)

        t.add_data_source('_total_records', Extractors.sif_extractor(
            ('_total_records')))
        t.add_data_source_tuple(
            '_expired_and_evicted',
            Extractors.sif_extractor(('expired-objects', 'expired_objects')),
            Extractors.sif_extractor(('evicted-objects', 'evicted_objects')))
        t.add_data_source('_used_bytes_disk', Extractors.byte_extractor(
            ('used-bytes-disk', 'device_used_bytes')))
        t.add_data_source('_used_bytes_memory', Extractors.byte_extractor(
            ('used-bytes-memory', 'memory_used_bytes')))

        t.add_data_source('_index_type',
            lambda data: get_value_from_dict( data, ('index-type'), default_value="shmem"))
        t.add_data_source('_index_used_bytes',
            Extractors.byte_extractor(('index_used_bytes')))

        t.add_data_source('_used_disk_pct', lambda data: 100 -
                          int(data['free_pct_disk']) if data['free_pct_disk'] is not " " else " ")

        t.add_data_source('_used_mem_pct', lambda data: 100 - int(
            data['free_pct_memory']) if data['free_pct_memory'] is not " " else " ")

        t.add_cell_alert('available_pct', lambda data: data['available_pct'] != " " and int(data['available_pct']) <= 10)

        t.add_cell_alert('stop_writes', lambda data: data['stop_writes'] != " " and data['stop_writes'] != 'false')

        t.add_cell_alert('_used_mem_pct', lambda data: data['free_pct_memory'] != " " and (100 - int(data['free_pct_memory'])) >= int(data['high-water-memory-pct']))

        t.add_cell_alert('_used_disk_pct', lambda data: data['free_pct_disk'] != " " and (100 - int(data['free_pct_disk'])) >= int(data['high-water-disk-pct']))

        t.add_cell_alert(
            'node', lambda data: data['real_node_id'] == principal, color=terminal.fg_green)

        t.add_cell_alert(
            'namespace', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_total_records', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_used_bytes_memory', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_used_bytes_disk', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_expired_and_evicted', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert('_index_used_bytes', lambda data: data['node'] is " ", color=terminal.fg_blue)

        total_res = {}

        # Need to maintain Node column ascending order per namespace.
        # If set sort_by in table, it will affect total rows. TODO: implement group_by
        # So we need to add rows as Nodes ascending order. So need to sort
        # stats.keys as per respective Node value (prefixes[node_key]).
        node_key_list = stats.keys()
        node_column_list = [prefixes[key] for key in node_key_list]
        sorted_node_list = [x for (y, x) in sorted(
            zip(node_column_list, node_key_list), key=lambda pair: pair[0])]

        for node_key in sorted_node_list:
            n_stats = stats[node_key]
            node = cluster.get_node(node_key)[0]
            if isinstance(n_stats, Exception):
                t.insert_row(
                    {'real_node_id': node.node_id, 'node': prefixes[node_key]})
                continue

            for ns, ns_stats in n_stats.iteritems():

                if isinstance(ns_stats, Exception):
                    row = {}
                else:
                    row = ns_stats

                _total_records = 0

                if ns not in total_res:
                    total_res[ns] = {}
                    total_res[ns]["_total_records"] = 0
                    total_res[ns]["used-bytes-memory"] = 0
                    total_res[ns]["used-bytes-disk"] = 0
                    total_res[ns]["evicted_objects"] = 0
                    total_res[ns]["expired_objects"] = 0
                    total_res[ns]["index_used_bytes"] = 0

                try:
                    _total_records += get_value_from_dict(
                        ns_stats, ('master-objects', 'master_objects'),
                        default_value=0, return_type=int)
                except Exception:
                    pass
                try:
                    _total_records += get_value_from_dict(
                        ns_stats, ('master_tombstones'), default_value=0, return_type=int)
                except Exception:
                    pass

                try:
                    _total_records += get_value_from_dict(
                        ns_stats, ('prole-objects', 'prole_objects'), default_value=0,
                        return_type=int)
                except Exception:
                    pass
                try:
                    _total_records += get_value_from_dict(
                        ns_stats, ('prole_tombstones'), default_value=0, return_type=int)
                except Exception:
                    pass

                try:
                    _total_records += get_value_from_dict(
                        ns_stats, ('non-replica-objects', 'non_replica_objects'),
                        default_value=0, return_type=int)
                except Exception:
                    pass
                try:
                    _total_records += get_value_from_dict(
                        ns_stats, ('non_replica_tombstones'), default_value=0, return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["used-bytes-memory"] += get_value_from_dict(
                        ns_stats, ('used-bytes-memory', 'memory_used_bytes'), return_type=int)
                except Exception:
                    pass
                try:
                    total_res[ns]["used-bytes-disk"] += get_value_from_dict(
                        ns_stats, ('used-bytes-disk', 'device_used_bytes'), return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["evicted_objects"] += get_value_from_dict(
                        ns_stats, ('evicted-objects', 'evicted_objects'), return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["expired_objects"] += get_value_from_dict(
                        ns_stats, ('expired-objects', 'expired_objects'), return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["index_used_bytes"] += get_value_from_dict(
                        ns_stats, ('index_flash_used_bytes', 'index_pmem_used_bytes'), default_value=0, return_type=int)
                except Exception:
                    pass

                row['namespace'] = ns
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                set_value_in_dict(row, "available_pct", get_value_from_dict(row, ('available_pct', 'device_available_pct')))
                set_value_in_dict(row, "free_pct_disk", get_value_from_dict(row, ('free-pct-disk', 'device_free_pct')))
                set_value_in_dict(row, "free_pct_memory", get_value_from_dict(row, ('free-pct-memory', 'memory_free_pct')))
                set_value_in_dict(row, "stop_writes", get_value_from_dict(row, ('stop-writes', 'stop_writes')))
                set_value_in_dict(row, "_total_records", _total_records)

                total_res[ns]["_total_records"] += _total_records

                set_value_in_dict(row, "index-type", get_value_from_dict(row, ('index-type'), default_value="shmem"))
                set_value_in_dict(row, "index_used_bytes", get_value_from_dict(row, ('index_flash_used_bytes', 'index_pmem_used_bytes', 'memory_used_index_bytes'), default_value=0))

                if row['index-type'] != "shmem":
                    set_value_in_dict(row, "index_used_pct", get_value_from_dict(row, ('index_flash_used_pct', 'index_pmem_used_pct'), default_value=0))

                t.insert_row(row)

        for ns in total_res:
            row = {}
            row['node'] = " "
            row['available_pct'] = " "
            row["stop_writes"] = " "
            row["high-water-disk-pct"] = " "
            row["free_pct_disk"] = " "
            row["free_pct_memory"] = " "
            row["high-water-memory-pct"] = " "
            row["stop-writes-pct"] = " "
            row["index-type"] = " "
            row["index_used_pct"] = " "
            row["index-type.mounts-high-water-pct"] = " "

            row['namespace'] = ns
            row["_total_records"] = str(total_res[ns]["_total_records"])
            row["used-bytes-memory"] = str(total_res[ns]["used-bytes-memory"])
            row["used-bytes-disk"] = str(total_res[ns]["used-bytes-disk"])
            row["evicted_objects"] = str(total_res[ns]["evicted_objects"])
            row["expired_objects"] = str(total_res[ns]["expired_objects"])
            row["index_used_bytes"] = str(total_res[ns]["index_used_bytes"])

            t.insert_row(row)

        CliView.print_result(t)

    @staticmethod
    def info_namespace_object(stats, cluster, timestamp="", **ignore):
        prefixes = cluster.get_node_names()
        principal = cluster.get_expected_principal()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Namespace Object Information%s" % (title_suffix)
        column_names = (
            'namespace', 'node',
            ('_total_records', 'Total Records'),
            ('_repl_factor', "Repl Factor"),
            ('_objects', 'Objects (Master,Prole,Non-Replica)'),
            ('_tombstones', 'Tombstones (Master,Prole,Non-Replica)'),
            ('_migrates', 'Pending Migrates (tx,rx)'), ('rack-id', 'Rack ID')
        )

        t = Table(title, column_names, sort_by=0)

        t.add_data_source(
            '_total_records',
            Extractors.sif_extractor('_total_records'))

        t.add_data_source(
            '_repl_factor',
            lambda data: get_value_from_dict(
                data, ('effective_replication_factor',  # introduced post 3.15.0.1
                       'repl-factor',
                       'replication-factor')
            ))

        t.add_data_source_tuple(
            '_objects',
            Extractors.sif_extractor(('master-objects', 'master_objects')),
            Extractors.sif_extractor(('prole-objects', 'prole_objects')),
            Extractors.sif_extractor(('non_replica_objects'))
        )

        t.add_data_source_tuple(
            '_tombstones',
            Extractors.sif_extractor(('master_tombstones')),
            Extractors.sif_extractor(('prole_tombstones')),
            Extractors.sif_extractor(('non_replica_tombstones'))
        )

        t.add_data_source_tuple(
            '_migrates',
            Extractors.sif_extractor(('migrate_tx_partitions_remaining',
                                      'migrate-tx-partitions-remaining')),
            Extractors.sif_extractor(('migrate_rx_partitions_remaining',
                                      'migrate-rx-partitions-remaining')))

        t.add_cell_alert(
            'node', lambda data: data['real_node_id'] == principal, color=terminal.fg_green)

        t.add_cell_alert(
            'namespace', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_total_records', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_objects', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_tombstones', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_migrates', lambda data: data['node'] is " ", color=terminal.fg_blue)

        total_res = {}

        # Need to maintain Node column ascending order per namespace.
        # If set sort_by in table, it will affect total rows.
        # So we need to add rows as Nodes ascending order. So need to sort
        # stats.keys as per respective Node value (prefixes[node_key]).
        node_key_list = stats.keys()
        node_column_list = [prefixes[key] for key in node_key_list]
        sorted_node_list = [x for (y, x) in sorted(
            zip(node_column_list, node_key_list), key=lambda pair: pair[0])]

        rack_id_available = False

        for node_key in sorted_node_list:
            n_stats = stats[node_key]
            node = cluster.get_node(node_key)[0]
            if isinstance(n_stats, Exception):
                t.insert_row(
                    {'real_node_id': node.node_id, 'node': prefixes[node_key]})
                continue

            for ns, ns_stats in n_stats.iteritems():
                if isinstance(ns_stats, Exception):
                    row = {}
                else:
                    row = ns_stats
                    ns_stats['_total_records'] = 0

                if ns not in total_res:
                    total_res[ns] = {}
                    total_res[ns]["_total_records"] = 0
                    total_res[ns]["master_objects"] = 0
                    total_res[ns]["master_tombstones"] = 0
                    total_res[ns]["prole_objects"] = 0
                    total_res[ns]["prole_tombstones"] = 0
                    total_res[ns]["non_replica_objects"] = 0
                    total_res[ns]["non_replica_tombstones"] = 0
                    total_res[ns]["migrate_tx_partitions_remaining"] = 0
                    total_res[ns]["migrate_rx_partitions_remaining"] = 0

                if "rack-id" in row:
                    rack_id_available = True

                try:
                    value = get_value_from_dict(
                        ns_stats, ('master-objects', 'master_objects'), return_type=int)
                    total_res[ns]["master_objects"] += value
                    ns_stats['_total_records'] += value
                except Exception:
                    pass

                try:
                    value = get_value_from_dict(ns_stats, ('master_tombstones'), return_type=int)
                    total_res[ns]["master_tombstones"] += value
                    ns_stats['_total_records'] += value
                except Exception:
                    pass

                try:
                    value = get_value_from_dict(
                        ns_stats, ('prole-objects', 'prole_objects'), return_type=int)
                    total_res[ns]["prole_objects"] += value
                    ns_stats['_total_records'] += value
                except Exception:
                    pass

                try:
                    value = get_value_from_dict(ns_stats, ('prole_tombstones'), return_type=int)
                    total_res[ns]["prole_tombstones"] += value
                    ns_stats['_total_records'] += value
                except Exception:
                    pass

                try:
                    value = get_value_from_dict(
                        ns_stats, ('non_replica_objects'), return_type=int)
                    total_res[ns]["non_replica_objects"] += value
                    ns_stats['_total_records'] += value
                except Exception:
                    pass

                try:
                    value = get_value_from_dict(ns_stats, ('non_replica_tombstones'), return_type=int)
                    total_res[ns]["non_replica_tombstones"] += value
                    ns_stats['_total_records'] += value
                except Exception:
                    pass

                try:
                    total_res[ns]["migrate_tx_partitions_remaining"] += get_value_from_dict(
                        ns_stats, ('migrate-tx-partitions-remaining',
                                   'migrate_tx_partitions_remaining'), return_type=int)
                except Exception:
                    pass

                try:
                    total_res[ns]["migrate_rx_partitions_remaining"] += get_value_from_dict(
                        ns_stats, ('migrate-rx-partitions-remaining',
                                   'migrate_rx_partitions_remaining'), return_type=int)
                except Exception:
                    pass

                if not isinstance(ns_stats, Exception):
                    total_res[ns]['_total_records'] += ns_stats['_total_records']

                row['namespace'] = ns
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                t.insert_row(row)

        for ns in total_res:
            row = {}
            row['node'] = " "

            row['namespace'] = ns
            row["_total_records"] = str(total_res[ns]["_total_records"])
            row["repl-factor"] = " "
            row["master_objects"] = str(total_res[ns]["master_objects"])
            row["master_tombstones"] = str(total_res[ns]["master_tombstones"])
            row["prole_objects"] = str(total_res[ns]["prole_objects"])
            row["prole_tombstones"] = str(total_res[ns]["prole_tombstones"])
            row["non_replica_objects"] = str(total_res[ns]["non_replica_objects"])
            row["non_replica_tombstones"] = str(total_res[ns]["non_replica_tombstones"])
            row["migrate_tx_partitions_remaining"] = str(
                total_res[ns]["migrate_tx_partitions_remaining"])
            row["migrate_rx_partitions_remaining"] = str(
                total_res[ns]["migrate_rx_partitions_remaining"])

            if rack_id_available:
                row["rack-id"] = " "

            t.insert_row(row)

        CliView.print_result(t)

    @staticmethod
    def info_set(stats, cluster, timestamp="", **ignore):
        prefixes = cluster.get_node_names()
        principal = cluster.get_expected_principal()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Set Information%s" % (title_suffix)
        column_names = ('set', 'namespace', 'node', ('_set-delete', 'Set Delete'), ('_n-bytes-memory', 'Mem Used'), ('_n_objects', 'Objects'), 'stop-writes-count', 'disable-eviction', 'set-enable-xdr'
                        )

        t = Table(title, column_names, sort_by=1, group_by=0)
        t.add_data_source(
            '_n-bytes-memory', Extractors.byte_extractor(('n-bytes-memory', 'memory_data_bytes')))
        t.add_data_source(
            '_n_objects', Extractors.sif_extractor(('n_objects', 'objects')))

        t.add_data_source(
            '_set-delete', lambda data: get_value_from_dict(data, ('set-delete', 'deleting')))

        t.add_cell_alert(
            'node', lambda data: data['real_node_id'] == principal, color=terminal.fg_green)

        t.add_cell_alert(
            'set', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            'namespace', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_n-bytes-memory', lambda data: data['node'] is " ", color=terminal.fg_blue)
        t.add_cell_alert(
            '_n_objects', lambda data: data['node'] is " ", color=terminal.fg_blue)

        total_res = {}

        # Need to maintain Node column ascending order per <set,namespace>. If set sort_by in table, it will affect total rows.
        # So we need to add rows as Nodes ascending order. So need to sort
        # stats.keys as per respective Node value (prefixes[node_key]).
        node_key_list = stats.keys()
        node_column_list = [prefixes[key] for key in node_key_list]
        sorted_node_list = [x for (y, x) in sorted(
            zip(node_column_list, node_key_list), key=lambda pair: pair[0])]

        for node_key in sorted_node_list:
            s_stats = stats[node_key]
            node = cluster.get_node(node_key)[0]
            if isinstance(s_stats, Exception):
                t.insert_row(
                    {'real_node_id': node.node_id, 'node': prefixes[node_key]})
                continue

            for (ns, set), set_stats in s_stats.iteritems():
                if isinstance(set_stats, Exception):
                    row = {}
                else:
                    row = set_stats

                if (ns, set) not in total_res:
                    total_res[(ns, set)] = {}
                    total_res[(ns, set)]["n-bytes-memory"] = 0
                    total_res[(ns, set)]["n_objects"] = 0
                try:
                    total_res[(ns, set)]["n-bytes-memory"] += get_value_from_dict(
                        set_stats, ('n-bytes-memory', 'memory_data_bytes'), 0, int)
                except Exception:
                    pass
                try:
                    total_res[(ns, set)][
                        "n_objects"] += get_value_from_dict(set_stats, ('n_objects', 'objects'), 0, int)
                except Exception:
                    pass

                row['set'] = set
                row['namespace'] = ns
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                t.insert_row(row)

        for (ns, set) in total_res:
            row = {}
            row['set'] = set
            row['namespace'] = ns
            row['node'] = " "
            row['set-delete'] = " "
            row['stop-writes-count'] = " "
            row['disable-eviction'] = " "
            row['set-enable-xdr'] = " "

            row['n-bytes-memory'] = str(total_res[(ns, set)]["n-bytes-memory"])
            row["n_objects"] = str(total_res[(ns, set)]["n_objects"])

            t.insert_row(row)

        CliView.print_result(t)

    @staticmethod
    def info_dc(stats, cluster, timestamp="", **ignore):
        prefixes = cluster.get_node_names()
        principal = cluster.get_expected_principal()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "DC Information%s" % (title_suffix)
        column_names = ('node', ('_dc-name', 'DC'), ('dc-type', 'DC type'), ('_xdr_dc_size', 'DC size'),
                        'namespaces',('_lag-secs', 'Lag (sec)'), ('_xdr_dc_remote_ship_ok', 'Records Shipped'),
                        ('_latency_avg_ship_ema', 'Avg Latency (ms)'), ('_xdr-dc-state', 'Status')
                        )

        t = Table(title, column_names, group_by=1)

        t.add_data_source(
            '_dc-name', lambda data: get_value_from_dict(data, ('dc-name', 'DC_Name')))

        t.add_data_source('_xdr_dc_size', lambda data: get_value_from_dict(
            data, ('xdr_dc_size', 'dc_size', 'dc_as_size', 'dc_http_good_locations')))

        t.add_data_source(
            '_lag-secs', Extractors.time_extractor(('xdr-dc-timelag', 'xdr_dc_timelag', 'dc_timelag')))

        t.add_data_source('_xdr_dc_remote_ship_ok', lambda data: get_value_from_dict(
            data, ('xdr_dc_remote_ship_ok', 'dc_remote_ship_ok', 'dc_recs_shipped_ok', 'dc_ship_success')))

        t.add_data_source('_latency_avg_ship_ema', lambda data: get_value_from_dict(
            data, ('latency_avg_ship_ema', 'dc_latency_avg_ship', 'dc_latency_avg_ship_ema', 'dc_ship_latency_avg')))

        t.add_data_source('_xdr-dc-state', lambda data:
                          get_value_from_dict(data, ('xdr_dc_state', 'xdr-dc-state', 'dc_state')))

        t.add_cell_alert(
            'node', lambda data: data['real_node_id'] == principal, color=terminal.fg_green)

        row = None
        for node_key, dc_stats in stats.iteritems():
            if isinstance(dc_stats, Exception):
                dc_stats = {}
            node = cluster.get_node(node_key)[0]
            for dc, row in dc_stats.iteritems():
                if isinstance(row, Exception):
                    row = {}
                if row:
                    row['real_node_id'] = node.node_id
                    row['node'] = prefixes[node_key]
                    t.insert_row(row)
        CliView.print_result(t)

    @staticmethod
    def info_old_XDR(stats, builds, xdr_enable, cluster, timestamp="", **ignore):
        if not max(xdr_enable.itervalues()):
            return

        prefixes = cluster.get_node_names()
        principal = cluster.get_expected_principal()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "XDR Information%s" % (title_suffix)
        column_names = ('node', 'build', ('_bytes-shipped', 'Data Shipped'), '_free-dlog-pct', ('_lag-secs', 'Lag (sec)'), '_req-outstanding',
                        '_req-shipped-success', '_req-shipped-errors', ('_cur_throughput', 'Cur Throughput'), ('_latency_avg_ship', 'Avg Latency (ms)'), '_xdr-uptime')

        t = Table(title, column_names, group_by=1)

        t.add_data_source('_xdr-uptime', Extractors.time_extractor(
            ('xdr-uptime', 'xdr_uptime')))

        t.add_data_source('_bytes-shipped',
                          Extractors.byte_extractor(
                              ('esmt-bytes-shipped', 'esmt_bytes_shipped', 'xdr_ship_bytes')))

        t.add_data_source('_lag-secs',
                          Extractors.time_extractor('xdr_timelag'))

        t.add_data_source('_req-outstanding',
                          Extractors.sif_extractor(('stat_recs_outstanding', 'xdr_ship_outstanding_objects')))

        t.add_data_source('_req-shipped-errors',
                          Extractors.sif_extractor('stat_recs_ship_errors'))

        t.add_data_source('_req-shipped-success',
                          Extractors.sif_extractor(('stat_recs_shipped_ok', 'xdr_ship_success')))

        t.add_data_source('_cur_throughput',
                          lambda data: get_value_from_dict(data, ('cur_throughput', 'xdr_throughput')))

        t.add_data_source('_latency_avg_ship',
                          lambda data: get_value_from_dict(data, ('latency_avg_ship', 'xdr_ship_latency_avg')))

        # Highlight red if lag is more than 30 seconds
        t.add_cell_alert(
            '_lag-secs', lambda data: int(data['xdr_timelag']) >= 300)

        t.add_cell_alert(
            'node', lambda data: data['real_node_id'] == principal, color=terminal.fg_green)

        row = None
        for node_key, row in stats.iteritems():
            if isinstance(row, Exception):
                row = {}

            node = cluster.get_node(node_key)[0]
            if xdr_enable[node_key]:
                if row:
                    row['build'] = builds[node_key]
                    set_value_in_dict(
                        row, '_free-dlog-pct', get_value_from_dict(row, ('free_dlog_pct', 'free-dlog-pct', 'dlog_free_pct')))
                    if row['_free-dlog-pct'].endswith("%"):
                        row['_free-dlog-pct'] = row['_free-dlog-pct'][:-1]

                    set_value_in_dict(row, 'xdr_timelag', get_value_from_dict(
                        row, ('xdr_timelag', 'timediff_lastship_cur_secs')))
                    if not get_value_from_dict(row, ('stat_recs_shipped_ok', 'xdr_ship_success')):
                        set_value_in_dict(row, 'stat_recs_shipped_ok', str(int(get_value_from_dict(row, ('stat_recs_shipped', 'stat-recs-shipped'), 0))
                                                                           -
                                                                           int(get_value_from_dict(
                                                                               row, ('err_ship_client', 'err-ship-client'), 0))
                                                                           - int(get_value_from_dict(row, ('err_ship_server', 'err-ship-server'), 0))))
                    set_value_in_dict(row, 'stat_recs_ship_errors', str(int(get_value_from_dict(row, ('err_ship_client', 'err-ship-client', 'xdr_ship_source_error'), 0))
                                                                        + int(get_value_from_dict(row, ('err_ship_server', 'err-ship-server', 'xdr_ship_destination_error'), 0))))
                else:
                    row = {}
                    row['node-id'] = node.node_id
                row['real_node_id'] = node.node_id
            else:
                continue

            row['node'] = prefixes[node_key]

            t.insert_row(row)
        CliView.print_result(t)

    @staticmethod
    def info_XDR(stats, cluster, timestamp="", **ignore):
        prefixes = cluster.get_node_names()
        principal = cluster.get_expected_principal()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "DC Information%s" % (title_suffix)
        column_names = ('node', ('_dc-name', 'DC'), ('dc-type', 'DC type'),
                        'namespaces',('_lag-secs', 'Lag (sec)'), ('success', 'Success'),
                        ('retry_conn_reset', 'Retry Connection Reset'), ('retry_dest', 'Retry Destination'),
                        ('total_recoveries', 'Recoveries'), ('_latency_avg_ship_ema', 'Avg Latency (ms)')
                        )

        t = Table(title, column_names, group_by=1)

        t.add_data_source(
            '_dc-name', lambda data: get_value_from_dict(data, ('dc-name', 'DC_Name')))

        t.add_data_source(
            '_lag-secs', Extractors.time_extractor(('xdr-dc-timelag', 'xdr_dc_timelag', 'dc_timelag')))

        t.add_data_source('success', lambda data: get_value_from_dict(
            data, ('success')))
        
        t.add_data_source('retry_conn_reset', lambda data: get_value_from_dict(
            data, ('retry_conn_reset')))

        t.add_data_source('rety_dest', lambda data: get_value_from_dict(
            data, ('rety_dest')))

        t.add_data_source('total_recoveries', lambda data: get_value_from_dict(
            data, ('total_recoveries')))

        t.add_data_source('_latency_avg_ship_ema', lambda data: get_value_from_dict(
            data, ('latency_avg_ship_ema', 'dc_latency_avg_ship', 'dc_latency_avg_ship_ema', 'dc_ship_latency_avg')))

        t.add_cell_alert(
            'node', lambda data: data['real_node_id'] == principal, color=terminal.fg_green)

        row = None
        for node_key, dc_stats in stats.iteritems():
            if isinstance(dc_stats, Exception):
                dc_stats = {}
            node = cluster.get_node(node_key)[0]
            for dc, row in dc_stats.iteritems():
                if isinstance(row, Exception):
                    row = {}
                if row:
                    row['real_node_id'] = node.node_id
                    row['node'] = prefixes[node_key]
                    row['total_recoveries'] = int(row['recoveries']) + int(row['recoveries_pending'])
                    row['dc-name'] = dc
                    t.insert_row(row)
        CliView.print_result(t)

    @staticmethod
    def info_sindex(stats, cluster, timestamp="", **ignore):
        prefixes = cluster.get_node_names()
        principal = cluster.get_expected_principal()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Secondary Index Information%s" % (title_suffix)
        column_names = ('node', ('indexname', 'Index Name'), ('indextype', 'Index Type'), ('ns', 'Namespace'), 'set', ('_bins', 'Bins'), ('_num_bins', 'Num Bins'), ('type', 'Bin Type'),
                        'state', 'sync_state', 'keys', 'entries', 'si_accounted_memory', ('_query_reqs', 'q'), ('_stat_write_success', 'w'), ('_stat_delete_success', 'd'), ('_query_avg_rec_count', 's'))

        t = Table(title, column_names, group_by=1, sort_by=2)
        t.add_data_source(
            '_bins', lambda data: get_value_from_dict(data, ('bins', 'bin')))
        t.add_data_source('_num_bins', lambda data: get_value_from_dict(
            data, ('num_bins'), default_value=1))
        t.add_data_source(
            'entries', Extractors.sif_extractor(('entries', 'objects')))
        t.add_data_source(
            '_query_reqs', Extractors.sif_extractor(('query_reqs')))
        t.add_data_source('_stat_write_success', Extractors.sif_extractor(
            ('stat_write_success', 'write_success')))
        t.add_data_source('_stat_delete_success', Extractors.sif_extractor(
            ('stat_delete_success', 'delete_success')))
        t.add_data_source(
            '_query_avg_rec_count', Extractors.sif_extractor(('query_avg_rec_count')))
        t.add_cell_alert(
            'node', lambda data: data['real_node_id'] == principal, color=terminal.fg_green)
        for stat in stats.values():
            for node_key, n_stats in stat.iteritems():
                node = cluster.get_node(node_key)[0]
                if isinstance(n_stats, Exception):
                    row = {}
                else:
                    row = n_stats
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                t.insert_row(row)

        CliView.print_result(t)

    @staticmethod
    def show_grep(title, summary):
        if not summary or len(summary.strip()) == 0:
            return
        if title:
            print "************************** %s **************************" % (title)
        CliView.print_result(summary)

    @staticmethod
    def show_distribution(title, histogram, unit, hist, cluster, like=None, timestamp="", **ignore):
        prefixes = cluster.get_node_names()

        likes = compile_likes(like)

        columns = ["%s%%" % (n) for n in xrange(10, 110, 10)]
        percentages = columns[:]
        columns.insert(0, 'node')

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        description = "Percentage of records having %s less than or " % (hist) + \
                      "equal to value measured in %s" % (unit)

        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.iteritems():
            if namespace not in namespaces or not node_data or isinstance(node_data, Exception):
                continue

            t = Table("%s - %s in %s%s" % (namespace, title, unit,
                                           title_suffix), columns, description=description)
            for node_id, data in node_data.iteritems():
                if not data or isinstance(data, Exception):
                    continue

                percentiles = data['percentiles']
                row = {}
                row['node'] = prefixes[node_id]
                for percent in percentages:
                    row[percent] = percentiles.pop(0)

                t.insert_row(row)

            CliView.print_result(t)

    @staticmethod
    def show_object_distribution(title, histogram, unit, hist, bucket_count, set_bucket_count, cluster, like=None, timestamp="", loganalyser_mode=False, **ignore):
        prefixes = cluster.get_node_names()

        likes = compile_likes(like)

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        description = "Number of records having %s in the range " % (hist) + \
                      "measured in %s" % (unit)

        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.iteritems():
            if namespace not in namespaces:
                continue
            columns = []
            for column in node_data["columns"]:
                # Tuple is required to give specific column display name,
                # otherwise it will print same column name but in title_format
                # (ex. KB -> Kb)
                columns.append((column, column))
            columns.insert(0, 'node')
            t = Table("%s - %s in %s%s" % (namespace, title, unit,
                                           title_suffix), columns, description=description)
            if not loganalyser_mode:
                for column in columns:
                    if column is not 'node':
                        t.add_data_source(
                            column, Extractors.sif_extractor(column))

            for node_id, data in node_data.iteritems():
                if node_id == "columns":
                    continue

                row = data['values']
                row['node'] = prefixes[node_id]
                t.insert_row(row)

            CliView.print_result(t)
            if set_bucket_count and (len(columns) - 1) < bucket_count:
                print "%sShowing only %s bucket%s as remaining buckets have zero objects%s\n" % (terminal.fg_green(), (len(columns) - 1), "s" if (len(columns) - 1) > 1 else "", terminal.fg_clear())

    @staticmethod
    def _update_latency_column_list(data, all_columns):
        if not data or "columns" not in data or not data["columns"]:
            return

        for column in data["columns"]:
            if column[0] == '>':
                c = int(column[1:-2])
                all_columns.add((c,(column, "%%>%dMs"%c)))

            elif column[0:2] == "%>":
                c = int(column[2:-2])
                all_columns.add((c, column))

    @staticmethod
    def _create_latency_row(data, ns=" "):
        if not data or "columns" not in data or not data["columns"] or "values" not in data or not data["values"]:
            return

        rows = []

        columns = data.pop("columns", None)
        for _values in data["values"]:
            row = dict(itertools.izip(columns, _values))
            row['namespace'] = ns
            rows.append(row)

        return rows

    @staticmethod
    def show_latency(latency, cluster, machine_wise_display=False, show_ns_details=False, like=None, timestamp="", **ignore):
        prefixes = cluster.get_node_names()

        if like:
            likes = compile_likes(like)

        if not machine_wise_display:
            if like:
                histograms = set(filter(likes.search, latency.keys()))
            else:
                histograms = set(latency.keys())

        title_suffix = CliView._get_timestamp_suffix(timestamp)

        for hist_or_node, data in sorted(latency.iteritems()):
            if not machine_wise_display and hist_or_node not in histograms:
                continue
            title = "%s Latency%s" % (hist_or_node, title_suffix)

            if machine_wise_display:
                if like:
                    histograms = set(filter(likes.search, data.keys()))
                else:
                    histograms = set(data.keys())
            all_columns = set()
            for node_or_hist_id, _data in data.iteritems():
                if machine_wise_display and node_or_hist_id not in histograms:
                    continue

                for _type, _type_data in _data.iteritems():
                    if _type == "namespace" and not show_ns_details:
                        continue

                    if _type == "total":
                        CliView._update_latency_column_list(_type_data, all_columns=all_columns)

                    else:
                        for ns, ns_data in _type_data.iteritems():
                            CliView._update_latency_column_list(ns_data, all_columns=all_columns)

            all_columns = [c[1] for c in sorted(all_columns, key=lambda c:c[0])]
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
                    t.add_cell_alert(
                        c, lambda data: data['namespace'] is " ", color=terminal.fg_blue)
            for node_or_hist_id, _data in data.iteritems():
                if machine_wise_display and node_or_hist_id not in histograms:
                    continue

                for _type in sorted(_data.keys()):
                    if _type == "namespace" and not show_ns_details:
                        continue

                    _type_data = _data[_type]
                    rows = []

                    if _type == "total":
                        rows = CliView._create_latency_row(_type_data)

                    else:
                        for _ns, _ns_data in _type_data.iteritems():
                            rows += CliView._create_latency_row(_ns_data, ns=_ns)

                    for row in rows:
                        if not row or isinstance(row, Exception):
                            continue

                        if machine_wise_display:
                            row['histogram'] = node_or_hist_id
                        else:
                            row['node'] = prefixes[node_or_hist_id]
                        t.insert_row(row)

            CliView.print_result(t)

    @staticmethod
    def show_config(title, service_configs, cluster, like=None, diff=None, show_total=False, title_every_nth=0, flip_output=False, timestamp="", **ignore):
        prefixes = cluster.get_node_names()
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
            likes = compile_likes(like)

            column_names = filter(likes.search, column_names)

        if len(column_names) == 0:
            return ''

        column_names.insert(0, "NODE")

        table_style = Styles.VERTICAL
        if flip_output:
            table_style = Styles.HORIZONTAL

        if show_total:
            n_last_columns_ignore_sort = 1
        else:
            n_last_columns_ignore_sort = 0

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = title + title_suffix
        t = Table(title, column_names,
                  title_format=TitleFormats.no_change, style=table_style, n_last_columns_ignore_sort=n_last_columns_ignore_sort)

        row = None
        if show_total:
            row_total = {}
        for node_id, row in service_configs.iteritems():
            if isinstance(row, Exception):
                row = {}

            row['NODE'] = prefixes[node_id]
            t.insert_row(row)

            if show_total:
                for key, val in row.iteritems():
                    if (val.isdigit()):
                        try:
                            row_total[key] = row_total[key] + int(val)
                        except Exception:
                            row_total[key] = int(val)
        if show_total:
            row_total['NODE'] = "Total"
            t.insert_row(row_total)

        CliView.print_result(
            t.__str__(horizontal_title_every_nth=title_every_nth))

    @staticmethod
    def show_grep_count(title, grep_result, title_every_nth=0, like=None, diff=None, **ignore):
        column_names = set()
        if grep_result:
            if grep_result[grep_result.keys()[0]]:
                column_names = CliView._sort_list_with_string_and_datetime(
                    grep_result[grep_result.keys()[0]][COUNT_RESULT_KEY].keys())

        if len(column_names) == 0:
            return ''

        column_names.insert(0, "NODE")

        t = Table(title, column_names,
                  title_format=TitleFormats.no_change, style=Styles.VERTICAL)

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

            t.insert_row(row1)
            t.insert_row(row2)

        t.ignore_sort()

        CliView.print_result(
            t.__str__(horizontal_title_every_nth=2 * title_every_nth))

    @staticmethod
    def show_grep_diff(title, grep_result, title_every_nth=0, like=None, diff=None, **ignore):
        column_names = set()
        different_writer_info = False

        if grep_result and grep_result[grep_result.keys()[0]]:
            if "diff_end" in grep_result[grep_result.keys()[0]]["value"]:
                for _k in grep_result.keys():
                    try:
                        if grep_result[_k]["value"]["diff_end"]:
                            different_writer_info = True
                        grep_result[_k]["value"].pop("diff_end")
                    except Exception:
                        continue

            column_names = CliView._sort_list_with_string_and_datetime(
                grep_result[grep_result.keys()[0]]["value"].keys())

        if len(column_names) == 0:
            return ''

        column_names.insert(0, ".")
        column_names.insert(0, "NODE")

        t = Table(title, column_names,
                  title_format=TitleFormats.no_change, style=Styles.VERTICAL)

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

            t.insert_row(row1)
            t.insert_row(row2)
            t.insert_row(row3)

        t.ignore_sort()

        CliView.print_result(
            t.__str__(horizontal_title_every_nth=title_every_nth * 3))
        if different_writer_info:
            print("\n" + terminal.fg_red() + "Input Key is not uniq, multiple writer instance (server_file:line_no) found." + terminal.fg_clear())

    @staticmethod
    def _sort_list_with_string_and_datetime(keys):
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
    def show_log_latency(title, grep_result, title_every_nth=0, like=None, diff=None, **ignore):
        column_names = set()
        tps_key = ("ops/sec", None)

        if grep_result:
            # find column names
            if grep_result[grep_result.keys()[0]]:
                column_names = CliView._sort_list_with_string_and_datetime(
                    grep_result[grep_result.keys()[0]][tps_key].keys())

        if len(column_names) == 0:
            return ''
        column_names.insert(0, ".")
        column_names.insert(0, "NODE")

        t = Table(title, column_names,
                  title_format=TitleFormats.no_change, style=Styles.VERTICAL)

        row = None
        sub_columns_per_column = 0
        for file in sorted(grep_result.keys()):
            if isinstance(grep_result[file], Exception):
                continue
            else:
                is_first = True
                sub_columns_per_column = len(grep_result[file].keys())
                relative_stats_columns = []

                for key, unit in sorted(grep_result[file].keys(), key=lambda tup: tup[0]):
                    if key == tps_key[0]:
                        continue

                    if not unit:
                        # this is relative stat column
                        relative_stats_columns.append((key, unit))
                        continue

                    row = grep_result[file][(key, unit)]
                    if is_first:
                        row['NODE'] = file
                        is_first = False
                    else:
                        row['NODE'] = "."

                    row['.'] = "%% >%d%s" % (key, unit)
                    t.insert_row(row)

                row = grep_result[file][tps_key]
                row['NODE'] = "."
                row['.'] = tps_key[0]
                t.insert_row(row)

                for stat in relative_stats_columns:
                    row = grep_result[file][stat]
                    row['NODE'] = "."
                    row['.'] = stat[0]
                    t.insert_row(row)

                row = {}
                for key in grep_result[file][tps_key].keys():
                    row[key] = "|"

                row['NODE'] = "|"
                row['.'] = "|"
                t.insert_row(row)

        t.ignore_sort()
        # print t
        CliView.print_result(t.__str__(
            horizontal_title_every_nth=title_every_nth * (sub_columns_per_column + 1)))

    @staticmethod
    def show_stats(*args, **kwargs):
        print("in show_stats")
        CliView.show_config(*args, **kwargs)

    @staticmethod
    def show_mapping(col1, col2, mapping, like=None, timestamp="", **ignore):
        if not mapping:
            return

        column_names = []
        column_names.insert(0, col2)
        column_names.insert(0, col1)

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        t = Table("%s to %s Mapping%s" % (col1, col2, title_suffix), column_names,
                  title_format=TitleFormats.no_change, style=Styles.HORIZONTAL)

        if like:
            likes = compile_likes(like)
            filtered_keys = filter(likes.search, mapping.keys())

        else:
            filtered_keys = mapping.keys()

        for col1_val, col2_val in mapping.iteritems():
            if col1_val not in filtered_keys:
                continue
            row = {}
            if not isinstance(col2_val, Exception):
                row[col1] = col1_val
                row[col2] = col2_val
            t.insert_row(row)
        CliView.print_result(t)

    @staticmethod
    def show_health(*args, **kwargs):
        CliView.show_config(*args, **kwargs)

    @staticmethod
    def asinfo(results, line_sep, show_node_name, cluster, **kwargs):
        like = set([])
        if 'like' in kwargs:
            like = set(kwargs['like'])

        for node_id, value in results.iteritems():

            if show_node_name:
                prefix = cluster.get_node_names()[node_id]
                node = cluster.get_node(node_id)[0]
                print "%s%s (%s) returned%s:" % (terminal.bold(), prefix, node.ip, terminal.reset())

            if isinstance(value, Exception):
                print "%s%s%s" % (terminal.fg_red(), value, terminal.reset())
                print "\n"
            else:
                if isinstance(value, types.StringType):
                    delimiter = find_delimiter_in(value)
                    value = value.split(delimiter)

                    if like:
                        likes = compile_likes(like)
                        value = filter(likes.search, value)

                    if line_sep:
                        value = "\n".join(value)
                    else:
                        value = delimiter.join(value)

                    print value
                    if show_node_name:
                        print
                else:
                    i = 1
                    for name, val in value.iteritems():
                        print i, ": ", name
                        print "    ", val
                        i += 1
                    if show_node_name:
                        print

    @staticmethod
    def group_output(output):
        i = 0
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

        if line[0] == "--no-diff":
            diff_highlight = False
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
                    next_iterator = CliView.peekable(
                        next_peeked, next_iterator)

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
                st = datetime.datetime.fromtimestamp(
                    ts).strftime(' %Y-%m-%d %H:%M:%S')
                command = " ".join(line)
                print >> real_stdout, "[%s '%s' sleep: %ss iteration: %s" % (
                    st, command, sleep, count),
                if num_iterations:
                    print >> real_stdout, " of %s" % (num_iterations),
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

###########################
### Health Print functions
###########################

    @staticmethod
    def _print_data(d):
        if d is None:
            return
        if isinstance(d, tuple):
            print d
        elif isinstance(d, dict):
            print_dict(d)
        else:
            print str(d)

    @staticmethod
    def _print_counter_list(data, header=None):
        if not data:
            return
        print "\n" + ("_" * 100) + "\n"
        if header:
            print terminal.fg_red() + terminal.bold() + str(header) + " ::\n" + terminal.unbold() + terminal.fg_clear()
        for d in data:
            CliView._print_data(d)
            print ""

    @staticmethod
    def _print_status(status_counters, verbose=False):
        if not status_counters:
            return
        s = "\n" + terminal.bold() + "Summary".center(H_width, "_") + terminal.unbold()
        s += "\n" + CliView._get_header("Total") + CliView._get_msg([str(status_counters[HealthResultCounter.ASSERT_QUERY_COUNTER])])
        s += CliView._get_header("Passed") + CliView._get_msg([str(status_counters[HealthResultCounter.ASSERT_PASSED_COUNTER])])
        s += CliView._get_header("Failed") + CliView._get_msg([str(status_counters[HealthResultCounter.ASSERT_FAILED_COUNTER])])
        s += CliView._get_header("Skipped") + CliView._get_msg([str(status_counters[HealthResultCounter.ASSERT_QUERY_COUNTER]
                                                        - status_counters[HealthResultCounter.ASSERT_FAILED_COUNTER]
                                                        - status_counters[HealthResultCounter.ASSERT_PASSED_COUNTER])])
        print s

    @staticmethod
    def _print_debug_messages(ho):
        try:
            for d in ho[HealthResultType.DEBUG_MESSAGES]:
                try:
                    print "Value of %s:" % (d[1])
                    CliView._print_data(d[2])
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _print_exceptions(ho):
        try:
            for e in ho[HealthResultType.EXCEPTIONS]:
                try:
                    CliView._print_counter_list(
                        data=ho[HealthResultType.EXCEPTIONS][e], header="%s Exceptions" % (e.upper()))
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _get_header(header):
        return "\n" + terminal.bold() + ("%s:" % header).rjust(H1_offset) + \
            terminal.unbold() + " ".rjust(H2_offset - H1_offset)

    @staticmethod
    def _get_msg(msg, level=None):
        if level is not None:
            if level == AssertLevel.WARNING:
                return terminal.fg_blue() + ("\n" + " ".rjust(H2_offset)).join(msg) + terminal.fg_clear()
            elif level == AssertLevel.INFO:
                return terminal.fg_green() + ("\n" + " ".rjust(H2_offset)).join(msg) + terminal.fg_clear()
            else:
                return terminal.fg_red() + ("\n" + " ".rjust(H2_offset)).join(msg) + terminal.fg_clear()
        else:
            return ("\n" + " ".rjust(H2_offset)).join(msg)

    @staticmethod
    def _format_value(val, formatting=True):
        if not val or not formatting:
            return val

        if isinstance(val, int):
            try:
                # For python 2.7
                return str(format(val, ',d'))

            except Exception:
                try:
                    # For python 2.6
                    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
                    return str(locale.format('%d', val, True))

                except Exception:
                    pass

        elif isinstance(val, float):
            return_val = None
            try:
                # For python 2.7
                return_val = format(val, ',f')

            except Exception:
                try:
                    # For python 2.6
                    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
                    return_val = locale.format('%f', val, True)

                except Exception:
                    pass

            if return_val is not None:
                return_val = str(return_val)
                if '.' in return_val:
                    return_val = return_val.rstrip('0')
                    return_val = return_val.rstrip('.')
                return return_val

        elif isinstance(val, str) and val.isdigit():
            return CliView._format_value(int(val))

        elif isinstance(val, str):
            try:
                val = float(val)
                return CliView._format_value(val)
            except Exception:
                pass

        return val

    @staticmethod
    def _get_kv_msg_list(kv_list):
        if not kv_list:
            return []

        res_str = []
        for kv in kv_list:
            if not isinstance(kv, tuple):
                res_str.append(str(kv))
                continue

            tmp_res_str = str(kv[0])
            if kv[1] and isinstance(kv[1], list):
                _str = None
                for _kv in kv[1]:
                    if _kv:
                        try:
                            _str += ", " + ("%s:"%(str(_kv[0])) if len(str(_kv[0]).strip())>0 else "") + "%s"%(CliView._format_value(_kv[1], _kv[2]))
                        except Exception:
                            _str = ("%s:"%(str(_kv[0])) if len(str(_kv[0]).strip())>0 else "") + "%s"%(CliView._format_value(_kv[1], _kv[2]))

                if _str:
                    tmp_res_str += " {%s}"%(_str)

            if tmp_res_str:
                res_str.append(tmp_res_str)

        return res_str

    @staticmethod
    def _get_error_string(data, verbose=False, level=AssertLevel.CRITICAL):
        if not data:
            return "", 0
        f_msg_str = ""
        f_msg_cnt = 0
        s_msg_str = ""
        s_msg_cnt = 0

        for d in data:
            s = ""

            if d[AssertResultKey.LEVEL] == level:

                if d[AssertResultKey.SUCCESS]:
                    if d[AssertResultKey.SUCCESS_MSG]:

                        s_msg_str += CliView._get_header(d[AssertResultKey.CATEGORY][0]) + \
                            CliView._get_msg([d[AssertResultKey.SUCCESS_MSG]])
                        s_msg_cnt += 1
                    continue

                s += CliView._get_header(d[AssertResultKey.CATEGORY][0]) + \
                    CliView._get_msg([d[AssertResultKey.FAIL_MSG]], level)

                if verbose:
                    import textwrap

                    s += "\n"
                    s += CliView._get_header("Description:")
                    s += CliView._get_msg(textwrap.wrap(str(d[AssertResultKey.DESCRIPTION]), H_width - H2_offset,
                                                       break_long_words=False, break_on_hyphens=False))

                    s += "\n"
                    s += CliView._get_header("Keys:")
                    s += CliView._get_msg(CliView._get_kv_msg_list(d[AssertResultKey.KEYS]))

                    # Extra new line in case verbose output is printed
                    s += "\n"

                f_msg_str += s
                f_msg_cnt += 1

        res_fail_msg_str = ""
        if f_msg_cnt > 0:
            res_fail_msg_str += f_msg_str

        res_success_msg_str = ""

        if s_msg_cnt > 0:
            # res_success_msg_str = "\n\n"
            # res_success_msg_str += (".".join(data[0]
            #                         [AssertResultKey.CATEGORY]) + ":").ljust(25) + ""
            res_success_msg_str += s_msg_str

        return res_fail_msg_str, f_msg_cnt, res_success_msg_str, s_msg_cnt

    @staticmethod
    def _get_assert_output_string(assert_out, verbose=False, output_filter_category=[], level=AssertLevel.CRITICAL):

        if not assert_out:
            return ""

        res_fail_msg_str = ""
        total_fail_msg_cnt = 0
        res_success_msg_str = ""
        total_success_msg_cnt = 0

        if not isinstance(assert_out, dict):
            if not output_filter_category:
                return CliView._get_error_string(assert_out, verbose, level=level)
        else:
            for _k in sorted(assert_out.keys()):
                category = []

                if output_filter_category:
                    if _k == output_filter_category[0]:
                        category = output_filter_category[1:] if len(
                            output_filter_category) > 1 else []
                    else:
                        category = output_filter_category

                f_msg_str, f_msg_cnt, s_msg_str, s_msg_cnt = CliView._get_assert_output_string(
                    assert_out[_k], verbose, category, level=level)

                res_fail_msg_str += f_msg_str
                total_fail_msg_cnt += f_msg_cnt
                res_success_msg_str += s_msg_str
                total_success_msg_cnt += s_msg_cnt

        return res_fail_msg_str, total_fail_msg_cnt, res_success_msg_str, total_success_msg_cnt

    @staticmethod
    def _print_assert_summary(assert_out, verbose=False, output_filter_category=[], output_filter_warning_level=None):

        if not output_filter_warning_level:
            search_levels = [AssertLevel.INFO, AssertLevel.WARNING, AssertLevel.CRITICAL]
        elif output_filter_warning_level == "CRITICAL":
            search_levels = [AssertLevel.CRITICAL]
        elif output_filter_warning_level == "WARNING":
            search_levels = [AssertLevel.WARNING]
        elif output_filter_warning_level == "INFO":
            search_levels = [AssertLevel.INFO]
        else:
            search_levels = [AssertLevel.INFO, AssertLevel.WARNING, AssertLevel.CRITICAL]

        all_success_str = ""
        all_fail_str = ""
        all_fail_cnt = 0
        all_success_cnt = 0

        for level in search_levels:
            res_fail_msg_str = ""
            total_fail_msg_cnt = 0
            res_success_msg_str = ""
            total_success_msg_cnt = 0

            for _k in sorted(assert_out.keys()):
                if not assert_out[_k]:
                    continue
                category = []
                if output_filter_category:
                    if _k == output_filter_category[0]:
                        category = output_filter_category[1:] if len(
                            output_filter_category) > 1 else []
                    else:
                        category = output_filter_category

                f_msg_str, f_msg_cnt, s_msg_str, s_msg_cnt = CliView._get_assert_output_string(
                    assert_out[_k], verbose, category, level=level)
                if f_msg_str:
                    total_fail_msg_cnt += f_msg_cnt
                    res_fail_msg_str += f_msg_str

                if s_msg_str:
                    total_success_msg_cnt += s_msg_cnt
                    res_success_msg_str += s_msg_str

            if total_fail_msg_cnt > 0:
                summary_str = ""
                if level == AssertLevel.CRITICAL:
                    summary_str = terminal.bold() + terminal.fg_red() + str("%s" %
                                                          ("CRITICAL")).center(H_width, " ") + terminal.fg_clear() + terminal.unbold()
                elif level == AssertLevel.WARNING:
                    summary_str = terminal.bold() + terminal.fg_blue() + str("%s" %
                                                           ("WARNING")).center(H_width, " ") + terminal.fg_clear() + terminal.unbold()
                elif level == AssertLevel.INFO:
                    summary_str = terminal.bold() + terminal.fg_green() + str("%s" %
                                                            ("INFO")).center(H_width, " ") + terminal.fg_clear() + terminal.unbold()

                all_fail_str += "\n" + summary_str + "\n" + res_fail_msg_str + "\n"
                all_fail_cnt += total_fail_msg_cnt

            if total_success_msg_cnt > 0:
                all_success_str += res_success_msg_str
                all_success_cnt += total_success_msg_cnt

        if all_success_cnt > 0:
            print "\n\n" + terminal.bold() + str(" %s: count(%d) " %("PASS", all_success_cnt)).center(H_width, "_") + terminal.unbold()
            print all_success_str

        if all_fail_cnt > 0:
            print "\n\n" + terminal.bold() + str(" %s: count(%d) " %("FAIL", all_fail_cnt)).center(H_width, "_") + terminal.unbold()
            print all_fail_str

        print "_" * H_width + "\n"

    @staticmethod
    def print_health_output(ho, verbose=False, debug=False, output_file=None, output_filter_category=[], output_filter_warning_level=None):
        if not ho:
            return
        o_s = None

        if output_file is not None:
            try:
                o_s = open(output_file, "a")
                sys.stdout = o_s
            except Exception:
                sys.stdout = sys.__stdout__

        CliView._print_debug_messages(ho)
        if debug:
            CliView._print_exceptions(ho)

        CliView._print_status(
            ho[HealthResultType.STATUS_COUNTERS], verbose=verbose)
        CliView._print_assert_summary(ho[HealthResultType.ASSERT], verbose=verbose,
                                     output_filter_category=output_filter_category, output_filter_warning_level=output_filter_warning_level)

        if o_s:
            o_s.close()
        sys.stdout = sys.__stdout__

###########################

    @staticmethod
    def get_summary_line_prefix(index, key):
        s = " " * 3
        s += str(index)
        s += "." + (" " * 3)
        s += key.ljust(19)
        s += ":" + (" " * 2)
        return s

    @staticmethod
    def _summary_namespace_table_view(stats, **ignore):
        title = "Namespaces"
        column_names = ('namespace', ('_devices', 'Devices (Total,Per-Node)'), ('_memory', 'Memory (Total,Used%,Avail%)'),
                        ('_disk', 'Disk (Total,Used%,Avail%)'), ('repl_factor', 'Replication Factor'), ('cache_read_pct','Post-Write-Queue Hit-Rate'),
                        'rack_aware', ('master_objects', 'Master Objects'),
                        ('license_data_in_memory', 'Usage (Unique-Data) In-Memory'), ('license_data_on_disk', 'Usage (Unique-Data) On-Disk'),
                        'compression_ratio'
                        )


        t = Table(title, column_names, sort_by=0)

        t.add_cell_alert(
            'namespace',
            lambda data: data['migrations_in_progress'],
            color=terminal.fg_red
        )

        t.add_data_source_tuple(
            '_devices',
            lambda data:str(data['devices_total']),
            lambda data:str(data['devices_per_node']))

        t.add_data_source_tuple(
            '_memory',
            Extractors.byte_extractor('memory_total'),
            lambda data:"%.2f"%data["memory_used_pct"],
            lambda data:"%.2f"%data["memory_available_pct"])

        t.add_data_source_tuple(
            '_disk',
            Extractors.byte_extractor('disk_total'),
            lambda data:"%.2f"%data["disk_used_pct"],
            lambda data:"%.2f"%data["disk_available_pct"])

        t.add_data_source(
            'repl_factor',
            lambda data:",".join([str(rf) for rf in data["repl_factor"]])
        )

        t.add_data_source(
            'master_objects',
            Extractors.sif_extractor('master_objects')
        )

        t.add_data_source(
            'license_data_in_memory',
            Extractors.byte_extractor('license_data_in_memory')
        )

        t.add_data_source(
            'license_data_on_disk',
            Extractors.byte_extractor('license_data_on_disk')
        )

        for ns, ns_stats in stats.iteritems():
            if isinstance(ns_stats, Exception):
                row = {}
            else:
                row = ns_stats

            row['namespace'] = ns
            row['memory_used_pct'] = 100.00 - row['memory_available_pct']

            t.insert_row(row)

        CliView.print_result(t)

    @staticmethod
    def _summary_namespace_list_view(stats, **ignore):
        print "Namespaces"
        print "=========="
        print
        for ns in stats:
            index = 1
            print "   " + ("%s"%(terminal.fg_red() + ns + terminal.fg_clear())
                           if stats[ns]["migrations_in_progress"] else ns)
            print "   " + "=" * len(ns)

            print CliView.get_summary_line_prefix(index, "Devices") + "Total %d, per-node %d%s"%(
                stats[ns]["devices_total"], stats[ns]["devices_per_node"],
                " (number differs across nodes)" if not stats[ns]["devices_count_same_across_nodes"] else "")
            index += 1

            print CliView.get_summary_line_prefix(index, "Memory") + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"%(
                filesize.size(stats[ns]["memory_total"]).strip(), 100.00 - stats[ns]["memory_available_pct"],
                filesize.size(stats[ns]["memory_total"] - stats[ns]["memory_aval"]).strip(),
                stats[ns]["memory_available_pct"], filesize.size(stats[ns]["memory_aval"]).strip())
            index += 1

            if stats[ns]["disk_total"]:
                print CliView.get_summary_line_prefix(index, "Disk") + "Total %s, %.2f%% used (%s), %.2f%% available contiguous space (%s)"%(
                    filesize.size(stats[ns]["disk_total"]).strip(), stats[ns]["disk_used_pct"],
                    filesize.size(stats[ns]["disk_used"]).strip(), stats[ns]["disk_available_pct"],
                    filesize.size(stats[ns]["disk_aval"]).strip())
                index += 1

            print CliView.get_summary_line_prefix(index, "Replication Factor") + "%s"%(",".join([str(rf) for rf in stats[ns]["repl_factor"]]))
            index += 1

            if "cache_read_pct" in stats[ns]:
                print CliView.get_summary_line_prefix(index, "Post-Write-Queue Hit-Rate") + "%s"%(filesize.size(stats[ns]["cache_read_pct"], filesize.sif))
                index += 1

            if "rack_aware" in stats[ns]:
                print CliView.get_summary_line_prefix(index, "Rack-aware") + "%s"%(str(stats[ns]["rack_aware"]))
                index += 1

            print CliView.get_summary_line_prefix(index, "Master Objects") + "%s"%(filesize.size(stats[ns]["master_objects"], filesize.sif))
            index += 1
            s = ""

            if "license_data_in_memory" in stats[ns]:
                s += "%s in-memory"%(filesize.size(stats[ns]["license_data_in_memory"]))

            if "license_data_on_disk" in stats[ns]:
                if s:
                    s += ", "
                s += "%s on-disk"%(filesize.size(stats[ns]["license_data_on_disk"]))
            print CliView.get_summary_line_prefix(index, "Usage (Unique Data)") + s
            index += 1

            if "compression_ratio" in stats[ns]:
                print CliView.get_summary_line_prefix(index, "Compression-ratio") + "%s"%(str(stats[ns]["compression_ratio"]))
                index += 1
            print

    @staticmethod
    def print_summary(summary, list_view=True):

        index = 1
        print "Cluster" + ("  (%s)"%(terminal.fg_red() + "Migrations in Progress" + terminal.fg_clear())
                           if summary["CLUSTER"]["migrations_in_progress"] else "")
        print "=======" + ("==========================" if summary["CLUSTER"]["migrations_in_progress"] else "")
        print

        if "cluster_name" in summary["CLUSTER"] and len(summary["CLUSTER"]["cluster_name"]) > 0:
            print CliView.get_summary_line_prefix(index, "Cluster Name") + ", ".join(summary["CLUSTER"]["cluster_name"])
            index += 1

        print CliView.get_summary_line_prefix(index, "Server Version") + ", ".join(summary["CLUSTER"]["server_version"])
        index += 1

        print CliView.get_summary_line_prefix(index, "OS Version") + ", ".join(summary["CLUSTER"]["os_version"])
        index += 1

        print CliView.get_summary_line_prefix(index, "Cluster Size") + ", ".join([str(cs) for cs in summary["CLUSTER"]["cluster_size"]])
        index += 1

        print CliView.get_summary_line_prefix(index, "Devices") + "Total %d, per-node %d%s"%(
            summary["CLUSTER"]["device"]["count"], summary["CLUSTER"]["device"]["count_per_node"],
            " (number differs across nodes)" if not summary["CLUSTER"]["device"]["count_same_across_nodes"] else "")
        index += 1

        print CliView.get_summary_line_prefix(index, "Memory") + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"%(
            filesize.size(summary["CLUSTER"]["memory"]["total"]).strip(), 100.00 - summary["CLUSTER"]["memory"]["aval_pct"],
            filesize.size(summary["CLUSTER"]["memory"]["total"] - summary["CLUSTER"]["memory"]["aval"]).strip(),
            summary["CLUSTER"]["memory"]["aval_pct"], filesize.size(summary["CLUSTER"]["memory"]["aval"]).strip())
        index += 1

        print CliView.get_summary_line_prefix(index, "Disk") + "Total %s, %.2f%% used (%s), %.2f%% available contiguous space (%s)"%(
            filesize.size(summary["CLUSTER"]["device"]["total"]).strip(), summary["CLUSTER"]["device"]["used_pct"],
            filesize.size(summary["CLUSTER"]["device"]["used"]).strip(), summary["CLUSTER"]["device"]["aval_pct"],
            filesize.size(summary["CLUSTER"]["device"]["aval"]).strip())
        index += 1

        print CliView.get_summary_line_prefix(index, "Usage (Unique Data)") + "%s in-memory, %s on-disk"%(filesize.size(summary["CLUSTER"]["license_data"]["memory_size"]),filesize.size(summary["CLUSTER"]["license_data"]["device_size"]))
        index += 1

        print CliView.get_summary_line_prefix(index, "Active Namespaces") + "%d of %d"%(summary["CLUSTER"]["active_ns"], summary["CLUSTER"]["ns_count"])
        index += 1

        print CliView.get_summary_line_prefix(index, "Features") + ", ".join(sorted(summary["CLUSTER"]["active_features"]))

        print "\n"

        if list_view:
            CliView._summary_namespace_list_view(summary["FEATURES"]["NAMESPACE"])

        else:
            CliView._summary_namespace_table_view(summary["FEATURES"]["NAMESPACE"])

    @staticmethod
    def show_pmap(pmap_data, cluster, timestamp="", **ignore):
        prefixes = cluster.get_node_names()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Partition Map Analysis%s"%(title_suffix)
        column_names = (('cluster_key', 'Cluster Key'),
                        'namespace',
                        'node',
                        ('_primary_partitions', 'Primary Partitions'),
                        ('_secondary_partitions', 'Secondary Partitions'),
                        ('dead_partitions', 'Dead Partitions'),
                        ('unavailable_partitions', 'Unavailable Partitions'),
                        )
        t = Table(title, column_names, group_by=0, sort_by=1)

        for node_key, n_stats in pmap_data.iteritems():

            for ns, ns_stats in n_stats.iteritems():
                row = ns_stats
                row['node'] = prefixes[node_key]
                row['namespace'] = ns
                row['_primary_partitions'] = ns_stats['master_partition_count']
                row['_secondary_partitions'] = ns_stats['prole_partition_count']

                t.insert_row(row)

        CliView.print_result(t)
