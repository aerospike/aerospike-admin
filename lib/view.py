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
    def infoNetwork(stats, versions, builds, visibilities, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()
        hosts = cluster.nodes

        title = "Network Information"
        column_names = ('node'
                        , 'node_id'
                        , 'ip'
                        , 'build'
                        , 'Enterprise'
                        , 'cluster_size'
                        , 'cluster_key'
                        , 'cluster_visibility'
                        , '_cluster_integrity'
                        , ('_paxos_principal', 'Principal')
                        , '_uptime')

        t = Table(title, column_names)

        t.addCellAlert('node_id'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addDataSource('_cluster_integrity'
                        , lambda data:
                        True if row['cluster_integrity'] == 'true' else False)
        t.addDataSource('_uptime', Extractors.timeExtractor('uptime'))

        t.addCellAlert('cluster_visibility'
                       , lambda data: data['cluster_visibility'] is not True)

        t.addCellAlert('_cluster_integrity'
                       ,lambda data: data['cluster_integrity'] != 'true')

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addDataSource('Enterprise'
                        , lambda data:
                        True if "Enterprise" in data['version'] else False)

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

            build = builds[node_key]
            if not isinstance(build, Exception):
                row['build'] = build

            version = versions[node_key]
            if not isinstance(version, Exception):
                row['version'] = version

            if node_key in visibilities:
                row['cluster_visibility'] = visibilities[node_key]

            t.insertRow(row)

        #print t
        CliView.print_result(t)

    @staticmethod
    def infoService(stats, hosts, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Service Information"
        column_names = ('node'
                        , ('system_free_mem_pct', 'Free Mem%')
                        , ('_migrates', 'Migrates (tx,rx,a)')
                        , '_objects')

        principal = cluster.getExpectedPrincipal()

        t = Table(title, column_names)


        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addDataSource('_migrates'
                        ,lambda data:
                        "(%s,%s,%s)"%(row.get('tx_migrations', 'N/E')
                                      , row.get('rx_migrations', 'N/E')
                                      , int(row.get('migrate_progress_send',0)) + int(row.get('migrate_progress_recv',0))
                                            if (row.has_key('migrate_progress_send')
                                                and row.has_key('migrate_progress_recv')) else 'N/E'))

        t.addDataSource('_objects'
                        ,Extractors.sifExtractor('objects'))

        t.addCellAlert('system_free_mem_pct'
                       ,lambda data: int(data['free-pct-memory']) < 40)



        for node_key, n_stats in stats.iteritems():
            if isinstance(n_stats, Exception):
                n_stats = {}
            node = cluster.getNode(node_key)[0]
            row = n_stats
            row['node'] = prefixes[node_key]
            row['real_node_id'] = node.node_id
            t.insertRow(row)
        #print t
        CliView.print_result(t)

    @staticmethod
    def infoNamespace(stats, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Namespace Information"
        column_names = ('namespace'
                        , 'node'
                        , ('available_pct', 'Avail%')
                        , ('evicted-objects', 'Evictions')
                        , ('_master-objects', 'Master Objects')
                        , ('_prole-objects', 'Replica Objects')
                        , 'repl-factor'
                        , 'stop-writes'
                        , ('_migrates', 'Migrates (tx,rx)')
                        , ('_used-bytes-disk', 'Disk Used')
                        , ('_used-disk-pct', 'Disk Used%')
                        , ('high-water-disk-pct', 'HWM Disk%')
                        , ('_used-bytes-memory', 'Mem Used')
                        , ('_used-mem-pct', 'Mem Used%')
                        , ('high-water-memory-pct', 'HWM Mem%')
                        , ('stop-writes-pct', 'Stop Writes%'))

        t = Table(title, column_names, sort_by=0)
        t.addDataSource('_used-bytes-disk'
                        ,Extractors.byteExtractor('used-bytes-disk'))
        t.addDataSource('_used-bytes-memory'
                        ,Extractors.byteExtractor(
                            'used-bytes-memory'))

        t.addDataSource('_master-objects'
                        ,Extractors.sifExtractor('master-objects'))

        t.addDataSource('_prole-objects'
                        ,Extractors.sifExtractor('prole-objects'))

        t.addDataSource('_used-disk-pct'
                        , lambda data: 100 - int(data['free-pct-disk']) if data['free-pct-disk'] is not " " else " ")

        t.addDataSource('_used-mem-pct'
                        , lambda data: 100 - int(data['free-pct-memory']) if data['free-pct-memory'] is not " " else " ")

        t.addCellAlert('available_pct'
                       , lambda data: int(data['available_pct']) <= 10 if data['available_pct'] is not " " else " ")

        t.addCellAlert('stop-writes'
                       , lambda data: data['stop-writes'] != 'false')

        t.addDataSource('_migrates'
                        , lambda data:
                        "(%s,%s)"%(data.get('migrate-tx-partitions-remaining', 'N/E')
                                      , data.get('migrate-rx-partitions-remaining','N/E')))

        t.addCellAlert('_used-disk-pct'
                       , lambda data: int(data['_used-disk-pct']) >= int(data['high-water-disk-pct']) if data['_used-disk-pct'] is not " " else " ")

        t.addCellAlert('_used-mem-pct'
                       , lambda data: (100 - int(data['free-pct-memory'])) >= int(data['high-water-memory-pct']) if data['free-pct-memory'] is not " " else " ")

        t.addCellAlert('_used-disk-pct'
                       , lambda data: (100 - int(data['free-pct-disk'])) >= int(data['high-water-disk-pct']) if data['free-pct-disk'] is not " " else " ")

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addCellAlert('namespace'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('_master-objects'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('_prole-objects'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('_used-bytes-memory'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('_used-bytes-disk'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('evicted-objects'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('_migrates'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)

        total_res = {}

        for node_key, n_stats in stats.iteritems():
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
                    total_res[ns]["master-objects"] = 0
                    total_res[ns]["prole-objects"] = 0
                    total_res[ns]["used-bytes-memory"] = 0
                    total_res[ns]["used-bytes-disk"] = 0
                    total_res[ns]["evicted-objects"] = 0
                    total_res[ns]["migrate-tx-partitions-remaining"] = 0
                    total_res[ns]["migrate-rx-partitions-remaining"] = 0
                try:
                    total_res[ns]["master-objects"] += int(ns_stats["master-objects"])
                except:
                    pass
                try:
                    total_res[ns]["prole-objects"] += int(ns_stats["prole-objects"])
                except:
                    pass

                try:
                    total_res[ns]["used-bytes-memory"] += int(ns_stats["used-bytes-memory"])
                except:
                    pass
                try:
                    total_res[ns]["used-bytes-disk"] += int(ns_stats["used-bytes-disk"])
                except:
                    pass

                try:
                    total_res[ns]["evicted-objects"] += int(ns_stats["evicted-objects"])
                except:
                    pass

                try:
                    total_res[ns]["migrate-tx-partitions-remaining"] += int(ns_stats["migrate-tx-partitions-remaining"])
                except:
                    pass

                try:
                    total_res[ns]["migrate-rx-partitions-remaining"] += int(ns_stats["migrate-rx-partitions-remaining"])
                except:
                    pass

                row['namespace'] = ns
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                t.insertRow(row)

        for ns in total_res:
            row = {}
            row['node'] = " "
            row['available_pct'] = " "
            row["repl-factor"] = " "
            row["stop-writes"] = " "
            row["evicted-objects"] = " "
            row["high-water-disk-pct"] = " "
            row["free-pct-disk"] = " "
            row["free-pct-memory"] = " "
            row["high-water-memory-pct"] = " "
            row["stop-writes-pct"] = " "

            row['namespace'] = ns
            row["master-objects"] = str(total_res[ns]["master-objects"])
            row["prole-objects"] = str(total_res[ns]["prole-objects"])
            row["used-bytes-memory"] = str(total_res[ns]["used-bytes-memory"])
            row["used-bytes-disk"] = str(total_res[ns]["used-bytes-disk"])
            row["evicted-objects"] = str(total_res[ns]["evicted-objects"])
            row["migrate-tx-partitions-remaining"] = str(total_res[ns]["migrate-tx-partitions-remaining"])
            row["migrate-rx-partitions-remaining"] = str(total_res[ns]["migrate-rx-partitions-remaining"])
            t.insertRow(row)

        #print t
        CliView.print_result(t)

    @staticmethod
    def infoSet(stats, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Set Information"
        column_names = ( 'set'
                        , 'namespace'
                        , 'node'
                        , 'set-delete'
                        , ('_n-bytes-memory', 'Mem used')
                        , ('_n_objects', 'Objects')
                        , 'stop-writes-count'
                        , 'disable-eviction'
                        , 'set-enable-xdr'
                        )

        t = Table(title, column_names, sort_by=1, group_by=0)
        t.addDataSource('_n-bytes-memory'
                        ,Extractors.byteExtractor('n-bytes-memory'))
        t.addDataSource('_n_objects'
                        ,Extractors.sifExtractor('n_objects'))

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addCellAlert('set'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('namespace'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('_n-bytes-memory'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)
        t.addCellAlert('_n_objects'
                       ,lambda data: data['node'] is " "
                       , color=terminal.bg_yellow)

        total_res = {}
        for node_key, s_stats in stats.iteritems():
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
                    total_res[(ns,set)]["n-bytes-memory"] += int(set_stats["n-bytes-memory"])
                except:
                    pass
                try:
                    total_res[(ns,set)]["n_objects"] += int(set_stats["n_objects"])
                except:
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

        #print t
        CliView.print_result(t)

    @staticmethod
    def infoXDR(stats, builds, xdr_enable, cluster, **ignore):
        if not max(xdr_enable.itervalues()):
            return

        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "XDR Information"
        column_names = ('node'
                        ,'build'
                        ,('_bytes-shipped', 'Data Shipped')
                        ,'_free-dlog-pct'
                        ,('_lag-secs', 'Lag (sec)')
                        ,'_req-outstanding'
                        ,'_req-relog'
                        ,'_req-shipped'
                        ,'cur_throughput'
                        ,('latency_avg_ship', 'Avg Latency (ms)')
                        ,'_xdr-uptime')

        t = Table(title, column_names, group_by=1)

        t.addDataSource('_xdr-uptime', Extractors.timeExtractor(
            ('xdr-uptime', 'xdr_uptime')))

        t.addDataSource('_bytes-shipped',
                        Extractors.byteExtractor(
                            ('esmt-bytes-shipped', 'esmt_bytes_shipped')))

        t.addDataSource('_lag-secs',
                        Extractors.timeExtractor('timediff_lastship_cur_secs'))

        t.addDataSource('_req-outstanding',
                        Extractors.sifExtractor('stat_recs_outstanding'))

        t.addDataSource('_req-relog',
                        Extractors.sifExtractor('stat_recs_relogged'))

        t.addDataSource('_req-shipped',
                        Extractors.sifExtractor('stat_recs_shipped'))

        # Highligh red if lag is more than 30 seconds
        t.addCellAlert('_lag-secs'
                       , lambda data: int(data['timediff_lastship_cur_secs']) >= 300)

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
                    if 'free_dlog_pct' in row:
                        row['_free-dlog-pct'] = row['free_dlog_pct'][:-1]
                    else:
                        row['_free-dlog-pct'] = row['free-dlog-pct'][:-1]
                else:
                    row = {}
                    row['node-id'] = node.node_id
                row['real_node_id'] = node.node_id
            else:
                continue

            row['node'] = prefixes[node_key]

            t.insertRow(row)
        #print t
        CliView.print_result(t)

    @staticmethod
    def infoDC(stats, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "DC Information"
        column_names = ('node'
                        ,('DC_Name','DC')
                        ,('xdr_dc_size','DC size')
                        ,'namespaces'
                        ,('_lag-secs', 'Lag (sec)')
                        ,('xdr_dc_remote_ship_ok', 'Records Shipped')
                        ,('latency_avg_ship_ema', 'Avg Latency (ms)')
                        ,('_xdr-dc-state', 'Status')
                        )

        t = Table(title, column_names, group_by=1)

        t.addDataSource('_lag-secs',
                        Extractors.timeExtractor(('xdr-dc-timelag','xdr_dc_timelag')))

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
                    if 'xdr_dc_state' in row:
                        row['_xdr-dc-state'] = row['xdr_dc_state']
                    else:
                        row['_xdr-dc-state'] = row['xdr-dc-state']
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                t.insertRow(row)
        #print t
        CliView.print_result(t)

    @staticmethod
    def infoSIndex(stats, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Secondary Index Information"
        column_names = ('node'
                        , ('indexname', 'Index Name')
                        ,('ns', 'Namespace')
                        , 'set'
                        , 'bins'
                        , 'num_bins'
                        , ('type', 'Bin Type')
                        , 'state'
                        , 'sync_state'
                        , 'keys'
                        , 'objects'
                        , ('ibtr_memory_used','si_accounted_memory')
                        , ('query_reqs','q')
                        , ('stat_write_success','w')
                        , ('stat_delete_success','d')
                        , ('query_avg_rec_count', 's'))

        t = Table(title, column_names, group_by=1)
        for stat in stats.values():
            for node_key, n_stats in stat.iteritems():
                node = prefixes[node_key]
                if isinstance(n_stats, Exception):
                    row = {}
                else:
                    row = n_stats
                row['node'] = node
                t.insertRow(row)

        #print t
        CliView.print_result(t)


    @staticmethod
    def showDistribution(title
                         , histogram
                         , unit
                         , hist
                         , cluster
                         , like=None
                         , **ignore):
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

            t = Table("%s - %s in %s"%(namespace, title, unit)
                      , columns
                      , description=description)
            if hist is "objsz":
                for column in percentages:
                    t.addDataSource(column, Extractors.byteExtractor(column))
            for node_id, data in node_data.iteritems():
                percentiles = data['percentiles']
                row = {}
                row['node'] = prefixes[node_id]
                for percent in percentages:
                    row[percent] = percentiles.pop(0)

                t.insertRow(row)

            #print t
            CliView.print_result(t)

    @staticmethod
    def showLatency(latency, cluster, like=None, **ignore):
        prefixes = cluster.getNodeNames()

        if like:
            likes = CliView.compileLikes(like)

            histograms = set(filter(likes.search, latency.keys()))
        else:
            histograms = set(latency.keys())

        for hist_name, node_data in sorted(latency.iteritems()):
            if hist_name not in histograms:
                continue

            title = "%s Latency"%(hist_name)
            all_columns = set()

            for _, (columns, _) in node_data.iteritems():
                for column in columns:
                    if column[0] == '>':
                        column = int(column[1:-2])
                        all_columns.add(column)

            all_columns = [">%sms"%(c) for c in sorted(all_columns)]
            all_columns.insert(0, 'ops/sec')
            all_columns.insert(0, 'Time Span')
            all_columns.insert(0, 'node')

            t = Table(title, all_columns)

            for node_id, (columns, data) in node_data.iteritems():
                node_data = dict(itertools.izip(columns, data))
                node_data['node'] = prefixes[node_id]
                t.insertRow(node_data)

            #print t
            CliView.print_result(t)

    @staticmethod
    def showConfig(title, service_configs, cluster, like=None, diff=None, show_total=False, **ignore):
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
                        except:
                            rowTotal[key] = int(val)
        if show_total:
            rowTotal['NODE'] = "Total"
            t.insertRow(rowTotal)

        #print t
        CliView.print_result(t)

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
        #print t
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
        #print t
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
        except:
            pass
        else:
            try:
                num_iterations = int(line[0])
                line.pop(0)
            except:
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
                                    result += terminal.bg_clear()
                                    highlight = False
                            elif prev_group == next_group:
                                if highlight:
                                    result += terminal.bg_clear()
                                    highlight = False
                            else:
                                if not highlight:
                                    result += terminal.bg_blue()
                                    highlight = True

                            result += next_group

                            if '\n' == prev_group and '\n' != next_group:
                                continue
                            break

                    for next_group in next_iterator:
                        if next_group == ' ' or next_group == '\n':
                            if highlight:
                                result += terminal.bg_clear()
                                highlight = False
                        else:
                            if not highlight:
                                result += terminal.bg_blue()
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
