# Copyright 2013-2014 Aerospike, Inc.
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

class CliView(object):
    @staticmethod
    def compileLikes(likes):
        likes = map(re.escape, likes)
        likes = "|".join(likes)
        likes = re.compile(likes)
        return likes

    @staticmethod
    def infoService(stats, builds, visibilities, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Service Information"
        column_names = ('node'
                        , 'build'
                        , 'cluster_size'
                        , 'cluster_visibility'
                        , '_cluster_integrity'
                        , ('free-pct-disk', 'Free Disk%')
                        , ('free-pct-memory', 'Free Mem%')
                        , ('_migrates', 'Migrates (tx,rx,a)')
                        , ('_paxos_principal', 'Principal')
                        , '_objects'
                        , '_uptime')

        t = Table(title, column_names)
        t.addDataSource('_migrates'
                        ,lambda data:
                        "(%s,%s,%s)"%(row.get('tx_migrations', 'N/E')
                                      , row.get('rx_migrations', 'N/E')
                                      , int(row.get('migrate_progress_send',0)) + int(row.get('migrate_progress_recv',0))
                                            if (row.has_key('migrate_progress_send')
                                                and row.has_key('migrate_progress_recv')) else 'N/E'))
        t.addDataSource('_objects'
                        ,Extractors.sifExtractor('objects'))
        t.addDataSource('_cluster_integrity'
                        , lambda data:
                        True if row['cluster_integrity'] == 'true' else False)
        t.addDataSource('_uptime', Extractors.timeExtractor('uptime'))

        t.addCellAlert('cluster_visibility'
                       , lambda data: data['cluster_visibility'] is not True)

        t.addCellAlert('_cluster_integrity'
                       ,lambda data: data['cluster_integrity'] != 'true')

        t.addCellAlert('free-pct-disk'
                       ,lambda data: int(data['free-pct-disk']) < 40)

        t.addCellAlert('free-pct-memory'
                       ,lambda data: int(data['free-pct-memory']) < 40)

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        for node_key, n_stats in stats.iteritems():
            if isinstance(n_stats, Exception):
                n_stats = {}

            node = cluster.getNode(node_key)[0]
            row = n_stats
            row['real_node_id'] = node.node_id
            row['node'] = prefixes[node_key]
            try:
                paxos_node = cluster.getNode(row['paxos_principal'])[0]
                row['_paxos_principal'] = prefixes[paxos_node.key]
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

            if node_key in visibilities:
                row['cluster_visibility'] = visibilities[node_key]

            t.insertRow(row)

        print t

    @staticmethod
    def infoNetwork(stats, hosts, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Network Information"
        column_names = ('node'
                        , 'node_id'
                        , 'fqdn'
                        , 'ip'
                        , ('client_connections', 'Client Conns')
                        , 'current-time'
                        , ('heartbeat_received_self', 'HB Self')
                        , ('heartbeat_received_foreign', 'HB Foreign'))

        principal = cluster.getExpectedPrincipal()

        t = Table(title, column_names)

        t.addCellAlert('node_id'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

        for node_key, n_stats in stats.iteritems():
            if isinstance(n_stats, Exception):
                n_stats = {}
            node = cluster.getNode(node_key)[0]
            row = n_stats
            row['node'] = prefixes[node_key]
            row['real_node_id'] = node.node_id
            row['node_id'] = node.node_id if node.node_id != principal else "*%s"%(node.node_id)
            row['fqdn'] = hosts[node_key].sockName(use_fqdn = True)
            row['ip'] = hosts[node_key].sockName(use_fqdn = False)
            t.insertRow(row)
        print t

    @staticmethod
    def infoNamespace(stats, cluster, **ignore):
        prefixes = cluster.getNodeNames()
        principal = cluster.getExpectedPrincipal()

        title = "Namespace Information"
        column_names = ('node'
                        , 'namespace'
                        , ('available_pct', 'Avail%')
                        , ('evicted-objects', 'Evictions')
                        , ('_master-objects', 'Master Objects')
                        , ('_prole-objects', 'Replica Objects')
                        , 'repl-factor'
                        , 'stop-writes'
                        , ('_used-bytes-disk', 'Disk Used')
                        , ('_used-disk-pct', 'Disk Used%')
                        , ('high-water-disk-pct', 'HWM Disk%')
                        , ('_used-bytes-memory', 'Mem Used')
                        , ('_used-mem-pct', 'Mem Used%')
                        , ('high-water-memory-pct', 'HWM Mem%')
                        , ('stop-writes-pct', 'Stop Writes%'))

        t = Table(title, column_names, group_by=1)
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
                        , lambda data: 100 - int(data['free-pct-disk']))

        t.addDataSource('_used-mem-pct'
                        , lambda data: 100 - int(data['free-pct-memory']))

        t.addCellAlert('available_pct'
                       , lambda data: int(data['available_pct']) <= 10)

        t.addCellAlert('stop-writes'
                       , lambda data: data['stop-writes'] != 'false')

        t.addCellAlert('_used-disk-pct'
                       , lambda data: int(data['_used-disk-pct']) >= int(data['high-water-disk-pct']))

        t.addCellAlert('_used-mem-pct'
                       , lambda data: (100 - int(data['free-pct-memory'])) >= int(data['high-water-memory-pct']))

        t.addCellAlert('_used-disk-pct'
                       , lambda data: (100 - int(data['free-pct-disk'])) >= int(data['high-water-disk-pct']))

        t.addCellAlert('node'
                       ,lambda data: data['real_node_id'] == principal
                       , color=terminal.fg_green)

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

                row['namespace'] = ns
                row['real_node_id'] = node.node_id
                row['node'] = prefixes[node_key]
                t.insertRow(row)
        print t

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

        t = Table(title, column_names)

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
        print t

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
                        , 'sync_state')

        t = Table(title, column_names, group_by=1)

        for node_key, n_stats in stats.iteritems():
            node = prefixes[node_key]
            for index_stats in n_stats:
                if isinstance(index_stats, Exception):
                    row = {}
                else:
                    row = index_stats

                row['node'] = node
                t.insertRow(row)

        print t


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
            for node_id, data in node_data.iteritems():
                percentiles = data['percentiles']
                row = {}
                row['node'] = prefixes[node_id]
                for percent in percentages:
                    row[percent] = percentiles.pop(0)

                t.insertRow(row)

            print t

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

            print t

    @staticmethod
    def showConfig(title, service_configs, cluster, like=None, diff=None, **ignore):
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
        for node_id, row in service_configs.iteritems():
            if isinstance(row, Exception):
                row = {}

            row['NODE'] = prefixes[node_id]
            t.insertRow(row)

        print t

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
