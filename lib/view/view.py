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
from lib.utils.util import (compile_likes, find_delimiter_in)
from lib.view import sheet, terminal
from lib.view.sheet import (Aggregators, Converters, Field, FieldAlignment,
                            FieldType, Formatters, Projectors, Sheet,
                            TupleField)
from lib.view.table import Extractors, Styles, Table, TitleFormats

H1_offset = 13
H2_offset = 15
H_width = 80

# Common set of fields.
cluster_field = Field('Cluster',
                      Projectors.Func(FieldType.string,
                                      lambda c: c if c != 'null' else None,
                                      Projectors.String('cluster_names', None)),
                      key='cluster_name')
node_field = Field('Node', Projectors.String('prefixes', None),
                   formatters=(Formatters.green_alert(
                       lambda edata: edata.record['Node ID'] == edata.common['principal']),))
hidden_node_id_field = Field('Node ID',
                             Projectors.String('node_ids', None), hidden=True)
namespace_field = Field('Namespace', Projectors.String('ns_stats', None, for_each_key=True))


def project_build(b, v):
    if 'community' in v.lower():
        return 'C-' + b

    if 'enterprise' in v.lower():
        return 'E-' + b

    return b


network_sheet = Sheet(
    (cluster_field,
     node_field,
     Field('Node ID', Projectors.String('node_ids', None),
           converter=(lambda edata: '*' + edata.value
                      if edata.value == edata.common['principal']
                      else edata.value),
           formatters=(Formatters.green_alert(
               lambda edata: edata.record['Node ID'] == edata.common['principal']),),
           align=FieldAlignment.right),
     Field('IP', Projectors.String('hosts', None)),
     Field('Build',
           Projectors.Func(
               FieldType.string,
               project_build,
               Projectors.String('builds', None),
               Projectors.String('versions', None))),
     Field('Migrations',
           Projectors.Number('stats', 'migrate_partitions_remaining'),
           converter=Converters.sif),
     TupleField(
         'Cluster',
         (Field('Size', Projectors.Number('stats', 'cluster_size')),
          Field('Key', Projectors.String('stats', 'cluster_key'),
                align=FieldAlignment.right),
          Field('Integrity', Projectors.Boolean('stats', 'cluster_integrity'),
                formatters=(Formatters.red_alert(
                    lambda edata: not edata.value),)),
          Field('Principal', Projectors.String('stats', 'paxos_principal'),
                align=FieldAlignment.right))),
     Field('Client Conns', Projectors.Number('stats', 'client_connections')),
     Field('Uptime', Projectors.Number('stats', 'uptime'),
           converter=Converters.time)),
    from_source=('cluster_names', 'prefixes', 'node_ids', 'hosts', 'builds',
                 'versions', 'stats'),
    group_by='cluster_name',
    order_by='Node'
)

namespace_usage_sheet = Sheet(
    (cluster_field,
     namespace_field,
     node_field,
     hidden_node_id_field,
     Field('Total Records',
           Projectors.Sum(
               Projectors.Number('ns_stats',
                                 'master_objects', 'master-objects'),
               Projectors.Number('ns_stats', 'master_tombstones'),
               Projectors.Number('ns_stats', 'prole_objects', 'prole-objects'),
               Projectors.Number('ns_stats', 'non_replica_objects'),
               Projectors.Number('ns_stats', 'non_replica_tombstones')),
           converter=Converters.sif,
           aggregator=Aggregators.sum()),
     Field('Expirations',
           Projectors.Number('ns_stats', 'expired_objects', 'expired-objects'),
           converter=Converters.sif,
           aggregator=Aggregators.sum()),
     Field('Evictions',
           Projectors.Number('ns_stats', 'evicted_objects', 'evicted-objects'),
           converter=Converters.sif,
           aggregator=Aggregators.sum()),
     Field('Stop Writes',
           Projectors.Boolean('ns_stats', 'stop_writes', 'stop-writes'),
           formatters=(Formatters.red_alert(
               lambda edata: edata.value),)),
     TupleField(
         'Disk',
         (Field('Used',
                Projectors.Number('ns_stats',
                                  'device_used_bytes', 'used-bytes-disk'),
                converter=Converters.byte,
                aggregator=Aggregators.sum()),
          Field('Used%',
                Projectors.Percent('ns_stats',
                                   'device_free_pct', 'free_pct_disk',
                                   invert=True),
                formatters=(Formatters.yellow_alert(
                    lambda edata: edata.value >= edata.record['HWM Disk%']),)),
          Field('HWM%',
                Projectors.Number('ns_stats', 'high-water-disk-pct')),
          Field('Avail%',
                Projectors.Number('ns_stats',
                                  'device_available_pct', 'available_pct'),
                formatters=(Formatters.red_alert(
                    lambda edata: edata.value < 10),)))),
     TupleField(
         'Memory',
         (Field('Used', Projectors.Number('ns_stats', 'memory_used_bytes'),
                converter=Converters.byte,
                aggregator=Aggregators.sum()),
          Field('Used%',
                Projectors.Percent('ns_stats',
                                   'memory_free_pct', 'free_pct_memory',
                                   invert=True),
                formatters=(Formatters.yellow_alert(
                    lambda edata: edata.value > edata.record['HWM Mem%']),)),
          Field('HWM%',
                Projectors.Number('ns_stats', 'high-water-memory-pct')),
          Field('Stop%',
                Projectors.Number('ns_stats', 'stop-writes-pct'))))),
    from_source=('cluster_names', 'node_ids', 'prefixes', 'ns_stats'),
    for_each='ns_stats',
    group_by=('cluster_name', 'Namespace'),
    order_by='Node'
)

namespace_object_sheet = Sheet(
    (cluster_field,
     namespace_field,
     node_field,
     hidden_node_id_field,
     Field('Rack ID', Projectors.Number('ns_stats', 'rack-id')),
     Field('Repl Factor', Projectors.Number(
         'ns_stats',
         'effective_replication_factor',  # introduced post 3.15.0.1
         'replication-factor',
         'repl-factor')),
     Field('Total Records',
           Projectors.Sum(
               Projectors.Number('ns_stats',
                                 'master_objects', 'master-objects'),
               Projectors.Number('ns_stats', 'master_tombstones'),
               Projectors.Number('ns_stats', 'prole_objects', 'prole-objects'),
               Projectors.Number('ns_stats', 'prole_tombstones'),
               Projectors.Number('ns_stats', 'non_replica_objects'),
               Projectors.Number('ns_stats', 'non_replica_tombstones')),
           converter=Converters.sif,
           aggregator=Aggregators.sum()),
     TupleField(
         'Objects',
         (Field('Master',
                Projectors.Number('ns_stats',
                                  'master_objects', 'master-objects'),
                converter=Converters.sif, aggregator=Aggregators.sum()),
          Field('Prole',
                Projectors.Number('ns_stats', 'prole_objects', 'prole-objects'),
                converter=Converters.sif, aggregator=Aggregators.sum()),
          Field('Non-Replica',
                Projectors.Number('ns_stats', 'non_replica_objects'),
                converter=Converters.sif, aggregator=Aggregators.sum()))),
     TupleField(
         'Tombstones',
         (Field('Master',
                Projectors.Number('ns_stats', 'master_tombstones'),
                converter=Converters.sif, aggregator=Aggregators.sum()),
          Field('Prole', Projectors.Number('ns_stats', 'prole_tombstones'),
                converter=Converters.sif, aggregator=Aggregators.sum()),
          Field('Non-Replica',
                Projectors.Number('ns_stats', 'non_replica_tombstones'),
                converter=Converters.sif, aggregator=Aggregators.sum()))),
     TupleField(
         'Pending Migrates',
         (Field('Tx',
                Projectors.Number(
                    'ns_stats',
                    'migrate_tx_partitions_remaining',
                    'migrate-tx-partitions-remaining'),
                converter=Converters.sif, aggregator=Aggregators.sum()),
          Field('Rx',
                Projectors.Number(
                    'ns_stats',
                    'migrate_rx_partitions_remaining',
                    'migrate-rx-partitions-remaining'),
                converter=Converters.sif, aggregator=Aggregators.sum())))),
    from_source=('cluster_names', 'node_ids', 'prefixes', 'ns_stats'),
    for_each='ns_stats',
    group_by=('cluster_name', 'Namespace'),
    order_by='Node'
)

set_sheet = Sheet(
    (cluster_field,
     Field('Namespace', Projectors.String('set_stats', 0, for_each_key=True)),
     Field('Set', Projectors.String('set_stats', 1, for_each_key=True)),
     node_field,
     hidden_node_id_field,
     Field('Set Delete',
           Projectors.Boolean('set_stats', 'deleting', 'set-delete')),
     Field('Mem Used',
           Projectors.Number('set_stats',
                             'memory_data_bytes', 'n-bytes-memory'),
           converter=Converters.byte,
           aggregator=Aggregators.sum()),
     Field('Objects', Projectors.Number('set_stats', 'objects', 'n_objects'),
           converter=Converters.sif,
           aggregator=Aggregators.sum()),
     Field('Stop Writes Count',
           Projectors.Number('set_stats', 'stop-writes-count')),
     Field('Disable Eviction',
           Projectors.Boolean('set_stats', 'disable-eviction')),
     Field('Set Enable XDR', Projectors.String('set_stats', 'set-enable-xdr'))),
    from_source=('cluster_names', 'node_ids', 'prefixes', 'set_stats'),
    for_each='set_stats',
    group_by=('cluster_name', 'Namespace', 'Set'),
    order_by='Node'
)


def project_xdr_free_dlog(s):
    return int(s.translate(None, '%'))


def project_xdr_req_shipped_success(s, rs, esc, ess):
    if s is not None:
        return s

    return rs - esc - ess


def project_xdr_req_shipped_errors(s, esc, ess):
    if s is not None:
        return s

    return esc + ess


xdr_sheet = Sheet(
    (Field('XDR Enabled', Projectors.Boolean('xdr_enable', None), hidden=True),
     node_field,
     hidden_node_id_field,
     Field('Build', Projectors.String('builds', None)),
     Field('Data Shipped',
           Projectors.Number('xdr_stats',
                             'xdr_ship_bytes',
                             'esmt_bytes_shipped',
                             'esmt-bytes-shipped'),
           converter=Converters.byte, aggregator=Aggregators.sum()),
     Field('Free DLog%',
           Projectors.Func(
               FieldType.number,
               project_xdr_free_dlog,
               Projectors.String('xdr_stats',
                                 'dlog_free_pct',
                                 'free-dlog-pct',
                                 'free_dlog_pct'))),
     Field('Lag (sec)',
           Projectors.Number('xdr_stats',
                             'xdr_timelag', 'timediff_lastship_cur_secs'),
           converter=Converters.time,
           formatters=(
               Formatters.red_alert(lambda edata: edata.value >= 300),)),
     TupleField(
         'Records',
         (Field('Outstanding',
                Projectors.Number('xdr_stats',
                                  'xdr_ship_outstanding_objects',
                                  'stat_recs_outstanding'),
                converter=Converters.sif, aggregator=Aggregators.sum()),
          Field('Shipped Success',
                Projectors.Func(
                    FieldType.number,
                    project_xdr_req_shipped_success,
                    Projectors.Number('xdr_stats',
                                      'xdr_ship_success',
                                      'stat_recs_shipped_ok'),
                    Projectors.Number('xdr_stats',
                                      'stat_recs_shipped', 'stat-recs-shipped'),
                    Projectors.Number('xdr_stats',
                                      'err_ship_client', 'error-ship-client'),
                    Projectors.Number('xdr_stats',
                                      'err_ship_server', 'err-ship-server')),
                aggregator=Aggregators.sum()),
          Field('Shipped Errors',
                Projectors.Func(
                    FieldType.number,
                    project_xdr_req_shipped_errors,
                    Projectors.Number('xdr_stats', 'stat_recs_ship_errors'),
                    Projectors.Number('xdr_stats',
                                      'err_ship_client', 'err-ship-client',
                                      'xdr_ship_source_error'),
                    Projectors.Number('xdr_stats',
                                      'err_ship_server', 'err-ship-server',
                                      'xdr_ship_destination_error')),
                aggregator=Aggregators.sum()))),
     Field('Throughput',
           Projectors.Number('xdr_stats', 'xdr_throughput', 'cur_throughput'),
           aggregator=Aggregators.sum()),
     Field('Avg Latency (ms)',
           Projectors.Number('xdr_stats',
                             'xdr_ship_latency_avg', 'latency_avg_ship')),
     Field('XDR Uptime',  # obsolete since 3.11.1.1
           Projectors.Number('xdr_stats', 'xdr_uptime', 'xdr-uptime'),
           converter=Converters.time)),
    from_source=('xdr_enable', 'node_ids', 'prefixes', 'builds', 'xdr_stats'),
    where=lambda record: record['XDR Enabled'],
    order_by='Node'
)

xdr_dc_sheet = Sheet(
    (node_field,
     hidden_node_id_field,
     Field('DC', Projectors.String('dc_stats', 'dc-name', 'DC_Name')),
     Field('DC Size', Projectors.Number('dc_stats', 'xdr_dc_size', 'dc_size')),
     Field('Namespaces', Projectors.String('dc_stats', 'namespaces')),
     Field('Lag',
           Projectors.Number('dc_stats', 'xdr_dc_timelag', 'xdr-dc-timelag',
                             'dc_timelag'),
           converter=Converters.time),
     Field('Records Shipped',
           Projectors.Number('dc_stats',
                             'xdr_dc_remote_ship_ok', 'dc_remote_ship_ok',
                             'dc_recs_shipped_ok', 'dc_ship_success')),
     Field('Avg Latency (ms)',
           Projectors.Number('dc_stats',
                             'latency_avg_ship_ema', 'dc_latency_avg_ship',
                             'dc_latency_avg_ship_ema', 'dc_ship_latency_avg')),
     Field('Status',
           Projectors.Number('dc_stats',
                             'xdr_dc_state', 'xdr-dc-state', 'dc_state'))),
    from_source=('node_ids', 'prefixes', 'dc_stats'),
    for_each='dc_stats',
    where=lambda record: record['DC'],
    group_by=('DC', 'Namespaces'),
    order_by='Node'
)

sindex_sheet = Sheet(
    (Field('Index Name', Projectors.String('sindex_stats', 'indexname')),
     Field('Namespace', Projectors.String('sindex_stats', 'ns')),
     Field('Set', Projectors.String('sindex_stats', 'set')),
     node_field,
     hidden_node_id_field,
     Field('Bins', Projectors.Number('sindex_stats', 'bins', 'bin')),
     Field('Num Bins', Projectors.Number('sindex_stats', 'num_bins')),
     Field('Bin Type', Projectors.String('sindex_stats', 'type')),
     Field('State', Projectors.String('sindex_stats', 'state')),
     Field('Sync State', Projectors.String('sindex_stats', 'sync_state')),
     Field('Keys', Projectors.Number('sindex_stats', 'keys')),
     Field('Entries', Projectors.Number('sindex_stats', 'entries', 'objects'),
           converter=Converters.sif, aggregator=Aggregators.sum()),
     Field('Memory Used',
           Projectors.Number('sindex_stats', 'si_accounted_memory'),
           converter=Converters.byte, aggregator=Aggregators.sum()),
     TupleField(
         'Queries',
         (Field('Requests', Projectors.Number('sindex_stats', 'query_reqs'),
                converter=Converters.sif, aggregator=Aggregators.sum()),
          Field('Avg Num Recs',
                Projectors.Number('sindex_stats', 'query_avg_rec_count'),
                converter=Converters.sif, aggregator=Aggregators.sum()))),
     TupleField(
         'Updates',
         (Field('Writes',
                Projectors.Number('sindex_stats',
                                  'write_success', 'stat_write_success'),
                converter=Converters.sif, aggregator=Aggregators.sum()),
          Field('Deletes',
                Projectors.Number('sindex_stats',
                                  'delete_success', 'stat_delete_success'),
                converter=Converters.sif, aggregator=Aggregators.sum())))),
    from_source=('node_ids', 'prefixes', 'sindex_stats'),
    for_each='sindex_stats',
    group_by=('Index Name', 'Namespace', 'Set'),
    order_by='Node'
)


distribution_sheet = Sheet(
    tuple(itertools.chain(
        [Field('Node', Projectors.String('prefixes', None))],
        [Field('{}%'.format(pct), Projectors.Number('histogram', i))
         for i, pct in enumerate(range(10, 110, 10))])),
    from_source=('prefixes', 'histogram'),
    order_by='Node'
)


summary_namespace_sheet = Sheet(
    (Field('Namespace', Projectors.String('ns_stats', None),
           Formatters.red_alert(
               lambda edata: edata.record['active_migrations'])),
     Field('active_migrations', Projectors.Boolean('ns_stats',
                                                   'migrations_in_progress'),
           hidden=True),
     TupleField('Devices',
                (Field('Total', Projectors.Number('ns_stats', 'devices_total')),
                 Field('Per-Node', Projectors.Number('ns_stats',
                                                     'devices_per_node')))),
     TupleField('Memory',
                (Field('Total', Projectors.Number('ns_stats', 'memory_total'),
                       converter=Converters.byte),
                 Field('Used%',
                       Projectors.Percent('ns_stats',
                                          'memory_available_pct', invert=True)),
                 Field('Avail%', Projectors.Number('ns_stats',
                                                   'memory_available_pct'),
                       converter=Converters.byte))),
     TupleField('Disk',
                (Field('Total', Projectors.Number('ns_stats', 'disk_total'),
                       converter=Converters.byte),
                 Field('Used%', Projectors.Number('ns_stats', 'disk_used_pct')),
                 Field('Avail%', Projectors.Number('ns_stats',
                                                   'disk_available_pct'),
                       converter=Converters.byte))),
     Field('Replication Factors',
           Projectors.Func(FieldType.string,
                           lambda *v: ','.join(map(str, v[0])),
                           Projectors.String('ns_stats', 'repl_factor')),
           align=FieldAlignment.right),
     Field('Cache Read%', Projectors.Number('ns_stats', 'cache_read_pct')),
     Field('Master Objects', Projectors.Number('ns_stats', 'master_objects'),
           Converters.sif),
     TupleField('Usage (Unique-Data)',
                (Field('In-Memory',
                       Projectors.Number('ns_stats', 'license_data_in_memory'),
                       Converters.byte),
                 Field('On-Disk',
                       Projectors.Number('ns_stats', 'license_data_on_disk'),
                       Converters.byte)))),
    from_source=('ns_stats',),
    order_by='Namespace'
)

pmap_sheet = Sheet(
    (Field('Namespace', Projectors.String('pmap', None, for_each_key=True)),
     node_field,
     hidden_node_id_field,
     Field('Cluster Key', Projectors.Number('pmap', 'cluster_key')),
     Field('Primary Partitions',
           Projectors.Number('pmap', 'master_partition_count'),
           aggregator=Aggregators.sum()),
     Field('Secondary Partitions',
           Projectors.Number('pmap', 'prole_partition_count'),
           aggregator=Aggregators.sum()),
     Field('Missing Partitions',
           Projectors.Number('pmap', 'missing_partition_count'),
           aggregator=Aggregators.sum())),
    from_source=('prefixes', 'node_ids', 'pmap'),
    for_each='pmap',
    group_by='Namespace',
    order_by='Node'
)

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

        return ' (' + str(timestamp) + ')'

    @staticmethod
    def info_network(stats, cluster_names, versions, builds, cluster,
                     timestamp='', **ignore):
        prefixes = cluster.get_node_names()
        hosts = cluster.nodes

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Network Information' + title_suffix
        sources = dict(
            cluster_names=cluster_names,
            prefixes=prefixes,
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.iterkeys())),
            hosts=dict(((k, h.sock_name(use_fqdn=False))
                        for k, h in hosts.iteritems())),
            builds=builds,
            versions=versions,
            stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(network_sheet, title, sources, common=common))

    @staticmethod
    def info_namespace_usage(stats, cluster, timestamp='', **ignore):
        prefixes = cluster.get_node_names()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Namespace Usage Information' + title_suffix
        sources = dict(
            # TODO - collect cluster-name.
            cluster_names=dict([(k, None) for k in stats.iterkeys()]),
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.iterkeys())),
            prefixes=prefixes,
            ns_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(namespace_usage_sheet, title, sources, common=common))

    @staticmethod
    def info_namespace_object(stats, cluster, timestamp='', **ignore):
        prefixes = cluster.get_node_names()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Namespace Object Information' + title_suffix
        sources = dict(
            # TODO - collect cluster-name.
            cluster_names=dict([(k, None) for k in stats.iterkeys()]),
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.iterkeys())),
            prefixes=prefixes,
            ns_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(namespace_object_sheet, title, sources, common=common))

    @staticmethod
    def info_set(stats, cluster, timestamp='', **ignore):
        prefixes = cluster.get_node_names()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Set Information%s' + title_suffix
        sources = dict(
            # TODO - collect cluster-name.
            cluster_names=dict([(k, None) for k in stats.iterkeys()]),
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.iterkeys())),
            prefixes=prefixes,
            set_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(set_sheet, title, sources, common=common))

    @staticmethod
    def info_XDR(stats, builds, xdr_enable, cluster, timestamp='', **ignore):
        if not any(xdr_enable.itervalues()):
            return

        prefixes = cluster.get_node_names()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'XDR Information' + title_suffix
        sources = dict(
            xdr_enable=xdr_enable,
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.iterkeys())),
            prefixes=prefixes,
            builds=builds,
            xdr_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(xdr_sheet, title, sources, common=common))

    @staticmethod
    def info_dc(stats, cluster, timestamp='', **ignore):
        prefixes = cluster.get_node_names()

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'DC Information%s' % (title_suffix)
        sources = dict(
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.iterkeys())),
            prefixes=prefixes,
            dc_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(xdr_dc_sheet, title, sources, common=common))

    @staticmethod
    def info_sindex(stats, cluster, timestamp='', **ignore):
        # return if sindex stats are empty.
        if not stats:
            return

        # stats comes in {index:{node:{k:v}}}, needs to be {node:{index:{k:v}}}
        sindex_stats = {}

        for iname, nodes in stats.iteritems():
            for node, values in nodes.iteritems():
                sindex_stats[node] = node_stats = sindex_stats.get(node, {})
                node_stats[iname] = values

        prefixes = cluster.get_node_names()
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Secondary Index Information' + title_suffix
        sources = dict(
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.iterkeys())),
            prefixes=prefixes,
            sindex_stats=sindex_stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(sindex_sheet, title, sources, common=common))

    @staticmethod
    def show_grep(title, summary):
        if not summary or len(summary.strip()) == 0:
            return
        if title:
            print "************************** %s **************************" % (title)
        CliView.print_result(summary)

    @staticmethod
    def show_distribution(title, histogram, unit, hist, cluster, like=None,
                          timestamp="", **ignore):
        prefixes = cluster.get_node_names()
        likes = compile_likes(like)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        description = 'Percentage of records having {} less than or '.format(hist) + \
                      'equal to value measured in {}'.format(unit)
        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.iteritems():
            if namespace not in namespaces or not node_data or isinstance(node_data, Exception):
                continue

            this_title = '{} - {} in {}{}'.format(
                namespace, title, unit, title_suffix)
            sources = dict(
                prefixes=prefixes,
                histogram=dict((k, d['percentiles']) for k, d in node_data.iteritems())
            )

            CliView.print_result(
                sheet.render(distribution_sheet, this_title, sources,
                             description=description))

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
    def show_stats(*args, **kwargs):
        CliView.show_config(*args, **kwargs)

    @staticmethod
    def show_health(*args, **kwargs):
        CliView.show_config(*args, **kwargs)

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
        CliView.print_result(t.__str__(
            horizontal_title_every_nth=title_every_nth * (sub_columns_per_column + 1)))

    @staticmethod
    def show_mapping(col1, col2, mapping, like=None, timestamp="", **ignore):
        if not mapping:
            return

        column_names = [col1, col2]
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
    def show_pmap(pmap_data, cluster, timestamp='', **ignore):
        prefixes = cluster.get_node_names()
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Partition Map Analysis' + title_suffix
        sources = dict(
            prefixes=prefixes,
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.iterkeys())),
            pmap=pmap_data
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(sheet.render(pmap_sheet, title, sources, common=common))

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
        sources = dict(ns_stats=stats)
        CliView.print_result(
            sheet.render(summary_namespace_sheet, title, sources))

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
