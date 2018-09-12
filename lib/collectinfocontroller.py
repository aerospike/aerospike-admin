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

import copy

from lib.controllerlib import BaseController, CommandHelp, CommandController
from lib.collectinfo.loghdlr import CollectinfoLoghdlr
from lib.health.util import create_health_input_dict, h_eval, create_snapshot_key
from lib.utils.constants import *
from lib.utils import common, util
from lib.view import terminal
from lib.view.view import CliView


class CollectinfoCommandController(CommandController):

    loghdlr = None

    def __init__(self, loghdlr):
        CollectinfoCommandController.loghdlr = loghdlr


@CommandHelp('Aerospike Admin')
class CollectinfoRootController(BaseController):

    loghdlr = None
    command = None

    def __init__(self, asadm_version='', clinfo_path=" "):

        super(CollectinfoRootController, self).__init__(asadm_version)

        # Create Static Instance of Loghdlr
        CollectinfoRootController.loghdlr = CollectinfoLoghdlr(clinfo_path)

        CollectinfoRootController.command = CollectinfoCommandController(
            self.loghdlr)

        self.controller_map = {
            'list': ListController,
            'show': ShowController,
            'info': InfoController,
            'features': FeaturesController,
            'pager': PagerController,
            'health': HealthCheckController,
            'summary': SummaryController}

    def close(self):
        try:
            self.loghdlr.close()
        except Exception:
            pass

    @CommandHelp('Terminate session')
    def do_exit(self, line):
        # This function is a hack for autocomplete
        return "EXIT"

    @CommandHelp(
        'Returns documentation related to a command.',
        'for example, to retrieve documentation for the "info"',
        'command use "help info".')
    def do_help(self, line):
        self.execute_help(line)


@CommandHelp(
    'The "info" command provides summary tables for various aspects',
    'of Aerospike functionality.')
class InfoController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set()

        self.controller_map = dict(
            namespace=InfoNamespaceController)

    @CommandHelp(
        'Displays network, namespace, and xdr summary information.')
    def _do_default(self, line):
        self.do_network(line)
        self.controller_map['namespace']()(line[:])
        self.do_xdr(line)

    @CommandHelp(
        'Displays network summary information.')
    def do_network(self, line):
        service_stats = self.loghdlr.info_statistics(stanza=STAT_SERVICE)
        cluster_configs = self.loghdlr.info_getconfig(stanza=CONFIG_CLUSTER)
        for timestamp in sorted(service_stats.keys()):
            for node in service_stats[timestamp]:
                try:
                    if not isinstance(cluster_configs[timestamp][node]["mode"], Exception):
                        service_stats[timestamp][node]["rackaware_mode"] = cluster_configs[timestamp][node]["mode"]
                except Exception:
                    pass
            cinfo_log = self.loghdlr.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()
            versions = cinfo_log.get_asd_version()
            cluster_names = cinfo_log.get_cluster_name()

            # Note how cinfo_log mapped to cluster. Both implement interfaces
            # required by view object
            self.view.info_network(service_stats[timestamp], cluster_names,
                                   versions, builds, cluster=cinfo_log,
                                   timestamp=timestamp, **self.mods)

    def _convert_key_to_tuple(self, stats):
        for key in stats.keys():
            key_tuple = tuple(key.split())
            stats[key_tuple] = stats[key]
            del stats[key]

    @CommandHelp(
        'Displays set summary information.')
    def do_set(self, line):
        set_stats = self.loghdlr.info_statistics(stanza=STAT_SETS, flip=True)

        for timestamp in sorted(set_stats.keys()):
            if not set_stats[timestamp]:
                continue

            self._convert_key_to_tuple(set_stats[timestamp])
            self.view.info_set(util.flip_keys(set_stats[timestamp]),
                               self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                               timestamp=timestamp, **self.mods)

    @CommandHelp(
        'Displays Cross Datacenter Replication (XDR) summary information.')
    def do_xdr(self, line):
        xdr_stats = self.loghdlr.info_statistics(stanza=STAT_XDR)
        for timestamp in sorted(xdr_stats.keys()):
            if not xdr_stats[timestamp]:
                continue

            xdr_enable = {}
            cinfo_log = self.loghdlr.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_xdr_build()

            for xdr_node in xdr_stats[timestamp].keys():
                xdr_enable[xdr_node] = True

            self.view.info_XDR(xdr_stats[timestamp], builds, xdr_enable,
                               cluster=cinfo_log, timestamp=timestamp,
                               **self.mods)

    @CommandHelp(
        'Displays datacenter summary information.')
    def do_dc(self, line):
        dc_stats = self.loghdlr.info_statistics(stanza=STAT_DC, flip=True)
        dc_config = self.loghdlr.info_getconfig(stanza=CONFIG_DC, flip=True)
        for timestamp in sorted(dc_stats.keys()):
            if not dc_stats[timestamp]:
                continue

            for dc in dc_stats[timestamp].keys():
                try:
                    if (dc_stats[timestamp][dc]
                            and not isinstance(dc_stats[timestamp][dc], Exception)
                            and dc_config[timestamp]
                            and dc_config[timestamp][dc]
                            and not isinstance(dc_config[timestamp][dc], Exception)):

                        for node in dc_stats[timestamp][dc].keys():
                            if node in dc_config[timestamp][dc]:
                                dc_stats[timestamp][dc][node].update(dc_config[timestamp][dc][node])

                    elif ((not dc_stats[timestamp][dc]
                            or isinstance(dc_stats[timestamp][dc], Exception))
                          and dc_config[timestamp]
                          and dc_config[timestamp][dc]
                          and not isinstance(dc_config[timestamp][dc], Exception)):

                        dc_stats[timestamp][dc] = dc_config[timestamp][dc]

                except Exception:
                    pass

            self.view.info_dc(util.flip_keys(dc_stats[timestamp]),
                              self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                              timestamp=timestamp, **self.mods)

    @CommandHelp(
        'Displays secondary index (SIndex) summary information).')
    def do_sindex(self, line):
        sindex_stats = self.loghdlr.info_statistics(stanza=STAT_SINDEX, flip=True)
        for timestamp in sorted(sindex_stats.keys()):
            if not sindex_stats[timestamp]:
                continue

            self.view.info_sindex(sindex_stats[timestamp],
                                  self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                                  timestamp=timestamp, **self.mods)


@CommandHelp('The "namespace" command provides summary tables for various aspects',
             'of Aerospike namespaces.')
class InfoNamespaceController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set()

    @CommandHelp('Displays usage and objects information for namespaces')
    def _do_default(self, line):
        self.do_usage(line)
        self.do_object(line)

    @CommandHelp('Displays usage information for each namespace.')
    def do_usage(self, line):
        ns_stats = self.loghdlr.info_statistics(stanza=STAT_NAMESPACE, flip=True)

        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                continue

            self.view.info_namespace_usage(
                util.flip_keys(ns_stats[timestamp]),
                self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp, **self.mods)

    @CommandHelp('Displays object information for each namespace.')
    def do_object(self, line):
        ns_stats = self.loghdlr.info_statistics(stanza=STAT_NAMESPACE, flip=True)

        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                continue

            self.view.info_namespace_object(
                util.flip_keys(ns_stats[timestamp]),
                self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp, **self.mods)


@CommandHelp(
    '"show" is used to display Aerospike Statistics and',
    'configuration.')
class ShowController(CollectinfoCommandController):

    def __init__(self):
        self.controller_map = {
            'config': ShowConfigController,
            'statistics': ShowStatisticsController,
            'latency': ShowLatencyController,
            'distribution': ShowDistributionController,
            'pmap': ShowPmapController
        }
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    '"show config" is used to display Aerospike configuration settings')
class ShowConfigController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set(['like', 'diff'])

    @CommandHelp('Displays service, network, and namespace configuration',
                 '  Options:',
                 '    -r <int>     - Repeating output table title and row header after every r columns.',
                 '                   default: 0, no repetition.',
                 '    -flip        - Flip output table to show Nodes on Y axis and config on X axis.')
    def _do_default(self, line):
        self.do_service(line[:])
        self.do_network(line[:])
        self.do_namespace(line[:])

    @CommandHelp('Displays service configuration')
    def do_service(self, line):
        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                                                            arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        service_configs = self.loghdlr.info_getconfig(stanza=CONFIG_SERVICE)

        for timestamp in sorted(service_configs.keys()):
            self.view.show_config("Service Configuration",
                                  service_configs[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_every_nth=title_every_nth, flip_output=flip_output,
                                  timestamp=timestamp, **self.mods)

    @CommandHelp('Displays network configuration')
    def do_network(self, line):
        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                                                            arg="-r", return_type=int, default=0,
                                                            modifiers=self.modifiers, mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        network_configs = self.loghdlr.info_getconfig(stanza=CONFIG_NETWORK)

        for timestamp in sorted(network_configs.keys()):
            self.view.show_config("Network Configuration",
                                  network_configs[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_every_nth=title_every_nth, flip_output=flip_output,
                                  timestamp=timestamp, **self.mods)

    @CommandHelp('Displays namespace configuration')
    def do_namespace(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        ns_configs = self.loghdlr.info_getconfig(stanza=CONFIG_NAMESPACE, flip=True)

        for timestamp in sorted(ns_configs.keys()):
            for ns, configs in ns_configs[timestamp].iteritems():
                self.view.show_config("%s Namespace Configuration"%(ns), configs,
                                      self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                                      title_every_nth=title_every_nth, flip_output=flip_output,
                                      timestamp=timestamp, **self.mods)

    @CommandHelp('Displays XDR configuration')
    def do_xdr(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        xdr_configs = self.loghdlr.info_getconfig(stanza=CONFIG_XDR)

        for timestamp in sorted(xdr_configs.keys()):
            self.view.show_config("XDR Configuration",
                                  xdr_configs[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_every_nth=title_every_nth, flip_output=flip_output,
                                  timestamp=timestamp, **self.mods)

    @CommandHelp('Displays datacenter configuration')
    def do_dc(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        dc_configs = self.loghdlr.info_getconfig(stanza=CONFIG_DC, flip=True)

        for timestamp in sorted(dc_configs.keys()):
            for dc, configs in dc_configs[timestamp].iteritems():
                self.view.show_config("%s DC Configuration"%(dc), configs,
                                      self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                                      title_every_nth=title_every_nth, flip_output=flip_output,
                                      timestamp=timestamp, **self.mods)

    @CommandHelp('Displays cluster configuration')
    def do_cluster(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        cl_configs = self.loghdlr.info_getconfig(stanza=CONFIG_CLUSTER)

        for timestamp in sorted(cl_configs.keys()):
            self.view.show_config("Cluster Configuration",
                                  cl_configs[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_every_nth=title_every_nth, flip_output=flip_output,
                                  timestamp=timestamp, **self.mods)

@CommandHelp(
    '"distribution" is used to show the distribution of object sizes',
    'and time to live for node and a namespace.')
class ShowDistributionController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set(['for'])

    @CommandHelp('Shows the distributions of Time to Live and Object Size')
    def _do_default(self, line):
        self.do_time_to_live(line)
        self.do_object_size(line)

    def _do_distribution(self, histogram_name, title, unit):
        histogram = self.loghdlr.info_histogram(histogram_name)
        for timestamp in sorted(histogram.keys()):
            if not histogram[timestamp]:
                continue
            self.view.show_distribution(title, common.create_histogram_output(histogram_name, histogram[timestamp]), unit,
                                        histogram_name,
                                        self.loghdlr.get_cinfo_log_at(
                                            timestamp=timestamp),
                                        timestamp=timestamp, like=self.mods['for'])

    @CommandHelp('Shows the distribution of TTLs for namespaces')
    def do_time_to_live(self, line):
        return self._do_distribution('ttl', 'TTL Distribution', 'Seconds')

    @CommandHelp('Shows the distribution of Object sizes for namespaces',
                 '  Options:',
                 '    -b   - Displays byte wise distribution of Object Sizes if it is collected in collectinfo.')
    def do_object_size(self, line):

        byte_distribution = util.check_arg_and_delete_from_mods(line=line,
                                                                arg="-b", default=False, modifiers=self.modifiers,
                                                                mods=self.mods)
        bucket_count = util.get_arg_and_delete_from_mods(line=line,
                arg="-k", return_type=int, default=5, modifiers=self.modifiers,
                mods=self.mods)

        histogram_name = "objsz"
        if not byte_distribution:
            return self._do_distribution(histogram_name, 'Object Size Distribution', 'Record Blocks')

        histogram = self.loghdlr.info_histogram(histogram_name, byte_distribution=True)
        builds = self.loghdlr.info_meta_data(stanza="asd_build")

        for timestamp in histogram:
            self.view.show_object_distribution('Object Size Distribution',
                                                common.create_histogram_output(histogram_name, histogram[timestamp], byte_distribution=True, bucket_count=bucket_count, builds=builds),
                                                'Bytes', 'objsz', bucket_count, True,
                                                self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                                                timestamp=timestamp,
                                                loganalyser_mode=True, like=self.mods['for'])

    @CommandHelp('Shows the distribution of Eviction TTLs for namespaces')
    def do_eviction(self, line):
        return self._do_distribution('evict', 'Eviction Distribution', 'Seconds')


class ShowLatencyController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set(['like', 'for'])

    @CommandHelp('Displays latency information for Aerospike cluster.',
                 '  Options:',
                 '    -m           - Set to display the output group by machine names.')
    def _do_default(self, line):

        machine_wise_display = util.check_arg_and_delete_from_mods(line=line,
                arg="-m", default=False, modifiers=self.modifiers,
                mods=self.mods)

        namespaces = {}
        if self.mods['for']:
            namespaces = self.loghdlr.info_namespaces()

        latency = self.loghdlr.info_latency()

        for timestamp in sorted(latency.keys()):
            namespace_set = set()
            _latency = {}
            if timestamp in namespaces:
                _namespaces = namespaces[timestamp].values()
                for _namespace in _namespaces:
                    if isinstance(_namespace, Exception):
                        continue
                    namespace_set.update(_namespace)
                namespace_set = set(
                    util.filter_list(list(namespace_set), self.mods['for']))

                for node_id, node_data in latency[timestamp].iteritems():
                    if not node_data or isinstance(node_data, Exception):
                        continue
                    if node_id not in _latency:
                        _latency[node_id] = {}
                    for hist_name, hist_data in node_data.iteritems():
                        if not hist_data or isinstance(hist_data, Exception):
                            continue

                        if hist_name not in _latency[node_id]:
                            _latency[node_id][hist_name] = {}

                        for _type, _type_data in hist_data.iteritems():
                            _latency[node_id][hist_name][_type] = {}
                            if _type != "namespace":
                                _latency[node_id][hist_name][_type] = _type_data
                                continue

                            for _ns, _ns_data in _type_data.iteritems():
                                if _ns in namespace_set:
                                    _latency[node_id][hist_name][_type][_ns] = _ns_data

            else:
                _latency = latency[timestamp]

            hist_latency = {}
            if machine_wise_display:
                hist_latency = _latency
            else:
                for node_id, node_data in _latency.iteritems():
                    if not node_data or isinstance(node_data, Exception):
                        continue
                    for hist_name, hist_data in node_data.iteritems():
                        if hist_name not in hist_latency:
                            hist_latency[hist_name] = {}

                        hist_latency[hist_name][node_id] = hist_data

            self.view.show_latency(hist_latency, self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                    machine_wise_display=machine_wise_display,
                    show_ns_details=True if namespace_set else False, timestamp=timestamp, **self.mods)


@CommandHelp('Displays statistics for Aerospike components.')
class ShowStatisticsController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set(['like', 'for'])

    @CommandHelp('Displays bin, set, service, and namespace statistics',
                 '  Options:',
                 '    -t           - Set to show total column at the end. It contains node wise sum for statistics.',
                 '    -r <int>     - Repeating output table title and row header after every r columns.',
                 '                   default: 0, no repetition.',
                 '    -flip        - Flip output table to show Nodes on Y axis and stats on X axis.')
    def _do_default(self, line):
        self.do_bins(line[:])
        self.do_sets(line[:])
        self.do_service(line[:])
        self.do_namespace(line[:])

    @CommandHelp('Displays service statistics')
    def do_service(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        service_stats = self.loghdlr.info_statistics(stanza=STAT_SERVICE)

        for timestamp in sorted(service_stats.keys()):
            self.view.show_config("Service Statistics",
                                  service_stats[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  show_total=show_total, title_every_nth=title_every_nth, flip_output=flip_output,
                                  timestamp=timestamp, **self.mods)

    @CommandHelp('Displays namespace statistics')
    def do_namespace(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        ns_stats = self.loghdlr.info_statistics(stanza=STAT_NAMESPACE, flip=True)

        for timestamp in sorted(ns_stats.keys()):
            namespace_list = util.filter_list(
                ns_stats[timestamp].keys(), self.mods['for'])
            for ns in sorted(namespace_list):
                stats = ns_stats[timestamp][ns]
                self.view.show_stats("%s Namespace Statistics" %(ns), stats,
                                     self.loghdlr.get_cinfo_log_at(
                                         timestamp=timestamp),
                                     show_total=show_total, title_every_nth=title_every_nth, flip_output=flip_output,
                                     timestamp=timestamp, **self.mods)

    @CommandHelp('Displays set statistics')
    def do_sets(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        set_stats = self.loghdlr.info_statistics(stanza=STAT_SETS, flip=True)

        for timestamp in sorted(set_stats.keys()):
            if not set_stats[timestamp]:
                continue
            namespace_list = [ns_set.split()[0]
                              for ns_set in set_stats[timestamp].keys()]

            try:
                namespace_list = util.filter_list(namespace_list, self.mods['for'][:1])
            except Exception:
                pass

            set_list = [ns_set.split()[1]
                              for ns_set in set_stats[timestamp].keys()]
            try:
                set_list = util.filter_list(set_list, self.mods['for'][1:2])
            except Exception:
                pass

            for ns_set, stats in set_stats[timestamp].iteritems():
                ns, set = ns_set.split()
                if ns not in namespace_list or set not in set_list:
                    continue

                self.view.show_stats("%s Set Statistics" %(ns_set), stats,
                                     self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                                     show_total=show_total, title_every_nth=title_every_nth, flip_output=flip_output,
                                     timestamp=timestamp, **self.mods)

    @CommandHelp('Displays bin statistics')
    def do_bins(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        new_bin_stats = self.loghdlr.info_statistics(stanza=STAT_BINS, flip=True)

        for timestamp in sorted(new_bin_stats.keys()):
            if (not new_bin_stats[timestamp]
                    or isinstance(new_bin_stats[timestamp], Exception)):
                continue

            namespace_list = util.filter_list(new_bin_stats[timestamp].keys(),
                                              self.mods['for'])

            for ns, stats in new_bin_stats[timestamp].iteritems():
                if ns not in namespace_list:
                    continue

                self.view.show_stats("%s Bin Statistics" % (ns),
                                     stats,
                                     self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                                     show_total=show_total, title_every_nth=title_every_nth, flip_output=flip_output,
                                     timestamp=timestamp, **self.mods)

    @CommandHelp('Displays XDR statistics')
    def do_xdr(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        xdr_stats = self.loghdlr.info_statistics(stanza=STAT_XDR)

        for timestamp in sorted(xdr_stats.keys()):
            self.view.show_config(
                "XDR Statistics", xdr_stats[timestamp],
                self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                show_total=show_total, title_every_nth=title_every_nth, flip_output=flip_output,
                timestamp=timestamp, **self.mods)

    @CommandHelp('Displays datacenter statistics')
    def do_dc(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        dc_stats = self.loghdlr.info_statistics(stanza=STAT_DC, flip=True)

        for timestamp in sorted(dc_stats.keys()):
            for dc, stats in dc_stats[timestamp].iteritems():
                self.view.show_stats(
                    "%s DC Statistics" % (dc), stats,
                    self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total, title_every_nth=title_every_nth, flip_output=flip_output,
                    timestamp=timestamp, **self.mods)

    @CommandHelp('Displays sindex statistics')
    def do_sindex(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        sindex_stats = self.loghdlr.info_statistics(stanza=STAT_SINDEX, flip=True)

        for timestamp in sorted(sindex_stats.keys()):
            if not sindex_stats[timestamp] or isinstance(sindex_stats[timestamp], Exception):
                continue

            namespace_list = [ns_set_sindex.split()[0]
                              for ns_set_sindex in sindex_stats[timestamp].keys()]
            try:
                namespace_list = util.filter_list(namespace_list, self.mods['for'][:1])
            except Exception:
                pass

            sindex_list = [ns_set_sindex.split()[2]
                              for ns_set_sindex in sindex_stats[timestamp].keys()]
            try:
                sindex_list = util.filter_list(sindex_list, self.mods['for'][1:2])
            except Exception:
                pass

            for sindex, stats in sindex_stats[timestamp].iteritems():
                ns, set, si = sindex.split()
                if ns not in namespace_list or si not in sindex_list:
                    continue

                self.view.show_stats("%s Sindex Statistics" %(sindex), stats,
                                     self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                                     show_total=show_total, title_every_nth=title_every_nth, flip_output=flip_output,
                                     timestamp=timestamp, **self.mods)


@CommandHelp('Displays partition map analysis of Aerospike cluster.')
class ShowPmapController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        pmap_data = self.loghdlr.info_pmap()

        for timestamp in sorted(pmap_data.keys()):
            if not pmap_data[timestamp]:
                continue

            self.view.show_pmap(pmap_data[timestamp], self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                                timestamp=timestamp)

@CommandHelp('Displays features used in Aerospike cluster.')
class FeaturesController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set(['like'])

    def _do_default(self, line):
        service_stats = self.loghdlr.info_statistics(stanza=STAT_SERVICE)
        namespace_stats = self.loghdlr.info_statistics(stanza=STAT_NAMESPACE)
        service_configs = self.loghdlr.info_getconfig(stanza=CONFIG_SERVICE)
        namespace_configs = self.loghdlr.info_getconfig(stanza=CONFIG_NAMESPACE)
        cluster_configs = self.loghdlr.info_getconfig(stanza=CONFIG_CLUSTER)

        for timestamp in sorted(service_stats.keys()):
            features = {}
            s_stats = service_stats[timestamp]
            ns_stats = {}
            s_configs = {}
            ns_configs = {}
            cl_configs = {}

            if timestamp in namespace_stats:
                ns_stats = namespace_stats[timestamp]

            if timestamp in service_configs:
                s_configs = service_configs[timestamp]

            if timestamp in namespace_configs:
                ns_configs = namespace_configs[timestamp]

            if timestamp in cluster_configs:
                cl_configs = cluster_configs[timestamp]

            features = common.find_nodewise_features(service_stats=s_stats, ns_stats=ns_stats, service_configs=s_configs,
                                                     ns_configs=ns_configs, cluster_configs=cl_configs)

            self.view.show_config(
                "Features",
                features,
                self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp, **self.mods)


@CommandHelp('Checks for common inconsistencies and print if there is any.',
             'This command is still in beta and its output should not be directly acted upon without further analysis.')
class HealthCheckController(CollectinfoCommandController):

    health_check_input_created = False
    def __init__(self):
        self.modifiers = set()

    @CommandHelp(
        'Displays all lines from cluster logs (collectinfos) matched with input strings.',
        '  Options:',
        '    -f <string>     - Query file path. Default: inbuilt health queries.',
        '    -o <string>     - Output file path. ',
        '                      This parameter works if Query file path provided, otherwise health command will work in interactive mode.',
        '    -v              - Enable to display extra details of assert errors.',
        '    -d              - Enable to display extra details of exceptions.',
        '    -oc <string>    - Output filter Category. ',
        '                      This parameter works if Query file path provided, otherwise health command will work in interactive mode.',
        '                      Format : string of dot (.) separated category levels',
        '    -wl <string>    - Output filter Warning level. Expected value CRITICAL or WARNING or INFO ',
        '                      This parameter works if Query file path provided, otherwise health command will work in interactive mode.',
    )
    def _do_default(self, line):

        output_file = util.get_arg_and_delete_from_mods(line=line, arg="-o",
                                                        return_type=str, default=None, modifiers=self.modifiers,
                                                        mods=self.mods)

        verbose = util.check_arg_and_delete_from_mods(line=line, arg="-v",
                                                      default=False, modifiers=self.modifiers, mods=self.mods)

        debug = util.check_arg_and_delete_from_mods(line=line, arg="-d",
                                                    default=False, modifiers=self.modifiers, mods=self.mods)

        output_filter_category = util.get_arg_and_delete_from_mods(line=line,
                                                                   arg="-oc", return_type=str, default=None,
                                                                   modifiers=self.modifiers, mods=self.mods)

        output_filter_warning_level = util.get_arg_and_delete_from_mods(
            line=line, arg="-wl", return_type=str, default=None,
            modifiers=self.modifiers, mods=self.mods)

        # Query file name last to be parsed as health
        # command can be run without -f and directly
        # with file name
        query_file = util.get_arg_and_delete_from_mods(line=line, arg="-f",
                                                       return_type=str, default=None, modifiers=self.modifiers,
                                                       mods=self.mods)

        if query_file:
            query_file = util.strip_string(query_file)

        if output_file:
            output_file = util.strip_string(output_file)

        if output_filter_category:
            output_filter_category = [util.strip_string(c).upper()
                                      for c in util.strip_string(output_filter_category).split(".")]
        else:
            output_filter_category = []

        if output_filter_warning_level:
            output_filter_warning_level = util.strip_string(
                output_filter_warning_level).upper()

        if not HealthCheckController.health_check_input_created:
            # There is possibility of different cluster-names in old heartbeat protocol.
            # As asadm works with single cluster, so we are setting one static
            # cluster-name.
            cluster_name = "C1"
            stanza_dict = {
                "statistics": (self.loghdlr.info_statistics, [
                    ("service", "SERVICE", "STATISTICS", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("namespace", "NAMESPACE", "STATISTICS", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("set", "SET", "STATISTICS", True, [("CLUSTER", cluster_name), ("NODE", None), (
                        None, None), ("NAMESPACE", ("ns_name", "ns",)), ("SET", ("set_name", "set",))]),
                    ("bin", "BIN", "STATISTICS", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("xdr", "XDR", "STATISTICS", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC", "STATISTICS", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("sindex", "SINDEX", "STATISTICS", True, [("CLUSTER", cluster_name), ("NODE", None), (
                        None, None), ("NAMESPACE", ("ns",)), ("SET", ("set",)), ("SINDEX", ("indexname",))])
                ]),
                "config": (self.loghdlr.info_getconfig, [
                    ("service", "SERVICE", "CONFIG", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("xdr", "XDR", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("network", "NETWORK", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("namespace", "NAMESPACE", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("roster", "ROSTER", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("racks", "RACKS", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None), (None, None), ("RACKS", None)])
                ]),
                "original_config": (self.loghdlr.info_get_originalconfig, [
                    ("service", "SERVICE", "ORIGINAL_CONFIG", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("xdr", "XDR", "ORIGINAL_CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("network", "NETWORK", "ORIGINAL_CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC", "ORIGINAL_CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("namespace", "NAMESPACE", "ORIGINAL_CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)])
                ]),
                "cluster": (self.loghdlr.info_meta_data, [
                    ("asd_build", "METADATA", "CLUSTER", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "version")]),
                    ("edition", "METADATA", "CLUSTER", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "edition")]),
                    ("node_id", "METADATA", "CLUSTER", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "node-id")]),
                ]),
                "endpoints": (self.loghdlr.info_meta_data, [
                    ("endpoints", "METADATA", "ENDPOINTS", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "endpoints")]),
                ]),
                "services": (self.loghdlr.info_meta_data, [
                    ("services", "METADATA", "SERVICES", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "services")]),
                ]),
                "udf": (self.loghdlr.info_meta_data, [
                    ("udf", "UDF", "METADATA", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("FILENAME", None)]),
                ]),

                "sys_stats": (self.loghdlr.get_sys_data, [
                    ("free-m", "SYSTEM", "FREE", True,
                     [(None, None), ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("top", "SYSTEM", "TOP", True, [
                     (None, None), ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("iostat", "SYSTEM", "IOSTAT", False, [
                     (None, None), ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DEVICE", None)]),
                    ("meminfo", "SYSTEM", "MEMINFO", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dmesg", "SYSTEM", "DMESG", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("lscpu", "SYSTEM", "LSCPU", True,
                     [("CLUSTER", cluster_name), ("NODE", None), ("LSCPU", None)]),
                    ("sysctlall", "SYSTEM", "SYSCTLALL", True,
                     [("CLUSTER", cluster_name), ("NODE", None), ("SYSCTL", None)]),
                    ("iptables", "SYSTEM", "IPTABLES", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("hdparm", "SYSTEM", "HDPARM", True,
                     [("CLUSTER", cluster_name), ("NODE", None), ("HDPARM", None)]),
                    ("limits", "SYSTEM", "LIMITS", True,
                     [("CLUSTER", cluster_name), ("NODE", None), ("LIMITS", None)]),
                    ("interrupts", "SYSTEM", "INTERRUPTS", False, [(None, None), ("CLUSTER", cluster_name), ("NODE", None), (None, None),
                                                                   ("INTERRUPT_TYPE", None), (None, None), ("INTERRUPT_ID", None), (None, None), ("INTERRUPT_DEVICE", None)]),
                    ("df", "SYSTEM", "DF", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("FILE_SYSTEM", None)]),
                    ("lsb", "SYSTEM", "LSB", True,
                     [("CLUSTER", cluster_name), ("NODE", None), ("LSB", None)]),
                    ("environment", "SYSTEM", "ENVIRONMENT", True,
                     [("CLUSTER", cluster_name), ("NODE", None), ("ENVIRONMENT", None)]),
                    ("scheduler", "SYSTEM", "SCHEDULER", False,
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DEVICE", None)]),
                ]),

            }
            health_input = {}
            for _key, (info_function, stanza_list) in stanza_dict.iteritems():
                for stanza_item in stanza_list:

                    stanza = stanza_item[0]
                    component_name = stanza_item[1]
                    sub_component_name = stanza_item[2]
                    forced_all_new_keys = stanza_item[3]

                    d = info_function(stanza=stanza)

                    if not d:
                        continue

                    if stanza == "free-m":
                        d = util.mbytes_to_bytes(d)

                    sn_ct = 0
                    new_tuple_keys = []

                    try:
                        new_tuple_keys = copy.deepcopy(stanza_item[4])
                    except Exception:
                        pass

                    for _k in sorted(d.keys()):
                        health_input = create_health_input_dict(d[_k],
                                                                health_input, new_tuple_keys=new_tuple_keys,
                                                                new_component_keys=[create_snapshot_key(sn_ct),
                                                                                    component_name, sub_component_name],
                                                                forced_all_new_keys=forced_all_new_keys)
                        sn_ct += 1

            health_input = h_eval(health_input)
            self.health_checker.set_health_input_data(health_input)
            HealthCheckController.health_check_input_created = True

        health_summary = self.health_checker.execute(query_file=query_file)

        if health_summary:
            self.view.print_health_output(health_summary, debug=debug,
                                          verbose=verbose, output_file=output_file,
                                          output_filter_category=output_filter_category,
                                          output_filter_warning_level=output_filter_warning_level)
            if not verbose:
                self.logger.info("Please use -v option for more details on failure. \n")

class ListController(CollectinfoCommandController):

    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_default(self, line):
        self.do_all(line)

    @CommandHelp('Displays list of all added collectinfos files.')
    def do_all(self, line):
        cinfo_logs = self.loghdlr.all_cinfo_logs
        for timestamp, snapshot in cinfo_logs.items():
            print terminal.bold() + str(timestamp) + terminal.unbold() + ": " + str(snapshot.cinfo_file)


@CommandHelp("Set pager for output")
class PagerController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)

    @CommandHelp("Displays output with vertical and horizontal paging for each output table same as linux 'less' command.",
                 "Use arrow keys to scroll output and 'q' to end page for table.",
                 "All linux less commands can work in this pager option.")
    def do_on(self, line):
        CliView.pager = CliView.LESS

    @CommandHelp("Removes pager and prints output normally")
    def do_off(self, line):
        CliView.pager = CliView.NO_PAGER

    @CommandHelp("Display output in scrolling mode")
    def do_scroll(self, line):
        CliView.pager = CliView.SCROLL


@CommandHelp('Displays summary of Aerospike cluster.',
             '  Options:',
             '    -l    - Enable to display namespace output in List view. Default: Table view',
             )
class SummaryController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set([])

    def _do_default(self, line):
        enable_list_view = util.check_arg_and_delete_from_mods(line=line, arg="-l", default=False, modifiers=self.modifiers, mods=self.mods)

        service_stats = self.loghdlr.info_statistics(stanza=STAT_SERVICE)
        namespace_stats = self.loghdlr.info_statistics(stanza=STAT_NAMESPACE)
        set_stats = self.loghdlr.info_statistics(stanza=STAT_SETS)

        service_configs = self.loghdlr.info_getconfig(stanza=CONFIG_SERVICE)
        namespace_configs = self.loghdlr.info_getconfig(stanza=CONFIG_NAMESPACE)
        cluster_configs = self.loghdlr.info_getconfig(stanza=CONFIG_CLUSTER)

        os_version = self.loghdlr.get_sys_data(stanza="lsb")
        kernel_version = self.loghdlr.get_sys_data(stanza="uname")
        server_version = self.loghdlr.info_meta_data(stanza="asd_build")
        server_edition = self.loghdlr.info_meta_data(stanza="edition")

        last_timestamp = sorted(service_stats.keys())[-1]

        try:
            cluster_configs = cluster_configs[last_timestamp]
        except Exception:
            cluster_configs = {}

        cluster_name = {}
        try:
            cinfo_log = self.loghdlr.get_cinfo_log_at(timestamp=last_timestamp)
            cluster_name = cinfo_log.get_cluster_name()
        except Exception:
            pass

        metadata = {}
        metadata["server_version"] = {}
        metadata["server_build"] = {}
        metadata["cluster_name"] = {}

        server_version = server_version[last_timestamp]
        server_edition = server_edition[last_timestamp]

        for node, version in server_version.iteritems():
            if not version or isinstance(version, Exception):
                continue

            metadata["server_build"][node] = version

            if node in server_edition and server_edition[node] and not isinstance(server_edition[node], Exception):
                if 'enterprise' in server_edition[node].lower():
                    metadata["server_version"][node] = "E-%s" % (str(version))
                elif 'community' in server_edition[node].lower():
                    metadata["server_version"][node] = "C-%s" % (str(version))
                else:
                    metadata["server_version"][node] = version

            else:
                metadata["server_version"][node] = version

            if node in cluster_name and cluster_name[node] and not isinstance(cluster_name[node], Exception):
                metadata["cluster_name"][node] = cluster_name[node]

        os_version = os_version[last_timestamp]
        kernel_version = kernel_version[last_timestamp]

        try:
            if kernel_version:
                for node, version in os_version.iteritems():
                    if not version or isinstance(version, Exception):
                        continue

                    if node not in kernel_version or not kernel_version[node] or isinstance(kernel_version[node], Exception):
                        continue

                    try:
                        ov = version["description"]
                        kv = kernel_version[node]["kernel_release"]
                        version["description"] = str(ov) + " (%s)"%str(kv)
                    except Exception:
                        pass

        except Exception:
            pass

        metadata["os_version"] = os_version

        self.view.print_summary(common.create_summary(service_stats=service_stats[last_timestamp],
                                                      namespace_stats=namespace_stats[last_timestamp],
                                                      set_stats=set_stats[last_timestamp], metadata=metadata,
                                                      service_configs=service_configs[last_timestamp],
                                                      ns_configs=namespace_configs[last_timestamp],
                                                      cluster_configs=cluster_configs,),
                                list_view=enable_list_view)
