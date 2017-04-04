# Copyright 2013-2017 Aerospike, Inc.
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
import os

from lib.controllerlib import BaseController, CommandHelp, CommandController
from lib.collectinfo.loghdlr import CollectinfoLoghdlr
from lib.health.util import create_health_input_dict, h_eval, create_snapshot_key
from lib.utils.constants import *
from lib.utils import util
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

    @CommandHelp(
        'Displays network, namespace, and xdr summary information.')
    def _do_default(self, line):
        self.do_network(line)
        self.do_namespace(line)
        self.do_xdr(line)

    @CommandHelp(
        'Displays network summary information.')
    def do_network(self, line):
        network_infos = self.loghdlr.info_summary(stanza=SUMMARY_NETWORK)
        service_infos = self.loghdlr.info_summary(stanza=SUMMARY_SERVICE)
        network_stats = self.loghdlr.info_statistics(stanza=STAT_SERVICE)
        cluster_configs = self.loghdlr.info_getconfig(stanza=CONFIG_CLUSTER)
        for timestamp in sorted(network_stats.keys()):
            if not network_stats[timestamp]:
                try:
                    if service_infos[timestamp]:
                        self.view.info_string(
                            timestamp, service_infos[timestamp])
                except Exception:
                    pass
                try:
                    if network_infos[timestamp]:
                        self.view.info_string(
                            timestamp, network_infos[timestamp])
                except Exception:
                    pass
                continue
            for node in network_stats[timestamp]:
                try:
                    if not isinstance(cluster_configs[timestamp][node]["mode"],
                                      Exception):
                        network_stats[timestamp][node][
                            "rackaware_mode"] = cluster_configs[timestamp][node]["mode"]
                except Exception:
                    pass
            cinfo_log = self.loghdlr.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()
            versions = cinfo_log.get_asd_version()
            cluster_names = cinfo_log.get_cluster_name()

            # Note how clinfo_log mapped to cluster. Both implement interfaces
            # required by view object
            self.view.info_network(network_stats[timestamp], cluster_names,
                                   versions, builds, cluster=cinfo_log,
                                   title_suffix=" (%s)" % (timestamp), **self.mods)

    @CommandHelp(
        'Displays namespace summary information.')
    def do_namespace(self, line):
        ns_infos = self.loghdlr.info_summary(stanza=SUMMARY_NAMESPACE)
        ns_stats = self.loghdlr.info_statistics(stanza=STAT_NAMESPACE)
        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                try:
                    if ns_infos[timestamp]:
                        self.view.info_string(timestamp, ns_infos[timestamp])
                except Exception:
                    pass
                continue
            self.view.info_namespace(util.flip_keys(ns_stats[timestamp]),
                                     self.loghdlr.get_cinfo_log_at(
                                         timestamp=timestamp),
                                     title_suffix=" (%s)" % (timestamp), **self.mods)

    def convert_key_to_tuple(self, stats):
        for key in stats.keys():
            key_tuple = tuple(key.split())
            stats[key_tuple] = stats[key]
            del stats[key]

    @CommandHelp(
        'Displays set summary information.')
    def do_set(self, line):
        set_infos = self.loghdlr.info_summary(stanza=SUMMARY_SETS)
        set_stats = self.loghdlr.info_statistics(stanza=STAT_SETS)
        for timestamp in sorted(set_stats.keys()):
            if not set_stats[timestamp]:
                try:
                    if set_infos[timestamp]:
                        self.view.info_string(timestamp, set_infos[timestamp])
                except Exception:
                    pass
                continue
            self.convert_key_to_tuple(set_stats[timestamp])
            self.view.info_set(util.flip_keys(set_stats[timestamp]),
                               self.loghdlr.get_cinfo_log_at(
                                   timestamp=timestamp),
                               title_suffix=" (%s)" % (timestamp), **self.mods)

    @CommandHelp(
        'Displays Cross Datacenter Replication (XDR) summary information.')
    def do_xdr(self, line):
        xdr_infos = self.loghdlr.info_summary(stanza=SUMMARY_XDR)
        xdr_stats = self.loghdlr.info_statistics(stanza=STAT_XDR)
        for timestamp in sorted(xdr_stats.keys()):
            if not xdr_stats[timestamp]:
                try:
                    if xdr_infos[timestamp]:
                        self.view.info_string(timestamp, xdr_infos[timestamp])
                except Exception:
                    pass
                continue
            xdr_enable = {}
            cinfo_log = self.loghdlr.get_cinfo_log_at(
                timestamp=timestamp)
            builds = cinfo_log.get_xdr_build()
            for xdr_node in xdr_stats[timestamp].keys():
                xdr_enable[xdr_node] = True

            self.view.info_XDR(xdr_stats[timestamp], builds, xdr_enable,
                               cluster=cinfo_log, title_suffix=" (%s)" % (
                                   timestamp),
                               **self.mods)

    @CommandHelp(
        'Displays datacenter summary information.')
    def do_dc(self, line):
        dc_infos = self.loghdlr.info_summary(stanza=SUMMARY_DC)
        dc_stats = self.loghdlr.info_statistics(stanza=STAT_DC)
        dc_config = self.loghdlr.info_getconfig(stanza=CONFIG_DC)
        for timestamp in sorted(dc_stats.keys()):
            if not dc_stats[timestamp]:
                try:
                    if dc_infos[timestamp]:
                        self.view.info_string(timestamp, dc_infos[timestamp])
                except Exception:
                    pass
                continue
            for dc in dc_stats[timestamp].keys():
                if (dc_stats[timestamp][dc]
                        and not isinstance(dc_stats[timestamp][dc], Exception)
                        and dc_config[timestamp]
                        and dc_config[timestamp][dc]
                        and not isinstance(dc_config[timestamp][dc], Exception)):

                    for node in dc_stats[timestamp][dc].keys():
                        if node in dc_config[timestamp][dc]:
                            dc_stats[timestamp][dc][node].update(
                                dc_config[timestamp][dc][node])

                elif ((not dc_stats[timestamp][dc]
                        or isinstance(dc_stats[timestamp][dc], Exception))
                      and dc_config[timestamp]
                      and dc_config[timestamp][dc]
                      and not isinstance(dc_config[timestamp][dc], Exception)):

                    dc_stats[timestamp][dc] = dc_config[timestamp][dc]

            self.view.info_dc(util.flip_keys(dc_stats[timestamp]),
                              self.loghdlr.get_cinfo_log_at(
                                  timestamp=timestamp),
                              title_suffix=" (%s)" % (timestamp), **self.mods)

    @CommandHelp(
        'Displays secondary index (SIndex) summary information).')
    def do_sindex(self, line):
        sindex_infos = self.loghdlr.info_summary(stanza=SUMMARY_SINDEX)
        sindex_stats = self.loghdlr.info_statistics(stanza=STAT_SINDEX)
        for timestamp in sorted(sindex_stats.keys()):
            if not sindex_stats[timestamp]:
                try:
                    if sindex_infos[timestamp]:
                        self.view.info_string(
                            timestamp, sindex_infos[timestamp])
                except Exception:
                    pass
                continue
            self.view.info_sindex(sindex_stats[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_suffix=" (%s)" % (timestamp), **self.mods)


@CommandHelp(
    '"show" is used to display Aerospike Statistics and',
    'configuration.')
class ShowController(CollectinfoCommandController):

    def __init__(self):
        self.controller_map = {
            'config': ShowConfigController,
            'statistics': ShowStatisticsController,
            'distribution': ShowDistributionController}
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    '"show config" is used to display Aerospike configuration settings')
class ShowConfigController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set(['like', 'diff'])

    @CommandHelp('Displays service, network, and namespace configuration',
                 '  Options:', '    -r <int>     - Repeating output table title and row header after every r columns.',
                 '                   default: 0, no repetition.')
    def _do_default(self, line):
        self.do_service(line)
        self.do_network(line)
        self.do_namespace(line)

    @CommandHelp('Displays service configuration')
    def do_service(self, line):
        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                                                            arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        service_configs = self.loghdlr.info_getconfig(stanza=CONFIG_SERVICE)

        for timestamp in sorted(service_configs.keys()):
            self.view.show_config("Service Configuration (%s)" % (timestamp),
                                  service_configs[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_every_nth=title_every_nth, **self.mods)

    @CommandHelp('Displays network configuration')
    def do_network(self, line):
        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                                                            arg="-r", return_type=int, default=0,
                                                            modifiers=self.modifiers, mods=self.mods)

        service_configs = self.loghdlr.info_getconfig(stanza=CONFIG_NETWORK)

        for timestamp in sorted(service_configs.keys()):
            self.view.show_config("Network Configuration (%s)" % (timestamp),
                                  service_configs[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_every_nth=title_every_nth, **self.mods)

    @CommandHelp('Displays namespace configuration')
    def do_namespace(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        ns_configs = self.loghdlr.info_getconfig(stanza=CONFIG_NAMESPACE)

        for timestamp in sorted(ns_configs.keys()):
            for ns, configs in ns_configs[timestamp].iteritems():
                self.view.show_config("%s Namespace Configuration (%s)" %
                                      (ns, timestamp), configs,
                                      self.loghdlr.get_cinfo_log_at(
                                          timestamp=timestamp),
                                      title_every_nth=title_every_nth, **self.mods)

    @CommandHelp('Displays XDR configuration')
    def do_xdr(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        xdr_configs = self.loghdlr.info_getconfig(stanza=CONFIG_XDR)

        for timestamp in sorted(xdr_configs.keys()):
            self.view.show_config("XDR Configuration (%s)" % (timestamp),
                                  xdr_configs[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_every_nth=title_every_nth, **self.mods)

    @CommandHelp('Displays datacenter configuration')
    def do_dc(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        dc_configs = self.loghdlr.info_getconfig(stanza=CONFIG_DC)

        for timestamp in sorted(dc_configs.keys()):
            for dc, configs in dc_configs[timestamp].iteritems():
                self.view.show_config("%s DC Configuration (%s)" %
                                      (dc, timestamp), configs,
                                      self.loghdlr.get_cinfo_log_at(
                                          timestamp=timestamp),
                                      title_every_nth=title_every_nth, **self.mods)

    @CommandHelp('Displays cluster configuration')
    def do_cluster(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        cl_configs = self.loghdlr.info_getconfig(stanza=CONFIG_CLUSTER)

        for timestamp in sorted(cl_configs.keys()):
            self.view.show_config("Cluster Configuration (%s)" % (timestamp),
                                  cl_configs[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  title_every_nth=title_every_nth, **self.mods)


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
            self.view.show_distribution(title, histogram[timestamp], unit,
                                        histogram_name,
                                        self.loghdlr.get_cinfo_log_at(
                                            timestamp=timestamp),
                                        title_suffix=" (%s)" % (timestamp), like=self.mods['for'])

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

        if byte_distribution:
            histogram = self.loghdlr.info_histogram("objsz-b")
            for timestamp in histogram:
                self.view.show_object_distribution('Object Size Distribution',
                                                   histogram[
                                                       timestamp], 'Bytes', 'objsz', 10, False,
                                                   self.loghdlr.get_cinfo_log_at(
                                                       timestamp=timestamp),
                                                   title_suffix=" (%s)" % (
                                                       timestamp),
                                                   loganalyser_mode=True, like=self.mods['for'])
        else:
            return self._do_distribution('objsz', 'Object Size Distribution',
                                         'Record Blocks')

    @CommandHelp('Shows the distribution of Eviction TTLs for namespaces')
    def do_eviction(self, line):
        return self._do_distribution('evict', 'Eviction Distribution', 'Seconds')


@CommandHelp('Displays statistics for Aerospike components.')
class ShowStatisticsController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set(['like', 'for'])

    @CommandHelp('Displays bin, set, service, and namespace statistics',
                 '  Options:',
                 '    -t           - Set to show total column at the end. It contains node wise sum for statistics.',
                 '    -r <int>     - Repeating output table title and row header after every r columns.',
                 '                   default: 0, no repetition.')
    def _do_default(self, line):
        self.do_bins(line)
        self.do_sets(line)
        self.do_service(line)
        self.do_namespace(line)

    @CommandHelp('Displays service statistics')
    def do_service(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        service_stats = self.loghdlr.info_statistics(stanza=STAT_SERVICE)

        for timestamp in sorted(service_stats.keys()):
            self.view.show_config("Service Statistics (%s)" % (timestamp),
                                  service_stats[timestamp],
                                  self.loghdlr.get_cinfo_log_at(
                                      timestamp=timestamp),
                                  show_total=show_total, title_every_nth=title_every_nth,
                                  **self.mods)

    @CommandHelp('Displays namespace statistics')
    def do_namespace(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        ns_stats = self.loghdlr.info_statistics(stanza=STAT_NAMESPACE)

        for timestamp in sorted(ns_stats.keys()):
            namespace_list = util.filter_list(
                ns_stats[timestamp].keys(), self.mods['for'])
            for ns in sorted(namespace_list):
                stats = ns_stats[timestamp][ns]
                self.view.show_stats("%s Namespace Statistics (%s)" %
                                     (ns, timestamp), stats,
                                     self.loghdlr.get_cinfo_log_at(
                                         timestamp=timestamp),
                                     show_total=show_total, title_every_nth=title_every_nth,
                                     **self.mods)

    @CommandHelp('Displays set statistics')
    def do_sets(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        set_stats = self.loghdlr.info_statistics(stanza=STAT_SETS)

        for timestamp in sorted(set_stats.keys()):
            if not set_stats[timestamp]:
                continue
            namespace_list = [ns_set.split()[0]
                              for ns_set in set_stats[timestamp].keys()]
            namespace_list = util.filter_list(namespace_list, self.mods['for'])
            for ns_set, stats in set_stats[timestamp].iteritems():
                if ns_set.split()[0] not in namespace_list:
                    continue
                self.view.show_stats("%s Set Statistics (%s)" %
                                     (ns_set, timestamp), stats,
                                     self.loghdlr.get_cinfo_log_at(
                                         timestamp=timestamp),
                                     show_total=show_total, title_every_nth=title_every_nth,
                                     **self.mods)

    @CommandHelp('Displays bin statistics')
    def do_bins(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        new_bin_stats = self.loghdlr.info_statistics(stanza=STAT_BINS)

        for timestamp in sorted(new_bin_stats.keys()):
            if (not new_bin_stats[timestamp]
                    or isinstance(new_bin_stats[timestamp], Exception)):
                continue
            namespace_list = util.filter_list(new_bin_stats[timestamp].keys(),
                                              self.mods['for'])

            for ns, stats in new_bin_stats[timestamp].iteritems():
                if ns not in namespace_list:
                    continue
                self.view.show_stats("%s Bin Statistics (%s)" % (ns, timestamp),
                                     stats,
                                     self.loghdlr.get_cinfo_log_at(
                                         timestamp=timestamp),
                                     show_total=show_total, title_every_nth=title_every_nth,
                                     **self.mods)

    @CommandHelp('Displays XDR statistics')
    def do_xdr(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        xdr_stats = self.loghdlr.info_statistics(stanza=STAT_XDR)

        for timestamp in sorted(xdr_stats.keys()):
            self.view.show_config(
                "XDR Statistics (%s)" % (timestamp), xdr_stats[timestamp],
                self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                show_total=show_total, title_every_nth=title_every_nth,
                **self.mods)

    @CommandHelp('Displays datacenter statistics')
    def do_dc(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        dc_stats = self.loghdlr.info_statistics(stanza=STAT_DC)

        for timestamp in sorted(dc_stats.keys()):
            for dc, stats in dc_stats[timestamp].iteritems():
                self.view.show_stats(
                    "%s DC Statistics (%s)" % (dc, timestamp), stats,
                    self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total, title_every_nth=title_every_nth,
                    **self.mods)

    @CommandHelp('Displays sindex statistics')
    def do_sindex(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                                                         default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line, arg="-r",
                                                            return_type=int, default=0, modifiers=self.modifiers,
                                                            mods=self.mods)

        sindex_stats = self.loghdlr.info_statistics(stanza=STAT_SINDEX)

        for timestamp in sorted(sindex_stats.keys()):
            if not sindex_stats[timestamp] or isinstance(sindex_stats[timestamp], Exception):
                continue
            namespace_list = [ns_set_sindex.split()[0]
                              for ns_set_sindex in sindex_stats[timestamp].keys()]
            namespace_list = util.filter_list(namespace_list, self.mods['for'])
            for sindex, stats in sindex_stats[timestamp].iteritems():
                if sindex.split()[0] not in namespace_list:
                    continue
                self.view.show_stats("%s Sindex Statistics (%s)" %
                                     (sindex, timestamp), stats,
                                     self.loghdlr.get_cinfo_log_at(
                                         timestamp=timestamp),
                                     show_total=show_total, title_every_nth=title_every_nth,
                                     **self.mods)


@CommandHelp('Displays features used in Aerospike cluster.')
class FeaturesController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set(['like'])

    def _do_default(self, line):
        service_stats = self.loghdlr.info_statistics(stanza=STAT_SERVICE)
        namespace_stats = self.loghdlr.info_statistics(stanza=STAT_NAMESPACE)

        for timestamp in sorted(service_stats.keys()):
            features = {}
            ns_stats = {}

            if timestamp in namespace_stats:
                ns_stats = namespace_stats[timestamp]
                ns_stats = util.flip_keys(ns_stats)

            for feature, keys in util.FEATURE_KEYS.iteritems():
                for node, s_stats in service_stats[timestamp].iteritems():

                    if node not in features:
                        features[node] = {}

                    features[node][feature.upper()] = "NO"
                    n_stats = None

                    if node in ns_stats and not isinstance(ns_stats[node], Exception):
                        n_stats = ns_stats[node]

                    if util.check_feature_by_keys(s_stats, keys[0], n_stats, keys[1]):
                        features[node][feature.upper()] = "YES"

            self.view.show_config(
                "(%s) Features" %
                (timestamp),
                features,
                self.loghdlr.get_cinfo_log_at(timestamp=timestamp),
                **self.mods)


@CommandHelp('Checks for common inconsistencies and print if there is any')
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
                "statistics": (self.loghdlr.get_asstat_data, [
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
                "config": (self.loghdlr.get_asconfig_data, [
                    ("service", "SERVICE", "CONFIG", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("xdr", "XDR", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("network", "NETWORK", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("namespace", "NAMESPACE", "CONFIG", True, [
                        ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)])
                ]),
                "cluster": (self.loghdlr.get_asmeta_data, [
                    ("asd_build", "METADATA", "CLUSTER", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "version")]),
                ]),
                "udf": (self.loghdlr.get_asmeta_data, [
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
                    ("interrupts", "SYSTEM", "INTERRUPTS", False, [(None, None), ("CLUSTER", cluster_name), ("NODE", None), (None, None),
                                                                   ("INTERRUPT_TYPE", None), (None, None), ("INTERRUPT_ID", None), (None, None), ("INTERRUPT_DEVICE", None)]),
                    ("df", "SYSTEM", "DF", True, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("FILE_SYSTEM", None)])
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
            try:
                self.view.print_health_output(health_summary, debug=debug,
                                              verbose=verbose, output_file=output_file,
                                              output_filter_category=output_filter_category,
                                              output_filter_warning_level=output_filter_warning_level)
                if not verbose:
                    self.logger.info("Please use -v option for more details on failure. \n")

            except Exception as e:
                self.logger.error(e)


class ListController(CollectinfoCommandController):

    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_default(self, line):
        self.do_all(line)

    @CommandHelp('Displays list of all added collectinfos files.')
    def do_all(self, line):
        timestamp = self.loghdlr.get_cinfo_timestamp()
        print terminal.bold() + str(timestamp) + terminal.unbold() + ": " + str(self.loghdlr.get_cinfo_path())


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


@CommandHelp('Displays summary of Aerospike cluster.')
class SummaryController(CollectinfoCommandController):

    def __init__(self):
        self.modifiers = set([])

    def _do_default(self, line):
        service_stats = self.loghdlr.get_asstat_data(stanza=STAT_SERVICE)
        namespace_stats = self.loghdlr.get_asstat_data(stanza=STAT_NAMESPACE)
        set_stats = self.loghdlr.get_asstat_data(stanza="set")

        os_version = self.loghdlr.get_sys_data(stanza="lsb")
        server_version = self.loghdlr.get_asmeta_data(stanza="asd_build")

        last_timestamp = sorted(service_stats.keys())[-1]

        metadata = {}
        metadata["server_version"] = server_version[last_timestamp]
        metadata["os_version"] = os_version[last_timestamp]

        self.view.print_summary(util.create_summary(service_stats=service_stats[last_timestamp], namespace_stats=namespace_stats[last_timestamp],
                                                    set_stats=set_stats[last_timestamp], metadata=metadata))