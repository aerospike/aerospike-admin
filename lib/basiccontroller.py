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
from distutils.version import LooseVersion
import json
import time
import os
import sys
import platform
import shutil
import urllib2
import socket
import zipfile

from lib.client.cluster import Cluster
from lib.collectinfocontroller import CollectinfoRootController
from lib.controllerlib import BaseController, CommandController, CommandHelp, ShellException
from lib.getcontroller import GetConfigController, GetStatisticsController, GetDistributionController, get_sindex_stats, \
    GetPmapController
from lib.health.util import create_health_input_dict, h_eval, create_snapshot_key
from lib.utils import util
from lib.utils.data import lsof_file_type_desc
from lib.view.view import CliView
from lib.view import terminal

aslogfile = ""
aslogdir = ""

class BasicCommandController(CommandController):
    cluster = None

    def __init__(self, cluster):
        BasicCommandController.cluster = cluster

@CommandHelp('Aerospike Admin')
class BasicRootController(BaseController):

    cluster = None
    command = None

    def __init__(self, seed_nodes=[('127.0.0.1', 3000, None)], user=None,
                 password=None, use_services_alumni=False, use_services_alt=False, ssl_context=None,
                 asadm_version='', only_connect_seed=False, timeout=5):

        super(BasicRootController, self).__init__(asadm_version)

        # Create static instance of cluster
        BasicRootController.cluster = Cluster(seed_nodes, user, password,
                                              use_services_alumni, use_services_alt,
                                              ssl_context, only_connect_seed, timeout=timeout)

        # Create Basic Command Controller Object
        BasicRootController.command = BasicCommandController(self.cluster)

        self.controller_map = {
            'asinfo': ASInfoController,
            'collectinfo': CollectinfoController,
            'show': ShowController,
            'info': InfoController,
            'features': FeaturesController,
            'pager': PagerController,
            'health': HealthCheckController,
            'summary': SummaryController,
        }

    def close(self):
        try:
            self.cluster.close()
        except Exception:
            pass

    # This function is a hack for autocomplete
    @CommandHelp('Terminate session')
    def do_exit(self, line):
        return "EXIT"

    @CommandHelp('Returns documentation related to a command',
                 'for example, to retrieve documentation for the "info"',
                 'command use "help info".')
    def do_help(self, line):
        self.execute_help(line)

    @CommandHelp('"watch" Runs a command for a specified pause and iterations.',
                 'Usage: watch [pause] [iterations] [--no-diff] command]',
                 '   pause:      the duration between executions.',
                 '               [default: 2 seconds]',
                 '   iterations: Number of iterations to execute command.',
                 '               [default: until keyboard interrupt]',
                 '   --no-diff:  Do not do diff highlighting',
                 'Example 1: Show "info network" 3 times with 1 second pause',
                 '           watch 1 3 info network',
                 'Example 2: Show "info namespace" with 5 seconds pause until',
                 '           interrupted',
                 '           watch 5 info namespace')
    def do_watch(self, line):
        self.view.watch(self, line)


@CommandHelp('The "info" command provides summary tables for various aspects',
             'of Aerospike functionality.')
class InfoController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with'])

    @CommandHelp('Displays network, namespace, and XDR summary information.')
    def _do_default(self, line):
        actions = (util.Future(self.do_network, line).start(),
                   util.Future(self.do_namespace, line).start(),
                   util.Future(self.do_xdr, line).start())

        return [action.result() for action in actions]

    @CommandHelp('Displays network information for Aerospike.')
    def do_network(self, line):
        stats = util.Future(self.cluster.info_statistics,
                            nodes=self.nodes).start()

        cluster_configs = util.Future(self.cluster.info_get_config,
                                      nodes=self.nodes,
                                      stanza='cluster').start()

        cluster_names = util.Future(
            self.cluster.info, 'cluster-name', nodes=self.nodes).start()
        builds = util.Future(
            self.cluster.info, 'build', nodes=self.nodes).start()
        versions = util.Future(
            self.cluster.info, 'version', nodes=self.nodes).start()

        stats = stats.result()
        cluster_configs = cluster_configs.result()
        cluster_names = cluster_names.result()
        builds = builds.result()
        versions = versions.result()

        for node in stats:
            try:
                if not isinstance(cluster_configs[node]["cluster"]["mode"],
                                  Exception):
                    stats[node]["rackaware_mode"] = cluster_configs[
                        node]["cluster"]["mode"]
            except Exception:
                pass
        return util.Future(self.view.info_network, stats, cluster_names,
                           versions, builds, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for each set.')
    def do_set(self, line):
        stats = self.cluster.info_set_statistics(nodes=self.nodes)
        return util.Future(self.view.info_set, stats, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for each namespace.')
    def do_namespace(self, line):
        stats = self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        return util.Future(self.view.info_namespace, stats, self.cluster,
                           **self.mods)

    @CommandHelp('Displays summary information for objects of each namespace.')
    def do_object(self, line):
        stats = self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        return util.Future(self.view.info_object, stats, self.cluster,
                           **self.mods)

    @CommandHelp('Displays summary information for Cross Datacenter',
                 'Replication (XDR).')
    def do_xdr(self, line):
        stats = util.Future(self.cluster.info_XDR_statistics,
                            nodes=self.nodes).start()

        builds = util.Future(self.cluster.info_XDR_build_version,
                             nodes=self.nodes).start()

        xdr_enable = util.Future(self.cluster.is_XDR_enabled,
                                 nodes=self.nodes).start()

        stats = stats.result()
        builds = builds.result()
        xdr_enable = xdr_enable.result()
        return util.Future(self.view.info_XDR, stats, builds, xdr_enable,
                           self.cluster, **self.mods)

    @CommandHelp('Displays summary information for each datacenter.')
    def do_dc(self, line):

        stats = util.Future(self.cluster.info_all_dc_statistics,
                            nodes=self.nodes).start()

        configs = util.Future(self.cluster.info_dc_get_config,
                              nodes=self.nodes).start()

        stats = stats.result()
        configs = configs.result()

        for node in stats.keys():

            if (stats[node]
                    and not isinstance(stats[node], Exception)
                    and configs[node]
                    and not isinstance(configs[node], Exception)):

                for dc in stats[node].keys():
                    stats[node][dc].update(configs[node][dc])
            elif ((not stats[node]
                   or isinstance(stats[node], Exception))
                    and configs[node]
                    and not isinstance(configs[node], Exception)):
                stats[node] = configs[node]

        return util.Future(self.view.info_dc, stats, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for Secondary Indexes (SIndex).')
    def do_sindex(self, line):
        sindex_stats = get_sindex_stats(self.cluster, self.nodes)
        return util.Future(self.view.info_sindex, sindex_stats, self.cluster,
                           **self.mods)

@CommandHelp('"asinfo" provides raw access to the info protocol.',
             '  Options:',
             '    -v <command>  - The command to execute',
             '    -p <port>     - Port to use in case of XDR info command',
             '                    and XDR is not in asd',
             '    -l            - Replace semicolons ";" with newlines.')
class ASInfoController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Executes an info command.')
    def _do_default(self, line):
        mods = self.parse_modifiers(line)
        line = mods['line']
        nodes = self.nodes

        value = None
        line_sep = False
        xdr = False
        show_node_name = True

        tline = line[:]

        try:
            while tline:
                word = tline.pop(0)
                if word == '-v':
                    value = tline.pop(0)
                elif word == '-l':
                    line_sep = True
                elif word == '-p':
                    port = tline.pop(0)
                    if port == '3004':  # ugly Hack
                        xdr = True
                elif word == '--no_node_name':
                    show_node_name = False
                else:
                    raise ShellException(
                        "Do not understand '%s' in '%s'" % (word, " ".join(line)))
        except Exception:
            self.logger.error(
                "Do not understand '%s' in '%s'" % (word, " ".join(line)))
            return
        if value is not None:
            value = value.translate(None, "'\"")
        if xdr:
            results = self.cluster.xdr_info(value, nodes=nodes)
        else:
            results = self.cluster.info(value, nodes=nodes)

        return util.Future(self.view.asinfo, results, line_sep, show_node_name,
                           self.cluster, **mods)


@CommandHelp('"show" is used to display Aerospike Statistics configuration.')
class ShowController(BasicCommandController):

    def __init__(self):
        self.controller_map = {
            'config': ShowConfigController,
            'statistics': ShowStatisticsController,
            'latency': ShowLatencyController,
            'distribution': ShowDistributionController,
            'mapping': ShowMappingController,
            'pmap': ShowPmapController
        }

        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp('"distribution" is used to show the distribution of object sizes',
             'and time to live for node and a namespace.')
class ShowDistributionController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with', 'for'])
        self.getter = GetDistributionController(self.cluster); 
        

    @CommandHelp('Shows the distributions of Time to Live and Object Size')
    def _do_default(self, line):
        actions = (util.Future(self.do_time_to_live, line[:]).start(),
                util.Future(self.do_object_size, line[:]).start())

        return [action.result() for action in actions]

    @CommandHelp('Shows the distribution of TTLs for namespaces')
    def do_time_to_live(self, line):
        
        histogram = self.getter.do_distribution('ttl', nodes=self.nodes)

        return util.Future(self.view.show_distribution, 'TTL Distribution',
                histogram, 'Seconds', 'ttl', self.cluster, like=self.mods['for'])


    @CommandHelp('Shows the distribution of Eviction TTLs for namespaces')
    def do_eviction(self, line):
        
        histogram = self.getter.do_distribution('evict', nodes=self.nodes)

        return util.Future(self.view.show_distribution, 'Eviction Distribution',
                histogram, 'Seconds', 'evict', self.cluster, like=self.mods['for'])

    @CommandHelp('Shows the distribution of Object sizes for namespaces',
                 '  Options:',
                 '    -b               - Force to show byte wise distribution of Object Sizes.',
                 '                       Default is rblock wise distribution in percentage',
                 '    -k <buckets>     - Maximum number of buckets to show if -b is set.',
                 '                       It distributes objects in same size k buckets and ',
                 '                       display only buckets which has objects in it. Default is 5.')
    def do_object_size(self, line):

        byte_distribution = util.check_arg_and_delete_from_mods(line=line,
                arg="-b", default=False, modifiers=self.modifiers,
                mods=self.mods)
    
        bucket_count = util.get_arg_and_delete_from_mods(line=line,
                arg="-k", return_type=int, default=5, modifiers=self.modifiers,
                mods=self.mods)

        if not byte_distribution:
            histogram = self.getter.do_object_size(nodes=self.nodes)

            return util.Future(self.view.show_distribution,
                    'Object Size Distribution', histogram, 'Record Blocks',
                    'objsz', self.cluster, like=self.mods['for'])
        

        histogram = self.getter.do_object_size(byte_distribution = True, bucket_count=bucket_count, nodes=self.nodes)

        histogram_name = 'objsz'
        title = 'Object Size Distribution'
        unit = 'Bytes'
        set_bucket_count = True

        return util.Future(self.view.show_object_distribution, title,
                histogram, unit, histogram_name, bucket_count,
                set_bucket_count, self.cluster, like=self.mods['for'])

class ShowLatencyController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with', 'like', 'for'])

    @CommandHelp('Displays latency information for Aerospike cluster.',
                 '  Options:',
                 '    -f <int>     - Number of seconds (before now) to look back to.',
                 '                   default: Minimum to get last slice',
                 '    -d <int>     - Duration, the number of seconds from start to search.',
                 '                   default: everything to present',
                 '    -t <int>     - Interval in seconds to analyze.',
                 '                   default: 0, everything as one slice',
                 '    -m           - Set to display the output group by machine names.')
    def _do_default(self, line):

        back = util.get_arg_and_delete_from_mods(line=line, arg="-f",
                return_type=int, default=None, modifiers=self.modifiers,
                mods=self.mods)

        duration = util.get_arg_and_delete_from_mods(line=line, arg="-d",
                return_type=int, default=None, modifiers=self.modifiers,
                mods=self.mods)

        slice_tm = util.get_arg_and_delete_from_mods(line=line, arg="-t",
                return_type=int, default=None, modifiers=self.modifiers,
                mods=self.mods)

        machine_wise_display = util.check_arg_and_delete_from_mods(line=line,
                arg="-m", default=False, modifiers=self.modifiers,
                mods=self.mods)

        namespace_set = set()
        if self.mods['for']:
            namespaces = self.cluster.info_namespaces(nodes=self.nodes)
            namespaces = namespaces.values()
            for namespace in namespaces:
                if isinstance(namespace, Exception):
                    continue
                namespace_set.update(namespace)
            namespace_set = set(
                util.filter_list(list(namespace_set), self.mods['for']))

        latency = self.cluster.info_latency(
            nodes=self.nodes, back=back, duration=duration, slice_tm=slice_tm, 
            ns_set=namespace_set)

        hist_latency = {}
        if machine_wise_display:
            hist_latency = latency
        else:
            for node_id, hist_data in latency.iteritems():
                if isinstance(hist_data, Exception):
                    continue
                for hist_name, data in hist_data.iteritems():
                    if hist_name not in hist_latency:
                        hist_latency[hist_name] = {node_id: data}
                    else:
                        hist_latency[hist_name][node_id] = data

        self.view.show_latency(hist_latency, self.cluster,
                machine_wise_display=machine_wise_display,
                show_ns_details=True if namespace_set else False, **self.mods)


@CommandHelp('"show config" is used to display Aerospike configuration settings')
class ShowConfigController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with', 'like', 'diff'])
        self.getter = GetConfigController(self.cluster)

    @CommandHelp('Displays service, network, and namespace configuration',
                 '  Options:',
                 '    -r <int>     - Repeating output table title and row header after every r columns.',
                 '                   default: 0, no repetition.',
                 '    -flip        - Flip output table to show Nodes on Y axis and config on X axis.')
    def _do_default(self, line):
        actions = (util.Future(self.do_service, line[:]).start(),
                   util.Future(self.do_network, line[:]).start(),
                   util.Future(self.do_namespace, line[:]).start())

        return [action.result() for action in actions]

    @CommandHelp('Displays service configuration')
    def do_service(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line, arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        service_configs = self.getter.get_service(nodes=self.nodes)

        return util.Future(self.view.show_config, "Service Configuration",
                           service_configs, self.cluster,
                           title_every_nth=title_every_nth, flip_output=flip_output,
                           **self.mods)

    @CommandHelp('Displays network configuration')
    def do_network(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        network_configs = self.getter.get_network(nodes=self.nodes)

        return util.Future(self.view.show_config, "Network Configuration",
                network_configs, self.cluster, title_every_nth=title_every_nth, flip_output=flip_output,
                **self.mods)

    @CommandHelp('Displays namespace configuration')
    def do_namespace(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        ns_configs = self.getter.get_namespace(nodes=self.nodes)

        return [util.Future(self.view.show_config, 
            "%s Namespace Configuration" % (ns), configs, self.cluster, 
            title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)
                for ns, configs in ns_configs.iteritems()]

    @CommandHelp('Displays XDR configuration')
    def do_xdr(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        xdr_configs = self.getter.get_xdr(nodes=self.nodes)

        return util.Future(self.view.show_config, "XDR Configuration",
                xdr_configs, self.cluster, title_every_nth=title_every_nth, flip_output=flip_output,
                **self.mods)

    @CommandHelp('Displays datacenter configuration')
    def do_dc(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        dc_configs = self.getter.get_dc(nodes=self.nodes)

        return [util.Future(self.view.show_config,
            "%s DC Configuration" % (dc), configs, self.cluster,
            title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)
            for dc, configs in dc_configs.iteritems()]

    @CommandHelp('Displays Cluster configuration')
    def do_cluster(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        cl_configs = self.getter.get_cluster(nodes=self.nodes)

        return util.Future(self.view.show_config, "Cluster Configuration",
                cl_configs, self.cluster, title_every_nth=title_every_nth, flip_output=flip_output,
                **self.mods)


@CommandHelp('"show mapping" is used to display Aerospike mapping from IP to Node_id and Node_id to IPs')
class ShowMappingController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['like'])

    @CommandHelp('Displays mapping IPs to Node_id and Node_id to IPs')
    def _do_default(self, line):
        actions = (util.Future(self.do_ip, line).start(),
                   util.Future(self.do_node, line).start())
        return [action.result() for action in actions]

    @CommandHelp('Displays IP to Node_id mapping')
    def do_ip(self, line):
        ip_to_node_map = self.cluster.get_IP_to_node_map()
        return util.Future(self.view.show_mapping, "IP", "NODE-ID",
                ip_to_node_map, **self.mods)

    @CommandHelp('Displays Node_id to IPs mapping')
    def do_node(self, line):
        node_to_ip_map = self.cluster.get_node_to_IP_map()
        return util.Future(self.view.show_mapping, "NODE-ID", "IPs",
                node_to_ip_map, **self.mods)


@CommandHelp('Displays statistics for Aerospike components.')
class ShowStatisticsController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with', 'like', 'for'])
        self.getter = GetStatisticsController(self.cluster)

    @CommandHelp('Displays bin, set, service, and namespace statistics',
                 '  Options:',
                 '    -t           - Set to show total column at the end. It contains node wise sum for statistics.',
                 '    -r <int>     - Repeating output table title and row header after every r columns.',
                 '                   default: 0, no repetition.',
                 '    -flip        - Flip output table to show Nodes on Y axis and stats on X axis.')
    def _do_default(self, line):

        actions = (util.Future(self.do_bins, line[:]).start(),
                   util.Future(self.do_sets, line[:]).start(),
                   util.Future(self.do_service, line[:]).start(),
                   util.Future(self.do_namespace, line[:]).start())

        return [action.result() for action in actions]

    @CommandHelp('Displays service statistics')
    def do_service(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        service_stats = self.getter.get_service(nodes=self.nodes)

        return util.Future(self.view.show_stats, "Service Statistics",
                service_stats, self.cluster, show_total=show_total,
                title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)

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

        ns_stats = self.getter.get_namespace(nodes=self.nodes, for_mods=self.mods['for'])

        return [util.Future(self.view.show_stats,
            "%s Namespace Statistics" % (namespace), ns_stats[namespace], 
            self.cluster, show_total=show_total, 
            title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)
            for namespace in sorted(ns_stats.keys())]

    @CommandHelp('Displays sindex statistics')
    def do_sindex(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        sindex_stats = self.getter.get_sindex(nodes=self.nodes, for_mods=self.mods['for'])

        return [util.Future(self.view.show_stats,
            "%s Sindex Statistics" % (ns_set_sindex),
            sindex_stats[ns_set_sindex], self.cluster, show_total=show_total,
            title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)
            for ns_set_sindex in sorted(sindex_stats.keys())]

    @CommandHelp('Displays set statistics')
    def do_sets(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        set_stats = self.getter.get_sets(nodes=self.nodes, for_mods=self.mods['for'])

        return [util.Future(self.view.show_stats,
            "%s %s Set Statistics" % (namespace, set_name), stats,
            self.cluster, show_total=show_total,
            title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)
            for (namespace, set_name), stats in set_stats.iteritems()]

    @CommandHelp('Displays bin statistics')
    def do_bins(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        new_bin_stats = self.getter.get_bins(nodes=self.nodes, for_mods=self.mods['for'])

        return [util.Future(self.view.show_stats,
            "%s Bin Statistics" % (namespace), new_bin_stat, self.cluster,
            show_total=show_total, title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)
            for namespace, new_bin_stat in new_bin_stats.iteritems()]

    @CommandHelp('Displays XDR statistics')
    def do_xdr(self, line):

        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                default=False, modifiers=self.modifiers, mods=self.mods)

        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        xdr_stats = self.getter.get_xdr(nodes=self.nodes)

        return util.Future(self.view.show_stats, "XDR Statistics", xdr_stats,
                self.cluster, show_total=show_total,
                title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)

    @CommandHelp('Displays datacenter statistics')
    def do_dc(self, line):
        
        show_total = util.check_arg_and_delete_from_mods(line=line, arg="-t",
                default=False, modifiers=self.modifiers, mods=self.mods)
        
        title_every_nth = util.get_arg_and_delete_from_mods(line=line,
                arg="-r", return_type=int, default=0, modifiers=self.modifiers,
                mods=self.mods)

        flip_output = util.check_arg_and_delete_from_mods(line=line,
                arg="-flip", default=False, modifiers=self.modifiers,
                mods=self.mods)

        dc_stats = self.getter.get_dc(nodes=self.nodes)

        return [util.Future(self.view.show_config, "%s DC Statistics" % (dc),
            stats, self.cluster, show_total=show_total,
            title_every_nth=title_every_nth, flip_output=flip_output, **self.mods)
            for dc, stats in dc_stats.iteritems()]

@CommandHelp('Displays partition map analysis of Aerospike cluster.')
class ShowPmapController(BasicCommandController):
    def __init__(self):
        self.modifiers = set()
        self.getter = GetPmapController(self.cluster)

    def _do_default(self, line):
        pmap_data = self.getter.get_pmap(nodes=self.nodes)

        return util.Future(self.view.show_pmap, pmap_data, self.cluster)

@CommandHelp('"collectinfo" is used to collect cluster info, aerospike conf file and system stats.')
class CollectinfoController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with'])

    def _collect_local_file(self, src, dest_dir):
        self.logger.info("Copying file %s to %s" % (src, dest_dir))
        try:
            shutil.copy2(src, dest_dir)
        except Exception, e:
            self.logger.error(e)
        return

    def _collectinfo_content(self, func, parm='', alt_parm=''):
        name = ''
        capture_stdout = util.capture_stdout
        sep = "\n====ASCOLLECTINFO====\n"
        try:
            name = func.func_name
        except Exception:
            pass
        info_line = "Data collection for " + name + \
            "%s" % (" %s" % (str(parm)) if parm else "") + " in progress.."
        self.logger.info(info_line)
        if parm:
            sep += str(parm) + "\n"

        if func == 'shell':
            o, e = util.shell_command(parm)
            if e:
                if e:
                    self.logger.error(str(e))

                if alt_parm and alt_parm[0]:
                    info_line = "Data collection for alternative command " + \
                                name + str(alt_parm) + " in progress.."
                    self.logger.info(info_line)
                    sep += str(alt_parm) + "\n"
                    o_alt, e_alt = util.shell_command(alt_parm)

                    if e_alt:
                        self.cmds_error.add(parm[0])
                        self.cmds_error.add(alt_parm[0])

                        if e_alt:
                            self.logger.error(str(e_alt))

                    if o_alt:
                        o = o_alt

                else:
                    self.cmds_error.add(parm[0])

        elif func == 'cluster':
            o = self.cluster.info(parm)
        else:
            if self.nodes and isinstance(self.nodes, list):
                parm += ["with"] + self.nodes
            o = capture_stdout(func, parm)
        self._write_log(sep + str(o))
        return ''

    def _write_log(self, collectedinfo):
        f = open(str(aslogfile), 'a')
        f.write(str(collectedinfo))
        return f.close()

    def _write_version(self, line):
        print "asadm version " + str(self.asadm_version)

    def _get_metadata(self, response_str, prefix='', old_response=''):
        aws_c = ''
        aws_metadata_base_url = 'http://169.254.169.254/latest/meta-data'

        # set of values which will give same old_response, so no need to go further
        last_values = []
        for rsp in response_str.split("\n"):
            if rsp[-1:] == '/':
                rsp_p = rsp.strip('/')
                aws_c += self._get_metadata(rsp_p, prefix, old_response=old_response)
            else:
                meta_url = aws_metadata_base_url + prefix + rsp

                req = urllib2.Request(meta_url)
                r = urllib2.urlopen(req)
                # r = requests.get(meta_url,timeout=aws_timeout)
                if r.code != 404:
                    response = r.read().strip()
                    if response == old_response:
                        last_values.append(rsp.strip())
                        continue
                    try:
                            aws_c += self._get_metadata(response, prefix + rsp + "/", old_response=response)
                    except Exception:
                            aws_c +=  (prefix + rsp).strip('/') + '\n' + response + "\n\n"

        if last_values:
            aws_c += prefix.strip('/') + '\n' + '\n'.join(last_values) + "\n\n"

        return aws_c

    def _get_awsdata(self, line):
        aws_rsp = ''
        aws_timeout = 1
        socket.setdefaulttimeout(aws_timeout)
        aws_metadata_base_url = 'http://169.254.169.254/latest/meta-data'
        print "['AWS']"
        try:
            req = urllib2.Request(aws_metadata_base_url)
            r = urllib2.urlopen(req)
            # r = requests.get(aws_metadata_base_url,timeout=aws_timeout)
            if r.code == 200:
                rsp = r.read()
                aws_rsp += self._get_metadata(rsp, '/')
                print "Requesting... {0} \n{1}  \t Successful".format(aws_metadata_base_url, aws_rsp)
            else:
                aws_rsp = " Not likely in AWS"
                print "Requesting... {0} \t FAILED {1} ".format(aws_metadata_base_url, aws_rsp)

        except Exception as e:
            print "Requesting... {0} \t  {1} ".format(aws_metadata_base_url, e)
            print "FAILED! Node Is Not likely In AWS"

    def _collect_sys(self, line=''):
        print "['cpuinfo']"
        cpu_info_cmd = 'cat /proc/cpuinfo | grep "vendor_id"'
        o, e = util.shell_command([cpu_info_cmd])
        if o:
            o = o.strip().split("\n")
            cpu_info = {}
            for item in o:
                items = item.strip().split(":")
                if len(items) == 2:
                    key = items[1].strip()
                    if key in cpu_info.keys():
                        cpu_info[key] = cpu_info[key] + 1
                    else:
                        cpu_info[key] = 1
            print "vendor_id\tprocessor count"
            for key in cpu_info.keys():
                print key + "\t" + str(cpu_info[key])

    def _get_asd_pids(self):
        pids = []
        ps_cmd = 'sudo ps aux|grep -v grep|grep -E "asd|cld"'
        ps_o, ps_e = util.shell_command([ps_cmd])
        if ps_o:
            ps_o = ps_o.strip().split("\n")
            pids = []
            for item in ps_o:
                vals = item.strip().split()
                if len(vals) >= 2:
                    pids.append(vals[1])
        return pids

    def _collect_logs_from_systemd_journal(self, as_logfile_prefix):
        asd_pids = self._get_asd_pids()
        for pid in asd_pids:
            try:
                journalctl_cmd = [
                    'journalctl _PID=%s --since "24 hours ago" -q -o cat' % (pid)]
                aslogfile = as_logfile_prefix + 'aerospike_%s.log' % (pid)
                print "[INFO] Data collection for %s to %s in progress..." % (str(journalctl_cmd), aslogfile)
                o, e = util.shell_command(journalctl_cmd)
                if e:
                    print e
                else:
                    self._write_log(o)
            except Exception as e1:
                print str(e1)
                sys.stdout = sys.__stdout__

    def _collect_lsof(self, verbose=False):
        print "['lsof']"
        pids = self._get_asd_pids()
        if pids and len(pids) > 0:
            search_str = pids[0]
            for _str in pids[1:len(pids)]:
                search_str += "\\|" + _str
            lsof_cmd = 'sudo lsof -n |grep "%s"' % (search_str)
            lsof_o, lsof_e = util.shell_command([lsof_cmd])
            if lsof_e:
                print lsof_e
                self.cmds_error.add(lsof_cmd)
            if lsof_o:
                if verbose:
                    print lsof_o
                else:
                    lsof_dic = {}
                    unidentified_protocol_count = 0
                    lsof_list = lsof_o.strip().split("\n")
                    type_ljust_parm = 20
                    desc_ljust_parm = 20
                    for row in lsof_list:
                        try:
                            if "can't identify protocol" in row:
                                unidentified_protocol_count = unidentified_protocol_count + \
                                    1
                        except Exception:
                            pass

                        try:
                            type = row.strip().split()[4]
                            if type not in lsof_dic:

                                if len(type) > type_ljust_parm:
                                    type_ljust_parm = len(type)

                                if (type in lsof_file_type_desc
                                        and len(lsof_file_type_desc[type]) > desc_ljust_parm):
                                    desc_ljust_parm = len(
                                        lsof_file_type_desc[type])

                                lsof_dic[type] = 1
                            else:
                                lsof_dic[type] = lsof_dic[type] + 1

                        except Exception:
                            continue

                    print "FileType".ljust(type_ljust_parm) + "Description".ljust(desc_ljust_parm) + "fd count"
                    for ftype in sorted(lsof_dic.keys()):
                        desc = "Unknown"
                        if ftype in lsof_file_type_desc:
                            desc = lsof_file_type_desc[ftype]
                        print ftype.ljust(type_ljust_parm) + desc.ljust(desc_ljust_parm) + str(lsof_dic[ftype])

                    print "\nUnidentified Protocols = " + str(unidentified_protocol_count)

    def _zip_files(self, dir_path, _size=1):
        """
        If file size is greater then given _size, create zip of file on same location and
        remove original one. Won't zip If zlib module is not available.
        """
        for root, dirs, files in os.walk(dir_path):
            for _file in files:
                file_path = os.path.join(root, _file)
                size_mb = (os.path.getsize(file_path) / (1024 * 1024))
                if size_mb >= _size:
                    os.chdir(root)
                    try:
                        newzip = zipfile.ZipFile(
                            _file + ".zip", "w", zipfile.ZIP_DEFLATED)
                        newzip.write(_file)
                        newzip.close()
                        os.remove(_file)
                    except Exception as e:
                        print e
                        pass

    def _archive_log(self, logdir):
        self._zip_files(logdir)
        util.shell_command(["tar -czvf " + logdir + ".tgz " + aslogdir])
        sys.stderr.write("\x1b[2J\x1b[H")
        print "\n\n\n"
        self.logger.info("Files in " + logdir + " and " + logdir + ".tgz saved. ")
        self.logger.info("END OF ASCOLLECTINFO")

    def _parse_namespace(self, namespace_data):
        """
        This method will return set of namespaces present given namespace data
        @param namespace_data: should be a form of dict returned by info protocol for namespace.
        """
        namespaces = set()
        for _value in namespace_data.values():
            for ns in _value.split(';'):
                namespaces.add(ns)
        return namespaces

    ###########################################################################
    # Function for dumping json

    def _restructure_set_section(self, stats):
        for node, node_data in stats.iteritems():
            if 'set' not in node_data.keys():
                continue

            for key, val in node_data['set'].iteritems():
                ns_name = key[0]
                setname = key[1]

                if ns_name not in node_data['namespace']:
                    continue

                ns = node_data['namespace'][ns_name]

                if 'set' not in ns.keys():
                    ns['set'] = {}

                ns['set'][setname] = copy.deepcopy(val)

            del node_data['set']

    def _restructure_sindex_section(self, stats):
        # Due to new server feature namespace add/remove with rolling restart,
        # there is possibility that different nodes will have different namespaces and
        # old sindex info available for node which does not have namespace for that sindex.

        for node, node_data in stats.iteritems():
            if 'sindex' not in node_data.keys():
                continue

            for key, val in node_data['sindex'].iteritems():
                key_list = key.split()
                ns_name = key_list[0]
                sindex_name = key_list[2]

                if ns_name not in node_data['namespace']:
                    continue

                ns = node_data['namespace'][ns_name]
                if 'sindex' not in ns.keys():
                    ns['sindex'] = {}
                ns['sindex'][sindex_name] = copy.deepcopy(val)

            del node_data['sindex']

    def _restructure_bin_section(self, stats):
        for node, node_data in stats.iteritems():
            if 'bin' not in node_data.keys():
                continue
            for ns_name, val in node_data['bin'].iteritems():
                if ns_name not in node_data['namespace']:
                    continue

                ns = node_data['namespace'][ns_name]
                ns['bin'] = copy.deepcopy(val)

            del node_data['bin']

    def _init_stat_ns_subsection(self, data):
        for node, node_data in data.iteritems():
            if 'namespace' not in node_data.keys():
                continue
            ns_map = node_data['namespace']
            for ns, data in ns_map.iteritems():
                ns_map[ns]['set'] = {}
                ns_map[ns]['bin'] = {}
                ns_map[ns]['sindex'] = {}

    def _restructure_ns_section(self, data):
        for node, node_data in data.iteritems():
            if 'namespace' not in node_data.keys():
                continue
            ns_map = node_data['namespace']
            for ns, data in ns_map.iteritems():
                stat = {}
                stat[ns] = {}
                stat[ns]['service'] = data
                ns_map[ns] = stat[ns]

    def _remove_exception_from_section_output(self, data):
        for section in data:
            for node in data[section]:
                if isinstance(data[section][node], Exception):
                    data[section][node] = {}

    def _get_as_data_json(self):
        as_map = {}
        getter = GetStatisticsController(self.cluster)
        stats = getter.get_all(nodes=self.nodes)

        getter = GetConfigController(self.cluster)
        config = getter.get_all(nodes=self.nodes)

        # All these section have have nodeid in inner level
        # flip keys to get nodeid in upper level.
        # {'namespace': 'test': {'ip1': {}, 'ip2': {}}} -->
        # {'namespace': {'ip1': {'test': {}}, 'ip2': {'test': {}}}}
        stats['namespace'] = util.flip_keys(stats['namespace'])
        stats['set'] = util.flip_keys(stats['set'])
        stats['bin'] = util.flip_keys(stats['bin'])
        stats['dc'] = util.flip_keys(stats['dc'])
        stats['sindex'] = util.flip_keys(stats['sindex'])
        config['namespace'] = util.flip_keys(config['namespace'])
        config['dc'] = util.flip_keys(config['dc'])

        self._remove_exception_from_section_output(stats)
        self._remove_exception_from_section_output(config)

        # flip key to get node ids in upper level and sections inside them.
        # {'namespace': {'ip1': {'test': {}}, 'ip2': {'test': {}}}} -->
        # {'ip1':{'namespace': {'test': {}}}, 'ip2': {'namespace': {'test': {}}}}
        new_stats = util.flip_keys(stats)
        new_config = util.flip_keys(config)

        # Create a new service level for all ns stats.
        # {'namespace': 'test': {<stats>}} -->
        # {'namespace': 'test': {'service': {<stats>}}}
        self._restructure_ns_section(new_stats)
        # ns stats would have set and bin data too, service level will
        # consolidate its service stats and put sets, sindex, bin stats
        # in namespace section
        self._init_stat_ns_subsection(new_stats)
        self._restructure_set_section(new_stats)
        self._restructure_sindex_section(new_stats)
        self._restructure_bin_section(new_stats)
        # No config for set, sindex, bin
        self._restructure_ns_section(new_config)

        # check this 'XDR': {'STATISTICS': {'192.168.112.194:3000':
        # Type_error('expected str
        as_map['statistics'] = new_stats
        as_map['config'] = new_config

        new_as_map = util.flip_keys(as_map)

        return new_as_map

    def _get_meta_for_sec(self, metasec, sec_name, nodeid, metamap):
        if nodeid in metasec:
            if not isinstance(metasec[nodeid], Exception):
                metamap[nodeid][sec_name] = metasec[nodeid]
            else:
                metamap[nodeid][sec_name] = ''

    def _get_as_metadata(self):
        metamap = {}
        builds = util.Future(self.cluster.info, 'build', nodes=self.nodes).start().result()
        editions = util.Future(self.cluster.info, 'version', nodes=self.nodes).start().result()
        xdr_builds = util.Future(self.cluster.info_XDR_build_version, nodes=self.nodes).start().result()
        node_ids = util.Future(self.cluster.info_node, nodes=self.nodes).start().result()
        ips = util.Future(self.cluster.info_ip_port, nodes=self.nodes).start().result()
        udf_data = util.Future(self.cluster.info_udf_list, nodes=self.nodes).start().result()

        for nodeid in builds:
            metamap[nodeid] = {}
            self._get_meta_for_sec(builds, 'asd_build', nodeid, metamap)
            self._get_meta_for_sec(editions, 'edition', nodeid, metamap)
            self._get_meta_for_sec(xdr_builds, 'xdr_build', nodeid, metamap)
            self._get_meta_for_sec(node_ids, 'node_id', nodeid, metamap)
            self._get_meta_for_sec(ips, 'ip', nodeid, metamap)
            self._get_meta_for_sec(udf_data, 'udf', nodeid, metamap)

        return metamap

    def _get_as_histograms(self):
        histogram_map = {}
        hist_list = ['ttl', 'objsz']

        for hist in hist_list:
            hist_dump = util.Future(self.cluster.info_histogram, hist, raw_output=True, nodes=self.nodes).start().result()
            for node in hist_dump:
                if node not in histogram_map:
                    histogram_map[node] = {}

                if not hist_dump[node] or isinstance(hist_dump[node], Exception):
                    continue

                histogram_map[node][hist] = hist_dump[node]

        return histogram_map

    def _get_as_pmap(self):
        getter = GetPmapController(self.cluster)
        return getter.get_pmap(nodes=self.nodes)

    def _dump_in_json_file(self, as_logfile_prefix, dump):
        self.logger.info("Dumping collectinfo in JSON format.")
        aslogfile = as_logfile_prefix + 'ascinfo.json'
        with open(aslogfile, "w") as f:
            f.write(json.dumps(dump, indent=4, separators=(',', ':')))

    def _get_collectinfo_data_json(self, default_user, default_pwd,
            default_ssh_port, default_ssh_key, credential_file):

        dump_map = {}

        meta_map = self._get_as_metadata()

        histogram_map = self._get_as_histograms()

        pmap_map = self._get_as_pmap()

        sys_map = self.cluster.info_system_statistics(default_user=default_user, default_pwd=default_pwd, default_ssh_key=default_ssh_key,
                                                      default_ssh_port=default_ssh_port, credential_file=credential_file, nodes=self.nodes)

        as_map = self._get_as_data_json()

        for node in as_map:
            dump_map[node] = {}
            dump_map[node]['as_stat'] = as_map[node]
            if node in sys_map:
                dump_map[node]['sys_stat'] = sys_map[node]
            if node in meta_map:
                dump_map[node]['as_stat']['meta_data'] = meta_map[node]

            if node in histogram_map:
                 dump_map[node]['as_stat']['histogram'] = histogram_map[node]

            if node in pmap_map:
                 dump_map[node]['as_stat']['pmap'] = pmap_map[node]

        # Get the cluster name and add one more level in map
        cluster_name = 'null'
        cluster_names = util.Future(
            self.cluster.info, 'cluster-name').start().result()

        # Cluster name.
        for node in cluster_names:
            if not isinstance(cluster_names[node], Exception) and cluster_names[node] not in ["null"]:
                cluster_name = cluster_names[node]
                break

        snp_map = {}
        snp_map[cluster_name] = dump_map
        return snp_map

    def _dump_collectinfo_json(self, timestamp, as_logfile_prefix, default_user, default_pwd, default_ssh_port, default_ssh_key, credential_file,
                               snp_count, wait_time):
        snpshots = {}

        for i in range(snp_count):

            snp_timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            self.logger.info("Data collection for Snapshot: " + str(i + 1) + " in progress..")
            snpshots[snp_timestamp] = self._get_collectinfo_data_json(
                default_user, default_pwd, default_ssh_port, default_ssh_key, credential_file)

            time.sleep(wait_time)

        self._dump_in_json_file(as_logfile_prefix, snpshots)

    def _dump_collectinfo_pretty_print(self, timestamp, as_logfile_prefix,
            show_all=False, verbose=False):

        # getting service port to use in ss/netstat command
        port = 3000
        try:
            host, port, tls = list(self.cluster._original_seed_nodes)[0]
        except Exception:
            port = 3000

        # Unfortunately timestamp can not be printed in Centos with dmesg,
        # storing dmesg logs without timestamp for this particular OS.
        if 'centos' == (platform.linux_distribution()[0]).lower():
            cmd_dmesg = 'sudo dmesg'
            alt_dmesg = ''
        else:
            cmd_dmesg = 'sudo dmesg -T'
            alt_dmesg = 'sudo dmesg'

        collect_output = time.strftime("%Y-%m-%d %H:%M:%S UTC\n", timestamp)
        global aslogfile, output_time

        # cmd and alternative cmds are stored in list of list instead of dic to
        # maintain proper order for output
        sys_shell_cmds = [
            ['hostname -I', 'hostname'],
            ['uname -a', ''],
            ['lsb_release -a',
             'ls /etc|grep release|xargs -I f cat /etc/f'],
            ['cat /proc/meminfo', 'vmstat -s'],
            ['cat /proc/interrupts', ''],
            ['cat /proc/partitions', 'fdisk -l'],
            [
                'ls /sys/block/{sd*,xvd*}/queue/rotational |xargs -I f sh -c "echo f; cat f;"', ''],
            [
                'ls /sys/block/{sd*,xvd*}/device/model |xargs -I f sh -c "echo f; cat f;"', ''],
            [
                'ls /sys/block/{sd*,xvd*}/queue/scheduler |xargs -I f sh -c "echo f; cat f;"', ''],
            ['rpm -qa|grep -E "citrus|aero"',
             'dpkg -l|grep -E "citrus|aero"'],
            ['ip addr', ''],
            ['ip -s link', ''],
            ['sudo iptables -L', ''],
            ['sudo sysctl -a | grep -E "shmmax|file-max|maxfiles"',
             ''],
            ['iostat -x 1 10', ''],
            ['sar -n DEV', ''],
            ['sar -n EDEV', ''],
            ['df -h', ''],
            ['free -m', ''],
            [cmd_dmesg, alt_dmesg],
            ['top -n3 -b', 'top -l 3'],
            ['mpstat -P ALL 2 3', ''],
            ['uptime', ''],
            ['ss -pant | grep %d | grep TIME-WAIT | wc -l' %
                (port), 'netstat -pant | grep %d | grep TIME_WAIT | wc -l' % (port)],
            ['ss -pant | grep %d | grep CLOSE-WAIT | wc -l' %
                (port), 'netstat -pant | grep %d | grep CLOSE_WAIT | wc -l' % (port)],
            ['ss -pant | grep %d | grep ESTAB | wc -l' %
                (port), 'netstat -pant | grep %d | grep ESTABLISHED | wc -l' % (port)],
            ['ss -pant | grep %d | grep LISTEN | wc -l' %
                (port), 'netstat -pant | grep %d | grep LISTEN | wc -l' % (port)]
        ]
        dignostic_info_params = [
            'network', 'namespace', 'set', 'xdr', 'dc', 'sindex']
        dignostic_features_params = ['features']
        dignostic_show_params = ['config', 'config xdr', 'config dc', 'config cluster', 'distribution', 'distribution eviction',
                                 'distribution object_size -b', 'latency', 'statistics', 'statistics xdr', 'statistics dc', 'statistics sindex', 'pmap']
        dignostic_aerospike_cluster_params = ['service', 'services']
        dignostic_aerospike_cluster_params_additional = [
            'partition-info',
            'dump-msgs:',
            'dump-wr:'
        ]
        dignostic_aerospike_cluster_params_additional_verbose = [
            'dump-fabric:',
            'dump-hb:',
            'dump-migrates:',
            'dump-paxos:',
            'dump-smd:'
        ]

        summary_params = ['summary']
        summary_info_params = ['network', 'namespace', 'object', 'set', 'xdr', 'dc', 'sindex']
        health_params = ['health -v']

        hist_list = ['ttl', 'objsz']
        hist_dump_info_str = "hist-dump:ns=%s;hist=%s"

        my_ips = (util.shell_command(["hostname -I"])[0]).split(' ')
        _ip = my_ips[0].strip()
        as_version = None

        # Need to find correct IP as per the configuration
        for ip in my_ips:
            try:
                as_version = self.cluster.call_node_method(
                    [ip.strip()], "info", "build").popitem()[1]
                if not as_version or isinstance(as_version, Exception):
                    continue
                _ip = ip.strip()
                break
            except Exception:
                pass

        try:
            namespaces = self._parse_namespace(self.cluster.info("namespaces"))
        except Exception:
            namespaces = []

        for ns in namespaces:
            for hist in hist_list:
                dignostic_aerospike_cluster_params.append(
                    hist_dump_info_str % (ns, hist))

        if show_all:

            for ns in namespaces:
                # dump-wb dumps debug information about Write Bocks, it needs
                # namespace, device-id and write-block-id as a parameter
                # dignostic_cluster_params_additional.append('dump-wb:ns=' + ns)

                dignostic_aerospike_cluster_params_additional.append(
                    'dump-wb-summary:ns=' + ns)

            if verbose:
                for index, param in enumerate(dignostic_aerospike_cluster_params_additional_verbose):
                    if param.startswith("dump"):
                        if not param.endswith(":"):
                            param = param + ";"
                        param = param + "verbose=true"
                    dignostic_aerospike_cluster_params_additional_verbose[
                        index] = param

            dignostic_aerospike_cluster_params = dignostic_aerospike_cluster_params + \
                dignostic_aerospike_cluster_params_additional + \
                dignostic_aerospike_cluster_params_additional_verbose

        if 'ubuntu' == (platform.linux_distribution()[0]).lower():
            cmd_dmesg = 'cat /var/log/syslog'
        else:
            cmd_dmesg = 'cat /var/log/messages'

        ####### Dignostic info ########

        aslogfile = as_logfile_prefix + 'ascollectinfo.log'
        self._write_log(collect_output)

        try:
            self._collectinfo_content(self._write_version)
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            info_controller = InfoController()
            for info_param in dignostic_info_params:
                self._collectinfo_content(info_controller, [info_param])
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            show_controller = ShowController()
            for show_param in dignostic_show_params:
                self._collectinfo_content(show_controller, show_param.split())
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            features_controller = FeaturesController()
            for cmd in dignostic_features_params:
                self._collectinfo_content(features_controller, [cmd])
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            for cmd in dignostic_aerospike_cluster_params:
                self._collectinfo_content('cluster', cmd)
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        ####### Summary ########
        collectinfo_root_controller = CollectinfoRootController(asadm_version=self.asadm_version, clinfo_path=as_logfile_prefix + "ascinfo.json")

        aslogfile = as_logfile_prefix + 'summary.log'
        self._write_log(collect_output)
        try:
            self._collectinfo_content(self._write_version)
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            for summary_param in summary_params:
                self._collectinfo_content(collectinfo_root_controller.execute, [summary_param])
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            info_controller = InfoController()
            for info_param in summary_info_params:
                self._collectinfo_content(info_controller, [info_param])
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        ####### Health ########

        aslogfile = as_logfile_prefix + 'health.log'
        self._write_log(collect_output)

        try:
            for health_param in health_params:
                self._collectinfo_content(collectinfo_root_controller.execute, health_param.split())
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        ####### System info ########

        aslogfile = as_logfile_prefix + 'sysinfo.log'
        self._write_log(collect_output)

        try:
            for cmds in sys_shell_cmds:
                self._collectinfo_content('shell', [cmds[0]], [cmds[1]])
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            self._collectinfo_content(self._collect_sys)
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            self._collectinfo_content(self._get_awsdata)
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            self._collectinfo_content(self._collect_lsof)
        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

        if show_all and verbose:
            try:
                self._collectinfo_content(self._collect_lsof, verbose)
            except Exception as e:
                self._write_log(str(e))
                sys.stdout = sys.__stdout__

        ####### Logs and conf ########

        ##### aerospike logs #####

        conf_path = '/etc/aerospike/aerospike.conf'
        # Comparing with this version because prior to this it was
        # citrusleaf.conf
        if LooseVersion(as_version) <= LooseVersion("3.0.0"):
            conf_path = '/etc/citrusleaf/citrusleaf.conf'

        if show_all:
            ##### aerospike xdr logs #####
            # collectinfo can read the xdr log file from default path for old aerospike version which can not provide xdr log path in asinfo command
            # for latest xdr-in-asd versions, 'asinfo -v logs' provide all logs
            # including xdr log, so no need to read it separately
            try:
                if True in self.cluster.is_XDR_enabled().values():
                    is_xdr_in_asd_version = False
                    try:
                        is_xdr_in_asd_version = self.cluster.call_node_method(
                            [_ip], "is_feature_present", "xdr").popitem()[1]
                    except Exception:
                        from lib.node import Node
                        temp_node = Node(_ip)
                        is_xdr_in_asd_version = self.cluster.call_node_method(
                            [temp_node.ip], "is_feature_present", "xdr").popitem()[1]

                    if not is_xdr_in_asd_version:
                        try:
                            o, e = util.shell_command(
                                ["grep errorlog-path " + conf_path])
                            if e:
                                xdr_log_location = '/var/log/aerospike/*xdr.log'
                            else:
                                xdr_log_location = o.split()[1]
                        except Exception:
                            xdr_log_location = '/var/log/aerospike/*xdr.log'

                        aslogfile = as_logfile_prefix + 'asxdr.log'
                        self._collectinfo_content(
                            'shell', ['cat ' + xdr_log_location])
            except Exception as e:
                self._write_log(str(e))
                sys.stdout = sys.__stdout__

            try:
                try:
                    log_locations = [i.split(':')[1] for i in self.cluster.call_node_method(
                        [_ip], "info", "logs").popitem()[1].split(';')]
                except Exception:
                    from lib.node import Node
                    temp_node = Node(_ip)
                    log_locations = [i.split(':')[1] for i in self.cluster.call_node_method(
                        [temp_node.ip], "info", "logs").popitem()[1].split(';')]
                file_name_used = {}
                for log in log_locations:
                    if os.path.exists(log):
                        file_name_base = os.path.basename(log)
                        if file_name_base in file_name_used:
                            file_name_used[file_name_base] = file_name_used[
                                file_name_base] + 1
                            file_name, ext = os.path.splitext(file_name_base)
                            file_name_base = file_name + "-" + \
                                str(file_name_used[file_name_base]) + ext
                        else:
                            file_name_used[file_name_base] = 1

                        self._collect_local_file(
                            log, as_logfile_prefix + file_name_base)
                    # machine is running with systemd, so need to read logs
                    # from systemd journal
                    else:
                        try:
                            self._collect_logs_from_systemd_journal(
                                as_logfile_prefix)
                        except Exception as e1:
                            self._write_log(str(e1))
                            sys.stdout = sys.__stdout__
            except Exception as e:
                self._write_log(str(e))
                sys.stdout = sys.__stdout__

        ##### aerospike conf file #####
        try:
            # Comparing with this version because prior to this it was
            # citrusleaf.conf & citrusleaf.log
            if LooseVersion(as_version) > LooseVersion("3.0.0"):
                aslogfile = as_logfile_prefix + 'aerospike.conf'
            else:
                aslogfile = as_logfile_prefix + 'citrusleaf.conf'

            self._write_log(collect_output)
            self._collectinfo_content('shell', ['cat %s' % (conf_path)])

        except Exception as e:
            self._write_log(str(e))
            sys.stdout = sys.__stdout__

    def _main_collectinfo(self, default_user, default_pwd, default_ssh_port, default_ssh_key,
            credential_file, snp_count, wait_time, show_all=False,
            verbose=False):
        global aslogdir, output_time
        timestamp = time.gmtime()
        output_time = time.strftime("%Y%m%d_%H%M%S", timestamp)
        aslogdir = '/tmp/collect_info_' + output_time
        as_logfile_prefix = aslogdir + '/' + output_time + '_'

        os.makedirs(aslogdir)

        # Coloring might writes extra characters to file, to avoid it we need to disable terminal coloring
        terminal.enable_color(False)

        # JSON collectinfo
        if snp_count < 1:
            self._archive_log(aslogdir)
            return

        self._dump_collectinfo_json(timestamp, as_logfile_prefix, default_user, default_pwd, default_ssh_port, default_ssh_key,
                                    credential_file, snp_count, wait_time,)

        # Pretty print collectinfo
        self._dump_collectinfo_pretty_print(timestamp, as_logfile_prefix, show_all=show_all, verbose=verbose)

        # Archive collectinfo directory
        self._archive_log(aslogdir)

        # If multiple commands are given in execute_only mode then we might need coloring for next commands
        terminal.enable_color(True)


    @CommandHelp('Collects cluster info, aerospike conf file for local node and system stats from all nodes if remote server credentials provided.',
                 'If credentials are not available then it will collect system stats from local node only.',
                 '  Options:',
                 '    -n <int>        - Number of snapshots. Default: 1',
                 '    -s <int>        - Sleep time in seconds between each snapshot. Default: 5 sec',
                 '    -U <string>     - Default user id for remote servers. This is System user id (not Aerospike user id).',
                 '    -P <string>     - Default password or passphrase for key for remote servers. This is System password (not Aerospike password).',
                 '    -sp <int>       - Default SSH port for remote servers. Default: 22',
                 '    -sk <string>    - Default SSH key (file path) for remote servers.',
                 '    -cf <string>    - Remote System Credentials file path. ',
                 '                      If server credentials are not available in credential file then default credentials will be used ',
                 '                      File format : each line should contain <IP[:PORT]>,<USER_ID>,<PASSWORD or PASSPHRASE>,<SSH_KEY>',
                 '                      Example:  1.2.3.4,uid,pwd',
                 '                                1.2.3.4:3232,uid,pwd',
                 '                                1.2.3.4:3232,uid,,key_path',
                 '                                1.2.3.4:3232,uid,passphrase,key_path',
                 '                                [2001::1234:10],uid,pwd',
                 '                                [2001::1234:10]:3232,uid,,key_path',
                 )
    def _do_default(self, line):

        default_user = util.get_arg_and_delete_from_mods(line=line,
                arg="-U", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_pwd = util.get_arg_and_delete_from_mods(line=line, arg="-P",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        snp_count = util.get_arg_and_delete_from_mods(line=line, arg="-n",
                return_type=int, default=1, modifiers=self.modifiers,
                mods=self.mods)

        wait_time = util.get_arg_and_delete_from_mods(line=line, arg="-t",
                return_type=int, default=5, modifiers=self.modifiers,
                mods=self.mods)

        default_ssh_port = util.get_arg_and_delete_from_mods(line=line,
                arg="-sp", return_type=int, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_ssh_key = util.get_arg_and_delete_from_mods(line=line,
                arg="-sk", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        credential_file = util.get_arg_and_delete_from_mods(line=line,
                arg="-cf", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        self.cmds_error = set()
        self._main_collectinfo(default_user, default_pwd, default_ssh_port, default_ssh_key,
                credential_file, snp_count, wait_time, show_all=False, verbose=False)

        if self.cmds_error:
            self.logger.error(
                "Following commands are either unavailable or giving runtime error")
            self.logger.error(self.cmds_error)

    @CommandHelp('Collects all default stats and additional stats like "info dump-*" commands output',
                 '  Options:',
                 '    verbose     - Enable to collect additional stats with detailed output of "info dump-*" commands'
                 )
    def do_all(self, line):
        default_user = util.get_arg_and_delete_from_mods(line=line,
                arg="-U", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_pwd = util.get_arg_and_delete_from_mods(line=line, arg="-P",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        snp_count = util.get_arg_and_delete_from_mods(line=line, arg="-n",
                return_type=int, default=1, modifiers=self.modifiers,
                mods=self.mods)

        wait_time = util.get_arg_and_delete_from_mods(line=line, arg="-t",
                return_type=int, default=5, modifiers=self.modifiers,
                mods=self.mods)

        default_ssh_port = util.get_arg_and_delete_from_mods(line=line,
                arg="-sp", return_type=int, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_ssh_key = util.get_arg_and_delete_from_mods(line=line,
                arg="-sk", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        credential_file = util.get_arg_and_delete_from_mods(line=line,
                arg="-cf", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        verbose = False
        if 'verbose' in line:
            verbose = True

        self.cmds_error = set()
        self._main_collectinfo(default_user, default_pwd, default_ssh_port, default_ssh_key,
                credential_file, snp_count, wait_time, show_all=True, verbose=verbose)

        if self.cmds_error:
            self.logger.error(
                "Following commands are either unavailable or giving runtime error")
            self.logger.error(self.cmds_error)


@CommandHelp('Displays features used in running Aerospike cluster.')
class FeaturesController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with', 'like'])
        self.getter = GetStatisticsController(self.cluster)

    def _do_default(self, line):

        features = self.getter.get_features(nodes=self.nodes)

        return util.Future(self.view.show_config, "Features", features,
                self.cluster, **self.mods)


@CommandHelp("Set pager for output")
class PagerController(BasicCommandController):

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


@CommandHelp('Checks for common inconsistencies and print if there is any')
class HealthCheckController(BasicCommandController):
    last_snapshot_collection_time = 0
    last_snapshot_count = 0

    def __init__(self):
        self.modifiers = set()

    def _get_asstat_data(self, stanza):
        if stanza == "service":
            return self.cluster.info_statistics(nodes=self.nodes)
        elif stanza == "namespace":
            return self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        elif stanza == "sets":
            return self.cluster.info_set_statistics(nodes=self.nodes)
        elif stanza == "bins":
            return self.cluster.info_bin_statistics(nodes=self.nodes)
        elif stanza == "xdr":
            return self.cluster.info_XDR_statistics(nodes=self.nodes)
        elif stanza == "dc":
            return self.cluster.info_all_dc_statistics(nodes=self.nodes)
        elif stanza == "sindex":
            return get_sindex_stats(cluster=self.cluster, nodes=self.nodes)
        elif stanza == "udf":
            return self.cluster.info_udf_list(nodes=self.nodes)
        elif stanza == "endpoints":
            return self.cluster.info_service(nodes=self.nodes)
        elif stanza == "services":
            return self.cluster.info_services(nodes=self.nodes)

    def _get_asconfig_data(self, stanza):
        if stanza == "xdr":
            return self.cluster.info_XDR_get_config(nodes=self.nodes)
        elif stanza == "dc":
            return self.cluster.info_dc_get_config(nodes=self.nodes)
        else:
            return self.cluster.info_get_config(nodes=self.nodes, stanza=stanza)

    @CommandHelp(
        'Displays health summary. If remote server System credentials provided, then it will collect remote system stats',
        'and analyse that also. If credentials are not available then it will collect only localhost system statistics.',
        '  Options:',
        '    -f <string>     - Query file path. Default: inbuilt health queries.',
        '    -o <string>     - Output file path. ',
        '                      This parameter works if Query file path provided, otherwise health command will work in interactive mode.',
        '    -v              - Enable to display extra details of assert errors.',
        '    -d              - Enable to display extra details of exceptions.',
        '    -n <int>        - Number of snapshots. Default: 3',
        '    -s <int>        - Sleep time in seconds between each snapshot. Default: 1 sec',
        '    -U <string>     - Default user id for remote servers. This is System user id (not Aerospike user id).',
        '    -P <string>     - Default password or passphrase for key for remote servers. This is System password (not Aerospike password).',
        '    -sp <int>       - Default SSH port for remote servers. Default: 22',
        '    -sk <string>    - Default SSH key (file path) for remote servers.',
        '    -cf <string>    - Remote System Credentials file path. ',
        '                      If server credentials are not available in credential file then default credentials will be used ',
        '                      File format : each line should contain <IP[:PORT]>,<USER_ID>,<PASSWORD or PASSPHRASE>,<SSH_KEY>',
        '                      Example:  1.2.3.4,uid,pwd',
        '                                1.2.3.4:3232,uid,pwd',
        '                                1.2.3.4:3232,uid,,key_path',
        '                                1.2.3.4:3232,uid,passphrase,key_path',
        '                                [2001::1234:10],uid,pwd',
        '                                [2001::1234:10]:3232,uid,,key_path',
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

        snap_count = util.get_arg_and_delete_from_mods(line=line, arg="-n",
                return_type=int, default=3, modifiers=self.modifiers,
                mods=self.mods)

        sleep_tm = util.get_arg_and_delete_from_mods(line=line, arg="-s",
                return_type=int, default=1, modifiers=self.modifiers,
                mods=self.mods)

        verbose = util.check_arg_and_delete_from_mods(line=line, arg="-v",
                default=False, modifiers=self.modifiers, mods=self.mods)

        debug = util.check_arg_and_delete_from_mods(line=line, arg="-d",
                default=False, modifiers=self.modifiers, mods=self.mods)

        credential_file = util.get_arg_and_delete_from_mods(line=line,
                arg="-cf", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_user = util.get_arg_and_delete_from_mods(line=line, arg="-U",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_pwd = util.get_arg_and_delete_from_mods(line=line, arg="-P",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_ssh_port = util.get_arg_and_delete_from_mods(line=line,
                arg="-sp", return_type=int, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_ssh_key = util.get_arg_and_delete_from_mods(line=line,
                arg="-sk", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        output_filter_category = util.get_arg_and_delete_from_mods(line=line,
                arg="-oc", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        output_filter_warning_level = util.get_arg_and_delete_from_mods(line,
                arg="-wl", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        # Query file can be specified without -f
        # hence always parsed in the end
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

        if (time.time() - HealthCheckController.last_snapshot_collection_time > 60) or HealthCheckController.last_snapshot_count != snap_count:
            # There is possibility of different cluster-names in old
            # heartbeat protocol. As asadm works with single cluster,
            # so we are setting one static cluster-name.
            cluster_name = "C1"

            stanza_dict = {
                "statistics": (self._get_asstat_data, [
                    ("service", "SERVICE", False, False,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("namespace", "NAMESPACE", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("sets", "SET", False, False, [("CLUSTER", cluster_name), ("NODE", None), (
                        None, None), ("NAMESPACE", ("ns_name", "ns",)), ("SET", ("set_name", "set",))]),
                    ("bins", "BIN", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("xdr", "XDR", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("sindex", "SINDEX", True, False, [("CLUSTER", cluster_name), ("NODE", None), (
                        None, None), ("NAMESPACE", ("ns",)), ("SET", ("set",)), ("SINDEX", ("indexname",))])
                ]),
                "config": (self._get_asconfig_data, [
                    ("service", "SERVICE", True, True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("xdr", "XDR", True, True, [
                     ("CLUSTER", cluster_name), ("NODE", None)]),
                    ("network", "NETWORK", True, True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("namespace", "NAMESPACE", True, True, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)])
                ]),
                "cluster": (self.cluster.info, [
                    ("build", "METADATA", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "version")]),
                ]),
                "endpoints": (self._get_asstat_data, [
                    ("endpoints", "METADATA", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "endpoints")]),
                ]),
                "services": (self._get_asstat_data, [
                    ("services", "METADATA", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None), ("KEY", "services")]),
                ]),
                "metadata": (self._get_asstat_data, [
                    ("udf", "UDF", False, False, [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("FILENAME", None)]),
                ]),
            }
            sys_cmd_dict = {
                "sys_stats": (util.restructure_sys_data, [
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

            sn_ct = 0
            sleep = sleep_tm * 1.0

            self.logger.info("Collecting " + str(snap_count) +
                             " collectinfo snapshot. Use -n to set number of snapshots.")
            while sn_ct < snap_count:
                fetched_as_val = {}

                # Collecting data
                sys_stats = self.cluster.info_system_statistics(nodes=self.nodes, default_user=default_user, default_pwd=default_pwd, default_ssh_key=default_ssh_key,
                                                                default_ssh_port=default_ssh_port, credential_file=credential_file)

                for _key, (info_function, stanza_list) in stanza_dict.iteritems():

                    for stanza_item in stanza_list:

                        stanza = stanza_item[0]
                        fetched_as_val[(_key, stanza)] = info_function(stanza)

                # Creating health input model
                for _key, (info_function, stanza_list) in stanza_dict.iteritems():

                    for stanza_item in stanza_list:

                        stanza = stanza_item[0]
                        component_name = stanza_item[1]
                        is_flip_needs = stanza_item[2]
                        remove_first_key = stanza_item[3]

                        try:
                            d = fetched_as_val[(_key, stanza)]
                        except Exception:
                            continue

                        try:
                            new_tuple_keys = copy.deepcopy(stanza_item[4])
                        except Exception:
                            new_tuple_keys = []

                        if is_flip_needs:
                            d = util.flip_keys(d)

                        if remove_first_key:
                            for i in d:

                                new_component_keys = [create_snapshot_key(sn_ct),
                                                      component_name, i,
                                                      _key.upper()]

                                health_input = create_health_input_dict(d[i],
                                        health_input, new_tuple_keys,
                                        new_component_keys)
                        else:
                            new_component_keys = [create_snapshot_key(sn_ct),
                                                  component_name, _key.upper()]

                            health_input = create_health_input_dict(d, health_input,
                                    new_tuple_keys, new_component_keys)

                sys_stats = util.flip_keys(sys_stats)

                for cmd_key, (sys_function, sys_cmd_list) in sys_cmd_dict.iteritems():

                    for cmd_item in sys_cmd_list:

                        cmd_section = cmd_item[0]
                        component_name = cmd_item[1]
                        sub_component_name = cmd_item[2]
                        forced_all_new_keys = cmd_item[3]

                        try:
                            d = sys_function(sys_stats[cmd_section], cmd_section)
                        except Exception:
                            continue

                        if cmd_section == "free-m":
                            d = util.mbytes_to_bytes(d)

                        try:
                            new_tuple_keys = copy.deepcopy(cmd_item[4])
                        except:
                            new_tuple_keys = []

                        new_component_keys = [create_snapshot_key(sn_ct),
                                              component_name, sub_component_name]

                        health_input = create_health_input_dict(d, health_input,
                                new_tuple_keys, new_component_keys,
                                forced_all_new_keys)

                sn_ct += 1
                self.logger.info("Snapshot " + str(sn_ct))
                time.sleep(sleep)

            health_input = h_eval(health_input)
            self.health_checker.set_health_input_data(health_input)
            HealthCheckController.last_snapshot_collection_time = time.time()
            HealthCheckController.last_snapshot_count = snap_count

        else:
            self.logger.info("Using previous collected snapshot data since it is not older than 1 minute.")

        health_summary = self.health_checker.execute(query_file=query_file)

        if health_summary:
            try:
                self.view.print_health_output(health_summary, verbose, debug,
                        output_file, output_filter_category,
                        output_filter_warning_level)
                if not verbose:
                    self.logger.info("Please use -v option for more details on failure. \n")

            except Exception as e:
                self.logger.error(e)


@CommandHelp(
        'Displays summary of Aerospike cluster.',
        '  Options:',
        '    -U <string>     - Default user id for remote servers. This is System user id (not Aerospike user id).',
        '    -P <string>     - Default password or passphrase for key for remote servers. This is System password (not Aerospike password).',
        '    -sp <int>       - Default SSH port for remote servers. Default: 22',
        '    -sk <string>    - Default SSH key (file path) for remote servers.',
        '    -cf <string>    - Remote System Credentials file path. ',
        '                      If server credentials are not available in credential file then default credentials will be used ',
        '                      File format : each line should contain <IP[:PORT]>,<USER_ID>,<PASSWORD or PASSPHRASE>,<SSH_KEY>',
        '                      Example:  1.2.3.4,uid,pwd',
        '                                1.2.3.4:3232,uid,pwd',
        '                                1.2.3.4:3232,uid,,key_path',
        '                                1.2.3.4:3232,uid,passphrase,key_path',
        '                                [2001::1234:10],uid,pwd',
        '                                [2001::1234:10]:3232,uid,,key_path',
        )
class SummaryController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with'])

    def _do_default(self, line):
        default_user = util.get_arg_and_delete_from_mods(line=line, arg="-U",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_pwd = util.get_arg_and_delete_from_mods(line=line, arg="-P",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_ssh_port = util.get_arg_and_delete_from_mods(line=line,
                arg="-sp", return_type=int, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_ssh_key = util.get_arg_and_delete_from_mods(line=line,
                arg="-sk", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        credential_file = util.get_arg_and_delete_from_mods(line=line,
                arg="-cf", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        service_stats = util.Future(self.cluster.info_statistics, nodes=self.nodes).start()
        namespace_stats = util.Future(self.cluster.info_all_namespace_statistics, nodes=self.nodes).start()
        set_stats = util.Future(self.cluster.info_set_statistics, nodes=self.nodes).start()

        os_version = self.cluster.info_system_statistics(nodes=self.nodes, default_user=default_user, default_pwd=default_pwd, default_ssh_key=default_ssh_key,
                                                         default_ssh_port=default_ssh_port, credential_file=credential_file, commands=["lsb"])
        server_version = util.Future(self.cluster.info, 'build', nodes=self.nodes).start()

        service_stats = service_stats.result()
        namespace_stats = namespace_stats.result()
        set_stats = set_stats.result()
        server_version = server_version.result()

        metadata = {}
        metadata["server_version"] = server_version
        try:
            metadata["os_version"] = util.flip_keys(os_version)["lsb"]
        except Exception:
            metadata["os_version"] = os_version

        return util.Future(self.view.print_summary, util.create_summary(service_stats=service_stats, namespace_stats=namespace_stats,
                                                    set_stats=set_stats, metadata=metadata))


