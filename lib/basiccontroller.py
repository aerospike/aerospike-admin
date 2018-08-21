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
import json
import os
import platform
import shutil
import sys
import time
from distutils.version import LooseVersion

from lib.client.cluster import Cluster
from lib.collectinfocontroller import CollectinfoRootController
from lib.controllerlib import (BaseController, CommandController, CommandHelp,
                               ShellException)
from lib.getcontroller import (GetConfigController, GetDistributionController,
                               GetPmapController, GetStatisticsController, GetFeaturesController,
                               get_sindex_stats)
from lib.health.util import (create_health_input_dict, create_snapshot_key,
                             h_eval)
from lib.utils import common, constants, util
from lib.view import terminal
from lib.view.view import CliView


class BasicCommandController(CommandController):
    cluster = None

    def __init__(self, cluster):
        BasicCommandController.cluster = cluster


@CommandHelp('Aerospike Admin')
class BasicRootController(BaseController):

    cluster = None
    command = None

    def __init__(self, seed_nodes=[('127.0.0.1', 3000, None)], user=None, password=None, auth_mode=constants.AuthMode.INTERNAL,
                 use_services_alumni=False, use_services_alt=False, ssl_context=None,
                 asadm_version='', only_connect_seed=False, timeout=5):

        super(BasicRootController, self).__init__(asadm_version)

        # Create static instance of cluster
        BasicRootController.cluster = Cluster(seed_nodes, user, password, auth_mode,
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

        self.controller_map = dict(
            namespace=InfoNamespaceController)
        self.config_getter = GetConfigController(self.cluster)

    @CommandHelp('Displays network, namespace, and XDR summary information.')
    def _do_default(self, line):
        actions = [util.Future(self.do_network, line).start()]
        # We are not using line for any of subcommand, but if user enters 'info object' or 'info usage' then it will
        # give error for unexpected format. We can catch this inside InfoNamespaceController but in that case
        # it will show incomplete output, for ex. 'info object' will print output of 'info network', 'info xdr' and
        # 'info namespace object', but since it is not correct command it should print output for partial correct
        # command, in this case it should print data for 'info'. To keep consistent output format, we are passing empty
        # list as line.
        actions.extend(self.controller_map['namespace'](get_futures=True)([])['futures'])
        actions.append(util.Future(self.do_xdr, line).start())

        return [action.result() for action in actions]

    @CommandHelp('Displays network information for Aerospike.')
    def do_network(self, line):
        stats = util.Future(self.cluster.info_statistics,
                            nodes=self.nodes).start()

        cluster_configs = self.config_getter.get_cluster(nodes=self.nodes)

        cluster_names = util.Future(
            self.cluster.info, 'cluster-name', nodes=self.nodes).start()
        builds = util.Future(
            self.cluster.info, 'build', nodes=self.nodes).start()
        versions = util.Future(
            self.cluster.info, 'version', nodes=self.nodes).start()

        stats = stats.result()
        cluster_names = cluster_names.result()
        builds = builds.result()
        versions = versions.result()

        for node in stats:
            try:
                if not isinstance(cluster_configs[node]["mode"], Exception):
                    stats[node]["rackaware_mode"] = cluster_configs[node]["mode"]
            except Exception:
                pass
        return util.Future(self.view.info_network, stats, cluster_names,
                           versions, builds, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for each set.')
    def do_set(self, line):
        stats = self.cluster.info_set_statistics(nodes=self.nodes)
        return util.Future(self.view.info_set, stats, self.cluster, **self.mods)

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

        configs = self.config_getter.get_dc(flip=False, nodes=self.nodes)

        stats = stats.result()

        for node in stats.keys():

            if (stats[node]
                    and not isinstance(stats[node], Exception)
                    and node in configs
                    and configs[node]
                    and not isinstance(configs[node], Exception)):

                for dc in stats[node].keys():
                    try:
                        stats[node][dc].update(configs[node][dc])
                    except Exception:
                        pass

            elif ((not stats[node]
                   or isinstance(stats[node], Exception))
                    and node in configs
                    and configs[node]
                    and not isinstance(configs[node], Exception)):
                try:
                    stats[node] = configs[node]
                except Exception:
                    pass

        return util.Future(self.view.info_dc, stats, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for Secondary Indexes (SIndex).')
    def do_sindex(self, line):
        sindex_stats = get_sindex_stats(self.cluster, self.nodes)
        return util.Future(self.view.info_sindex, sindex_stats, self.cluster,
                           **self.mods)


@CommandHelp('The "namespace" command provides summary tables for various aspects',
             'of Aerospike namespaces.')
class InfoNamespaceController(BasicCommandController):
    def __init__(self, get_futures=False):
        self.modifiers = set(['with'])
        self.get_futures = get_futures

    @CommandHelp('Displays usage and objects information for namespaces')
    def _do_default(self, line):
        actions = [util.Future(self.do_usage, line).start(),
                   util.Future(self.do_object, line).start()]

        if self.get_futures:
            # Wrapped to prevent base class from calling result.
            return dict(futures=actions)

        return [action.result() for action in actions]

    @CommandHelp('Displays usage information for each namespace.')
    def do_usage(self, line):
        stats = self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        return util.Future(self.view.info_namespace_usage, stats, self.cluster,
                           **self.mods)

    @CommandHelp('Displays object information for each namespace.')
    def do_object(self, line):
        stats = self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        return util.Future(self.view.info_namespace_object, stats, self.cluster,
                           **self.mods)


@CommandHelp(
    '"asinfo" provides raw access to the info protocol.',
    '  Options:',
    '    -v <command>   - The command to execute',
    '    -p <port>      - Port to use in case of XDR info command and XDR is',
    '                     not in asd',
    '    -l             - Replace semicolons ";" with newlines. If output does',
    '                     not contain semicolons "-l" will attempt to use',
    '                     colons ":" followed by commas ",".',
    '    --no_node_name - Force to display output without printing node names.'
)
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
            self.logger.warning(
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
        self.getter = GetDistributionController(self.cluster)


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
            units = None

            try:
                units = common.is_new_histogram_version(histogram)

                if units is None:
                    units = 'Record Blocks'
            except Exception as e:
                self.logger.error(e)
                return

            return util.Future(self.view.show_distribution,
                    'Object Size Distribution', histogram, units,
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
        self.aslogfile = ""
        self.aslogdir = ""

    def _collect_local_file(self, src, dest_dir):
        self.logger.info("Copying file %s to %s" % (src, dest_dir))
        try:
            shutil.copy2(src, dest_dir)
        except Exception, e:
            self.logger.error(e)

    def _collectinfo_content(self, func, parm='', alt_parms=''):
        name = ''
        capture_stdout = util.capture_stdout
        sep = constants.COLLECTINFO_SEPRATOR
        try:
            name = func.func_name
        except Exception:
            pass
        info_line = constants.COLLECTINFO_PROGRESS_MSG %(name, "%s" % (" %s" % (str(parm)) if parm else ""))
        self.logger.info(info_line)
        if parm:
            sep += str(parm) + "\n"

        if func == 'cluster':
            o = self.cluster.info(parm)
        else:
            if self.nodes and isinstance(self.nodes, list):
                parm += ["with"] + self.nodes
            o = capture_stdout(func, parm)
        util.write_to_file(self.aslogfile, sep + str(o))
        return ''

    def _write_version(self, line):
        print "asadm version " + str(self.asadm_version)

    def _collect_logs_from_systemd_journal(self, as_logfile_prefix):
        asd_pids = common.get_asd_pids()
        for pid in asd_pids:
            try:
                journalctl_cmd = [
                    'journalctl _PID=%s --since "24 hours ago" -q -o cat' % (pid)]
                self.aslogfile = as_logfile_prefix + 'aerospike_%s.log' % (pid)
                self.logger.info("Data collection for %s to %s in progress..." % (str(journalctl_cmd), self.aslogfile))
                o, e = util.shell_command(journalctl_cmd)
                if e:
                    self.logger.error(str(e))
                else:
                    util.write_to_file(self.aslogfile, str(o))
            except Exception as e1:
                self.logger.error(str(e1))
                sys.stdout = sys.__stdout__

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
        config = getter.get_all(nodes=self.nodes, flip=False)

        # All these section have have nodeid in inner level
        # flip keys to get nodeid in upper level.
        # {'namespace': 'test': {'ip1': {}, 'ip2': {}}} -->
        # {'namespace': {'ip1': {'test': {}}, 'ip2': {'test': {}}}}
        stats['namespace'] = util.flip_keys(stats['namespace'])
        stats['set'] = util.flip_keys(stats['set'])
        stats['bin'] = util.flip_keys(stats['bin'])
        stats['dc'] = util.flip_keys(stats['dc'])
        stats['sindex'] = util.flip_keys(stats['sindex'])

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
        builds = util.Future(self.cluster.info, 'build', nodes=self.nodes).start()
        editions = util.Future(self.cluster.info, 'version', nodes=self.nodes).start()
        xdr_builds = util.Future(self.cluster.info_XDR_build_version, nodes=self.nodes).start()
        node_ids = util.Future(self.cluster.info_node, nodes=self.nodes).start()
        ips = util.Future(self.cluster.info_ip_port, nodes=self.nodes).start()
        endpoints = util.Future(self.cluster.info_service, nodes=self.nodes).start()
        services = util.Future(self.cluster.info_services, nodes=self.nodes).start()
        udf_data = util.Future(self.cluster.info_udf_list, nodes=self.nodes).start()

        builds = builds.result()
        editions = editions.result()
        xdr_builds = xdr_builds.result()
        node_ids = node_ids.result()
        ips = ips.result()
        endpoints = endpoints.result()
        services = services.result()
        udf_data = udf_data.result()

        for nodeid in builds:
            metamap[nodeid] = {}
            self._get_meta_for_sec(builds, 'asd_build', nodeid, metamap)
            self._get_meta_for_sec(editions, 'edition', nodeid, metamap)
            self._get_meta_for_sec(xdr_builds, 'xdr_build', nodeid, metamap)
            self._get_meta_for_sec(node_ids, 'node_id', nodeid, metamap)
            self._get_meta_for_sec(ips, 'ip', nodeid, metamap)
            self._get_meta_for_sec(endpoints, 'endpoints', nodeid, metamap)
            self._get_meta_for_sec(services, 'services', nodeid, metamap)
            self._get_meta_for_sec(udf_data, 'udf', nodeid, metamap)

        return metamap

    def _get_as_histograms(self):
        histogram_map = {}
        hist_list = [('ttl', 'ttl', False), ('objsz', 'objsz', False), ('objsz', 'object-size', True)]
        hist_dumps = [util.Future(self.cluster.info_histogram, hist[0],
                                  logarithmic = hist[2],
                                  raw_output=True,
                                  nodes=self.nodes).start()
                      for hist in hist_list]

        for hist, hist_dump in zip(hist_list, hist_dumps):
            hist_dump = hist_dump.result()

            for node in hist_dump:
                if node not in histogram_map:
                    histogram_map[node] = {}

                if not hist_dump[node] or isinstance(hist_dump[node], Exception):
                    continue

                histogram_map[node][hist[1]] = hist_dump[node]

        return histogram_map

    def _get_as_latency(self):
        latency_map = {}
        latency_data = util.Future(self.cluster.info_latency,
                                  nodes=self.nodes).start()
        latency_data = latency_data.result()

        for node in latency_data:
            if node not in latency_map:
                latency_map[node] = {}

            if not latency_data[node] or isinstance(latency_data[node], Exception):
                continue

            latency_map[node] = latency_data[node]

        return latency_map

    def _get_as_pmap(self):
        getter = GetPmapController(self.cluster)
        return getter.get_pmap(nodes=self.nodes)

    def _dump_in_json_file(self, as_logfile_prefix, dump):
        self.logger.info("Dumping collectinfo in JSON format.")
        self.aslogfile = as_logfile_prefix + 'ascinfo.json'

        try:
            json_dump = json.dumps(dump, indent=4, separators=(',', ':'))
            with open(self.aslogfile, "w") as f:
                f.write(json_dump)
        except Exception as e:
            self.logger.error("Failed to write JSON file: " + str(e))

    def _get_collectinfo_data_json(self, default_user, default_pwd, default_ssh_port,
                                   default_ssh_key, credential_file, enable_ssh):

        dump_map = {}

        meta_map = self._get_as_metadata()

        histogram_map = self._get_as_histograms()

        latency_map = self._get_as_latency()

        pmap_map = self._get_as_pmap()

        sys_map = self.cluster.info_system_statistics(default_user=default_user, default_pwd=default_pwd, default_ssh_key=default_ssh_key,
                                                      default_ssh_port=default_ssh_port, credential_file=credential_file, nodes=self.nodes,
                                                      collect_remote_data=enable_ssh)

        cluster_names = util.Future(
            self.cluster.info, 'cluster-name').start()

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

            if node in latency_map:
                 dump_map[node]['as_stat']['latency'] = latency_map[node]

            if node in pmap_map:
                 dump_map[node]['as_stat']['pmap'] = pmap_map[node]

        # Get the cluster name and add one more level in map
        cluster_name = 'null'
        cluster_names = cluster_names.result()

        # Cluster name.
        for node in cluster_names:
            if not isinstance(cluster_names[node], Exception) and cluster_names[node] not in ["null"]:
                cluster_name = cluster_names[node]
                break

        snp_map = {}
        snp_map[cluster_name] = dump_map
        return snp_map

    def _dump_collectinfo_json(self, timestamp, as_logfile_prefix, default_user, default_pwd, default_ssh_port,
                               default_ssh_key, credential_file, enable_ssh, snp_count, wait_time):
        snpshots = {}

        for i in range(snp_count):

            snp_timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            self.logger.info("Data collection for Snapshot: " + str(i + 1) + " in progress..")
            snpshots[snp_timestamp] = self._get_collectinfo_data_json(
                default_user, default_pwd, default_ssh_port, default_ssh_key, credential_file, enable_ssh)

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



        collect_output = time.strftime("%Y-%m-%d %H:%M:%S UTC\n", timestamp)

        dignostic_info_params = [
            'network', 'namespace', 'set', 'xdr', 'dc', 'sindex']
        dignostic_features_params = ['features']
        dignostic_show_params = ['config', 'config xdr', 'config dc', 'config cluster', 'distribution', 'distribution eviction',
                                 'distribution object_size -b', 'latency', 'statistics', 'statistics xdr', 'statistics dc', 'statistics sindex', 'pmap']
        dignostic_aerospike_cluster_params = ['service', 'services', 'roster:']
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
        summary_info_params = ['network', 'namespace', 'set', 'xdr', 'dc', 'sindex']
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

        self.aslogfile = as_logfile_prefix + 'ascollectinfo.log'
        util.write_to_file(self.aslogfile, collect_output)

        try:
            self._collectinfo_content(self._write_version)
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            info_controller = InfoController()
            for info_param in dignostic_info_params:
                self._collectinfo_content(info_controller, [info_param])
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            show_controller = ShowController()
            for show_param in dignostic_show_params:
                self._collectinfo_content(show_controller, show_param.split())
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            features_controller = FeaturesController()
            for cmd in dignostic_features_params:
                self._collectinfo_content(features_controller, [cmd])
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            for cmd in dignostic_aerospike_cluster_params:
                self._collectinfo_content('cluster', cmd)
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        ####### Summary ########

        collectinfo_root_controller = CollectinfoRootController(asadm_version=self.asadm_version, clinfo_path=self.aslogdir)

        self.aslogfile = as_logfile_prefix + 'summary.log'
        util.write_to_file(self.aslogfile, collect_output)
        try:
            self._collectinfo_content(self._write_version)
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            for summary_param in summary_params:
                self._collectinfo_content(collectinfo_root_controller.execute, [summary_param])
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            info_controller = InfoController()
            for info_param in summary_info_params:
                self._collectinfo_content(info_controller, [info_param])
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        ####### Health ########

        self.aslogfile = as_logfile_prefix + 'health.log'
        util.write_to_file(self.aslogfile, collect_output)

        try:
            for health_param in health_params:
                self._collectinfo_content(collectinfo_root_controller.execute, health_param.split())
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        ####### System info ########

        self.aslogfile = as_logfile_prefix + 'sysinfo.log'
        self.failed_cmds = common.collect_sys_info(port=port, timestamp=collect_output, outfile=self.aslogfile, verbose=show_all & verbose)

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
                        from lib.client.node import Node
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

                        self.aslogfile = as_logfile_prefix + 'asxdr.log'
                        self._collect_local_file(xdr_log_location, self.aslogfile)

            except Exception as e:
                util.write_to_file(self.aslogfile, str(e))
                sys.stdout = sys.__stdout__

            try:
                try:
                    log_locations = [i.split(':')[1] for i in self.cluster.call_node_method(
                        [_ip], "info", "logs").popitem()[1].split(';')]
                except Exception:
                    from lib.client.node import Node
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
                            util.write_to_file(self.aslogfile, str(e1))
                            sys.stdout = sys.__stdout__
            except Exception as e:
                util.write_to_file(self.aslogfile, str(e))
                sys.stdout = sys.__stdout__

        ##### aerospike conf file #####
        try:
            # Comparing with this version because prior to this it was
            # citrusleaf.conf & citrusleaf.log
            if LooseVersion(as_version) > LooseVersion("3.0.0"):
                self.aslogfile = as_logfile_prefix + 'aerospike.conf'
            else:
                self.aslogfile = as_logfile_prefix + 'citrusleaf.conf'

            self._collect_local_file(conf_path, self.aslogfile)

        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

    def _main_collectinfo(self, default_user, default_pwd, default_ssh_port, default_ssh_key,
                          credential_file, snp_count, wait_time, enable_ssh=False,
                          show_all=False, verbose=False, output_prefix=""):

        # JSON collectinfo snapshot count check
        if snp_count < 1:
            self.logger.error("Wrong collectinfo snapshot count")
            return

        timestamp = time.gmtime()
        self.aslogdir, as_logfile_prefix = common.set_collectinfo_path(timestamp, output_prefix=output_prefix)

        # Coloring might writes extra characters to file, to avoid it we need to disable terminal coloring
        terminal.enable_color(False)

        # list of failed system commands
        self.failed_cmds = []

        # JSON collectinfo

        self._dump_collectinfo_json(timestamp, as_logfile_prefix, default_user, default_pwd, default_ssh_port, default_ssh_key,
                                    credential_file, enable_ssh, snp_count, wait_time,)

        # Pretty print collectinfo
        self._dump_collectinfo_pretty_print(timestamp, as_logfile_prefix, show_all=show_all, verbose=verbose)

        # Archive collectinfo directory
        common.archive_log(self.aslogdir)

        # printing collectinfo summary
        common.print_collecinto_summary(self.aslogdir, failed_cmds=self.failed_cmds)

    def _collect_info(self, line, show_all=False):

        snp_count = util.get_arg_and_delete_from_mods(line=line, arg="-n",
                return_type=int, default=1, modifiers=self.modifiers,
                mods=self.mods)

        wait_time = util.get_arg_and_delete_from_mods(line=line, arg="-t",
                return_type=int, default=5, modifiers=self.modifiers,
                mods=self.mods)

        enable_ssh = util.check_arg_and_delete_from_mods(line=line, arg="--enable-ssh", default=False, modifiers=self.modifiers, mods=self.mods)

        default_user = util.get_arg_and_delete_from_mods(line=line, arg="--ssh-user",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_pwd = util.get_arg_and_delete_from_mods(line=line, arg="--ssh-pwd",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_ssh_port = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-port", return_type=int, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_ssh_key = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-key", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        credential_file = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-cf", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        output_prefix = util.get_arg_and_delete_from_mods(line=line,
                arg="--output-prefix", return_type=str, default="",
                modifiers=self.modifiers, mods=self.mods)

        verbose = False
        if 'verbose' in line:
            verbose = True

        self._main_collectinfo(default_user, default_pwd, default_ssh_port, default_ssh_key,
                               credential_file, snp_count, wait_time, enable_ssh=enable_ssh,
                               show_all=show_all, verbose=verbose, output_prefix=output_prefix)

    @CommandHelp('Collects cluster info, aerospike conf file for local node and system stats from all nodes if remote server credentials provided.',
                 'If credentials are not available then it will collect system stats from local node only.',
                 '  Options:',
                 '    -n              <int>        - Number of snapshots. Default: 1',
                 '    -s              <int>        - Sleep time in seconds between each snapshot. Default: 5 sec',
                 '    --enable-ssh                 - Enable remote server system statistics collection.',
                 '    --ssh-user      <string>     - Default user id for remote servers. This is System user id (not Aerospike user id).',
                 '    --ssh-pwd       <string>     - Default password or passphrase for key for remote servers. This is System password (not Aerospike password).',
                 '    --ssh-port      <int>        - Default SSH port for remote servers. Default: 22',
                 '    --ssh-key       <string>     - Default SSH key (file path) for remote servers.',
                 '    --ssh-cf        <string>     - Remote System Credentials file path.',
                 '                                   If server credentials are not available in credential file then default credentials will be used ',
                 '                                   File format : each line should contain <IP[:PORT]>,<USER_ID>,<PASSWORD or PASSPHRASE>,<SSH_KEY>',
                 '                                   Example:  1.2.3.4,uid,pwd',
                 '                                             1.2.3.4:3232,uid,pwd',
                 '                                             1.2.3.4:3232,uid,,key_path',
                 '                                             1.2.3.4:3232,uid,passphrase,key_path',
                 '                                             [2001::1234:10],uid,pwd',
                 '                                             [2001::1234:10]:3232,uid,,key_path',
                 '    --output-prefix <string>     - Output directory name prefix.',
                 )
    def _do_default(self, line):
        self._collect_info(line=line)

    @CommandHelp('Collects all default stats and additional stats like "info dump-*" commands output',
                 '  Options:',
                 '    verbose     - Enable to collect additional stats with detailed output of "info dump-*" commands'
                 )
    def do_all(self, line):
        self._collect_info(line=line, show_all=True)

@CommandHelp('Displays features used in running Aerospike cluster.')
class FeaturesController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with', 'like'])
        self.getter = GetFeaturesController(self.cluster)

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


@CommandHelp('Checks for common inconsistencies and print if there is any.',
             'This command is still in beta and its output should not be directly acted upon without further analysis.')
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
            return util.flip_keys(get_sindex_stats(cluster=self.cluster, nodes=self.nodes))
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
        elif stanza == "roster":
            return self.cluster.info_roster(nodes=self.nodes)
        elif stanza == "racks":
            return self.cluster.info_racks(nodes=self.nodes)
        else:
            return self.cluster.info_get_config(nodes=self.nodes, stanza=stanza)

    def _get_as_meta_data(self, stanza):
        if stanza == "build":
            return self.cluster.info("build", nodes=self.nodes)
        if stanza == "node_id":
            return self.cluster.info("node", nodes=self.nodes)
        elif stanza == "edition":
            editions = self.cluster.info("edition", nodes=self.nodes)
            if not editions:
                return editions

            editions_in_shortform = {}
            for node, edition in editions.iteritems():
                if not edition or isinstance(edition, Exception):
                    continue

                editions_in_shortform[node] = util.convert_edition_to_shortform(edition)

            return editions_in_shortform

    @CommandHelp(
        'Displays health summary. If remote server System credentials provided, then it will collect remote system stats',
        'and analyse that also. If credentials are not available then it will collect only localhost system statistics.',
        '  Options:',
        '    -f           <string>     - Query file path. Default: inbuilt health queries.',
        '    -o           <string>     - Output file path. ',
        '                                This parameter works if Query file path provided, otherwise health command will work in interactive mode.',
        '    -v                        - Enable to display extra details of assert errors.',
        '    -d                        - Enable to display extra details of exceptions.',
        '    -n           <int>        - Number of snapshots. Default: 1',
        '    -s           <int>        - Sleep time in seconds between each snapshot. Default: 1 sec',
        '    -oc          <string>     - Output filter Category. ',
        '                                This parameter works if Query file path provided, otherwise health command will work in interactive mode.',
        '                                Format : string of dot (.) separated category levels',
        '    -wl          <string>     - Output filter Warning level. Expected value CRITICAL or WARNING or INFO ',
        '                                This parameter works if Query file path provided, otherwise health command will work in interactive mode.',
        '    --enable-ssh              - Enable remote server system statistics collection.',
        '    --ssh-user   <string>     - Default user id for remote servers. This is System user id (not Aerospike user id).',
        '    --ssh-pwd    <string>     - Default password or passphrase for key for remote servers. This is System password (not Aerospike password).',
        '    --ssh-port   <int>        - Default SSH port for remote servers. Default: 22',
        '    --ssh-key    <string>     - Default SSH key (file path) for remote servers.',
        '    --ssh-cf     <string>     - Remote System Credentials file path.',
        '                                If server credentials are not available in credential file then default credentials will be used ',
        '                                File format : each line should contain <IP[:PORT]>,<USER_ID>,<PASSWORD or PASSPHRASE>,<SSH_KEY>',
        '                                Example:  1.2.3.4,uid,pwd',
        '                                          1.2.3.4:3232,uid,pwd',
        '                                          1.2.3.4:3232,uid,,key_path',
        '                                          1.2.3.4:3232,uid,passphrase,key_path',
        '                                          [2001::1234:10],uid,pwd',
        '                                          [2001::1234:10]:3232,uid,,key_path',
    )
    def _do_default(self, line):

        output_file = util.get_arg_and_delete_from_mods(line=line, arg="-o",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        snap_count = util.get_arg_and_delete_from_mods(line=line, arg="-n",
                return_type=int, default=1, modifiers=self.modifiers,
                mods=self.mods)

        sleep_tm = util.get_arg_and_delete_from_mods(line=line, arg="-s",
                return_type=int, default=1, modifiers=self.modifiers,
                mods=self.mods)

        verbose = util.check_arg_and_delete_from_mods(line=line, arg="-v",
                default=False, modifiers=self.modifiers, mods=self.mods)

        debug = util.check_arg_and_delete_from_mods(line=line, arg="-d",
                default=False, modifiers=self.modifiers, mods=self.mods)

        output_filter_category = util.get_arg_and_delete_from_mods(line=line,
                arg="-oc", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        output_filter_warning_level = util.get_arg_and_delete_from_mods(line,
                arg="-wl", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        enable_ssh = util.check_arg_and_delete_from_mods(line=line, arg="--enable-ssh", default=False, modifiers=self.modifiers, mods=self.mods)

        default_user = util.get_arg_and_delete_from_mods(line=line, arg="--ssh-user",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_pwd = util.get_arg_and_delete_from_mods(line=line, arg="--ssh-pwd",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_ssh_port = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-port", return_type=int, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_ssh_key = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-key", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        credential_file = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-cf", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        # Query file can be specified without -f
        # hence always parsed in the end
        query_file = util.get_arg_and_delete_from_mods(line=line, arg="-f",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        if not query_file and line:
            query_file = line[0]

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
                    ("service", "SERVICE",
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("namespace", "NAMESPACE",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("sets", "SET", [("CLUSTER", cluster_name), ("NODE", None), (
                        None, None), ("NAMESPACE", ("ns_name", "ns",)), ("SET", ("set_name", "set",))]),
                    ("bins", "BIN", [
                     ("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("xdr", "XDR",
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("sindex", "SINDEX", [("CLUSTER", cluster_name), ("NODE", None), (
                        None, None), ("NAMESPACE", ("ns",)), ("SET", ("set",)), ("SINDEX", ("indexname",))])
                ]),
                "config": (self._get_asconfig_data, [
                    ("service", "SERVICE",
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("xdr", "XDR",
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("network", "NETWORK",
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("namespace", "NAMESPACE",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("roster", "ROSTER",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)]),
                    ("racks", "RACKS",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None), (None, None), ("RACKS", None)])
                ]),
                "original_config": (self.cluster.info_get_originalconfig, [
                    ("service", "SERVICE",
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("xdr", "XDR",
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("network", "NETWORK",
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("dc", "DC",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("DC", None)]),
                    ("namespace", "NAMESPACE",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("NAMESPACE", None)])
                ]),
                "cluster": (self._get_as_meta_data, [
                    ("build", "METADATA",
                     [("CLUSTER", cluster_name), ("NODE", None), ("KEY", "version")]),
                    ("edition", "METADATA",
                     [("CLUSTER", cluster_name), ("NODE", None), ("KEY", "edition")]),
                    ("node_id", "METADATA",
                     [("CLUSTER", cluster_name), ("NODE", None), ("KEY", "node-id")]),
                ]),
                "endpoints": (self._get_asstat_data, [
                    ("endpoints", "METADATA",
                     [("CLUSTER", cluster_name), ("NODE", None), ("KEY", "endpoints")]),
                ]),
                "services": (self._get_asstat_data, [
                    ("services", "METADATA",
                     [("CLUSTER", cluster_name), ("NODE", None), ("KEY", "services")]),
                ]),
                "metadata": (self._get_asstat_data, [
                    ("udf", "UDF",
                     [("CLUSTER", cluster_name), ("NODE", None), (None, None), ("FILENAME", None)]),
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
                    ("dmesg", "SYSTEM", "DMESG", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("lscpu", "SYSTEM", "LSCPU", True,
                     [("CLUSTER", cluster_name), ("NODE", None), ("LSCPU", None)]),
                    ("iptables", "SYSTEM", "IPTABLES", True,
                     [("CLUSTER", cluster_name), ("NODE", None)]),
                    ("sysctlall", "SYSTEM", "SYSCTLALL", True,
                     [("CLUSTER", cluster_name), ("NODE", None), ("SYSCTL", None)]),
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

            sn_ct = 0
            sleep = sleep_tm * 1.0

            self.logger.info("Collecting " + str(snap_count) +
                             " collectinfo snapshot. Use -n to set number of snapshots.")
            while sn_ct < snap_count:
                fetched_as_val = {}

                # Collecting data
                sys_stats = self.cluster.info_system_statistics(nodes=self.nodes, default_user=default_user, default_pwd=default_pwd, default_ssh_key=default_ssh_key,
                                                                default_ssh_port=default_ssh_port, credential_file=credential_file, collect_remote_data=enable_ssh)

                for _key, (info_function, stanza_list) in stanza_dict.iteritems():

                    for stanza_item in stanza_list:

                        stanza = stanza_item[0]
                        fetched_as_val[(_key, stanza)] = info_function(stanza)

                # Creating health input model
                for _key, (info_function, stanza_list) in stanza_dict.iteritems():

                    for stanza_item in stanza_list:

                        stanza = stanza_item[0]
                        component_name = stanza_item[1]

                        try:
                            d = fetched_as_val[(_key, stanza)]
                        except Exception:
                            continue

                        try:
                            new_tuple_keys = copy.deepcopy(stanza_item[2])
                        except Exception:
                            new_tuple_keys = []

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
            self.view.print_health_output(health_summary, verbose, debug,
                                          output_file, output_filter_category,
                                          output_filter_warning_level)
            if not verbose:
                self.logger.info("Please use -v option for more details on failure. \n")


@CommandHelp(
        'Displays summary of Aerospike cluster.',
        '  Options:',
        '    -l                        - Enable to display namespace output in List view. Default: Table view',
        '    --enable-ssh              - Enable remote server system statistics collection.',
        '    --ssh-user   <string>     - Default user id for remote servers. This is System user id (not Aerospike user id).',
        '    --ssh-pwd    <string>     - Default password or passphrase for key for remote servers. This is System password (not Aerospike password).',
        '    --ssh-port   <int>        - Default SSH port for remote servers. Default: 22',
        '    --ssh-key    <string>     - Default SSH key (file path) for remote servers.',
        '    --ssh-cf     <string>     - Remote System Credentials file path.',
        '                                If server credentials are not available in credential file then default credentials will be used ',
        '                                File format : each line should contain <IP[:PORT]>,<USER_ID>,<PASSWORD or PASSPHRASE>,<SSH_KEY>',
        '                                Example:  1.2.3.4,uid,pwd',
        '                                          1.2.3.4:3232,uid,pwd',
        '                                          1.2.3.4:3232,uid,,key_path',
        '                                          1.2.3.4:3232,uid,passphrase,key_path',
        '                                          [2001::1234:10],uid,pwd',
        '                                          [2001::1234:10]:3232,uid,,key_path',
        )
class SummaryController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['with'])

    def _do_default(self, line):
        enable_list_view = util.check_arg_and_delete_from_mods(line=line, arg="-l", default=False, modifiers=self.modifiers, mods=self.mods)

        enable_ssh = util.check_arg_and_delete_from_mods(line=line, arg="--enable-ssh", default=False, modifiers=self.modifiers, mods=self.mods)

        default_user = util.get_arg_and_delete_from_mods(line=line, arg="--ssh-user",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_pwd = util.get_arg_and_delete_from_mods(line=line, arg="--ssh-pwd",
                return_type=str, default=None, modifiers=self.modifiers,
                mods=self.mods)

        default_ssh_port = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-port", return_type=int, default=None,
                modifiers=self.modifiers, mods=self.mods)

        default_ssh_key = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-key", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        credential_file = util.get_arg_and_delete_from_mods(line=line,
                arg="--ssh-cf", return_type=str, default=None,
                modifiers=self.modifiers, mods=self.mods)

        service_stats = util.Future(self.cluster.info_statistics, nodes=self.nodes).start()
        namespace_stats = util.Future(self.cluster.info_all_namespace_statistics, nodes=self.nodes).start()
        set_stats = util.Future(self.cluster.info_set_statistics, nodes=self.nodes).start()

        service_configs = util.Future(self.cluster.info_get_config, nodes=self.nodes, stanza='service').start()
        namespace_configs = util.Future(self.cluster.info_get_config, nodes=self.nodes, stanza='namespace').start()
        cluster_configs = util.Future(self.cluster.info_get_config, nodes=self.nodes, stanza='cluster').start()

        os_version = self.cluster.info_system_statistics(nodes=self.nodes, default_user=default_user, default_pwd=default_pwd, default_ssh_key=default_ssh_key,
                                                         default_ssh_port=default_ssh_port, credential_file=credential_file, commands=["lsb"], collect_remote_data=enable_ssh)
        kernel_version = self.cluster.info_system_statistics(nodes=self.nodes, default_user=default_user, default_pwd=default_pwd, default_ssh_key=default_ssh_key,
                                                         default_ssh_port=default_ssh_port, credential_file=credential_file, commands=["uname"], collect_remote_data=enable_ssh)
        server_version = util.Future(self.cluster.info, 'build', nodes=self.nodes).start()

        server_edition = util.Future(self.cluster.info, 'version', nodes=self.nodes).start()

        service_stats = service_stats.result()
        namespace_stats = namespace_stats.result()
        set_stats = set_stats.result()
        service_configs = service_configs.result()
        namespace_configs = namespace_configs.result()
        cluster_configs = cluster_configs.result()
        server_version = server_version.result()
        server_edition = server_edition.result()

        metadata = {}
        metadata["server_version"] = {}
        metadata["server_build"] = {}

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

        try:
            try:
                kernel_version = util.flip_keys(kernel_version)["uname"]
            except Exception:
                pass

            os_version = util.flip_keys(os_version)["lsb"]

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

        return util.Future(self.view.print_summary, common.create_summary(service_stats=service_stats, namespace_stats=namespace_stats,
                                                                          set_stats=set_stats, metadata=metadata,
                                                                          service_configs=service_configs, ns_configs=namespace_configs,
                                                                          cluster_configs=cluster_configs),
                           list_view=enable_list_view)
