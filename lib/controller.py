# Copyright 2013-2016 Aerospike, Inc.
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

from lib.controllerlib import *
from lib import util
import time, os, sys, platform, shutil, urllib2, socket
from distutils.version import StrictVersion, LooseVersion
import zipfile
import copy
from lib.data import lsof_file_type_desc
from lib.util import clear_val_from_dict, fetch_line_clear_dict, get_arg_and_delete_from_mods, \
    check_arg_and_delete_from_mods, get_value_from_dict
from lib.view import CliView
from lib import filesize


def flip_keys(orig_data):
    new_data = {}
    for key1, data1 in orig_data.iteritems():
        if isinstance(data1, Exception):
            continue
        for key2, data2 in data1.iteritems():
            if key2 not in new_data:
                new_data[key2] = {}
            new_data[key2][key1] = data2

    return new_data

def get_sindex_stats(cluster, nodes='all', for_mods=[]):
    stats = cluster.infoSIndex(nodes=nodes)

    sindex_stats = {}
    if stats:
        for host, stat_list in stats.iteritems():
            if not stat_list or isinstance(stat_list, Exception):
                continue
            namespace_list = [stat['ns'] for stat in stat_list]
            namespace_list = util.filter_list(namespace_list, for_mods)
            for stat in stat_list:
                if not stat or stat['ns'] not in namespace_list:
                    continue
                ns = stat['ns']
                set = stat['set']
                indexname = stat['indexname']

                if not indexname or not ns:
                    continue

                sindex_key = "%s %s %s"%(ns,set,indexname)

                if sindex_key not in sindex_stats:
                    sindex_stats[sindex_key] = {}
                sindex_stats[sindex_key] = cluster.infoSIndexStatistics(ns,indexname)
                for node in sindex_stats[sindex_key].keys():
                    if not sindex_stats[sindex_key][node] or isinstance(sindex_stats[sindex_key][node],Exception):
                        continue
                    for key,value in stat.iteritems():
                        sindex_stats[sindex_key][node][key] = value

    return sindex_stats

@CommandHelp('Aerospike Admin')
class RootController(BaseController):
    def __init__(self, seed_nodes=[('127.0.0.1',3000)]
                 , use_telnet=False, user=None, password=None, use_services=False, asadm_version=''):
        super(RootController, self).__init__(seed_nodes=seed_nodes
                                             , use_telnet=use_telnet
                                             , user=user
                                             , password=password, use_services=use_services, asadm_version=asadm_version)
        self.controller_map = {
            'info':InfoController
            , 'show':ShowController
            , 'asinfo':ASInfoController
            , 'cluster':ClusterController
            , '!':ShellController
            , 'shell':ShellController
            , 'collectinfo':CollectinfoController
            , 'features':FeaturesController
            , 'pager':PagerController
        }

    @CommandHelp('Terminate session')
    def do_exit(self, line):
        # This function is a hack for autocomplete
        return "EXIT"

    @CommandHelp('Returns documentation related to a command'
                 , 'for example, to retrieve documentation for the "info"'
                 , 'command use "help info".')
    def do_help(self, line):
        self.executeHelp(line)

    @CommandHelp('"watch" Runs a command for a specified pause and iterations.'
                 , 'Usage: watch [pause] [iterations] [--no-diff] command]'
                 , '   pause:      the duration between executions.'
                 , '               [default: 2 seconds]'
                 , '   iterations: Number of iterations to execute command.'
                 , '               [default: until keyboard interrupt]'
                 , '   --no-diff:  Do not do diff highlighting'
                 , 'Example 1: Show "info network" 3 times with 1 second pause'
                 , '           watch 1 3 info network'
                 , 'Example 2: Show "info namespace" with 5 seconds pause until'
                 , '           interrupted'
                 , '           watch 5 info namespace')
    def do_watch(self, line):
        self.view.watch(self, line)

@CommandHelp('The "info" command provides summary tables for various aspects'
             , 'of Aerospike functionality.')
class InfoController(CommandController):
    def __init__(self):
        self.modifiers = set(['with'])

    @CommandHelp('Displays network, namespace, and XDR summary'
                 , 'information.')
    def _do_default(self, line):
        actions = (util.Future(self.do_network, line).start()
                   , util.Future(self.do_namespace, line).start()
                   , util.Future(self.do_xdr, line).start()
                   )
        return [action.result() for action in actions]

    @CommandHelp('Displays network information for Aerospike.')
    def do_network(self, line):
        stats = util.Future(self.cluster.infoStatistics, nodes=self.nodes).start()
        builds = util.Future(self.cluster.info, 'build', nodes=self.nodes).start()
        versions = util.Future(self.cluster.info, 'version', nodes=self.nodes).start()

        stats = stats.result()

        builds = builds.result()
        versions = versions.result()

        return util.Future(self.view.infoNetwork, stats, versions, builds, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for each set.')
    def do_set(self, line):
        stats = self.cluster.infoSetStatistics(nodes=self.nodes)
        return util.Future(self.view.infoSet, stats, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for each namespace.')
    def do_namespace(self, line):
        stats = self.cluster.infoAllNamespaceStatistics(nodes=self.nodes)
        return util.Future(self.view.infoNamespace, stats, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for Cross Datacenter'
                 , 'Replication (XDR).')
    def do_xdr(self, line):
        stats = util.Future(self.cluster.infoXDRStatistics, nodes=self.nodes).start()
        builds = util.Future(self.cluster.infoXDRBuildVersion, nodes=self.nodes).start()
        xdr_enable = util.Future(self.cluster.isXDREnabled, nodes=self.nodes).start()

        stats = stats.result()
        builds = builds.result()
        xdr_enable = xdr_enable.result()
        return util.Future(self.view.infoXDR, stats, builds, xdr_enable, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for each datacenter.')
    def do_dc(self, line):
        stats = self.cluster.infoAllDCStatistics(nodes=self.nodes)
        configs = self.cluster.infoDCGetConfig(nodes=self.nodes)
        for node in stats.keys():
            if stats[node] and not isinstance(stats[node],Exception) and configs[node] and not isinstance(configs[node],Exception):
                for dc in stats[node].keys():
                    stats[node][dc].update(configs[node][dc])
            elif (not stats[node] or isinstance(stats[node],Exception)) and configs[node] and not isinstance(configs[node],Exception):
                stats[node] = configs[node]
        return util.Future(self.view.infoDC, stats, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for Secondary Indexes (SIndex).')
    def do_sindex(self, line):
        sindex_stats = get_sindex_stats(self.cluster, self.nodes)
        return util.Future(self.view.infoSIndex, sindex_stats, self.cluster, **self.mods)


@CommandHelp('"asinfo" provides raw access to the info protocol.'
             , '  Options:'
             , '    -v <command>  - The command to execute'
             , '    -p <port>     - The port to use.'
             , '                    NOTE: currently restricted to 3000 or 3004'
             , '    -l            - Replace semicolons ";" with newlines.')
class ASInfoController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Executes an info command.')
    def _do_default(self, line):
        if not line:
            raise ShellException("Could not understand asinfo request, " + \
                                 "see 'help asinfo'")
        mods = self.parseModifiers(line)
        line = mods['line']
        like = mods['like']
        nodes = self.nodes

        value = None
        line_sep = False
        xdr = False

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
                    if port == '3004': # ugly Hack
                        xdr = True
                else:
                    raise ShellException(
                        "Do not understand '%s' in '%s'"%(word
                                                       , " ".join(line)))
        except Exception:
            print  "Do not understand '%s' in '%s'"%(word
                                              , " ".join(line))
            return

        value = value.translate(None, "'\"")
        if xdr:
            results = self.cluster.xdrInfo(value, nodes=nodes)
        else:
            results = self.cluster.info(value, nodes=nodes)

        return util.Future(self.view.asinfo, results, line_sep, self.cluster, **mods)

@CommandHelp('"shell" is used to run shell commands on the local node.')
class ShellController(CommandController):
    def _do_default(self, line):
        command = line
        out, err = util.shell_command(command)
        if err:
            print err

        if out:
            print out

@CommandHelp('"show" is used to display Aerospike Statistics and'
             , 'configuration.')
class ShowController(CommandController):
    def __init__(self):
        self.controller_map = {
            'config':ShowConfigController
            , 'statistics':ShowStatisticsController
            , 'latency':ShowLatencyController
            , 'distribution':ShowDistributionController
            #, 'health':ShowHealthController
        }

        self.modifiers = set()

    def _do_default(self, line):
        self.executeHelp(line)

@CommandHelp('"distribution" is used to show the distribution of object sizes'
             , 'and time to live for node and a namespace.')
class ShowDistributionController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'for'])

    @CommandHelp('Shows the distributions of Time to Live and Object Size'
                 , '  Options(only for Object Size distribution):'
                 , '    -b               - Force to show byte wise distribution of Object Sizes. Default is rblock wise distribution in percentage'
                 , '    -k <buckets>     - Maximum number of buckets to show if -b is set.'
                   ' It distributes objects in same size k buckets and display only buckets which has objects in it. Default is 5.')
    def _do_default(self, line):
        actions = (util.Future(self.do_time_to_live, line[:]).start()
                   , util.Future(self.do_object_size, line[:]).start())
        return [action.result() for action in actions]

    def _do_distribution(self, histogram_name, title, unit):
        histogram = self.cluster.infoHistogram(histogram_name, nodes=self.nodes)
        histogram = flip_keys(histogram)

        for namespace, host_data in histogram.iteritems():
            for host_id, data in host_data.iteritems():
                hist = data['data']
                width = data['width']

                cum_total = 0
                total = sum(hist)
                percentile = 0.1
                result = []

                for i, v in enumerate(hist):
                    cum_total += float(v)
                    if total > 0:
                        portion = cum_total / total
                    else:
                        portion = 0.0

                    while portion >= percentile:
                        percentile += 0.1
                        result.append(i+1)

                    if percentile > 1.0:
                        break

                if result == []:
                    result = [0] * 10

                if histogram_name is "objsz":
                    data['percentiles'] = [(r * width)-1 if r>0 else r for r in result]
                else:
                    data['percentiles'] = [r * width for r in result]
        return util.Future(self.view.showDistribution
                           , title
                           , histogram
                           , unit
                           , histogram_name
                           , self.cluster
                           , like=self.mods['for'])

    @CommandHelp('Shows the distribution of TTLs for namespaces')
    def do_time_to_live(self, line):
        return self._do_distribution('ttl', 'TTL Distribution', 'Seconds')

    @CommandHelp('Shows the distribution of Eviction TTLs for namespaces')
    def do_eviction(self, line):
        return self._do_distribution('evict', 'Eviction Distribution', 'Seconds')

    @CommandHelp('Shows the distribution of Object sizes for namespaces'
                 , '  Options:'
                 , '    -b               - Force to show byte wise distribution of Object Sizes. Default is rblock wise distribution in percentage'
                 , '    -k <buckets>     - Maximum number of buckets to show if -b is set.'
                   ' It distributes objects in same size k buckets and display only buckets which has objects in it. Default is 5.')
    def do_object_size(self, line):
        byte_distribution = check_arg_and_delete_from_mods(line=line, arg="-b", default=False, modifiers=self.modifiers, mods=self.mods)
        if not byte_distribution:
            return self._do_distribution('objsz', 'Object Size Distribution', 'Record Blocks')

        histogram_name = 'objsz'
        title = 'Object Size Distribution'
        unit = 'Bytes'
        set_bucket_count = True
        show_bucket_count = get_arg_and_delete_from_mods(line=line, arg="-k", return_type=int, default=5, modifiers=self.modifiers, mods=self.mods)

        histogram = self.cluster.infoHistogram(histogram_name, nodes=self.nodes)
        builds = util.Future(self.cluster.info, 'build', nodes=self.nodes).start().result()
        histogram = flip_keys(histogram)

        for namespace, host_data in histogram.iteritems():
            result = []
            rblock_size_bytes = 128
            width = 1
            for host_id, data in host_data.iteritems():
                try:
                    as_version = builds[host_id]
                    if LooseVersion(as_version) < LooseVersion("2.7.0") or (LooseVersion(as_version) >= LooseVersion("3.0.0") and LooseVersion(as_version) < LooseVersion("3.1.3")):
                        rblock_size_bytes = 512
                except Exception:
                    pass

                hist = data['data']
                width = data['width']

                for i, v in enumerate(hist):
                    if v and v>0:
                        result.append(i)

            result = list(set(result))
            result.sort()
            start_buckets = []
            if len(result) <= show_bucket_count:
            # if asinfo buckets with values>0 are less than show_bucket_count then we can show all single buckets as it is, no need to merge to show big range
                for res in result:
                    start_buckets.append(res)
                    start_buckets.append(res+1)
            else:
            # dividing volume buckets (from min possible bucket with value>0 to max possible bucket with value>0) into same range
                start_bucket = result[0]
                size = result[len(result)-1]-result[0]+1

                bucket_width = size/show_bucket_count
                additional_bucket_index = show_bucket_count -(size%show_bucket_count)

                bucket_index = 0

                while bucket_index < show_bucket_count:
                    start_buckets.append(start_bucket)
                    if bucket_index == additional_bucket_index:
                        bucket_width += 1
                    start_bucket += bucket_width
                    bucket_index += 1
                start_buckets.append(start_bucket)

            columns = []
            need_to_show = {}
            for i,bucket in enumerate(start_buckets):
                if i==len(start_buckets)-1:
                    break
                key = self.get_bucket_range(bucket,start_buckets[i+1],width,rblock_size_bytes)
                need_to_show[key] = False
                columns.append(key)
            for host_id, data in host_data.iteritems():
                rblock_size_bytes = 128
                try:
                    as_version = builds[host_id]
                    if LooseVersion(as_version) < LooseVersion("2.7.0") or (LooseVersion(as_version) >= LooseVersion("3.0.0") and LooseVersion(as_version) < LooseVersion("3.1.3")):
                        rblock_size_bytes = 512
                except Exception:
                    pass
                hist = data['data']
                width = data['width']
                data['values'] = {}
                for i, s in enumerate(start_buckets):
                    if i == len(start_buckets)-1:
                        break
                    b_index = s
                    key = self.get_bucket_range(s,start_buckets[i+1],width,rblock_size_bytes)
                    if key not in columns:
                        columns.append(key)
                    if key not in data["values"]:
                        data["values"][key] = 0
                    while b_index < start_buckets[i+1]:
                        data["values"][key] += hist[b_index]
                        b_index += 1

                    if data["values"][key] > 0:
                        need_to_show[key] = True
                    else:
                        if key not in need_to_show:
                            need_to_show[key] = False
            host_data["columns"] = []
            for column in columns:
                if need_to_show[column]:
                    host_data["columns"].append(column)
        return util.Future(self.view.showObjectDistribution
                           , title
                           , histogram
                           , unit
                           , histogram_name
                           , show_bucket_count
                           , set_bucket_count
                           , self.cluster
                           , like=self.mods['for'])

    def get_bucket_range(self, current_bucket, next_bucket, width, rblock_size_bytes):
        s_b = "0 B"
        if current_bucket>0:
            last_bucket_last_rblock_end = ((current_bucket*width)-1)*rblock_size_bytes
            if last_bucket_last_rblock_end<1:
                last_bucket_last_rblock_end = 0
            else:
                last_bucket_last_rblock_end += 1
            s_b = filesize.size(last_bucket_last_rblock_end,filesize.byte)
            if current_bucket==99 or next_bucket>99:
                return ">%s"%(s_b.replace(" ",""))

        bucket_last_rblock_end = ((next_bucket*width)-1)*rblock_size_bytes
        e_b = filesize.size(bucket_last_rblock_end, filesize.byte)
        return "%s to %s"%(s_b.replace(" ",""),e_b.replace(" ",""))

class ShowLatencyController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like', 'for'])

    @CommandHelp('Displays latency information for Aerospike cluster.'
                 , '  Options:'
                 , '    -f <int>     - Number of seconds (before now) to look back to.'
                 , '                   default: Minimum to get last slice'
                 , '    -d <int>     - Duration, the number of seconds from start to search.'
                 , '                   default: everything to present'
                 , '    -t <int>     - Interval in seconds to analyze.'
                 , '                   default: 0, everything as one slice'
                 , '    -m           - Set to display the output group by machine names.')
    def _do_default(self, line):
        back = get_arg_and_delete_from_mods(line=line, arg="-f", return_type=int, default=None, modifiers=self.modifiers, mods=self.mods)
        duration = get_arg_and_delete_from_mods(line=line, arg="-d", return_type=int, default=None, modifiers=self.modifiers, mods=self.mods)
        slice = get_arg_and_delete_from_mods(line=line, arg="-t", return_type=int, default=None, modifiers=self.modifiers, mods=self.mods)
        machine_wise_display = check_arg_and_delete_from_mods(line=line, arg="-m", default=False, modifiers=self.modifiers, mods=self.mods)

        namespace_set = set()
        if self.mods['for']:
            namespaces = self.cluster.infoNamespaces(nodes=self.nodes)
            namespaces = namespaces.values()
            for namespace in namespaces:
                if isinstance(namespace, Exception):
                    continue
                namespace_set.update(namespace)
            namespace_set = set(util.filter_list(list(namespace_set), self.mods['for']))

        latency = self.cluster.infoLatency(nodes=self.nodes, back=back, duration=duration, slice=slice, ns_set=namespace_set)

        hist_latency = {}
        if machine_wise_display:
            hist_latency = latency
        else:
            for node_id, hist_data in latency.iteritems():
                if isinstance(hist_data, Exception):
                    continue
                for hist_name, data in hist_data.iteritems():
                    if hist_name not in hist_latency:
                        hist_latency[hist_name] = {node_id:data}
                    else:
                        hist_latency[hist_name][node_id] = data
        self.view.showLatency(hist_latency, self.cluster, machine_wise_display=machine_wise_display, show_ns_details=True if namespace_set else False, **self.mods)

@CommandHelp('"show config" is used to display Aerospike configuration settings')
class ShowConfigController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like', 'diff'])

    @CommandHelp('Displays service, network, and namespace configuration'
                 , '  Options:'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def _do_default(self, line):
        actions = (util.Future(self.do_service, line).start()
                   , util.Future(self.do_network, line).start()
                   , util.Future(self.do_namespace, line).start()
                   )
        return [action.result() for action in actions]

    @CommandHelp('Displays service configuration'
                 , '  Options:'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_service(self, line):
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        service_configs = self.cluster.infoGetConfig(nodes=self.nodes
                                                     , stanza='service')
        for node in service_configs:
            if isinstance(service_configs[node], Exception):
                service_configs[node] = {}
            else:
                service_configs[node] = service_configs[node]['service']

        return util.Future(self.view.showConfig, "Service Configuration"
                    , service_configs, self.cluster, title_every_nth=title_every_nth
                    , **self.mods)

    @CommandHelp('Displays network configuration'
                 , '  Options:'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_network(self, line):
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        hb_configs = util.Future(self.cluster.infoGetConfig, nodes=self.nodes
                                                , stanza='network.heartbeat').start()
        info_configs  = util.Future(self.cluster.infoGetConfig, nodes=self.nodes
                                                   , stanza='network.info').start()
        nw_configs = util.Future(self.cluster.infoGetConfig, nodes=self.nodes
                                                   , stanza='network').start()

        network_configs = {}
        hb_configs = hb_configs.result()
        for node in hb_configs:
            if isinstance(hb_configs[node], Exception):
                network_configs[node] = {}
            else:
                network_configs[node] = hb_configs[node]['network.heartbeat']

        info_configs = info_configs.result()
        for node in info_configs:
            if isinstance(info_configs[node], Exception):
                continue
            else:
                network_configs[node].update(info_configs[node]['network.info'])

        nw_configs = nw_configs.result()
        for node in nw_configs:
            if isinstance(nw_configs[node], Exception):
                continue
            else:
                network_configs[node].update(nw_configs[node]['network'])

        return util.Future(self.view.showConfig, "Network Configuration", network_configs
                             , self.cluster, title_every_nth=title_every_nth, **self.mods)

    @CommandHelp('Displays namespace configuration'
                 , '  Options:'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_namespace(self, line):
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        namespace_configs = self.cluster.infoGetConfig(nodes=self.nodes
                                                       , stanza='namespace')
        for node in namespace_configs:
            if isinstance(namespace_configs[node], Exception):
                namespace_configs[node] = {}
            else:
                namespace_configs[node] = namespace_configs[node]['namespace']

        ns_configs = {}
        for host, configs in namespace_configs.iteritems():
            for ns, config in configs.iteritems():
                if ns not in ns_configs:
                    ns_configs[ns] = {}

                try:
                    ns_configs[ns][host].update(config)
                except KeyError:
                    ns_configs[ns][host] = config

        return [util.Future(self.view.showConfig, "%s Namespace Configuration"%(ns)
                            , configs, self.cluster, title_every_nth=title_every_nth, **self.mods)
                for ns, configs in ns_configs.iteritems()]

    @CommandHelp('Displays XDR configuration'
                 , '  Options:'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_xdr(self, line):
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        configs = self.cluster.infoXDRGetConfig(nodes=self.nodes)

        xdr_configs = {}
        for node, config in configs.iteritems():
            if isinstance(config, Exception):
                continue

            xdr_configs[node] = config['xdr']

        return util.Future(self.view.showConfig, "XDR Configuration", xdr_configs, self.cluster
                           , title_every_nth=title_every_nth, **self.mods)

    @CommandHelp('Displays datacenter configuration'
                 , '  Options:'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_dc(self, line):
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        all_dc_configs = self.cluster.infoDCGetConfig(nodes=self.nodes)
        dc_configs = {}
        for host, configs in all_dc_configs.iteritems():
            if not configs or isinstance(configs,Exception):
                continue
            for dc, config in configs.iteritems():
                if dc not in dc_configs:
                    dc_configs[dc] = {}

                try:
                    dc_configs[dc][host].update(config)
                except KeyError:
                    dc_configs[dc][host] = config

        return [util.Future(self.view.showConfig, "%s DC Configuration"%(dc)
                            , configs, self.cluster, title_every_nth=title_every_nth, **self.mods)
                for dc, configs in dc_configs.iteritems()]

@CommandHelp('"show health" is used to display Aerospike configuration health')
class ShowHealthController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

        self.FREE_PCT_MEMORY = 'free-pct-memory'
        self.MIN_AVAIL_PCT = 'min-avail-pct'
        self.STOP_WRITES = 'stop-writes'
        self.HWM_BREACHED = 'hwm-breached'
        self.MEMORY_SIZE = 'memory-size'
        self.HIGH_WATER_DISK_PCT = 'high-water-disk-pct'
        self.HIGH_WATER_MEMEORY_PCT = 'high-water-memory-pct'
        self.STOP_WRITES_PCT = 'stop-writes-pct'
        self.REPL_FACTOR = 'repl-factor'
        self.SET_EVICTED_OBJECTS = 'set-evicted-objects'
        self.TYPE = 'type'
        self.HWM_WARN_CHECK_PCT = 10
        self.HEARTBEAT_INTERVAL = 'heartbeat-interval'
        self.HEARTBEAT_TIMEOUT = 'heartbeat-timeout'
        self.PROTO_FD_MAX = 'proto-fd-max'
        self.WARNING = 'WARNING'
        self.CRITICAL = 'CRITICAL'

        self.NAMESPACE_PARAMS = {
                            self.HIGH_WATER_DISK_PCT : 'OK',
                            self.HIGH_WATER_MEMEORY_PCT : 'OK',
                            self.HWM_BREACHED : 'OK',
                            self.MIN_AVAIL_PCT : 'OK',
                            self.MEMORY_SIZE : 'OK',
                            self.REPL_FACTOR : 'OK',
                            self.STOP_WRITES_PCT : 'OK',
                            self.STOP_WRITES : 'OK',
                            self.SET_EVICTED_OBJECTS : 'OK',
                            self.TYPE: 'OK'
                           }

        self.NETWORK_PARAMS = {
                          self.HEARTBEAT_INTERVAL : 'OK',
                          self.HEARTBEAT_TIMEOUT : 'OK',
                          self.PROTO_FD_MAX : 'OK'
                         }

    @CommandHelp('Displays cluster health')
    def _do_default(self, line):
        self.do_namespace(line)
        self.do_log(line)
        self.do_network(line)
        self.do_xdr(line)
        pass

    def get_namespaces_health(self, namespace_config = ''):
        namespaces_health = dict()
        for ns, nodes in namespace_config.items():
            broken = {}
            is_first = True
            namespaces_health[ns] = dict()
            for ip, params in nodes.items():
                if params:
                    health_params = copy.deepcopy(self.NAMESPACE_PARAMS)
                    if is_first:
                        high_water_disk_pct = params.get(self.HIGH_WATER_DISK_PCT)
                        memory_size =  params.get(self.MEMORY_SIZE)
                        repl_factor =  params.get(self.REPL_FACTOR)
                        stop_writes_pct =  params.get(self.STOP_WRITES_PCT)
                        set_evicted_objects = params.get(self.SET_EVICTED_OBJECTS)
                        _type = params.get(self.TYPE)
                        is_first = False
                    def update_health(param, comparator, result):
                        if params.get(param) != comparator:
                            if ip not in broken:
                                broken[ip] = {}
                            broken[ip][param] =  result

                    update_health(self.HIGH_WATER_DISK_PCT, high_water_disk_pct, self.WARNING)
                    # update_health(self.HIGH_WATER_MEMEORY_PCT, high_water_memory_pct, self.WARNING)
                    update_health(self.HWM_BREACHED, 'false', self.WARNING)
                    update_health(self.MEMORY_SIZE, memory_size, self.WARNING)
                    update_health(self.REPL_FACTOR, repl_factor, self.CRITICAL)
                    update_health(self.STOP_WRITES, 'false', self.CRITICAL)
                    update_health(self.STOP_WRITES_PCT, stop_writes_pct, self.WARNING)
                    update_health(self.SET_EVICTED_OBJECTS, set_evicted_objects, self.WARNING)
                    update_health(self.TYPE, _type, self.WARNING)
                    high_water_memory_pct = params.get(self.HIGH_WATER_MEMEORY_PCT)
                    min_avail_pct = params.get(self.MIN_AVAIL_PCT)
                    if high_water_memory_pct is not None:
                        high_water_memory_pct = int(high_water_memory_pct)
                        used_memory_pct = 100 - int(params[self.FREE_PCT_MEMORY])
                        hwm_warn_range = range(high_water_memory_pct - (high_water_memory_pct * self.HWM_WARN_CHECK_PCT / 100) , high_water_memory_pct)
                        if used_memory_pct >= high_water_memory_pct:
                            health_params[self.HIGH_WATER_MEMEORY_PCT] = self.CRITICAL
                        elif high_water_memory_pct > 65 or used_memory_pct in hwm_warn_range:
                            health_params[self.HIGH_WATER_MEMEORY_PCT] = self.WARNING
                    if min_avail_pct is not None:
                        min_avail_pct = int(min_avail_pct)
                        if min_avail_pct < 5:
                                health_params[self.MIN_AVAIL_PCT] = self.CRITICAL
                        elif min_avail_pct <= 20 and min_avail_pct >= 5:
                                health_params[self.MIN_AVAIL_PCT] = self.WARNING
                    namespaces_health[ns][ip] = health_params
            for _params in namespaces_health[ns].values():
                for broken_param in broken.values():
                    for param, status in broken_param.items():
                        _params[param] = status
        return namespaces_health

    @CommandHelp('Displays namespace health of cluster')
    def do_namespace(self, line):
        namespaces = self.cluster.infoNamespaces(nodes=self.nodes)
        namespaces = namespaces.values()
        namespace_set = set()
        namespace_stats = dict()
        for namespace in namespaces:
            if isinstance(namespace, Exception):
                continue
            namespace_set.update(namespace)
        for namespace in sorted(namespace_set):
            ns_stats = self.cluster.infoNamespaceStatistics(namespace
                                                            , nodes=self.nodes)
            for node, params in ns_stats.items():
                if isinstance(params, Exception):
                    ns_stats[node] = {}
            namespace_stats[namespace] = ns_stats
        ns_health = self.get_namespaces_health(namespace_stats)
        for ns, configs in ns_health.iteritems():
            self.view.showHealth("%s Namespace Health"%(ns)
                                 , configs, self.cluster, **self.mods)

    def get_logs_health(self, logs_config = ''):
        KEY_NAME = 'contexts'
        log_health = dict()
        log_health_missing = dict()
        for ip, params in logs_config.items():
            context_dict = {KEY_NAME : 'OK'}
            context_missing = {}
            for param in params.split(';'):
                context_info =  param.rsplit(':', 1)
                if context_info[1] != 'INFO':
                    context_dict[KEY_NAME] = self.WARNING
                    context_missing[context_info[0]] = context_info[1]
            log_health[ip]= context_dict
            log_health_missing[ip] = context_missing
        return(log_health, log_health_missing)

    @CommandHelp('Displays log health of cluster')
    def do_log(self,line):
        logs_config = self.cluster._callNodeMethod(self.nodes, "info", "log/0")
        for log, value in logs_config.items():
            if isinstance(value, Exception):
                del logs_config[log]
        health, health_missing = self.get_logs_health(logs_config)
        self.view.showHealth('Logs Health', health, self.cluster, **self.mods)
        # TODO: develop printing logic for health_missing

    def get_network_health(self, network_config = None):
        broken = {}
        network_health = dict()
        is_first = True
        for ip, params in network_config.items():
            if params:
                network_health[ip] = dict()
                health_params = copy.deepcopy(self.NETWORK_PARAMS)
                if is_first:
                    heartbeat_interval = params.get(self.HEARTBEAT_INTERVAL)
                    heartbeat_timeout =  params.get(self.HEARTBEAT_TIMEOUT)
                    proto_fd_max = params.get(self.PROTO_FD_MAX)
                    is_first = False
                def update_health(param, comparator, result):
                    if params.get(param) != comparator:
                        if ip not in broken:
                            broken[ip] = {}
                        broken[ip][param] =  result
                update_health(self.HEARTBEAT_INTERVAL, heartbeat_interval, self.CRITICAL)
                update_health(self.HEARTBEAT_TIMEOUT, heartbeat_timeout, self.CRITICAL)
                update_health(self.PROTO_FD_MAX, proto_fd_max, self.CRITICAL)
                network_health[ip] = health_params
        for _params in network_health.values():
            for broken_param in broken.values():
                for param, status in broken_param.items():
                    _params[param] = status
        return network_health

    @CommandHelp('Displays Network health of cluster')
    def do_network(self, line):
        network_config = self.cluster.infoGetConfig(nodes=self.nodes
                                                , stanza='network.heartbeat')
        service_configs = self.cluster.infoGetConfig(nodes=self.nodes
                                                     , stanza='service')

        for node in network_config:
            if isinstance(network_config[node], Exception):
                network_config[node] = {}
            else:
                network_config[node] = network_config[node]['network.heartbeat']

        for node in service_configs:
            if isinstance(service_configs[node], Exception):
                service_configs[node] = {}
            else:
                network_config[node].update(service_configs[node]['service'])
        network_health = self.get_network_health(network_config)
        self.view.showHealth('Network Health', network_health, self.cluster, **self.mods)

    def get_xdr_health(self, xdr_config):
        pass

    @CommandHelp('Displays xdr health')
    def do_xdr(self, line):
        xdr_stats = self.cluster.infoXDRStatistics(nodes=self.nodes)
        for node in xdr_stats:
            if isinstance(xdr_stats[node], Exception):
                xdr_stats[node] = {}
        self.view.showStats("XDR Statistics"
                            , xdr_stats
                            , self.cluster
                            , **self.mods)

@CommandHelp('Displays statistics for Aerospike components.')
class ShowStatisticsController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like', 'for'])

    @CommandHelp('Displays bin, set, service, and namespace statistics'
                 , '  Options:'
                 , '    -t           - Set to show total column at the end. It contains node wise sum for statistics.'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def _do_default(self, line):
        actions = (util.Future(self.do_bins, line).start()
                   , util.Future(self.do_sets, line).start()
                   , util.Future(self.do_service, line).start()
                   , util.Future(self.do_namespace, line).start()
                   )

        return [action.result() for action in actions]

    @CommandHelp('Displays service statistics'
                 , '  Options:'
                 , '    -t           - Set to show total column at the end. It contains node wise sum for statistics.'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_service(self, line):
        service_stats = self.cluster.infoStatistics(nodes=self.nodes)
        show_total = check_arg_and_delete_from_mods(line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods)
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        return util.Future(self.view.showStats, "Service Statistics", service_stats, self.cluster, show_total=show_total
                            , title_every_nth=title_every_nth, **self.mods)

    @CommandHelp('Displays namespace statistics'
                 , '  Options:'
                 , '    -t           - Set to show total column at the end. It contains node wise sum for statistics.'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_namespace(self, line):
        show_total = check_arg_and_delete_from_mods(line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods)
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        namespaces = self.cluster.infoNamespaces(nodes=self.nodes)

        namespaces = namespaces.values()
        namespace_set = set()
        for namespace in namespaces:
            if isinstance(namespace, Exception):
                continue
            namespace_set.update(namespace)

        namespace_set = set(util.filter_list(list(namespace_set), self.mods['for']))

        ns_stats = {}
        for namespace in namespace_set:
            ns_stats[namespace] = util.Future(self.cluster.infoNamespaceStatistics
                                              , namespace
                                              , nodes=self.nodes).start()

        return [util.Future(self.view.showStats
                            , "%s Namespace Statistics"%(namespace)
                            , ns_stats[namespace].result()
                            , self.cluster
                            , show_total=show_total, title_every_nth=title_every_nth
                            , **self.mods)
                for namespace in sorted(namespace_set)]

    @CommandHelp('Displays sindex statistics'
                 , '  Options:'
                 , '    -t           - Set to show total column at the end. It contains node wise sum for statistics.'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_sindex(self, line):
        show_total = check_arg_and_delete_from_mods(line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods)
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        sindex_stats = get_sindex_stats(self.cluster, self.nodes, self.mods['for'])
        return [util.Future(self.view.showStats
                            , "%s Sindex Statistics"%(ns_set_sindex)
                            , sindex_stats[ns_set_sindex]
                            , self.cluster
                            , show_total=show_total, title_every_nth=title_every_nth
                            , **self.mods)
                for ns_set_sindex in sorted(sindex_stats.keys())]

    @CommandHelp('Displays set statistics'
                 , '  Options:'
                 , '    -t           - Set to show total column at the end. It contains node wise sum for statistics.'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_sets(self, line):
        show_total = check_arg_and_delete_from_mods(line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods)
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        sets = self.cluster.infoSetStatistics(nodes=self.nodes)

        set_stats = {}
        for host_id, key_values in sets.iteritems():
            if isinstance(key_values, Exception) or not key_values:
                continue
            namespace_list = [ns_set[0] for ns_set in key_values.keys()]
            namespace_list = util.filter_list(namespace_list, self.mods['for'])
            for key, values in key_values.iteritems():
                if key[0] not in namespace_list:
                    continue
                if key not in set_stats:
                    set_stats[key] = {}
                host_vals = set_stats[key]

                if host_id not in host_vals:
                    host_vals[host_id] = {}
                hv = host_vals[host_id]
                hv.update(values)

        return [util.Future(self.view.showStats, "%s %s Set Statistics"%(namespace, set_name)
                            , stats
                            , self.cluster
                            , show_total=show_total, title_every_nth=title_every_nth
                            , **self.mods)
                for (namespace, set_name), stats in set_stats.iteritems()]

    @CommandHelp('Displays bin statistics'
                 , '  Options:'
                 , '    -t           - Set to show total column at the end. It contains node wise sum for statistics.'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_bins(self, line):
        show_total = check_arg_and_delete_from_mods(line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods)
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        bin_stats = self.cluster.infoBinStatistics(nodes=self.nodes)
        new_bin_stats = {}

        for node_id, bin_stat in bin_stats.iteritems():
            if not bin_stat or isinstance(bin_stat, Exception) :
                continue
            namespace_list = util.filter_list(bin_stat.keys(), self.mods['for'])
            for namespace, stats in bin_stat.iteritems():
                if namespace not in namespace_list:
                    continue
                if namespace not in new_bin_stats:
                    new_bin_stats[namespace] = {}
                ns_stats = new_bin_stats[namespace]

                if node_id not in ns_stats:
                    ns_stats[node_id] = {}
                node_stats = ns_stats[node_id]

                node_stats.update(stats)

        views = []
        return [util.Future(self.view.showStats, "%s Bin Statistics"%(namespace)
                            , bin_stats
                            , self.cluster
                            , show_total=show_total, title_every_nth=title_every_nth
                            , **self.mods)
                for namespace, bin_stats in new_bin_stats.iteritems()]

    @CommandHelp('Displays XDR statistics'
                 , '  Options:'
                 , '    -t           - Set to show total column at the end. It contains node wise sum for statistics.'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_xdr(self, line):
        show_total = check_arg_and_delete_from_mods(line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods)
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        xdr_stats = self.cluster.infoXDRStatistics(nodes=self.nodes)

        return util.Future(self.view.showStats, "XDR Statistics"
                            , xdr_stats
                            , self.cluster
                            , show_total=show_total, title_every_nth=title_every_nth
                            , **self.mods)

    @CommandHelp('Displays datacenter statistics'
                 , '  Options:'
                 , '    -t           - Set to show total column at the end. It contains node wise sum for statistics.'
                 , '    -r <int>     - Repeating output table title and row header after every r columns.'
                 , '                   default: 0, no repetition.')
    def do_dc(self, line):
        show_total = check_arg_and_delete_from_mods(line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods)
        title_every_nth = get_arg_and_delete_from_mods(line=line, arg="-r", return_type=int, default=0, modifiers=self.modifiers, mods=self.mods)
        all_dc_stats = self.cluster.infoAllDCStatistics(nodes=self.nodes)
        dc_stats = {}
        for host, stats in all_dc_stats.iteritems():
            if not stats or isinstance(stats,Exception):
                continue
            for dc, stat in stats.iteritems():
                if dc not in dc_stats:
                    dc_stats[dc] = {}

                try:
                    dc_stats[dc][host].update(stat)
                except KeyError:
                    dc_stats[dc][host] = stat
        return [util.Future(self.view.showConfig, "%s DC Statistics"%(dc)
                            , stats, self.cluster, show_total=show_total, title_every_nth=title_every_nth, **self.mods)
                for dc, stats in dc_stats.iteritems()]

class ClusterController(CommandController):
    def __init__(self):
        self.modifiers = set(['with'])

    def _do_default(self, line):
        self.executeHelp(line)

    def do_dun(self, line):
        results = self.cluster.infoDun(self.mods['line'], nodes=self.nodes)
        self.view.dun(results, self.cluster, **self.mods)

    def do_undun(self, line):
        results = self.cluster.infoUndun(self.mods['line'], nodes=self.nodes)
        self.view.dun(results, self.cluster, **self.mods)
    
    def format_missing_part(self, part_data):
        missing_part = ''
        get_part = lambda pid, pindex: str(pid) + ':S:' + str(pindex) + ','
        for pid, part in enumerate(part_data):
            if part:
                for pindex in part:
                    missing_part += get_part(pid, pindex)
        return missing_part[:-1]

    def get_namespace_data(self, namespace_stats):
        disc_pct_allowed = 1   # Considering Negative & Positive both discrepancy
        ns_info = {}
        for ns, nodes in namespace_stats.items():
            ns_info[ns] = {}
            master_objs = 0
            replica_objs = 0
            repl_factor = 0
            for params in nodes.values():
                if isinstance(params, Exception):
                    continue
                master_objs += get_value_from_dict(params,('master-objects','master_objects'),0,int)
                replica_objs += get_value_from_dict(params,('prole-objects','prole_objects'),0,int)
                repl_factor = max(repl_factor, int(params['repl-factor']))
            ns_info[ns]['avg_master_objs'] = master_objs / 4096
            ns_info[ns]['avg_replica_objs'] = replica_objs / 4096
            ns_info[ns]['repl_factor'] = repl_factor
            diff_master = ns_info[ns]['avg_master_objs'] * disc_pct_allowed / 100
            if diff_master < 1024:
                diff_master = 1024
            diff_replica = ns_info[ns]['avg_replica_objs'] * disc_pct_allowed / 100
            if diff_replica < 1024:
                diff_replica = 1024
            ns_info[ns]['diff_master'] = diff_master
            ns_info[ns]['diff_replica'] = diff_replica
        return ns_info

    def get_pmap_data(self, pmap_info, ns_info, versions):
        # TODO: check if node not have master & replica objects
        pid_range = 4096        # each namespace is divided into 4096 partition
        is_dist_delta_exeeds = lambda exp, act, diff: abs(exp - act) > diff
        pmap_data = {}
        ns_missing_part = {}
        visited_ns = set()
        # required fields
        # format : (index_ptr, field_name, default_index)
        required_fields = [("ns_index","namespace",0),("pid_index","partition",1),("state_index","state",2),
                           ("pindex_index","replica",3),("objects_index","records",9)]
        for _node, partitions in pmap_info.items():
            node_pmap = dict()
            if isinstance(partitions, Exception):
                continue
            f_indices = {}
            # default index in partition fields for server < 3.6.1
            for t in required_fields:
                f_indices[t[0]] = t[2]
            index_set = False
            for item in partitions.split(';'):
                fields = item.split(':')
                if not index_set:
                    index_set = True
                    if all(i[1] in fields for i in required_fields):
                        # pmap format contains headers from server 3.9 onwards
                        for t in required_fields:
                            f_indices[t[0]] = fields.index(t[1])
                        continue
                    elif LooseVersion(versions[_node]) >= LooseVersion("3.6.1"):
                        # pmap format is changed(1 field is removed) in aerospike 3.6.1
                        # In 3.7.5, one new field got added but at the end of the fields. So it doesn't affect required indices
                        f_indices["objects_index"]=8
                ns, pid, state, pindex, objects = fields[f_indices["ns_index"]], int(fields[f_indices["pid_index"]]),\
                                         fields[f_indices["state_index"]], int(fields[f_indices["pindex_index"]]),\
                                         int(fields[f_indices["objects_index"]])

                if ns not in node_pmap:
                    node_pmap[ns] = { 'pri_index' : 0,
                                      'sec_index' : 0,
                                      'master_disc_part': [],
                                      'replica_disc_part':[]
                                    }
                if ns not in visited_ns:
                    ns_missing_part[ns] = {}
                    ns_missing_part[ns]['missing_part'] = [range(ns_info[ns]['repl_factor']) for i in range(pid_range)]
                    visited_ns.add(ns)
                if state == 'S':
                    # partition state is SYNC
                    try:
                        if  pindex == 0:
                            node_pmap[ns]['pri_index'] += 1
                            exp_master_objs = ns_info[ns]['avg_master_objs']
                            if exp_master_objs == 0 and objects == 0:
                                pass
                            elif is_dist_delta_exeeds(exp_master_objs, objects, ns_info[ns]['diff_master']):
                                node_pmap[ns]['master_disc_part'].append(pid)
                        if  pindex in range(1, ns_info[ns]['repl_factor']):
                            node_pmap[ns]['sec_index'] += 1
                            exp_replica_objs = ns_info[ns]['avg_replica_objs']
                            if exp_replica_objs == 0 and objects == 0:
                                pass
                            elif is_dist_delta_exeeds(exp_replica_objs, objects, ns_info[ns]['diff_replica']):
                                node_pmap[ns]['replica_disc_part'].append(pid)

                        ns_missing_part[ns]['missing_part'][pid].remove(pindex)
                    except Exception:
                        pass
                if pid not in range(pid_range):
                    print "For {0} found partition-ID {1} which is beyond legal partitions(0...4096)".format(ns, pid)
            pmap_data[_node] = node_pmap
        for _node, _ns in pmap_data.items():
            for ns_name, params in _ns.items():
                params['missing_part'] = self.format_missing_part(ns_missing_part[ns_name]['missing_part'])
        return pmap_data
    
    @CommandHelp('"pmap" command is used for displaying partition map analysis of cluster')
    def do_pmap(self, line):
        versions = util.Future(self.cluster.info, 'version', nodes=self.nodes).start()
        pmap_info = util.Future(self.cluster.info, 'partition-info', nodes=self.nodes).start()
        namespaces = util.Future(self.cluster.infoNamespaces, nodes=self.nodes).start()
        versions = versions.result()
        pmap_info = pmap_info.result()
        namespaces = namespaces.result()
        namespaces = namespaces.values()
        namespace_set = set()
        namespace_stats = dict()
        for namespace in namespaces:
            if isinstance(namespace, Exception):
                continue
            namespace_set.update(namespace)
        for namespace in sorted(namespace_set):
            ns_stats = self.cluster.infoNamespaceStatistics(namespace
                                                            , nodes=self.nodes)
            namespace_stats[namespace] = ns_stats
        pmap_data = self.get_pmap_data(pmap_info, self.get_namespace_data(namespace_stats), versions)
        return util.Future(self.view.clusterPMap, pmap_data, self.cluster)

    def get_qnode_data(self, qnode_config=''):
        qnode_data = dict()
        for _node, config in qnode_config.items():
            if isinstance(config, Exception):
                continue
            node_qnode = dict()
            for item in config.split(';'):
                fields = item.split(':')
                ns, pid, node_type = fields[0], int(fields[1]), fields[5]
                # qnode format is changed(1 field is removed) in aerospike's 3.6.1 version
                if len(fields) == 7:
                    pdata = int(fields[6])
                else:
                    pdata = int(fields[7])
                if ns not in node_qnode:
                    node_qnode[ns] = { 'MQ_without_data' : 0,
                                      'RQ_data' : 0,
                                      'RQ_without_data' : []
                                     }
                if node_type == 'MQ' and pdata == 0:
                    node_qnode[ns]['MQ_without_data'] += 1
                elif node_type == 'RQ' and pdata == 0:
                    node_qnode[ns]['RQ_without_data'].append(pid)
                    node_qnode[ns]['RQ_data'] += 1
                elif node_type == 'RQ':
                    node_qnode[ns]['RQ_data'] += 1
            qnode_data[_node] = node_qnode
        return qnode_data

    def _do_qnode(self, line):
        qnode_info = self.cluster.info("sindex-qnodemap:", nodes = self.nodes)
        qnode_data = self.get_qnode_data(qnode_info)
        return util.Future(self.view.clusterQNode, qnode_data, self.cluster)

@CommandHelp('"collectinfo" is used to collect system stats on the local node.')
class CollectinfoController(CommandController):

    def collect_local_file(self,src,dest_dir):
        print "[INFO] Copying file %s to %s"%(src,dest_dir)
        try:
            shutil.copy2(src, dest_dir)
        except Exception,e:
            print e
        return

    def collectinfo_content(self, func, parm='', alt_parm=''):
        name = ''
        capture_stdout = util.capture_stdout
        sep = "\n====ASCOLLECTINFO====\n"
        try:
            name = func.func_name
        except Exception:
            pass
        info_line = "[INFO] Data collection for " + name +"%s"%(" %s"%(str(parm)) if parm else "") + " in progress.."
        print info_line
        if parm:
            sep += str(parm)+"\n"

        if func == 'shell':
            o,e = util.shell_command(parm)
            if e:
                if e:
                    info_line = "[ERROR] " + str(e)
                    print info_line
                if alt_parm and alt_parm[0]:
                    info_line = "[INFO] Data collection for alternative command " + name +str(alt_parm) + " in progress.."
                    print info_line
                    sep += str(alt_parm)+"\n"
                    o_alt,e_alt = util.shell_command(alt_parm)
                    if e_alt:
                        self.cmds_error.add(parm[0])
                        self.cmds_error.add(alt_parm[0])
                        if e_alt:
                            info_line = "[ERROR] " + str(e_alt)
                            print info_line
                    if o_alt:
                        o = o_alt
                else:
                    self.cmds_error.add(parm[0])

        elif func == 'cluster':
            o = self.cluster.info(parm)
        else:
            o = capture_stdout(func,parm)
        self.write_log(sep+str(o))
        return ''

    def write_log(self,collectedinfo):
        f = open(str(aslogfile), 'a')
        f.write(str(collectedinfo))
        return f.close()

    def write_version(self,line):
        print "asadm version " + str(self.asadm_version)

    def get_metadata(self,response_str,prefix=''):
        aws_c = ''
        aws_metadata_base_url = 'http://169.254.169.254/latest/meta-data'
        prefix_o = prefix
        if prefix_o == '/':
            prefix = ''
        for rsp in response_str.split("\n"):
            if rsp[-1:] == '/':
                if prefix_o == '': #First level child
                    rsp_p = rsp.strip('/')
                else:
                    rsp_p = rsp
                self.get_metadata(rsp_p,prefix)
            else:
                meta_url = aws_metadata_base_url+prefix+'/'+rsp
                req = urllib2.Request(meta_url)
                r = urllib2.urlopen(req)
                # r = requests.get(meta_url,timeout=aws_timeout)
                if r.code != 404:
                    aws_c += rsp +'\n'+r.read() +"\n"
        return aws_c

    def get_awsdata(self,line):
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
                aws_rsp += self.get_metadata(rsp,'/')
                print "Requesting... {0} {1}  \t Successful".format(aws_metadata_base_url, aws_rsp)
            else:
                aws_rsp = " Not likely in AWS"
                print "Requesting... {0} \t FAILED {1} ".format(aws_metadata_base_url, aws_rsp)

        except Exception as e:
            print "Requesting... {0} \t  {1} ".format(aws_metadata_base_url, e)
            print "FAILED! Node Is Not likely In AWS"
            
    def collect_sys(self, line=''):
        print "['cpuinfo']"
        cpu_info_cmd = 'cat /proc/cpuinfo | grep "vendor_id"'
        o,e = util.shell_command([cpu_info_cmd])
        if o:
            o = o.strip().split("\n")
            cpu_info = {}
            for item in o:
                items = item.strip().split(":")
                if len(items)== 2:
                    key = items[1].strip()
                    if key in cpu_info.keys():
                        cpu_info[key] = cpu_info[key] + 1
                    else:
                        cpu_info[key] = 1
            print "vendor_id\tprocessor count"
            for key in cpu_info.keys():
                print key + "\t" + str(cpu_info[key])

    def get_asd_pids(self):
        pids = []
        ps_cmd = 'sudo ps aux|grep -v grep|grep -E "asd|cld"'
        ps_o,ps_e = util.shell_command([ps_cmd])
        if ps_o:
            ps_o = ps_o.strip().split("\n")
            pids = []
            for item in ps_o:
                vals = item.strip().split()
                if len(vals)>=2:
                    pids.append(vals[1])
        return pids

    def collect_logs_from_systemd_journal(self, as_logfile_prefix):
        global aslogfile
        asd_pids = self.get_asd_pids()
        for pid in asd_pids:
            try:
                journalctl_cmd = ['journalctl _PID=%s --since "24 hours ago" -q -o cat'%(pid)]
                aslogfile = as_logfile_prefix + 'aerospike_%s.log'%(pid)
                print "[INFO] Data collection for %s to %s in progress..." %(str(journalctl_cmd), aslogfile)
                o,e = util.shell_command(journalctl_cmd)
                if e:
                    print e
                else:
                    self.write_log(o)
            except Exception as e1:
                print str(e1)
                sys.stdout = sys.__stdout__

    def collect_lsof(self, verbose=False):
        print "['lsof']"
        pids = self.get_asd_pids()
        if pids and len(pids)>0:
            search_str = pids[0]
            for _str in pids[1:len(pids)]:
                search_str += "\\|" + _str
            lsof_cmd='sudo lsof -n |grep "%s"'%(search_str)
            lsof_o,lsof_e = util.shell_command([lsof_cmd])
            if lsof_e :
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
                                unidentified_protocol_count = unidentified_protocol_count + 1
                        except Exception:
                            pass

                        try:
                            type = row.strip().split()[4]
                            if type not in lsof_dic:
                                if len(type)>type_ljust_parm:
                                    type_ljust_parm = len(type)
                                if type in lsof_file_type_desc and len(lsof_file_type_desc[type])>desc_ljust_parm:
                                    desc_ljust_parm = len(lsof_file_type_desc[type])
                                lsof_dic[type] = 1
                            else:
                                lsof_dic[type] = lsof_dic[type] + 1

                        except Exception:
                            continue

                    print "FileType".ljust(type_ljust_parm)+"Description".ljust(desc_ljust_parm)+"fd count"
                    for ftype in sorted(lsof_dic.keys()):
                        desc = "Unknown"
                        if ftype in lsof_file_type_desc:
                            desc = lsof_file_type_desc[ftype]
                        print ftype.ljust(type_ljust_parm)+desc.ljust(desc_ljust_parm) + str(lsof_dic[ftype])

                    print "\nUnidentified Protocols = " + str(unidentified_protocol_count)

    def zip_files(self, dir_path, _size = 1):
        """
        If file size is greater then given _size, create zip of file on same location and 
        remove original one. Won't zip If zlib module is not available. 
        """ 
        for root, dirs, files in os.walk(dir_path):
            for _file in files:
                file_path = os.path.join(root,_file)
                size_mb = (os.path.getsize(file_path)/(1024*1024))
                if size_mb >= _size:
                    os.chdir(root)
                    try:                                      
                        newzip =  zipfile.ZipFile(_file + ".zip", "w", zipfile.ZIP_DEFLATED)
                        newzip.write(_file)
                        newzip.close()
                        os.remove(_file)
                    except Exception as e: 
                        print e
                        pass
    
    def archive_log(self,logdir):
        self.zip_files(logdir)
        util.shell_command(["tar -czvf " + logdir + ".tgz " + aslogdir])
        sys.stderr.write("\x1b[2J\x1b[H")
        print "\n\n\nFiles in " + logdir + " and " + logdir + ".tgz saved. "
        print "END OF ASCOLLECTINFO"

    def parse_namespace(self, namespace_data):
        """
        This method will return set of namespaces present given namespace data
        @param namespace_data: should be a form of dict returned by info protocol for namespace.
        """
        namespaces = set()
        for _value in namespace_data.values():
            for ns in _value.split(';'):
                namespaces.add(ns)
        return namespaces

    def main_collectinfo(self, show_all=False, verbose=False):
        # getting service port to use in ss/netstat command
        port = 3000
        try:
            host,port = list(self.cluster._original_seed_nodes)[0]
        except Exception:
            port = 3000

        # Unfortunately timestamp can not be printed in Centos with dmesg,
        # storing dmesg logs without timestamp for this particular OS.
        if 'centos' == (platform.linux_distribution()[0]).lower():
            cmd_dmesg  = 'sudo dmesg'
            alt_dmesg  = ''
        else:
            cmd_dmesg  = 'sudo dmesg -T'
            alt_dmesg  = 'sudo dmesg'
        
        collect_output = time.strftime("%Y-%m-%d %H:%M:%S UTC\n", time.gmtime())
        global aslogdir, aslogfile, output_time
        output_time = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        aslogdir = '/tmp/collectInfo_' + output_time
        as_logfile_prefix = aslogdir + '/' + output_time + '_'

        # cmd and alternative cmds are stored in list of list instead of dic to maintain proper order for output
        sys_shell_cmds = [
                      ['hostname -I','hostname'],
                      ['uname -a',''],
                      ['lsb_release -a','ls /etc|grep release|xargs -I f cat /etc/f'],
                      ['cat /proc/meminfo','vmstat -s'],
                      ['cat /proc/interrupts',''],
                      ['ls /sys/block/{sd*,xvd*}/queue/rotational |xargs -I f sh -c "echo f; cat f;"',''],
                      ['ls /sys/block/{sd*,xvd*}/device/model |xargs -I f sh -c "echo f; cat f;"',''],
                      ['rpm -qa|grep -E "citrus|aero"', 'dpkg -l|grep -E "citrus|aero"'],
                      ['ip addr',''],
                      ['ip -s link',''],
                      ['sudo iptables -L',''],
                      ['sudo sysctl -a | grep -E "shmmax|file-max|maxfiles"',''],
                      ['iostat -x 1 10',''],
                      ['sar -n DEV',''],
                      ['sar -n EDEV',''],
                      ['df -h',''],
                      ['free -m',''],
                      [cmd_dmesg,alt_dmesg],
                      ['top -n3 -b','top -l 3'],
                      ['mpstat -P ALL 2 3',''],
                      ['uptime',''],
                      ['ss -pant | grep %d | grep TIME-WAIT | wc -l'%(port),'netstat -pant | grep %d | grep TIME_WAIT | wc -l'%(port)],
                      ['ss -pant | grep %d | grep CLOSE-WAIT | wc -l'%(port),'netstat -pant | grep %d | grep CLOSE_WAIT | wc -l'%(port)],
                      ['ss -pant | grep %d | grep ESTAB | wc -l'%(port),'netstat -pant | grep %d | grep ESTABLISHED | wc -l'%(port)]
                      ]
        dignostic_info_params = ['network', 'namespace', 'set', 'xdr', 'dc', 'sindex']
        dignostic_features_params = ['features']
        dignostic_cluster_params = ['pmap']
        dignostic_show_params = ['config', 'config xdr', 'config dc', 'config diff', 'distribution', 'distribution eviction', 'distribution object_size -b', 'latency', 'statistics', 'statistics xdr', 'statistics dc', 'statistics sindex' ]
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

        _ip = ((util.shell_command(["hostname -I"])[0]).split(' ')[0].strip())

        if show_all:
            try:
                namespaces = self.parse_namespace(self.cluster._callNodeMethod([_ip], "info", "namespaces"))
            except Exception:
                from lib.node import Node
                tempNode = Node(_ip)
                namespaces = self.parse_namespace(self.cluster._callNodeMethod([tempNode.ip], "info", "namespaces"))

            for ns in namespaces:
                # dump-wb dumps debug information about Write Bocks, it needs namespace, device-id and write-block-id as a parameter
                # dignostic_cluster_params_additional.append('dump-wb:ns=' + ns)

                dignostic_aerospike_cluster_params_additional.append('dump-wb-summary:ns=' + ns)

            if verbose:
                for index, param in enumerate(dignostic_aerospike_cluster_params_additional_verbose):
                    if param.startswith("dump"):
                        if not param.endswith(":"):
                            param = param + ";"
                        param = param + "verbose=true"
                    dignostic_aerospike_cluster_params_additional_verbose[index]=param

            dignostic_aerospike_cluster_params = dignostic_aerospike_cluster_params + dignostic_aerospike_cluster_params_additional + dignostic_aerospike_cluster_params_additional_verbose

        if 'ubuntu' == (platform.linux_distribution()[0]).lower():
            cmd_dmesg  = 'cat /var/log/syslog'
        else:
            cmd_dmesg  = 'cat /var/log/messages'
        
        terminal.enable_color(False)
        os.makedirs(aslogdir)

        ####### Dignostic info ########

        aslogfile = as_logfile_prefix + 'ascollectinfo.log'
        self.write_log(collect_output)

        try:
            self.collectinfo_content(self.write_version)
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            info_controller = InfoController()
            for info_param in dignostic_info_params:
                self.collectinfo_content(info_controller,[info_param])
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            show_controller = ShowController()
            for show_param in dignostic_show_params:
                self.collectinfo_content(show_controller,show_param.split())
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            features_controller = FeaturesController()
            for cmd in dignostic_features_params:
                self.collectinfo_content(features_controller, [cmd])
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            cluster_controller = ClusterController()
            for cmd in dignostic_cluster_params:
                self.collectinfo_content(cluster_controller, [cmd])
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            for cmd in dignostic_aerospike_cluster_params:
                self.collectinfo_content('cluster', cmd)
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__


        ####### System info ########

        aslogfile = as_logfile_prefix + 'sysinfo.log'
        self.write_log(collect_output)

        try:
            for cmds in sys_shell_cmds:
                self.collectinfo_content('shell',[cmds[0]],[cmds[1]])
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            self.collectinfo_content(self.collect_sys)
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            self.collectinfo_content(self.get_awsdata)
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        try:
            self.collectinfo_content(self.collect_lsof)
        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__

        if show_all and verbose:
            try:
                self.collectinfo_content(self.collect_lsof,verbose)
            except Exception as e:
                self.write_log(str(e))
                sys.stdout = sys.__stdout__

        ####### Logs and conf ########

        ##### aerospike logs #####

        try:
            as_version = self.cluster._callNodeMethod([_ip], "info", "build").popitem()[1]
        except Exception:
            from lib.node import Node
            tempNode = Node(_ip)
            as_version = self.cluster._callNodeMethod([tempNode.ip], "info", "build").popitem()[1]

        conf_path = '/etc/aerospike/aerospike.conf'
        #Comparing with this version because prior to this it was citrusleaf.conf
        if LooseVersion(as_version) <= LooseVersion("3.0.0"):
            conf_path = '/etc/citrusleaf/citrusleaf.conf'


        if show_all:
            ##### aerospike xdr logs #####
               #### collectinfo can read the xdr log file from default path for old aerospike version which can not provide xdr log path in asinfo command
               #### for latest xdr-in-asd versions, 'asinfo -v logs' provide all logs including xdr log, so no need to read it separately
            try:
                if True in self.cluster.isXDREnabled().values():
                    is_xdr_in_asd_version = False
                    try:
                        is_xdr_in_asd_version = self.cluster._callNodeMethod([_ip], "isFeaturePresent", "xdr").popitem()[1]
                    except Exception:
                        from lib.node import Node
                        tempNode = Node(_ip)
                        is_xdr_in_asd_version = self.cluster._callNodeMethod([tempNode.ip], "isFeaturePresent", "xdr").popitem()[1]

                    if not is_xdr_in_asd_version:
                        try:
                            o,e = util.shell_command(["grep errorlog-path " + conf_path])
                            if e:
                                xdr_log_location = '/var/log/aerospike/*xdr.log'
                            else:
                                xdr_log_location = o.split()[1]
                        except Exception:
                            xdr_log_location = '/var/log/aerospike/*xdr.log'

                        aslogfile = as_logfile_prefix + 'asxdr.log'
                        self.collectinfo_content('shell',['cat ' + xdr_log_location])
            except Exception as e:
                self.write_log(str(e))
                sys.stdout = sys.__stdout__

            try:
                try:
                    log_locations = [i.split(':')[1] for i in self.cluster._callNodeMethod([_ip], "info", "logs").popitem()[1].split(';')]
                except Exception:
                    from lib.node import Node
                    tempNode = Node(_ip)
                    log_locations = [i.split(':')[1] for i in self.cluster._callNodeMethod([tempNode.ip], "info", "logs").popitem()[1].split(';')]
                file_name_used = {}
                for log in log_locations:
                    if os.path.exists(log):
                        file_name_base = os.path.basename(log)
                        if file_name_base in file_name_used:
                            file_name_used[file_name_base] = file_name_used[file_name_base] + 1
                            file_name, ext = os.path.splitext(file_name_base)
                            file_name_base = file_name + "-" + str(file_name_used[file_name_base]) + ext
                        else:
                            file_name_used[file_name_base] = 1

                        self.collect_local_file(log, as_logfile_prefix + file_name_base)
                    else:  # machine is running with systemd, so need to read logs from systemd journal
                        try:
                            self.collect_logs_from_systemd_journal(as_logfile_prefix)
                        except Exception as e1:
                            self.write_log(str(e1))
                            sys.stdout = sys.__stdout__
            except Exception as e:
                self.write_log(str(e))
                sys.stdout = sys.__stdout__

        ##### aerospike conf file #####
        try:
            # Comparing with this version because prior to this it was citrusleaf.conf & citrusleaf.log
            if LooseVersion(as_version) > LooseVersion("3.0.0"):
                aslogfile = as_logfile_prefix + 'aerospike.conf'
            else:
                aslogfile = as_logfile_prefix + 'citrusleaf.conf'

            self.write_log(collect_output)
            self.collectinfo_content('shell',['cat %s'%(conf_path)])

        except Exception as e: 
            self.write_log(str(e))
            sys.stdout = sys.__stdout__            
                    
        self.archive_log(aslogdir)

    @CommandHelp('Collects system stats on the local node.')
    def _do_default(self, line):
        self.cmds_error = set()
        self.main_collectinfo(False,False)
        if self.cmds_error:
            print "\n\n--------------------------------------------------------------------------------------------------\n"
            print "ERROR ::: Following commands are either unavailable or giving runtime error..."
            print "  " + '\n  '.join(self.cmds_error)
            print "\n--------------------------------------------------------------------------------------------------\n"

    @CommandHelp('collecting all default stats and additional stats like info dump-* commands output'
             , '  Options:'
             , '  verbose     - collecting all default and additional stats with detailed output of info dump-* commands'
             )
    def do_all(self, line):
        verbose = False
        if 'verbose' in line:
            verbose = True
        self.cmds_error = set()
        self.main_collectinfo(True,verbose)
        if self.cmds_error:
            print "\n\n--------------------------------------------------------------------------------------------------\n"
            print "ERROR ::: Following commands are either unavailable or giving runtime error..."
            print "  " + '\n  '.join(self.cmds_error)
            print "\n--------------------------------------------------------------------------------------------------\n"

@CommandHelp('Displays features used in running Aerospike cluster.')
class FeaturesController(CommandController):

    def __init__(self):
        self.modifiers = set(['with', 'like'])

    def check_key_for_gt(self, d={}, keys=(), v=0, is_and=False, type_check=int):
        if not keys:
            return True
        if not d:
            return False
        if not isinstance(keys, tuple):
            keys = (keys,)
        if is_and:
            if all(get_value_from_dict(d,k,v,type_check)>v for k in keys):
                return True
        else:
            if any(get_value_from_dict(d,k,v,type_check)>v for k in keys):
                return True
        return False

    def _do_default(self, line):
        service_stats = self.cluster.infoStatistics(nodes=self.nodes)
        ns_stats = self.cluster.infoAllNamespaceStatistics(nodes=self.nodes)

        features = {}
        for node, stats in service_stats.iteritems():
            features[node] = {}
            features[node]["KVS"] = "NO"
            if self.check_key_for_gt(stats,('stat_read_reqs','stat_write_reqs')):
                features[node]["KVS"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self.check_key_for_gt(nsval,('client_read_error','client_read_success','client_write_error','client_write_success')):
                        features[node]["KVS"] = "YES"
                        break

            features[node]["UDF"] = "NO"
            if self.check_key_for_gt(stats,('udf_read_reqs','udf_write_reqs')):
                features[node]["UDF"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self.check_key_for_gt(nsval,('client_udf_complete','client_udf_error')):
                        features[node]["UDF"] = "YES"
                        break

            features[node]["BATCH"] = "NO"
            if self.check_key_for_gt(stats,('batch_initiate')):
                features[node]["BATCH"] = "YES"

            features[node]["SCAN"] = "NO"
            if self.check_key_for_gt(stats,('tscan_initiate','basic_scans_succeeded','basic_scans_failed','aggr_scans_succeeded'
                                            'aggr_scans_failed','udf_bg_scans_succeeded','udf_bg_scans_failed')):
                features[node]["SCAN"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self.check_key_for_gt(nsval,('scan_basic_complete','scan_basic_error','scan_aggr_complete',
                                                    'scan_aggr_error','scan_udf_bg_complete','scan_udf_bg_error')):
                        features[node]["SCAN"] = "YES"
                        break

            features[node]["SINDEX"] = "NO"
            if self.check_key_for_gt(stats,('sindex-used-bytes-memory')):
                features[node]["SINDEX"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self.check_key_for_gt(nsval,('memory_used_sindex_bytes')):
                        features[node]["SINDEX"] = "YES"
                        break

            features[node]["QUERY"] = "NO"
            if self.check_key_for_gt(stats,('query_reqs','query_success')):
                features[node]["QUERY"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self.check_key_for_gt(nsval,('query_reqs','query_success')):
                        features[node]["QUERY"] = "YES"
                        break

            features[node]["AGGREGATION"] = "NO"
            if self.check_key_for_gt(stats,('query_agg','query_agg_success')):
                features[node]["AGGREGATION"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self.check_key_for_gt(nsval,('query_agg','query_agg_success')):
                        features[node]["AGGREGATION"] = "YES"
                        break

            features[node]["LDT"] = "NO"
            if self.check_key_for_gt(stats,('sub-records','ldt-writes','ldt-reads','ldt-deletes'
                                            ,'ldt_writes','ldt_reads','ldt_deletes','sub_objects')):
                features[node]["LDT"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self.check_key_for_gt(nsval,('ldt-writes','ldt-reads','ldt-deletes','ldt_writes','ldt_reads','ldt_deletes')):
                        features[node]["LDT"] = "YES"
                        break

            features[node]["XDR ENABLED"] = "NO"
            if self.check_key_for_gt(stats,('stat_read_reqs_xdr','xdr_read_success','xdr_read_error')):
                features[node]["XDR ENABLED"] = "YES"

            features[node]["XDR DESTINATION"] = "NO"
            if self.check_key_for_gt(stats,('stat_write_reqs_xdr')):
                features[node]["XDR DESTINATION"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self.check_key_for_gt(nsval,('xdr_write_success')):
                        features[node]["XDR DESTINATION"] = "YES"
                        break


        return util.Future(self.view.showConfig, "Features"
                    , features
                    , self.cluster, **self.mods)

@CommandHelp("Set pager for output")
class PagerController(CommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.executeHelp(line)

    @CommandHelp("Displays output with vertical and horizontal paging for each output table same as linux 'less' command.",
                 "We can use arrow keys to scroll output and 'q' to end page for table.",
                 "All linux less commands can work in this pager option.")
    def do_less(self, line):
        CliView.pager = CliView.LESS

    @CommandHelp("Removes pager and prints output normally.")
    def do_remove(self, line):
        CliView.pager = CliView.NO_PAGER

    @CommandHelp("Displays current selected pager option.")
    def do_show(self, line):
        CliView.print_pager()
