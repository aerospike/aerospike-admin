# Copyright 2013-2014 Aerospike, Inc.
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
from lib.controller import ShellController
from lib.controllerlib import *
from lib import util
import time, os, sys, platform, shutil, urllib2, socket
from lib.loghelper import LogHelper


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

@CommandHelp('Aerospike Admin')
class LogRootController(BaseController):
    def __init__(self, seed_nodes=[('127.0.0.1',3000)]
                 , use_telnet=False, user=None, password=None, log_path=""):
        super(LogRootController, self).__init__(seed_nodes=seed_nodes
                                             , use_telnet=use_telnet
                                             , user=user
                                             , password=password, log_path=log_path)
        self.controller_map = {
            'info':InfoController
            , 'show':ShowController
            , '!':ShellController
            , 'shell':ShellController
            , 'grep':GrepController
            , 'assert':AssertController
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

@CommandHelp('The "info" command provides summary tables for various aspects'
             , 'of Aerospike functionality.')
class InfoController(CommandController):
    def __init__(self):
        self.modifiers = set(['with'])

    @CommandHelp('Displays service, network, namespace, and xdr summary'
                 , 'information.')
    def _do_default(self, line):
        self.do_service(line)
        self.do_network(line)
        self.do_namespace(line)
        self.do_xdr(line)

    @CommandHelp('Displays help.')
    def do_help(self, line):
        self.executeHelp(line)

    @CommandHelp('Displays summary information for the Aerospike service.')
    def do_service(self, line):
        print "info service"

    @CommandHelp('Displays network information for Aerospike, the main'
                 , 'purpose of this information is to link node ids to'
                 , 'fqdn/ip addresses.')
    def do_network(self, line):
        print "info network"

    @CommandHelp('Displays summary information for each namespace.')
    def do_namespace(self, line):
        print "info namespace"

    @CommandHelp('Displays summary information for Cross Datacenter'
                 , 'Replication (XDR).')
    def do_xdr(self, line):
        print ("info xdr")

    @CommandHelp('Displays summary information for Seconday Indexes (SIndex).')
    def do_sindex(self, line):
        print ("info sindex")

    @CommandHelp('Displays summary information for User Defined Functions (UDF).')
    def do_udf(self, line):
        print ("info udf")

    @CommandHelp('Displays summary information for Batch (UDF).')
    def do_batch(self, line):
        print ("info batch")

    @CommandHelp('Displays summary information for Scan (UDF).')
    def do_scan(self, line):
        print ("info scan")


@CommandHelp('"show" is used to display Aerospike Statistics and'
             , 'configuration.')
class ShowController(CommandController):
    def __init__(self):
        self.controller_map = {
            'config':ShowConfigController
            , 'statistics':ShowStatisticsController
            , 'latency':ShowLatencyController
            , 'distribution':ShowDistributionController
        }
        self.modifiers = set()

    def _do_default(self, line):
        self.executeHelp(line)

@CommandHelp('"distribution" is used to show the distribution of object sizes'
             , 'and time to live for node and a namespace.')
class ShowDistributionController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Shows the distributions of Time to Live and Object Size')
    def _do_default(self, line):
        self.do_time_to_live(line[:])
        self.do_object_size(line[:])

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

                data['percentiles'] = [r * width for r in result]

        self.view.showDistribution(title
                                   , histogram
                                   , unit
                                   , histogram_name
                                   , self.cluster
                                   , **self.mods)

    @CommandHelp('Shows the distribution of TTLs for namespaces')
    def do_time_to_live(self, line):
        self._do_distribution('ttl', 'TTL Distribution', 'Seconds')

    @CommandHelp('Shows the distribution of Eviction TTLs for namespaces')
    def do_eviction(self, line):
        self._do_distribution('evict', 'Eviction Distribution', 'Seconds')

    @CommandHelp('Shows the distribution of Object sizes for namespaces')
    def do_object_size(self, line):
        self._do_distribution('objsz', 'Object Size Distribution', 'Record Blocks')

class ShowLatencyController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Displays latency information for Aerospike cluster.')
    def _do_default(self, line):
        self.modifiers.add('like')
        self.modifiers.remove('like')

        latency = self.cluster.infoLatency(nodes=self.nodes)

        hist_latency = {}
        for node_id, hist_data in latency.iteritems():
            if isinstance(hist_data, Exception):
                continue
            for hist_name, data in hist_data.iteritems():
                if hist_name not in hist_latency:
                    hist_latency[hist_name] = {node_id:data}
                else:
                    hist_latency[hist_name][node_id] = data
        print hist_latency
        self.view.showLatency(hist_latency, self.cluster, **self.mods)

@CommandHelp('"show config" is used to display Aerospike configuration settings')
class ShowConfigController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Displays service, network, namespace, and xdr configuration')
    def _do_default(self, line):
        self.do_service(line)
        self.do_network(line)
        self.do_namespace(line)
        self.do_xdr(line)

    @CommandHelp('Displays service configuration')
    def do_service(self, line):
        service_configs = self.logger.infoGetConfig(stanza='service')

        for file in sorted(service_configs.keys()):
            self.view.showConfig("Service Configuration (%s)"%(file)
                         , service_configs[file]
                         , LogHelper(file), **self.mods)

    @CommandHelp('Displays network configuration')
    def do_network(self, line):
        service_configs = self.logger.infoGetConfig(stanza='network')

        for file in sorted(service_configs.keys()):
            self.view.showConfig("Network Configuration (%s)"%(file)
                         , service_configs[file]
                         , LogHelper(file), **self.mods)

    @CommandHelp('Displays namespace configuration')
    def do_namespace(self, line):
        ns_configs = self.logger.infoGetConfig(stanza='namespace')

        for file in sorted(ns_configs.keys()):
            for ns, configs in ns_configs[file].iteritems():
                self.view.showConfig("%s Namespace Configuration (%s)"%(ns, file)
                                 , configs, LogHelper(file), **self.mods)

    @CommandHelp('Displays XDR configuration')
    def do_xdr(self, line):
        print "ToDo"

@CommandHelp('Displays statistics for Aerospike components.')
class ShowStatisticsController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Displays bin, set, service, namespace, and xdr statistics')
    def _do_default(self, line):
        self.do_bins(line)
        self.do_sets(line)
        self.do_service(line)
        self.do_namespace(line)
        self.do_xdr(line)

    @CommandHelp('Displays service statistics')
    def do_service(self, line):
        service_stats = self.logger.infoStatistics(stanza="service")
        for file in sorted(service_stats.keys()):
            self.view.showConfig("Service Statistics (%s)"%(file)
                         , service_stats[file]
                         , LogHelper(file), **self.mods)

    @CommandHelp('Displays namespace statistics')
    def do_namespace(self, line):
        ns_stats = self.logger.infoStatistics(stanza="namespace")
        for file in sorted(ns_stats.keys()):
            for ns, configs in ns_stats[file].iteritems():
                self.view.showStats("%s Namespace Statistics (%s)"%(ns, file)
                                    , configs
                                    , LogHelper(file)
                                    , **self.mods)

    @CommandHelp('Displays set statistics')
    def do_sets(self, line):
        set_stats = self.logger.infoStatistics(stanza="sets")
        for file in sorted(set_stats.keys()):
            for ns_set, configs in set_stats[file].iteritems():
                self.view.showStats("%s Set Statistics (%s)"%(ns_set, file)
                             , configs
                             , LogHelper(file), **self.mods)

    @CommandHelp('Displays bin statistics')
    def do_bins(self, line):
        new_bin_stats = self.logger.infoStatistics(stanza="bins")
        for file in sorted(new_bin_stats.keys()):
            for ns, configs in new_bin_stats[file].iteritems():
                self.view.showStats("%s Bin Statistics (%s)"%(ns, file)
                                    , configs
                                    , LogHelper(file)
                                    , **self.mods)

    @CommandHelp('Displays xdr statistics')
    def do_xdr(self, line):
        print "ToDo"

@CommandHelp('Displays grep results for input string.')
class GrepController(CommandController):
    def __init__(self):
        self.controller_map = {
           'cluster':GrepClusterController
            , 'servers':GrepServersController
        }
        self.modifiers = set()

    def _do_default(self, line):
        self.executeHelp(line)

class GrepFile(CommandController):
    def __init__(self, grep_cluster, modifiers):
        self.grep_cluster = grep_cluster
        self.modifiers = modifiers

    def do_show(self, line):
        if not line:
            raise ShellException("Could not understand grep request, " + \
                                 "see 'help grep'")

        mods = self.parseModifiers(line)
        line = mods['line']

        tline = line[:]
        search_str = ""
        while tline:
            word = tline.pop(0)
            if word == '-s':
                search_str = tline.pop(0)
                search_str = self.stripString(search_str)
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'"%(word
                                                   , " ".join(line)))
        grepRes = {}
        if(search_str):
            grepRes = self.logger.grep(search_str, self.grep_cluster)

        for dir_path in sorted(grepRes.keys()):
            #ToDo : Grep Output
            print "***************** %s ****************"%(dir_path)
            for key in sorted(grepRes[dir_path].keys()):
                print grepRes[dir_path][key]

    def do_count(self, line):
        if not line:
            raise ShellException("Could not understand grep request, " + \
                                 "see 'help grep'")

        mods = self.parseModifiers(line)
        line = mods['line']

        tline = line[:]
        search_str = ""
        while tline:
            word = tline.pop(0)
            if word == '-s':
                search_str = tline.pop(0)
                search_str = self.stripString(search_str)
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'"%(word
                                                   , " ".join(line)))
        grepRes = {}
        if(search_str):
            grepRes = self.logger.grepCount(search_str, self.grep_cluster)

        for file in grepRes.keys():
            #ToDo : Grep Count Output
            print grepRes[file]

    def do_diff(self,line):
        if not line:
            raise ShellException("Could not understand grep request, " + \
                                 "see 'help grep'")

        mods = self.parseModifiers(line)
        line = mods['line']

        tline = line[:]
        search_str = ""
        start_tm = "head"
        duration = ""
        slice_tm = "10"
        show_count = 1
        while tline:
            word = tline.pop(0)
            if word == '-s':
                search_str = tline.pop(0)
                search_str = self.stripString(search_str)
            elif word == '-f':
                start_tm = tline.pop(0)
                start_tm = self.stripString(start_tm)
            elif word == '-d':
                duration = tline.pop(0)
                duration = self.stripString(duration)
            elif word == '-t':
                slice_tm = tline.pop(0)
                slice_tm = self.stripString(slice_tm)
            elif word == '-n':
                show_count = tline.pop(0)
                show_count = int(self.stripString(show_count))
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'"%(word
                                                   , " ".join(line)))
        grepRes = {}

        if(search_str):
            grepRes = self.logger.grepDiff(search_str, self.grep_cluster, start_tm, duration, slice_tm, show_count)

        for dir_path in sorted(grepRes.keys()):
            #ToDo : Grep Latency Output
            self.view.showGrepDiff(dir_path, grepRes[dir_path])

    def stripString(self, search_str):
        search_str = search_str.strip()
        if(search_str[0]=="\"" or search_str[0]=="\'"):
            return search_str[1:len(search_str)-1]
        else:
            return search_str

@CommandHelp('"grep" search in server logs(ascollectinfo.log)')
class GrepClusterController(CommandController):
    def __init__(self):
        self.modifiers = set()
        self.grepFile = GrepFile(True, self.modifiers)

    @CommandHelp('Display all lines with input string in server logs(ascollectinfo.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files')
    def _do_default(self, line):
        self.grepFile.do_show(line)

    @CommandHelp('Display all lines with input string in server logs(ascollectinfo.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files')
    def do_show(self, line):
        self.grepFile.do_show(line)

    @CommandHelp('Display count of lines with input string in server logs(ascollectinfo.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files')
    def do_count(self, line):
        self.grepFile.do_count(line)

    @CommandHelp('Display values and diff for input string in server logs(ascollectinfo.log).'
             , 'Currently it is working for format KEY<space>VALUE and KEY<space>(Comma separated VALUE list).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files'
             , '    -t <string>  - Analysis slice interval in seconds or time format.'
             , '    -f <string>  - Log time from which to analyze.'
               ' May use the following formats:  \'Sep 22 2011 22:40:14\', -3600, or \'-1:00:00\''
             , '    -d <string>  - Maximum time period to analyze.'
               ' May use the following formats: 3600 or 1:00:00'
             , '    -n <string>  - Show the 0-th and then every n-th bucket'
                  )
    def do_diff(self, line):
        self.grepFile.do_diff(line)

@CommandHelp('"grep" search in server logs(aerospike.log)')
class GrepServersController(CommandController):
    def __init__(self):
        self.modifiers = set()
        self.grepFile = GrepFile(False, self.modifiers)

    @CommandHelp('Display all lines with input string in server logs(aerospike.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files')
    def _do_default(self, line):
        self.grepFile.do_show(line)

    @CommandHelp('Display all lines with input string in server logs(aerospike.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files')
    def do_show(self, line):
        self.grepFile.do_show(line)

    @CommandHelp('Display count of lines with input string in server logs(aerospike.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files')
    def do_count(self, line):
        self.grepFile.do_count(line)

    @CommandHelp('Display values and diff for input string in server logs(aerospike.log).'
             , 'Currently it is working for format KEY<space>VALUE and KEY<space>(Comma separated VALUE list).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files'
             , '    -t <string>  - Analysis slice interval in seconds or time format.'
             , '    -f <string>  - Log time from which to analyze.'
               ' May use the following formats:  \'Sep 22 2011 22:40:14\', -3600, or \'-1:00:00\''
             , '    -d <string>  - Maximum time period to analyze.'
               ' May use the following formats: 3600 or 1:00:00'
             , '    -n <string>  - Show the 0-th and then every n-th bucket'
                  )
    def do_diff(self, line):
        self.grepFile.do_diff(line)


@CommandHelp('Checks for common inconsistencies and print if there is any')
class AssertController(CommandController):
    def __init__(self):
        self.controller_map = {
           'cluster':AssertClusterController
            , 'servers':AssertServersController
        }
        self.modifiers = set()

    def _do_default(self, line):
        self.executeHelp(line)

class AssertClusterController(CommandController):
    def __init__(self):
        self.modifiers = set()
        self.grepFile = GrepFile(True, self.modifiers)

    @CommandHelp('Displays All Cluster Level Assetions !!')
    def _do_default(self, line):
        print "Todo"

@CommandHelp('"grep" searches for lines with input string in logs.'
             , '  Options:'
             , '    -s <string>  - The String to search in log files')
class AssertServersController(CommandController):
    def __init__(self):
        self.modifiers = set()
        self.grepFile = GrepFile(False, self.modifiers)

    @CommandHelp('Displays all possible results from logs')
    def _do_default(self, line):
        print "Todo"
