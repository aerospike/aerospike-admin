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

def stripString(search_str):
        search_str = search_str.strip()
        if(search_str[0]=="\"" or search_str[0]=="\'"):
            return search_str[1:len(search_str)-1]
        else:
            return search_str

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
            , 'grepstr':GrepStrController
            , 'assert':AssertController
            , 'list':ListController
            , 'select':SelectController
            , 'add':AddController
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

        for timestamp in sorted(service_configs.keys()):
            self.view.showConfig("Service Configuration (%s)"%(timestamp)
                         , service_configs[timestamp]
                         , LogHelper(self.logger.log_reader.selected_cluster_files[timestamp]), **self.mods)

    @CommandHelp('Displays network configuration')
    def do_network(self, line):
        service_configs = self.logger.infoGetConfig(stanza='network')

        for timestamp in sorted(service_configs.keys()):
            self.view.showConfig("Network Configuration (%s)"%(timestamp)
                         , service_configs[timestamp]
                         , LogHelper(self.logger.log_reader.selected_cluster_files[timestamp]), **self.mods)

    @CommandHelp('Displays namespace configuration')
    def do_namespace(self, line):
        ns_configs = self.logger.infoGetConfig(stanza='namespace')

        for timestamp in sorted(ns_configs.keys()):
            for ns, configs in ns_configs[timestamp].iteritems():
                self.view.showConfig("%s Namespace Configuration (%s)"%(ns, timestamp)
                                 , configs, LogHelper(self.logger.log_reader.selected_cluster_files[timestamp]), **self.mods)

    @CommandHelp('Displays XDR configuration')
    def do_xdr(self, line):
        print "config XDR :: ToDo"

@CommandHelp('"distribution" is used to show the distribution of object sizes'
             , 'and time to live for node and a namespace.')
class ShowDistributionController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Displays ttl, object, and eviction distribution')
    def _do_default(self, line):
        self.do_ttl(line)
        self.do_object(line)
        self.do_evict(line)

    def _do_distribution(self, histogram_name, title, unit):
        histogram = self.logger.infoGetHistogram(histogram_name)
        for timestamp in sorted(histogram.keys()):
            print "************************** %s for %s **************************"%(title, timestamp)
            self.view.showDistribution( title
                           , histogram[timestamp]
                           , unit
                           , histogram_name
                           , LogHelper(self.logger.log_reader.selected_cluster_files[timestamp])
                           , **self.mods)

    @CommandHelp('Shows the distribution of TTLs for namespaces')
    def do_ttl(self, line):
        return self._do_distribution('ttl', 'TTL Distribution', 'Seconds')

    @CommandHelp('Shows the distribution of Object sizes for namespaces')
    def do_object_size(self, line):
        return self._do_distribution('objsz', 'Object Size Distribution', 'Record Blocks')

    @CommandHelp('Shows the distribution of Eviction TTLs for namespaces')
    def do_eviction(self, line):
        return self._do_distribution('evict', 'Eviction Distribution', 'Seconds')

class ShowLatencyController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Displays latency information for Aerospike cluster log.')
    def _do_default(self, line):
        self.modifiers.add('like')
        self.modifiers.remove('like')

        hist_latency = self.logger.infoGetLatency()
        for timestamp in sorted(hist_latency.keys()):
            #print hist_latency[timestamp]
            print "************************** Latency for %s **************************"%(timestamp)
            self.view.showLatency(hist_latency[timestamp], LogHelper(self.logger.log_reader.selected_cluster_files[timestamp]), **self.mods)

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
        for timestamp in sorted(service_stats.keys()):
            self.view.showConfig("Service Statistics (%s)"%(timestamp)
                         , service_stats[timestamp]
                         , LogHelper(self.logger.log_reader.selected_cluster_files[timestamp]), **self.mods)

    @CommandHelp('Displays namespace statistics')
    def do_namespace(self, line):
        ns_stats = self.logger.infoStatistics(stanza="namespace")
        for timestamp in sorted(ns_stats.keys()):
            for ns, configs in ns_stats[timestamp].iteritems():
                self.view.showStats("%s Namespace Statistics (%s)"%(ns, timestamp)
                                    , configs
                                    , LogHelper(self.logger.log_reader.selected_cluster_files[timestamp])
                                    , **self.mods)

    @CommandHelp('Displays set statistics')
    def do_sets(self, line):
        set_stats = self.logger.infoStatistics(stanza="sets")
        for timestamp in sorted(set_stats.keys()):
            for ns_set, configs in set_stats[timestamp].iteritems():
                self.view.showStats("%s Set Statistics (%s)"%(ns_set, timestamp)
                             , configs
                             , LogHelper(self.logger.log_reader.selected_cluster_files[timestamp]), **self.mods)

    @CommandHelp('Displays bin statistics')
    def do_bins(self, line):
        new_bin_stats = self.logger.infoStatistics(stanza="bins")
        for timestamp in sorted(new_bin_stats.keys()):
            for ns, configs in new_bin_stats[timestamp].iteritems():
                self.view.showStats("%s Bin Statistics (%s)"%(ns, timestamp)
                                    , configs
                                    , LogHelper(self.logger.log_reader.selected_cluster_files[timestamp])
                                    , **self.mods)

    @CommandHelp('Displays xdr statistics')
    def do_xdr(self, line):
        print "statistics XDR :: ToDo"

@CommandHelp('Displays grep results for input string.')
class GrepStrController(CommandController):
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
        start_tm = "head"
        duration = ""
        sources = []
        while tline:
            word = tline.pop(0)
            if word == '-s':
                search_str = tline.pop(0)
                search_str = self.stripString(search_str)
            elif word == '-f' and not self.grep_cluster:
                start_tm = tline.pop(0)
                start_tm = self.stripString(start_tm)
            elif word == '-d' and not self.grep_cluster:
                duration = tline.pop(0)
                duration = self.stripString(duration)
            elif word == '-n':
                try:
                    sources = [int(i) for i in self.stripString(tline.pop(0)).split(",")]
                except:
                    sources = []
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'"%(word
                                                   , " ".join(line)))
        if(search_str):
            files = self.logger.log_reader.getFilesFromCurrentList(self.grep_cluster, sources)
            for timestamp in sorted(files.keys()):
                print "***************** %s ****************"%(timestamp)
                grepRes = self.logger.grep(files[timestamp], search_str, self.grep_cluster, start_tm, duration)
                for key in sorted(grepRes.keys()):
                    print grepRes[key]

    def do_count(self, line):
        if not line:
            raise ShellException("Could not understand grep request, " + \
                                 "see 'help grep'")

        mods = self.parseModifiers(line)
        line = mods['line']

        tline = line[:]
        search_str = ""
        sources = []
        while tline:
            word = tline.pop(0)
            if word == '-s':
                search_str = tline.pop(0)
                search_str = self.stripString(search_str)
            elif word == '-n':
                try:
                    sources = [int(i) for i in self.stripString(tline.pop(0)).split(",")]
                except:
                    sources = []
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'"%(word
                                                   , " ".join(line)))
        if(search_str):
            files = self.logger.log_reader.getFilesFromCurrentList(self.grep_cluster, sources)
            for timestamp in sorted(files.keys()):
                print "***************** %s ****************"%(timestamp)
                res = self.logger.grepCount(files[timestamp], search_str, self.grep_cluster)
                for key in sorted(res.keys()):
                    str =" "
                    if not self.grep_cluster:
                        str = key + " : "
                    print str+ "Count of %s is : %s"%(search_str, res[key])

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
        limit = ""
        sources = []
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
            elif word == '-k':
                show_count = tline.pop(0)
                show_count = int(self.stripString(show_count))
            elif word == '-l':
                limit = tline.pop(0)
                limit = int(self.stripString(limit))
            elif word == '-n':
                try:
                    sources = [int(i) for i in self.stripString(tline.pop(0)).split(",")]
                except:
                    sources = []
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'"%(word
                                                   , " ".join(line)))
        grepRes = {}

        if(search_str):
            files = self.logger.log_reader.getFilesFromCurrentList(self.grep_cluster, sources)
            for timestamp in sorted(files.keys()):
                grep_res = self.logger.grepDiff(files[timestamp], search_str, self.grep_cluster, start_tm, duration, slice_tm, show_count, limit)
                self.view.showGrepDiff(timestamp, grep_res)

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
             , '    -s <string>  - The String to search in log files'
             , '    -n <string>  - Comma separated cluster snapshot numbers. You can get this numbers by list command. Format : -n \'1,2,5\'')
    def _do_default(self, line):
        self.grepFile.do_show(line)

    @CommandHelp('Display all lines with input string in server logs(ascollectinfo.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files'
             , '    -n <string>  - Comma separated cluster snapshot numbers. You can get this numbers by list command. Format : -n \'1,2,5\'')
    def do_show(self, line):
        self.grepFile.do_show(line)

    @CommandHelp('Display count of lines with input string in server logs(ascollectinfo.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files'
             , '    -n <string>  - Comma separated cluster snapshot numbers. You can get this numbers by list command. Format : -n \'1,2,5\'')
    def do_count(self, line):
        self.grepFile.do_count(line)
'''
    @CommandHelp('Display values and diff for input string in server logs(ascollectinfo.log).'
             , 'Currently it is working for format KEY<space>VALUE and KEY<space>(Comma separated VALUE list).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files'
             , '    -t <string>  - Analysis slice interval in seconds or time format.'
             , '    -f <string>  - Log time from which to analyze.'
               ' May use the following formats:  \'Sep 22 2011 22:40:14\', -3600, or \'-1:00:00\''
             , '    -d <string>  - Maximum time period to analyze.'
               ' May use the following formats: 3600 or 1:00:00'
             , '    -k <string>  - Show the 0-th and then every k-th bucket'
                  )
    def do_diff(self, line):
        self.grepFile.do_diff(line)
'''
@CommandHelp('"grep" search in server logs(aerospike.log)')
class GrepServersController(CommandController):
    def __init__(self):
        self.modifiers = set()
        self.grepFile = GrepFile(False, self.modifiers)

    @CommandHelp('Display all lines with input string in server logs(aerospike.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files'
             , '    -n <string>  - Comma separated node numbers. You can get this numbers by list command. Format : -n \'1,2,5\'')
    def _do_default(self, line):
        self.grepFile.do_show(line)

    @CommandHelp('Display all lines with input string in server logs(aerospike.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files'
             , '    -f <string>  - Log time from which to analyze.'
               ' May use the following formats:  \'Sep 22 2011 22:40:14\', -3600, or \'-1:00:00\''
             , '    -d <string>  - Maximum time period to analyze.'
               ' May use the following formats: 3600 or 1:00:00'
             , '    -n <string>  - Comma separated node numbers. You can get this numbers by list command. Format : -n \'1,2,5\'')
    def do_show(self, line):
        self.grepFile.do_show(line)

    @CommandHelp('Display count of lines with input string in server logs(aerospike.log).'
             , '  Options:'
             , '    -s <string>  - The String to search in log files'
             , '    -n <string>  - Comma separated node numbers. You can get this numbers by list command. Format : -n \'1,2,5\'')
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
             , '    -k <string>  - Show the 0-th and then every k-th bucket'
             , '    -l <string>  - Show results with at least one diff value greater than or equal to limit'
             , '    -n <string>  - Comma separated node numbers. You can get this numbers by list command. Format : -n \'1,2,5\'')
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

@CommandHelp('Display list of snapshots')
class ListController(CommandController):
    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_default(self, line):
        self.do_all(line)

    @CommandHelp('Displays list of all available snapshots from which tool can read data')
    def do_all(self, line):
        print "*************************** CLUSTER ***************************"
        index = 1
        for timestamp in sorted(self.logger.log_reader.all_cluster_files.keys()):
            print str(index) + "  : " + timestamp + "\t" + self.logger.log_reader.all_cluster_files[timestamp]
            index += 1
        print "*************************** SERVER ***************************"
        index = 1
        for node in sorted(self.logger.log_reader.added_server_files.keys()):
            print str(index) + "  : " + node + "\t" + self.logger.log_reader.added_server_files[node]
            index += 1

    @CommandHelp('Displays list of snapshots from which tool is reading data')
    def do_selected(self, line):
        print "*************************** CLUSTER ***************************"
        index = 1
        for timestamp in sorted(self.logger.log_reader.selected_cluster_files.keys()):
            print str(index) + "  : " + timestamp + "\t" + self.logger.log_reader.selected_cluster_files[timestamp]
            index += 1
        print "*************************** SERVER ***************************"
        index = 1
        for node in sorted(self.logger.log_reader.selected_server_files.keys()):
            print str(index) + "  : " + node + "\t" + self.logger.log_reader.selected_server_files[node]
            index += 1

@CommandHelp('Select list of snapshots')
class SelectController(CommandController):
    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    @CommandHelp('Select list of snapshots.'
             , '  Options:'
             , '    -y - Expected year of snapshot. May use the following formats: \'2015\', \'2011-2015\' or \'2011,2013,2015\''
             , '    -m - Expected month of snapshot. May use the following formats: \'10\', \'5-10\' or \'1,6,12\''
             , '    -d - Expected date of snapshot. May use the following formats: \'27\', \'20-25\' or \'11,13,29\''
             , '    -hh - Expected hour value of snapshot. May use the following formats: \'15\', \'1-8\' or \'11,22\''
             , '    -mm - Expected minute value of snapshot. May use the following formats: \'55\', \'30-55\' or \'1,4,45\''
             , '    -ss - Expected second value of snapshot. May use the following formats: \'43\', \'3-23\' or \'6,8,58\''
             )
    def do_cluster(self, line):
        tline = line[:]
        year = ""
        month = ""
        date = ""
        hr = ""
        minutes = ""
        sec = ""

        while tline:
            word = tline.pop(0)
            if word == '-y':
                year = tline.pop(0)
                year = self.stripString(year)
            elif word == '-m':
                month = tline.pop(0)
                month = self.stripString(month)
            elif word == '-d':
                date = tline.pop(0)
                date = self.stripString(date)
            elif word == '-hh':
                hr = tline.pop(0)
                hr = self.stripString(hr)
            elif word == '-mm':
                minutes = tline.pop(0)
                minutes = self.stripString(minutes)
            elif word == '-ss':
                sec = tline.pop(0)
                sec = self.stripString(sec)
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'"%(word
                                                   , " ".join(line)))
        self.logger.log_reader.select_cluster_snapshots(year, month, date, hr, minutes, sec)

    @CommandHelp('Select list of servers. You can get server number from list command. May use the following formats: select server 1 2 3')
    def do_server(self, line):
        self.logger.log_reader.select_servers(line)

    def stripString(self, search_str):
        search_str = search_str.strip()
        if(search_str[0]=="\"" or search_str[0]=="\'"):
            return search_str[1:len(search_str)-1]
        else:
            return search_str

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

@CommandHelp('Allow users to add cluster and server logs. After adding new log file by using this command also update the selected file list with new input')
class AddController(CommandController):
    def __init__(self):
        self.controller_map = {
           'cluster':AddClusterController
            , 'server':AddServerController
        }
        self.modifiers = set()

    def _do_default(self, line):
        self.executeHelp(line)

@CommandHelp("Adds cluster logs. Format : add cluster /'cluster log path1/' /'cluster log path2/' /'cluster log path3/' ...")
class AddClusterController(CommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        for ip in line:
            ip = stripString(ip)
            timestamp = self.logger.log_reader.get_timestamp(ip)
            if "===ASCOLLECTINFO===" == timestamp:
                print ">>>> Cannot add collectinfo file from asmonitor. Use the one from asadm <<<< \n"
            else:
                self.logger.log_reader.added_cluster_files[timestamp] = ip
                self.logger.log_reader.selected_cluster_files[timestamp] = ip
                self.logger.log_reader.all_cluster_files[timestamp] = ip

@CommandHelp("Adds server logs. Format : add server /'server_name1/' /'server log path1/' /'server_name2/' /'server log path2/'/'server_name3/' /'server log path3/' ...")
class AddServerController(CommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        length = len(line)
        if length<2:
            return

        for index in range(0,length,2):
            if(index==length-1):
                break
            self.logger.log_reader.added_server_files[line[index]] = line[index+1]
            self.logger.log_reader.selected_server_files[line[index]] = line[index+1]
