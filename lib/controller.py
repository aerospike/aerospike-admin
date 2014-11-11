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

from lib.controllerlib import *

@CommandHelp('Aerospike Admin')
class RootController(BaseController):
    def __init__(self, seed_nodes=[('127.0.0.1',3000)]
                 , use_telnet=False, user=None, password=None):
        super(RootController, self).__init__(seed_nodes=seed_nodes
                                             , use_telnet=use_telnet
                                             , user=user
                                             , password=password)

        self.controller_map = {
            'info':InfoController
            , 'show':ShowController
            , 'asinfo':ASInfoController
            , 'clinfo':ASInfoController
            , 'cluster':ClusterController
        }

    @CommandHelp('Terminate session')
    def do_exit(self, line):
        # This function is a hack for autocomplete
        raise Exception("Should not be possible to call")

    @CommandHelp('Returns documentation related to a command'
                 , 'for example, to retrieve documentation for the "info"'
                 , 'command use "help info".')
    def do_help(self, line):
        self.executeHelp(line)

    @CommandHelp('"watch" Runs a command for a specified pause and iterations.'
                 , 'Usage: watch [pause] [iterations] [command]'
                 , '   pause:      the duration between executions.'
                 , '               [default: 2 seconds]'
                 , '   iterations: Number of iterations to execute command.'
                 , '               [default: until keyboard interrupt]'
                 , 'Example 1: Show "info network" 3 times with 1 second pause'
                 , '           watch 1 3 info network'
                 , 'Example 2: Show "info namespace" with 5 second pause until'
                 , '           interrupted'
                 , '           watch 5 info namespace')
    def do_watch(self, line):
        self.view.watch(self, line)

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

    @CommandHelp('Displays summary information for the Aerospike service.')
    def do_service(self, line):
        stats = self.cluster.infoStatistics(nodes=self.nodes)
        builds = self.cluster.info('build', nodes=self.nodes)
        services = self.cluster.infoServices(nodes=self.nodes)
        visible = self.cluster.getVisibility()

        visibility = {}
        for node_id, service_list in services.iteritems():
            if isinstance(service_list, Exception):
                continue

            service_set = set(service_list)
            if len((visible | service_set) - service_set) != 1:
                visibility[node_id] = False
            else:
                visibility[node_id] = True

        self.view.infoService(stats, builds, visibility, self.cluster, **self.mods)

    @CommandHelp('Displays network information for Aerospike, the main'
                 , 'purpose of this information is to link node ids to'
                 , 'fqdn/ip addresses.')
    def do_network(self, line):
        stats = self.cluster.infoStatistics(nodes=self.nodes)
        hosts = self.cluster.nodes

        # get current time from namespace
        ns_stats = self.cluster.infoAllNamespaceStatistics(nodes=self.nodes)

        for host, configs in ns_stats.iteritems():
            if isinstance(configs, Exception):
                continue
            ns = configs.keys()[0]

            if ns:
                # lets just add it to stats
                if not isinstance(configs[ns], Exception) and \
                   not isinstance(stats[host], Exception):
                    stats[host]['current-time'] = configs[ns]['current-time']

        self.view.infoNetwork(stats, hosts, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for each namespace.')
    def do_namespace(self, line):
        stats = self.cluster.infoAllNamespaceStatistics(nodes=self.nodes)
        self.view.infoNamespace(stats, self.cluster, **self.mods)

    @CommandHelp('Displays summary information for Cross Datacenter'
                 , 'Replication (XDR).')
    def do_xdr(self, line):
        stats = self.cluster.infoXDRStatistics(nodes=self.nodes)
        builds = self.cluster.xdrInfo('build', nodes=self.nodes)
        xdr_enable = self.cluster.isXDREnabled(nodes=self.nodes)
        self.view.infoXDR(stats, builds, xdr_enable, self.cluster, **self.mods)

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

        value = value.translate(None, "'\"")
        if xdr:
            results = self.cluster.xdrInfo(value, nodes=nodes)
        else:
            results = self.cluster.info(value, nodes=nodes)

        self.view.asinfo(results, line_sep, self.cluster, **mods)

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

@CommandHelp('"distribution" is used ot show the ditribution of object sizes'
             , 'and time to live for node and a namespace.')
class ShowDistributionController(CommandController):
    def __init__(self):
        self.modifiers = set(['with', 'like'])

    @CommandHelp('Shows the distributions of Time to Live and Object Size')
    def _do_default(self, line):
        self.do_time_to_live(line[:])
        self.do_object_size(line[:])

    def flip_keys(self, orig_data):
        new_data = {}
        for key1, data1 in orig_data.iteritems():
            if isinstance(data1, Exception):
                continue
            for key2, data2 in data1.iteritems():
                if key2 not in new_data:
                    new_data[key2] = {}
                new_data[key2][key1] = data2

        return new_data

    def _do_distribution(self, histogram_name, title, unit):
        histogram = self.cluster.infoHistogram(histogram_name, nodes=self.nodes)

        histogram = self.flip_keys(histogram)

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
        service_configs = self.cluster.infoGetConfig(nodes=self.nodes
                                                     , stanza='service')
        for node in service_configs:
            if isinstance(service_configs[node], Exception):
                service_configs[node] = {}
            else:
                service_configs[node] = service_configs[node]['service']

        self.view.showConfig("Service Configuration"
                             , service_configs
                             , self.cluster, **self.mods)

    @CommandHelp('Displays network configuration')
    def do_network(self, line):
        hb_configs = self.cluster.infoGetConfig(nodes=self.nodes
                                                , stanza='network.heartbeat')
        info_configs  = self.cluster.infoGetConfig(nodes=self.nodes
                                                   , stanza='network.info')

        network_configs = {}
        for node in hb_configs:
            if isinstance(hb_configs[node], Exception):
                network_configs[node] = {}
            else:
                network_configs[node] = hb_configs[node]['network.heartbeat']

        for node in info_configs:
            if isinstance(info_configs[node], Exception):
                continue
            else:
                network_configs[node].update(info_configs[node]['network.info'])

        self.view.showConfig("Network Configuration", network_configs
                             , self.cluster, **self.mods)

    @CommandHelp('Displays namespace configuration')
    def do_namespace(self, line):
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

        for ns, configs in ns_configs.iteritems():
            self.view.showConfig("%s Namespace Configuration"%(ns)
                                 , configs, self.cluster, **self.mods)

    @CommandHelp('Displays XDR configuration')
    def do_xdr(self, line):
        xdr_configs = self.cluster.infoXDRGetConfig(nodes=self.nodes)

        xdr_filtered = {}
        for node, config in xdr_configs.iteritems():
            if isinstance(config, Exception):
                continue

            xdr_filtered[node] = config['xdr']

        self.view.showConfig("XDR Configuration", xdr_filtered, self.cluster
                             , **self.mods)

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
        service_stats = self.cluster.infoStatistics(nodes=self.nodes)

        self.view.showStats("Service Statistics", service_stats, self.cluster
                            , **self.mods)
        
    @CommandHelp('Displays namespace statistics')
    def do_namespace(self, line):
        namespaces = self.cluster.infoNamespaces(nodes=self.nodes)

        namespaces = namespaces.values()
        namespace_set = set()
        for namespace in namespaces:
            if isinstance(namespace, Exception):
                continue
            namespace_set.update(namespace)

        for namespace in sorted(namespace_set):
            ns_stats = self.cluster.infoNamespaceStatistics(namespace
                                                            , nodes=self.nodes)
            self.view.showStats("%s Namespace Statistics"%(namespace)
                                , ns_stats
                                , self.cluster
                                , **self.mods)

    @CommandHelp('Displays set statistics')
    def do_sets(self, line):
        sets = self.cluster.infoSetStatistics(nodes=self.nodes)

        set_stats = {}
        for host_id, key_values in sets.iteritems():
            if isinstance(key_values, Exception):
                continue
            for key, values in key_values.iteritems():
                if key not in set_stats:
                    set_stats[key] = {}
                host_vals = set_stats[key]

                if host_id not in host_vals:
                    host_vals[host_id] = {}
                hv = host_vals[host_id]
                hv.update(values)

        for (namespace, set_name), stats in set_stats.iteritems():
            self.view.showStats("%s %s Set Statistics"%(namespace, set_name)
                                , stats
                                , self.cluster
                                , **self.mods)

    @CommandHelp('Displays bin statistics')
    def do_bins(self, line):
        bin_stats = self.cluster.infoBinStatistics(nodes=self.nodes)
        new_bin_stats = {}
        
        for node_id, bin_stat in bin_stats.iteritems():
            if isinstance(bin_stat, Exception):
                continue
            for namespace, stats in bin_stat.iteritems():
                if namespace not in new_bin_stats:
                    new_bin_stats[namespace] = {}
                ns_stats = new_bin_stats[namespace]

                if node_id not in ns_stats:
                    ns_stats[node_id] = {}
                node_stats = ns_stats[node_id]

                node_stats.update(stats)

        for namespace, bin_stats in new_bin_stats.iteritems():
            self.view.showStats("%s Bin Statistics"%(namespace)
                                , bin_stats
                                , self.cluster
                                , **self.mods)

    @CommandHelp('Displays xdr statistics')
    def do_xdr(self, line):
        xdr_stats = self.cluster.infoXDRStatistics(nodes=self.nodes)

        self.view.showStats("XDR Statistics"
                            , xdr_stats
                            , self.cluster
                            , **self.mods)

class ClusterController(CommandController):
    def __init__(self):
        self.modifiers = set(['with'])
        #self.default_nodes = [None]

    def _do_default(self, line):
        self.executeHelp(line)

    def do_dun(self, line):
        results = self.cluster.infoDun(self.mods['line'], nodes=self.nodes)
        self.view.dun(results, self.cluster, **self.mods)

    def do_undun(self, line):
        results = self.cluster.infoUndun(self.mods['line'], nodes=self.nodes)
        self.view.dun(results, self.cluster, **self.mods)
