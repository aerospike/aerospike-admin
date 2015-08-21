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

from lib.controllerlib import *
from lib import util
import time, os, sys, platform, shutil, urllib2, socket
from distutils.version import StrictVersion
import zipfile

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
            , '!':ShellController
            , 'shell':ShellController
            , 'collectinfo':CollectinfoController
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

    @CommandHelp('Displays summary information for Seconday Indexes (SIndex).')
    def do_sindex(self, line):
        stats = self.cluster.infoSIndex(nodes=self.nodes)
        sindexes = {}

        for host, stat_list in stats.iteritems():
            for stat in stat_list:
                if not stat:
                    continue
                indexname = stat['indexname']

                if indexname not in sindexes:
                    sindexes[indexname] = {}
                sindexes[indexname][host] = stat

        self.view.infoSIndex(stats, self.cluster, **self.mods)


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

    def _do_default(self, line):
        self.executeHelp(line)

    def do_dun(self, line):
        results = self.cluster.infoDun(self.mods['line'], nodes=self.nodes)
        self.view.dun(results, self.cluster, **self.mods)

    def do_undun(self, line):
        results = self.cluster.infoUndun(self.mods['line'], nodes=self.nodes)
        self.view.dun(results, self.cluster, **self.mods)

@CommandHelp('"collectinfo" is used to collect system stats on the local node.')
class CollectinfoController(CommandController):
    def collect_local_file(self,src,dest_dir):
        try:
            shutil.copy2(src, dest_dir)
        except Exception,e:
            print e
            pass
        return

    def collectinfo_content(self, func, parm=''):
        name = ''
        capture_stdout = util.capture_stdout
        sep = "\n=======ASCOLLECTINFO(" + output_time + ")======\n"
        try:
            name = func.func_name
        except Exception:
            pass
        info_line = "[INFO] Data collection for " + name +str(parm) + " in progress.."
        print info_line
        sep += info_line+"\n"

        if func == 'shell':
            o,e = util.shell_command(parm)
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
#                 r = requests.get(meta_url,timeout=aws_timeout)
                if r.code != 404:
                    aws_c += rsp +'\n'+r.read() +"\n"
        return aws_c

    def get_awsdata(self,line):
        aws_rsp = ''
        aws_timeout = 1
        socket.setdefaulttimeout(aws_timeout)
        aws_metadata_base_url = 'http://169.254.169.254/latest/meta-data'
        try:
            req = urllib2.Request(aws_metadata_base_url)
            r = urllib2.urlopen(req)
#             r = requests.get(aws_metadata_base_url,timeout=aws_timeout)
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
            
    def collect_sys(self,line):
        lsof_cmd='sudo lsof|grep `sudo ps aux|grep -v grep|grep -E \'asd|cld\'|awk \'{print $2}\'` 2>/dev/null'
        print util.shell_command([lsof_cmd])
        print platform.platform()
        smd_home = '/opt/aerospike/smd'
        if os.path.isdir(smd_home):
            smd_files = [ f for f in os.listdir(smd_home) if os.path.isfile(os.path.join(smd_home, f)) ]
            for f in smd_files:
                smd_f = os.path.join(smd_home, f)
                print smd_f
                smd_fp = open(smd_f, 'r')
                print smd_fp.read()
                smd_fp.close()

    def zip_files(self, dir_path, _size = 5):
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

    def main_collectinfo(self, line):
        global aslogdir, aslogfile, output_time
        output_time = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        aslogdir = '/tmp/collectInfo_' + output_time
        as_sysinfo_logdir = os.path.join(aslogdir, 'sysInformation')
        as_logfile_prefix = aslogdir + '/' + output_time + '_'
                
        info_params = ['network','service', 'namespace', 'xdr', 'sindex']
        show_params = ['config', 'distribution', 'latency', 'statistics']
        cluster_params = ['service',
                          'services',
                          'xdr-min-lastshipinfo:',
                          'dump-fabric:',
                          'dump-hb:',
                          'dump-migrates:',
                          'dump-msgs:',
                          'dump-paxos:',
                          'dump-smd:',
                          'dump-wb:',
                          'dump-wb-summary:',
                          'dump-wr:',
                          'sindex-dump:'
                          ]
        shell_cmds = ['date',
                      'hostname',
                      'ip addr',
                      'uptime',
                      'uname -a',
                      'lsb_release -a',
                      'ls /etc|grep release|xargs -I f cat /etc/f',
                      'rpm -qa|grep -E "citrus|aero"',
                      'dpkg -l|grep -E "citrus|aero"',
                      'free -m',
                      'df -h',
                      'ls /sys/block/{sd*,xvd*}/queue/rotational |xargs -I f sh -c "echo f; cat f;"',
                      'ls /sys/block/{sd*,xvd*}/device/model |xargs -I f sh -c "echo f; cat f;"',
                      'vmstat -s',
                      'vmstat -m',
                      'iptables -L',
                      ]
        cpu_stat = ['top -n3 -b', 'iostat -x 1 10', 'ss -pant']


        if 'ubuntu' == (platform.linux_distribution()[0]).lower():
            cmd_dmesg  = 'cat /var/log/syslog'
        else:
            cmd_dmesg  = 'cat /var/log/messages'
        
        terminal.enable_color(False)
        
        os.makedirs(as_sysinfo_logdir)
                
        try:            
            aslogfile = as_logfile_prefix + 'asadmCmd.log'
            cinfo = InfoController()
            for info_param in info_params:
                self.collectinfo_content(cinfo,[info_param])
            
            do_show = ShowController()
            for show_param in show_params:
                self.collectinfo_content(do_show,[show_param])
            
            aslogfile = as_logfile_prefix + 'clusterCmd.log'
            for cluster_param in cluster_params:
                self.collectinfo_content('cluster',cluster_param)

        except Exception as e:
            self.write_log(str(e))
            sys.stdout = sys.__stdout__
            
        aslogfile = os.path.join(as_sysinfo_logdir, output_time + '_' + 'sysCmdOutput.log')
        for cmd in shell_cmds:
            self.collectinfo_content('shell',[cmd])
            
        aslogfile = os.path.join(as_sysinfo_logdir, output_time + '_' + 'cpu_stat.log')
        for _cmd in cpu_stat:
            self.collectinfo_content('shell',[_cmd])
        
        aslogfile = os.path.join(as_sysinfo_logdir, output_time + '_' + 'dmesg.log')
        self.collectinfo_content('shell',[cmd_dmesg])
        
        if 'True' in self.cluster.isXDREnabled().values():
            aslogfile = as_logfile_prefix + 'xdr.log'
            self.collectinfo_content('shell',['tail -n 10000 /var/log/*xdr.log'])
            
        try:         
            _ip = ((util.shell_command(["hostname -I"])[0]).split(' ')[0].strip())
            as_version = self.cluster._callNodeMethod([_ip], "info", "build").popitem()[1]
            log_location = self.cluster._callNodeMethod([_ip], "info", 
                                                        "logs").popitem()[1].split(':')[1]
            # Comparing with this version because prior to this it was citrusleaf.conf & citrusleaf.log
            if StrictVersion(as_version) > StrictVersion("3.0.0"):            
                aslogfile = as_logfile_prefix + 'aerospike.conf'
                self.collectinfo_content('shell',['cat /etc/aerospike/aerospike.conf'])
            else:
                aslogfile = as_logfile_prefix + 'citrusleaf.conf'
                self.collectinfo_content('shell',['cat /etc/citrusleaf/citrusleaf.conf'])
                
            self.collect_local_file(log_location, aslogdir)
        except Exception as e: 
            self.write_log(str(e))
            sys.stdout = sys.__stdout__            
                    
        aslogfile = as_logfile_prefix + 'collectSys.log'
        self.collectinfo_content(self.collect_sys)
        
        aslogfile = as_logfile_prefix + 'awsData.log'
        self.collectinfo_content(self.get_awsdata)
        
        self.archive_log(aslogdir)

    def _do_default(self, line):
        self.main_collectinfo(line)
