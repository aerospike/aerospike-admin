# Copyright 2013-2016 Aerospike, Inc.
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

import copy
import re
from lib import util
import lib
from telnetlib import Telnet
from time import time
import socket
import threading
from distutils.version import LooseVersion
from lib.assocket import ASSocket
from lib.util import remove_suffix


def getfqdn(address, timeout=0.5):
    # note: cannot use timeout lib because signal must be run from the
    #       main thread

    result = [address]

    def helper():
        result[0] = socket.getfqdn(address)

    t = threading.Thread(target=helper)

    t.start()

    t.join(timeout)

    return result[0]

def return_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            args[0].alive = False
            return e

    return wrapper

class Node(object):
    dns_cache = {}
    pool_lock = threading.Lock()

    def __init__(self, address, port=3000, tls_name=None, timeout=3, use_telnet=False
                 , user=None, password=None,  ssl_context=None, consider_alumni=False):
        """
        address -- ip or fqdn for this node
        port -- info port for this node
        timeout -- number of seconds to wait before giving up on the node
        If address is ip then get fqdn else get ip
        store ip in self.ip
        store fqdn in self.fqdn
        store port in self.port

        NOTE: would be nice if the port could either be the service or telnet
        access port. Can we detect from the socket?
        ALSO NOTE: May be better to just use telnet instead?
        """
        self._updateIP(address, port)
        self.port = port
        self.xdr_port = 3004 # TODO: Find the xdr port
        self._timeout = timeout
        self._use_telnet = use_telnet
        self.user = user
        self.password = password
        self.tls_name = tls_name
        self.ssl_context = ssl_context
        if ssl_context:
            self.enable_tls = True
        else:
            self.enable_tls = False
        self.consider_alumni = consider_alumni
        # hack, _key needs to be defines before info calls... but may have
        # wrong (localhost) address before infoService is called. Will set
        # again after that call.

        self._key = hash(self.createKey(address, self.port))
        self.peers_generation = -1
        self.service_addresses = []
        self.socket_pool = {}
        self.socket_pool[self.port] = set()
        self.socket_pool[self.xdr_port] = set()
        self.connect(address, port)

    def connect(self, address, port):
        try:
            self.node_id = self.infoNode()
            if isinstance(self.node_id, Exception):
                # Not able to connect this address
                raise self.node_id
            # Original address may not be the service address, the
            # following will ensure we have the service address
            service_addresses = self.infoService(address, return_None=True)
            if service_addresses and not isinstance(self.service_addresses, Exception):
                self.service_addresses = service_addresses
            #else : might be it's IP is not available, node should try all old service addresses
            self.close()
            if not self.service_addresses or (self.ip,self.port,self.tls_name) not in self.service_addresses:
                # if asd >= 3.10 and node has only IPv6 address
                self.service_addresses.append((self.ip,self.port,self.tls_name))
            for s in self.service_addresses:
                try:
                    address = s[0]
                    # calling update ip again because infoService may have provided a
                    # different IP than what was seeded.
                    self._updateIP(address, self.port)
                    self.node_id = self.infoNode()

                    if not isinstance(self.node_id, Exception):
                        break
                except Exception:
                    # Sometime unavailable address might be present in service list, for ex. Down NIC address (server < 3.10).
                    # In such scenario, we want to try all addresses from service list till we get available address
                    pass

            if isinstance(self.node_id, Exception):
                raise self.node_id
            self._serviceIPPort = self.createKey(self.ip, self.port)
            self._key = hash(self._serviceIPPort)
            self.features = self.info('features')
            self.use_peers_list = self.isFeaturePresent(feature="peers")
            if self.isPeersChanged():
                self.peers = self._findFriendNodes()
            self.alive = True
        except Exception:
            # Node is offline... fake a node
            self.ip = address
            self.fqdn = address
            self.port = port
            self._serviceIPPort = self.createKey(self.ip, self.port)
            self._key = hash(self._serviceIPPort)

            self.node_id = "000000000000000"
            self.service_addresses = [(self.ip, self.port, self.tls_name)]
            self.features = ""
            self.use_peers_list = False
            self.peers = []
            self.alive = False

    def refresh_connection(self):
        self.connect(self.ip, self.port)

    @property
    def key(self):
        """Get the value of serviceIPPort"""
        return self._serviceIPPort

    @staticmethod
    def createKey(address, port):
        if address and ":" in address:
            #IPv6 format
            return "[%s]:%s"%(address, port)
        return "%s:%s"%(address, port)

    def __hash__(self):
        return hash(self._key)

    def __eq__(self, other):
        return self._key == other._key

    def _updateIP(self, address, port):
        if address not in self.dns_cache:
            self.dns_cache[address] = (socket.getaddrinfo(address, port, socket.AF_UNSPEC, socket.SOCK_STREAM)[0][4][0]
                                       , getfqdn(address))
        self.ip, self.fqdn = self.dns_cache[address]

    def sockName(self, use_fqdn = False):
        if use_fqdn:
            address = self.fqdn
        else:
            address = self.ip

        return self.createKey(address, self.port)

    def __str__(self):
        return self.sockName()

    def isXDREnabled(self):
        config = self.infoGetConfig('xdr')
        if isinstance(config, Exception):
            return False
        try:
            xdr_enabled = config['xdr']['enable-xdr']
            return xdr_enabled == 'true'
        except Exception:
            pass
        return False

    def isFeaturePresent(self, feature):
        if not self.features or isinstance(self.features, Exception):
            return False

        return (feature in self.features)

    def isPeersChanged(self):
        try:
            if not self.use_peers_list:
                # old server code < 3.10
                return True
            new_generation = self.info("peers-generation")
            if self.peers_generation != new_generation:
                self.peers_generation = new_generation
                return True
            else:
                return False
        except Exception:
            return True

    # We need to provide ip to _infoTelnet and _infoCInfo as to maintain unique key for cache. When we run cluster on VM and
    # asadm on Host then services returns all endpoints of server but some of them might not allowed by Host and VM connection. If we
    # do not provide IP here, then we will get same result from cache for that IP to which asadm can't connect. If this happens while
    # setting ip (connection process) then node will get that ip to which asadm can't connect. It will create new
    # issues in future process.

    @return_exceptions
    @util.cached
    def _infoTelnet(self, command, ip = None, port = None):
        # TODO: Handle socket failures
        if ip == None:
            ip = self.ip
        if port == None:
            port = self.port
        try:
            self.sock == self.sock # does self.sock exist?
        except Exception:
            self.sock = Telnet(ip, port)

        self.sock.write("%s\n"%command)

        starttime = time()
        result = ""
        while not result:
            result = self.sock.read_very_eager().strip()
            if starttime + self._timeout < time():
                # TODO: rasie appropriate exception
                raise IOError("Could not connect to node %s"%ip)
        return result

    def _get_connection(self, ip, port):
        sock = None
        with Node.pool_lock:
            try:
                while True:
                    sock = self.socket_pool[port].pop()
                    if sock.is_connected():
                        if not self.ssl_context:
                            sock.settimeout(5.0)
                        break
                    sock.close(force=True)
            except Exception:
                pass
        if sock:
            return sock
        sock = ASSocket(self, ip, port)
        if sock.connect():
            return sock
        return None

    def close(self):
        try:
            while True:
                sock = self.socket_pool[self.port].pop()
                sock.close(force=True)
        except Exception:
            pass

        try:
            while True:
                sock = self.socket_pool[self.xdr_port].pop()
                sock.close(force=True)
        except Exception:
            pass
        self.socket_pool = None

    @return_exceptions
    @util.cached
    def _infoCInfo(self, command, ip = None, port = None):
        # TODO: citrusleaf.py does not support passing a timeout default is 0.5s
        if ip == None:
            ip = self.ip
        if port == None:
            port = self.port
        result = None
        sock = self._get_connection(ip, port)
        try:
            if sock:
                result = sock.execute(command)
                sock.close()
            if result != -1 and result is not None:
                return result
            else:
                raise IOError("Invalid command or Could not connect to node %s "%ip)
        except Exception:
            if sock:
                sock.close()
            raise IOError("Invalid command or Could not connect to node %s "%ip)

    @return_exceptions
    def info(self, command):
        """
        asinfo function equivalent

        Arguments:
        command -- the info command to execute on this node
        """
        if self._use_telnet:
            return self._infoTelnet(command, self.ip)
        else:
            return self._infoCInfo(command, self.ip)

    @return_exceptions
    @util.cached
    def xdrInfo(self, command):
        """
        asinfo -p [xdr-port] equivalent

        Arguments:
        command -- the info command to execute on this node
        """

        try:
            return self._infoCInfo(command, self.ip, self.xdr_port)
        except Exception as e:
            return e

    @return_exceptions
    def infoNode(self):
        """
        Get this nodes id. asinfo -v "node"

        Returns:
        string -- this node's id.
        """

        return self.info("node")

    @return_exceptions
    def _infoPeersListHelper(self, peers):
        """
        Takes an info peers list response and returns a list.
        """
        gen_port_peers = util._parse_string(peers)
        if not gen_port_peers or len(gen_port_peers)<3:
            return []
        default_port = 3000
        generation = gen_port_peers[0]
        if (gen_port_peers[1]):
            default_port = int(gen_port_peers[1])

        peers_list = util._parse_string(gen_port_peers[2])
        if not peers_list or len(peers_list) < 1:
            return []
        p_list = []
        for p in peers_list:
            p_data = util._parse_string(p)
            if not p_data or len(p_data) < 3:
                continue
            node_name = p_data[0]
            tls_name = None
            if p_data[1] and len(p_data[1]) > 0:
                tls_name = p_data[1]

            endpoints = util._parse_string(p_data[2])
            if not endpoints or len(endpoints)<1:
                continue

            if not tls_name:
                tls_name = util.find_dns(endpoints)
            endpoint_list = []
            for e in endpoints:
                if "[" in e and not "]:" in e:
                    addr_port = util._parse_string(e, delim=",")
                else:
                    addr_port = util._parse_string(e, delim=":")
                addr = addr_port[0]
                if addr.startswith("["):
                    addr = addr[1:]
                if addr.endswith("]"):
                    addr = addr[:-1].strip()

                if(len(addr_port)>1 and addr_port[1] and len(addr_port[1])>0):
                    port = addr_port[1]
                else:
                    port = default_port
                try:
                    port = int(port)
                except Exception:
                    port = default_port
                endpoint_list.append((addr, port, tls_name))
            p_list.append(tuple(endpoint_list))
        return p_list

    @return_exceptions
    def infoPeersList(self):
        """
        Get peers this node knows of that are active

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        if self.enable_tls:
            return self._infoPeersListHelper(self.info("peers-tls-std"))
        return self._infoPeersListHelper(self.info("peers-clear-std"))

    @return_exceptions
    def infoAlumniPeersList(self):
        """
        Get peers this node has ever know of

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        if self.enable_tls:
            return self._infoPeersListHelper(self.info("alumni-tls-std"))
        return self._infoPeersListHelper(self.info("alumni-clear-std"))

    @return_exceptions
    def _infoServicesHelper(self, services):
        """
        Takes an info services response and returns a list.
        """
        if not services or isinstance(services, Exception):
            return []

        s = map(util.info_to_tuple, util.info_to_list(services))
        return map(lambda v: (v[0], int(v[1]), self.tls_name), s)

    @return_exceptions
    def infoServices(self):
        """
        Get other services this node knows of that are active

        Returns:
        list -- [(ip,port),...]
        """

        return self._infoServicesHelper(self.info("services"))

    @return_exceptions
    def infoService(self, address, return_None=False):
        try:
            service = self.info("service")
            s = map(util.info_to_tuple, util.info_to_list(service))
            return map(lambda v: (v[0], int(v[1]), self.tls_name), s)
        except Exception:
            pass
        if return_None:
            return None
        return [(address, self.port, self.tls_name)]

    @return_exceptions
    def infoServicesAlumni(self):
        """
        Get other services this node has ever know of

        Returns:
        list -- [(ip,port),...]
        """

        try:
            return self._infoServicesHelper(self.info("services-alumni"))
        except IOError:
            # Possibly old asd without alumni feature
            return self.infoServices()

    @return_exceptions
    def _findFriendNodes(self):
        if self.use_peers_list:
            peers = self.infoPeersList()
            if not self.consider_alumni:
                return peers
            return peers + self.infoAlumniPeersList()
        else:
            services = None
            if self.consider_alumni:
                services = self.infoServicesAlumni()
            if services and not isinstance(services,Exception):
                    return services
            return self.infoServices() # either want to avoid alumni or alumni list is empty (compatible for version without alumni)

    @return_exceptions
    def infoStatistics(self):
        """
        Get statistics for this node. asinfo -v "statistics"

        Returns:
        dictionary -- statistic name -> value
        """

        return util.info_to_dict(self.info("statistics"))

    @return_exceptions
    def infoNamespaces(self):
        """
        Get a list of namespaces for this node. asinfo -v "namespaces"

        Returns:
        list -- list of namespaces
        """

        return util.info_to_list(self.info("namespaces"))

    @return_exceptions
    def infoNamespaceStatistics(self, namespace):
        """
        Get statistics for a namespace.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """

        return util.info_to_dict(self.info("namespace/%s"%namespace))

    @return_exceptions
    def infoAllNamespaceStatistics(self):
        namespaces = self.infoNamespaces()

        if isinstance(namespaces, Exception):
            return namespaces

        stats = {}
        for ns in namespaces:
            stats[ns] = self.infoNamespaceStatistics(ns)

        return stats

    @return_exceptions
    def infoSetStatistics(self):
        stats = self.info("sets")
        stats = util.info_to_list(stats)
        stats.pop()
        stats = [util.info_colon_to_dict(stat) for stat in stats]
        sets = {}
        for stat in stats:
            ns_name = util.get_value_from_dict(d=stat, keys=('ns_name','namespace','ns'))
            set_name = util.get_value_from_dict(d=stat, keys=('set_name','set'))

            key = (ns_name, set_name)
            if key not in sets:
                sets[key] = {}
            set_dict = sets[key]

            set_dict.update(stat)

        return sets

    @return_exceptions
    def infoBinStatistics(self):
        stats = util.info_to_list(self.info("bins"))
        stats.pop()
        stats = [value.split(':') for value in stats]
        stat_dict = {}

        for stat in stats:
            values = util.info_to_list(stat[1], ',')
            values = ";".join(filter(lambda v: '=' in v, values))
            values = util.info_to_dict(values)
            stat_dict[stat[0]] = values

        return stat_dict

    @return_exceptions
    def infoXDRStatistics(self):
        """
        Get statistics for XDR

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        if self.isFeaturePresent('xdr'): # for new aerospike version (>=3.8) with xdr-in-asd stats available on service port
            return util.info_to_dict(self.info("statistics/xdr"))

        return util.info_to_dict(self.xdrInfo('statistics'))

    @return_exceptions
    def infoGetConfig(self, stanza = "", namespace = ""):
        """
        Get the complete config for a node. This should include the following
        stanzas: Service, Network, XDR, and Namespace
        Sadly it seems Service and Network are not seperable.

        Returns:
        dict -- stanza --> [namespace] --> param --> value
        """
        config = {}
        if stanza == 'namespace':
            if namespace != "":
                config[stanza] = {namespace:util.info_to_dict(
                    self.info("get-config:context=namespace;id=%s"%namespace))}
            else:
                namespace_configs = {}
                namespaces = self.infoNamespaces()
                for namespace in namespaces:
                    namespace_config = self.infoGetConfig('namespace', namespace)
                    namespace_config = namespace_config['namespace'][namespace]
                    namespace_configs[namespace] = namespace_config
                config['namespace'] = namespace_configs

        elif stanza == '':
            config['service'] = util.info_to_dict(self.info("get-config:"))
        elif stanza != 'all':
            config[stanza] = util.info_to_dict(
                self.info("get-config:context=%s"%stanza))
        elif stanza == "all":
            namespace_configs = {}
            namespaces = self.infoNamespaces()
            for namespace in namespaces:
                namespace_config = self.infoGetConfig('namespace', namespace)
                namespace_config = namespace_config['namespace'][namespace]
                namespace_configs[namespace] = namespace_config
            config['namespace'] = namespace_configs
            config['service'] = self.infoGetConfig("service")
            # Server lumps this with service
            # config["network"] = self.infoGetConfig("network")
        return config

    def _update_total_latency(self, t_rows, row):
        if not row or not isinstance(row, list):
            return t_rows
        if not t_rows:
            t_rows = []
            t_rows.append(row)
            return t_rows

        tm_range = row[0]
        updated = False
        for t_row in t_rows:
            if t_row[0]==tm_range:
                n_sum = float(row[1])
                if n_sum>0:
                    o_sum = float(t_row[1])
                    for i, t_p in enumerate(t_row[2:]):
                        o_t = float((o_sum*t_p)/100.00)
                        n_t = float((n_sum*row[i+2])/100.00)
                        t_row[i+2] = round(float(((o_t+n_t)*100)/(o_sum+n_sum)), 2)
                    t_row[1] = round(o_sum+n_sum, 2)
                updated = True
                break

        if not updated:
            t_rows.append(copy.deepcopy(row))
        return t_rows

    @return_exceptions
    def infoLatency(self, back=None, duration=None, slice=None, ns_set=None):
        cmd = 'latency:'
        try:
            if back or back==0:
                cmd += "back=%d"%(back) + ";"
        except Exception:
            pass

        try:
            if duration or duration==0:
                cmd += "duration=%d"%(duration) + ";"
        except Exception:
            pass

        try:
            if slice or slice==0:
                cmd += "slice=%d"%(slice) + ";"
        except Exception:
            pass
        data = {}

        try:
            hist_info = self.info(cmd)
        except Exception:
            return data
        #tdata = hist_info.split(';')[:-1]
        tdata = hist_info.split(';')
        hist_name = None
        ns = None
        start_time = None
        columns = []
        ns_hist_pattern = '{([A-Za-z_\d-]+)}-([A-Za-z_-]+)'
        total_key = (" ", "total")

        while tdata != []:
            row = tdata.pop(0)
            if not row:
                continue
            row = row.split(",")
            if len(row)<2:
                continue

            s1, s2 = row[0].split(':', 1)

            if not s1.isdigit():
                m = re.search(ns_hist_pattern, s1)
                if m:
                    ns = m.group(1)
                    hist_name = m.group(2)
                else:
                    ns = None
                    hist_name = s1
                if ns_set and (not ns or ns not in ns_set):
                    hist_name = None
                    continue
                columns = row[1:]
                start_time = s2
                start_time = remove_suffix(start_time, "-GMT")
                columns.insert(0, 'Time Span')
                continue

            if not hist_name or not start_time:
                continue
            try:
                end_time = row.pop(0)
                end_time = remove_suffix(end_time, "-GMT")
                row = [float(r) for r in row]
                row.insert(0, "%s->%s"%(start_time, end_time))
                if hist_name not in data:
                    data[hist_name] = {}
                if ns:
                    ns_key = (ns, "namespace")
                    if ns_key not in data[hist_name]:
                        data[hist_name][ns_key] = {}
                        data[hist_name][ns_key]["columns"] = columns
                        data[hist_name][ns_key]["values"] = []
                    data[hist_name][ns_key]["values"].append(copy.deepcopy(row))
                if total_key not in data[hist_name]:
                    data[hist_name][total_key]={}
                    data[hist_name][total_key]["columns"] = columns
                    data[hist_name][total_key]["values"] = []

                data[hist_name][total_key]["values"] = self._update_total_latency(data[hist_name][total_key]["values"], row)
                start_time = end_time
            except Exception:
                pass
        return data

    @return_exceptions
    def infoDCs(self):
        """
        Get a list of datacenters for this node. asinfo -v "dcs" -p 3004

        Returns:
        list -- list of dcs
        """
        if self.isFeaturePresent('xdr'):
            return util.info_to_list(self.info("dcs"))

        return util.info_to_list(self.xdrInfo("dcs"))

    @return_exceptions
    def infoDCStatistics(self, dc):
        """
        Get statistics for a datacenter.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        if self.isFeaturePresent('xdr'):
            return util.info_to_dict(self.info("dc/%s"%dc))
        return util.info_to_dict(self.xdrInfo("dc/%s"%dc))

    @return_exceptions
    def infoAllDCStatistics(self):
        dcs = self.infoDCs()

        if isinstance(dcs, Exception):
            return {}

        stats = {}
        for dc in dcs:
            stat = self.infoDCStatistics(dc)
            if not stat or isinstance(stat,Exception):
                stat = {}
            stats[dc] = stat

        return stats

    @return_exceptions
    def infoDCGetConfig(self):
        """
        Get config for a datacenter.

        Returns:
        dict -- {dc_name1:{config_name : config_value, ...}, dc_name2:{config_name : config_value, ...}}
        """
        if self.isFeaturePresent('xdr'):
            configs = self.info("get-dc-config")
            if not configs or isinstance(configs,Exception):
                configs = self.info("get-dc-config:")
            if not configs or isinstance(configs,Exception):
                return {}
            return util.info_to_dict_multi_level(configs, "DC_Name")

        configs = self.xdrInfo("get-dc-config")
        if not configs or isinstance(configs,Exception):
            return {}
        return util.info_to_dict_multi_level(configs, "DC_Name")

    @return_exceptions
    def infoXDRGetConfig(self):
        xdr_configs = self.infoGetConfig(stanza='xdr')
        if self.isFeaturePresent('xdr'): # for new aerospike version (>=3.8) with xdr-in-asd config from service port is sufficient
            return xdr_configs
        xdr_configs_xdr = self.xdrInfo('get-config') # required for old aerospike server versions (<3.8)
        if xdr_configs_xdr and not isinstance(xdr_configs_xdr, Exception):
            xdr_configs_xdr = {'xdr':util.info_to_dict(xdr_configs_xdr)}
            if xdr_configs_xdr['xdr'] and not isinstance(xdr_configs_xdr['xdr'], Exception):
                if xdr_configs and xdr_configs['xdr'] and not isinstance(xdr_configs['xdr'],Exception):
                    xdr_configs['xdr'].update(xdr_configs_xdr['xdr'])
                else:
                    xdr_configs = {}
                    xdr_configs['xdr'] = xdr_configs_xdr['xdr']
        return xdr_configs

    @return_exceptions
    def infoHistogram(self, histogram):
        namespaces = self.infoNamespaces()

        data = {}
        for namespace in namespaces:
            try:
                datum = self.info("hist-dump:ns=%s;hist=%s"%(namespace
                                                             , histogram))
                datum = datum.split(',')
                datum.pop(0) # don't care about ns, hist_name, or length
                width = int(datum.pop(0))
                datum[-1] = datum[-1].split(';')[0]
                datum = map(int, datum)

                data[namespace] = {'histogram':histogram
                                   , 'width':width
                                   , 'data':datum}
            except Exception:
                pass
        return data

    def _parseDunList(self, dun_list):
        c = lib.cluster.Cluster(self.ip)
        lookup = c.node_lookup
        result = set()

        if 'all' in dun_list:
            as_version = self.info('build')
            # Comparing with this version because the ability
            # to specify "all" in cluster dun was added in 3.3.26
            if LooseVersion(as_version) < LooseVersion("3.3.26"):
                for node in  c.nodes.values():
                    result.add(node.node_id)
            else:
                result.add('all')
        else:
            for node in dun_list:
                if node in lookup:
                    nodes = lookup[node]
                    if len(nodes) == 1:
                        result.add(nodes[0].node_id)
                    else:
                        keys = lookup.getKey(node)
                        raise Exception(
                            "Node Name: %s is not unique, conflicts "%(node) + \
                            "with %s"%(','.join(keys)))

        dun_list = ','.join(sorted(result))
        if not dun_list:
            raise Exception('Did not recieve any valid hosts')

        return dun_list

    @return_exceptions
    def infoDun(self, dun_list):
        dun_list = self._parseDunList(dun_list)
        command = "dun:nodes=%s"%(dun_list)
        result = self.info(command)
        return command, result

    @return_exceptions
    def infoUndun(self, dun_list):
        dun_list = self._parseDunList(dun_list)
        command = "undun:nodes=%s"%(dun_list)
        result = self.info(command)
        return command, result

    @return_exceptions
    def infoSIndex(self):
        return [util.info_to_dict(v, ':')
                for v in util.info_to_list(self.info("sindex"))[:-1]]

    @return_exceptions
    def infoSIndexStatistics(self, namespace, indexname):
        """
        Get statistics for a sindex.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        return util.info_to_dict(self.info("sindex/%s/%s"%(namespace,indexname)))

    @return_exceptions
    def infoXDRBuildVersion(self):
        """
        Get Build Version for XDR

        Returns:
        string -- build version
        """
        if self.isFeaturePresent('xdr'): # for new aerospike version (>=3.8) with xdr-in-asd stats available on service port
            return self.info('build')

        return self.xdrInfo('build')
