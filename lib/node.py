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

from lib import citrusleaf
from lib import util
import lib
from telnetlib import Telnet
from time import time
import socket
import threading
from distutils.version import LooseVersion

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

    def __init__(self, address, port=3000, timeout=3, use_telnet=False
                 , user=None, password=None):
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
        self._updateIP(address)
        self.port = port
        self.xdr_port = 3004 # TODO: Find the xdr port
        self._timeout = timeout
        self._use_telnet = use_telnet
        self.user = user
        self.password = password
        # hack, _key needs to be defines before info calls... but may have
        # wrong (localhost) address before infoService is called. Will set
        # again after that call.

        self._key = hash(self.createKey(address, self.port))

        try:
            self.node_id = self.infoNode()
            if isinstance(self.node_id, Exception):
                raise self.node_id

            # Original address may not be the service address, the
            # following will ensure we have the service address
            address = self.infoService(address)[0]
            if isinstance(address, Exception):
                raise address

            # calling update ip again because infoService may have provided a
            # different IP than what was seeded.
            self._updateIP(address)
            self._serviceIPPort = self.createKey(self.ip, self.port)
            self._key = hash(self._serviceIPPort)
            self.alive = True
        except:
            # Node is offline... fake a node
            self.ip = address
            self.fqdn = address
            self.port = port
            self._serviceIPPort = self.createKey(self.ip, self.port)
            self._key = hash(self._serviceIPPort)

            self.node_id = "000000000000000"
            self.alive = False

    @property
    def key(self):
        """Get the value of serviceIPPort"""
        return self._serviceIPPort

    @staticmethod
    def createKey(address, port):
        return "%s:%s"%(address, port)

    def __hash__(self):
        return hash(self._key)

    def __eq__(self, other):
        return self._key == other._key

    def _updateIP(self, address):
        if address not in self.dns_cache:
            self.dns_cache[address] = (socket.gethostbyname(address)
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


        xdr_enabled = config['xdr']['enable-xdr']
        return xdr_enabled == 'true'

    def isFeaturePresent(self, feature):
        features = self.info('features')
        if isinstance(features, Exception):
            return False

        return (feature in features)

    @return_exceptions
    @util.cached
    def _infoTelnet(self, command, port = None):
        # TODO: Handle socket failures
        if port == None:
            port = self.port
        try:
            self.sock == self.sock # does self.sock exist?
        except:
            self.sock = Telnet(self.ip, port)

        self.sock.write("%s\n"%command)

        starttime = time()
        result = ""
        while not result:
            result = self.sock.read_very_eager().strip()
            if starttime + self._timeout < time():
                # TODO: rasie appropriate exception
                raise IOError("Could not connect to node %s"%self.ip)
        return result

    @return_exceptions
    @util.cached
    def _infoCInfo(self, command, port = None):
        # TODO: citrusleaf.py does not support passing a timeout default is 0.5s
        if port == None:
            port = self.port

        result = citrusleaf.citrusleaf_info(self.ip, port, command
                                            , user=self.user
                                            , password=self.password)
        if result != -1 and result is not None:
            return result
        else:
            raise IOError(
                "Invalid command or Could not connect to node %s "%self.ip)

    @return_exceptions
    def info(self, command):
        """
        asinfo function equivalent

        Arguments:
        command -- the info command to execute on this node
        """
        if self._use_telnet:
            return self._infoTelnet(command)
        else:
            return self._infoCInfo(command)

    @return_exceptions
    @util.cached
    def xdrInfo(self, command):
        """
        asinfo -p [xdr-port] equivalent

        Arguments:
        command -- the info command to execute on this node
        """

        try:
            return self._infoCInfo(command, self.xdr_port)
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
    def _infoServicesHelper(self, services):
        """
        Takes an info services response and returns a list.
        """
        if not services:
            return []

        s = map(util.info_to_tuple, util.info_to_list(services))
        return map(lambda v: (v[0], int(v[1])), s)

    @return_exceptions
    def infoServices(self):
        """
        Get other services this node knows of that are active

        Returns:
        list -- [(ip,port),...]
        """

        return self._infoServicesHelper(self.info("services"))

    @return_exceptions
    def infoService(self, address):
        try:
            service = self.info("service")
            return tuple(service.split(':'))
        except:
            return [address]

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
            ns_name = stat['ns_name']
            set_name = stat['set_name']

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
        if self.isFeaturePresent('xdr'): # for new aerospike version (>=3.7.2) with xdr-in-asd stats available on service port
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

    @return_exceptions
    def infoLatency(self):
        tdata = self.info('latency:').split(';')[:-1]
        data = {}
        while tdata != []:
            columns = tdata.pop(0)
            row = tdata.pop(0)

            hist_name, columns = columns.split(':', 1)
            columns = columns.split(',')
            row = row.split(',')
            start_time = columns.pop(0)
            end_time = row.pop(0)
            columns.insert(0, 'Time Span')
            row = [float(r) for r in row]
            row.insert(0, "%s->%s"%(start_time, end_time))

            data[hist_name] = (columns, row)

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
        if self.isFeaturePresent('xdr'): # for new aerospike version (>=3.7.2) with xdr-in-asd config from service port is sufficient
            return xdr_configs
        xdr_configs_xdr = self.xdrInfo('get-config') # required for old aerospike server versions (<3.7.2)
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
