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
import threading

from lib import util
from lib.node import Node
from lib.prefixdict import PrefixDict
from lib import info
import re

class Cluster(object):
    # Kinda like a singleton... All instantiated classes will share the same
    # state... This makes the class no
    cluster_state = {}
    use_services = True
    tls_cert = None
    crawl_lock = threading.Lock()

    def __init__(self, seed_nodes, use_telnet=False, user=None, password=None, use_services=True, tls_cert=None):
        """
        Want to be able to support multiple nodes on one box (for testing)
        seed_nodes should be the form (address,port,tls) address can be fqdn or ip.
        """

        self.__dict__ = self.cluster_state
        if self.cluster_state != {}:
            return

        # will we connect using telnet port?
        self.use_telnet = use_telnet

        self.user = user
        self.password = password
        Cluster.use_services = use_services
        Cluster.tls_cert = tls_cert

        # self.nodes is a dict from Node ID -> Node objects
        self.nodes = {}

        # to avoid multiple entries of endpoints for same server we are keeping this pointers
        self.aliases = {}

        # self.node_lookup is a dict of (fqdn, port) -> Node
        # and (ip, port) -> Node, and node.node_id -> Node
        self.node_lookup = PrefixDict()

        self._original_seed_nodes = set(seed_nodes)
        self._seed_nodes = set(seed_nodes)
        self._live_nodes = set()
        # crawl the cluster search for nodes in addition to the seed nodes.
        self._refreshCluster()

    def __str__(self):
        nodes = self.nodes.values()
        if len(nodes) == 0:
            return ""

        online = [n.key for n in filter(lambda n: n.alive, nodes)]
        offline = [n.key for n in filter(lambda n: not n.alive, nodes)]

        retval = "Found %s nodes"%(len(nodes))
        if online:
            retval += "\nOnline:  %s"%(", ".join(online))
        if offline:
            retval += "\nOffline: %s"%(", ".join(offline))

        return retval

    def getPrefixes(self):
        prefixes = {}
        for node_key, node in self.nodes.iteritems():
            fqdn = node.sockName(use_fqdn=True)
            prefixes[node_key] = self.node_lookup.getPrefix(fqdn)

        return prefixes

    def getNodeNames(self):
        nodeNames = {}
        for node_key, node in self.nodes.iteritems():
            nodeNames[node_key] = node.sockName(use_fqdn=True)

        return nodeNames

    def getExpectedPrincipal(self):
        try:
            principal = "0"
            for k in self.nodes.keys():
                n = self.nodes[k]
                if n.node_id.zfill(16) > principal.zfill(16):
                    principal = n.node_id
            return principal
            #return max([n.node_id for n in self.nodes.itervalues()])
        except Exception as e:
            print e
            return ''

    def getLiveNodes(self):
        return self._live_nodes

    def getClusterVisibilityErrorNodes(self):
        visible = self.getLiveNodes()
        cluster_visibility_error_nodes = []
        for k in self.nodes.keys():
            node = self.nodes[k]
            if not node.alive:
                # in case of using alumni services, we might have offline nodes which can't detect online nodes
                continue
            peers = util.flatten(node.peers)
            not_visible = set(visible) - set(peers)
            if len(not_visible) != 1:
                cluster_visibility_error_nodes.append(node.key)

        return cluster_visibility_error_nodes

    def update_aliases(self, aliases, endpoints, key):
        for e in endpoints:
            try:
                addr = e[0]
                port = e[1]
                node_key = Node.createKey(addr, port)
                if len(aliases) == 0 or not node_key in aliases:
                    # same node's service addresses not added already
                    aliases[node_key] = key
                else:
                    # same node's service addresses added already
                    # Ex. NIC down IP available in service list
                    # We want to avoid creation of two nodes
                    aliases_node_key = aliases[node_key]
                    if aliases_node_key != key:
                        node = self.nodes[aliases_node_key]
                        if not node.alive:
                            aliases[node_key] = key
            except Exception:
                pass

    def find_new_nodes(self):
        added_endpoints = []
        peers = []
        aliases = {}
        if self.nodes:
            for node_key in self.nodes.keys():
                node = self.nodes[node_key]
                node.refresh_connection()
                if node.key != node_key:
                    # change in service list
                    self.nodes.pop(node_key)
                    self.updateNode(node)
                _endpoints = node.service_addresses
                self.update_aliases(aliases, _endpoints, node.key)
                added_endpoints = added_endpoints + _endpoints
                peers = peers + node.peers
        else:
            peers = self._original_seed_nodes

        if not added_endpoints:
            return peers
        else:
            # IPv6 addresses are not available in service list we need to check those missing endpoints and add into aliases list
            # following set operation removes only single IPv4 addresses which are present in both list( for old server code < 3.10)
            # But it will keep peers-list as it is, so we will check it again while crawling and update missing endpoints(IPv6) to aliases
            nodes_to_add = list(set(peers) - set(added_endpoints))
            self.aliases = copy.deepcopy(aliases)

        return nodes_to_add

    def _crawl(self):
        """
        Find all the nodes in the cluster and add them to self.nodes.
        """
        nodes_to_add = self.find_new_nodes()
        if not nodes_to_add or len(nodes_to_add) == 0:
            return
        try:
            all_services = set()
            visited = set()
            unvisited = set(nodes_to_add)

            while unvisited - visited:
                l_unvisited = list(unvisited)
                nodes = map(self._registerNode, l_unvisited)
                live_nodes = [node
                              for node in nodes
                              if node is not None and node.alive and node not in visited]
                visited |= unvisited
                unvisited.clear()

                services_list = util.concurrent_map(self._getServices, live_nodes)
                for node, services in zip(live_nodes, services_list):
                    if isinstance(services, Exception):
                        continue
                    all_services.update(set(services))
                    all_services.add((node.ip, node.port, node.tls))
                unvisited = all_services - visited
            self._refreshNodeLiveliness()
        except Exception:
            pass
        finally:
            self.clear_node_list()

    def clear_node_list(self):
        # remove old entries from self.nodes
        # helps to remove multiple entries of same node ( in case of service list change or node is up after going down)
        service_nodes = set(self.aliases.values())
        for n in self.nodes.keys():
            if n not in service_nodes:
                self.nodes.pop(n)

    def _refreshNodeLiveliness(self):
        live_nodes = [node for node in self.nodes.itervalues() if node.alive]
        self._live_nodes.clear()
        self._live_nodes.update(((node.ip, node.port, node.tls) for node in live_nodes))

    def updateNode(self, node):
        self.nodes[node.key] = node
        # add node to lookup
        self.node_lookup[node.sockName(use_fqdn=True)] = node
        self.node_lookup[node.sockName()] = node
        if node.alive:
            self.node_lookup[node.node_id] = node

    def getNode(self, node):
        return self.node_lookup[node]

    def _registerNode(self, addr_port_tls):
        if not addr_port_tls:
            return None
        if not isinstance(addr_port_tls, tuple):
            return None
        if not isinstance(addr_port_tls[0], tuple):
            return self._createNode(addr_port_tls, force=True)

        new_node = None
        for i, a_p_t in enumerate(addr_port_tls):
            if i == len(addr_port_tls)-1:
                new_node = self._createNode(a_p_t, force=True)
            else:
                new_node = self._createNode(a_p_t)
            if not new_node:
                continue
            else:
                break
        self.update_aliases(self.aliases, addr_port_tls, new_node.key)
        return new_node

    def info_request(self, command, addr, port = None, user = None, password = None, tls_subject = None, tls_cert = None ):
        # TODO: citrusleaf.py does not support passing a timeout default is 0.5s
        if port == None:
            port = 3000

        result = info.info(addr, port, command
                                            , user=user
                                            , password=password, tls_subject=tls_subject, tls_cert=tls_cert)
        if result != -1 and result is not None:
            return result
        else:
            return -1

    def is_present_as_alias(self, addr, port, aliases=None):
        if not aliases:
            aliases = self.aliases
        return Node.createKey(addr, port) in aliases

    def get_node_for_alias(self, addr, port):
        try:
            if self.is_present_as_alias(addr, port):
                return self.nodes[self.aliases[Node.createKey(addr, port)]]
        except Exception:
            pass
        return None

    def _createNode(self, addr_port_tls, force=False):
        """
        Instantiate and return a new node

        If cannot instantiate node, return None.
        Creates a new node if:
           1) key(addr,port) is not available in self.aliases
        """
        try:
            # tuple of length 3 for server version >= 3.10.0 (with tls name)
            addr, port, tls = addr_port_tls
        except Exception:
            try:
                # tuple of length 2 for server version < 3.10.0 ( without tls name)
                addr, port = addr_port_tls
                tls = None
            except Exception:
                print "ip_port is expected to be a tuple of len 2, " + \
                    "instead it is of type %s and str value of %s"%(type(addr_port_tls)
                                                                    , str(addr_port_tls))
                return None
        try:
            if self.is_present_as_alias(addr, port):
                # Alias entry already added for this endpoint
                n = self.get_node_for_alias(addr, port)
                if n:
                    # Node already added for this endpoint
                    # No need to check for offline/online as we already did this while finding new nodes to add
                    return n
                # else
                # Will create node again


            # if not existing:
            new_node = Node(addr, port, use_telnet=self.use_telnet,
                            user=self.user, password=self.password,
                            tls=tls, tls_cert=Cluster.tls_cert,
                            consider_alumni=not Cluster.use_services)
            if not new_node:
                return new_node
            if not new_node.alive:
                if not force:
                    # We can check other endpoints
                    return None
            self.updateNode(new_node)
            self.update_aliases(self.aliases, new_node.service_addresses, new_node.key)
            return new_node
        except Exception:
            return None

    @staticmethod
    def _getServices(node):
        """
        Given a node object return its services list / peers list
        """
        try:
            return node.peers
        except Exception:
            return []

    def _refreshCluster(self):
        with Cluster.crawl_lock:
            try:
                self._crawl()
            except Exception as e:
                print e
                raise e

    def _callNodeMethod(self, nodes, method_name, *args, **kwargs):
        """
        Run a particular method command across a set of nodes
        nodes is a list of nodes to to run the command against.
        if nodes is None then we run on all nodes.
        """
        self._refreshCluster()

        if nodes == 'all':
            use_nodes = self.nodes.values()
        elif isinstance(nodes, list):
            use_nodes = []
            for node in nodes:
                try:
                    node_list = self.getNode(node)
                    if isinstance(node_list, list):
                        use_nodes.extend(self.getNode(node))
                    else:
                        use_nodes.append(self.getNode(node))
                except Exception: # Ignore ambiguous and key errors
                    continue
        else:
            raise TypeError(
                "nodes should be 'all' or list found %s"%type(nodes))
        if len(use_nodes) == 0:
            raise IOError('Unable to find any Aerospike nodes')
        return dict(
            util.concurrent_map(
                lambda node:
                (node.key, getattr(node, method_name)(*args, **kwargs)),
                use_nodes))

    def isXDREnabled(self, nodes='all'):
        return self._callNodeMethod(nodes, 'isXDREnabled')

    def isFeaturePresent(self, feature, nodes='all'):
        return self._callNodeMethod(nodes, 'isFeaturePresent', feature)

    def getIP2NodeMap(self):
        self._refreshCluster()
        ipMap = {}
        for a in self.aliases.keys():
            try:
                ipMap[a] = self.nodes.get(self.aliases[a]).node_id
            except Exception:
                pass
        return ipMap

    def getNode2IPMap(self):
        self._refreshCluster()
        ipMap = {}
        for a in self.aliases.keys():
            try:
                id = self.nodes.get(self.aliases[a]).node_id
                if id in ipMap:
                    ipMap[id] = ipMap[id] + ", " + a
                else:
                    ipMap[id] = a
            except Exception:
                pass
        return ipMap

    def __getattr__(self, name):
        regex = re.compile("^info.*$|^xdr.*$")
        if regex.match(name):
            def infoFunc(*args, **kwargs):
                if 'nodes' not in kwargs:
                    nodes = 'all'
                else:
                    nodes = kwargs['nodes']
                    del kwargs['nodes']

                return self._callNodeMethod(nodes, name, *args, **kwargs)

            return infoFunc
        else:
            raise AttributeError("Cluster has not attribute '%s'"%(name))
