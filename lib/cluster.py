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

from lib import util
from lib.node import Node
from lib.prefixdict import PrefixDict
from lib import terminal
import re

class Cluster(object):
    # Kinda like a singleton... All instantiated classes will share the same
    # state... This makes the class no
    cluster_state = {}
    use_services = False

    def __init__(self, seed_nodes, use_telnet=False, user=None, password=None, use_services=False):
        """
        Want to be able to support multiple nodes on one box (for testing)
        seed_nodes should be the form (address,port) address can be fqdn or ip.
        """

        self.__dict__ = self.cluster_state
        if self.cluster_state != {}:
            return

        # will we connect using telnet port?
        self.use_telnet = use_telnet

        self.user = user
        self.password = password
        Cluster.use_services = use_services

        # self.nodes is a dict from Node ID -> Node objects
        self.nodes = {}

        # self.node_lookup is a dict of (fqdn, port) -> Node
        # and (ip, port) -> Node, and node.node_id -> Node
        self.node_lookup = PrefixDict()

        self._original_seed_nodes = set(seed_nodes)
        self._seed_nodes = set(seed_nodes)
        self._live_nodes = set()
        # crawl the cluster search for nodes in addition to the seed nodes.
        self._enable_crawler = True
        self._crawl()

    def __str__(self):
        nodes = self.nodes.values()
        online = [node.key for node in nodes if node.alive]
        offline = [node.key for node in nodes if not node.alive]

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
            for n in self.nodes.itervalues():
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
        for node in self.nodes.values():
            service_list = node.infoServices()
            if isinstance(service_list, Exception):
                continue

            service_set = set(service_list)
            if len((visible | service_set) - service_set) != 1:
                cluster_visibility_error_nodes.append(node.key)

        return cluster_visibility_error_nodes

    def _shouldCrawl(self):
        """
        Determine if we need to do a crawl.

        We crawl if the union of all services lists is not equal to the set
        of nodes that this tool percieves as alive.
        """
        if not self._enable_crawler:
            return False
        self._enable_crawler = False
        current_services = set()

        self._refreshNodeLiveliness()

        try:
            for services in self.infoServices().itervalues():
                if isinstance(services, Exception):
                    continue
                current_services |= set(services)

            if current_services and current_services == self._live_nodes:
                # services have not changed, do not crawl
                # if services are empty they crawl regardless
                return False
            else:
                # services have changed
                return True

        except IOError:
            # We aren't connected yet, definitely crawl.
            return True

        finally:
            # Re-enable crawler before exiting
            self._enable_crawler = True

    def _crawl(self):
        """
        Find all the nodes in the cluster and add them to self.nodes.
        """
        if not self._shouldCrawl():
            return
        self._enable_crawler = False

        try:
            if self._seed_nodes:
                seed_nodes = self._seed_nodes
            else:
                seed_nodes = self._original_seed_nodes

            # clear the current lookup and node list
            all_services = set()
            visited = set()
            unvisited = set(seed_nodes)
            while unvisited - visited:
                l_unvisited = list(unvisited)

                nodes = util.concurrent_map(self._registerNode, l_unvisited)
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
                    all_services.add((node.ip, node.port))
                unvisited = all_services - visited
            if all_services:
                self._seed_nodes = all_services
            self._refreshNodeLiveliness()
        except:
            pass
        finally:
            self._enable_crawler = True

    def _refreshNodeLiveliness(self):
        live_nodes = [node for node in self.nodes.itervalues() if node.alive]
        self._live_nodes.clear()
        self._live_nodes.update(((node.ip, node.port) for node in live_nodes))

    def updateNode(self, node):
        self.nodes[node.key] = node
        # add node to lookup
        self.node_lookup[node.sockName(use_fqdn=True)] = node
        self.node_lookup[node.sockName()] = node
        if node.alive:
            self.node_lookup[node.node_id] = node

    def getNode(self, node):
        return self.node_lookup[node]

    def _registerNode(self, addr_port):
        """
        Instantiate and return a new node

        If cannot instantiate node, return None.
        Creates a new node if:
           1) node.key doesn't already exist
           2) node.key exists but existing node is not alive
        """
        try:
            addr, port = addr_port
        except:
            print "ip_port is expected to be a tuple of len 2, " + \
                "instead it is of type %s and str value of %s"%(type(addr_port)
                                                                , str(addr_port))
            return None

        try:
            node_key = Node.createKey(addr, port)
            existing = self.nodes.get(node_key, None)

            if not existing or not existing.alive:
                new_node = Node(addr,
                                port,
                                use_telnet=self.use_telnet,
                                user=self.user,
                                password=self.password)

                if existing and not new_node.alive:
                    new_node = existing
            else:
                return existing

            self.updateNode(new_node)
            return new_node
        except:
            return None

    @staticmethod
    def _getServices(node):
        """
        Given a node object return its services list
        """
        if Cluster.use_services:
            return node.infoServices()

        services = node.infoServicesAlumni()
        if services:
            return services
        return node.infoServices() # compatible for version without alumni

    def _callNodeMethod(self, nodes, method_name, *args, **kwargs):
        """
        Run a particular method command across a set of nodes
        nodes is a list of nodes to to run the command against.
        if nodes is None then we run on all nodes.
        """
        self._crawl()
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
                except: # Ignore ambiguous and key errors
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
