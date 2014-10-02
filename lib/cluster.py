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

from lib import citrusleaf
from lib import util
from lib.node import Node
from lib.prefixdict import PrefixDict
import re

class Cluster(object):
    # Kinda like a singleton... All instantiated classes will share the same
    # state... This makes the class no
    cluster_state = {}

    def __init__(self, seed_nodes, use_telnet=False, user=None, password=None):
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

    def getExpectedPrincipal(self):
        try:
            return max([n.node_id for n in self.nodes.itervalues()])
        except:
            return ''

    def getVisibility(self):
        return self._live_nodes

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
            infoservices = self.infoServices().values()

            for s in self.infoServices().values():
                if isinstance(s, Exception):
                    continue
                current_services |= set(s)

            if current_services and current_services == self._live_nodes:
                # services have not changed, do not crawl
                # if services are empty they crawl regardless
                return False
            else:
                # services have changed
                return True

        except IOError:
            # We aren't connected yet, definently crawl.
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
                live_nodes = filter(
                    lambda n: n is not None and n.alive and n not in visited
                    , nodes)

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
        live_nodes = filter(lambda n: n.alive, self.nodes.itervalues())
        self._live_nodes.clear()
        self._live_nodes.update(map(lambda n: (n.ip, n.port), live_nodes))

    def updateNode(self, node):
        self.nodes[node.key] = node
        # add node to lookup
        self.node_lookup[node.sockName(use_fqdn = True)] = node
        self.node_lookup[node.sockName()] = node
        if node.alive:
            self.node_lookup[node.node_id] = node

    def getNode(self, node):
        return self.node_lookup[node]

    def _registerNode(self, ip_port):
        """
        Instantiate and return a new node

        If cannot instantiate node, return None.
        Creates a new node if:
           1) node.key doesn't already exist
           2) node.key exists but existing node is not alive
        """
        try:
            ip, port = ip_port
        except Exception as e:
            print "ip_port is expected to be a tuple of len 2, " + \
                "instead it is of type %s and str value of %s"%(type(ip_port)
                                                                , str(ip_port))
            return None

        try:
            node_key = Node.createKey(ip, port)
            if node_key in self.nodes:
                existing = self.nodes[node_key]
            else:
                existing = None

            if not existing or not existing.alive:
                new_node = Node(ip
                              , port
                              , use_telnet=self.use_telnet
                              , user=self.user
                              , password=self.password)

                if existing and not new_node.alive:
                    new_node = existing
            self.updateNode(new_node)

            return new_node
        except:
            return None

    def _getServices(self, node):
        """
        Given a node object return its services list
        """
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
        elif type(nodes) == list:
            use_nodes = []
            for n in nodes:
                try:
                    node_list = self.getNode(n)
                    if isinstance(node_list, list):
                        use_nodes.extend(self.getNode(n))
                    else:
                        use_nodes.append(self.getNode(n))
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

    def isXDREnabled(self, nodes = 'all'):
        return self._callNodeMethod(nodes, 'isXDREnabled')

    def __getattr__(self, name):
        regex = re.compile("^info.*$|^xdr.*$")
        if regex.match(name):
            def infoFunc(*args, **kwargs):
                if 'nodes' not in kwargs:
                    nodes = 'all'
                else:
                    nodes = kwargs['nodes']
                    del(kwargs['nodes'])

                return self._callNodeMethod(nodes, name, *args, **kwargs)

            return infoFunc
        else:
            raise AttributeError("Cluster has not attribute '%s'"%(name))
