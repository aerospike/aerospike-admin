# Copyright 2013-2020 Aerospike, Inc.
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

from __future__ import print_function
from builtins import zip
from builtins import str
from builtins import object

import copy
import re
import threading
from time import time

from lib.client import util
from lib.client.node import Node
from lib.utils import util as commonutil
from lib.utils.constants import AuthMode
from lib.utils.lookupdict import LookupDict


# interval time in second for cluster refreshing
CLUSTER_REFRESH_INTERVAL = 3


class Cluster(object):
    # Kinda like a singleton... All instantiated classes will share the same
    # state.
    cluster_state = {}
    use_services_alumni = False
    use_services_alt = False
    crawl_lock = threading.Lock()

    def __init__(self, seed_nodes, user=None, password=None, auth_mode=AuthMode.INTERNAL,
                 use_services_alumni=False, use_services_alt=False,
                 ssl_context=None, only_connect_seed=False, timeout=5):
        """
        Want to be able to support multiple nodes on one box (for testing)
        seed_nodes should be the form (address,port,tls) address can be fqdn or ip.
        """

        self.__dict__ = self.cluster_state
        if self.cluster_state != {}:
            return

        self._timeout = timeout

        self.user = user
        self.password = password
        self.auth_mode = auth_mode

        Cluster.use_services_alumni = use_services_alumni
        Cluster.use_services_alt = use_services_alt

        # self.nodes is a dict from Node ID -> Node objects
        self.nodes = {}

        # to avoid multiple entries of endpoints for same server we are keeping
        # this pointers
        self.aliases = {}

        # self.node_lookup is a dict of (fqdn, port) -> Node
        # and (ip, port) -> Node, and node.node_id -> Node
        self.node_lookup = LookupDict()

        self._seed_nodes = set(seed_nodes)
        self._live_nodes = set()
        self.ssl_context = ssl_context

        # crawl the cluster search for nodes in addition to the seed nodes.
        self.last_cluster_refresh_time = 0
        self.only_connect_seed = only_connect_seed
        self._refresh_cluster()

        # to avoid same label (NODE column) for multiple nodes we need to keep track
        # of available nodes name, if names are same then we can use ip:port
        self._same_name_nodes = False

    def __str__(self):
        nodes = list(self.nodes.values())
        if len(nodes) == 0:
            return ""

        online = [n.key for n in [n for n in nodes if n.alive]]
        offline = [n.key for n in [n for n in nodes if not n.alive]]

        retval = "Found %s nodes" % (len(nodes))
        if online:
            retval += "\nOnline:  %s" % (", ".join(online))
        if offline:
            retval += "\nOffline: %s" % (", ".join(offline))

        return retval

    def get_node_displaynames(self):
        node_names = {}
        for node_key, node in list(self.nodes.items()):
            k = node.sock_name(use_fqdn=True)
            if commonutil.is_valid_ip_port(k):
                node_names[node_key] = k
            else:
                node_names[node_key] = self.node_lookup.get_shortname(k, min_prefix_len=20, min_suffix_len=5)

        return node_names

    def get_node_names(self):
        node_names = {}

        if not self._same_name_nodes:
            for node_key, node in list(self.nodes.items()):
                name = node.sock_name(use_fqdn=True)
                if name in list(node_names.values()):
                    # found same name for multiple nodes
                    self._same_name_nodes = True
                    node_names.clear()
                    break
                node_names[node_key] = name

        if not node_names:
            for node_key, node in list(self.nodes.items()):
                node_names[node_key] = node.sock_name(use_fqdn=False)

        return node_names

    def get_expected_principal(self):
        try:
            principal = "0"
            for k in list(self.nodes.keys()):
                n = self.nodes[k]
                if n.node_id.zfill(16) > principal.zfill(16):
                    principal = n.node_id
            return principal
        except Exception as e:
            print(e)
            return ''

    def get_live_nodes(self):
        return self._live_nodes

    def get_visibility_error_nodes(self):
        visible = self.get_live_nodes()
        cluster_visibility_error_nodes = []
        for k in list(self.nodes.keys()):
            node = self.nodes[k]
            if not node.alive:
                # in case of using alumni services, we might have offline nodes
                # which can't detect online nodes
                continue
            peers = util.flatten(node.peers)
            not_visible = set(visible) - set(peers)
            if len(not_visible) != 1:
                cluster_visibility_error_nodes.append(node.key)

        return cluster_visibility_error_nodes

    def get_down_nodes(self):
        cluster_down_nodes = []
        for k in list(self.nodes.keys()):
            try:
                node = self.nodes[k]
                if not node.alive:
                    # in case of using alumni services, we might have offline
                    # nodes which can't detect online nodes
                    continue

                alumni_peers = util.flatten(node.get_alumni_peers())
                peers = util.flatten(node.get_peers(all=True))
                not_visible = set(alumni_peers) - set(peers)
                if len(not_visible) >= 1:
                    for n in not_visible:
                        _key = Node.create_key(n[0], n[1])
                        if _key not in cluster_down_nodes:
                            cluster_down_nodes.append(_key)
            except Exception:
                pass

        return cluster_down_nodes

    def update_aliases(self, aliases, endpoints, key):
        for e in endpoints:
            try:
                addr = e[0]
                port = e[1]
                node_key = Node.create_key(addr, port)
                if len(aliases) == 0 or not node_key in aliases:
                    # same node's service addresses not added already
                    aliases[node_key] = key
                else:
                    # same node's service addresses added already
                    # Ex. NIC down IP available in service list
                    # Avoid creation of two nodes
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
            for node_key in list(self.nodes.keys()):
                node = self.nodes[node_key]
                node.refresh_connection()
                if node.key != node_key:
                    # change in service list
                    self.nodes.pop(node_key)
                    self.update_node(node)
                _endpoints = node.service_addresses
                self.update_aliases(aliases, _endpoints, node.key)
                added_endpoints = added_endpoints + _endpoints
                if not self.only_connect_seed:
                    peers = peers + node.peers
        else:
            peers = self._seed_nodes

        if not added_endpoints:
            return peers
        else:
            # IPv6 addresses are not available in service list we need
            # to check those missing endpoints and add into aliases list
            # following set operation removes only single IPv4 addresses
            # which are present in both list( for old server code < 3.10)
            # But it will keep peers-list as it is, so we will check it again
            # while crawling and update missing endpoints(IPv6) to aliases
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
                nodes = util.concurrent_map(self._register_node, l_unvisited)
                live_nodes = [node
                              for node in nodes
                              if (node is not None and node.alive
                                  and node not in visited)]
                visited |= unvisited
                unvisited.clear()

                if not self.only_connect_seed:
                    services_list = util.concurrent_map(
                        self._get_services, live_nodes)
                    for node, services in zip(live_nodes, services_list):
                        if isinstance(services, Exception):
                            continue
                        all_services.update(set(services))
                        all_services.add((node.ip, node.port, node.tls_name))
                unvisited = all_services - visited
            self._refresh_node_liveliness()
        except Exception:
            pass
        finally:
            self.clear_node_list()

    def clear_node_list(self):
        # remove old entries from self.nodes
        # helps to remove multiple entries of same node ( in case of service
        # list change or node is up after going down)
        service_nodes = set(self.aliases.values())
        for n in list(self.nodes.keys()):
            if n not in service_nodes:
                self.nodes.pop(n)

    def _refresh_node_liveliness(self):
        live_nodes = [node for node in list(self.nodes.values()) if node.alive]
        self._live_nodes.clear()
        self._live_nodes.update(
            ((node.ip, node.port, node.tls_name) for node in live_nodes))

    def update_node(self, node):
        self.nodes[node.key] = node
        # add node to lookup
        self.node_lookup[node.sock_name(use_fqdn=True)] = node
        self.node_lookup[node.sock_name()] = node
        if node.alive:
            self.node_lookup[node.node_id] = node

    def get_node(self, node):
        return self.node_lookup[node]

    def _register_node(self, addr_port_tls):
        if not addr_port_tls:
            return None
        if not isinstance(addr_port_tls, tuple):
            return None
        if not isinstance(addr_port_tls[0], tuple):
            return self._create_node(addr_port_tls, force=True)

        new_node = None
        for i, a_p_t in enumerate(addr_port_tls):
            if i == len(addr_port_tls) - 1:
                new_node = self._create_node(a_p_t, force=True)
            else:
                new_node = self._create_node(a_p_t)
            if not new_node:
                continue
            else:
                break
        self.update_aliases(self.aliases, addr_port_tls, new_node.key)
        return new_node

    def is_present_as_alias(self, addr, port, aliases=None):
        if not aliases:
            aliases = self.aliases
        return Node.create_key(addr, port) in aliases

    def get_node_for_alias(self, addr, port):
        try:
            if self.is_present_as_alias(addr, port):
                return self.nodes[self.aliases[Node.create_key(addr, port)]]
        except Exception:
            pass
        return None

    def _create_node(self, addr_port_tls, force=False):
        """
        Instantiate and return a new node

        If cannot instantiate node, return None.
        Creates a new node if:
           1) key(addr,port) is not available in self.aliases
        """
        try:
            # tuple of length 3 for server version >= 3.10.0 (with tls name)
            addr, port, tls_name = addr_port_tls
        except Exception:
            try:
                # tuple of length 2 for server version < 3.10.0 ( without tls
                # name)
                addr, port = addr_port_tls
                tls_name = None
            except Exception:
                print("ip_port is expected to be a tuple of len 2, " + \
                    "instead it is of type %s and str value of %s" % (
                        type(addr_port_tls), str(addr_port_tls)))
                return None
        try:
            if self.is_present_as_alias(addr, port):
                # Alias entry already added for this endpoint
                n = self.get_node_for_alias(addr, port)
                if n:
                    # Node already added for this endpoint
                    # No need to check for offline/online as we already did
                    # this while finding new nodes to add
                    return n
                # else
                # Will create node again

            # if not existing:
            new_node = Node(addr, port, tls_name=tls_name, timeout=self._timeout,
                            user=self.user, password=self.password, auth_mode=self.auth_mode,
                            consider_alumni=Cluster.use_services_alumni,
                            use_services_alt=Cluster.use_services_alt,
                            ssl_context=self.ssl_context)

            if not new_node:
                return new_node
            if not new_node.alive:
                if not force:
                    # Check other endpoints
                    new_node.close()
                    return None
            self.update_node(new_node)
            self.update_aliases(
                self.aliases, new_node.service_addresses, new_node.key)
            return new_node
        except Exception:
            return None

    @staticmethod
    def _get_services(node):
        """
        Given a node object return its services list / peers list
        """
        try:
            return node.peers
        except Exception:
            return []

    def need_to_refresh_cluster(self):
        if time() - self.last_cluster_refresh_time > CLUSTER_REFRESH_INTERVAL:
            return True
        return False

    def _refresh_cluster(self):
        with Cluster.crawl_lock:
            try:
                if self.need_to_refresh_cluster():
                    self._crawl()
                    self.last_cluster_refresh_time = time()
            except Exception as e:
                print(e)
                raise e

    def call_node_method(self, nodes, method_name, *args, **kwargs):
        """
        Run a particular method command across a set of nodes
        nodes is a list of nodes to to run the command against.
        if nodes is None then we run on all nodes.
        """
        if self.need_to_refresh_cluster():
            self._refresh_cluster()

        if nodes == 'all':
            use_nodes = list(self.nodes.values())
        elif isinstance(nodes, list):
            use_nodes = []
            for node in nodes:
                try:
                    node_list = self.get_node(node)
                    if isinstance(node_list, list):
                        use_nodes.extend(self.get_node(node))
                    else:
                        use_nodes.append(self.get_node(node))
                except Exception:  # Ignore ambiguous and key errors
                    continue
        else:
            raise TypeError(
                "nodes should be 'all' or list found %s" % type(nodes))
        if len(use_nodes) == 0:
            raise IOError('Unable to find any Aerospike nodes')
        return dict(
            util.concurrent_map(
                lambda node:
                (node.key, getattr(node, method_name)(*args, **kwargs)),
                use_nodes))

    def is_XDR_enabled(self, nodes='all'):
        return self.call_node_method(nodes, 'is_XDR_enabled')

    def is_feature_present(self, feature, nodes='all'):
        return self.call_node_method(nodes, 'is_feature_present', feature)

    def get_IP_to_node_map(self):
        if self.need_to_refresh_cluster():
            self._refresh_cluster()
        node_map = {}
        for a in list(self.aliases.keys()):
            try:
                node_map[a] = self.nodes.get(self.aliases[a]).node_id
            except Exception:
                pass
        return node_map

    def get_node_to_IP_map(self):
        if self.need_to_refresh_cluster():
            self._refresh_cluster()
        ip_map = {}
        for addr in list(self.aliases.keys()):
            try:
                id = self.nodes.get(self.aliases[addr]).node_id
                if id in ip_map:
                    ip_map[id].append(addr)
                else:
                    ip_map[id] = [addr]
            except Exception:
                pass

        for node, ip_list in list(ip_map.items()):
            ip_map[node] = ",".join(sorted(ip_map[node]))

        return ip_map

    def __getattr__(self, name):
        regex = re.compile("^info.*$|^xdr.*$")
        if regex.match(name):
            def info_func(*args, **kwargs):
                if 'nodes' not in kwargs:
                    nodes = 'all'
                else:
                    nodes = kwargs['nodes']
                    del kwargs['nodes']

                return self.call_node_method(nodes, name, *args, **kwargs)

            return info_func
        else:
            raise AttributeError("Cluster has not attribute '%s'" % (name))

    def close(self):
        for node_key in list(self.nodes.keys()):
            try:
                node = self.nodes[node_key]
                node.close()
            except Exception:
                pass
        self.nodes = None
        self.node_lookup = None

    def get_seed_nodes(self):
        return list(self._seed_nodes)