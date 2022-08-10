# Copyright 2013-2021 Aerospike, Inc.
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

import asyncio
import copy
import random
import re
import logging
import inspect
from typing import Any, Callable, Coroutine, Literal, Union
from time import time
from lib.live_cluster.client import ASInfoNotAuthenticatedError, ASProtocolError
from lib.live_cluster.client.types import Addr_Port_TLSName
from lib.utils.async_object import AsyncObject

from lib.utils.lookup_dict import LookupDict
from lib.utils import util, constants

from . import client_util
from .node import Node


# interval time in second for cluster refreshing
CLUSTER_REFRESH_INTERVAL = 3


class Cluster(AsyncObject):
    use_services_alumni = False
    use_services_alt = False
    logger = logging.getLogger("asadm")

    async def __init__(
        self,
        seed_nodes: list[Addr_Port_TLSName],
        user=None,
        password=None,
        auth_mode=constants.AuthMode.INTERNAL,
        use_services_alumni=False,
        use_services_alt=False,
        ssl_context=None,
        only_connect_seed=False,
        timeout=1,
    ):
        """
        Want to be able to support multiple nodes on one box (for testing)
        seed_nodes should be the form (address,port,tls) address can be fqdn or ip.
        """
        Cluster.crawl_lock = asyncio.Lock()

        self._timeout = timeout

        self.user = user
        self.password = password
        self.auth_mode = auth_mode

        self.use_services_alumni = use_services_alumni
        self.use_services_alt = use_services_alt

        # self.nodes is a dict from Node ID -> Node objects
        self.nodes: dict[str, Node] = {}

        # to avoid multiple entries of endpoints for same server we are keeping
        # this pointers
        self.aliases = {}

        # self.node_lookup is a dict of (fqdn, port) -> Node
        # and (ip, port) -> Node, and node.node_id -> Node
        self.node_lookup = LookupDict(LookupDict.PREFIX_MODE)

        self._seed_nodes: set[Addr_Port_TLSName] = set(seed_nodes)
        self._live_nodes: set[Addr_Port_TLSName] = set()
        self.ssl_context = ssl_context

        # crawl the cluster search for nodes in addition to the seed nodes.
        self.last_cluster_refresh_time = 0
        self.only_connect_seed = only_connect_seed
        await self._refresh_cluster()

        # to avoid same label (NODE column) for multiple nodes we need to keep track
        # of available nodes name, if names are same then we can use ip:port
        self._same_name_nodes = False

    def __str__(self):
        nodes = self.nodes.values()
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

    def get_node_displaynames(self, nodes=None):
        selected_nodes = nodes
        nodes = self.nodes.items()

        if selected_nodes:
            with_nodes = set()

            for w in selected_nodes:
                try:
                    with_nodes.update(self.get_node(w))
                except KeyError:
                    pass

            new_nodes = []

            for node_key, node in nodes:
                if node in with_nodes:
                    new_nodes.append((node_key, node))

            nodes = new_nodes

        node_names = {}
        for node_key, node in self.nodes.items():
            k = node.sock_name(use_fqdn=True)
            if util.is_valid_ip_port(k):
                node_names[node_key] = k
            else:
                node_names[node_key] = self.node_lookup.get_shortname(
                    k, min_prefix_len=20, min_suffix_len=5
                )

        return node_names

    def get_node_names(self, nodes=None):
        selected_nodes = nodes
        nodes = self.nodes.items()

        if selected_nodes:
            with_nodes = set()

            for w in selected_nodes:
                try:
                    with_nodes.update(self.get_node(w))
                except KeyError:
                    pass

            new_nodes = []

            for node_key, node in nodes:
                if node in with_nodes:
                    new_nodes.append((node_key, node))

            nodes = new_nodes

        node_names = {}

        if not self._same_name_nodes:
            for node_key, node in nodes:
                name = node.sock_name(use_fqdn=True)
                if name in list(node_names.values()):
                    # found same name for multiple nodes
                    self._same_name_nodes = True
                    node_names.clear()
                    break
                node_names[node_key] = name

        if not node_names:
            for node_key, node in self.nodes.items():
                node_names[node_key] = node.sock_name(use_fqdn=False)

        return node_names

    def get_node_ids(self, nodes=None):
        selected_nodes = set()
        node_ids = {}

        if nodes:
            for w in nodes:
                try:
                    selected_nodes.update(self.get_node(w))
                except KeyError:
                    pass

        for node_key, node in self.nodes.items():
            if not nodes or node in selected_nodes:
                node_ids[node_key] = node.node_id

        return node_ids

    def get_expected_principal(self):
        try:
            principal = "0"
            for k in self.nodes.keys():
                n = self.nodes[k]
                if n.node_id.zfill(16) > principal.zfill(16):
                    principal = n.node_id
            return principal
        except Exception as e:
            self.logger.error(e)
            return ""

    def get_live_nodes(self) -> set[Addr_Port_TLSName]:
        # TODO: why not return a reference to Node objects instead?
        return self._live_nodes

    def get_visibility_error_nodes(self):
        visible = self.get_live_nodes()
        cluster_visibility_error_nodes = []

        for k in self.nodes.keys():
            node = self.nodes[k]
            if not node.alive:
                # in case of using alumni services, we might have offline nodes
                # which can't detect online nodes
                continue
            peers = client_util.flatten(node.peers)
            not_visible = set(visible) - set(peers)

            if len(not_visible) != 1:
                cluster_visibility_error_nodes.append(node.key)

        return cluster_visibility_error_nodes

    async def get_down_nodes(self):
        cluster_down_nodes = []
        for k in self.nodes.keys():
            try:
                node = self.nodes[k]
                if not node.alive:
                    # in case of using alumni services, we might have offline
                    # nodes which can't detect online nodes
                    continue

                alumni_peers, peers, alt_peers = await asyncio.gather(
                    node.info_peers_alumni(), node.info_peers(), node.info_peers_alt()
                )
                alumni_peers = client_util.flatten(alumni_peers)
                peers = client_util.flatten(peers)
                alt_peers = client_util.flatten(alt_peers)
                not_visible = set(alumni_peers) - set(peers) - set(alt_peers)

                if len(not_visible) >= 1:
                    for n in not_visible:
                        _key = Node.create_key(n[0], n[1])
                        if _key not in cluster_down_nodes:
                            cluster_down_nodes.append(_key)
            except Exception as e:
                self.logger.debug(e, include_traceback=True)

        return cluster_down_nodes

    def update_aliases(self, aliases, endpoints, key):
        for e in endpoints:
            try:
                addr = e[0]
                port = e[1]
                node_key = Node.create_key(addr, port)
                if len(aliases) == 0 or node_key not in aliases:
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
            except Exception as e:
                self.logger.debug(e, include_traceback=True)

    async def find_new_nodes(self):
        added_endpoints = []
        peers = []
        aliases = {}
        if self.nodes:
            for node_key in list(self.nodes.keys()):
                node = self.nodes[node_key]
                await node.refresh_connection()
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

    async def _crawl(self):
        """
        Find all the nodes in the cluster and add them to self.nodes.
        """
        nodes_to_add = await self.find_new_nodes()

        self.logger.debug("Unvisited nodes: %s", nodes_to_add)

        if not nodes_to_add or len(nodes_to_add) == 0:
            return
        try:
            all_services = set()
            visited = set()
            unvisited = set(nodes_to_add)

            while unvisited - visited:
                l_unvisited = list(unvisited)
                self.logger.debug(
                    "Attempting to add nodes to the cluster: %s", l_unvisited
                )
                nodes = await client_util.concurrent_map(
                    self._register_node, l_unvisited
                )
                live_nodes = [
                    node
                    for node in nodes
                    if (node is not None and node.alive and node not in visited)
                ]

                # In the LB case, the LB seed node will be in unvisited but the actual AS node
                # will be in "nodes".  This ensures we don't visit the same node twice.
                visited |= set(
                    [
                        (node.ip, node.port, node.tls_name)
                        for node in nodes
                        if node is not None
                    ]
                )
                self.logger.debug("Added nodes to the cluster: %s", visited)
                visited |= unvisited
                unvisited.clear()

                if not self.only_connect_seed:
                    visted_nodes_peers = map(self._get_peers, live_nodes)

                    for node, peers in zip(live_nodes, visted_nodes_peers):
                        if isinstance(peers, Exception):
                            continue

                        for peer in peers:
                            # peer can be a list of tuples. Most likely just
                            # as single tuple though.
                            for s in peer:
                                all_services.add(s)

                        all_services.add((node.ip, node.port, node.tls_name))

                unvisited = all_services - visited
                self.logger.debug("Peers to add to cluster: %s", unvisited)

            self._refresh_node_liveliness()
        except Exception as e:
            self.logger.debug(e, include_traceback=True)

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
        live_nodes = [node for node in self.nodes.values() if node.alive]
        self._live_nodes.clear()
        self._live_nodes.update(
            ((node.ip, node.port, node.tls_name) for node in live_nodes)
        )

    def update_node(self, node):
        self.nodes[node.key] = node
        # add node to lookup
        self.node_lookup[node.sock_name(use_fqdn=True)] = node
        self.node_lookup[node.sock_name()] = node
        if node.alive:
            self.node_lookup[node.node_id] = node

    def get_node(self, node) -> list[Node]:
        """
        node: str, either a nodes ip, id, fqdn, or a prefix of them.
        If ends with '*' then do a prefix match which can return multiple nodes.
        If node 100% matches a known nodes (object) ip, id, or fqdn then return it.
        If node is an ip or fqdn w/o a port number then check if there is only a single node
        (object) with that given ip and return it.
        """
        if node.endswith("*"):
            return self.node_lookup[node[0:-1]]

        # Can't use "if not in self.node_lookup" here because we need to check for
        # exact matches.
        if node in self.node_lookup.keys():
            return self.node_lookup[node]

        node_matchs = self.node_lookup[node]

        if len(node_matchs) == 1:
            match_ip = node_matchs[0].ip

            if match_ip.split(":")[0] == node:
                return [node_matchs[0]]

            match_id = node_matchs[0].fqdn

            if match_id.split(":")[0] == node:
                return [node_matchs[0]]

        return []

    def get_nodes(
        self,
        nodes: Union[
            Literal["all"], Literal["random"], Literal["principal"], list[str]
        ],
    ) -> list[Node]:
        use_nodes = []

        # TODO: Make an enum to store the different nodes values
        if nodes == "all":
            use_nodes = list(self.nodes.values())
        elif nodes == "random":
            randint = random.randint(0, len(self.nodes) - 1)
            use_nodes = [list(self.nodes.values())[randint]]
        elif nodes == "principal":
            principal = self.get_expected_principal()
            use_nodes = self.get_node(principal)

        elif isinstance(nodes, list):
            for node in nodes:
                try:
                    node_list = self.get_node(node)
                    if isinstance(node_list, list):
                        use_nodes.extend(node_list)
                    else:
                        use_nodes.append(node_list)
                except Exception:  # Ignore ambiguous and key errors
                    continue
        else:
            raise TypeError("nodes should be 'all' or list found %s" % type(nodes))

        return use_nodes

    async def _register_node(self, addr_port_tls):
        if not addr_port_tls:
            return None
        if not isinstance(addr_port_tls, tuple):
            return None
        if not isinstance(addr_port_tls[0], tuple):
            return await self._create_node(addr_port_tls, force=True)

        new_node = None
        for i, a_p_t in enumerate(addr_port_tls):
            if i == len(addr_port_tls) - 1:
                new_node = await self._create_node(a_p_t, force=True)
            else:
                new_node = await self._create_node(a_p_t)
            if not new_node:
                continue
            else:
                break

        if new_node is not None:
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

    async def _create_node(self, addr_port_tls, force=False):
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
                print(
                    "ip_port is expected to be a tuple of len 2, "
                    + "instead it is of type %s and str value of %s"
                    % (type(addr_port_tls), str(addr_port_tls))
                )
                return None
        try:
            if self.is_present_as_alias(addr, port):
                # Alias entry already added for this endpoint
                n = self.get_node_for_alias(addr, port)
                if n:
                    self.logger.debug(
                        "{}:{} is present as an alias for [{},{},{}]. Do not create a new node".format(
                            addr, port, n.ip, n.tls_name, n.port
                        )
                    )
                    # Node already added for this endpoint
                    # No need to check for offline/online as we already did
                    # this while finding new nodes to add
                    return n
                # else
                # Will create node again

            # if not existing:
            new_node = await Node(
                addr,
                port,
                tls_name=tls_name,
                timeout=self._timeout,
                user=self.user,
                password=self.password,
                auth_mode=self.auth_mode,
                consider_alumni=self.use_services_alumni,
                use_services_alt=self.use_services_alt,
                ssl_context=self.ssl_context,
            )  # type: ignore

            if not new_node:
                return new_node
            if not new_node.alive:
                if not force:
                    # Check other endpoints
                    new_node.close()
                    return None
            self.update_node(new_node)
            self.update_aliases(self.aliases, new_node.service_addresses, new_node.key)
            return new_node
        except (ASInfoNotAuthenticatedError, ASProtocolError) as e:
            self.logger.error(e)
        except Exception as e:
            self.logger.debug(e, include_traceback=True)
        return None

    @staticmethod
    def _get_peers(node):
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

    async def _refresh_cluster(self):
        async with Cluster.crawl_lock:
            try:
                if self.need_to_refresh_cluster():
                    await self._crawl()
                    self.last_cluster_refresh_time = time()
            except Exception:
                raise

        return

    async def call_node_method_async(
        self, nodes, method_name, *args, **kwargs
    ) -> dict[str, Any]:
        """
        Run a particular method command across a set of nodes
        nodes is a list of nodes to to run the command against.
        if nodes is None then we run on all nodes.
        """
        if self.need_to_refresh_cluster():
            await self._refresh_cluster()

        use_nodes = self.get_nodes(nodes)

        if len(use_nodes) == 0:
            raise IOError("Unable to find any Aerospike nodes")

        async def key_to_method(node) -> tuple[str, Any]:
            node_result = getattr(node, method_name)(*args, **kwargs)

            if inspect.iscoroutine(node_result):
                return (node.key, await node_result)

            return (node.key, node_result)

        return dict(
            await client_util.concurrent_map(
                key_to_method,
                use_nodes,
            )
        )

    def call_node_method(self, nodes, method_name, *args, **kwargs) -> dict[str, Any]:
        """
        Run a particular method command across a set of nodes.
        "nodes" is a list of nodes to to run the command against.
        if nodes is None then we run on all nodes.
        """
        use_nodes = self.get_nodes(nodes)

        if len(use_nodes) == 0:
            raise IOError("Unable to find any Aerospike nodes")

        def key_to_method(node):
            node_result = getattr(node, method_name)(*args, **kwargs)

            return (node.key, node_result)

        return dict(
            map(
                key_to_method,
                use_nodes,
            )
        )

    async def is_XDR_enabled(self, nodes="all"):
        return await self.call_node_method_async(nodes, "is_XDR_enabled")

    async def is_feature_present(self, feature, nodes="all"):
        return await self.call_node_method_async(nodes, "is_feature_present", feature)

    async def get_IP_to_node_map(self):
        if self.need_to_refresh_cluster():
            await self._refresh_cluster()
        node_map = {}
        for addr, other_addr in self.aliases.items():
            try:
                node = self.nodes.get(other_addr)

                if node:
                    node_map[addr] = node.node_id
            except Exception:
                pass
        return node_map

    async def get_node_to_IP_map(self):
        if self.need_to_refresh_cluster():
            await self._refresh_cluster()
        ip_map = {}
        for addr, other_addr in self.aliases.items():
            try:
                node = self.nodes.get(other_addr)

                if not node:
                    continue

                id = node.node_id

                if id in ip_map:
                    ip_map[id].append(addr)
                else:
                    ip_map[id] = [addr]
            except Exception:
                pass

        for node, ip_list in list(ip_map.items()):
            ip_map[node] = ",".join(sorted(ip_map[node]))

        return ip_map

    def __getattr__(
        self, name
    ) -> Union[
        Callable[[Any, Any], Coroutine[Any, Any, dict[str, Any]]],
        Callable[[Any, Any], dict[str, Any]],
    ]:
        regex_async = re.compile("^info.*$|^admin.*$")
        regex_sync = re.compile("^config.*$")

        if regex_async.match(name):

            async def async_call_nodes(*args, **kwargs):
                if "nodes" not in kwargs:
                    nodes = "all"
                else:
                    nodes = kwargs["nodes"]
                    del kwargs["nodes"]

                result = await self.call_node_method_async(nodes, name, *args, **kwargs)

                if inspect.iscoroutine(result):
                    result = await result

                return result

            return async_call_nodes
        elif regex_sync.match(name):

            def call_nodes(*args, **kwargs):
                if "nodes" not in kwargs:
                    nodes = "all"
                else:
                    nodes = kwargs["nodes"]
                    del kwargs["nodes"]

                result = self.call_node_method(nodes, name, *args, **kwargs)

                return result

            return call_nodes
        else:
            raise AttributeError("Cluster has no attribute '%s'" % (name))

    async def close(self):
        for node_key in self.nodes.keys():
            try:
                node = self.nodes[node_key]
                await node.close()
            except Exception:
                pass
        self.nodes = {}
        self.node_lookup = LookupDict()

    def get_seed_nodes(self):
        return list(self._seed_nodes)
