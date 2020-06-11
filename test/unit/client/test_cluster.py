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

from mock import patch, Mock
import socket
import unittest2 as unittest

import lib
from lib.client.cluster import Cluster
from lib.client.node import Node

class ClusterTest(unittest.TestCase):
    def get_cluster_mock(self, node_count, return_key_value={}):
        cl = Cluster([("127.0.0.0", 3000, None)])
        cl.clear_node_list()

        for i in range(node_count):
            n = self.get_info_mock("A0000000000000"+str(i), return_key_value=return_key_value, ip="127.0.0."+str(i))
            cl.update_node(n)
        return cl

    def get_info_mock(self, return_value, return_key_value={}, ip="127.0.0.1"):

        if "build" not in return_key_value:
            return_key_value["build"] = "3.1.0"

        def info_cinfo_side_effect(*args):
            ip_last_digit = ip.split(".")[3]
            cmd = args[0]

            if cmd == "service":
                return str(ip)+":3000;" + "192.168.120." + ip_last_digit + ":3000"

            if cmd == "service-clear-std":
                return str(ip)+":3000;172.17.0.1:3000,172.17.1.1:3000"

            if cmd == "service-tls-std":
                return "172.17.0.1:4333,172.17.1.1:4333"

            if cmd == "service-clear-alt":
                return "172.17.0.2:3000,172.17.1.2:3000"

            if cmd == "service-tls-alt":
                return "172.17.0.2:4333,172.17.1.2:4333"

            if cmd == "services":
                return "192.168.120." + ip_last_digit + ":3000;127.0.0." + ip_last_digit + ":3000"

            if cmd == "services-alumni":
                return "192.168.123." + ip_last_digit + ":3000;127.3.0." + ip_last_digit + ":3000"

            if cmd == "services-alternate":
                return "192.168.122." + ip_last_digit + ":3000;127.2.0." + ip_last_digit + ":3000"

            if cmd == "peers-clear-std":
                return "10,3000,[[BB9050011AC4202,,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]"

            if cmd == "peers-tls-std":
                return "10,4333,[[BB9050011AC4202,peers,[172.17.0.1]],[BB9070011AC4202,peers,[[2001:db8:85a3::8a2e]]]]"

            if cmd == "alumni-clear-std":
                return "0,3000,[[BB9050011AC4202,,[172.17.0.3]]]"

            if cmd == "alumni-tls-std":
                return "0,4333,[[BB9050011AC4202,peers-alumni,[172.17.0.3]]]"

            if cmd == "peers-clear-alt":
                return "0,3000,[[BB9050011AC4202,,[172.17.0.2]]]"

            if cmd == "peers-tls-alt":
                return "0,4333,[[BB9050011AC4202,peers-alt,[172.17.0.2]]]"

            if cmd in return_key_value:
                return return_key_value[cmd]

            return return_value

        Node._info_cinfo = Mock(side_effect=info_cinfo_side_effect)
        # Node._info_cinfo.return_value = side_effect

        n = Node(ip)
        return n

    def setUp(self):
        info_cinfo = patch('lib.client.node.Node._info_cinfo')
        getfqdn = patch('lib.client.node.getfqdn')
        getaddrinfo = patch('socket.getaddrinfo')

        self.addCleanup(patch.stopall)

        lib.client.node.Node._info_cinfo = info_cinfo.start()
        lib.client.node.getfqdn = getfqdn.start()
        socket.getaddrinfo = getaddrinfo.start()

        Node._info_cinfo.return_value = ""
        lib.client.node.getfqdn.return_value = "host.domain.local"
        def getaddressinfo_side_effect(*args):
            return [(2, 1, 6, '', (args[0], 3000))]

        socket.getaddrinfo = Mock(side_effect=getaddressinfo_side_effect)
        # socket.getaddrinfo.return_value = [(2, 1, 6, '', ("192.1.1.1", 3000))]

    def test_get_node_displaynames(self):
        cl = self.get_cluster_mock(0)
        expected = {'127.0.0.0:3000': 'host.domain.local:3000'}
        self.assertEqual(cl.get_node_displaynames(), expected, "get_node_displaynames did not return the expected result")

    def test_get_node_names(self):
        cl = self.get_cluster_mock(0)
        expected = {'127.0.0.0:3000': 'host.domain.local:3000'}
        self.assertEqual(cl.get_node_names(), expected, "get_node_names did not return the expected result")

    def test_get_expected_principal(self):
        cl = self.get_cluster_mock(3)
        expected = "A00000000000002"
        self.assertEqual(cl.get_expected_principal(), expected, "get_expected_principal did not return the expected result")

    def test_get_visibility_error_nodes(self):
        cl = self.get_cluster_mock(3)

        expected = ['127.0.0.0:3000']
        self.assertEqual(cl.get_visibility_error_nodes(), expected, "get_visibility_error_nodes did not return the expected result")

        cl._live_nodes = ['127.0.0.1:3000', '127.0.0.2:3000', '127.0.0.0:3000']
        expected = ['127.0.0.1:3000', '127.0.0.2:3000', '127.0.0.0:3000']
        self.assertEqual(sorted(cl.get_visibility_error_nodes()), sorted(expected), "get_visibility_error_nodes did not return the expected result")

    def test_get_down_nodes(self):
        cl = self.get_cluster_mock(3)

        expected = ['192.168.123.2:3000', '127.3.0.2:3000']
        self.assertEqual(sorted(cl.get_down_nodes()), sorted(expected), "get_down_nodes did not return the expected result")

    def test_update_aliases(self):
        cl = self.get_cluster_mock(3)
        aliases = {}
        endpoints = [('127.0.0.1', 3000)]
        key1 = Node.create_key('127.0.0.2', 3000)
        cl.update_aliases(aliases, endpoints, key1)
        expected = {'127.0.0.1:3000': '127.0.0.2:3000'}
        self.assertEqual(aliases, expected, "update_aliases did not return the expected result")

        key2 = Node.create_key('127.0.0.3', 3000)
        cl.update_aliases(aliases, endpoints, key2)
        self.assertEqual(aliases, expected, "update_aliases did not return the expected result")

        n = cl.nodes[key1]
        n.alive = False
        cl.nodes[key1] = n
        cl.update_aliases(aliases, endpoints, key2)
        expected = {'127.0.0.1:3000': '127.0.0.3:3000'}
        self.assertEqual(aliases, expected, "update_aliases did not return the expected result")

    def test_clear_node_list(self):
        cl = self.get_cluster_mock(3)
        aliases = cl.aliases
        cl.aliases = {'127.0.0.1:3000': '127.0.0.2:3000', '127.0.0.2:3000':'127.0.0.2:3000', '127.0.0.0:3000':'127.0.0.0:3000'}
        cl.clear_node_list()
        self.assertEqual(len(cl.nodes), 2, "clear_node_list did not return the expected result")
        cl.aliases = aliases

    def test_call_node_method(self):
        cl = self.get_cluster_mock(2)

        cl.call_node_method(nodes='all', method_name='info_peers')
        for n in cl.nodes.values():
            n._info_cinfo.assert_any_call('peers-clear-std', n.ip)

        key = '127.0.0.1:3000'
        cl.call_node_method(nodes=[key], method_name='info', command='build')
        n = cl.get_node(key)[0]
        n._info_cinfo.assert_called_with('build', n.ip)

    def test_is_XDR_enabled(self):
        cl = self.get_cluster_mock(2, return_key_value={'get-config:context=xdr': 'enable-xdr=true;config1=config1value;'})
        expected = {'127.0.0.1:3000': True, '127.0.0.0:3000': True}
        self.assertEqual(cl.is_XDR_enabled(), expected, "is_XDR_enabled(nodes=all) did not return the expected result")

        cl = self.get_cluster_mock(2, return_key_value={'get-config:context=xdr': 'enable-xdr=false;config1=config1value;'})
        key = '127.0.0.1:3000'
        expected = {key : False}
        self.assertEqual(cl.is_XDR_enabled(nodes=[key]), expected, "is_XDR_enabled did not return the expected result")

    def test_is_feature_present(self):
        cl = self.get_cluster_mock(2, return_key_value={'features': 'batch-index;blob-bits;cdt-list;cdt-map;cluster-stable;float;geo;'})
        expected = {'127.0.0.1:3000': True, '127.0.0.0:3000': True}
        self.assertEqual(cl.is_feature_present('cdt-map'), expected, "is_feature_present(nodes=all) did not return the expected result")

        cl = self.get_cluster_mock(2, return_key_value={'features': 'batch-index;blob-bits;cdt-list;cdt-map;cluster-stable;float;geo;'})
        key = '127.0.0.1:3000'
        expected = {key : False}
        self.assertEqual(cl.is_feature_present('wrongFeature', nodes=[key]), expected, "is_feature_present did not return the expected result")

    def test_get_IP_to_node_map(self):
        cl = self.get_cluster_mock(3)
        aliases = cl.aliases
        cl.aliases = {'127.0.0.1:3000': '127.0.0.2:3000', '127.0.0.2:3000':'127.0.0.2:3000', '127.0.0.0:3000':'127.0.0.0:3000'}
        expected = {'127.0.0.1:3000': 'A00000000000002', '127.0.0.2:3000': 'A00000000000002', '127.0.0.0:3000': 'A00000000000000'}
        self.assertEqual(cl.get_IP_to_node_map(), expected, "get_IP_to_node_map did not return the expected result")
        cl.aliases = aliases

    def test_get_node_to_IP_map(self):
        cl = self.get_cluster_mock(3)
        aliases = cl.aliases
        cl.aliases = {'127.0.0.1:3000': '127.0.0.2:3000', '127.0.0.2:3000':'127.0.0.2:3000', '127.0.0.0:3000':'127.0.0.0:3000'}
        expected = {'A00000000000002': '127.0.0.1:3000, 127.0.0.2:3000', 'A00000000000000': '127.0.0.0:3000'}
        self.assertEqual(cl.get_node_to_IP_map(), expected, "get_node_to_IP_map did not return the expected result")
        cl.aliases = aliases

    def test_get_seed_nodes(self):
        cl = self.get_cluster_mock(3)
        expected = [('127.0.0.0', 3000, None)]
        self.assertEqual(cl.get_seed_nodes(), expected, "get_seed_nodes did not return the expected result")