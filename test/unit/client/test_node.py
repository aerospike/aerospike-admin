# Copyright 2013-2019 Aerospike, Inc.
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
from lib.client.node import Node

class NodeTest(unittest.TestCase):


    def get_info_mock(self, return_value, return_key_value={}):
        def info_cinfo_side_effect(*args):
            cmd = args[0]
            if cmd == "service":
                return "192.168.120.111:3000;127.0.0.1:3000"

            if cmd == "service-clear-std":
                return "172.17.0.1:3000,172.17.1.1:3000"

            if cmd == "service-tls-std":
                return "172.17.0.1:4333,172.17.1.1:4333"

            if cmd == "service-clear-alt":
                return "172.17.0.2:3000,172.17.1.2:3000"

            if cmd == "service-tls-alt":
                return "172.17.0.2:4333,172.17.1.2:4333"

            if cmd == "services":
                return "192.168.120.111:3000;127.0.0.1:3000"

            if cmd == "services-alumni":
                return "192.168.120.113:3000;127.0.0.3:3000"

            if cmd == "services-alternate":
                return "192.168.120.112:3000;127.0.0.2:3000"

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

        n = Node("127.0.0.1")
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
        socket.getaddrinfo.return_value = [(2, 1, 6, '', ('192.1.1.1', 3000))]

    #@unittest.skip("Known Failure")
    def test_init_node(self):
        """
        Ensures that we can instantiate a Node and that the node acquires the
        correct information
        """
        n = self.get_info_mock("A00000000000000")

        self.assertEqual(n.ip, '192.1.1.1', 'IP address is not correct')

        # FQDN is currently broken
        self.assertEqual(n.fqdn, 'host.domain.local', 'FQDN is not correct')

        self.assertEqual(n.port, 3000, 'Port is not correct')
        self.assertEqual(n.node_id, 'A00000000000000', 'Node Id is not correct')

    def test_info_init(self):
        """
        Ensure that when passed use_telnet false or true the appropriate _info
        function is called
        """
        n = self.get_info_mock("")

        n.info("node")
        assert n._info_cinfo.called, "_info_cinfo was not called"

    ###### Services ######

    def test_info_services(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.get_info_mock("")
        services = n.info_services()
        expected = [("192.168.120.111",3000,None), ("127.0.0.1",3000,None)]
        self.assertEqual(services, expected, "info_services did not return the expected result")

    def test_info_services_alumni(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.get_info_mock("")
        services = n.info_services_alumni()
        expected = [("192.168.120.113",3000,None), ("127.0.0.3",3000,None)]
        self.assertEqual(services, expected,
            "info_services_alumni did not return the expected result")

    def test_info_services_alt(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.get_info_mock("")
        services = n.info_services_alt()
        expected = [("192.168.120.112",3000,None), ("127.0.0.2",3000,None)]
        self.assertEqual(services, expected,
            "info_services_alt did not return the expected result")

    def test_info_peers(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.get_info_mock("")
        services = n.info_peers()
        expected = [(("172.17.0.1",3000,None),), (("2001:db8:85a3::8a2e",6666,None),)]
        self.assertEqual(services, expected,
            "info_peers did not return the expected result")
        
        n.enable_tls = True
        services = n.info_peers()
        expected = [(("172.17.0.1",4333,"peers"),), (("2001:db8:85a3::8a2e",4333,"peers"),)]
        self.assertEqual(services, expected,
            "info_peers with TLS enabled did not return the expected result")

    def test_info_peers_alumni(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.get_info_mock("")
        services = n.info_peers_alumni()
        expected = [(("172.17.0.3",3000,None),)]
        self.assertEqual(services, expected,
            "info_peers_alumni did not return the expected result")

        n.enable_tls = True
        services = n.info_peers_alumni()
        expected = [(("172.17.0.3",4333,"peers-alumni"),)]
        self.assertEqual(services, expected,
            "info_peers_alumni with TLS enabled did not return the expected result")

    def test_info_peers_alt(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.get_info_mock("")
        services = n.info_peers_alt()
        expected = [(("172.17.0.2",3000,None),)]
        self.assertEqual(services, expected,
            "info_peers_alt did not return the expected result")

        n.enable_tls = True
        services = n.info_peers_alt()
        expected = [(("172.17.0.2",4333,"peers-alt"),)]
        self.assertEqual(services, expected,
            "info_peers_alt with TLS enabled did not return the expected result")

    def test_info_peers_list(self):
        n = self.get_info_mock("")

        peers_list = n.info_peers_list()
        expected = [("192.168.120.111",3000,None), ("127.0.0.1",3000,None)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(services) did not return the expected result")

        n.use_services_alt = True
        peers_list = n.info_peers_list()
        expected = [("192.168.120.112",3000,None), ("127.0.0.2",3000,None)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(services-alt) did not return the expected result")
        n.use_services_alt = False

        n.consider_alumni = True
        peers_list = n.info_peers_list()
        expected = [("192.168.120.113",3000,None), ("127.0.0.3",3000,None)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(services-alt) did not return the expected result")
        n.consider_alumni = False

        n.use_peers_list = True

        peers_list = n.info_peers_list()
        expected = [(("172.17.0.1",3000,None),), (("2001:db8:85a3::8a2e",6666,None),)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(peers) did not return the expected result")
        n.enable_tls = True
        peers_list = n.info_peers_list()
        expected = [(("172.17.0.1",4333,"peers"),), (("2001:db8:85a3::8a2e",4333,"peers"),)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(peers with tls enabled) did not return the expected result")
        n.enable_tls = False

        n.use_services_alt = True
        peers_list = n.info_peers_list()
        expected = [(("172.17.0.2",3000,None),)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(peers-alt) did not return the expected result")
        n.enable_tls = True
        peers_list = n.info_peers_list()
        expected = [(("172.17.0.2",4333,"peers-alt"),)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(peers-alt with tls enabled) did not return the expected result")
        n.enable_tls = False
        n.use_services_alt = True

        n.consider_alumni = True
        peers_list = n.info_peers_list()
        expected = [(('172.17.0.3', 3000, None),), (('172.17.0.2', 3000, None),)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(peers-alumni) did not return the expected result")
        n.enable_tls = True
        peers_list = n.info_peers_list()
        expected = [(("172.17.0.3",4333,"peers-alumni"),), (("172.17.0.2",4333,"peers-alt"),)]
        self.assertEqual(peers_list, expected,
            "info_peers_list(peers-alumni with tls enabled) did not return the expected result")
        n.enable_tls = False
        n.consider_alumni = False

        n.use_peers_list = False

    def test_info_service_list(self):
        n = self.get_info_mock("")

        service_list = n.info_service_list()
        expected = [("192.168.120.111",3000,None), ("127.0.0.1",3000,None)]
        self.assertEqual(service_list, expected,
            "info_service_list(service) did not return the expected result")

        n.use_peers_list = True

        service_list = n.info_service_list()
        expected = [("172.17.0.1",3000,None), ("172.17.1.1",3000,None)]
        self.assertEqual(service_list, expected,
            "info_service_list(service-clear) did not return the expected result")
        n.enable_tls = True
        service_list = n.info_service_list()
        expected = [("172.17.0.1",4333,None), ("172.17.1.1",4333,None)]
        self.assertEqual(service_list, expected,
            "info_service_list(service-tls) did not return the expected result")
        n.enable_tls = False

        n.use_services_alt = True
        service_list = n.info_service_list()
        expected = [("172.17.0.2",3000,None), ("172.17.1.2",3000,None)]
        self.assertEqual(service_list, expected,
            "info_service_list(service-clear-alt) did not return the expected result")
        n.enable_tls = True
        service_list = n.info_service_list()
        expected = [("172.17.0.2",4333,None), ("172.17.1.2",4333,None)]
        self.assertEqual(service_list, expected,
            "info_service_list(service-tls-alt) did not return the expected result")
        n.enable_tls = False
        n.use_services_alt = False

        n.use_peers_list = False

    def test_info_statistics(self):
        # TODO: Currently info_statistics is mocked and cannot be unmocked
        n = self.get_info_mock("cs=2;ck=71;ci=false;o=5")
        stats = n.info_statistics()
        expected = {"cs":"2","ck":"71","ci":"false","o":"5"}
        self.assertEqual(stats, expected,
            "info_statistics error:\n_expected:\t%s\n_found:\t%s"%(expected,stats))

    def test_info_namespaces(self):
        # TODO: Currently info_namespaces is mocked and cannot be unmocked
        n = self.get_info_mock("test;bar")
        namespaces = n.info_namespaces()
        expected = ["test", "bar"]
        self.assertEqual(namespaces, expected,
            "info_namespaces error:\n_expected:\t%s\n_found:\t%s"%(expected,namespaces))

    def test_info_node(self):
        # TODO: Currently info_node is mocked and cannot be unmocked
        n = self.get_info_mock("BB96DDF04CA0568")
        node = n.info_node()
        expected = "BB96DDF04CA0568"
        self.assertEqual(node, expected,
            "info_node error:\n_expected:\t%s\n_found:\t%s"%(expected,node))

    def test_info_namespace_statistics(self):
        n = self.get_info_mock("asdf=1;b=b;c=!@#$%^&*()")
        stats = n.info_namespace_statistics("test")
        expected = {"asdf":"1", "b":"b", "c":"!@#$%^&*()"}
        self.assertEqual(stats, expected,
            "info_namespace_statistics error:\n_expected:\t%s\n_found:\t%s"%(expected,stats))
    
    def test_info_get_config(self):
        # todo call getconfig with various formats
        n = self.get_info_mock("asdf=1;b=b;c=!@#$%^&*()")
        config = n.info_get_config("service")
        expected = {"asdf":"1", "b":"b", "c":"!@#$%^&*()"}
        self.assertEqual(config, expected,
            "info_namespace_statistics error:\n_expected:\t%s\n_found:\t%s"%(expected,config))
        n._info_cinfo.assert_called_with("get-config:", n.ip)
        n.info_get_config("namespace", "test", 0)
        n._info_cinfo.assert_called_with("get-config:context=namespace;id=test", n.ip)
        n.info_namespaces = Mock()
        n.info_namespaces.return_value = ["test_two",]
        n.info_get_config("all")
        n.info_namespaces.assert_called()
        n._info_cinfo.assert_any_call(
            "get-config:context=namespace;id=test_two", n.ip)

    def test_info_latency(self):
        n = self.get_info_mock("{ns}-read:23:53:38-GMT,ops/sec,>1ms,>8ms,>64ms;23:53:48,5234.4,0.54,0.02,0.00;"
                               "{ns}-write:23:53:38-GMT,ops/sec,>1ms,>8ms,>64ms;"
                               "23:53:48,354.7,2.34,0.77,0.00;error-no-data-yet-or-back-too-small;"
                               "error-no-data-yet-or-back-too-small")

        expected = {
            'read': {
                'total': {
                    'values': [['23:53:38->23:53:48', 5234.4, 0.54, 0.02, 0.0]],
                    'columns': ['Time Span', 'ops/sec', '>1ms', '>8ms', '>64ms']
                },
                'namespace': {'ns': {
                    'values': [['23:53:38->23:53:48', 5234.4, 0.54, 0.02, 0.0]],
                    'columns': ['Time Span', 'ops/sec', '>1ms', '>8ms', '>64ms']
                    }
                }
            },
            'write': {
                'total': {
                    'values': [['23:53:38->23:53:48', 354.7, 2.34, 0.77, 0.0]], 
                    'columns': ['Time Span', 'ops/sec', '>1ms', '>8ms', '>64ms']
                },
                 'namespace': {'ns': {
                     'values': [['23:53:38->23:53:48', 354.7, 2.34, 0.77, 0.0]],
                     'columns': ['Time Span', 'ops/sec', '>1ms', '>8ms', '>64ms']}
                    }
                }
        }
        self.assertEqual(n.info_latency(), expected,
            "info_latency did not return the expected result")
        n._info_cinfo.assert_called_with("latency:", n.ip)

    def test_info_latency_with_args(self):
        n = self.get_info_mock("{ns}-read:23:50:28-GMT,ops/sec,>1ms,>8ms,>64ms;23:50:58,0.0,0.00,0.00,0.00;"
                                "23:51:28,0.0,0.00,0.00,0.00;23:51:58,0.0,0.00,0.00,0.00;"
                                "23:52:28,0.0,0.00,0.00,0.00;3:52:58,0.0,0.00,0.00,0.00;"
                                "23:53:28,0.0,0.00,0.00,0.00;23:53:58,0.0,0.00,0.00,0.00;"
                                "23:54:28,0.0,0.00,0.00,0.00;23:54:58,0.0,0.00,0.00,0.00")

        expected = {
            'read': {
                'total': {
                    'values': [
                        ['23:50:28->23:50:58', 0.0, 0.0, 0.0, 0.0],
                        ['23:50:58->23:51:28', 0.0, 0.0, 0.0, 0.0], 
                        ['23:51:28->23:51:58', 0.0, 0.0, 0.0, 0.0], 
                        ['23:51:58->23:52:28', 0.0, 0.0, 0.0, 0.0], 
                        ['23:52:28->3:52:58', 0.0, 0.0, 0.0, 0.0], 
                        ['3:52:58->23:53:28', 0.0, 0.0, 0.0, 0.0], 
                        ['23:53:28->23:53:58', 0.0, 0.0, 0.0, 0.0], 
                        ['23:53:58->23:54:28', 0.0, 0.0, 0.0, 0.0], 
                        ['23:54:28->23:54:58', 0.0, 0.0, 0.0, 0.0]
                        ], 
                    'columns': ['Time Span', 'ops/sec', '>1ms', '>8ms', '>64ms']
                }, 
                'namespace': {'ns': {
                    'values': [
                        ['23:50:28->23:50:58', 0.0, 0.0, 0.0, 0.0], 
                        ['23:50:58->23:51:28', 0.0, 0.0, 0.0, 0.0], 
                        ['23:51:28->23:51:58', 0.0, 0.0, 0.0, 0.0], 
                        ['23:51:58->23:52:28', 0.0, 0.0, 0.0, 0.0], 
                        ['23:52:28->3:52:58', 0.0, 0.0, 0.0, 0.0], 
                        ['3:52:58->23:53:28', 0.0, 0.0, 0.0, 0.0], 
                        ['23:53:28->23:53:58', 0.0, 0.0, 0.0, 0.0], 
                        ['23:53:58->23:54:28', 0.0, 0.0, 0.0, 0.0], 
                        ['23:54:28->23:54:58', 0.0, 0.0, 0.0, 0.0]
                        ], 
                    'columns': ['Time Span', 'ops/sec', '>1ms', '>8ms', '>64ms']
                    }
                }
            }
        }
        self.assertEqual(n.info_latency(back=300, duration=120, slice_tm=30), expected,
            "info_latency with args did not return the expected result")
        n._info_cinfo.assert_called_with("latency:back=300;duration=120;slice=30;", n.ip)

    def test_info_udf_list(self):
        n = self.get_info_mock("filename=basic_udf.lua,hash=706c57cb29e027221560a3cb4b693573ada98bf2,type=LUA;")
        expected = {
            'basic_udf.lua': {
                'filename': 'basic_udf.lua', 
                'hash': '706c57cb29e027221560a3cb4b693573ada98bf2', 
                'type': 'LUA'
            }
        }
        self.assertEqual(n.info_udf_list(), expected,
            "info_roster did not return the expected result")
        n._info_cinfo.assert_called_with("udf-list", n.ip)

    def test_info_roster(self):
        n = self.get_info_mock("ns=test:roster=null:pending_roster=null:observed_nodes=BB9070016AE4202,BB9060016AE4202,BB9050016AE4202,BB9040016AE4202,BB9020016AE4202")
        expected = {
            'test': {
                'observed_nodes': ['BB9070016AE4202', 'BB9060016AE4202', 'BB9050016AE4202', 'BB9040016AE4202', 'BB9020016AE4202'], 
                'ns': 'test', 
                'pending_roster': ['null'], 
                'roster': ['null']
            }
        }
        self.assertEqual(n.info_roster(), expected,
            "info_roster did not return the expected result")
        n._info_cinfo.assert_called_with("roster:", n.ip)

    def test_info_racks(self):
        n = self.get_info_mock("ns=test:rack_1=BCD10DFA9290C00,BB910DFA9290C00:rack_2=BD710DFA9290C00,BC310DFA9290C00")
        expected = {
            'test': {
                '1': {
                    'rack-id': '1',
                    'nodes': ['BCD10DFA9290C00','BB910DFA9290C00']
                },
                '2': {
                    'rack-id': '2',
                    'nodes': ['BD710DFA9290C00','BC310DFA9290C00']
                }
            }
        }
        self.assertEqual(n.info_racks(), expected,
            "info_racks did not return the expected result")
        n._info_cinfo.assert_called_with("racks:", n.ip)

    def test_info_dc_get_config(self):
        n = self.get_info_mock("dc-name=REMOTE_DC:dc-type=aerospike:tls-name=:dc-security-config-file=/private/aerospike/security_credentials_REMOTE_DC.txt:"
                                "nodes=192.168.100.140+3000,192.168.100.147+3000:int-ext-ipmap=:dc-connections=64:"
                                "dc-connections-idle-ms=55000:dc-use-alternate-services=false:namespaces=test")
        expected = {
            'REMOTE_DC': {
                'dc-security-config-file': '/private/aerospike/security_credentials_REMOTE_DC.txt',
                'tls-name': '', 
                'dc-name': 'REMOTE_DC', 
                'dc-connections-idle-ms': '55000', 
                'dc-use-alternate-services': 'false', 
                'int-ext-ipmap': '', 
                'dc-connections': '64', 
                'namespaces': 'test', 
                'nodes': '192.168.100.140+3000,192.168.100.147+3000', 
                'dc-type': 'aerospike'
            }
        }
        self.assertEqual(n.info_dc_get_config(), expected,
            "info_dc_get_config did not return the expected result")
        n._info_cinfo.assert_any_call("get-dc-config", n.ip, n.xdr_port)

        n.features = ['xdr']
        self.assertEqual(n.info_dc_get_config(), expected,
            "info_dc_get_config with xdr feature did not return the expected result")
        n._info_cinfo.assert_any_call("get-dc-config", n.ip)

    def test_info_histogram(self):
        # raw = "units=bytes:hist-width=8388608:bucket-width=8192:buckets=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,505,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"
        # "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0"
        raw = '''
         units=bytes:hist-width=8388608:bucket-width=8192:buckets=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,505,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 
        '''

        n = self.get_info_mock(raw, {'namespaces':'test'})
        expected = {
            'test': {
                # 'units': 'bytes', 
                'width': 8192, 
                'data': [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 505, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 
                'histogram': 'object-size-linear'
            }
        }
        n.new_histogram_version = True
        self.assertEqual(n.info_histogram('objsz'), expected,
            "info_histogram did not return the expected result")
        n._info_cinfo.assert_called_with("histogram:namespace=test;type=object-size-linear", n.ip)

        expected = {
            'test': raw
        }
        self.assertEqual(n.info_histogram('objsz', logarithmic=True, raw_output=True), expected,
            "info_histogram did not return the expected result")
        n._info_cinfo.assert_called_with("histogram:namespace=test;type=object-size", n.ip)
        n.info_histogram('ttl', logarithmic=True, raw_output=True)
        n._info_cinfo.assert_called_with("histogram:namespace=test;type=ttl", n.ip)

        n.new_histogram_version = False
        n.info_histogram('objsz', logarithmic=True, raw_output=True)
        n._info_cinfo.assert_called_with("hist-dump:ns=test;hist=objsz", n.ip)

if __name__ == "__main__":
    unittest.main()
