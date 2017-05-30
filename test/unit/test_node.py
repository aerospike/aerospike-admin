# Copyright 2013-2017 Aerospike, Inc.
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
    def get_info_mock(self, return_value):
        Node._info_cinfo.return_value = return_value

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

    def test_info_services(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.get_info_mock("192.168.120.111:3000;127.0.0.1:3000")
        services = n.info_services()
        expected = [("192.168.120.111",3000,None), ("127.0.0.1",3000,None)]
        self.assertEqual(services, expected, "info_services did not return the expected result")

    def test_info_services_alumni(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.get_info_mock("192.168.120.111:3000;127.0.0.1:3000")
        services = n.info_services_alumni()
        expected = [("192.168.120.111",3000,None), ("127.0.0.1",3000,None)]
        self.assertEqual(services, expected,
            "info_services_alumni did not return the expected result")

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
    
    @unittest.skip("unknown Failure")
    def test_info_get_config(self):
        # todo call getconfig with various formats
        n = self.get_info_mock("asdf=1;b=b;c=!@#$%^&*()")
        config = n.info_get_config("service")
        expected = {"service":{"asdf":"1", "b":"b", "c":"!@#$%^&*()"}}
        self.assertEqual(config, expected,
            "info_namespace_statistics error:\n_expected:\t%s\n_found:\t%s"%(expected,config))
        n._info_cinfo.assert_called_with("get-config:context=service")
        n.info_get_config("namespace", "test")
        n._info_cinfo.assert_called_with("get-config:context=namespace;id=test")
        n.info_namespaces = Mock()
        n.info_namespaces.return_value = ["test_two",]
        n.info_get_config("all")
        n.info_namespaces.assert_called()
        n._info_cinfo.assert_anny_call(
            "get-config:context=namespace;id=test_two")

if __name__ == "__main__":
    unittest.main()
