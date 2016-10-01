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

from mock import patch, Mock
import unittest2 as unittest
from lib.node import Node
import lib
import socket

class NodeTest(unittest.TestCase):
    def getInfoMock(self, return_value):
        Node._infoCInfo.return_value = return_value
        Node._infoTelnet.return_value = return_value

        n = Node("127.0.0.1")

        return n

    def setUp(self):
        info_cinfo = patch('lib.node.Node._infoCInfo')
        info_telnet = patch('lib.node.Node._infoTelnet')
        getfqdn = patch('lib.node.getfqdn')
        getaddrinfo = patch('socket.getaddrinfo')

        self.addCleanup(patch.stopall)

        Node._infoCInfo = info_cinfo.start()
        Node._infoTelnet = info_telnet.start()
        lib.node.getfqdn = getfqdn.start()
        socket.getaddrinfo = getaddrinfo.start()

        Node._infoCInfo.return_value = ""
        Node._infoTelnet.return_value = ""
        lib.node.getfqdn.return_value = "host.domain.local"
        socket.getaddrinfo.return_value = [(2, 1, 6, '', ('192.1.1.1', 3000))]

    #@unittest.skip("Known Failure")
    def testInitNode(self):
        """
        Ensures that we can instantiate a Node and that the node acquires the
        correct information
        """
        n = self.getInfoMock("A00000000000000")

        self.assertEqual(n.ip, '192.1.1.1', 'IP address is not correct')

        # FQDN is currently broken
        self.assertEqual(n.fqdn, 'host.domain.local', 'FQDN is not correct')

        self.assertEqual(n.port, 3000, 'Port is not correct')
        self.assertEqual(n.node_id, 'A00000000000000', 'Node Id is not correct')

    def testInfoInit(self):
        """
        Ensure that when passed use_telnet false or true the appropriate _info
        function is called
        """
        n = self.getInfoMock("")

        n.info("node")
        assert n._infoCInfo.called, "_infoCInfo was not called"

        n._use_telnet = True
        n.info("ndoe")
        assert n._infoTelnet.called, "_infoTelnet was not called"

    def testInfoServices(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.getInfoMock("192.168.120.111:3000;127.0.0.1:3000")
        services = n.infoServices()
        expected = [("192.168.120.111",3000,None), ("127.0.0.1",3000,None)]
        self.assertEqual(services, expected, "infoServices did not return the expected result")

    def testInfoServicesAlumni(self):
        """
        Ensure function returns a list of tuples
        """
        n = self.getInfoMock("192.168.120.111:3000;127.0.0.1:3000")
        services = n.infoServicesAlumni()
        expected = [("192.168.120.111",3000,None), ("127.0.0.1",3000,None)]
        self.assertEqual(services, expected,
            "infoServicesAlumni did not return the expected result")

    def testInfoStatistics(self):
        # TODO: Currently infoStatistics is mocked and cannot be unmocked
        n = self.getInfoMock("cs=2;ck=71;ci=false;o=5")
        stats = n.infoStatistics()
        expected = {"cs":"2","ck":"71","ci":"false","o":"5"}
        self.assertEqual(stats, expected,
            "infoStatistics error:\nExpected:\t%s\nFound:\t%s"%(expected,stats))

    def testInfoNamespaces(self):
        # TODO: Currently infoNamespaces is mocked and cannot be unmocked
        n = self.getInfoMock("test;bar")
        namespaces = n.infoNamespaces()
        expected = ["test", "bar"]
        self.assertEqual(namespaces, expected,
            "infoNamespaces error:\nExpected:\t%s\nFound:\t%s"%(expected,namespaces))

    def testInfoNode(self):
        # TODO: Currently infoNode is mocked and cannot be unmocked
        n = self.getInfoMock("BB96DDF04CA0568")
        node = n.infoNode()
        expected = "BB96DDF04CA0568"
        self.assertEqual(node, expected,
            "infoNode error:\nExpected:\t%s\nFound:\t%s"%(expected,node))

    def testInfoNamespaceStatistics(self):
        n = self.getInfoMock("asdf=1;b=b;c=!@#$%^&*()")
        stats = n.infoNamespaceStatistics("test")
        expected = {"asdf":"1", "b":"b", "c":"!@#$%^&*()"}
        self.assertEqual(stats, expected,
            "infoNamespaceStatistics error:\nExpected:\t%s\nFound:\t%s"%(expected,stats))
    
    @unittest.skip("unknown Failure")
    def testInfoGetConfig(self):
        # todo call getconfig with various formats
        n = self.getInfoMock("asdf=1;b=b;c=!@#$%^&*()")
        config = n.infoGetConfig("service")
        expected = {"service":{"asdf":"1", "b":"b", "c":"!@#$%^&*()"}}
        self.assertEqual(config, expected,
            "infoNamespaceStatistics error:\nExpected:\t%s\nFound:\t%s"%(expected,config))
        n._infoCInfo.assert_called_with("get-config:context=service")
        n.infoGetConfig("namespace", "test")
        n._infoCInfo.assert_called_with("get-config:context=namespace;id=test")
        n.infoNamespaces = Mock()
        n.infoNamespaces.return_value = ["test_two",]
        n.infoGetConfig("all")
        n.infoNamespaces.assert_called()
        n._infoCInfo.assert_anny_call(
            "get-config:context=namespace;id=test_two")

if __name__ == "__main__":
    unittest.main()
