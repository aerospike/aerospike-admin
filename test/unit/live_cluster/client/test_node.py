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

from ctypes import ArgumentError
from lib.live_cluster.client.config_handler import BoolConfigType, IntConfigType
from mock import MagicMock, patch
import socket
import unittest

import lib
from test.unit import util
from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.node import (
    ASINFO_RESPONSE_OK,
    ASInfoConfigError,
    ASInfoError,
    Node,
)


class ASInfoErrorTest(unittest.TestCase):
    def test_raises_exception_with_ok(self):
        util.assert_exception(
            self,
            ValueError,
            'info() returned value "ok" which is not an error.',
            ASInfoError,
            "message",
            "ok",
        )

        util.assert_exception(
            self,
            ValueError,
            'info() returned value "ok" which is not an error.',
            ASInfoError,
            "message",
            "OK",
        )

        util.assert_exception(
            self,
            ValueError,
            'info() returned value "ok" which is not an error.',
            ASInfoError,
            "message",
            "",
        )

    def test_creates_str(self):
        message = "test message"
        responses = [
            "error=a-white-whale",
            "ERROR=a-white-whale.",
            "ERROR:1234:a-white-whale",
            "ERROR::a-white-whale",
            "error:1234:a-white-whale.",
            "error::a-white-whale",
            "fail:1234:a-white-whale.",
            "FAIL::a-white-whale",
            "error:1234:a-white-whale.",
            "error::a-white-whale",
        ]
        exp_string = "test message : a-white-whale."

        for response in responses:
            error = ASInfoError(message, response)
            self.assertEqual(
                str(error), exp_string, "Fail caused by {}".format(response)
            )

    def test_create_unknow_error_str(self):
        message = "test message"
        responses = [
            "error",
            "ERROR",
            "fail",
            "FAIL",
        ]
        exp_string = "test message : Unknown error occurred."

        for response in responses:
            error = ASInfoError(message, response)
            self.assertEqual(
                str(error), exp_string, "Fail caused by {}".format(response)
            )


class ASInfoConfigErrorTest(unittest.TestCase):
    def setUp(self):
        self.node_mock = MagicMock()
        self.test_message = "this is a test message"

    def test_invalid_subcontext(self):
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        expected = "this is a test message : Invalid subcontext bar4."

        actual = ASInfoConfigError(
            self.test_message,
            "irrelevant",
            self.node_mock,
            ["foo2", "blah1", "bar4"],
            "irrelevant",
            "irrelevant",
        )

        self.assertEqual(str(actual), expected)

    def test_invalid_param(self):
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = None
        expected = "this is a test message : Invalid parameter."

        actual = ASInfoConfigError(
            self.test_message,
            "irrelevant",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "bad-param",
            "irrelevant",
        )

        self.assertEqual(str(actual), expected)

    def test_param_is_not_dynamic(self):
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = BoolConfigType(False)
        expected = "this is a test message : Parameter is not dynamically configurable."

        actual = ASInfoConfigError(
            self.test_message,
            "irrelevant",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "bad-param",
            "irrelevant",
        )

        self.assertEqual(str(actual), expected)

    def test_invalid_value(self):
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = IntConfigType(
            0,
            10,
            True,
        )
        expected = "this is a test message : Invalid value for Int(min: 0, max: 10)."

        actual = ASInfoConfigError(
            self.test_message,
            "irrelevant",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "good-param",
            -2,
        )

        self.assertEqual(str(actual), expected)

    def test_unknown_error(self):
        """
        This is when the server sends back ambiguous error message but a problem could not
        be found with context, param, or value.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = IntConfigType(
            0,
            10,
            True,
        )
        expected = "this is a test message : this-is-the-reason."

        actual = ASInfoConfigError(
            self.test_message,
            "error::this-is-the-reason",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "good-param",
            5,
        )

        self.assertEqual(str(actual), expected)

    def test_error_with_message(self):
        """
        This is when the server sends back error message with a reason AND a problem
        could not be found with context, param, or value.
        """
        self.node_mock.config_subcontext.side_effect = [
            ["foo1", "foo2", "foo3"],
            ["blah1", "blah2", "blah3"],
            ["bar1", "bar2", "bar3"],
        ]
        self.node_mock.config_type.return_value = IntConfigType(
            0,
            10,
            True,
        )
        expected = "this is a test message : Unknown error occurred."

        actual = ASInfoConfigError(
            self.test_message,
            "error",
            self.node_mock,
            ["foo2", "blah1", "bar3"],
            "good-param",
            5,
        )

        self.assertEqual(str(actual), expected)


class NodeTest(unittest.TestCase):
    def setUp(self):
        self.maxDiff = None
        self.ip = "192.1.1.1"
        info_build_version = patch(
            "lib.live_cluster.client.node.Node.info_build_version"
        )
        self.get_fully_qualified_domain_name = patch(
            "lib.live_cluster.client.node.get_fully_qualified_domain_name"
        ).start()

        getaddrinfo = patch("socket.getaddrinfo")

        self.addCleanup(patch.stopall)

        lib.live_cluster.client.node.Node.info_build_version = (
            info_build_version.start()
        )
        socket.getaddrinfo = getaddrinfo.start()

        lib.live_cluster.client.node.Node.info_build_version.return_value = "5.0.0.11"
        self.get_fully_qualified_domain_name.return_value = "host.domain.local"
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.1.1.1", 3000))]

        self.node = Node(self.ip)

        # Here so call count does not include Node initialization
        self.info_mock = patch("lib.live_cluster.client.node.Node._info_cinfo").start()
        self.node.conf_schema_handler = MagicMock()

    def test_init_node(self):
        """
        Ensures that we can instantiate a Node and that the node acquires the
        correct information
        """

        def side_effect(*args):
            cmd = args[0]

            if cmd == "node":
                return "A00000000000000"
            elif cmd == "service":
                return "192.3.3.3:4567"
            else:
                return "5.0.0.11"

        self.info_mock.side_effect = side_effect
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.3.3.3", 4567))]

        n = Node("192.1.1.1")

        self.assertEqual(n.ip, "192.3.3.3", "IP address is not correct")
        self.assertEqual(n.fqdn, "host.domain.local", "FQDN is not correct")
        self.assertEqual(n.port, 4567, "Port is not correct")
        self.assertEqual(n.node_id, "A00000000000000", "Node Id is not correct")

    ###### Services ######

    def test_info_services(self):
        """
        Ensure function returns a list of tuples
        """

        self.info_mock.return_value = "192.168.120.111:3000;127.0.0.1:3000"
        expected = [("192.168.120.111", 3000, None), ("127.0.0.1", 3000, None)]

        services = self.node.info_services()

        self.info_mock.assert_called_with("services", self.ip)
        self.assertEqual(
            services, expected, "info_services did not return the expected result"
        )

    def test_info_services_alumni(self):
        """
        Ensure function returns a list of tuples
        """
        self.info_mock.return_value = "192.168.120.113:3000;127.0.0.3:3000"
        expected = [("192.168.120.113", 3000, None), ("127.0.0.3", 3000, None)]

        services = self.node.info_services_alumni()

        self.info_mock.assert_called_with("services-alumni", self.ip)
        self.assertEqual(
            services,
            expected,
            "info_services_alumni did not return the expected result",
        )

    def test_info_services_alternate(self):
        """
        Ensure function returns a list of tuples
        """
        self.info_mock.return_value = "192.168.120.112:3000;127.0.0.2:3000"
        expected = [("192.168.120.112", 3000, None), ("127.0.0.2", 3000, None)]

        services = self.node.info_services_alt()

        self.info_mock.assert_called_with("services-alternate", self.ip)
        self.assertEqual(
            services, expected, "info_services_alt did not return the expected result"
        )

    def test_info_peers(self):
        """
        Ensure function returns a list of tuples
        """
        self.info_mock.return_value = "10,3000,[[BB9050011AC4202,,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]"
        expected = [
            (("172.17.0.1", 3000, None),),
            (("2001:db8:85a3::8a2e", 6666, None),),
        ]

        services = self.node.info_peers()

        self.info_mock.assert_called_with("peers-clear-std", self.ip)
        self.assertEqual(
            services, expected, "info_peers did not return the expected result"
        )

        self.info_mock.return_value = "10,4333,[[BB9050011AC4202,peers,[172.17.0.1]],[BB9070011AC4202,peers,[[2001:db8:85a3::8a2e]]]]"
        self.node.enable_tls = True
        expected = [
            (("172.17.0.1", 4333, "peers"),),
            (("2001:db8:85a3::8a2e", 4333, "peers"),),
        ]

        services = self.node.info_peers()

        self.info_mock.assert_called_with("peers-tls-std", "192.1.1.1")
        self.assertEqual(
            services,
            expected,
            "info_peers with TLS enabled did not return the expected result",
        )

    def test_info_peers_alumni(self):
        """
        Ensure function returns a list of tuples
        """
        self.info_mock.return_value = "0,3000,[[BB9050011AC4202,,[172.17.0.3]]]"
        expected = [(("172.17.0.3", 3000, None),)]

        services = self.node.info_peers_alumni()

        self.info_mock.assert_called_with("alumni-clear-std", "192.1.1.1")
        self.assertEqual(
            services, expected, "info_peers_alumni did not return the expected result"
        )

        self.info_mock.return_value = (
            "0,4333,[[BB9050011AC4202,peers-alumni,[172.17.0.3]]]"
        )
        self.node.enable_tls = True
        expected = [(("172.17.0.3", 4333, "peers-alumni"),)]

        services = self.node.info_peers_alumni()

        self.info_mock.assert_called_with("alumni-tls-std", "192.1.1.1")
        self.assertEqual(
            services,
            expected,
            "info_peers_alumni with TLS enabled did not return the expected result",
        )

    def test_info_peers_alt(self):
        """
        Ensure function returns a list of tuples
        """
        self.info_mock.return_value = "0,3000,[[BB9050011AC4202,,[172.17.0.2]]]"
        expected = [(("172.17.0.2", 3000, None),)]

        services = self.node.info_peers_alt()

        self.info_mock.assert_called_with("peers-clear-alt", "192.1.1.1")
        self.assertEqual(
            services, expected, "info_peers_alt did not return the expected result"
        )

        self.info_mock.return_value = (
            "0,4333,[[BB9050011AC4202,peers-alt,[172.17.0.2]]]"
        )
        self.node.enable_tls = True
        expected = [(("172.17.0.2", 4333, "peers-alt"),)]

        services = self.node.info_peers_alt()

        self.info_mock.assert_called_with("peers-tls-alt", "192.1.1.1")
        self.assertEqual(
            services,
            expected,
            "info_peers_alt with TLS enabled did not return the expected result",
        )

    def test_info_peers_list(self):
        self.info_mock.return_value = "192.168.120.111:3000;127.0.0.1:3000"
        expected = [("192.168.120.111", 3000, None), ("127.0.0.1", 3000, None)]

        peers_list = self.node.info_peers_list()

        self.info_mock.assert_called_with("services", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(services) did not return the expected result",
        )

        self.info_mock.return_value = "192.168.120.112:3000;127.0.0.2:3000"
        self.node.use_services_alt = True
        expected = [("192.168.120.112", 3000, None), ("127.0.0.2", 3000, None)]

        peers_list = self.node.info_peers_list()

        self.info_mock.assert_called_with("services-alternate", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(services-alt) did not return the expected result",
        )

        self.node.use_services_alt = False
        self.info_mock.return_value = "192.168.120.113:3000;127.0.0.3:3000"
        self.node.consider_alumni = True
        expected = [("192.168.120.113", 3000, None), ("127.0.0.3", 3000, None)]

        peers_list = self.node.info_peers_list()

        self.info_mock.assert_called_with("services-alumni", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(services-alt) did not return the expected result",
        )

        self.node.consider_alumni = False
        self.info_mock.return_value = "10,3000,[[BB9050011AC4202,,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]"
        self.node.use_peers_list = True
        expected = [
            (("172.17.0.1", 3000, None),),
            (("2001:db8:85a3::8a2e", 6666, None),),
        ]

        peers_list = self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-clear-std", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers) did not return the expected result",
        )

        self.info_mock.return_value = "10,4333,[[BB9050011AC4202,peers,[172.17.0.1]],[BB9070011AC4202,peers,[[2001:db8:85a3::8a2e]]]]"
        self.node.enable_tls = True
        expected = [
            (("172.17.0.1", 4333, "peers"),),
            (("2001:db8:85a3::8a2e", 4333, "peers"),),
        ]

        peers_list = self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-tls-std", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers with tls enabled) did not return the expected result",
        )

        self.node.enable_tls = False
        self.info_mock.return_value = "0,3000,[[BB9050011AC4202,,[172.17.0.2]]]"
        self.node.use_services_alt = True
        expected = [(("172.17.0.2", 3000, None),)]

        peers_list = self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-clear-alt", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alt) did not return the expected result",
        )

        self.info_mock.return_value = (
            "0,4333,[[BB9050011AC4202,peers-alt,[172.17.0.2]]]"
        )
        self.node.enable_tls = True
        expected = [(("172.17.0.2", 4333, "peers-alt"),)]

        peers_list = self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-tls-alt", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alt with tls enabled) did not return the expected result",
        )

        self.info_mock.reset_mock()
        self.node.enable_tls = False
        self.info_mock.side_effect = [
            "0,3000,[[BB9050011AC4202,,[172.17.0.3]]]",
            "0,3000,[[BB9050011AC4202,,[172.17.0.2]]]",
        ]
        self.node.use_services_alt = True
        self.node.consider_alumni = True
        expected = [(("172.17.0.3", 3000, None),), (("172.17.0.2", 3000, None),)]

        peers_list = self.node.info_peers_list()

        self.assertEqual(self.info_mock.call_count, 2)
        self.info_mock.assert_any_call("alumni-clear-std", "192.1.1.1")
        self.info_mock.assert_any_call("peers-clear-alt", "192.1.1.1")

        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alumni) did not return the expected result",
        )

        self.info_mock.reset_mock()
        self.info_mock.side_effect = [
            "0,4333,[[BB9050011AC4202,peers-alumni,[172.17.0.3]]]",
            "0,4333,[[BB9050011AC4202,peers-alt,[172.17.0.2]]]",
        ]
        self.node.enable_tls = True
        expected = [
            (("172.17.0.3", 4333, "peers-alumni"),),
            (("172.17.0.2", 4333, "peers-alt"),),
        ]

        peers_list = self.node.info_peers_list()

        self.assertEqual(self.info_mock.call_count, 2)
        self.info_mock.assert_any_call("alumni-tls-std", "192.1.1.1")
        self.info_mock.assert_any_call("peers-tls-alt", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alumni with tls enabled) did not return the expected result",
        )

        self.node.enable_tls = False
        self.node.consider_alumni = False
        self.node.use_peers_list = False

    def test_info_service_list(self):
        self.info_mock.return_value = "192.168.120.111:3000;127.0.0.1:3000"
        expected = [("192.168.120.111", 3000, None), ("127.0.0.1", 3000, None)]

        service_list = self.node.info_service_list()

        self.info_mock.assert_called_with("service", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service) did not return the expected result",
        )

        self.info_mock.return_value = "172.17.0.1:3000,172.17.1.1:3000"
        self.node.use_peers_list = True
        expected = [("172.17.0.1", 3000, None), ("172.17.1.1", 3000, None)]

        service_list = self.node.info_service_list()

        self.info_mock.assert_called_with("service-clear-std", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service-clear) did not return the expected result",
        )

        self.info_mock.return_value = "172.17.0.1:4333,172.17.1.1:4333"
        self.node.enable_tls = True
        expected = [("172.17.0.1", 4333, None), ("172.17.1.1", 4333, None)]

        service_list = self.node.info_service_list()

        self.info_mock.assert_called_with("service-tls-std", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service-tls) did not return the expected result",
        )

        self.node.enable_tls = False
        self.info_mock.return_value = "172.17.0.2:3000,172.17.1.2:3000"
        self.node.use_services_alt = True
        expected = [("172.17.0.2", 3000, None), ("172.17.1.2", 3000, None)]

        service_list = self.node.info_service_list()

        self.info_mock.assert_called_with("service-clear-alt", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service-clear-alt) did not return the expected result",
        )

        self.node.enable_tls = True
        self.info_mock.return_value = "172.17.0.2:4333,172.17.1.2:4333"
        expected = [("172.17.0.2", 4333, None), ("172.17.1.2", 4333, None)]

        service_list = self.node.info_service_list()

        self.info_mock.assert_called_with("service-tls-alt", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service-tls-alt) did not return the expected result",
        )

        self.node.enable_tls = False
        self.node.use_services_alt = False
        self.node.use_peers_list = False

    def test_info_statistics(self):
        self.info_mock.return_value = "cs=2;ck=71;ci=false;o=5"
        expected = {"cs": "2", "ck": "71", "ci": "false", "o": "5"}

        stats = self.node.info_statistics()

        self.info_mock.assert_called_with("statistics", self.ip)
        self.assertEqual(
            stats,
            expected,
            "info_statistics error:\n_expected:\t%s\n_found:\t%s" % (expected, stats),
        )

    def test_info_namespaces(self):
        self.info_mock.return_value = "test;bar"
        expected = ["test", "bar"]

        namespaces = self.node.info_namespaces()

        self.info_mock.assert_called_with("namespaces", self.ip)
        self.assertEqual(
            namespaces,
            expected,
            "info_namespaces error:\n_expected:\t%s\n_found:\t%s"
            % (expected, namespaces),
        )

    def test_info_node(self):
        self.info_mock.return_value = "BB96DDF04CA0568"
        expected = "BB96DDF04CA0568"

        node = self.node.info_node()

        self.info_mock.assert_called_with("node", self.ip)
        self.assertEqual(
            node,
            expected,
            "info_node error:\n_expected:\t%s\n_found:\t%s" % (expected, node),
        )

    def test_info_namespace_statistics(self):
        self.info_mock.return_value = "asdf=1;b=b;c=!@#$%^&*()"
        expected = {"asdf": "1", "b": "b", "c": "!@#$%^&*()"}

        stats = self.node.info_namespace_statistics("test")

        self.info_mock.assert_called_with("namespace/test", self.ip)
        self.assertEqual(
            stats,
            expected,
            "info_namespace_statistics error:\n_expected:\t%s\n_found:\t%s"
            % (expected, stats),
        )

    def test_info_all_namespace_statistics(self):
        self.info_mock.side_effect = [
            "foo;bar",
            "asdf=1;b=b;c=!@#$%^&*()",
            "cdef=2;c=c;d=)(*&^%$#@!",
        ]
        expected = {
            "foo": {"asdf": "1", "b": "b", "c": "!@#$%^&*()"},
            "bar": {"cdef": "2", "c": "c", "d": ")(*&^%$#@!"},
        }

        actual = self.node.info_all_namespace_statistics()

        self.assertEqual(self.info_mock.call_count, 3)
        self.info_mock.assert_any_call("namespaces", self.ip)
        self.info_mock.assert_any_call("namespace/foo", self.ip)
        self.info_mock.assert_any_call("namespace/bar", self.ip)
        self.assertEqual(actual, expected)

    def info_all_namespace_statistics(self):
        self.info_mock.return_value = (
            "ns=test:set=jar-set:objects=1:tombstones=2:"
            "memory_data_bytes=3:device_data_bytes=4:truncate_lut=5:"
            "stop-writes-count=6:disable-eviction=false;ns=test:set=testset:"
            "objects=7:tombstones=8:memory_data_bytes=9:"
            "device_data_bytes=10:truncate_lut=11:stop-writes-count=12:"
            "disable-eviction=true;"
        )
        expected = {
            ("test", "jar-set"): {
                "object": "1",
                "tombstones": "2",
                "memory_data_bytes": "3",
                "device_data_bytes": "4",
                "truncate_lut": "5",
                "stop-writes-count": "6",
                "disable-eviction": "false",
            },
            ("test", "testset"): {
                "object": "7",
                "tombstones": "8",
                "memory_data_bytes": "9",
                "device_data_bytes": "10",
                "truncate_lut": "11",
                "stop-writes-count": "12",
                "disable-eviction": "true",
            },
        }

        actual = self.node.info_all_set_statistics()

        self.info_mock.assert_called_with("sets")
        self.assertDictEqual(actual, expected)

    def test_info_health_outliers(self):
        self.info_mock.return_value = (
            "id=bb9040011ac4202:confidence_pct=100:"
            "reason=fabric_connections_opened;id=bb9040011ac4203:"
            "confidence_pct=100:reason=proxies;id=bb9040011ac4204:"
            "confidence_pct=100:reason=node_arrivals"
        )
        expected = {
            "outlier0": {
                "id": "bb9040011ac4202",
                "confidence_pct": "100",
                "reason": "fabric_connections_opened",
            },
            "outlier1": {
                "id": "bb9040011ac4203",
                "confidence_pct": "100",
                "reason": "proxies",
            },
            "outlier2": {
                "id": "bb9040011ac4204",
                "confidence_pct": "100",
                "reason": "node_arrivals",
            },
        }

        actual = self.node.info_health_outliers()

        self.info_mock.assert_called_with("health-outliers", self.ip)
        self.assertDictEqual(actual, expected)

    def test_info_bin_statistics(self):
        self.info_mock.return_value = (
            "test:bin_names=1,bin_names_quota=2,3,name,"
            "age;bar:bin_names=5,bin_names_quota=6,age;"
        )
        expected = {
            "test": {"bin_names": "1", "bin_names_quota": "2"},
            "bar": {"bin_names": "5", "bin_names_quota": "6"},
        }

        actual = self.node.info_bin_statistics()

        self.info_mock.assert_called_with("bins", self.ip)
        self.assertDictEqual(actual, expected)

    def test_info_XDR_statistics_with_server_before_5(self):
        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.9"
        self.info_mock.side_effect = ["a=b;c=1;2=z"]
        expected = {"a": "b", "c": "1", "2": "z"}
        actual = self.node.info_XDR_statistics()

        self.assertEqual(self.info_mock.call_count, 1)
        self.info_mock.assert_any_call("statistics", self.ip, self.node.xdr_port)
        self.assertDictEqual(actual, expected)

        self.info_mock.reset_mock()
        lib.live_cluster.client.node.Node.info_build_version.return_value = "2.5.6"
        self.info_mock.side_effect = ["a=b;c=1;2=z"]
        self.node.features = "xdr"
        expected = {"a": "b", "c": "1", "2": "z"}

        actual = self.node.info_XDR_statistics()

        self.assertEqual(self.info_mock.call_count, 1)
        self.info_mock.assert_any_call("statistics/xdr", self.ip)
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_all_dc_statistics")
    def test_info_XDR_statistics_with_server_after_5(self, info_all_dc_statistics_mock):
        info_all_dc_statistics_mock.return_value = "blah"
        expected = "blah"

        actual = self.node.info_XDR_statistics()

        self.assertEqual(
            lib.live_cluster.client.node.Node.info_build_version.call_count, 2
        )
        self.assertEqual(info_all_dc_statistics_mock.call_count, 1)
        self.assertEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    def test_info_set_config_xdr_create_dc_success(self, info_dcs_mock):
        info_dcs_mock.return_value = ["DC2", "DC3"]
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_create_dc("DC1")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;action=create", self.ip
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.9"
        info_dcs_mock.return_value = ["DC2", "DC3"]
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_create_dc("DC1")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;action=create", self.ip
        )
        self.assertEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    def test_info_set_config_xdr_create_dc_fail(self, info_dcs_mock):
        info_dcs_mock.return_value = ["DC1", "DC2", "DC3"]

        actual = self.node.info_set_config_xdr_create_dc("DC1")

        self.assertEqual(
            str(actual), "Failed to create XDR datacenter : DC already exists."
        )

        info_dcs_mock.return_value = ["DC2", "DC3"]
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_xdr_create_dc("DC1")

        self.assertEqual(
            str(actual), "Failed to create XDR datacenter : Unknown error occurred."
        )

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    def test_info_set_config_xdr_delete_dc_success(self, info_dcs_mock):
        info_dcs_mock.return_value = ["DC1", "DC2"]
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_delete_dc("DC1")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;action=delete", self.ip
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.9"
        info_dcs_mock.return_value = ["DC1", "DC2"]
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_delete_dc("DC1")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;action=delete", self.ip
        )
        self.assertEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    def test_info_set_config_xdr_delete_dc_fail(self, info_dcs_mock):
        info_dcs_mock.return_value = ["DC2", "DC3"]

        actual = self.node.info_set_config_xdr_delete_dc("DC1")

        self.assertEqual(actual.message, "Failed to delete XDR datacenter")
        self.assertEqual(actual.response, "DC does not exist")

        info_dcs_mock.return_value = ["DC1", "DC2", "DC3"]
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_xdr_delete_dc("DC1")

        self.assertEqual(actual.message, "Failed to delete XDR datacenter")
        self.assertEqual(actual.response, "Unknown error occurred")

    def test_info_set_config_xdr_add_namespace_success(self):
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_add_namespace("DC1", "ns")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;namespace=ns;action=add", self.ip
        )
        self.assertEqual(actual, expected)

        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_xdr_add_namespace(
            "DC1", "ns", rewind="12345"
        )

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;namespace=ns;action=add;rewind=12345",
            self.ip,
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.3.5.8"
        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_xdr_add_namespace(
            "DC1", "ns", rewind="12345"
        )

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;namespace=ns;action=add;rewind=12345",
            self.ip,
        )
        self.assertEqual(actual, expected)

    def test_info_set_config_xdr_add_namespace_fail(self):
        actual = self.node.info_set_config_xdr_add_namespace(
            "DC1", "ns", rewind="123aaa456"
        )

        self.assertEqual(actual.message, "Failed to add namespace to XDR datacenter")
        self.assertEqual(actual.response, 'Invalid rewind. Must be int or "all"')

        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_xdr_add_namespace("DC1", "ns", rewind="all")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;namespace=ns;action=add;rewind=all",
            self.ip,
        )
        self.assertEqual(actual.message, "Failed to add namespace to XDR datacenter")
        self.assertEqual(actual.response, "Unknown error occurred")

    def test_info_set_config_xdr_remove_namespace_success(self):
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_remove_namespace("DC1", "ns")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;namespace=ns;action=remove", self.ip
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "2.1.1.1"
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_remove_namespace("DC1", "ns")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;namespace=ns;action=remove", self.ip
        )
        self.assertEqual(actual, expected)

    def test_info_set_config_xdr_remove_namespace_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_xdr_remove_namespace("DC1", "ns")

        self.assertEqual(
            actual.message, "Failed to remove namespace from XDR datacenter"
        )
        self.assertEqual(actual.response, "Unknown error occurred")

    def test_info_set_config_xdr_add_node_success(self):
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_add_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;node-address-port=3.3.3.3:8000;action=add",
            self.ip,
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.5.6.9"
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_add_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;node-address-port=3.3.3.3:8000;action=add",
            self.ip,
        )
        self.assertEqual(actual, expected)

    def test_info_set_config_xdr_add_node_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_xdr_add_node("DC1", "3.3.3.3:8000")

        self.assertEqual(actual.message, "Failed to add node to XDR datacenter")
        self.assertEqual(actual.response, "Unknown error occurred")

    def test_info_set_config_xdr_remove_node_success(self):
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_remove_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;node-address-port=3.3.3.3:8000;action=remove",
            self.ip,
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.9.9.9"
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = self.node.info_set_config_xdr_remove_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;node-address-port=3.3.3.3:8000;action=remove",
            self.ip,
        )
        self.assertEqual(actual, expected)

    def test_info_set_config_xdr_remove_node_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_xdr_remove_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;node-address-port=3.3.3.3:8000;action=remove",
            self.ip,
        )
        self.assertEqual(actual.message, "Failed to remove node from XDR datacenter")
        self.assertEqual(actual.response, "Unknown error occurred")

    def test_info_set_config_xdr_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_xdr("foo", "bar", dc="DC1", namespace="NS")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;foo=bar;dc=DC1;namespace=NS", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "3.9"
        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_xdr("foo", "bar", dc="DC1", namespace="NS")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;foo=bar;datacenter=DC1;namespace=NS", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_set_config_xdr_fail(self):
        actual = self.node.info_set_config_xdr("foo", "bar", namespace="NS")

        self.assertIsInstance(actual, ArgumentError)
        self.assertEqual(str(actual), "Namespace must be accompanied by a dc.")

        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_xdr("foo", "bar", dc="DC1", namespace="NS")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;foo=bar;dc=DC1;namespace=NS", self.ip
        )
        self.assertEqual(
            actual.message, "Failed to set XDR configuration parameter foo to bar"
        )
        """
        This response has to do with the ASInfoConfigError trying to determine the cause of the
        error. It first checks to see if the context exists and since the config_handler
        is mocked it thinks xdr (same for the rest of tests) is a bad subcontext.
        """
        self.assertEqual(actual.response, "Invalid subcontext xdr")

    def test_info_logs(self):
        self.info_mock.return_value = "0:path0;1:path1;2:path2"
        expected = {"path0": "0", "path1": "1", "path2": "2"}

        actual = self.node.info_logs()

        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_logs")
    def test_info_set_config_logging_success(self, info_logs_mock):
        info_logs_mock.return_value = {"path0": "0", "path1": "1", "path2": "2"}
        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_logging("path1", "foo", "bar")

        self.info_mock.assert_called_with("log-set:id=1;foo=bar", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    @patch("lib.live_cluster.client.node.Node.info_logs")
    def test_info_set_config_logging_fail(self, info_logs_mock):
        info_logs_mock.return_value = {"path0": "0", "path1": "1", "path2": "2"}

        actual = self.node.info_set_config_logging("path-DNE", "foo", "bar")

        self.assertIsInstance(actual, ASInfoError)
        self.assertEqual(
            actual.message, "Failed to set logging configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "path-DNE does not exist")

        info_logs_mock.return_value = {"path0": "0", "path1": "1", "path2": "2"}
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_logging("path2", "foo", "bar")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set logging configuration parameter foo to bar"
        )

        self.assertEqual(actual.response, "Invalid subcontext logging")

    def test_info_set_config_service_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_service("foo", "bar")

        self.info_mock.assert_called_with("set-config:context=service;foo=bar", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_set_config_service_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_service("foo", "bar")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set service configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "Invalid subcontext service")

    def test_info_set_config_namespace_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_namespace("foo", "bar", "buff")

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_namespace(
            "foo", "bar", "buff", set_="test-set"
        )

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;foo=bar;set=test-set", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_namespace(
            "foo", "bar", "buff", subcontext="storage-engine"
        )

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_namespace(
            "foo", "bar", "buff", subcontext="geo2dsphere-within"
        )

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;geo2dsphere-within-foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        actual = self.node.info_set_config_namespace(
            "foo", "bar", "buff", subcontext="index-type"
        )

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;index-type.foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_set_config_namespace_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_namespace("foo", "bar", "buff")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set namespace configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "Invalid subcontext namespace")

    def test_info_set_config_network_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_network("foo", "bar", "sub-context")

        self.info_mock.assert_called_with(
            "set-config:context=network;sub-context.foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_set_config_network_fail(self):
        self.info_mock.return_value = "error"
        self.node.conf_schema_handler.get_subcontext.side_effect = [
            ["network"],
            ["not-sub"],
        ]

        actual = self.node.info_set_config_network("foo", "bar", "sub")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set network configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "Invalid subcontext sub")

    def test_info_set_config_security_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_security(
            "foo", "bar", subcontext="sub-context"
        )

        self.info_mock.assert_called_with(
            "set-config:context=security;sub-context.foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "ok"

        actual = self.node.info_set_config_security("foo", "bar")

        self.info_mock.assert_called_with(
            "set-config:context=security;foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_set_config_security_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_set_config_security("foo", "bar", "sub")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set security configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "Invalid subcontext security")

    def test_info_get_config_service(self):

        # todo call getconfig with various formats
        self.info_mock.return_value = "asdf=1;b=b;c=!@#$%^&*()"
        expected = {"asdf": "1", "b": "b", "c": "!@#$%^&*()"}

        config = self.node.info_get_config("service")

        self.info_mock.assert_called_with("get-config:", self.ip)
        self.assertEqual(
            config,
            expected,
            "info_namespace_statistics error:\n_expected:\t%s\n_found:\t%s"
            % (expected, config),
        )

    def test_info_get_config_namespace(self):
        self.node.info_get_config("namespace", "test", 0)
        self.info_mock.assert_called_with(
            "get-config:context=namespace;id=test", self.ip
        )

    @patch("lib.live_cluster.client.node.Node.info_namespaces")
    def test_info_get_config_all(self, info_namespaces_mock):
        info_namespaces_mock.return_value = [
            "test_two",
        ]
        self.node.info_get_config("all")

        info_namespaces_mock.assert_called()
        self.assertEqual(self.info_mock.call_count, 2)
        self.info_mock.assert_any_call(
            "get-config:context=namespace;id=test_two", self.ip
        )
        self.info_mock.assert_any_call("get-config:", self.ip)

    def test_info_get_config_xdr(self):
        self.info_mock.side_effect = [
            "dcs=DC1,DC2;src-id=0;trace-sample=0",
            "namespaces=bar,foo;a=1;b=2;c=3",
            "d=4;e=5;f=6",
            "d=7;e=8;f=9",
            "namespaces=jar;a=10;b=11;c=12",
            "d=13;e=14;f=15",
        ]
        expected = {
            "dc_configs": {
                "DC1": {"namespaces": "bar,foo", "a": "1", "b": "2", "c": "3"},
                "DC2": {"namespaces": "jar", "a": "10", "b": "11", "c": "12"},
            },
            "ns_configs": {
                "DC1": {
                    "bar": {"d": "4", "e": "5", "f": "6"},
                    "foo": {"d": "7", "e": "8", "f": "9"},
                },
                "DC2": {"jar": {"d": "13", "e": "14", "f": "15"}},
            },
            "xdr_configs": {"dcs": "DC1,DC2", "src-id": "0", "trace-sample": "0"},
        }

        actual = self.node.info_get_config("xdr")

        self.assertEqual(self.info_mock.call_count, 6)
        self.info_mock.assert_any_call("get-config:context=xdr", self.ip)
        self.info_mock.assert_any_call("get-config:context=xdr;dc=DC1", self.ip)
        self.info_mock.assert_any_call(
            "get-config:context=xdr;dc=DC1;namespace=bar", self.ip
        )
        self.info_mock.assert_any_call(
            "get-config:context=xdr;dc=DC1;namespace=foo", self.ip
        )
        self.info_mock.assert_any_call("get-config:context=xdr;dc=DC2", self.ip)
        self.info_mock.assert_any_call(
            "get-config:context=xdr;dc=DC2;namespace=jar", self.ip
        )
        self.assertDictEqual(actual, expected)

    @patch(
        "lib.collectinfo_analyzer.collectinfo_handler.collectinfo_parser.conf_parser.parse_file"
    )
    def test_info_get_originalconfig(self, parse_file_mock):
        self.assertDictEqual(self.node.info_get_originalconfig(), {})

        self.node.localhost = True
        parse_file_mock.return_value = {
            "namespace": {
                "foo": {"service": "config_data_1"},
                "bar": {"service": "config_data_2"},
                "tar": {"service": "config_data_3"},
            }
        }
        expected = {
            "foo": "config_data_1",
            "bar": "config_data_2",
            "tar": "config_data_3",
        }

        actual = self.node.info_get_originalconfig("namespace")

        self.assertDictEqual(actual, expected)

        parse_file_mock.return_value = {
            "namespace": {
                "foo": {"service": "config_data_1"},
                "bar": {"service": "config_data_2"},
                "tar": {"service": "config_data_3"},
            }
        }

        self.assertDictEqual(
            {}, self.node.info_get_originalconfig(stanza="does-not-exist")
        )

    def test_info_latency(self):
        self.info_mock.return_value = (
            "{ns}-read:23:53:38-GMT,ops/sec,>1ms,>8ms,>64ms;23:53:48,5234.4,0.54,0.02,0.00;"
            "{ns}-write:23:53:38-GMT,ops/sec,>1ms,>8ms,>64ms;"
            "23:53:48,354.7,2.34,0.77,0.00;error-no-data-yet-or-back-too-small;"
            "error-no-data-yet-or-back-too-small"
        )
        expected = {
            "read": {
                "total": {
                    "values": [["23:53:38->23:53:48", 5234.4, 0.54, 0.02, 0.0]],
                    "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                },
                "namespace": {
                    "ns": {
                        "values": [["23:53:38->23:53:48", 5234.4, 0.54, 0.02, 0.0]],
                        "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                    }
                },
            },
            "write": {
                "total": {
                    "values": [["23:53:38->23:53:48", 354.7, 2.34, 0.77, 0.0]],
                    "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                },
                "namespace": {
                    "ns": {
                        "values": [["23:53:38->23:53:48", 354.7, 2.34, 0.77, 0.0]],
                        "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                    }
                },
            },
        }

        latency_data = self.node.info_latency()

        self.assertDictEqual(
            latency_data, expected, "info_latency did not return the expected result"
        )
        self.info_mock.assert_called_with("latency:", self.ip)

    def test_info_latency_with_args(self):
        self.info_mock.return_value = (
            "{ns}-read:23:50:28-GMT,ops/sec,>1ms,>8ms,>64ms;23:50:58,0.0,0.00,0.00,0.00;"
            "23:51:28,0.0,0.00,0.00,0.00;23:51:58,0.0,0.00,0.00,0.00;"
            "23:52:28,0.0,0.00,0.00,0.00;3:52:58,0.0,0.00,0.00,0.00;"
            "23:53:28,0.0,0.00,0.00,0.00;23:53:58,0.0,0.00,0.00,0.00;"
            "23:54:28,0.0,0.00,0.00,0.00;23:54:58,0.0,0.00,0.00,0.00"
        )
        expected = {
            "read": {
                "total": {
                    "values": [
                        ["23:50:28->23:50:58", 0.0, 0.0, 0.0, 0.0],
                        ["23:50:58->23:51:28", 0.0, 0.0, 0.0, 0.0],
                        ["23:51:28->23:51:58", 0.0, 0.0, 0.0, 0.0],
                        ["23:51:58->23:52:28", 0.0, 0.0, 0.0, 0.0],
                        ["23:52:28->3:52:58", 0.0, 0.0, 0.0, 0.0],
                        ["3:52:58->23:53:28", 0.0, 0.0, 0.0, 0.0],
                        ["23:53:28->23:53:58", 0.0, 0.0, 0.0, 0.0],
                        ["23:53:58->23:54:28", 0.0, 0.0, 0.0, 0.0],
                        ["23:54:28->23:54:58", 0.0, 0.0, 0.0, 0.0],
                    ],
                    "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                },
                "namespace": {
                    "ns": {
                        "values": [
                            ["23:50:28->23:50:58", 0.0, 0.0, 0.0, 0.0],
                            ["23:50:58->23:51:28", 0.0, 0.0, 0.0, 0.0],
                            ["23:51:28->23:51:58", 0.0, 0.0, 0.0, 0.0],
                            ["23:51:58->23:52:28", 0.0, 0.0, 0.0, 0.0],
                            ["23:52:28->3:52:58", 0.0, 0.0, 0.0, 0.0],
                            ["3:52:58->23:53:28", 0.0, 0.0, 0.0, 0.0],
                            ["23:53:28->23:53:58", 0.0, 0.0, 0.0, 0.0],
                            ["23:53:58->23:54:28", 0.0, 0.0, 0.0, 0.0],
                            ["23:54:28->23:54:58", 0.0, 0.0, 0.0, 0.0],
                        ],
                        "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                    }
                },
            }
        }

        latency_actual = self.node.info_latency(back=300, duration=120, slice_tm=30)

        self.assertDictEqual(
            latency_actual,
            expected,
            "info_latency with args did not return the expected result",
        )
        self.info_mock.assert_called_with(
            "latency:back=300;duration=120;slice=30;", self.ip
        )

    def test_info_latencies_default(self):
        raw = """
        batch-index:;{test}-read:msec,1.0,2.00,3.00,4.00,5.00,6.00,7.00,8.00,
        9.00,10.00,11.00,12.00,13.00,14.00,15.00,16.00,17.00,18.00;{test}-write:msec,
        19.0,20.00,21.00,22.00,23.00,24.00,25.00,26.00,27.00,28.00,29.00,30.00,31.00,32.00,
        33.00,34.00,35.00,36.00;{test}-udf:;{test}-query:;{bar}-read:msec,37.0,38.00,39.00,40.00,41.00,42.00,43.00,44.00,
        45.00,46.00,47.00,48.00,49.00,50.00,51.00,52.00,53.00,54.00;{bar}-write:msec,
        55.0,56.00,57.00,58.00,59.00,60.00,61.00,62.00,63.00,64.00,65.00,66.00,67.00,68.00,
        69.00,70.00,71.00,72.00;
        {bar}-udf:;{bar}-query:"
        """
        self.info_mock.return_value = raw
        expected = {
            "read": {
                "namespace": {
                    "test": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                        "values": [[1.0, 2.0, 5.0, 8.0]],
                    },
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                        "values": [[37.0, 38.0, 41.0, 44.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                    "values": [[38.0, 37.05, 40.05, 43.05]],
                },
            },
            "write": {
                "namespace": {
                    "test": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                        "values": [[19.0, 20.0, 23.0, 26.0]],
                    },
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                        "values": [[55.0, 56.0, 59.0, 62.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                    "values": [[74.0, 46.76, 49.76, 52.76]],
                },
            },
        }

        result = self.node.info_latencies()
        self.assertDictEqual(result, expected)
        self.info_mock.assert_called_with("latencies:", self.ip)

    def test_info_latencies_e2_b4(self):
        raw = """
        batch-index:;{test}-read:msec,1.0,2.00,3.00,4.00,5.00,6.00,7.00,8.00,
        9.00,10.00,11.00,12.00,13.00,14.00,15.00,16.00,17.00,18.00;{test}-write:msec,
        19.0,20.00,21.00,22.00,23.00,24.00,25.00,26.00,27.00,28.00,29.00,30.00,31.00,32.00,
        33.00,34.00,35.00,36.00;{test}-udf:;{test}-query:;{bar}-read:msec,37.0,38.00,39.00,40.00,41.00,42.00,43.00,44.00,
        45.00,46.00,47.00,48.00,49.00,50.00,51.00,52.00,53.00,54.00;{bar}-write:msec,
        55.0,56.00,57.00,58.00,59.00,60.00,61.00,62.00,63.00,64.00,65.00,66.00,67.00,68.00,
        69.00,70.00,71.00,72.00;
        {bar}-udf:;{bar}-query:"
        """
        self.info_mock.return_value = raw
        expected = {
            "read": {
                "namespace": {
                    "test": {
                        "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                        "values": [[1.0, 2.0, 4.0, 6.0, 8.0]],
                    },
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                        "values": [[37.0, 38.0, 40.0, 42.0, 44.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                    "values": [[38.0, 37.05, 39.05, 41.05, 43.05]],
                },
            },
            "write": {
                "namespace": {
                    "test": {
                        "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                        "values": [[19.0, 20.0, 22.0, 24.0, 26.0]],
                    },
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                        "values": [[55.0, 56.0, 58.0, 60.0, 62.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                    "values": [[74.0, 46.76, 48.76, 50.76, 52.76]],
                },
            },
        }

        result = self.node.info_latencies(buckets=4, exponent_increment=2)
        self.assertDictEqual(result, expected)
        self.info_mock.assert_called_with("latencies:", self.ip)

    def test_info_latencies_verbose(self):
        raw = ""
        self.info_mock.side_effect = [
            "test",
            raw,
            raw,
            raw,
            raw,
            raw,
            raw,
            raw,
            raw,
            raw,
        ]

        _ = self.node.info_latencies(verbose=True)

        self.assertEqual(self.info_mock.call_count, 10)
        self.info_mock.assert_any_call("latencies:", self.ip)
        self.info_mock.assert_any_call("latencies:hist={test}-proxy", self.ip)
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmark-fabric", self.ip
        )
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmarks-ops-sub", self.ip
        )
        self.info_mock.assert_any_call("latencies:hist={test}-benchmarks-read", self.ip)
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmarks-write", self.ip
        )
        self.info_mock.assert_any_call("latencies:hist={test}-benchmarks-udf", self.ip)
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmarks-udf-sub", self.ip
        )
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmarks-batch-sub", self.ip
        )

    def test_info_dcs(self):
        self.info_mock.return_value = "a=b;c=d;e=f;dcs=DC1,DC2,DC3"
        expected = ["DC1", "DC2", "DC3"]

        actual = self.node.info_dcs()

        self.info_mock.assert_called_with(
            "get-config:context=xdr", self.ip, self.node.xdr_port
        )
        self.assertListEqual(actual, expected)

        self.info_mock.return_value = "a=b;c=d;e=f;dcs=DC1,DC2,DC3"
        self.node.features = "xdr"

        actual = self.node.info_dcs()

        self.info_mock.assert_called_with("get-config:context=xdr", self.ip)
        self.assertListEqual(actual, expected)

        self.info_mock.return_value = "DC3;DC4;DC5"
        expected = ["DC3", "DC4", "DC5"]
        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.9"

        actual = self.node.info_dcs()

        self.info_mock.assert_called_with("dcs", self.ip)
        self.assertListEqual(actual, expected)

        self.info_mock.return_value = "DC3;DC4;DC5"
        expected = ["DC3", "DC4", "DC5"]
        self.node.features = ""
        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.9"

        actual = self.node.info_dcs()

        self.info_mock.assert_called_with("dcs", self.ip, self.node.xdr_port)
        self.assertListEqual(actual, expected)

    def test_info_dc_statistics(self):
        expected = {"a": "b", "c": "d", "e": "f"}
        dc = "foo"
        self.info_mock.return_value = "a=b;c=d;e=f"

        actual = self.node.info_dc_statistics(dc=dc)

        self.info_mock.assert_called_with(
            "get-stats:context=xdr;dc={}".format(dc), self.ip, self.node.xdr_port
        )
        self.assertDictEqual(actual, expected)

        self.info_mock.return_value = "a=b;c=d;e=f"
        self.node.features = "xdr"

        actual = self.node.info_dc_statistics(dc=dc)

        self.info_mock.assert_called_with(
            "get-stats:context=xdr;dc={}".format(dc), self.ip
        )
        self.assertDictEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.9"
        self.info_mock.return_value = "a=b;c=d;e=f"

        actual = self.node.info_dc_statistics(dc=dc)

        self.info_mock.assert_called_with("dc/{}".format(dc), self.ip)
        self.assertDictEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build_version.return_value = "4.9"
        self.info_mock.return_value = "a=b;c=d;e=f"
        self.node.features = ""

        actual = self.node.info_dc_statistics(dc=dc)

        self.info_mock.assert_called_with(
            "dc/{}".format(dc), self.ip, self.node.xdr_port
        )
        self.assertDictEqual(actual, expected)

    def test_info_udf_list(self):
        self.info_mock.return_value = "filename=basic_udf.lua,hash=706c57cb29e027221560a3cb4b693573ada98bf2,type=LUA;"
        expected = {
            "basic_udf.lua": {
                "filename": "basic_udf.lua",
                "hash": "706c57cb29e027221560a3cb4b693573ada98bf2",
                "type": "LUA",
            }
        }

        udf_actual = self.node.info_udf_list()

        self.assertEqual(
            udf_actual, expected, "info_roster did not return the expected result"
        )
        self.info_mock.assert_called_with("udf-list", self.ip)

    def test_info_udf_put_success(self):
        self.info_mock.return_value = ""
        udf_file_name = "test.lua"
        udf_str = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum"
        udf_type = "LUA"
        b64content = "TG9yZW0gSXBzdW0gaXMgc2ltcGx5IGR1bW15IHRleHQgb2YgdGhlIHByaW50aW5nIGFuZCB0eXBlc2V0dGluZyBpbmR1c3RyeS4gTG9yZW0gSXBzdW0gaGFzIGJlZW4gdGhlIGluZHVzdHJ5J3Mgc3RhbmRhcmQgZHVtbXkgdGV4dCBldmVyIHNpbmNlIHRoZSAxNTAwcywgd2hlbiBhbiB1bmtub3duIHByaW50ZXIgdG9vayBhIGdhbGxleSBvZiB0eXBlIGFuZCBzY3JhbWJsZWQgaXQgdG8gbWFrZSBhIHR5cGUgc3BlY2ltZW4gYm9vay4gSXQgaGFzIHN1cnZpdmVkIG5vdCBvbmx5IGZpdmUgY2VudHVyaWVzLCBidXQgYWxzbyB0aGUgbGVhcCBpbnRvIGVsZWN0cm9uaWMgdHlwZXNldHRpbmcsIHJlbWFpbmluZyBlc3NlbnRpYWxseSB1bmNoYW5nZWQuIEl0IHdhcyBwb3B1bGFyaXNlZCBpbiB0aGUgMTk2MHMgd2l0aCB0aGUgcmVsZWFzZSBvZiBMZXRyYXNldCBzaGVldHMgY29udGFpbmluZyBMb3JlbSBJcHN1bSBwYXNzYWdlcywgYW5kIG1vcmUgcmVjZW50bHkgd2l0aCBkZXNrdG9wIHB1Ymxpc2hpbmcgc29mdHdhcmUgbGlrZSBBbGR1cyBQYWdlTWFrZXIgaW5jbHVkaW5nIHZlcnNpb25zIG9mIExvcmVtIElwc3Vt"
        content_len = len(b64content)
        expected_call = (
            "udf-put:filename={};udf-type={};content-len={};content={}".format(
                udf_file_name, udf_type, content_len, b64content
            )
        )

        actual = self.node.info_udf_put(udf_file_name, udf_str, udf_type)

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_udf_put_fail(self):
        self.info_mock.return_value = "error=invalid_base64_content"

        actual = self.node.info_udf_put("udf_file_name", "udf_str", "udf_type")

        self.assertEqual(actual.message, "Failed to add UDF")
        self.assertEqual(actual.response, "invalid_base64_content")

    @patch("lib.live_cluster.client.node.Node.info_udf_list")
    def test_info_udf_remove_success(self, info_udf_list_mock):
        info_udf_list_mock.return_value = {
            "file": {
                "filename": "bar.lua",
                "hash": "591d2536acb21a329040beabfd9bfaf110d35c18",
                "type": "LUA",
            }
        }
        self.info_mock.return_value = "OK"

        actual = self.node.info_udf_remove("file")

        self.info_mock.assert_called_with("udf-remove:filename=file;", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    @patch("lib.live_cluster.client.node.Node.info_udf_list")
    def test_info_udf_remove_fail(self, info_udf_list_mock):
        self.info_mock.return_value = "error=invalid_filename"
        info_udf_list_mock.return_value = {
            "file": {
                "filename": "bar.lua",
                "hash": "591d2536acb21a329040beabfd9bfaf110d35c18",
                "type": "LUA",
            }
        }

        actual = self.node.info_udf_remove("file")

        self.assertEqual(actual.message, "Failed to remove UDF file")
        self.assertEqual(actual.response, "invalid_filename")

        info_udf_list_mock.return_value = {
            "NOT-file": {
                "filename": "bar.lua",
                "hash": "591d2536acb21a329040beabfd9bfaf110d35c18",
                "type": "LUA",
            }
        }

        actual = self.node.info_udf_remove("file")

        self.assertEqual(actual.message, "Failed to remove UDF file")
        self.assertEqual(actual.response, "UDF does not exist")

    def test_info_roster(self):
        self.info_mock.return_value = "ns=test:roster=null:pending_roster=null:observed_nodes=BB9070016AE4202,BB9060016AE4202,BB9050016AE4202,BB9040016AE4202,BB9020016AE4202"
        expected = {
            "test": {
                "observed_nodes": [
                    "BB9070016AE4202",
                    "BB9060016AE4202",
                    "BB9050016AE4202",
                    "BB9040016AE4202",
                    "BB9020016AE4202",
                ],
                "ns": "test",
                "pending_roster": ["null"],
                "roster": ["null"],
            }
        }

        roster_actual = self.node.info_roster()

        self.assertEqual(
            roster_actual, expected, "info_roster did not return the expected result"
        )
        self.info_mock.assert_called_with("roster:", self.ip)

    def test_info_racks(self):
        self.info_mock.return_value = "ns=test:rack_1=BCD10DFA9290C00,BB910DFA9290C00:rack_2=BD710DFA9290C00,BC310DFA9290C00"
        expected = {
            "test": {
                "1": {"rack-id": "1", "nodes": ["BCD10DFA9290C00", "BB910DFA9290C00"]},
                "2": {"rack-id": "2", "nodes": ["BD710DFA9290C00", "BC310DFA9290C00"]},
            }
        }

        racks_actual = self.node.info_racks()

        self.info_mock.assert_called_with("racks:", self.ip)
        self.assertEqual(
            racks_actual, expected, "info_racks did not return the expected result"
        )

    def test_info_dc_get_config(self):
        self.info_mock.return_value = (
            "dc-name=REMOTE_DC:dc-type=aerospike:tls-name=:dc-security-config-file=/private/aerospike/security_credentials_REMOTE_DC.txt:"
            "nodes=192.168.100.140+3000,192.168.100.147+3000:int-ext-ipmap=:dc-connections=64:"
            "dc-connections-idle-ms=55000:dc-use-alternate-services=false:namespaces=test"
        )
        expected = {
            "REMOTE_DC": {
                "dc-security-config-file": "/private/aerospike/security_credentials_REMOTE_DC.txt",
                "tls-name": "",
                "dc-name": "REMOTE_DC",
                "dc-connections-idle-ms": "55000",
                "dc-use-alternate-services": "false",
                "int-ext-ipmap": "",
                "dc-connections": "64",
                "namespaces": "test",
                "nodes": "192.168.100.140+3000,192.168.100.147+3000",
                "dc-type": "aerospike",
            }
        }

        dc_config = self.node.info_dc_get_config()

        self.assertEqual(
            dc_config, expected, "info_dc_get_config did not return the expected result"
        )
        self.info_mock.assert_called_with("get-dc-config", self.ip, self.node.xdr_port)

        self.node.features = ["xdr"]

        xdr_dc_confg = self.node.info_dc_get_config()

        self.assertEqual(
            xdr_dc_confg,
            expected,
            "info_dc_get_config with xdr feature did not return the expected result",
        )
        self.info_mock.assert_any_call("get-dc-config", self.ip)

    @patch("lib.live_cluster.client.node.Node.info_get_config")
    def test_info_XDR_get_config(self, info_get_config):
        info_get_config.return_value = {"a": "1", "b": "2", "c": "3"}
        self.info_mock.return_value = "b=4;d=5;e=6"
        expected = {"a": "1", "b": "4", "c": "3", "d": "5", "e": "6"}

        actual = self.node.info_XDR_get_config()

        self.assertDictEqual(actual, expected)

        info_get_config.return_value = {"a": "1", "b": "2", "c": "3"}
        self.node.features = "xdr"
        expected = {
            "a": "1",
            "b": "2",
            "c": "3",
        }

        actual = self.node.info_XDR_get_config()

        self.assertDictEqual(actual, expected)

    def test_info_histogram(self):
        raw = """
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
        """

        # nraw, {'namespaces':'test'})
        self.info_mock.side_effect = ["test", raw]
        self.node.new_histogram_version = True
        expected = {
            "test": {
                # 'units': 'bytes',
                "width": 8192,
                "data": [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    505,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
                "histogram": "object-size-linear",
            }
        }

        histogram_actual = self.node.info_histogram("objsz")

        self.assertEqual(
            histogram_actual,
            expected,
            "info_histogram did not return the expected result",
        )
        self.info_mock.assert_called_with(
            "histogram:namespace=test;type=object-size-linear", self.ip
        )

        self.info_mock.side_effect = ["test", raw]
        expected = {"test": raw}

        histogram_actual = self.node.info_histogram(
            "objsz", logarithmic=True, raw_output=True
        )

        self.assertEqual(
            histogram_actual,
            expected,
            "info_histogram did not return the expected result",
        )

        self.info_mock.assert_called_with(
            "histogram:namespace=test;type=object-size", self.ip
        )
        self.info_mock.side_effect = ["test", raw]
        self.node.info_histogram("ttl", logarithmic=True, raw_output=True)
        self.info_mock.assert_called_with("histogram:namespace=test;type=ttl", self.ip)

        self.node.new_histogram_version = False
        self.info_mock.side_effect = ["test", raw]
        self.node.info_histogram("objsz", logarithmic=True, raw_output=True)
        self.info_mock.assert_called_with("hist-dump:ns=test;hist=objsz", self.ip)

    def test_info_sindex(self):
        self.info_mock.return_value = "a=1:b=2:c=3:d=4:e=5;a=6:b=7:c=8:d=9:e=10;"
        expected = [
            {"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
            {"a": "6", "b": "7", "c": "8", "d": "9", "e": "10"},
        ]

        actual = self.node.info_sindex()

        self.info_mock.assert_called_with("sindex", self.ip)
        self.assertListEqual(actual, expected)

    def test_info_sindex_statistics(self):
        self.info_mock.return_value = "a=b;c=d;e=f"
        expected = {"a": "b", "c": "d", "e": "f"}

        actual = self.node.info_sindex_statistics("foo", "bar")

        self.info_mock.assert_called_with("sindex/{}/{}".format("foo", "bar"), self.ip)
        self.assertDictEqual(actual, expected)

    def test_info_sindex_create_success(self):
        self.info_mock.return_value = "OK"
        expected_call = "sindex-create:indexname={};ns={};indexdata={},{}".format(
            "iname", "ns", "data1", "data2"
        )

        actual = self.node.info_sindex_create("iname", "ns", "data1", "data2")

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "OK"
        expected_call = "sindex-create:indexname={};indextype={};ns={};set={};indexdata={},{}".format(
            "iname", "itype", "ns", "set", "data1", "data2"
        )

        actual = self.node.info_sindex_create(
            "iname", "ns", "data1", "data2", index_type="itype", set_="set"
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_sindex_create_fail(self):
        self.info_mock.return_value = "FAIL:4: Invalid indexdata"

        actual = self.node.info_sindex_create("iname", "ns", "data1", "data2")

        self.assertEqual(actual.message, "Failed to create sindex iname")
        self.assertEqual(actual.response, "Invalid indexdata")

    def test_info_sindex_delete_success(self):
        self.info_mock.return_value = "OK"
        expected_call = "sindex-delete:ns={};indexname={}".format(
            "ns",
            "iname",
        )

        actual = self.node.info_sindex_delete("iname", "ns")

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "OK"
        expected_call = "sindex-delete:ns={};set={};indexname={}".format(
            "ns",
            "set",
            "iname",
        )

        actual = self.node.info_sindex_delete("iname", "ns", set_="set")

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_sindex_delete_fail(self):
        self.info_mock.return_value = "FAIL:4: Invalid indexname"

        actual = self.node.info_sindex_delete("iname", "ns")

        self.assertEqual(actual.message, "Failed to delete sindex iname")
        self.assertEqual(actual.response, "Invalid indexname")

    def test_use_new_truncate_command(self):
        input_output = [
            ("4.3.1.11", True),
            ("4.3.2.0", False),
            ("4.4.0.10", False),
            ("4.4.0.12", True),
            ("4.5.1.4", False),
            ("4.5.1.5", True),
            ("4.5.2.0", True),
        ]

        for input, output in input_output:
            lib.live_cluster.client.node.Node.info_build_version.return_value = input

            self.assertEqual(self.node._use_new_truncate_command(), output)

    def test_info_truncate_with_ns_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_truncate("test-ns")

        self.info_mock.assert_called_once_with(
            "truncate-namespace:namespace=test-ns", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    @patch("lib.live_cluster.client.node.Node._use_new_truncate_command")
    def test_info_truncate_with_ns_and_older_command_success(
        self, use_new_truncate_command_mock
    ):
        self.info_mock.return_value = "ok"
        use_new_truncate_command_mock.return_value = False

        actual = self.node.info_truncate("test-ns")

        self.info_mock.assert_called_once_with("truncate:namespace=test-ns", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_truncate_with_ns_and_lut_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_truncate("test-ns", lut="123456789")

        self.info_mock.assert_called_once_with(
            "truncate-namespace:namespace=test-ns;lut=123456789", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_truncate_with_set_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_truncate("test-ns", "bar")

        self.info_mock.assert_called_once_with(
            "truncate:namespace=test-ns;set=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_truncate_with_set_and_lut_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_truncate("test-ns", "bar", "123456789")

        self.info_mock.assert_called_once_with(
            "truncate:namespace=test-ns;set=bar;lut=123456789", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_truncate_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_truncate("test-ns", "bar", "123456789")

        self.info_mock.assert_called_once_with(
            "truncate:namespace=test-ns;set=bar;lut=123456789", self.ip
        )
        self.assertEqual(
            str(actual),
            "Failed to truncate namespace test-ns set bar : Unknown error occurred.",
        )

        self.info_mock.return_value = "error"

        actual = self.node.info_truncate("test-ns")

        self.info_mock.assert_called_with(
            "truncate-namespace:namespace=test-ns", self.ip
        )
        self.assertEqual(
            str(actual),
            "Failed to truncate namespace test-ns : Unknown error occurred.",
        )

    def test_info_truncate_undo_with_ns_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_truncate_undo("test-ns")

        self.info_mock.assert_called_once_with(
            "truncate-namespace-undo:namespace=test-ns", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    @patch("lib.live_cluster.client.node.Node._use_new_truncate_command")
    def test_info_truncate_undo_with_ns_and_older_command_success(
        self, use_new_truncate_command_mock
    ):
        self.info_mock.return_value = "ok"
        use_new_truncate_command_mock.return_value = False

        actual = self.node.info_truncate_undo("test-ns")

        self.info_mock.assert_called_once_with(
            "truncate-undo:namespace=test-ns", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_truncate_undo_with_ns_and_lut_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_truncate_undo("test-ns")

        self.info_mock.assert_called_once_with(
            "truncate-namespace-undo:namespace=test-ns", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_truncate_undo_with_set_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_truncate_undo("test-ns", "bar")

        self.info_mock.assert_called_once_with(
            "truncate-undo:namespace=test-ns;set=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_truncate_undo_with_set_and_lut_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_truncate_undo("test-ns", "bar")

        self.info_mock.assert_called_once_with(
            "truncate-undo:namespace=test-ns;set=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_truncate_undo_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_truncate_undo("test-ns", "bar")

        self.info_mock.assert_called_once_with(
            "truncate-undo:namespace=test-ns;set=bar", self.ip
        )
        self.assertEqual(
            str(actual),
            "Failed to undo truncation of namespace test-ns set bar : Unknown error occurred.",
        )

        self.info_mock.return_value = "error"

        actual = self.node.info_truncate_undo("test-ns")

        self.info_mock.assert_called_with(
            "truncate-namespace-undo:namespace=test-ns", self.ip
        )
        self.assertEqual(
            str(actual),
            "Failed to undo truncation of namespace test-ns : Unknown error occurred.",
        )

    def test_info_recluster_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_recluster()

        self.info_mock.assert_called_once_with("recluster:", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_recluster_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_recluster()

        self.info_mock.assert_called_once_with("recluster:", self.ip)
        self.assertEqual(
            str(actual),
            "Failed to recluster : Unknown error occurred.",
        )

    def test_info_quiesce_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_quiesce()

        self.info_mock.assert_called_once_with("quiesce:", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_quiesce_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_quiesce()

        self.info_mock.assert_called_once_with("quiesce:", self.ip)
        self.assertEqual(
            str(actual),
            "Failed to quiesce : Unknown error occurred.",
        )

    def test_info_quiesce_undo_success(self):
        self.info_mock.return_value = "ok"

        actual = self.node.info_quiesce_undo()

        self.info_mock.assert_called_once_with("quiesce-undo:", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    def test_info_quiesce_undo_fail(self):
        self.info_mock.return_value = "error"

        actual = self.node.info_quiesce_undo()

        self.info_mock.assert_called_once_with("quiesce-undo:", self.ip)
        self.assertEqual(
            str(actual),
            "Failed to undo quiesce : Unknown error occurred.",
        )

    @patch("lib.live_cluster.client.assocket.ASSocket.create_user")
    @patch("lib.live_cluster.client.node.Node._get_connection")
    @patch("lib.live_cluster.client.assocket.ASSocket.settimeout")
    def test_admin_cadmin(
        self, set_timeout_mock, get_connection_mock, create_user_mock
    ):
        get_connection_mock.return_value = ASSocket(
            self.node.ip,
            self.node.port,
            self.node.tls_name,
            self.node.user,
            self.node.password,
            self.node.auth_mode,
            self.node.ssl_context,
            timeout=self.node._timeout,
        )
        expected = 1
        create_user_mock.return_value = expected
        set_timeout_mock.return_value = None

        actual = self.node._admin_cadmin(
            ASSocket.create_user, (1, 2, 3), self.node.ip, self.node.port
        )

        set_timeout_mock.assert_called_with(None)
        get_connection_mock.assert_called_with(self.node.ip, self.node.port)
        create_user_mock.assert_called_with(get_connection_mock.return_value, 1, 2, 3)
        self.assertEqual(actual, expected)

        get_connection_mock.return_value = None

        util.assert_exception(
            self,
            OSError,
            "Error: Could not connect to node 192.1.1.1",
            self.node._admin_cadmin,
            ASSocket.create_user,
            (1, 2, 3),
            self.node.ip,
            self.node.port,
        )


if __name__ == "__main__":
    unittest.main()
