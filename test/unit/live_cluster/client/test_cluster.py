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


from pytest import PytestUnraisableExceptionWarning
from mock import patch
import socket

import lib
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node

import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import asynctest


class ClusterTest(asynctest.TestCase):
    async def get_cluster_mock(self, node_count, return_key_value={}):
        cl: Cluster = await Cluster([("127.0.0.0", 3000, None)])
        cl.clear_node_list()

        for i in range(node_count):
            n = await self.get_info_mock(
                "A0000000000000" + str(i),
                return_key_value=return_key_value,
                ip="127.0.0." + str(i),
            )
            cl.update_node(n)
        return cl

    async def get_info_mock(
        self, return_value, return_key_value={}, ip="127.0.0.1", port=3000
    ):

        if "build" not in return_key_value:
            return_key_value["build"] = "4.9.0.0"

        async def info_cinfo_side_effect(*args, **kwargs):
            ip_last_digit = ip.split(".")[3]
            cmd = args[0]

            if cmd == ["node", "service-clear-std", "features", "peers-clear-std"]:
                return {
                    "node": return_value,
                    "service-clear-std": (
                        str(ip)
                        + ":"
                        + str(port)
                        + ",172.17.0.1:"
                        + str(port)
                        + ",172.17.1.1:"
                        + str(port)
                    ),
                    "peers-clear-std": "10,3000,[[BB9050011AC4202,,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]",
                    "features": "batch-index;blob-bits;cdt-list;cdt-map;cluster-stable;float;geo;",
                }

            if cmd == "service":
                return (
                    str(ip)
                    + ":"
                    + str(port)
                    + ",192.168.120."
                    + ip_last_digit
                    + ":3000"
                )

            if cmd == "service-clear-std":
                return (
                    str(ip)
                    + ":"
                    + str(port)
                    + ",172.17.0.1:"
                    + str(port)
                    + ",172.17.1.1:"
                    + str(port)
                )

            if cmd == "service-tls-std":
                return "172.17.0.1:4333,172.17.1.1:4333"

            if cmd == "service-clear-alt":
                return "172.17.0.2:3000,172.17.1.2:3000"

            if cmd == "service-tls-alt":
                return "172.17.0.2:4333,172.17.1.2:4333"

            if cmd == "services":
                return (
                    "192.168.120."
                    + ip_last_digit
                    + ":3000;127.0.0."
                    + ip_last_digit
                    + ":3000"
                )

            if cmd == "services-alumni":
                return (
                    "192.168.123."
                    + ip_last_digit
                    + ":3000;127.3.0."
                    + ip_last_digit
                    + ":3000"
                )

            if cmd == "services-alternate":
                return (
                    "192.168.122."
                    + ip_last_digit
                    + ":3000;127.2.0."
                    + ip_last_digit
                    + ":3000"
                )

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

        Node._info_cinfo.side_effect = info_cinfo_side_effect

        n = await Node(ip, port=port)
        return n

    def setUp(self):
        patch("lib.live_cluster.client.node.JsonDynamicConfigHandler").start()
        lib.live_cluster.client.node.Node._info_cinfo = patch(
            "lib.live_cluster.client.node.Node._info_cinfo"
        ).start()
        lib.live_cluster.client.node.get_fully_qualified_domain_name = patch(
            "lib.live_cluster.client.node.get_fully_qualified_domain_name"
        ).start()
        socket.getaddrinfo = patch("socket.getaddrinfo").start()

        Node._info_cinfo.return_value = ""
        lib.live_cluster.client.node.get_fully_qualified_domain_name.return_value = (
            "host.domain.local"
        )

        def getaddressinfo_side_effect(*args):
            return [(2, 1, 6, "", (args[0], 3000))]

        socket.getaddrinfo.side_effect = getaddressinfo_side_effect

        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

        self.addCleanup(patch.stopall)

    async def test_get_node(self):
        cl = await self.get_cluster_mock(1)
        ip_ports = [
            ("192.168.0.1", 3000),
            ("192.168.0.2", 3000),
            ("192.168.0.3", 3000),
            ("192.168.1.1", 3000),
            ("192.168.2.1", 3000),
            ("192.168.3.1", 3000),
            ("192.167.0.1", 3000),
            ("192.169.0.1", 3000),
            ("192.168.0.1", 3001),
            ("192.168.0.1", 3002),
        ]
        for i, (ip, port) in enumerate(ip_ports):
            n = await self.get_info_mock("A0000000000000" + str(i), ip=ip, port=port)
            cl.update_node(n)

        expected = [
            "192.168.0.1:3000",
            "192.168.0.1:3001",
            "192.168.0.1:3002",
        ]

        actual = cl.get_node("192.168.0.1*")
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

        expected = []

        actual = cl.get_node("192.168.0.1")
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

        expected = ["192.168.0.2:3000"]

        actual = cl.get_node("192.168.0.2")
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

        expected = [
            "192.168.0.1:3000",
            "192.168.0.2:3000",
            "192.168.0.3:3000",
            "192.168.1.1:3000",
            "192.168.2.1:3000",
            "192.168.3.1:3000",
            "192.167.0.1:3000",
            "192.169.0.1:3000",
            "192.168.0.1:3001",
            "192.168.0.1:3002",
        ]

        actual = cl.get_node("192.*")
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

        expected = []

        actual = cl.get_node("A0")
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

        expected = [
            "192.168.0.1:3000",
            "192.168.0.2:3000",
            "192.168.0.3:3000",
            "192.168.1.1:3000",
            "192.168.2.1:3000",
            "192.168.3.1:3000",
            "192.167.0.1:3000",
            "192.169.0.1:3000",
            "192.168.0.1:3001",
            "192.168.0.1:3002",
        ]

        actual = cl.get_node("A0*")
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

    async def test_get_nodes(self):
        cl = await self.get_cluster_mock(3)

        actual = cl.get_nodes("all")

        self.assertEqual(len(actual), 3)

        actual = cl.get_nodes("random")

        self.assertEqual(len(actual), 1)

        actual = cl.get_nodes("principal")

        self.assertEqual(len(actual), 1)
        self.assertEqual(actual[0].node_id, "A00000000000002")

        cl = await self.get_cluster_mock(1)
        ip_ports = [
            ("192.168.0.1", 3000),
            ("192.168.0.2", 3000),
            ("192.168.0.3", 3000),
            ("192.168.1.1", 3000),
            ("192.168.2.1", 3000),
            ("192.168.3.1", 3000),
            ("192.168.3.2", 3000),
            ("192.168.3.3", 3000),
            ("192.168.3.4", 3000),
            ("192.167.0.1", 3000),
            ("192.169.0.1", 3000),
            ("192.168.0.1", 3001),
            ("192.168.0.1", 3002),
        ]
        for i, (ip, port) in enumerate(ip_ports):
            n = await self.get_info_mock("A0000000000000" + str(i), ip=ip, port=port)
            cl.update_node(n)

        expected = [
            "192.168.0.2:3000",
            "192.168.1.1:3000",
            "192.168.3.1:3000",
            "192.168.3.2:3000",
            "192.168.3.3:3000",
            "192.168.3.4:3000",
        ]

        actual = cl.get_nodes(
            ["192.168.0.1", "192.168.0.2", "192.168.1.1", "192.168.3*"]
        )
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

    async def test_get_node_displaynames(self):
        cl = await self.get_cluster_mock(1)
        expected = {"127.0.0.0:3000": "host.domain.local:3000"}
        self.assertEqual(
            cl.get_node_displaynames(),
            expected,
            "get_node_displaynames did not return the expected result",
        )

    async def test_get_node_names(self):
        cl = await self.get_cluster_mock(1)
        expected = {"127.0.0.0:3000": "host.domain.local:3000"}
        self.assertEqual(
            cl.get_node_names(),
            expected,
            "get_node_names did not return the expected result",
        )

    async def test_get_expected_principal(self):
        cl = await self.get_cluster_mock(3)
        expected = "A00000000000002"
        self.assertEqual(
            cl.get_expected_principal(),
            expected,
            "get_expected_principal did not return the expected result",
        )

    async def test_get_visibility_error_nodes_returns_empty(self):
        cl = await self.get_cluster_mock(3)
        cl._refresh_node_liveliness()
        cl.nodes["127.0.0.0:3000"].peers = [
            (("127.0.0.1", 3000, None),),
            (("127.0.0.2", 3000, None),),
        ]
        cl.nodes["127.0.0.1:3000"].peers = [
            (("127.0.0.0", 3000, None),),
            (("127.0.0.2", 3000, None),),
        ]
        cl.nodes["127.0.0.2:3000"].peers = [
            (("127.0.0.0", 3000, None),),
            (("127.0.0.1", 3000, None),),
        ]

        expected = []
        self.assertEqual(
            cl.get_visibility_error_nodes(),
            expected,
            "get_visibility_error_nodes did not return the expected result",
        )

    async def test_get_visibility_error_nodes_returns_node(self):
        cl = await self.get_cluster_mock(3)
        cl._refresh_node_liveliness()
        cl.nodes["127.0.0.0:3000"].peers = [
            (("127.0.0.1", 3000, None),),
            (("127.0.0.2", 3000, None),),
        ]
        cl.nodes["127.0.0.1:3000"].peers = [
            (("127.0.0.2", 3000, None),),
        ]
        cl.nodes["127.0.0.2:3000"].peers = [
            (("127.0.0.0", 3000, None),),
            (("127.0.0.1", 3000, None),),
        ]

        expected = ["127.0.0.1:3000"]
        self.assertEqual(
            sorted(cl.get_visibility_error_nodes()),
            sorted(expected),
            "get_visibility_error_nodes did not return the expected result",
        )

    async def test_get_down_nodes(self):
        cl = await self.get_cluster_mock(3)

        expected = ["172.17.0.3:3000"]
        self.assertEqual(
            sorted(await cl.get_down_nodes()),
            sorted(expected),
            "get_down_nodes did not return the expected result",
        )

    async def test_update_aliases(self):
        cl = await self.get_cluster_mock(3)
        aliases = {}
        endpoints = [("127.0.0.1", 3000)]
        key1 = Node.create_key("127.0.0.2", 3000)
        cl.update_aliases(aliases, endpoints, key1)
        expected = {"127.0.0.1:3000": "127.0.0.2:3000"}
        self.assertEqual(
            aliases, expected, "update_aliases did not return the expected result"
        )

        key2 = Node.create_key("127.0.0.3", 3000)
        cl.update_aliases(aliases, endpoints, key2)
        self.assertEqual(
            aliases, expected, "update_aliases did not return the expected result"
        )

        n = cl.nodes[key1]
        n.alive = False
        cl.nodes[key1] = n
        cl.update_aliases(aliases, endpoints, key2)
        expected = {"127.0.0.1:3000": "127.0.0.3:3000"}
        self.assertEqual(
            aliases, expected, "update_aliases did not return the expected result"
        )

    async def test_clear_node_list(self):
        cl = await self.get_cluster_mock(3)
        aliases = cl.aliases
        cl.aliases = {
            "127.0.0.1:3000": "127.0.0.2:3000",
            "127.0.0.2:3000": "127.0.0.2:3000",
            "127.0.0.0:3000": "127.0.0.0:3000",
        }
        cl.clear_node_list()
        self.assertEqual(
            len(cl.nodes), 2, "clear_node_list did not return the expected result"
        )
        cl.aliases = aliases

    @asynctest.fail_on(active_handles=True)
    async def test_call_node_method(self):
        cl = await self.get_cluster_mock(2)

        await cl.call_node_method_async(nodes="all", method_name="info_peers")
        for n in cl.nodes.values():
            n._info_cinfo.assert_any_call("peers-clear-std", n.ip)

        key = "127.0.0.1:3000"
        await cl.call_node_method_async(
            nodes=[key], method_name="info", command="build"
        )
        n = cl.get_node(key)[0]
        n._info_cinfo.assert_called_with("build", n.ip)

        key = "127.0.0.1"
        await cl.call_node_method_async(
            nodes=[key], method_name="info", command="build"
        )
        n = cl.get_node(key)[0]
        n._info_cinfo.assert_called_with("build", n.ip)

        keys = ["127.0.0*"]
        await cl.call_node_method_async(nodes=keys, method_name="info", command="build")
        n = cl.get_node(keys[0])[0]
        n._info_cinfo.assert_any_call("build", n.ip)
        n = cl.get_node(keys[0])[1]
        n._info_cinfo.assert_any_call("build", n.ip)

    async def test_is_XDR_enabled(self):
        cl = await self.get_cluster_mock(
            2,
            return_key_value={
                "get-config:context=xdr": "enable-xdr=true;config1=config1value;"
            },
        )
        expected = {"127.0.0.1:3000": True, "127.0.0.0:3000": True}
        self.assertEqual(
            await cl.is_XDR_enabled(),
            expected,
            "is_XDR_enabled(nodes=all) did not return the expected result",
        )

        cl = await self.get_cluster_mock(
            2,
            return_key_value={
                "get-config:context=xdr": "enable-xdr=false;config1=config1value;"
            },
        )
        key = "127.0.0.1:3000"
        expected = {key: False}
        self.assertEqual(
            await cl.is_XDR_enabled(nodes=[key]),
            expected,
            "is_XDR_enabled did not return the expected result",
        )

    async def test_is_feature_present(self):
        cl = await self.get_cluster_mock(
            2,
        )
        expected = {"127.0.0.1:3000": True, "127.0.0.0:3000": True}
        self.assertEqual(
            await cl.is_feature_present("cdt-map"),
            expected,
            "is_feature_present(nodes=all) did not return the expected result",
        )

        cl = await self.get_cluster_mock(
            2,
            return_key_value={
                "features": "batch-index;blob-bits;cdt-list;cdt-map;cluster-stable;float;geo;"
            },
        )
        key = "127.0.0.1:3000"
        expected = {key: False}
        self.assertEqual(
            await cl.is_feature_present("wrongFeature", nodes=[key]),
            expected,
            "is_feature_present did not return the expected result",
        )

    async def test_get_IP_to_node_map(self):
        cl = await self.get_cluster_mock(3)
        aliases = cl.aliases
        cl.aliases = {
            "127.0.0.1:3000": "127.0.0.2:3000",
            "127.0.0.2:3000": "127.0.0.2:3000",
            "127.0.0.0:3000": "127.0.0.0:3000",
        }
        expected = {
            "127.0.0.1:3000": "A00000000000002",
            "127.0.0.2:3000": "A00000000000002",
            "127.0.0.0:3000": "A00000000000000",
        }
        self.assertEqual(
            await cl.get_IP_to_node_map(),
            expected,
            "get_IP_to_node_map did not return the expected result",
        )
        cl.aliases = aliases

    async def test_get_node_to_IP_map(self):
        cl = await self.get_cluster_mock(3)
        aliases = cl.aliases
        cl.aliases = {
            "127.0.0.1:3000": "127.0.0.2:3000",
            "127.0.0.2:3000": "127.0.0.2:3000",
            "127.0.0.0:3000": "127.0.0.0:3000",
        }
        expected = {
            "A00000000000002": "127.0.0.1:3000,127.0.0.2:3000",
            "A00000000000000": "127.0.0.0:3000",
        }
        self.assertEqual(
            await cl.get_node_to_IP_map(),
            expected,
            "get_node_to_IP_map did not return the expected result",
        )
        cl.aliases = aliases

    async def test_get_seed_nodes(self):
        cl = await self.get_cluster_mock(3)
        expected = [("127.0.0.0", 3000, None)]
        self.assertEqual(
            cl.get_seed_nodes(),
            expected,
            "get_seed_nodes did not return the expected result",
        )
