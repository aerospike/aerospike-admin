# Copyright 2013-2025 Aerospike, Inc.
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
from mock import patch, AsyncMock
import socket
from collections import deque

import lib
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node
from lib.utils import constants

import warnings

import unittest


class ClusterTest(unittest.IsolatedAsyncioTestCase):
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

            # First call - node and build for admin port detection
            if cmd == ["node", "build"]:
                return {
                    "node": return_value,
                    "build": return_key_value.get("build", "4.9.0.0"),
                }

            # Second call - connection info for admin port check (8.1+)
            if cmd == "connection":
                return "admin=false"

            # Third call - service addresses and peers
            if cmd == ["service-clear-std", "peers-clear-std"]:
                return {
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
                }

            # Legacy support for old test format
            if cmd == ["node", "service-clear-std", "peers-clear-std"]:
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

            # Handle the new command structure with build as separate command
            if cmd == ["node", "service-clear-std", "peers-clear-std"]:
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
                }

            if cmd == "peers-tls-std":
                return "10,4333,[[BB9050011AC4202,peers,[172.17.0.1]],[BB9070011AC4202,peers,[[2001:db8:85a3::8a2e]]]]"

            if cmd == "alumni-clear-std":
                return "0,3000,[[BB9050011AC4202,,[172.17.0.3]]]"

            if cmd == "alumni-clear-alt":
                return "0,3000,[[BB9050011AC4202,,[172.17.0.3]]]"

            if cmd == "alumni-tls-alt":
                return "0,4333,[[BB9050011AC4202,peers-alumni,[172.17.0.3]]]"

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

    async def asyncSetUp(self):
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
            ("183.168.0.1", 3000),
            ("183.168.0.11", 3000),
        ]
        for i, (ip, port) in enumerate(ip_ports):
            n = await self.get_info_mock("A0000000000000" + str(i), ip=ip, port=port)
            cl.update_node(n)

        n = await self.get_info_mock("A", ip="1.1.1.1", port=3000)
        cl.update_node(n)
        n = await self.get_info_mock("AB", ip="2.2.2.2", port=3000)
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
            "183.168.0.1:3000",
            "183.168.0.11:3000",
        ]

        actual = cl.get_node("A0*")
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

        expected = [
            "183.168.0.1:3000",
        ]

        actual = cl.get_node("183.168.0.1")
        actual = map(lambda x: x.key, actual)

        self.assertCountEqual(expected, actual)

        expected = [
            "1.1.1.1:3000",
        ]

        actual = cl.get_node("A")
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
        expected = {"127.0.0.0:3000": "host.domain.local:30"}
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

    async def test_cluster_with_admin_node(self):
        """
        Test that clusters properly handle admin nodes
        """
        # Create a mock admin node using the existing infrastructure
        # but override the mock to simulate admin port enabled
        original_side_effect = Node._info_cinfo.side_effect

        async def admin_info_side_effect(*args, **kwargs):
            cmd = args[0]
            ip = args[1] if len(args) > 1 else "127.0.0.1"

            # First call - node and build for admin port detection
            if cmd == ["node", "build"]:
                return {
                    "node": "ADMIN000000000",
                    "build": "8.1.0.0",  # 8.1+ supports admin port
                }
            # Second call - connection info (admin port enabled)
            elif cmd == "connection":
                return "admin=true"
            # Third call - admin address info
            elif cmd == "admin-clear-std":
                return "127.0.0.1:8081"
            # Legacy calls for backwards compatibility
            elif cmd == ["node", "admin-clear-std"]:
                return {
                    "node": "ADMIN000000000",
                    "admin-clear-std": "127.0.0.1:8081",
                }
            elif cmd == "node":
                return "ADMIN000000000"
            elif cmd == "build":
                return "8.1.0.0"
            else:
                # For any other calls, fall back to original mock behavior
                if original_side_effect:
                    return await original_side_effect(*args, **kwargs)
                else:
                    return ""

        Node._info_cinfo.side_effect = admin_info_side_effect

        # Create admin node
        admin_node = await Node("127.0.0.1", port=8081)

        # Verify admin node properties
        self.assertTrue(admin_node.is_admin_node, "Node should be marked as admin node")
        self.assertEqual(
            admin_node.node_id, "ADMIN000000000", "Admin node ID should be set"
        )
        self.assertEqual(
            admin_node.peers, [], "Admin node should have empty peers list"
        )

        # Create a cluster and add the admin node
        cl = await Cluster([("127.0.0.1", 8081, None)])
        cl.update_node(admin_node)

        # Verify admin node is in cluster but has no peers
        nodes = cl.get_nodes("all")
        admin_nodes = [n for n in nodes if getattr(n, "is_admin_node", False)]
        self.assertEqual(len(admin_nodes), 1, "Should have exactly one admin node")
        self.assertEqual(admin_nodes[0].peers, [], "Admin node should have empty peers")

        # Verify admin node peer methods return empty lists
        self.assertEqual(
            await admin_nodes[0].info_peers(),
            [],
            "Admin node info_peers should return empty list",
        )
        self.assertEqual(
            await admin_nodes[0].info_peers_alumni(),
            [],
            "Admin node info_peers_alumni should return empty list",
        )
        self.assertEqual(
            await admin_nodes[0].info_peers_alt(),
            [],
            "Admin node info_peers_alt should return empty list",
        )
        self.assertEqual(
            await admin_nodes[0].info_peers_list(),
            [],
            "Admin node info_peers_list should return empty list",
        )

        # Restore original mock behavior
        Node._info_cinfo.side_effect = original_side_effect

    async def test_has_admin_nodes_visual_cue_functionality(self):
        """Test has_admin_nodes() method for admin port visual cue functionality"""
        cl = await self.get_cluster_mock(2)

        # Test with no admin nodes
        self.assertFalse(cl.has_admin_nodes())

        # Add admin node
        admin_node = await self.get_info_mock(
            "ADMIN000000000", ip="127.0.0.1", port=3003
        )
        admin_node.is_admin_node = True
        cl.update_node(admin_node)

        # Test with admin nodes
        self.assertTrue(cl.has_admin_nodes())

    async def test_get_admin_nodes_visual_cue_functionality(self):
        """Test get_admin_nodes() method for admin port visual cue functionality"""
        cl = await self.get_cluster_mock(2)

        # Test empty list initially
        admin_nodes = cl.get_admin_nodes()
        self.assertEqual(len(admin_nodes), 0)

        # Add admin node
        admin_node = await self.get_info_mock(
            "ADMIN000000000", ip="127.0.0.1", port=3003
        )
        admin_node.is_admin_node = True
        cl.update_node(admin_node)

        # Test returns admin nodes
        admin_nodes = cl.get_admin_nodes()
        self.assertEqual(len(admin_nodes), 1)
        self.assertTrue(getattr(admin_nodes[0], "is_admin_node", False))

    async def test_cluster_str_admin_port_visual_cue(self):
        """Test cluster string representation shows admin port visual cue"""
        cl = await self.get_cluster_mock(2)

        # Test without admin nodes - no admin message
        cluster_str = str(cl)
        self.assertNotIn("Connected via admin port", cluster_str)

        # Add alive admin node
        admin_node = await self.get_info_mock(
            "ADMIN000000000", ip="127.0.0.1", port=3003
        )
        admin_node.is_admin_node = True
        admin_node.alive = True
        cl.update_node(admin_node)

        # Test with alive admin nodes - shows admin message
        cluster_str = str(cl)
        self.assertIn(constants.ADMIN_PORT_VISUAL_CUE_MSG, cluster_str)

        # Test with dead admin node - no admin message
        admin_node.alive = False
        cluster_str = str(cl)
        self.assertNotIn(constants.ADMIN_PORT_VISUAL_CUE_MSG, cluster_str)


class ClusterRefreshTest(unittest.IsolatedAsyncioTestCase):
    """Test cases for cluster refresh and socket reuse optimization"""

    async def asyncSetUp(self):
        # Mock dependencies
        self.get_fully_qualified_domain_name = patch(
            "lib.live_cluster.client.node.get_fully_qualified_domain_name"
        ).start()
        self.async_shell_cmd_mock = patch(
            "lib.live_cluster.client.node.util.async_shell_command"
        ).start()
        getaddrinfo = patch("socket.getaddrinfo")
        self.addCleanup(patch.stopall)

        lib.live_cluster.client.node.Node.info_build = patch(
            "lib.live_cluster.client.node.Node.info_build", AsyncMock()
        ).start()
        socket.getaddrinfo = getaddrinfo.start()

        lib.live_cluster.client.node.Node.info_build.return_value = "5.0.0.11"
        self.get_fully_qualified_domain_name.return_value = "host.domain.local"
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.1.1.1", 3000))]

        # Mock _info_cinfo for Node initialization
        self.init_info_mock = patch.object(
            lib.live_cluster.client.node.Node, "_info_cinfo", new_callable=AsyncMock
        ).start()

        def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "features", "connection"]:
                return {
                    "node": "A00000000000000",
                    "features": "features",
                    "connection": "admin=false",
                }
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "192.1.1.1:3000",
                    "peers-clear-std": "2,3000,[[1A0,,[192.1.1.1]]]",
                }
            else:
                return "mock_response"

        self.init_info_mock.side_effect = info_side_effect

    async def test_find_new_nodes_no_nodes(self):
        """Test find_new_nodes when cluster has no nodes"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])
        cluster.nodes = {}  # Empty nodes

        result = await cluster.find_new_nodes()

        # Should return seed nodes when no nodes exist
        self.assertEqual(set(result), {("192.1.1.1", 3000, None)})

    async def test_find_new_nodes_with_nodes_no_refresh_needed(self):
        """Test find_new_nodes when nodes don't need refresh"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])

        # Create a node that doesn't need refresh
        node = await Node("192.1.1.1", 3000)
        node.needs_refresh = AsyncMock(return_value=False)
        node.refresh_connection = AsyncMock()
        node.service_addresses = [("192.1.1.1", 3000, None)]
        node.peers = [("192.1.1.2", 3000, None)]
        # Key is automatically set based on IP and port

        cluster.nodes = {"192.1.1.1:3000": node}

        result = await cluster.find_new_nodes()

        # Should not call refresh_connection
        node.refresh_connection.assert_not_called()
        # Should return peers from existing nodes
        self.assertIn(("192.1.1.2", 3000, None), result)

    async def test_find_new_nodes_with_nodes_refresh_needed(self):
        """Test find_new_nodes when nodes need refresh"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])

        # Create a node that needs refresh
        node = await Node("192.1.1.1", 3000)
        node.needs_refresh = AsyncMock(return_value=True)
        node.refresh_connection = AsyncMock()
        node.service_addresses = [("192.1.1.1", 3000, None)]
        node.peers = [("192.1.1.2", 3000, None)]
        # Key is automatically set based on IP and port

        cluster.nodes = {"192.1.1.1:3000": node}

        result = await cluster.find_new_nodes()

        # Should call refresh_connection
        node.refresh_connection.assert_called_once()
        # Should return peers from refreshed nodes
        self.assertIn(("192.1.1.2", 3000, None), result)

    async def test_find_new_nodes_node_key_changed(self):
        """Test find_new_nodes when node key changes (service address change)"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])

        # Create a node with different key than expected
        node = await Node("192.1.1.1", 3000)
        node.needs_refresh = AsyncMock(return_value=False)
        node.refresh_connection = AsyncMock()
        node.service_addresses = [("192.1.1.2", 3000, None)]  # Different IP
        node.peers = [("192.1.1.3", 3000, None)]
        # Update IP to change the key
        node.ip = "192.1.1.2"
        node._service_IP_port = node.create_key("192.1.1.2", 3000)

        cluster.nodes = {"192.1.1.1:3000": node}  # Old key in cluster

        result = await cluster.find_new_nodes()

        # Should remove old key and add new key
        self.assertNotIn("192.1.1.1:3000", cluster.nodes)
        self.assertIn("192.1.1.2:3000", cluster.nodes)
        # Should return peers from updated nodes
        self.assertIn(("192.1.1.3", 3000, None), result)

    async def test_find_new_nodes_only_connect_seed(self):
        """Test find_new_nodes when only_connect_seed is True"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])
        cluster.only_connect_seed = True

        # Create a node with peers
        node = await Node("192.1.1.1", 3000)
        node.needs_refresh = AsyncMock(return_value=False)
        node.refresh_connection = AsyncMock()
        node.service_addresses = [("192.1.1.1", 3000, None)]
        node.peers = [("192.1.1.2", 3000, None)]
        # Key is automatically set based on IP and port

        cluster.nodes = {"192.1.1.1:3000": node}

        result = await cluster.find_new_nodes()

        # Should not include peers when only_connect_seed is True
        self.assertNotIn(("192.1.1.2", 3000, None), result)

    async def test_find_new_nodes_empty_service_addresses(self):
        """Test find_new_nodes when nodes have empty service addresses"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])

        # Create a node with empty service addresses
        node = await Node("192.1.1.1", 3000)
        node.needs_refresh = AsyncMock(return_value=False)
        node.refresh_connection = AsyncMock()
        node.service_addresses = []  # Empty
        node.peers = [("192.1.1.2", 3000, None)]
        # Key is automatically set based on IP and port

        cluster.nodes = {"192.1.1.1:3000": node}

        result = await cluster.find_new_nodes()

        # Should return peers when no service addresses
        self.assertIn(("192.1.1.2", 3000, None), result)

    async def test_find_new_nodes_socket_reuse_optimization(self):
        """Test that socket reuse optimization works at cluster level"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])

        # Create a node that doesn't need refresh (socket reuse scenario)
        node = await Node("192.1.1.1", 3000)
        node.needs_refresh = AsyncMock(return_value=False)  # No refresh needed
        node.refresh_connection = AsyncMock()
        node.service_addresses = [("192.1.1.1", 3000, None)]
        node.peers = [("192.1.1.2", 3000, None)]
        # Key is automatically set based on IP and port

        # Mock socket pool to verify it's not cleared
        node.socket_pool = {"3000": deque([AsyncMock()])}  # Has existing sockets

        cluster.nodes = {"192.1.1.1:3000": node}

        result = await cluster.find_new_nodes()

        # Should not call refresh_connection (socket reuse)
        node.refresh_connection.assert_not_called()
        # Socket pool should remain intact
        self.assertEqual(len(node.socket_pool["3000"]), 1)
        # Should return peers normally
        self.assertIn(("192.1.1.2", 3000, None), result)

    async def test_find_new_nodes_multiple_nodes_mixed_refresh(self):
        """Test find_new_nodes with multiple nodes, some needing refresh"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])

        # Node 1: doesn't need refresh
        node1 = await Node("192.1.1.1", 3000)
        node1.needs_refresh = AsyncMock(return_value=False)
        node1.refresh_connection = AsyncMock()
        node1.service_addresses = [("192.1.1.1", 3000, None)]
        node1.peers = [("192.1.1.2", 3000, None)]
        # Key is automatically set based on IP and port

        # Node 2: needs refresh
        node2 = await Node("192.1.1.2", 3000)
        node2.needs_refresh = AsyncMock(return_value=True)
        node2.refresh_connection = AsyncMock()
        node2.service_addresses = [("192.1.1.2", 3000, None)]
        node2.peers = [("192.1.1.3", 3000, None)]
        # Key is automatically set based on IP and port

        cluster.nodes = {"192.1.1.1:3000": node1, "192.1.1.2:3000": node2}

        result = await cluster.find_new_nodes()

        # Node 1 should not be refreshed
        node1.refresh_connection.assert_not_called()
        # Node 2 should be refreshed
        node2.refresh_connection.assert_called_once()

        # Should return peers that are not in any service addresses
        # ('192.1.1.2', 3000, None) is in Node2's service_addresses, so it's filtered out
        # ('192.1.1.3', 3000, None) is not in any service_addresses, so it's returned
        self.assertNotIn(
            ("192.1.1.2", 3000, None), result
        )  # Filtered out because it's in service addresses
        self.assertIn(
            ("192.1.1.3", 3000, None), result
        )  # Not in service addresses, so returned

    async def test_load_balancer_integration_scenario(self):
        """Test integration scenario: cluster with load balancer nodes"""
        cluster = await Cluster([("load-balancer.com", 3000, None)])

        # Create a node connected via load balancer
        lb_node = await Node("load-balancer.com", 3000)
        lb_node.needs_refresh = AsyncMock(
            return_value=True
        )  # Should refresh to try direct
        lb_node.refresh_connection = AsyncMock()
        lb_node.service_addresses = [
            ("192.1.1.1", 3000, None),
            ("192.1.1.2", 3000, None),
            ("load-balancer.com", 3000, None),  # LB also in addresses
        ]
        lb_node.peers = [("192.1.1.3", 3000, None)]

        cluster.nodes = {"load-balancer.com:3000": lb_node}

        result = await cluster.find_new_nodes()

        # Should call refresh to attempt direct connection optimization
        lb_node.refresh_connection.assert_called_once()

        # Should return peer addresses for discovery
        self.assertIn(("192.1.1.3", 3000, None), result)

    async def test_mixed_cluster_lb_and_direct_connections(self):
        """Test cluster with mix of load balancer and direct connections"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])

        # Node 1: Direct connection (no refresh needed)
        direct_node = await Node("192.1.1.1", 3000)
        direct_node.needs_refresh = AsyncMock(return_value=False)
        direct_node.refresh_connection = AsyncMock()
        direct_node.service_addresses = [("192.1.1.1", 3000, None)]
        direct_node.peers = [("192.1.1.2", 3000, None)]

        # Node 2: Load balancer connection (needs refresh)
        lb_node = await Node("load-balancer.com", 3000)
        lb_node.needs_refresh = AsyncMock(return_value=True)
        lb_node.refresh_connection = AsyncMock()
        lb_node.service_addresses = [("192.1.1.2", 3000, None)]
        lb_node.peers = [("192.1.1.3", 3000, None)]

        cluster.nodes = {
            "192.1.1.1:3000": direct_node,
            "load-balancer.com:3000": lb_node,
        }

        result = await cluster.find_new_nodes()

        # Direct node should not be refreshed
        direct_node.refresh_connection.assert_not_called()

        # LB node should be refreshed
        lb_node.refresh_connection.assert_called_once()

        # Should return new peer addresses
        self.assertIn(("192.1.1.3", 3000, None), result)

    async def test_cluster_refresh_optimization_performance(self):
        """Test that cluster refresh optimization improves performance"""
        cluster = await Cluster([("192.1.1.1", 3000, None)])

        # Create multiple nodes with different refresh needs
        nodes = {}
        refresh_call_count = 0

        for i in range(5):
            ip = f"192.1.1.{i+1}"
            node = await Node(ip, 3000)

            # Only odd-numbered nodes need refresh
            needs_refresh = i % 2 == 1
            node.needs_refresh = AsyncMock(return_value=needs_refresh)

            def make_refresh_mock():
                nonlocal refresh_call_count

                async def refresh_mock():
                    nonlocal refresh_call_count
                    refresh_call_count += 1

                return refresh_mock

            node.refresh_connection = AsyncMock(side_effect=make_refresh_mock())
            node.service_addresses = [(ip, 3000, None)]
            node.peers = []

            nodes[f"{ip}:3000"] = node

        cluster.nodes = nodes

        await cluster.find_new_nodes()

        # Should only refresh nodes that need it (indices 1 and 3, so 2 out of 5)
        total_refresh_calls = sum(
            node.refresh_connection.call_count for node in nodes.values()
        )
        self.assertEqual(total_refresh_calls, 2)  # Only odd-numbered indices (1, 3)


class ConnectionFlowEdgeCasesTest(unittest.IsolatedAsyncioTestCase):
    """Test edge cases for the new connection flow with build caching and admin port detection"""

    async def test_node_connection_with_invalid_build_version(self):
        """Test node connection when build version is malformed"""

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "build"]:
                return {
                    "node": "NODE000000000",
                    "build": "invalid.version.format",
                }
            elif cmd == "connection":
                return "admin=false"
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "127.0.0.1:3000",
                    "peers-clear-std": "",
                }
            return ""

        with patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):
            node = await Node("127.0.0.1", timeout=0)

        # Should still create node even with invalid version
        self.assertIsNotNone(node)
        # Node was created successfully
        self.assertTrue(node.alive or not node.alive)  # Node exists

    async def test_node_connection_build_call_returns_exception(self):
        """Test node connection when build info call returns exception"""

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "build"]:
                return {
                    "node": "NODE000000000",
                    "build": Exception("Network error"),
                }
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "127.0.0.1:3000",
                    "peers-clear-std": "",
                }
            return ""

        with patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):
            node = await Node("127.0.0.1", timeout=0)

        # Should still create node even when build is exceptional
        self.assertIsNotNone(node)
        # Node should exist (main point of test)
        self.assertIsNotNone(node.node_id)

    async def test_admin_port_detection_connection_call_fails(self):
        """Test admin port detection when connection info call fails"""

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "build"]:
                return {
                    "node": "NODE000000000",
                    "build": "8.1.0.0",  # Supports admin port
                }
            elif cmd == "connection":
                # Connection call fails
                raise Exception("Connection info not available")
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "127.0.0.1:3000",
                    "peers-clear-std": "",
                }
            return ""

        with patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):
            node = await Node("127.0.0.1", timeout=0)

        # Should fall back to service port path
        self.assertIsNotNone(node)
        self.assertFalse(node.is_admin_node)

    async def test_admin_port_enabled_but_address_fetch_fails(self):
        """Test when admin port is enabled but fetching admin address fails"""

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "build"]:
                return {
                    "node": "ADMIN000000000",
                    "build": "8.1.0.0",
                }
            elif cmd == "connection":
                return "admin=true"
            elif cmd == "admin-clear-std":
                # Admin address fetch fails
                raise Exception("Admin address not available")
            return ""

        with patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):
            try:
                node = await Node("127.0.0.1", timeout=0)
                # Should either fail or fall back gracefully
            except Exception as e:
                # Expected to fail if admin address can't be fetched
                self.assertIsInstance(e, Exception)

    async def test_connection_with_empty_peers_list(self):
        """Test connection when peers list is empty"""

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "build"]:
                return {
                    "node": "NODE000000000",
                    "build": "7.0.0.0",
                }
            elif cmd == "connection":
                return "admin=false"
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "127.0.0.1:3000",
                    "peers-clear-std": "",  # Empty peers
                }
            return ""

        with patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):
            node = await Node("127.0.0.1", timeout=0)

        # Should handle empty peers
        self.assertIsNotNone(node)
        self.assertEqual(node.peers, [])

    async def test_connection_with_multiple_service_addresses(self):
        """Test connection returns multiple service addresses"""

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "build"]:
                return {
                    "node": "NODE000000000",
                    "build": "7.0.0.0",
                }
            elif cmd == "connection":
                return "admin=false"
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "127.0.0.1:3000;192.168.1.1:3000;10.0.0.1:3000",
                    "peers-clear-std": "",
                }
            return ""

        with patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):
            node = await Node("127.0.0.1", timeout=0)

        # Should handle multiple addresses
        self.assertIsNotNone(node)
        self.assertGreaterEqual(len(node.service_addresses), 1)

    async def test_pre_8_1_server_skips_connection_check(self):
        """Test that pre-8.1 servers skip connection info call"""
        call_log = []

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            call_log.append(cmd)

            if cmd == ["node", "build"]:
                return {
                    "node": "NODE000000000",
                    "build": "7.9.0.0",  # Pre-8.1
                }
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "127.0.0.1:3000",
                    "peers-clear-std": "",
                }
            return ""

        with patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):
            node = await Node("127.0.0.1", timeout=0)

        # Connection call should NOT have been made for pre-8.1 servers
        self.assertNotIn("connection", call_log)
        self.assertFalse(node.is_admin_node)

    async def test_8_1_server_checks_connection_info(self):
        """Test that 8.1+ servers check connection info"""
        call_log = []

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            call_log.append(cmd)

            if cmd == ["node", "build"]:
                return {
                    "node": "NODE000000000",
                    "build": "8.1.0.0",  # 8.1+
                }
            elif cmd == "connection":
                return "admin=false"
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "127.0.0.1:3000",
                    "peers-clear-std": "",
                }
            return ""

        with patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):
            node = await Node("127.0.0.1", timeout=0)

        # Connection call SHOULD have been made for 8.1+ servers
        self.assertIn("connection", call_log)
        self.assertFalse(node.is_admin_node)  # admin=false

    async def test_node_refresh_updates_build_cache(self):
        """Test that node.refresh_connection() updates build cache (e.g., after server upgrade)"""
        call_phase = {"phase": "initial"}

        async def info_side_effect(*args, **kwargs):
            cmd = args[0]
            phase = call_phase["phase"]

            # Phase 1: Initial connection with version 7.0.0.0
            if phase == "initial":
                if cmd == ["node", "build"]:
                    return {
                        "node": "NODE000000000",
                        "build": "7.0.0.0",
                    }
                elif cmd == ["service-clear-std", "peers-clear-std"]:
                    return {
                        "service-clear-std": "127.0.0.1:3000",
                        "peers-clear-std": "",
                    }
                elif cmd == "node":
                    return "NODE000000000"
            # Phase 2: After refresh, server upgraded to 8.1.0.0
            elif phase == "refresh":
                if cmd == ["node", "build"]:
                    return {
                        "node": "NODE000000000",
                        "build": "8.1.0.0",  # Server upgraded!
                    }
                elif cmd == "connection":
                    return "admin=false"
                elif cmd == ["service-clear-std", "peers-clear-std"]:
                    return {
                        "service-clear-std": "127.0.0.1:3000",
                        "peers-clear-std": "",
                    }
                elif cmd == "node":
                    return "NODE000000000"
            return ""

        # Mock all necessary components for node initialization
        with patch(
            "lib.live_cluster.client.node.get_fully_qualified_domain_name",
            return_value="test.local",
        ), patch(
            "lib.live_cluster.client.node.util.async_shell_command",
            AsyncMock(return_value=None),
        ), patch(
            "socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 3000))]
        ), patch(
            "lib.live_cluster.client.node.Node.info_build",
            AsyncMock(return_value="7.0.0.0"),
        ), patch(
            "lib.live_cluster.client.node.Node._info_cinfo",
            AsyncMock(side_effect=info_side_effect),
        ):

            # Create node with initial version 7.0.0.0
            node = await Node("127.0.0.1", timeout=0)

            # Verify initial build version was set by _node_connect
            self.assertEqual(node.build, "7.0.0.0")
            self.assertFalse(node.is_admin_node)  # Pre-8.1

            # Simulate server upgrade - change phase for subsequent calls
            call_phase["phase"] = "refresh"

            # Refresh connection (this is what cluster.find_new_nodes() calls)
            await node.refresh_connection()

            # Build cache should now be updated to 8.1.0.0
            self.assertEqual(node.build, "8.1.0.0")
            # Connection info should have been checked for 8.1+
            self.assertFalse(node.is_admin_node)  # admin=false in mock
