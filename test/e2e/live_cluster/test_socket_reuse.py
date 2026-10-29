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

import asyncio
import unittest
from unittest.mock import patch

from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.cluster import Cluster
from test.e2e import lib

NODE_COUNT = 2
IDLE_REAP_MS = 1000
PROBE_TEST_COMMANDS = ("features", "service-clear-std", "rack-ids")


async def connect():
    return await Cluster(
        [(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin"
    )


def every_node_answered(answers):
    return len(answers) == NODE_COUNT and all(
        isinstance(answer, str) for answer in answers.values()
    )


class SocketReuseTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=NODE_COUNT, mesh_over_bridge=True)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    async def asyncSetUp(self):
        self.cl = await connect()
        self.assertEqual(len(self.cl.get_live_nodes()), NODE_COUNT)

    async def asyncTearDown(self):
        await self.cl.close()

    async def test_reused_sockets_are_not_probed(self):
        sent = []
        send = ASSocket.info

        async def recording_send(sock, command):
            sent.append(command)
            return await send(sock, command)

        with patch.object(ASSocket, "info", recording_send), patch.object(
            Cluster, "need_to_refresh_cluster", return_value=False
        ):
            for command in PROBE_TEST_COMMANDS:
                await self.cl.info(command)

        self.assertEqual(set(sent) - {"node"}, set(PROBE_TEST_COMMANDS), sent)
        self.assertNotIn("node", sent)

    async def test_connecting_opens_one_socket_per_node(self):
        connects = []
        open_socket = ASSocket.connect

        async def recording_connect(sock):
            connects.append((sock.ip, sock.port))
            return await open_socket(sock)

        with patch.object(ASSocket, "connect", recording_connect):
            cl = await connect()

            with patch.object(Cluster, "need_to_refresh_cluster", return_value=False):
                answers = await cl.info("statistics")

            await cl.close()

        self.assertTrue(every_node_answered(answers), answers)
        self.assertEqual(len(connects), NODE_COUNT, connects)

    async def test_sockets_the_server_reaped_while_idle_are_replaced(self):
        config = await self.cl.info_get_config(stanza="service")
        original = {node["proto-fd-idle-ms"] for node in config.values()}
        self.assertEqual(len(original), 1, original)
        await self.cl.info("statistics")
        lib.CLIENT.info_all(
            "set-config:context=service;proto-fd-idle-ms=%d" % IDLE_REAP_MS
        )

        try:
            await self.cl.info("cluster-name")
            await asyncio.sleep(IDLE_REAP_MS / 1000 * 3)

            with patch.object(Cluster, "need_to_refresh_cluster", return_value=False):
                answers = await self.cl.info("edition")
        finally:
            lib.CLIENT.info_all(
                "set-config:context=service;proto-fd-idle-ms=%s" % original.pop()
            )

        self.assertTrue(every_node_answered(answers), answers)
        self.assertEqual(len(self.cl.get_live_nodes()), NODE_COUNT)

    async def test_z_first_command_after_a_node_restart_reaches_every_node(self):
        """Runs last: the restart drops every pooled socket to that node. With the
        refresh held off, the command itself must notice and connect again."""
        await self.cl.info("statistics")

        lib.restart_node(NODE_COUNT)
        lib.wait_for_cluster(NODE_COUNT)

        with patch.object(Cluster, "need_to_refresh_cluster", return_value=False):
            answers = await self.cl.info("node")

        self.assertTrue(every_node_answered(answers), answers)
        self.assertEqual(len(self.cl.get_live_nodes()), NODE_COUNT)
