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

import collections
import contextlib
import unittest
from unittest.mock import patch

from lib.live_cluster.client import node
from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.get_controller import GetStatisticsController
from test.e2e import lib

NODE_COUNT = 2
SINDEXES = ("e2e-age", "e2e-name")


class RequestRecorder:
    """Records the commands of every info request, by the address it went to."""

    def __init__(self):
        self.requests = collections.defaultdict(list)
        self.original = ASSocket.info

    async def send(self, sock, command):
        self.requests["%s:%s" % (sock.ip, sock.port)].append(command)
        return await self.original(sock, command)

    def counts(self):
        return {address: len(sent) for address, sent in self.requests.items()}

    def single_commands(self):
        return [
            c for sent in self.requests.values() for c in sent if isinstance(c, str)
        ]


@contextlib.contextmanager
def recording():
    """Records requests, with the cluster refresh held off so only the command's own
    requests are counted."""
    recorder = RequestRecorder()

    with patch.object(
        ASSocket, "info", lambda sock, command: recorder.send(sock, command)
    ), patch.object(Cluster, "need_to_refresh_cluster", return_value=False):
        yield recorder


def stat_names(response):
    return sorted(pair.split("=")[0] for pair in response.split(";") if pair)


async def connect():
    return await Cluster(
        [(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin"
    )


class RoundTripTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=NODE_COUNT, mesh_over_bridge=True)
        lib.create_sindex(SINDEXES[0], "numeric", "test", "age")
        lib.create_sindex(SINDEXES[1], "string", "test", "name")

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    async def asyncSetUp(self):
        self.cl = await connect()
        self.assertEqual(len(self.cl.get_live_nodes()), NODE_COUNT)

    async def asyncTearDown(self):
        await self.cl.close()

    async def test_reused_sockets_are_not_probed(self):
        with recording() as recorder:
            for _ in range(3):
                await self.cl.info_statistics()

        self.assertNotIn("node", recorder.single_commands())

    async def test_namespace_statistics_take_two_requests_per_node(self):
        with recording() as recorder:
            stats = await self.cl.info_all_namespace_statistics()

        self.assertEqual(set(recorder.counts().values()), {2})

        for node_stats in stats.values():
            self.assertIn("objects", node_stats["test"])

    async def test_verbose_latencies_take_two_requests_per_node(self):
        with recording() as recorder:
            latencies = await self.cl.info_latencies(verbose=True)

        self.assertEqual(set(recorder.counts().values()), {2})
        self.assertEqual(len(latencies), NODE_COUNT)

    async def test_sindex_statistics_take_two_requests_per_node(self):
        with recording() as recorder:
            stats = await GetStatisticsController(self.cl).get_sindex()

        self.assertEqual(set(recorder.counts().values()), {2})
        self.assertEqual(len(stats), NODE_COUNT)

        for node_stats in stats.values():
            for name in SINDEXES:
                (key,) = [k for k in node_stats if k.endswith(" " + name)]
                self.assertGreater(len(node_stats[key]), 5, node_stats[key])

    async def test_batched_answers_match_single_ones(self):
        stable = (
            "service-clear-std",
            "peers-clear-std",
            "peers-generation",
            "roster:",
            "histogram:namespace=test;type=ttl",
        )
        changing = (
            "connection",
            "namespace/test",
            "sindex-stat:namespace=test;indexname=%s" % SINDEXES[0],
        )

        batched = await self.cl.info(stable + changing)

        for command in stable + changing:
            single = await self.cl.info(command)

            for address, answers in batched.items():
                self.assertIn(command, answers)

                if command in stable:
                    self.assertEqual(answers[command], single[address], command)
                else:
                    self.assertEqual(
                        stat_names(answers[command]),
                        stat_names(single[address]),
                        command,
                    )

    async def test_hostname_runs_at_most_once_for_the_cluster(self):
        shell = node.util.async_shell_command
        calls = []

        async def recording_shell(command):
            calls.append(command)
            return await shell(command)

        with patch.object(node.util, "async_shell_command", recording_shell):
            cl = await connect()
            live = len(cl.get_live_nodes())
            await cl.close()

        self.assertEqual(live, NODE_COUNT)
        self.assertLessEqual(calls.count("hostname -I"), 1)

    async def test_z_first_command_after_a_node_restart_reaches_every_node(self):
        """Runs last: the restart drops every pooled socket to that node. With the
        refresh held off, the command itself must notice and connect again."""
        await self.cl.info_statistics()

        lib.restart_node(NODE_COUNT)
        lib.wait_for_cluster(NODE_COUNT)

        with patch.object(Cluster, "need_to_refresh_cluster", return_value=False):
            answers = await self.cl.info("node")

        self.assertTrue(
            all(isinstance(answer, str) for answer in answers.values()), answers
        )
        self.assertEqual(len(self.cl.get_live_nodes()), NODE_COUNT)
