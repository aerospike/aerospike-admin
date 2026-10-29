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

from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node
from lib.live_cluster.get_controller import GetStatisticsController
from lib.utils import util
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

    def carrying(self, prefix):
        """Per address, the requests that carry at least one command with prefix."""
        return {
            address: [
                command
                for command in sent
                if any(
                    name.startswith(prefix)
                    for name in ([command] if isinstance(command, str) else command)
                )
            ]
            for address, sent in self.requests.items()
        }

    def assert_one_request_each(self, test, prefix):
        carrying = self.carrying(prefix)
        test.assertEqual(len(carrying), NODE_COUNT, carrying)

        for address, requests in carrying.items():
            test.assertEqual(len(requests), 1, (address, requests))


@contextlib.contextmanager
def recording():
    """Records requests, with the cluster refresh held off and earlier answers
    forgotten, so every request the command needs is seen."""
    recorder = RequestRecorder()

    for attr in vars(Node).values():
        if isinstance(attr, util.async_cached):
            attr.cache.clear()

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

    async def test_namespace_statistics_take_one_request_per_node(self):
        with recording() as recorder:
            stats = await self.cl.info_all_namespace_statistics()

        recorder.assert_one_request_each(self, "namespace/")

        for node_stats in stats.values():
            self.assertIn("objects", node_stats["test"])

    async def test_verbose_latencies_take_one_request_per_node(self):
        with recording() as recorder:
            latencies = await self.cl.info_latencies(verbose=True)

        recorder.assert_one_request_each(self, "latencies:")
        self.assertEqual(len(latencies), NODE_COUNT)

    async def test_sindex_list_and_statistics_take_one_request_each_per_node(self):
        with recording() as recorder:
            stats = await GetStatisticsController(self.cl).get_sindex()

        recorder.assert_one_request_each(self, "sindex-list:")
        recorder.assert_one_request_each(self, "sindex-stat:")
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
