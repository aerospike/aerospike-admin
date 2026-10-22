# Copyright 2026 Aerospike, Inc.
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
import glob
import os
import shutil
import socket
import time
import unittest
import uuid
from unittest.mock import patch

import bcrypt

import lib.live_cluster.live_cluster_root_controller as controller
from lib.live_cluster.client.node import Node
from lib.live_cluster.health_check_controller import HealthCheckController
from lib.utils import common, util
from test.e2e import lib
from test.perf.probe import Measurement, Probe

N_NODES = 3
TIMEOUT = 1
STARTUP_STALL_BUDGET = 0.1
COMMAND_STALL_BUDGET = 1
COLLECTINFO_PREFIX = "asadm_perf_"
ROLES = [
    "sys-admin",
    "user-admin",
    "data-admin",
    "read-write-udf",
    "sindex-admin",
    "read-write",
]


def delayed(func, seconds):
    def wrapper(*args, **kwargs):
        time.sleep(seconds)
        return func(*args, **kwargs)

    return wrapper


def on_node_shell_command(command):
    """The shell on an Aerospike host, where `iostat -y -x 5 1` samples for 5 s."""
    time.sleep(5 if "iostat" in command[0] else 0.01)
    return "", ""


def on_node_collect_sys_info(port=3000, file_header="", outfile=""):
    """collect_sys_info on an Aerospike host, scaled down from the 56 s measured."""
    time.sleep(5)
    return []


def wait_for_cluster(size):
    for _ in range(60):
        responses = lib.CLIENT.info_all("statistics").values()
        sizes = [
            dict(kv.split("=", 1) for kv in r.strip().split(";") if "=" in kv).get(
                "cluster_size"
            )
            for _, r in responses
            if r
        ]

        if len(sizes) == size and all(s == str(size) for s in sizes):
            return

        time.sleep(1)

    raise Exception(f"Cluster did not reach {size} nodes")


class LiveClusterPerformanceTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=N_NODES, mesh_over_bridge=True)
        wait_for_cluster(N_NODES)

        for set_name in ("perf-1", "perf-2", "perf-3"):
            lib.populate_db(set_name)

        lib.create_sindex("perf-int", "numeric", lib.NAMESPACE, "int", "perf-1")
        lib.create_sindex("perf-str", "string", lib.NAMESPACE, "str", "perf-2")

    @classmethod
    def tearDownClass(cls):
        lib.stop()

        for path in glob.glob(f"/tmp/{COLLECTINFO_PREFIX}*"):
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)

    async def asyncSetUp(self):
        asyncio.get_running_loop().set_debug(False)
        Node.dns_cache.clear()
        HealthCheckController.last_snapshot_collection_time = 0
        self.rc = None

    async def asyncTearDown(self):
        if self.rc:
            await self.rc.close()

    def new_user(self):
        """A new user, so the password hash starts cold, as in a new asadm process."""
        user, password = f"perf-{uuid.uuid4().hex[:8]}", uuid.uuid4().hex
        lib.CLIENT.admin_create_user(user, password, ROLES)
        time.sleep(1)

        return user, password

    async def start_asadm(self, user, password, on_node=False):
        self.rc = await controller.LiveClusterRootController(  # type: ignore
            [(lib.SERVER_IP, lib.PORT, None)],
            user=user,
            password=password,
            timeout=TIMEOUT,
        )

        for node in self.rc.cluster.nodes.values():
            node.localhost = on_node and node.port == lib.PORT

    async def measure_startup(self, scenario) -> Measurement:
        user, password = self.new_user()

        async with Probe(scenario) as m:
            await self.start_asadm(user, password)

        return m

    async def measure_command(self, scenario, command, on_node=False) -> Measurement:
        await self.start_asadm(*self.new_user(), on_node=on_node)

        async with Probe(scenario) as m:
            await util.capture_stdout(self.rc.execute, command.split())

        return m

    def assert_within_budget(self, m: Measurement, max_stall, max_hashes=None):
        m.live_nodes = len(self.rc.cluster.get_live_nodes())
        problems = []

        if m.live_nodes != N_NODES:
            problems.append(f"{m.live_nodes}/{N_NODES} nodes live")

        if m.timeouts:
            problems.append(f"{m.timeouts} timeouts")

        if m.max_stall > max_stall:
            where = ", ".join(w for w, _ in m.blockers.most_common(2))
            problems.append(
                f"event loop blocked {m.max_stall * 1000:.0f}ms, budget "
                f"{max_stall * 1000:.0f}ms ({where})"
            )

        if max_hashes is not None and m.hashes > max_hashes:
            problems.append(f"{m.hashes} password hashes, budget {max_hashes}")

        self.assertFalse(problems, f"{m.scenario}: " + "; ".join(problems))

    async def test_startup(self):
        m = await self.measure_startup("startup")
        self.assert_within_budget(m, STARTUP_STALL_BUDGET, max_hashes=1)

    async def test_info(self):
        m = await self.measure_command("info", "info")
        self.assert_within_budget(m, COMMAND_STALL_BUDGET)

    async def test_show_statistics(self):
        m = await self.measure_command("show statistics", "show statistics")
        self.assert_within_budget(m, COMMAND_STALL_BUDGET)

    async def test_show_latencies(self):
        m = await self.measure_command("show latencies -v", "show latencies -v")
        self.assert_within_budget(m, COMMAND_STALL_BUDGET)

    async def test_summary(self):
        m = await self.measure_command("summary", "summary")
        self.assert_within_budget(m, COMMAND_STALL_BUDGET)

    async def test_health(self):
        m = await self.measure_command("health", "health")
        self.assert_within_budget(m, COMMAND_STALL_BUDGET)

    async def test_collectinfo(self):
        m = await self.measure_command(
            "collectinfo", f"collectinfo --output-prefix {COLLECTINFO_PREFIX}"
        )
        self.assert_within_budget(m, COMMAND_STALL_BUDGET)

    async def test_startup_cpu_starved_host(self):
        """0.8 s per hash gives 3 nodes the stall 24 nodes had at 0.5 CPU."""
        with patch.object(bcrypt, "hashpw", delayed(bcrypt.hashpw, 0.8)):
            m = await self.measure_startup("startup, cpu-starved host")

        self.assert_within_budget(m, STARTUP_STALL_BUDGET, max_hashes=1)

    async def test_startup_unreachable_dns(self):
        with patch.object(socket, "getfqdn", delayed(socket.getfqdn, 2)):
            m = await self.measure_startup("startup, unreachable dns")

        self.assert_within_budget(m, STARTUP_STALL_BUDGET)

    async def test_startup_slow_dns(self):
        with patch.object(socket, "getaddrinfo", delayed(socket.getaddrinfo, 0.3)):
            m = await self.measure_startup("startup, slow dns")

        self.assert_within_budget(m, STARTUP_STALL_BUDGET)

    async def test_health_on_node(self):
        with patch.object(util, "shell_command", on_node_shell_command):
            m = await self.measure_command("health, on a node", "health", on_node=True)

        self.assert_within_budget(m, COMMAND_STALL_BUDGET)

    async def test_collectinfo_on_node(self):
        with patch.object(util, "shell_command", on_node_shell_command), patch.object(
            common, "collect_sys_info", on_node_collect_sys_info
        ):
            m = await self.measure_command(
                "collectinfo, on a node",
                f"collectinfo --output-prefix {COLLECTINFO_PREFIX}",
                on_node=True,
            )

        self.assert_within_budget(m, COMMAND_STALL_BUDGET)
