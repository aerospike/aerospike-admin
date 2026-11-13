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
import collections
import contextlib
import glob
import json
import os
import shutil
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node
from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController
from lib.utils import constants
from lib.utils import util as asadm_util
from test.e2e import lib, util

NODE_COUNT = 2
PREFIX = "asadm_e2e_requests_"


def remove_bundles():
    for path in glob.glob("/tmp/" + PREFIX + "*"):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.remove(path)


def bundle_file(suffix):
    (archive,) = glob.glob("/tmp/" + PREFIX + "*.tgz")
    extract_dir = tempfile.mkdtemp(prefix=PREFIX + "extract_")

    with tarfile.open(archive) as tar:
        tar.extractall(path=extract_dir)

    (path,) = [
        os.path.join(dirpath, name)
        for dirpath, _, names in os.walk(extract_dir)
        for name in names
        if name.endswith(suffix) and not name.startswith("._")
    ]

    with open(path) as f:
        content = f.read()

    shutil.rmtree(extract_dir, ignore_errors=True)
    return content


async def run_collectinfo(*args, during=contextlib.nullcontext):
    rc = await LiveClusterRootController(
        [(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin", timeout=5
    )

    for node in rc.cluster.nodes.values():
        node.localhost = False

    try:
        with during():
            await asadm_util.capture_stdout(
                rc.execute, ["collectinfo", "--output-prefix", PREFIX, *args]
            )
    finally:
        await rc.close()


class CollectinfoRequestsTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=NODE_COUNT, mesh_over_bridge=True)
        lib.create_sindex("e2e-age", "numeric", "test", "age")

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def setUp(self):
        remove_bundles()
        self.addCleanup(remove_bundles)
        self.addCleanup(os.chdir, os.getcwd())

    async def test_collectinfo_leaves_the_working_directory_alone(self):
        cwd = os.getcwd()

        await run_collectinfo()

        self.assertEqual(os.getcwd(), cwd)

    async def test_no_node_is_asked_the_same_thing_twice(self):
        asked = collections.Counter()
        send = ASSocket.info

        async def recording_send(sock, command):
            if command != "node":
                key = command if isinstance(command, str) else tuple(command)
                asked[(sock.port, key)] += 1

            return await send(sock, command)

        @contextlib.contextmanager
        def recording():
            with patch.object(ASSocket, "info", recording_send), patch.object(
                Cluster, "need_to_refresh_cluster", return_value=False
            ):
                yield

        await run_collectinfo(during=recording)

        self.assertGreater(len(asked), 0)
        self.assertEqual({k: n for k, n in asked.items() if n > 1}, {})

    async def test_a_single_snapshot_does_not_wait(self):
        waits = []
        sleep = asyncio.sleep

        async def recording_sleep(delay, *args, **kwargs):
            waits.append(delay)
            return await sleep(delay, *args, **kwargs)

        with patch(
            "lib.live_cluster.collectinfo_controller.asyncio.sleep", recording_sleep
        ):
            await run_collectinfo()

        self.assertNotIn(5, waits)

    def test_s_sets_the_wait_between_snapshots(self):
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin "
            f"-e 'collectinfo -n 2 -s 1 --output-prefix {PREFIX}'"
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        meta = json.loads(bundle_file(constants.COLLECTINFO_META_FILENAME))
        self.assertEqual(meta["collection"]["flags"]["sleep_between_snapshots_sec"], 1)

    async def test_histograms_are_kept_when_one_node_cannot_list_namespaces(self):
        info = Node.info

        async def failing_info(node, command, *args, **kwargs):
            if command == "namespaces" and node.port != lib.PORT:
                return OSError("e2e: namespaces failed")

            return await info(node, command, *args, **kwargs)

        with patch.object(Node, "info", failing_info):
            await run_collectinfo()

        self.assertIn(
            "histogram:namespace=test;type=ttl", bundle_file("ascollectinfo.log")
        )
