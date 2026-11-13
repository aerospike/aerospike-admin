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
import os
import shutil
import threading
import time
import unittest
from unittest.mock import patch

from lib.live_cluster.client import info, node
from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node
from test.e2e import lib, util

NODE_COUNT = 2
RECOVERY_SECONDS = 20
SSH_PASSWORD = "E2E-ssh-Pw0rd-marker"
NON_ASCII_USER = "e2e-non-ascii"
NON_ASCII_PASSWORD = "pässwörd-ü-密码"


class ThreadRecorder:
    """Calls through to `func`, recording the thread of every call."""

    def __init__(self, func):
        self.func = func
        self.threads = []

    def __call__(self, *args, **kwargs):
        self.threads.append(threading.get_ident())
        return self.func(*args, **kwargs)


class AsyncCallRecorder:
    """Awaits `func`, recording the arguments of every call."""

    def __init__(self, func):
        self.func = func
        self.calls = []

    async def __call__(self, *args, **kwargs):
        self.calls.append(args)
        return await self.func(*args, **kwargs)


async def connect(user="admin", password="admin"):
    return await Cluster(
        [(lib.SERVER_IP, lib.PORT, None)], user=user, password=password
    )


async def wait_for_every_node_to_answer(cl: Cluster):
    deadline = time.monotonic() + RECOVERY_SECONDS
    answers = None

    while time.monotonic() < deadline:
        try:
            answers = await cl.info("node")
        except Exception as e:
            answers = e
        else:
            if len(answers) == NODE_COUNT and all(
                isinstance(answer, str) for answer in answers.values()
            ):
                return answers

        await asyncio.sleep(1)

    raise AssertionError(
        "nodes did not answer within %ds: %r" % (RECOVERY_SECONDS, answers)
    )


class SecuredClusterTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=NODE_COUNT, mesh_over_bridge=True)
        lib.CLIENT.admin_create_user(
            NON_ASCII_USER, NON_ASCII_PASSWORD, ["sys-admin", "read-write"]
        )
        cls.build = lib.server_build()

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def test_asinfo_mode_logs_in_with_user(self):
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin --asinfo-mode -e build",
            strip_header=False,
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn(self.build, cp.stdout)

    def test_asinfo_mode_logs_in_with_password_from_stdin(self):
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -P --asinfo-mode -e build",
            strip_header=False,
            stdin_input="admin\n",
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn(self.build, cp.stdout)

    def test_hostname_seed_logs_in(self):
        """localhost resolves to more than one address, and the seed connects
        through whichever answers."""
        cp = util.run_asadm(
            f"-h localhost:{lib.PORT} -Uadmin -Padmin -e 'info network'"
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_non_ascii_password_logs_in(self):
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -U {NON_ASCII_USER} "
            f"-P '{NON_ASCII_PASSWORD}' -e 'info network'"
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_asinfo_wrapper_logs_in_with_user(self):
        cp = util.run_asinfo(
            f"-h {lib.SERVER_IP} -p {lib.PORT} -U admin -P admin -v build"
        )

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn(self.build, cp.stdout)

    def test_collectinfo_does_not_write_passwords(self):
        """Nothing listens on the SSH port, so collectinfo logs the failure and
        carries on."""
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin -e 'collectinfo "
            f"--enable-ssh --ssh-user root --ssh-pwd {SSH_PASSWORD} "
            f"--ssh-port {lib.PORT + 9} --output-prefix asadm_test_ssh_'"
        )
        bundle = util.get_collectinfo_path(cp, "/tmp/asadm_test_ssh_")
        self.addCleanup(shutil.rmtree, bundle[: -len(".tgz")], ignore_errors=True)
        self.addCleanup(os.remove, bundle)

        self.assertNotIn(SSH_PASSWORD, cp.stdout)
        self.assertNotIn(SSH_PASSWORD, cp.stderr)

        for secret in (SSH_PASSWORD.encode(), info._hash_password("admin")):
            self.assertListEqual(util.collectinfo_files_containing(bundle, secret), [])

    async def test_password_is_hashed_once_off_event_loop(self):
        loop_thread = threading.get_ident()
        hashpw = ThreadRecorder(info.bcrypt.hashpw)
        fqdn = ThreadRecorder(node.get_fully_qualified_domain_name)

        with patch.object(info.bcrypt, "hashpw", hashpw), patch.object(
            node, "get_fully_qualified_domain_name", fqdn
        ), patch.dict(Node.dns_cache, clear=True):
            cl = await connect()

            try:
                for _ in range(3):
                    await cl.info_statistics()

                self.assertEqual(len(cl.get_live_nodes()), NODE_COUNT)
            finally:
                await cl.close()

        self.assertEqual(len(hashpw.threads), 1)
        self.assertNotEqual(hashpw.threads[0], loop_thread)
        self.assertTrue(fqdn.threads)
        self.assertNotIn(loop_thread, fqdn.threads)

    async def test_node_restart_recovers(self):
        """The restarted node rejects the old session token, so recovering takes a
        new login."""
        login = AsyncCallRecorder(ASSocket.login)

        with patch.object(ASSocket, "login", lambda sock: login(sock)):
            cl = await connect()

            try:
                await wait_for_every_node_to_answer(cl)
                logins_before_restart = len(login.calls)

                lib.restart_node(2)
                lib.wait_for_cluster(NODE_COUNT)

                await wait_for_every_node_to_answer(cl)
            finally:
                await cl.close()

        self.assertGreater(len(login.calls), logins_before_restart)

    async def test_node_restart_recovers_after_relogin_times_out(self):
        """A restarted node rejects the old session token, and the re-login that
        follows times out once, as on a loaded host."""
        original_login = ASSocket.login
        failures_left = 0

        async def login(sock):
            nonlocal failures_left

            if failures_left:
                failures_left -= 1
                raise asyncio.TimeoutError()

            return await original_login(sock)

        with patch.object(ASSocket, "login", login):
            cl = await connect()

            try:
                await wait_for_every_node_to_answer(cl)

                lib.restart_node(2)
                lib.wait_for_cluster(NODE_COUNT)
                failures_left = 1

                await wait_for_every_node_to_answer(cl)
            finally:
                await cl.close()

        self.assertEqual(failures_left, 0)


class SecurityDisabledTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=NODE_COUNT, mesh_over_bridge=True, enable_security=False)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def test_user_given_runs_commands(self):
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin -e 'info network'"
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    async def test_user_given_hashes_once_and_never_authenticates(self):
        """No session token comes back, so a new socket has nothing to authenticate
        with and must not hash the password again."""
        hashpw = ThreadRecorder(info.bcrypt.hashpw)
        authenticate = AsyncCallRecorder(info._authenticate)

        with patch.object(info.bcrypt, "hashpw", hashpw), patch.object(
            info, "_authenticate", authenticate
        ):
            cl = await connect()

            try:
                for _ in range(3):
                    for n in cl.nodes.values():
                        await n.close()
                        n._initialize_socket_pool()

                    await wait_for_every_node_to_answer(cl)
            finally:
                await cl.close()

        self.assertEqual(len(hashpw.threads), 1)
        self.assertListEqual(authenticate.calls, [])


async def roll_security(cl: Cluster, enable_security):
    """Restarts the nodes one at a time with security switched, checking every node
    still answers after each, while the cluster is mixed and once it is done."""
    for index in range(NODE_COUNT, 0, -1):
        lib.restart_node(index, enable_security=enable_security)
        lib.wait_for_cluster(NODE_COUNT)

        await wait_for_every_node_to_answer(cl)


class SecurityEnabledAfterStartTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=NODE_COUNT, mesh_over_bridge=True, enable_security=False)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    async def test_session_recovers_when_security_is_enabled(self):
        """The session started with a user while security was off."""
        cl = await connect()

        try:
            await wait_for_every_node_to_answer(cl)
            await roll_security(cl, enable_security=True)
        finally:
            await cl.close()


class SecurityDisabledAfterStartTest(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=NODE_COUNT, mesh_over_bridge=True)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    async def test_session_recovers_when_security_is_disabled(self):
        """The session holds a token that the restarted nodes no longer ask for."""
        cl = await connect()

        try:
            await wait_for_every_node_to_answer(cl)
            await roll_security(cl, enable_security=False)
        finally:
            await cl.close()
