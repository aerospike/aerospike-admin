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
import contextlib
import os
import re
import shutil
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from lib.live_cluster.client import info, node
from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node
from lib.utils import constants
from test.e2e import lib, util

NODE_COUNT = 2
OFFLINE_NODE_ID = "000000000000000"
RECOVERY_SECONDS = 20
SHORTEST_SESSION_TTL = 120
SSH_PASSWORD = "E2E-ssh-Pw0rd-marker"
NON_ASCII_USER = "e2e-non-ascii"
NON_ASCII_PASSWORD = "pässwörd-ü-密码"
ROTATED_USER = "e2e-rotated"


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


@contextlib.contextmanager
def frozen_node(index):
    """Pauses node `index`, which then accepts connections but never answers, and
    yields its address."""
    container = lib.NODES[index - 1]
    conf = lib.NODE_CONFS[index - 1]
    container.pause()

    try:
        yield f"{conf['access_address']}:{conf['port_base']}"
    finally:
        container.reload()

        if container.status == "paused":
            container.unpause()

        lib.wait_for_cluster(NODE_COUNT)


def run_timed(run, args, **kwargs):
    start = time.monotonic()
    cp = run(args, **kwargs)
    return cp, time.monotonic() - start


def seed_text(address):
    host, port = address.rsplit(":", 1)
    return f"('{host}', {port}, None)"


def offline_warnings(stderr, address):
    prefix = f"WARNING: {address} is Offline: "
    return [line for line in stderr.splitlines() if line.startswith(prefix)]


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


def set_session_ttl(ttl):
    replies = lib.CLIENT.info_all("set-config:context=security;session-ttl=%s" % ttl)

    return [reply.strip() for _, reply in replies.values()]


def nodes_showing_build(info_network, build):
    """The nodes whose `info network` row shows the build, so the ones that answered."""
    lines = info_network.splitlines()
    nodes = [f"{lib.SERVER_IP}:{lib.PORT + 1000 * i}" for i in range(NODE_COUNT)]

    return [n for n in nodes if any(n in line and build in line for line in lines)]


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

    def test_unreachable_seed_is_reported_with_why(self):
        """TOOLS-4644"""
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT},127.0.0.1:1 -Uadmin -Padmin"
            " -e 'info network'"
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)
        self.assertRegex(
            cp.stderr,
            r"WARNING: 127\.0\.0\.1:1 is Offline: \[Errno \d+\] Connect call failed"
            r" \('127\.0\.0\.1', 1\)",
        )

    def test_asinfo_mode_says_why_it_cannot_connect(self):
        """TOOLS-4644"""
        cp = util.run_asadm(
            "-h 127.0.0.1:1 -Uadmin -Padmin --asinfo-mode -e build",
            strip_header=False,
        )

        self.assertRegex(
            cp.stderr,
            r"ERROR: Not able to connect any cluster with \('127\.0\.0\.1', 1, None\):"
            r" \[Errno \d+\] Connect call failed \('127\.0\.0\.1', 1\)",
        )

    def test_asinfo_wrapper_says_why_it_cannot_connect(self):
        """TOOLS-4644"""
        cp = util.run_asinfo("-h 127.0.0.1 -p 1 -U admin -P admin -v build")

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertRegex(
            cp.stderr,
            r"\AERROR: Not able to connect any cluster with \('127\.0\.0\.1', 1, None\):"
            r" \[Errno \d+\] Connect call failed \('127\.0\.0\.1', 1\)\Z",
        )

    def test_unresolvable_seed_is_reported_with_why(self):
        """TOOLS-4644"""
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT},nosuchhost.invalid:3000 -Uadmin -Padmin"
            " -e 'info network'"
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertRegex(
            cp.stderr,
            r"WARNING: nosuchhost\.invalid:3000 is Offline: \[Errno -?\d+\] \S",
        )

    def test_frozen_node_at_startup_is_reported_with_why(self):
        """TOOLS-4644: the SUP-172 case. The banner still lists the node Offline."""
        with frozen_node(2) as frozen, tempfile.TemporaryDirectory() as home:
            with patch.dict(os.environ, {"HOME": home}):
                cp = util.run_asadm(
                    f"-h {lib.SERVER_IP}:{lib.PORT},{frozen} -Uadmin -Padmin"
                    " --timeout 1",
                    stdin_input="info network\nexit\n",
                )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(
            offline_warnings(cp.stderr, frozen),
            [f"WARNING: {frozen} is Offline: login timed out after 1s"],
        )
        self.assertIn(f"Offline: {frozen}", cp.stdout)
        self.assertIn("Network Information", cp.stdout)

    def test_frozen_seed_is_reported_with_why(self):
        """TOOLS-4644"""
        with frozen_node(2) as frozen:
            cp = util.run_asadm(
                f"-h {frozen} -Uadmin -Padmin --timeout 1 -e 'info network'"
            )

        self.assertEqual(
            offline_warnings(cp.stderr, frozen),
            [f"WARNING: {frozen} is Offline: login timed out after 1s"],
        )
        self.assertIn("Not able to connect any cluster", cp.stderr)

    def test_node_lost_mid_session_is_reported_with_why(self):
        """TOOLS-4644: reported when it drops, not again on every command. Unbuffered,
        so the first table arrives while asadm is still running."""
        proc = util.AsadmProcess(
            f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin --timeout 1"
            " -e 'watch 4 3 info network'",
            env=dict(os.environ, PYTHONUNBUFFERED="1"),
        )

        try:
            self.assertTrue(proc.wait_for_stdout("Network Information", 30))
            self.assertIsNone(proc.proc.poll(), "asadm finished before the drop")

            with frozen_node(2) as frozen:
                returncode, _ = proc.wait(60)
        finally:
            proc.kill()

        stderr = proc.output.stderr
        warnings = offline_warnings(stderr, frozen)
        self.assertEqual(returncode, 0, stderr)
        self.assertTrue(warnings, stderr)
        self.assertRegex(warnings[0], r"is Offline: \w+ timed out after 1s$")

        for earlier, later in zip(warnings, warnings[1:]):
            self.assertNotEqual(earlier, later)

    def test_node_back_from_offline_is_used_again(self):
        """TOOLS-4644: the next refresh picks it up, with no further warning."""
        with frozen_node(2) as frozen:
            proc = util.AsadmProcess(
                f"-h {lib.SERVER_IP}:{lib.PORT},{frozen} -Uadmin -Padmin --timeout 1"
                " -e 'watch 4 3 info network'",
                env=dict(os.environ, PYTHONUNBUFFERED="1"),
            )

            try:
                self.assertTrue(proc.wait_for_stdout("Network Information", 30))
                self.assertIsNone(
                    proc.proc.poll(), "asadm finished before the node came back"
                )
                lib.NODES[1].unpause()
                returncode, _ = proc.wait(60)
            finally:
                proc.kill()

        output = proc.output
        tables = output.stdout.split("Network Information")[1:]
        self.assertEqual(returncode, 0, output.stderr)
        self.assertIn(OFFLINE_NODE_ID, tables[0])
        self.assertNotIn(OFFLINE_NODE_ID, tables[-1])
        self.assertIn(frozen, tables[-1])
        self.assertEqual(
            offline_warnings(output.stderr, frozen),
            [f"WARNING: {frozen} is Offline: login timed out after 1s"],
        )

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

    def test_asinfo_mode_frozen_node_login_timeout(self):
        """TOOLS-4655: one error line within --timeout, and exit code 1."""
        with frozen_node(2) as frozen:
            cp, elapsed = run_timed(
                util.run_asadm,
                f"-h {frozen} -Uadmin -Padmin --asinfo-mode --timeout 1 -e build",
                strip_header=False,
            )

        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertEqual(
            cp.stderr.splitlines(),
            [
                "ERROR: Not able to login and authenticate any cluster with"
                f" {seed_text(frozen)}: login timed out after 1s"
            ],
        )
        self.assertLess(elapsed, 4.5)

    def test_asinfo_wrapper_frozen_node_honors_timeout(self):
        """TOOLS-4655"""
        with frozen_node(2) as frozen:
            host, port = frozen.rsplit(":", 1)
            cp, elapsed = run_timed(
                util.run_asinfo,
                f"-h {host} -p {port} -U admin -P admin --timeout 1 -v build",
            )

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr.splitlines(),
            [
                "ERROR: Not able to login and authenticate any cluster with"
                f" {seed_text(frozen)}: login timed out after 1s"
            ],
        )
        self.assertLess(elapsed, 4.5)

    def test_asinfo_wrapper_frozen_node_defaults_to_5s(self):
        """TOOLS-4655: asinfo mode keeps its 5 s default and ignores the [asadm]
        timeout."""
        with tempfile.TemporaryDirectory() as tmp:
            conf = os.path.join(tmp, "astools.conf")

            with open(conf, "w") as f:
                f.write("[asadm]\ntimeout = 1\n")

            with frozen_node(2) as frozen:
                host, port = frozen.rsplit(":", 1)
                cp, elapsed = run_timed(
                    util.run_asinfo,
                    f"-h {host} -p {port} -U admin -P admin"
                    f" --only-config-file {conf} -v build",
                )

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr.splitlines(),
            [
                "ERROR: Not able to login and authenticate any cluster with"
                f" {seed_text(frozen)}: login timed out after 5s"
            ],
        )
        self.assertGreaterEqual(elapsed, 4.5)
        self.assertLess(elapsed, 9)

    def test_asinfo_mode_refused_seed_exits_1(self):
        """TOOLS-4655"""
        cp = util.run_asadm(
            "-h 127.0.0.1:1 -Uadmin -Padmin --asinfo-mode -e build",
            strip_header=False,
        )

        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertEqual(cp.stdout, "")
        self.assertRegex(
            cp.stderr,
            r"\AERROR: Not able to connect any cluster with \('127\.0\.0\.1', 1, None\):"
            r" \[Errno \d+\] Connect call failed \('127\.0\.0\.1', 1\)\Z",
        )

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

    async def test_a_command_after_the_session_expires_reaches_every_node(self):
        """Open connections outlive the session, but a new socket authenticates with
        the expired token, so the node has to log in again."""
        original_ttls = {
            re.search(r"session-ttl=(\d+)", response[1]).group(1)
            for response in lib.CLIENT.info_all("get-config:context=security").values()
        }
        self.assertEqual(len(original_ttls), 1, original_ttls)
        original_ttl = original_ttls.pop()

        def restore_session_ttl():
            try:
                replies = set_session_ttl(original_ttl)
            except Exception:
                lib.CLIENT.close()
                lib.connect_client()
                replies = set_session_ttl(original_ttl)

            self.assertEqual(replies, ["ok"] * NODE_COUNT)

        self.addCleanup(restore_session_ttl)
        replies = set_session_ttl(SHORTEST_SESSION_TTL)
        self.assertEqual(replies, ["ok"] * NODE_COUNT)
        cl = await connect()

        try:
            await wait_for_every_node_to_answer(cl)
            await asyncio.sleep(SHORTEST_SESSION_TTL + 5)

            for n in cl.nodes.values():
                await n.close()
                n._initialize_socket_pool()

            with patch.object(Cluster, "need_to_refresh_cluster", return_value=False):
                answers = await cl.info("node")

            alive = [n.alive for n in cl.nodes.values()]
        finally:
            await cl.close()

        self.assertEqual(len(answers), NODE_COUNT)
        self.assertTrue(all(isinstance(a, str) for a in answers.values()), answers)
        self.assertEqual(alive, [True] * NODE_COUNT)

    async def test_node_rejecting_the_login_after_a_restart_goes_offline(self):
        """The password changed mid-session, then node 2, the principal, restarted. It
        rejects the old password while node 1 keeps the session."""
        lib.CLIENT.admin_create_user(
            ROTATED_USER, "old-password", ["sys-admin", "read-write"]
        )
        self.addCleanup(lib.CLIENT.admin_drop_user, ROTATED_USER)
        node_1 = f"{lib.SERVER_IP}:{lib.PORT}"
        cl = await connect(ROTATED_USER, "old-password")

        try:
            await wait_for_every_node_to_answer(cl)
            self.assertEqual(
                list(await cl.info("node", nodes=constants.NodeSelection.PRINCIPAL)),
                [f"{lib.SERVER_IP}:{lib.PORT + 1000}"],
            )

            lib.CLIENT.admin_set_password(ROTATED_USER, "new-password")
            lib.restart_node(2)
            lib.wait_for_cluster(NODE_COUNT)

            every_node = await cl.info("node")
            principal = await cl.info("node", nodes=constants.NodeSelection.PRINCIPAL)

            lib.CLIENT.admin_set_password(ROTATED_USER, "old-password")
            await wait_for_every_node_to_answer(cl)
        finally:
            await cl.close()

        self.assertEqual(list(every_node), [node_1])
        self.assertEqual(list(principal), [node_1])

    def test_session_keeps_answering_when_a_restarted_node_rejects_the_login(self):
        """The same rotation and restart, in an interactive asadm session."""
        lib.CLIENT.admin_create_user(
            ROTATED_USER, "old-password", ["sys-admin", "read-write"]
        )
        self.addCleanup(lib.CLIENT.admin_drop_user, ROTATED_USER)
        node_1 = f"{lib.SERVER_IP}:{lib.PORT}"
        node_2 = f"{lib.SERVER_IP}:{lib.PORT + 1000}"
        session = util.AsadmSession(f"-h {node_1} -U {ROTATED_USER} -P old-password")
        self.addCleanup(session.close)

        before = session.run("info network")
        self.assertCountEqual(nodes_showing_build(before, self.build), [node_1, node_2])

        lib.CLIENT.admin_set_password(ROTATED_USER, "new-password")
        lib.restart_node(2)
        lib.wait_for_cluster(NODE_COUNT)
        after = session.run("info network")

        self.assertEqual(nodes_showing_build(after, self.build), [node_1])
        self.assertIn(
            f"ERROR: {node_2}: Login failed : No credential or bad credential.", after
        )


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

    def test_asinfo_mode_frozen_node_info_timeout(self):
        """TOOLS-4655: without security there is no login, so the first info call
        is the one that waits."""
        with frozen_node(2) as frozen:
            cp, elapsed = run_timed(
                util.run_asadm,
                f"-h {frozen} --asinfo-mode --timeout 1 -e build",
                strip_header=False,
            )

        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertEqual(
            cp.stderr.splitlines(),
            [
                f"ERROR: Not able to get info from {seed_text(frozen)}:"
                " info timed out after 1s"
            ],
        )
        self.assertLess(elapsed, 4.5)

    def test_asinfo_mode_user_given_warns_and_runs(self):
        """TOOLS-4655: as in normal mode."""
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin --asinfo-mode -e build",
            strip_header=False,
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn(lib.server_build(), cp.stdout)
        self.assertEqual(
            cp.stderr.splitlines(), ["WARNING: Login failed : Security not enabled."]
        )

    def test_asinfo_wrapper_user_given_warns_and_runs(self):
        """TOOLS-4655"""
        cp = util.run_asinfo(
            f"-h {lib.SERVER_IP} -p {lib.PORT} -U admin -P admin -v build"
        )

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn(lib.server_build(), cp.stdout)
        self.assertEqual(
            cp.stderr.splitlines(), ["WARNING: Login failed : Security not enabled."]
        )

    def test_asinfo_wrapper_reply_naming_set_app_error_succeeds(self):
        """TOOLS-4655: only a reply line that starts with error: fails."""
        lib.populate_db("app_error")

        cp = util.run_asinfo(f"-h {lib.SERVER_IP} -p {lib.PORT} -v sets")

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("set=app_error:", cp.stdout)
        self.assertEqual(cp.stderr, "")

    def test_asinfo_wrapper_reply_naming_a_connect_failure_succeeds(self):
        """TOOLS-4655: asadm reports a failed connect on stderr, never in the reply."""
        lib.populate_db("Could not connect to node")

        cp = util.run_asinfo(f"-h {lib.SERVER_IP} -p {lib.PORT} -v sets")

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("set=Could not connect to node:", cp.stdout)
        self.assertEqual(cp.stderr, "")

    def test_asinfo_wrapper_error_reply_fails(self):
        """TOOLS-4655"""
        cp = util.run_asinfo(
            f"-h {lib.SERVER_IP} -p {lib.PORT} -v 'get-config:context=nosuchcontext'"
        )

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertTrue(cp.stdout.lower().startswith("error:"), cp.stdout)
        self.assertEqual(cp.stderr, "")

    def test_undecodable_command_file_exits_1(self):
        """TOOLS-4655: asadm has connected by the time it reads the file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "commands.txt")

            with open(path, "wb") as f:
                f.write(b"info network\n\xff\xfe\n")

            cp = util.run_asadm(f"-h {lib.SERVER_IP}:{lib.PORT} -e {path}")

        errors = [line for line in cp.stderr.splitlines() if line.startswith("ERROR:")]
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertNotIn("Network Information", cp.stdout)
        self.assertEqual(len(errors), 1, cp.stderr)
        self.assertTrue(
            errors[0].startswith(f"ERROR: Not able to read the command file {path}: "),
            cp.stderr,
        )

    def test_bad_host_among_good_seeds_runs_and_exits_1(self):
        """TOOLS-4655: the command runs on the good seed, and the bad one fails
        the exit code."""
        cp = util.run_asadm(
            f"-h 127.0.0.1:abc,{lib.SERVER_IP}:{lib.PORT} -e 'info network'"
        )

        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn("Network Information", cp.stdout)
        self.assertIn(
            "ERROR: Not able to parse host 127.0.0.1:abc: invalid literal for int()"
            " with base 10: 'abc'",
            cp.stderr.splitlines(),
        )

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

    def test_unreachable_seed_is_reported_with_why(self):
        """TOOLS-4644: without security there is no login, and the failure comes
        from the first info call."""
        cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT},127.0.0.1:1 -e 'info network'"
        )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertRegex(
            cp.stderr,
            r"WARNING: 127\.0\.0\.1:1 is Offline: \[Errno \d+\] Connect call failed"
            r" \('127\.0\.0\.1', 1\)",
        )

    def test_frozen_node_is_reported_with_why(self):
        """TOOLS-4644"""
        with frozen_node(2) as frozen:
            cp = util.run_asadm(
                f"-h {lib.SERVER_IP}:{lib.PORT},{frozen} --timeout 1 -e 'info network'"
            )

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(
            offline_warnings(cp.stderr, frozen),
            [f"WARNING: {frozen} is Offline: info timed out after 1s"],
        )


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
