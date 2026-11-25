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

import base64
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from lib.secret_agent.testing import FakeSecretAgent
from test.unit.secret_agent import pki
from test.unit.utils.test_conf import KEYFILE_PASSWORD_HELP, SECRET_AGENT_HELP

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
ASINFO = os.path.join(ROOT, "asinfo", "asinfo.py")
ASADM = os.path.join(ROOT, "asadm.py")

FAKE_ASADM = """#!/bin/sh
printf '%s' "$FAKE_ASADM_STDERR" >&2
if [ -n "$FAKE_ASADM_STDOUT" ]; then printf '%s\\n' "$FAKE_ASADM_STDOUT"; fi
exit "${FAKE_ASADM_EXIT:-0}"
"""

SLEEPING_ASADM = """#!/bin/sh
echo $$ > "$FAKE_ASADM_PIDFILE"
exec sleep 30
"""

ECHO_ASADM = """#!/bin/sh
printf '%s\\n' "$*"
"""

LEGACY_CAFILE_WARNING = (
    "WARNING: Argument --sa-cafile is deprecated. Use --sa-ca-file instead.\n"
)
SECRET = "s3cr3t-from-agent"

REAL_ASADM = """#!/bin/sh
exec "$ASADM_PYTHON" "$ASADM_SCRIPT" "$@"
"""

NO_USER_WARNING = "WARNING: --password: ignored because no user is set"
LEGACY_PROVIDER_WARNING = (
    "<frozen importlib._bootstrap>:488: Warning: OpenSSL 3's legacy provider failed"
    " to load. Legacy algorithms will not be available. If you need those"
    " algorithms, check your OpenSSL configuration."
)
READ_WARNING = (
    "WARNING: Config file read error : /etc/aerospike/astools.conf Permission denied"
)
REFUSED_CONNECT_ERROR = (
    r"ERROR: Not able to connect any cluster with \('127\.0\.0\.1', 1, None\):"
    r" \[Errno \d+\] Connect call failed \('127\.0\.0\.1', 1\)\n\Z"
)


def install_asadm(test, script):
    tmpdir = tempfile.TemporaryDirectory()
    test.addCleanup(tmpdir.cleanup)

    path = os.path.join(tmpdir.name, "asadm")
    with open(path, "w") as f:
        f.write(script)
    os.chmod(path, 0o755)

    return tmpdir.name


@unittest.skipIf(sys.platform == "win32", "needs a POSIX shell")
class AsinfoStderrTest(unittest.TestCase):
    """asinfo runs asadm and treats its stderr as failure, except the no-user and
    config file read warnings."""

    def setUp(self):
        self.bindir = install_asadm(self, FAKE_ASADM)

    def run_asinfo(self, stderr, stdout="build-output", exit_code=0):
        env = dict(
            os.environ,
            PATH=self.bindir + os.pathsep + os.environ.get("PATH", ""),
            FAKE_ASADM_STDOUT=stdout,
            FAKE_ASADM_STDERR=stderr,
            FAKE_ASADM_EXIT=str(exit_code),
        )
        return subprocess.run(
            [sys.executable, ASINFO, "-P", "env:ASINFO_TEST_PW", "-v", "build"],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_warning_is_passed_through(self):
        for warning in (
            NO_USER_WARNING,
            "WARNING: password in config file: ignored because no user is set",
            READ_WARNING,
            "WARNING: Config file read error : /x.conf No such file",
            LEGACY_PROVIDER_WARNING,
        ):
            with self.subTest(warning=warning):
                cp = self.run_asinfo(warning + "\n")

                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout, "build-output\n")
                self.assertEqual(cp.stderr, warning + "\n")

    def test_security_not_enabled_warning_is_passed_through(self):
        """asadm's normal mode only warns when credentials meet a server without
        security, and asinfo follows it."""
        warning = "WARNING: Login failed : Security not enabled.\n"

        cp = self.run_asinfo(warning)

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, "build-output\n")
        self.assertEqual(cp.stderr, warning)

    def test_other_stderr_still_fails(self):
        for stderr in (
            "ERROR: Not able to connect any cluster with [('127.0.0.1', 1, None)].\n",
            "WARNING: Cannot create history directory /h: Permission denied\n",
        ):
            with self.subTest(stderr=stderr):
                cp = self.run_asinfo(stderr)

                self.assertEqual(cp.returncode, 1)
                self.assertEqual(cp.stdout, "build-output\n")
                self.assertEqual(cp.stderr, stderr)

    def test_reply_mentioning_error_succeeds(self):
        reply = "ns=test:set=app_error:objects=0:tombstones=0"

        cp = self.run_asinfo("", stdout=reply)

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, reply + "\n")
        self.assertEqual(cp.stderr, "")

    def test_reply_mentioning_a_connect_failure_succeeds(self):
        for reply in (
            "ns=test:set=Could not connect to node:objects=100:tombstones=0",
            "ns=test:set=Not able to connect any cluster:objects=100:tombstones=0",
        ):
            with self.subTest(reply=reply):
                cp = self.run_asinfo("", stdout=reply)

                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout, reply + "\n")
                self.assertEqual(cp.stderr, "")

    def test_error_reply_fails(self):
        for reply in (
            "ERROR:4:unrecognized command",
            "error::bad-namespace",
            "Error: Invalid command 'bogus'",
            "8.2.0.0\nERROR:4:unrecognized command",
        ):
            with self.subTest(reply=reply):
                cp = self.run_asinfo("", stdout=reply)

                self.assertEqual(cp.returncode, 1)
                self.assertEqual(cp.stdout, reply + "\n")

    def test_failed_asadm_without_output_fails(self):
        cp = self.run_asinfo("", stdout="", exit_code=3)

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(cp.stderr, "ERROR: asadm exited with code 3\n")

    def test_failed_asadm_with_only_output_fails(self):
        cp = self.run_asinfo("", exit_code=3)

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "build-output\n")
        self.assertEqual(cp.stderr, "ERROR: asadm exited with code 3\n")

    def test_error_with_a_warning_fails(self):
        for warning, error in (
            (
                NO_USER_WARNING,
                "ERROR: Not able to connect any cluster with [('127.0.0.1', 1, None)].",
            ),
            (
                READ_WARNING,
                "ERROR: --password: cannot fetch secrets:aql:pw:"
                " /etc/aerospike/astools.conf could not be loaded (see above); fix or"
                " remove it to fetch secrets",
            ),
        ):
            with self.subTest(warning=warning):
                cp = self.run_asinfo(warning + "\n" + error + "\n")

                self.assertEqual(cp.returncode, 1)
                self.assertEqual(cp.stdout, "build-output\n")
                self.assertEqual(cp.stderr, warning + "\n" + error + "\n")


@unittest.skipIf(sys.platform == "win32", "needs a POSIX shell")
class AsinfoRealAsadmTest(unittest.TestCase):
    """The warning filter matches what asadm.py itself logs."""

    def test_no_user_warning_from_asadm_is_passed_through(self):
        bindir = install_asadm(self, REAL_ASADM)
        env = dict(
            os.environ,
            PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
            ASADM_PYTHON=sys.executable,
            ASADM_SCRIPT=os.path.join(ROOT, "asadm.py"),
        )
        env.pop("ASINFO_TEST_UNSET", None)

        cp = subprocess.run(
            [sys.executable, ASINFO, "--no-config-file", "-h", "127.0.0.1", "-p", "1"]
            + ["-P", "env:ASINFO_TEST_UNSET", "-v", "build"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, "")
        self.assertRegex(
            cp.stderr, r"\A" + re.escape(NO_USER_WARNING + "\n") + REFUSED_CONNECT_ERROR
        )

    def test_read_warning_from_asadm_is_passed_through(self):
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        directory = os.path.join(tmpdir.name, "conf.d")
        os.mkdir(directory)
        link = os.path.join(directory, "agent.conf")
        os.symlink(os.path.join(tmpdir.name, "gone.conf"), link)
        path = os.path.join(tmpdir.name, "astools.conf")

        with open(path, "w") as f:
            f.write('[include]\ndirectory = "{}"\n'.format(directory))

        bindir = install_asadm(self, REAL_ASADM)
        env = dict(
            os.environ,
            PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
            ASADM_PYTHON=sys.executable,
            ASADM_SCRIPT=os.path.join(ROOT, "asadm.py"),
        )

        cp = subprocess.run(
            [sys.executable, ASINFO, "--only-config-file", path, "-h", "127.0.0.1"]
            + ["-p", "1", "-v", "build"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

        warning = (
            "WARNING: Config file read error : {} No such file or directory".format(
                link
            )
        )
        self.assertEqual(cp.stdout, "")
        self.assertRegex(
            cp.stderr, r"\A" + re.escape(warning + "\n") + REFUSED_CONNECT_ERROR
        )


class AsinfoSecretAgentOptionsTest(unittest.TestCase):
    """asinfo hands the Secret Agent options and secrets: values to asadm as given."""

    def run_asinfo(self, *argv):
        bindir = install_asadm(self, ECHO_ASADM)
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ.get("PATH", ""))

        return subprocess.run(
            [sys.executable, ASINFO, *argv, "-v", "build"],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_agent_options_and_secret_are_forwarded(self):
        cp = self.run_asinfo(
            "-U",
            "admin",
            "-P",
            "secrets:aql:pw",
            "--sa-address",
            "agent:4000",
            "--sa-port",
            "4001",
            "--sa-timeout",
            "500",
            "--sa-ca-file",
            "/ca.pem",
        )

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stderr, "")

        for forwarded in (
            "--password secrets:aql:pw",
            "--sa-address agent:4000",
            "--sa-port 4001",
            "--sa-timeout 500",
            "--sa-ca-file /ca.pem",
        ):
            self.assertIn(forwarded, cp.stdout)

    def test_usage_hides_c_cafile_spelling(self):
        cp = self.run_asinfo("--bogus")

        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("--sa-ca-file", cp.stderr)
        self.assertNotIn("--sa-cafile", cp.stderr)

    def test_legacy_cafile_warns_without_failing(self):
        cp = self.run_asinfo("--sa-cafile", "/ca.pem")

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stderr, LEGACY_CAFILE_WARNING)
        self.assertIn("--sa-ca-file /ca.pem", cp.stdout)
        self.assertNotIn("--sa-cafile", cp.stdout)

    def test_ca_file_beats_legacy_cafile_in_either_order(self):
        for argv in (
            ("--sa-cafile", "/old.pem", "--sa-ca-file", "/new.pem"),
            ("--sa-ca-file", "/new.pem", "--sa-cafile", "/old.pem"),
        ):
            with self.subTest(argv=argv):
                cp = self.run_asinfo(*argv)

                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertIn("--sa-ca-file /new.pem", cp.stdout)
                self.assertNotIn("/old.pem", cp.stdout)
                self.assertEqual(cp.stderr, LEGACY_CAFILE_WARNING)


class AsinfoRealAsadmSecretTest(unittest.TestCase):
    """asadm, run by asinfo, fetches a secrets: password before it connects."""

    def setUp(self):
        encoded = base64.b64encode(SECRET.encode()).decode()
        self.agent = FakeSecretAgent({"aql": {"pw": encoded}}).start()
        self.addCleanup(self.agent.stop)
        self.requests = []
        lookup = self.agent.lookup

        def record(request):
            self.requests.append(request)
            return lookup(request)

        self.agent.lookup = record

    def run_asinfo(self, password):
        bindir = install_asadm(self, REAL_ASADM)
        env = dict(
            os.environ,
            PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
            ASADM_PYTHON=sys.executable,
            ASADM_SCRIPT=os.path.join(ROOT, "asadm.py"),
        )

        return subprocess.run(
            [sys.executable, ASINFO, "--no-config-file", "-h", "127.0.0.1", "-p", "1"]
            + ["-U", "admin", "-P", password, "--sa-address", self.agent.address]
            + ["-v", "build"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def test_fetched_password_reaches_the_cluster_connect(self):
        cp = self.run_asinfo("secrets:aql:pw")

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertEqual(self.requests, [{"SecretKey": "pw", "Resource": "aql"}])
        self.assertIn("Not able to connect any cluster", cp.stderr)
        self.assertNotIn(SECRET, cp.stdout + cp.stderr)

    def test_agent_error_stops_before_connecting(self):
        cp = self.run_asinfo("secrets:aql:missing")

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertIn("agent error", cp.stdout + cp.stderr)
        self.assertIn(self.agent.address, cp.stdout + cp.stderr)
        self.assertNotIn("Not able to connect any cluster", cp.stdout + cp.stderr)


class AsinfoBadSecretAgentSectionTest(unittest.TestCase):
    """A [secret-agent] section asadm cannot use stops asinfo before any agent
    is asked for a secret or the cluster is contacted."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

        encoded = base64.b64encode(SECRET.encode()).decode()
        self.agent = FakeSecretAgent({"aql": {"pw": encoded}}).start()
        self.addCleanup(self.agent.stop)
        self.requests = []
        lookup = self.agent.lookup

        def record(request):
            self.requests.append(request)
            return lookup(request)

        self.agent.lookup = record

        self.cluster_connections = []
        self.cluster = FakeSecretAgent(
            handler=lambda sock: self.cluster_connections.append(sock.getpeername())
        ).start()
        self.addCleanup(self.cluster.stop)

        directory = os.path.join(self.tmpdir.name, "ca")
        os.mkdir(directory)
        self.ca_file = pki.generate(directory).ca_file

    def run_asinfo(self, config, *argv, password="secrets:aql:pw"):
        path = os.path.join(self.tmpdir.name, "astools.conf")

        with open(path, "w") as f:
            f.write(config.format(ca=self.ca_file))

        bindir = install_asadm(self, REAL_ASADM)
        env = dict(
            os.environ,
            HOME=self.tmpdir.name,
            PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
            ASADM_PYTHON=sys.executable,
            ASADM_SCRIPT=os.path.join(ROOT, "asadm.py"),
        )

        return subprocess.run(
            [sys.executable, ASINFO, "--only-config-file", path]
            + ["-h", self.cluster.host, "-p", str(self.cluster.port)]
            + ["-U", "admin", "-P", password]
            + ["--sa-address", self.agent.address, *argv, "-v", "build"],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def assert_stopped_before_any_request(self, cp):
        output = cp.stdout + cp.stderr
        self.assertNotEqual(cp.returncode, 0, output)
        self.assertEqual(self.requests, [], output)
        self.assertEqual(self.cluster_connections, [], output)
        self.assertNotIn(SECRET, output)

    def test_bad_command_line_value_without_secrets(self):
        cp = self.run_asinfo("", "--sa-port", "0", password="admin")
        self.assert_stopped_before_any_request(cp)
        self.assertIn(
            '--sa-port: invalid value "0", expected an integer from 1 to 65535',
            cp.stdout + cp.stderr,
        )

    def test_unknown_key_with_ca_file(self):
        cp = self.run_asinfo('[secret-agent]\nsa-ca-file = "{ca}"\nsa-time-out = 500\n')
        self.assert_stopped_before_any_request(cp)
        self.assertIn("sa-time-out", cp.stdout + cp.stderr)


class AsinfoHelpTest(unittest.TestCase):
    """asinfo -E shows asadm's key file password and Secret Agent text, and
    asinfo/asinfo.txt holds the whole output."""

    @classmethod
    def setUpClass(cls):
        cls.help = subprocess.run(
            [sys.executable, ASINFO, "-E"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout

    def test_help_keyfile_password_block(self):
        self.assertIn(KEYFILE_PASSWORD_HELP, self.help)

    def test_help_secret_agent_block(self):
        self.assertIn(SECRET_AGENT_HELP, self.help)

    def test_asinfo_txt_holds_the_help(self):
        with open(os.path.join(ROOT, "asinfo", "asinfo.txt")) as f:
            self.assertIn(self.help, f.read())

    def test_help_timeout_block(self):
        self.assertIn(
            " --timeout=value      Set timeout value in seconds.\n"
            "                      Default: 5 seconds\n",
            self.help,
        )
        self.assertNotIn("TLS connection does not support timeout", self.help)

    def test_help_host_names_the_ipv6_forms(self):
        self.assertIn(
            "                      server. Default: localhost:3000\n"
            '                      An IPv6 address goes in brackets: "[<ipv6>]",\n'
            '                      "[<ipv6>]:<port>" or "[<ipv6>]:<tlsname>:<port>".\n'
            "                      Examples:\n",
            self.help,
        )


class AsinfoModeSilentNodeTest(unittest.TestCase):
    """A node that takes the connection and never answers, like a paused server."""

    def setUp(self):
        release = threading.Event()
        self.node = FakeSecretAgent(handler=lambda sock: release.wait(60)).start()
        self.addCleanup(self.node.stop)
        self.addCleanup(release.set)

        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.env = dict(os.environ, HOME=home.name)
        self.seed = "('127.0.0.1', {}, None)".format(self.node.port)

    def run_timed(self, argv):
        start = time.monotonic()
        cp = subprocess.run(
            argv, capture_output=True, text=True, env=self.env, timeout=60
        )
        return cp, time.monotonic() - start

    def run_asadm(self, *argv):
        return self.run_timed(
            [sys.executable, ASADM, "--asinfo-mode", "--no-config-file"]
            + ["-h", self.node.address, *argv, "-e", "build"]
        )

    def test_timeout_bounds_the_wait(self):
        cp, elapsed = self.run_asadm("--timeout", "0.5")

        self.assertLess(elapsed, 4, cp.stderr)

    def test_info_timeout_is_one_error_line(self):
        cp, _ = self.run_asadm("--timeout", "0.5")

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr,
            "ERROR: Not able to get info from {}: info timed out after 0.5s\n".format(
                self.seed
            ),
        )

    def test_login_timeout_is_one_error_line(self):
        cp, _ = self.run_asadm("--timeout", "0.5", "-U", "admin", "-P", "admin")

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr,
            "ERROR: Not able to login and authenticate any cluster with {}:"
            " login timed out after 0.5s\n".format(self.seed),
        )

    def test_asinfo_forwards_the_timeout(self):
        bindir = install_asadm(self, REAL_ASADM)
        self.env.update(
            PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
            ASADM_PYTHON=sys.executable,
            ASADM_SCRIPT=ASADM,
        )

        cp, elapsed = self.run_timed(
            [sys.executable, ASINFO, "--no-config-file", "-h", self.node.host]
            + ["-p", str(self.node.port), "--timeout", "0.5", "-v", "build"]
        )

        self.assertEqual(cp.returncode, 1)
        self.assertLess(elapsed, 4, cp.stderr)
        self.assertIn("info timed out after 0.5s", cp.stderr)


class AsinfoModeClosedConnectionTest(unittest.TestCase):
    """A node that reads the request and closes the connection, like one that
    restarts mid-run."""

    def setUp(self):
        self.node = FakeSecretAgent(handler=lambda sock: sock.recv(65536)).start()
        self.addCleanup(self.node.stop)

        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.env = dict(os.environ, HOME=home.name)
        self.seed = "('127.0.0.1', {}, None)".format(self.node.port)

    def run_asadm(self, *argv):
        return subprocess.run(
            [sys.executable, ASADM, "--asinfo-mode", "--no-config-file"]
            + ["-h", self.node.address, *argv, "-e", "build"],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=60,
        )

    def test_closed_at_info_is_one_error_line(self):
        cp = self.run_asadm()

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr,
            "ERROR: Not able to get info from {}: Error: Connection closed by"
            " server.\n".format(self.seed),
        )

    def test_closed_at_login_is_one_error_line(self):
        cp = self.run_asadm("-U", "admin", "-P", "admin")

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr,
            "ERROR: Not able to login and authenticate any cluster with {}:"
            " Error: Connection closed by server.\n".format(self.seed),
        )


def _close_with_notify(sock):
    sock.recv(65536)
    sock.unwrap()


def _close_without_notify(sock):
    sock.recv(65536)


class AsinfoModeTLSClosedConnectionTest(unittest.TestCase):
    """The same over TLS, where pyOpenSSL raises its own errors instead of
    OSErrors."""

    def setUp(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.env = dict(os.environ, HOME=home.name)

        directory = os.path.join(home.name, "ca")
        os.mkdir(directory)
        self.pki = pki.generate(directory)

    def run_asadm(self, handler, *argv):
        node = FakeSecretAgent(
            handler=handler, ssl_context=self.pki.server_context()
        ).start()
        self.addCleanup(node.stop)
        self.seed = "('127.0.0.1', {}, 'localhost')".format(node.port)

        return subprocess.run(
            [sys.executable, ASADM, "--asinfo-mode", "--no-config-file"]
            + ["-h", "127.0.0.1:localhost:{}".format(node.port), "--tls-enable"]
            + ["--tls-cafile", self.pki.ca_file, "--timeout", "3", *argv]
            + ["-e", "build"],
            capture_output=True,
            text=True,
            env=self.env,
            timeout=60,
        )

    def test_close_notify_at_login_is_one_error_line(self):
        cp = self.run_asadm(_close_with_notify, "-U", "admin", "-P", "admin")

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr,
            "ERROR: Not able to login and authenticate any cluster with {}:"
            " Error: Connection closed by server.\n".format(self.seed),
        )

    def test_close_notify_at_info_is_one_error_line(self):
        cp = self.run_asadm(_close_with_notify)

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr,
            "ERROR: Not able to get info from {}: Error: Connection closed by"
            " server.\n".format(self.seed),
        )

    def test_closed_without_notify_at_login_is_one_error(self):
        """A source run also prints asyncio's "Fatal read error" block here, so
        only the ERROR lines are checked."""
        cp = self.run_asadm(_close_without_notify, "-U", "admin", "-P", "admin")
        errors = [line for line in cp.stderr.splitlines() if line.startswith("ERROR:")]

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(len(errors), 1, cp.stderr)
        self.assertTrue(
            errors[0].startswith(
                "ERROR: Not able to login and authenticate any cluster with {}:"
                " Error: ".format(self.seed)
            ),
            cp.stderr,
        )


class AsinfoWrapperTest(unittest.TestCase):
    def setUp(self):
        self.env = dict(os.environ)

    def install(self, script):
        bindir = install_asadm(self, script)
        self.env["PATH"] = bindir + os.pathsep + os.environ.get("PATH", "")

    def test_timeout_not_above_zero_is_refused(self):
        self.install(ECHO_ASADM)

        for value in ("0", "-1", "nan"):
            with self.subTest(value=value):
                cp = subprocess.run(
                    [sys.executable, ASINFO, "--timeout=" + value, "-v", "build"],
                    capture_output=True,
                    text=True,
                    env=self.env,
                    timeout=30,
                )

                self.assertEqual(cp.returncode, 2)
                self.assertEqual(cp.stdout, "")
                self.assertIn(
                    'argument --timeout: invalid value "{}", expected a number'
                    " greater than 0".format(value),
                    cp.stderr,
                )

    def test_interrupt_exits_130_and_stops_asadm(self):
        self.install(SLEEPING_ASADM)
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        pidfile = os.path.join(tmpdir.name, "asadm.pid")
        self.env["FAKE_ASADM_PIDFILE"] = pidfile

        proc = subprocess.Popen(
            [sys.executable, ASINFO, "-v", "build"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.env,
            preexec_fn=lambda: signal.signal(signal.SIGINT, signal.SIG_DFL),
        )
        self.addCleanup(proc.kill)

        deadline = time.monotonic() + 30
        while not (os.path.exists(pidfile) and os.path.getsize(pidfile)):
            self.assertLess(time.monotonic(), deadline, "asadm never started")
            time.sleep(0.05)

        with open(pidfile) as f:
            asadm_pid = int(f.read())

        self.addCleanup(self.kill_quietly, asadm_pid)
        proc.send_signal(signal.SIGINT)
        _, stderr = proc.communicate(timeout=30)

        self.assertEqual(proc.returncode, 130, stderr)
        self.assertNotIn("Traceback", stderr)
        with self.assertRaises(ProcessLookupError):
            os.kill(asadm_pid, 0)

    @staticmethod
    def kill_quietly(pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


class AsinfoModeExitCodeTest(unittest.TestCase):
    def test_refused_connect_exits_1(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)

        cp = subprocess.run(
            [sys.executable, ASADM, "--asinfo-mode", "--no-config-file"]
            + ["-h", "127.0.0.1:1", "-e", "build"],
            capture_output=True,
            text=True,
            env=dict(os.environ, HOME=home.name),
            timeout=60,
        )

        self.assertEqual(cp.returncode, 1)
        self.assertRegex(cp.stderr, r"\A" + REFUSED_CONNECT_ERROR)

    def test_bad_host_is_reported_without_a_traceback(self):
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)

        cp = subprocess.run(
            [sys.executable, ASADM, "--asinfo-mode", "--no-config-file"]
            + ["-h", "127.0.0.1:abc", "-e", "build"],
            capture_output=True,
            text=True,
            env=dict(os.environ, HOME=home.name),
            timeout=60,
        )

        self.assertEqual(cp.returncode, 1)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(
            cp.stderr,
            "ERROR: Not able to parse host 127.0.0.1:abc: invalid literal for int()"
            " with base 10: 'abc'\n"
            "ERROR: Not able to connect any cluster with [].\n",
        )


def _recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            return None
        data += chunk

    return data


def _answer_info(received):
    """Replies "<name>\\t8.2.0.0" to each name asked for, and to build when the
    request names none."""

    def handler(sock):
        while True:
            header = _recv_exact(sock, 8)
            if header is None:
                return

            names = _recv_exact(sock, int.from_bytes(header[2:], "big")).split()
            received.append([name.decode() for name in names])
            reply = b"".join(name + b"\t8.2.0.0\n" for name in names or [b"build"])
            header = ((2 << 56) | (1 << 48) | len(reply)).to_bytes(8, "big")
            sock.sendall(header + reply)

    return handler


class AsinfoAnsweringNodeTest(unittest.TestCase):
    """asinfo and the real asadm against a node that answers info requests."""

    def setUp(self):
        self.received = []
        self.node = FakeSecretAgent(handler=_answer_info(self.received)).start()
        self.addCleanup(self.node.stop)

        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        self.home = os.path.join(tmpdir.name, "home")
        self.cwd = os.path.join(tmpdir.name, "cwd")
        os.mkdir(self.home)
        os.mkdir(self.cwd)

        bindir = install_asadm(self, REAL_ASADM)
        self.env = dict(
            os.environ,
            HOME=self.home,
            PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
            ASADM_PYTHON=sys.executable,
            ASADM_SCRIPT=ASADM,
        )

    def run_asinfo(self, *argv):
        return subprocess.run(
            [sys.executable, ASINFO, "--no-config-file", "-h", self.node.host]
            + ["-p", str(self.node.port), *argv],
            capture_output=True,
            text=True,
            env=self.env,
            cwd=self.cwd,
            timeout=60,
        )

    @unittest.skipIf(os.geteuid() == 0, "root ignores file permissions")
    def test_all_values_on_a_read_only_home_succeeds(self):
        """TOOLS-4655: asinfo mode has no history, so it makes no ~/.aerospike."""
        os.chmod(self.home, 0o500)
        self.addCleanup(os.chmod, self.home, 0o700)

        cp = self.run_asinfo()

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, "1 :  build\n     8.2.0.0\n")
        self.assertEqual(cp.stderr, "")

    def test_value_naming_a_file_in_the_cwd_is_sent_as_given(self):
        with open(os.path.join(self.cwd, "build"), "w") as f:
            f.write("statistics\n")

        cp = self.run_asinfo("-v", "build")

        self.assertEqual(self.received, [["build"]])
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, "8.2.0.0\n")
        self.assertEqual(cp.stderr, "")


def _answer_with(reply):
    def handler(sock):
        while True:
            header = _recv_exact(sock, 8)
            if header is None:
                return

            _recv_exact(sock, int.from_bytes(header[2:], "big"))
            header = ((2 << 56) | (1 << 48) | len(reply)).to_bytes(8, "big")
            sock.sendall(header + reply)

    return handler


class AsinfoAllValuesErrorLineTest(unittest.TestCase):
    """An ERROR line in the all-values reply fails the run in asadm itself."""

    ERROR = "ERROR: Server returned an error response for info command : timeout.\n"

    def setUp(self):
        self.node = FakeSecretAgent(
            handler=_answer_with(b"build\t8.2.0.0\nERROR:9:timeout\n")
        ).start()
        self.addCleanup(self.node.stop)

        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)

        bindir = install_asadm(self, REAL_ASADM)
        self.env = dict(
            os.environ,
            HOME=home.name,
            PATH=bindir + os.pathsep + os.environ.get("PATH", ""),
            ASADM_PYTHON=sys.executable,
            ASADM_SCRIPT=ASADM,
        )

    def run_command(self, argv):
        return subprocess.run(
            argv, capture_output=True, text=True, env=self.env, timeout=60
        )

    def test_asinfo_mode_exits_1(self):
        cp = self.run_command(
            [sys.executable, ASADM, "--asinfo-mode", "--no-config-file"]
            + ["-h", self.node.address]
        )

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(cp.stderr, self.ERROR)

    def test_asinfo_exits_1(self):
        cp = self.run_command(
            [sys.executable, ASINFO, "--no-config-file", "-h", self.node.host]
            + ["-p", str(self.node.port)]
        )

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertEqual(cp.stdout, "")
        self.assertEqual(cp.stderr, self.ERROR)


if __name__ == "__main__":
    unittest.main()
