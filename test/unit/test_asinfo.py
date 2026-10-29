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
import subprocess
import sys
import tempfile
import unittest

from lib.secret_agent.testing import FakeSecretAgent
from test.unit.secret_agent import pki
from test.unit.utils.test_conf import KEYFILE_PASSWORD_HELP, SECRET_AGENT_HELP

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
ASINFO = os.path.join(ROOT, "asinfo", "asinfo.py")

FAKE_ASADM = """#!/bin/sh
printf '%s' "$FAKE_ASADM_STDERR" >&2
printf '%s\\n' "$FAKE_ASADM_STDOUT"
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
    """asinfo runs asadm and treats its stderr as failure, except the no-user warning."""

    def setUp(self):
        self.bindir = install_asadm(self, FAKE_ASADM)

    def run_asinfo(self, stderr):
        env = dict(
            os.environ,
            PATH=self.bindir + os.pathsep + os.environ.get("PATH", ""),
            FAKE_ASADM_STDOUT="build-output",
            FAKE_ASADM_STDERR=stderr,
        )
        return subprocess.run(
            [sys.executable, ASINFO, "-P", "env:ASINFO_TEST_PW", "-v", "build"],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )

    def test_no_user_warning_is_passed_through(self):
        for warning in (
            NO_USER_WARNING,
            "WARNING: password in config file: ignored because no user is set",
        ):
            with self.subTest(warning=warning):
                cp = self.run_asinfo(warning + "\n")

                self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
                self.assertEqual(cp.stdout, "build-output\n")
                self.assertEqual(cp.stderr, warning + "\n")

    def test_other_stderr_still_fails(self):
        for stderr in (
            "ERROR: Not able to connect any cluster with [('127.0.0.1', 1, None)].\n",
            "WARNING: Config file read error : /x.conf No such file\n",
        ):
            with self.subTest(stderr=stderr):
                cp = self.run_asinfo(stderr)

                self.assertEqual(cp.returncode, 1)
                self.assertIn(stderr.strip(), cp.stdout)
                self.assertEqual(cp.stderr, "")

    def test_error_with_no_user_warning_fails(self):
        error = "ERROR: Not able to connect any cluster with [('127.0.0.1', 1, None)]."
        cp = self.run_asinfo(NO_USER_WARNING + "\n" + error + "\n")

        self.assertEqual(cp.returncode, 1)
        self.assertIn(error, cp.stdout)
        self.assertNotIn(NO_USER_WARNING, cp.stdout)
        self.assertEqual(cp.stderr, NO_USER_WARNING + "\n")


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
        self.assertEqual(cp.stderr, NO_USER_WARNING + "\n")
        self.assertIn("Not able to connect any cluster", cp.stdout)
        self.assertNotIn("ignored because no user is set", cp.stdout)


@unittest.skipIf(sys.platform == "win32", "needs a POSIX shell")
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

    def test_legacy_cafile_warns_without_failing(self):
        cp = self.run_asinfo("--sa-cafile", "/ca.pem")

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertEqual(cp.stderr, LEGACY_CAFILE_WARNING)
        self.assertIn("--sa-ca-file /ca.pem", cp.stdout)
        self.assertNotIn("--sa-cafile", cp.stdout)

    def test_ca_file_beats_legacy_cafile(self):
        cp = self.run_asinfo("--sa-cafile", "/old.pem", "--sa-ca-file", "/new.pem")

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("--sa-ca-file /new.pem", cp.stdout)
        self.assertNotIn("/old.pem", cp.stdout)

    def test_ca_file_beats_legacy_cafile_given_first(self):
        cp = self.run_asinfo("--sa-ca-file", "/new.pem", "--sa-cafile", "/old.pem")

        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn("--sa-ca-file /new.pem", cp.stdout)
        self.assertNotIn("/old.pem", cp.stdout)
        self.assertEqual(cp.stderr, LEGACY_CAFILE_WARNING)


@unittest.skipIf(sys.platform == "win32", "needs a POSIX shell")
class AsinfoRealAsadmSecretTest(unittest.TestCase):
    """asadm, run by asinfo, fetches a secrets: password before it connects."""

    def setUp(self):
        encoded = base64.b64encode(SECRET.encode()).decode()
        self.agent = FakeSecretAgent({"aql": {"pw": encoded}}).start()
        self.addCleanup(self.agent.stop)

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
        self.assertIn("Not able to connect any cluster", cp.stdout)
        self.assertNotIn(SECRET, cp.stdout + cp.stderr)

    def test_agent_error_stops_before_connecting(self):
        cp = self.run_asinfo("secrets:aql:missing")

        self.assertEqual(cp.returncode, 1, cp.stdout + cp.stderr)
        self.assertIn("agent error", cp.stdout + cp.stderr)
        self.assertIn(self.agent.address, cp.stdout + cp.stderr)
        self.assertNotIn("Not able to connect any cluster", cp.stdout)


@unittest.skipIf(sys.platform == "win32", "needs a POSIX shell")
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

    def run_asinfo(self, config):
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
            + ["-U", "admin", "-P", "secrets:aql:pw"]
            + ["--sa-address", self.agent.address, "-v", "build"],
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

    def test_unknown_key_with_ca_file(self):
        cp = self.run_asinfo('[secret-agent]\nsa-ca-file = "{ca}"\nsa-time-out = 500\n')
        self.assert_stopped_before_any_request(cp)
        self.assertIn("sa-time-out", cp.stdout + cp.stderr)

    def test_wrong_type_names_key_and_section(self):
        cp = self.run_asinfo(
            '[secret-agent]\nsa-ca-file = "{ca}"\nsa-timeout = 1000.0\n'
        )
        self.assert_stopped_before_any_request(cp)
        self.assertIn(
            "invalid value 1000.0 for sa-timeout in the [secret-agent] config section,"
            " expected an integer from 1 to 2147483647",
            cp.stdout + cp.stderr,
        )


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


if __name__ == "__main__":
    unittest.main()
