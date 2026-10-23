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

import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
ASINFO = os.path.join(ROOT, "asinfo", "asinfo.py")

FAKE_ASADM = """#!/bin/sh
printf '%s' "$FAKE_ASADM_STDERR" >&2
printf '%s\\n' "$FAKE_ASADM_STDOUT"
"""

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


if __name__ == "__main__":
    unittest.main()
