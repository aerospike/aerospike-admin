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

ASINFO = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "asinfo", "asinfo.py"
)

FAKE_ASADM = """#!/bin/sh
printf '%s' "$FAKE_ASADM_STDERR" >&2
printf '%s\\n' "$FAKE_ASADM_STDOUT"
"""

NO_USER_WARNING = "WARNING: --password: ignored because no user is set"


@unittest.skipIf(sys.platform == "win32", "needs a POSIX shell")
class AsinfoStderrTest(unittest.TestCase):
    """asinfo runs asadm and treats its stderr as failure, except the no-user warning."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

        path = os.path.join(self.tmpdir.name, "asadm")
        with open(path, "w") as f:
            f.write(FAKE_ASADM)
        os.chmod(path, 0o755)

    def run_asinfo(self, stderr):
        env = dict(
            os.environ,
            PATH=self.tmpdir.name + os.pathsep + os.environ.get("PATH", ""),
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


if __name__ == "__main__":
    unittest.main()
