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
import unittest

from test.e2e import util

UNSET = "ASADM_E2E_UNSET_PASSWORD_VAR"
BASE = "--no-config-file -h 127.0.0.1:1 -e 'info network'"


class PasswordSourceErrorTests(unittest.TestCase):
    """Bad password sources stop asadm before it connects, so no server is needed."""

    def setUp(self):
        os.environ.pop(UNSET, None)

    def assert_fails_before_connecting(self, cp, message):
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn(message, cp.stderr)
        self.assertNotIn("Not able to connect", cp.stdout + cp.stderr)

    def test_password_env_unset(self):
        cp = util.run_asadm(f"{BASE} -U admin -P env:{UNSET}")
        self.assert_fails_before_connecting(
            cp, f"--password: environment variable {UNSET} is not set or empty"
        )

    def test_password_file_missing(self):
        cp = util.run_asadm(f"{BASE} -U admin --password=file:/nonexistent/asadm-pw")
        self.assert_fails_before_connecting(
            cp,
            "--password: cannot read file /nonexistent/asadm-pw: No such file or directory",
        )

    def test_password_invalid_b64_is_not_echoed(self):
        cp = util.run_asadm(f"{BASE} -U admin -Pb64:hunter2-secret")
        self.assert_fails_before_connecting(
            cp, "--password: invalid base64 in b64: value"
        )
        self.assertNotIn("hunter2-secret", cp.stdout + cp.stderr)

    def test_tls_keyfile_password_env_unset(self):
        cp = util.run_asadm(
            f"{BASE} --tls-enable --tls-keyfile /k.pem "
            f"--tls-keyfile-password env:{UNSET}"
        )
        self.assert_fails_before_connecting(
            cp,
            f"--tls-keyfile-password: environment variable {UNSET} is not set or empty",
        )


if __name__ == "__main__":
    unittest.main()
