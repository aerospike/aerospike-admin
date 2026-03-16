# Copyright 2025 Aerospike, Inc.
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

from test.e2e import util as test_util, lib


class TestTLS(unittest.TestCase):
    """
    End-to-end tests for asadm TLS functionality exercising the ssl_context.py
    code paths against a real TLS-enabled Aerospike Enterprise cluster.
    """

    @classmethod
    def setUpClass(cls):
        lib.start(
            num_nodes=1,
            docker_tag="latest",
            template_file="aerospike_tls.conf",
        )
        cls.host = f"{lib.SERVER_IP}:{lib.TLS_PORT}"
        cls.certs = lib.absolute_path("certs")
        cls.ca = os.path.join(cls.certs, "ca.pem")

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def _run(self, extra_args: str) -> test_util.CompletedProcess:
        base = (
            f"-h {self.host} --tls-enable --tls-name localhost "
            f"--tls-cafile {self.ca}"
        )
        return test_util.run_asadm(
            f"{base} {extra_args} -Uadmin -Padmin -e 'info network'",
            strip_header=False,
        )

    # ── Happy-path tests ─────────────────────────────────────────────────

    def test_basic_tls_connection(self):
        """_create_ssl_context, _parse_protocols, _verify_cb, _match_tlsname"""
        cp = self._run("")
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_mutual_tls(self):
        """certfile + keyfile loading path"""
        cp = self._run(
            f"--tls-certfile {self.certs}/client.pem "
            f"--tls-keyfile {self.certs}/client.key"
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_encrypted_keyfile_password(self):
        """_read_keyfile_password, load_pem_private_key with password"""
        cp = self._run(
            f"--tls-certfile {self.certs}/client.pem "
            f"--tls-keyfile {self.certs}/client_enc.key "
            f"--tls-keyfile-password testpass"
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_encrypted_keyfile_password_from_env(self):
        """_read_keyfile_password env: prefix"""
        os.environ["TLS_KEY_PASS"] = "testpass"
        try:
            cp = self._run(
                f"--tls-certfile {self.certs}/client.pem "
                f"--tls-keyfile {self.certs}/client_enc.key "
                f'--tls-keyfile-password "env:TLS_KEY_PASS"'
            )
            self.assertEqual(cp.returncode, 0, cp.stderr)
            self.assertIn("Network Information", cp.stdout)
        finally:
            del os.environ["TLS_KEY_PASS"]

    def test_encrypted_keyfile_password_from_file(self):
        """_read_keyfile_password file: prefix"""
        keypass_file = os.path.join(self.certs, "keypass.txt")
        cp = self._run(
            f"--tls-certfile {self.certs}/client.pem "
            f"--tls-keyfile {self.certs}/client_enc.key "
            f"--tls-keyfile-password file:{keypass_file}"
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_tls_protocol_tlsv12(self):
        """_parse_protocols with explicit TLSv1.2"""
        cp = self._run('--tls-protocols "TLSv1.2"')
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_tls_cipher_suite(self):
        """ctx.set_cipher_list with a valid cipher"""
        cp = self._run('--tls-cipher-suite "AES256-SHA256"')
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    # ── Negative tests ───────────────────────────────────────────────────

    def test_sslv2_rejected(self):
        """_parse_protocols rejects SSLv2 (RFC 6176)"""
        cp = self._run('--tls-protocols "SSLv2"')
        connected = "Network Information" in cp.stdout
        self.assertFalse(connected, "Should have failed – SSLv2 is not supported")

    def test_wrong_keyfile_password(self):
        """load_pem_private_key rejects wrong password for encrypted key"""
        cp = self._run(
            f"--tls-certfile {self.certs}/client.pem "
            f"--tls-keyfile {self.certs}/client_enc.key "
            f"--tls-keyfile-password wrongpass"
        )
        connected = "Network Information" in cp.stdout
        self.assertFalse(connected, "Should have failed with wrong keyfile password")

    def test_tls_name_mismatch(self):
        """_match_tlsname should reject when tls-name doesn't match cert"""
        cp = test_util.run_asadm(
            f"-h {self.host} --tls-enable --tls-name wrong_name "
            f"--tls-cafile {self.ca} -Uadmin -Padmin -e 'info'",
            strip_header=False,
        )
        connected = "Network Information" in cp.stdout
        self.assertFalse(connected, "Should have failed due to TLS name mismatch")

    def test_wrong_ca(self):
        """Handshake fails when CA didn't sign the server cert"""
        wrong_ca = os.path.join(self.certs, "wrong_ca.pem")
        cp = test_util.run_asadm(
            f"-h {self.host} --tls-enable --tls-name localhost "
            f"--tls-cafile {wrong_ca} -Uadmin -Padmin -e 'info'",
            strip_header=False,
        )
        connected = "Network Information" in cp.stdout
        self.assertFalse(connected, "Should have failed due to wrong CA")

    def test_crl_revoked_cert(self):
        """_parse_crl_cert, _cert_crl_check – server cert is in CRL"""
        crl_dir = os.path.join(self.certs, "crl_dir")
        cp = test_util.run_asadm(
            f"-h {self.host} --tls-enable --tls-name localhost "
            f"--tls-cafile {self.ca} --tls-capath {crl_dir} "
            f"--tls-crl-check -Uadmin -Padmin -e 'info'",
            strip_header=False,
        )
        connected = "Network Information" in cp.stdout
        self.assertFalse(
            connected, "Should have failed – server cert is revoked in CRL"
        )

    def test_crl_check_all(self):
        """_verify_cb CRL check at all depths via --tls-crl-check-all"""
        crl_dir = os.path.join(self.certs, "crl_dir")
        cp = test_util.run_asadm(
            f"-h {self.host} --tls-enable --tls-name localhost "
            f"--tls-cafile {self.ca} --tls-capath {crl_dir} "
            f"--tls-crl-check-all -Uadmin -Padmin -e 'info'",
            strip_header=False,
        )
        connected = "Network Information" in cp.stdout
        self.assertFalse(
            connected, "Should have failed – server cert is revoked (crl-check-all)"
        )


if __name__ == "__main__":
    unittest.main()
