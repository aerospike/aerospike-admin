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

import json
import os
import shutil
import tempfile
import time
import unittest

import docker
from cryptography.hazmat.primitives import serialization

from lib.secret_agent import SecretAgentClient, SecretAgentError, new_ssl_context
from test.e2e import lib, util
from test.unit.secret_agent import pki

AGENT_IMAGE = os.environ.get(
    "ASADM_E2E_SECRET_AGENT_IMAGE", "aerospike/aerospike-secret-agent:1.1.0"
)
AGENT_PLATFORM = "linux/amd64"
AGENT_START_TIMEOUT = 120
WRONG_PW = "not-the-admin-password"
SECRETS = {"password": "admin", "keypass": "testpass", "wrong": WRONG_PW}
AGENT_CONFIG = """service:
  tcp:
    endpoint: 0.0.0.0:3005
{tls}secret-manager:
  file:
    convert-to-base64: true
    resources:
      asadm: "/agent/asadm.json"
log:
  level: debug
"""
AGENT_TLS_CONFIG = """    tls:
      cert-file: "/agent/server.pem"
      key-file: "/agent/server-key.pem"
"""
NO_SERVER = "--no-config-file -h 127.0.0.1:1 -e 'info network'"
DEPRECATED_CAFILE = "Argument --sa-cafile is deprecated. Use --sa-ca-file instead."

AGENTS = {}


def setUpModule():
    try:
        AGENTS["plain"] = SecretAgent()
        AGENTS["plain"].start()
        AGENTS["tls"] = SecretAgent(tls=True)
        AGENTS["tls"].start()
    except BaseException:
        tearDownModule()
        raise


def tearDownModule():
    for agent in AGENTS.values():
        agent.stop()


class SecretAgent:
    """A real Secret Agent container with a file backend. The asadm resource
    holds the cluster's admin password, the e2e TLS key file password and a
    wrong one. A TLS agent's certificate names localhost but not 127.0.0.1."""

    def __init__(self, tls=False):
        self.client = docker.from_env()
        self.directory = os.path.realpath(tempfile.mkdtemp(prefix="asadm-sa-"))
        self.tls = tls
        self.ca_file = None
        self.container = None
        self.port = None
        self.address = None

    def start(self):
        try:
            self.client.images.get(AGENT_IMAGE)
        except docker.errors.ImageNotFound:
            self.client.images.pull(AGENT_IMAGE, platform=AGENT_PLATFORM)

        tls_config = ""

        if self.tls:
            self.ca_file = pki.generate(self.directory, hosts=("localhost",)).ca_file
            tls_config = AGENT_TLS_CONFIG

        self._write("asadm.json", json.dumps(SECRETS))
        self._write("agent.yaml", AGENT_CONFIG.format(tls=tls_config))

        # World-readable, so the agent reads them whatever uid Docker maps it to.
        for name in os.listdir(self.directory):
            os.chmod(os.path.join(self.directory, name), 0o644)

        os.chmod(self.directory, 0o755)

        self.container = self.client.containers.run(
            AGENT_IMAGE,
            command=["--config-file", "/agent/agent.yaml"],
            volumes={self.directory: {"bind": "/agent", "mode": "ro"}},
            ports={"3005/tcp": ("127.0.0.1", None)},
            detach=True,
        )
        self.container.reload()
        self.port = int(
            self.container.attrs["NetworkSettings"]["Ports"]["3005/tcp"][0]["HostPort"]
        )
        self.address = "127.0.0.1:{}".format(self.port)
        self._wait_until_serving()

    def stop(self):
        if self.container is not None:
            self.container.remove(force=True)

        shutil.rmtree(self.directory, ignore_errors=True)

    def _write(self, name, content):
        with open(os.path.join(self.directory, name), "w") as f:
            f.write(content)

    def _wait_until_serving(self):
        # The agent logs that it listens before its file backend has loaded.
        if self.tls:
            client = SecretAgentClient(
                "localhost",
                self.port,
                timeout=5,
                ssl_context=new_ssl_context(self.ca_file),
            )
        else:
            client = SecretAgentClient("127.0.0.1", self.port, timeout=5)

        deadline = time.monotonic() + AGENT_START_TIMEOUT

        while True:
            try:
                if client.resolve("secrets:asadm:password") == "admin":
                    return
            except SecretAgentError as e:
                if time.monotonic() > deadline:
                    raise RuntimeError(
                        "Secret Agent never served secrets: {}\n{}".format(
                            e, self.container.logs().decode(errors="replace")
                        )
                    ) from e

            time.sleep(0.25)


def untrusted_ca_file(test_class):
    directory = tempfile.TemporaryDirectory()
    test_class.addClassCleanup(directory.cleanup)

    return pki.generate(directory.name).ca_file


class AgentTestCase(unittest.TestCase):
    def setUp(self):
        self.agent = AGENTS["plain"]
        self.tls_agent = AGENTS["tls"]
        self.tls_address = "localhost:{}".format(self.tls_agent.port)
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write_file(self, name, content):
        path = os.path.join(self.tmpdir.name, name)

        with open(path, "w") as f:
            f.write(content)

        return path

    def assert_fails_before_connecting(self, cp, message):
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn(message, cp.stderr)
        self.assertNotIn("Not able to connect", cp.stdout + cp.stderr)

    def assert_connected(self, cp):
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)


class SecretAgentErrorTests(AgentTestCase):
    """Secret Agent failures stop asadm before it connects, so no server is
    needed."""

    def run_password(self, password, agent_args):
        return util.run_asadm(f"{NO_SERVER} -U admin -P {password} {agent_args}")

    def test_missing_secret(self):
        cp = self.run_password(
            "secrets:asadm:missing", f"--sa-address {self.agent.address}"
        )
        self.assert_fails_before_connecting(
            cp,
            f"--password: agent error from {self.agent.address} "
            "for secrets:asadm:missing",
        )

    def test_agent_error_names_the_agent(self):
        cp = self.run_password(
            "secrets:asadm:missing", f"--sa-address {self.agent.address}"
        )
        self.assert_fails_before_connecting(cp, self.agent.address)

    def test_unknown_resource(self):
        cp = self.run_password(
            "secrets:nonexistent:password", f"--sa-address {self.agent.address}"
        )
        self.assert_fails_before_connecting(
            cp,
            f"--password: agent error from {self.agent.address} "
            "for secrets:nonexistent:password",
        )

    def test_secret_without_resource(self):
        """Agent 1.1.0 finds no key without a resource, even with one file resource."""
        cp = self.run_password("secrets:password", f"--sa-address {self.agent.address}")
        self.assert_fails_before_connecting(
            cp,
            f"--password: agent error from {self.agent.address} for secrets:password: "
            "password not present in file /agent/asadm.json",
        )

    def test_empty_key(self):
        cp = self.run_password("secrets:asadm:", f"--sa-address {self.agent.address}")
        self.assert_fails_before_connecting(
            cp, "--password: secret reference secrets:asadm: has an empty key"
        )

    def test_agent_unreachable(self):
        cp = self.run_password("secrets:asadm:password", "--sa-address 127.0.0.1:1")
        self.assert_fails_before_connecting(
            cp, "--password: connect to 127.0.0.1:1 for secrets:asadm:password"
        )

    def test_keyfile_password_missing_secret(self):
        cp = util.run_asadm(
            f"{NO_SERVER} --tls-enable --tls-keyfile /k.pem "
            f"--tls-keyfile-password secrets:asadm:missing "
            f"--sa-address {self.agent.address}"
        )
        self.assert_fails_before_connecting(
            cp,
            f"--tls-keyfile-password: agent error from {self.agent.address} "
            "for secrets:asadm:missing",
        )

    def test_invalid_agent_port(self):
        cp = self.run_password("secrets:asadm:password", "--sa-port 0")
        self.assert_fails_before_connecting(cp, "--sa-port: invalid value 0")

    def test_invalid_agent_timeout(self):
        cp = self.run_password("secrets:asadm:password", "--sa-timeout 0")
        self.assert_fails_before_connecting(cp, "--sa-timeout: invalid value 0")

    def test_invalid_agent_port_in_config_file(self):
        path = self.write_file(
            "astools.conf",
            '[cluster]\nhost = "127.0.0.1:1"\nuser = "admin"\n'
            'password = "secrets:asadm:password"\n'
            "[secret-agent]\nsa-port = 0\n",
        )
        cp = util.run_asadm(f"--only-config-file {path} -e 'info network'")
        self.assert_fails_before_connecting(
            cp, "invalid value 0 for sa-port in the [secret-agent] config section"
        )


class SecretAgentTLSErrorTests(AgentTestCase):
    """TLS failures between asadm and the agent stop asadm before it connects,
    so no server is needed."""

    @classmethod
    def setUpClass(cls):
        cls.untrusted_ca = untrusted_ca_file(cls)

    def run_password(self, agent_args):
        return util.run_asadm(
            f"{NO_SERVER} -U admin -P secrets:asadm:password "
            f"--sa-timeout 5000 {agent_args}"
        )

    def test_plaintext_to_tls_agent(self):
        cp = self.run_password(f"--sa-address {self.tls_address}")
        self.assert_fails_before_connecting(
            cp,
            f"--password: read response from {self.tls_address} "
            "for secrets:asadm:password: "
            "connection closed by the agent",
        )

    def test_tls_to_plaintext_agent(self):
        cp = self.run_password(
            f"--sa-address {self.agent.address} "
            f"--sa-ca-file {self.tls_agent.ca_file}"
        )
        self.assert_fails_before_connecting(
            cp,
            f"--password: connect to {self.agent.address} for secrets:asadm:password",
        )

    def test_untrusted_ca(self):
        cp = self.run_password(
            f"--sa-address {self.tls_address} --sa-ca-file {self.untrusted_ca}"
        )
        self.assert_fails_before_connecting(
            cp, f"--password: connect to {self.tls_address} for secrets:asadm:password"
        )
        self.assertIn("CERTIFICATE_VERIFY_FAILED", cp.stderr)

    def test_address_not_in_certificate(self):
        cp = self.run_password(
            f"--sa-address {self.tls_agent.address} "
            f"--sa-ca-file {self.tls_agent.ca_file}"
        )
        self.assert_fails_before_connecting(
            cp,
            f"--password: connect to {self.tls_agent.address} for secrets:asadm:password",
        )
        self.assertIn(
            "IP address mismatch, certificate is not valid for '127.0.0.1'", cp.stderr
        )

    def test_missing_ca_file(self):
        cp = self.run_password(
            f"--sa-address {self.tls_address} --sa-ca-file /nonexistent/ca.pem"
        )
        self.assert_fails_before_connecting(
            cp, "--sa-ca-file: cannot load TLS CA file /nonexistent/ca.pem"
        )

    def test_ca_file_is_not_a_certificate(self):
        path = self.write_file("ca.pem", "not a certificate\n")
        cp = self.run_password(f"--sa-address {self.tls_address} --sa-ca-file {path}")
        self.assert_fails_before_connecting(
            cp, f"--sa-ca-file: cannot load TLS CA file {path}"
        )

    def test_missing_legacy_cafile_names_its_spelling(self):
        cp = self.run_password(
            f"--sa-address {self.tls_address} --sa-cafile /nonexistent/ca.pem"
        )
        self.assert_fails_before_connecting(
            cp, "--sa-cafile: cannot load TLS CA file /nonexistent/ca.pem"
        )

    def test_missing_cafile_in_config_file_names_its_key_and_section(self):
        path = self.write_file(
            "astools.conf",
            '[cluster]\nhost = "127.0.0.1:1"\nuser = "admin"\n'
            'password = "secrets:asadm:password"\n'
            f'[secret-agent]\nsa-address = "{self.tls_address}"\n'
            'sa-cafile = "/nonexistent/ca.pem"\n',
        )
        cp = util.run_asadm(f"--only-config-file {path} -e 'info network'")
        self.assert_fails_before_connecting(
            cp,
            "sa-cafile in the [secret-agent] config section: "
            "cannot load TLS CA file /nonexistent/ca.pem",
        )

    def test_legacy_cafile_with_untrusted_ca(self):
        cp = self.run_password(
            f"--sa-address {self.tls_address} --sa-cafile {self.untrusted_ca}"
        )
        self.assert_fails_before_connecting(cp, "CERTIFICATE_VERIFY_FAILED")
        self.assertIn(DEPRECATED_CAFILE, cp.stderr)


class SecretAgentClusterTests(AgentTestCase):
    """asadm authenticates with a password fetched from a real Secret Agent,
    over plaintext and over TLS."""

    @classmethod
    def setUpClass(cls):
        cls.addClassCleanup(lib.stop)
        lib.start(num_nodes=1)
        cls.untrusted_ca = untrusted_ca_file(cls)

    def setUp(self):
        super().setUp()
        self.host = f"{lib.SERVER_IP}:{lib.PORT}"

    def run_info(self, args):
        return util.run_asadm(f"{args} -e 'info network'")

    def run_password(self, password, agent_args):
        return self.run_info(
            f"--no-config-file -h {self.host} -U admin -P {password} {agent_args}"
        )

    def write_config(self, secret_agent_section, cluster_section="cluster"):
        return self.write_file(
            "astools.conf",
            f'[{cluster_section}]\nhost = "{self.host}"\nuser = "admin"\n'
            'password = "secrets:asadm:password"\n' + secret_agent_section,
        )

    def test_password_from_agent(self):
        cp = self.run_password(
            "secrets:asadm:password", f"--sa-address {self.agent.address}"
        )
        self.assert_connected(cp)

    def test_option_order(self):
        cp = self.run_info(
            f"--no-config-file --sa-address {self.agent.address} "
            f"-P secrets:asadm:password -h {self.host} -U admin"
        )
        self.assert_connected(cp)

    def test_config_file(self):
        path = self.write_config(
            f'[secret-agent]\nsa-address = "127.0.0.1"\nsa-port = {self.agent.port}\n'
        )
        self.assert_connected(self.run_info(f"--only-config-file {path}"))

    def test_config_file_timeout_in_quotes(self):
        path = self.write_config(
            f'[secret-agent]\nsa-address = "{self.agent.address}"\n'
            'sa-timeout = "5000"\n'
        )
        self.assert_connected(self.run_info(f"--only-config-file {path}"))

    def test_config_file_keys_ignore_case(self):
        """As in the C tools."""
        path = self.write_config(
            f'[secret-agent]\nSA-Address = "{self.agent.address}"\n'
            "SA-TIMEOUT = 5000\n"
        )
        self.assert_connected(self.run_info(f"--only-config-file {path}"))

    def test_include_applies_after_the_file_that_includes_it(self):
        """Each file is applied in turn, as in the C tools."""
        include = self.write_file(
            "include.conf", f'[secret-agent]\nsa-address = "{self.agent.address}"\n'
        )
        path = self.write_config(
            f'[secret-agent]\nsa-port = "1"\n[include]\nfile = "{include}"\n'
        )
        self.assert_connected(self.run_info(f"--only-config-file {path}"))

    def test_asinfo_password_from_agent(self):
        cp = util.run_asinfo(
            f"--no-config-file -h {lib.SERVER_IP} -p {lib.PORT} -U admin "
            f"-P secrets:asadm:password --sa-address {self.agent.address} -v build"
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn(lib.server_build(), cp.stdout)

    def test_asinfo_tls_agent_legacy_cafile(self):
        """asinfo fails on any stderr from asadm, but the deprecation warning is
        its own."""
        cp = util.run_asinfo(
            f"--no-config-file -h {lib.SERVER_IP} -p {lib.PORT} -U admin "
            f"-P secrets:asadm:password --sa-address {self.tls_address} "
            f"--sa-cafile {self.tls_agent.ca_file} -v build"
        )
        self.assertEqual(cp.returncode, 0, cp.stdout + cp.stderr)
        self.assertIn(lib.server_build(), cp.stdout)
        self.assertIn(DEPRECATED_CAFILE, cp.stderr)

    def test_command_line_beats_config_file(self):
        path = self.write_config('[secret-agent]\nsa-address = "127.0.0.1:1"\n')
        cp = self.run_info(
            f"--only-config-file {path} --sa-address {self.agent.address}"
        )
        self.assert_connected(cp)

    def test_instance_section(self):
        path = self.write_config(
            '[secret-agent]\nsa-address = "127.0.0.1:1"\n'
            f'[secret-agent_e2e]\nsa-address = "{self.agent.address}"\n',
            cluster_section="cluster_e2e",
        )
        cp = self.run_info(f"--only-config-file {path} --instance e2e")
        self.assert_connected(cp)

    def test_agent_options_unused_without_secrets(self):
        cp = self.run_password("admin", "--sa-port 0")
        self.assert_connected(cp)

    def test_fetched_value_is_the_password(self):
        cp = self.run_password(
            "secrets:asadm:wrong", f"--sa-address {self.agent.address}"
        )
        self.assertNotIn("--password:", cp.stderr)
        self.assertNotIn("Network Information", cp.stdout)
        self.assertNotIn(WRONG_PW, cp.stdout + cp.stderr)

    def test_tls_agent(self):
        cp = self.run_password(
            "secrets:asadm:password",
            f"--sa-address {self.tls_address} --sa-ca-file {self.tls_agent.ca_file}",
        )
        self.assert_connected(cp)
        self.assertNotIn("deprecated", cp.stderr)

    def test_tls_agent_config_file(self):
        path = self.write_config(
            f'[secret-agent]\nsa-address = "{self.tls_address}"\n'
            f'sa-ca-file = "{self.tls_agent.ca_file}"\n'
        )
        cp = self.run_info(f"--only-config-file {path}")
        self.assert_connected(cp)
        self.assertNotIn("deprecated", cp.stderr)

    def test_tls_agent_legacy_cafile_in_config_file(self):
        path = self.write_config(
            f'[secret-agent]\nsa-address = "{self.tls_address}"\n'
            f'sa-cafile = "{self.tls_agent.ca_file}"\n'
        )
        cp = self.run_info(f"--only-config-file {path}")
        self.assert_connected(cp)
        self.assertNotIn("deprecated", cp.stderr)

    def test_tls_agent_legacy_cafile_on_command_line(self):
        cp = self.run_password(
            "secrets:asadm:password",
            f"--sa-address {self.tls_address} --sa-cafile {self.tls_agent.ca_file}",
        )
        self.assert_connected(cp)
        self.assertIn(DEPRECATED_CAFILE, cp.stderr)

    def test_tls_agent_ca_file_beats_legacy_cafile(self):
        cp = self.run_password(
            "secrets:asadm:password",
            f"--sa-address {self.tls_address} --sa-cafile {self.untrusted_ca} "
            f"--sa-ca-file {self.tls_agent.ca_file}",
        )
        self.assert_connected(cp)

    def test_tls_agent_command_line_ca_beats_config_file(self):
        path = self.write_config(
            f'[secret-agent]\nsa-address = "{self.tls_address}"\n'
            f'sa-ca-file = "{self.untrusted_ca}"\n'
        )
        cp = self.run_info(
            f"--only-config-file {path} --sa-ca-file {self.tls_agent.ca_file}"
        )
        self.assert_connected(cp)


class SecretAgentTLSServerTests(AgentTestCase):
    """A TLS server login where the key file password and the login password
    both come from a TLS Secret Agent."""

    @classmethod
    def setUpClass(cls):
        cls.addClassCleanup(lib.cleanup_tls_certs)
        cls.addClassCleanup(lib.stop)
        lib.start(num_nodes=1, template_file="aerospike_tls.conf")

    def run_info(self, keyfile_password, keyfile="client_enc.key", stdin_input=None):
        certs = lib.CERTS_DIR

        return util.run_asadm(
            f"--no-config-file -h {lib.SERVER_IP}:{lib.TLS_PORT} --tls-enable "
            f"--tls-name localhost --tls-cafile {certs}/ca.pem "
            f"--tls-certfile {certs}/client.pem "
            f"--tls-keyfile {os.path.join(certs, keyfile)} "
            f"--tls-keyfile-password {keyfile_password} "
            "-U admin -P secrets:asadm:password "
            f"--sa-address {self.tls_address} --sa-ca-file {self.tls_agent.ca_file} "
            "-e 'info network'",
            stdin_input=stdin_input,
        )

    def test_keyfile_password_from_agent(self):
        self.assert_connected(self.run_info("secrets:asadm:keypass"))

    def test_piped_keyfile_password_is_never_fetched(self):
        """As in asbackup. The key is encrypted with the literal reference, so it
        only opens if the piped value is used as typed, not swapped for the
        agent's keypass."""
        literal = "secrets:asadm:keypass"

        with open(os.path.join(lib.CERTS_DIR, "client.key"), "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        keyfile = self.write_file(
            "client_literal.key",
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.BestAvailableEncryption(literal.encode()),
            ).decode(),
        )
        cp = self.run_info("", keyfile=keyfile, stdin_input=literal + "\n")
        self.assert_connected(cp)

    def test_wrong_keyfile_password_from_agent(self):
        cp = self.run_info("secrets:asadm:wrong")
        self.assertNotEqual(cp.returncode, 0)
        self.assertNotIn("--tls-keyfile-password:", cp.stderr)
        self.assertNotIn("--password:", cp.stderr)
        self.assertNotIn("Network Information", cp.stdout)
        self.assertNotIn(WRONG_PW, cp.stdout + cp.stderr)


if __name__ == "__main__":
    unittest.main()
