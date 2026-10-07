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

from lib.secret_agent import SecretAgentClient, SecretAgentError
from test.e2e import lib, util

AGENT_IMAGE = os.environ.get(
    "ASADM_E2E_SECRET_AGENT_IMAGE", "aerospike/aerospike-secret-agent:1.1.0"
)
AGENT_PLATFORM = "linux/amd64"
AGENT_START_TIMEOUT = 120
WRONG_PW = "not-the-admin-password"
AGENT_CONFIG = """service:
  tcp:
    endpoint: 0.0.0.0:3005
secret-manager:
  file:
    convert-to-base64: true
    resources:
      asadm: "/agent/asadm.json"
log:
  level: debug
"""


class SecretAgent:
    """A real Secret Agent container with a file backend. The asadm resource
    holds the cluster's admin password and a wrong one."""

    def __init__(self):
        self.client = docker.from_env()
        self.directory = os.path.realpath(tempfile.mkdtemp(prefix="asadm-sa-"))
        self.container = None
        self.address = None

    def start(self):
        try:
            self.client.images.get(AGENT_IMAGE)
        except docker.errors.ImageNotFound:
            self.client.images.pull(AGENT_IMAGE, platform=AGENT_PLATFORM)

        files = {
            "asadm.json": json.dumps({"password": "admin", "wrong": WRONG_PW}),
            "agent.yaml": AGENT_CONFIG,
        }

        # World-readable, so the agent reads them whatever uid Docker maps it to.
        for name, content in files.items():
            path = os.path.join(self.directory, name)

            with open(path, "w") as f:
                f.write(content)

            os.chmod(path, 0o644)

        os.chmod(self.directory, 0o755)

        self.container = self.client.containers.run(
            AGENT_IMAGE,
            command=["--config-file", "/agent/agent.yaml"],
            volumes={self.directory: {"bind": "/agent", "mode": "ro"}},
            ports={"3005/tcp": ("127.0.0.1", None)},
            detach=True,
        )
        self.container.reload()
        port = self.container.attrs["NetworkSettings"]["Ports"]["3005/tcp"][0][
            "HostPort"
        ]
        self.address = "127.0.0.1:" + port
        self._wait_until_serving(int(port))

    def stop(self):
        if self.container is not None:
            self.container.remove(force=True)

        shutil.rmtree(self.directory, ignore_errors=True)

    def _wait_until_serving(self, port):
        # The agent logs that it listens before its file backend has loaded.
        client = SecretAgentClient("127.0.0.1", port, timeout=5)
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


class SecretAgentErrorTests(unittest.TestCase):
    """Secret Agent failures stop asadm before it connects, so no server is
    needed."""

    BASE = "--no-config-file -h 127.0.0.1:1 -e 'info network'"

    @classmethod
    def setUpClass(cls):
        cls.agent = SecretAgent()
        cls.addClassCleanup(cls.agent.stop)
        cls.agent.start()

    def assert_fails_before_connecting(self, cp, message):
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn(message, cp.stderr)
        self.assertNotIn("Not able to connect", cp.stdout + cp.stderr)

    def test_missing_secret(self):
        cp = util.run_asadm(
            f"{self.BASE} -U admin -P secrets:asadm:missing "
            f"--sa-address {self.agent.address}"
        )
        self.assert_fails_before_connecting(
            cp, "--password: agent error for secrets:asadm:missing"
        )

    def test_agent_unreachable(self):
        cp = util.run_asadm(
            f"{self.BASE} -U admin -P secrets:asadm:password --sa-address 127.0.0.1:1"
        )
        self.assert_fails_before_connecting(
            cp, "--password: connect to 127.0.0.1:1 for secrets:asadm:password"
        )

    def test_keyfile_password_missing_secret(self):
        cp = util.run_asadm(
            f"{self.BASE} --tls-enable --tls-keyfile /k.pem "
            f"--tls-keyfile-password secrets:asadm:missing "
            f"--sa-address {self.agent.address}"
        )
        self.assert_fails_before_connecting(
            cp, "--tls-keyfile-password: agent error for secrets:asadm:missing"
        )

    def test_invalid_agent_port(self):
        cp = util.run_asadm(
            f"{self.BASE} -U admin -P secrets:asadm:password --sa-port 0"
        )
        self.assert_fails_before_connecting(cp, "--sa-port: invalid value 0")


class SecretAgentClusterTests(unittest.TestCase):
    """asadm authenticates with a password fetched from a real Secret Agent."""

    @classmethod
    def setUpClass(cls):
        cls.agent = SecretAgent()
        cls.addClassCleanup(cls.agent.stop)
        cls.agent.start()
        lib.start()
        cls.addClassCleanup(lib.stop)

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def run_info(self, args):
        return util.run_asadm(f"{args} -e 'info network'")

    def assert_connected(self, cp):
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_password_from_agent(self):
        cp = self.run_info(
            f"--no-config-file -h {lib.SERVER_IP}:{lib.PORT} -U admin "
            f"-P secrets:asadm:password --sa-address {self.agent.address}"
        )
        self.assert_connected(cp)

    def test_option_order(self):
        cp = self.run_info(
            f"--no-config-file --sa-address {self.agent.address} "
            f"-P secrets:asadm:password -h {lib.SERVER_IP}:{lib.PORT} -U admin"
        )
        self.assert_connected(cp)

    def test_config_file(self):
        host, port = self.agent.address.rsplit(":", 1)
        path = os.path.join(self.tmpdir.name, "astools.conf")

        with open(path, "w") as f:
            f.write(
                f'[cluster]\nhost = "{lib.SERVER_IP}:{lib.PORT}"\nuser = "admin"\n'
                'password = "secrets:asadm:password"\n'
                f'[secret-agent]\nsa-address = "{host}"\nsa-port = {port}\n'
            )

        self.assert_connected(self.run_info(f"--only-config-file {path}"))

    def test_fetched_value_is_the_password(self):
        cp = self.run_info(
            f"--no-config-file -h {lib.SERVER_IP}:{lib.PORT} -U admin "
            f"-P secrets:asadm:wrong --sa-address {self.agent.address}"
        )
        self.assertNotIn("Network Information", cp.stdout)
        self.assertNotIn(WRONG_PW, cp.stdout + cp.stderr)


if __name__ == "__main__":
    unittest.main()
