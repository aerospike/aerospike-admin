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

import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from test.e2e import lib, util

CLIENT_IMAGE = "asadm-e2e-fips-client"
CLIENT_NAME = "asadm-e2e-fips-client"
FIPS_ENV = {"OPENSSL_FORCE_FIPS_MODE": "1"}
REPO_ROOT = lib.absolute_path("..", "..")
WORK = lib.absolute_path(lib.WORK_DIRECTORY, "fips")
CLIENT_WORK = "/asadm/test/e2e/%s/fips" % lib.WORK_DIRECTORY
CLIENT_CERTS = "/asadm/test/e2e/certs"
SSHD_LOG = "/var/log/sshd.log"


def requirements_from_lock(lock_path):
    """asadm's runtime packages from Pipfile.lock, as hashed pip requirements."""
    with open(lock_path) as f:
        packages = json.load(f)["default"]

    lines = []
    for name, spec in sorted(packages.items()):
        line = name + spec["version"]
        if spec.get("markers"):
            line += "; " + spec["markers"]
        lines.append(line + "".join(" --hash=" + h for h in spec["hashes"]))

    return "\n".join(lines) + "\n"


def build_client_image():
    with tempfile.TemporaryDirectory() as context:
        shutil.copy(os.path.join(os.path.dirname(__file__), "Dockerfile"), context)
        with open(os.path.join(context, "requirements.txt"), "w") as f:
            f.write(requirements_from_lock(os.path.join(REPO_ROOT, "Pipfile.lock")))

        for chunk in lib.DOCKER_CLIENT.api.build(
            path=context, tag=CLIENT_IMAGE, rm=True, decode=True
        ):
            if "error" in chunk:
                raise Exception(
                    "building %s failed: %s" % (CLIENT_IMAGE, chunk["error"])
                )
            print(chunk.get("stream", ""), end="")


def remove_client():
    try:
        lib.DOCKER_CLIENT.containers.get(CLIENT_NAME).remove(force=True)
    except Exception:
        pass


def start_sshd(server, public_key):
    script = (
        "set -e; apt-get update -qq; "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "
        "openssh-server >/dev/null; "
        "mkdir -p /run/sshd /root/.ssh; chmod 700 /root/.ssh; "
        "echo '%s' > /root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys; "
        "/usr/sbin/sshd -E %s -o LogLevel=DEBUG1" % (public_key, SSHD_LOG)
    )
    result = server.exec_run(["sh", "-c", script])
    if result.exit_code != 0:
        raise Exception("starting sshd failed: %s" % result.output.decode())


def sshd_log(server):
    return server.exec_run(["cat", SSHD_LOG]).output.decode().splitlines()


def negotiated(log_lines, prefix):
    """What sshd logged after `prefix` for each SSH session, e.g. "kex: algorithm: "."""
    return [line.split(prefix, 1)[1].split()[0] for line in log_lines if prefix in line]


def sys_stat_nodenames(ascinfo):
    """Every uname nodename under a sys_stat section of a collectinfo ascinfo.json."""
    found = []

    def walk(value, keys):
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, keys + [key])
        elif "sys_stat" in keys and keys[-2:] == ["uname", "nodename"]:
            found.append(value)

    walk(ascinfo, [])
    return found


class TestFIPS(unittest.TestCase):
    """asadm from the working tree on a RHEL 9 host whose OpenSSL is in FIPS mode."""

    @classmethod
    def setUpClass(cls):
        build_client_image()
        lib.start(num_nodes=1, template_file="aerospike_tls.conf")

        cls.server = server = lib.NODES[0]
        server.reload()
        cls.server_ip = server.attrs["NetworkSettings"]["Networks"]["bridge"][
            "IPAddress"
        ]
        cls.server_hostname = server.attrs["Config"]["Hostname"]

        os.makedirs(WORK, exist_ok=True)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        with open(os.path.join(WORK, "id_rsa"), "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.OpenSSH,
                    serialization.NoEncryption(),
                )
            )
        start_sshd(
            server,
            key.public_key()
            .public_bytes(
                serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
            )
            .decode(),
        )

        remove_client()
        cls.client = lib.DOCKER_CLIENT.containers.run(
            CLIENT_IMAGE,
            command="sleep infinity",
            name=CLIENT_NAME,
            detach=True,
            network="bridge",
            volumes={REPO_ROOT: {"bind": "/asadm", "mode": "ro"}},
        )
        cp = cls._run(
            "sh -c 'mkdir -p /root/.ssh && ssh-keyscan -q %s > /root/.ssh/known_hosts'"
            % cls.server_ip,
            fips=False,
        )
        if cp.returncode != 0:
            raise Exception("ssh-keyscan failed: %s" % cp.stderr)

        cls.tls = (
            "-h %s:localhost:%d --tls-enable --tls-cafile %s/ca.pem -Uadmin -Padmin"
            % (cls.server_ip, lib.TLS_PORT, CLIENT_CERTS)
        )

    @classmethod
    def tearDownClass(cls):
        remove_client()
        lib.stop()
        lib.cleanup_tls_certs()

    @classmethod
    def _run(cls, cmd, fips=True):
        result = cls.client.exec_run(
            ["sh", "-c", cmd], environment=FIPS_ENV if fips else {}, demux=True
        )
        stdout, stderr = result.output
        return util.CompletedProcess(
            subprocess.CompletedProcess(
                cmd, result.exit_code, stdout or b"", stderr or b""
            )
        )

    def test_forced_fips_mode_is_enforced(self):
        """Guards the other tests: the host OpenSSL refuses MD5 and serves SHA-256."""
        self.assertEqual(self._run("openssl sha256 /dev/null").returncode, 0)
        self.assertNotEqual(self._run("openssl md5 /dev/null").returncode, 0)

    def test_tls_connection(self):
        cp = self._run("asadm %s -e 'info network'" % self.tls)

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_tls_refuses_a_cipher_fips_does_not_approve(self):
        cp = self._run(
            "asadm %s --tls-protocols TLSv1.2 "
            "--tls-cipher-suite ECDHE-RSA-CHACHA20-POLY1305 -e 'info network'"
            % self.tls
        )

        self.assertNotEqual(cp.returncode, 0)
        self.assertIn("no cipher match", cp.stdout + cp.stderr)

    def test_asinfo_over_tls(self):
        cp = self._run("asinfo %s -v build" % self.tls)

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertRegex(cp.stdout, r"^\d+\.\d+")

    def test_collectinfo_collects_system_statistics_over_ssh(self):
        logged_before = len(sshd_log(self.server))
        cp = self._run(
            "cd /tmp && asadm %s -e 'collectinfo --enable-ssh --ssh-user root "
            "--ssh-key %s/id_rsa --output-prefix asadm_fips_ssh_'"
            % (self.tls, CLIENT_WORK)
        )
        self.assertEqual(cp.returncode, 0, cp.stderr)

        archive, _ = self.client.get_archive(
            util.get_collectinfo_path(cp, "/tmp/asadm_fips_ssh_")
        )
        with tarfile.open(fileobj=io.BytesIO(b"".join(archive))) as outer:
            bundle = outer.extractfile(outer.getmembers()[0]).read()
        with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as tf:
            ascinfo = next(
                json.load(tf.extractfile(m))
                for m in tf.getmembers()
                if m.name.endswith("_ascinfo.json")
            )

        self.assertEqual([self.server_hostname], sys_stat_nodenames(ascinfo))

        sessions = sshd_log(self.server)[logged_before:]
        ciphers = negotiated(sessions, "kex: client->server cipher: ")
        key_exchanges = negotiated(sessions, "kex: algorithm: ")
        self.assertTrue(ciphers, "sshd logged no SSH session")
        self.assertTrue(all(c.startswith("aes") for c in ciphers), ciphers)
        self.assertFalse(any("25519" in k for k in key_exchanges), key_exchanges)

    def test_log_analyzer_hashes_log_names_and_lines(self):
        logs = os.path.join(WORK, "logs")
        os.makedirs(logs, exist_ok=True)
        with open(os.path.join(logs, "aerospike.log"), "w") as f:
            f.write(
                "Nov 16 2026 08:00:00 GMT: INFO (info): (ticker.c:160) cluster-size 1\n"
                "Nov 16 2026 08:00:01 GMT: INFO (info): (ticker.c:160) cluster-size 1\n"
            )

        cp = self._run("asadm -l -f %s/logs -e 'grep -s cluster-size -u'" % CLIENT_WORK)

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(1, cp.stdout.count("cluster-size 1"), cp.stdout)
