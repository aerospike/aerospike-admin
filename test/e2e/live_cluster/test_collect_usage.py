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
"""collect usage and the usage file in collectinfo bundles (TOOLS-4579).

The harness server predates usage reporting, so it covers the "no usage
reporting" path. Point ASADM_E2E_USAGE_SEED (host:port) at a server that has it,
with ASADM_E2E_USAGE_USER and ASADM_E2E_USAGE_PASSWORD for a user-admin user
(default admin/admin), to cover the export itself. That server is only read."""

import base64
import glob
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import unittest

from lib.utils import version
from test.e2e import lib, util

PREFIX = "asadm_collect_usage_test_"
USAGE_SEED = os.environ.get("ASADM_E2E_USAGE_SEED", "")
USAGE_USER = os.environ.get("ASADM_E2E_USAGE_USER", "admin")
USAGE_PASSWORD = os.environ.get("ASADM_E2E_USAGE_PASSWORD", "admin")
BASE64_VALUE = re.compile(r"^(eyJ[A-Za-z0-9+/=]+|ERROR\S*.*)$", re.M)
FIRST_VERSION = "8.2.1"
OLDER_SERVERS = "is not supported on aerospike versions < 8.2.1"
UNKNOWN_USAGE_COMMAND = "unrecognized command - 'usage-export'"


def remove_outputs():
    for path in glob.glob(f"/tmp/{PREFIX}*"):
        if os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.remove(path)


def usage_reply(connect):
    cp = util.run_asadm(f"{connect} --enable -e 'asinfo -v usage-export'")
    match = BASE64_VALUE.search(cp.stdout)

    if not match:
        raise AssertionError(f"no usage reply in:\n{cp.stdout}\n{cp.stderr}")

    return match.group(1)


def server_builds(connect):
    cp = util.run_asadm(f"{connect} --enable -e 'asinfo -v build'")

    return re.findall(r"^(\d+\.\d+\.\d+\.\d+\S*)$", cp.stdout, re.M)


def harness_server_logs():
    return [
        container.exec_run(["cat", lib.LOG_PATH]).output.decode(errors="replace")
        for container in lib.DOCKER_CLIENT.containers.list()
        if re.fullmatch(r"aerospike-\d+", container.name)
    ]


def cluster_uuid(connect):
    cp = util.run_asadm(f"{connect} --enable -e 'asinfo -v statistics -l'")
    match = re.search(r"^cluster_uuid=(\S+)$", cp.stdout, re.M)

    return match.group(1) if match else None


def without_taken(document):
    value = json.loads(document)
    value["data"].pop("taken")

    return value


def bundle_members(bundle):
    with tarfile.open(bundle) as tar:
        return {
            os.path.basename(member.name): tar.extractfile(member).read()
            for member in tar.getmembers()
            if member.isfile() and not os.path.basename(member.name).startswith("._")
        }


def saved_path(stdout):
    match = re.search(r"^Saved\s+(\S+) \(", stdout, re.M)

    return match.group(1) if match else None


def archived(archive, suffix):
    members = bundle_members(archive)
    names = [name for name in members if name.endswith(suffix)]

    if len(names) != 1:
        raise AssertionError(f"{archive} holds {sorted(members)}")

    return members[names[0]]


class CollectUsageWithoutUsageReportingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lib.start()
        cls.connect = f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin"

        builds = server_builds(cls.connect)

        if builds and all(
            version.LooseVersion(build) >= version.LooseVersion(FIRST_VERSION)
            for build in builds
        ):
            raise unittest.SkipTest("the harness server has usage reporting")

        cls.collect_usage = util.run_asadm(
            f"{cls.connect} -e 'collect usage --output-prefix {PREFIX}'"
        )
        cls.show_usage = util.run_asadm(f"{cls.connect} -e 'show usage'")
        cls.collect_info = util.run_asadm(
            f"{cls.connect} -e 'collect info --output-prefix {PREFIX}info_'"
        )
        cls.bundle = util.get_collectinfo_path(cls.collect_info, f"/tmp/{PREFIX}info_")
        cls.server_logs = harness_server_logs()

    @classmethod
    def tearDownClass(cls):
        remove_outputs()
        lib.stop()

    def test_collect_usage_warns_and_points_to_collect_info(self):
        self.assertEqual(self.collect_usage.returncode, 0, self.collect_usage.stderr)
        self.assertIn(
            f"WARNING: 'collect usage' {OLDER_SERVERS}. Use 'collect info' instead.",
            self.collect_usage.stderr,
        )
        self.assertNotIn("ERROR", self.collect_usage.stderr)
        self.assertEqual(glob.glob(f"/tmp/{PREFIX}collect_usage_*"), [])

    def test_show_usage_warns(self):
        self.assertEqual(self.show_usage.returncode, 0, self.show_usage.stderr)
        self.assertIn(f"WARNING: 'show usage' {OLDER_SERVERS}", self.show_usage.stderr)
        self.assertNotIn("ERROR", self.show_usage.stderr)

    def test_older_servers_are_never_sent_the_usage_command(self):
        self.assertTrue(self.server_logs)

        for log in self.server_logs:
            self.assertNotIn(UNKNOWN_USAGE_COMMAND, log)

    def test_collect_info_bundle_has_no_usage_file(self):
        members = bundle_members(self.bundle)
        meta_name = next(
            name for name in members if name.endswith("collectinfo_meta.json")
        )

        self.assertEqual([name for name in members if name.endswith("_usage.json")], [])
        self.assertEqual(
            json.loads(members[meta_name])["collection"]["usage"],
            {"status": "unsupported", "min_version": FIRST_VERSION},
        )
        self.assertNotIn("'usage-export'", self.collect_info.stderr)

    def test_show_usage_on_that_bundle_warns(self):
        cp = util.run_asadm(f"-cf {self.bundle} -e 'show usage'")

        self.assertIn(f"WARNING: 'show usage' {OLDER_SERVERS}", cp.stderr)

    def test_info_summary_shows_the_cluster_uuid_only_when_nodes_report_one(self):
        uuid = cluster_uuid(self.connect)
        cp = util.run_asadm(f"{self.connect} -e 'info summary'")
        lines = [
            util.remove_escape_sequence(line)
            for line in cp.stdout.splitlines()
            if "Cluster UUID" in line
        ]

        if uuid:
            self.assertEqual(len(lines), 1, cp.stdout)
            self.assertTrue(lines[0].endswith(uuid), lines)
        else:
            self.assertEqual(lines, [])

    def test_help_collect_lists_usage(self):
        cp = util.run_asadm(f"{self.connect} -e 'help collect'")
        lines = [util.remove_escape_sequence(line) for line in cp.stdout.splitlines()]

        self.assertTrue(any(line.split()[:1] == ["usage"] for line in lines), cp.stdout)


@unittest.skipUnless(
    USAGE_SEED, "set ASADM_E2E_USAGE_SEED to a server with usage reporting"
)
class CollectUsageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.connect = f"-h {USAGE_SEED} -U{USAGE_USER} -P{USAGE_PASSWORD}"
        cls.uuid = cluster_uuid(cls.connect)
        cls.collect_usage = util.run_asadm(
            f"{cls.connect} -e 'collect usage --output-prefix {PREFIX}'"
        )
        cls.reply = usage_reply(cls.connect)
        cls.collect_info = util.run_asadm(
            f"{cls.connect} -e 'collect info --output-prefix {PREFIX}info_'"
        )
        cls.bundle = util.get_collectinfo_path(cls.collect_info, f"/tmp/{PREFIX}info_")
        cls.archive = saved_path(cls.collect_usage.stdout)
        cls.file = b""
        cls.meta = {}

        if cls.archive and tarfile.is_tarfile(cls.archive):
            cls.file = archived(cls.archive, "_usage.json")
            cls.meta = json.loads(archived(cls.archive, "_usage_meta.json"))

    @classmethod
    def tearDownClass(cls):
        remove_outputs()

    def test_the_file_is_the_servers_export(self):
        self.assertEqual(self.collect_usage.returncode, 0, self.collect_usage.stderr)
        self.assertEqual(
            without_taken(self.file), without_taken(base64.b64decode(self.reply))
        )
        self.assertEqual(
            self.file,
            json.dumps(
                json.loads(self.file), sort_keys=True, separators=(",", ":")
            ).encode(),
        )

    def test_prints_the_cluster_and_the_saved_file(self):
        lines = self.collect_usage.stdout.splitlines()

        self.assertIn(f"Cluster {self.uuid}", lines)
        self.assertTrue(any(line.startswith("Days    ") for line in lines), lines)
        self.assertTrue(self.archive.startswith(f"/tmp/{PREFIX}collect_usage_"))
        self.assertTrue(self.archive.endswith(".tgz"), self.archive)

    def test_the_meta_file_names_the_cluster_and_the_nodes(self):
        self.assertEqual(self.meta.get("cluster_uuid"), self.uuid, self.meta)
        self.assertIn(self.meta.get("usage_node"), self.meta.get("responded_nodes"))
        self.assertTrue(
            set(self.meta["responded_nodes"]) <= set(self.meta["expected_nodes"])
        )

    def test_show_usage_reads_the_archive(self):
        cp = util.run_asadm(f"-cf {self.archive} -e 'show usage'")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertNotIn("ERROR", cp.stderr)
        self.assertIn(f"Cluster {self.uuid}", cp.stdout.splitlines())

    def test_collect_info_bundle_carries_the_same_file(self):
        members = bundle_members(self.bundle)
        usage = [name for name in members if name.endswith("_usage.json")]
        meta_name = next(
            name for name in members if name.endswith("collectinfo_meta.json")
        )

        self.assertEqual(len(usage), 1, sorted(members))
        self.assertEqual(without_taken(members[usage[0]]), without_taken(self.file))
        self.assertEqual(
            json.loads(members[meta_name])["collection"]["usage"]["status"], "written"
        )

    def test_show_usage_reads_the_cluster(self):
        cp = util.run_asadm(f"{self.connect} -e 'show usage'")
        lines = cp.stdout.splitlines()

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn(f"Cluster {self.uuid}", lines)
        self.assertTrue(any(line.startswith("Taken   ") for line in lines), lines)

    def test_show_usage_reads_the_bundle(self):
        cp = util.run_asadm(f"-cf {self.bundle} -e 'show usage'")

        self.assertIn(f"Cluster {self.uuid}", cp.stdout.splitlines())

    def test_info_summary_shows_the_cluster_uuid(self):
        cp = util.run_asadm(f"{self.connect} -e 'info summary'")
        lines = [
            util.remove_escape_sequence(line)
            for line in cp.stdout.splitlines()
            if "Cluster UUID" in line
        ]

        self.assertEqual(len(lines), 1, cp.stdout)
        self.assertTrue(lines[0].endswith(self.uuid), lines)

    def test_health_finds_no_uuid_mismatch(self):
        cp = util.run_asadm(f"{self.connect} -e 'health'")

        self.assertNotIn("Different Cluster UUID", cp.stdout)


class ShowUsageFromArchiveTest(unittest.TestCase):
    """No server: the archive is laid out here the way 'collect usage' writes it."""

    UUID = "963fa489-71bd-46a9-af70-765ce26c5a62"

    def setUp(self):
        self.work_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work_dir, ignore_errors=True)
        self.archive = os.path.join(self.work_dir, "collect_usage_20261116_191136.tgz")
        document = json.dumps(
            {
                "data": {
                    "cluster": self.UUID,
                    "feature_key": {"account-ID": "12345", "account-name": "Acme Corp"},
                    "records": [],
                    "schema": 1,
                    "taken": "2026-11-16T19:11:36Z",
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        members = {
            "20261116_191136_usage.json": document,
            "20261116_191136_usage_meta.json": b'{"meta_format_version":1}',
        }

        with tarfile.open(self.archive, "w:gz") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo("collect_usage_20261116_191136/" + name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

    def test_show_usage_reads_a_collect_usage_archive(self):
        cp = util.run_asadm(f"-cf {self.archive} -e 'show usage'")

        self.assertNotIn("ERROR", cp.stderr)
        self.assertNotIn("WARNING", cp.stderr)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(
            cp.stdout.splitlines()[:4],
            [
                f"Cluster {self.UUID}",
                "Account Acme Corp (12345)",
                "Days    none closed yet",
                "Taken   2026-11-16 19:11:36 UTC",
            ],
        )

    def test_an_abbreviated_show_usage_reads_the_archive(self):
        for command in ("sh usage", "show usa"):
            with self.subTest(command=command):
                cp = util.run_asadm(f"-cf {self.archive} -e '{command}'")

                self.assertNotIn("WARNING", cp.stderr)
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertEqual(cp.stdout.splitlines()[:1], [f"Cluster {self.UUID}"])

    def test_other_commands_find_no_collectinfo_data_and_do_not_fail(self):
        for command in ("info summary", "health", "info network", "show config"):
            with self.subTest(command=command):
                cp = util.run_asadm(f"-cf {self.archive} -e '{command}'")

                self.assertNotIn("ERROR", cp.stderr)
                self.assertNotIn("Traceback", cp.stdout + cp.stderr)
                self.assertEqual(cp.returncode, 0, cp.stderr)
                self.assertIn("no collectinfo data", cp.stderr)

    def test_the_intro_names_a_usage_archive_and_points_to_show_usage(self):
        cp = util.run_asadm(f"-cf {self.archive}", stdin_input="exit\n")
        intro = cp.stdout.lower()

        self.assertIn("usage archive", intro)
        self.assertIn("show usage", intro)
        self.assertNotIn("ERROR", cp.stderr)
