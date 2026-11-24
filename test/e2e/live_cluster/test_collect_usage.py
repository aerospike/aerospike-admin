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
reporting" path. The export itself (AER-7009, AER-7010) is in no release yet,
so those classes pin the 8.2.1.0 RC1 image."""

import base64
import glob
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
import unittest

from lib.utils import version
from test.e2e import lib, util

USAGE_SERVER_TAG = lib.SERVER_8_2_1_TAG
PREFIX = "asadm_collect_usage_test_"
NO_ROLES_USER = f"{PREFIX}no_roles"
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


def harness_connect():
    return f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin"


def wait_for_builds(connect, count, timeout=90):
    deadline = time.time() + timeout
    builds = []

    while time.time() < deadline:
        builds = server_builds(connect)

        if len(builds) == count:
            return builds

        time.sleep(2)

    raise AssertionError(f"asadm read {builds}, not {count} builds")


def service_template(line):
    """The harness template with one more line in the service stanza."""
    with open(lib.absolute_path("aerospike_latest.conf")) as f:
        content = f.read()

    marker = "\tproto-fd-max 1024\n"

    if marker not in content:
        raise AssertionError("service stanza anchor missing from the template")

    return content.replace(marker, marker + line + "\n")


def start_usage_server(num_nodes, template_content=None, timeout=90):
    """Starts RC1 and waits until asadm reads every node and each has a UUID."""
    lib.stop()
    lib.start(
        num_nodes=num_nodes,
        docker_tag=USAGE_SERVER_TAG,
        template_content=template_content,
        mesh_over_bridge=True,
    )
    connect = harness_connect()
    wait_for_one_uuid(connect, num_nodes, timeout)

    return connect


def wait_for_one_uuid(connect, num_nodes, timeout=90):
    deadline = time.time() + timeout
    cp = None

    while time.time() < deadline:
        cp = util.run_asadm(f"{connect} --enable -e 'asinfo -v statistics -l'")
        uuids = re.findall(r"^cluster_uuid=(\S+)$", cp.stdout, re.M)

        if (
            len(uuids) == num_nodes
            and len(set(uuids)) == 1
            and "Offline" not in cp.stderr
        ):
            return

        time.sleep(2)

    raise AssertionError(
        f"no cluster_uuid on {num_nodes} nodes:\n{cp.stdout}\n{cp.stderr}"
    )


def node_address(index):
    conf = lib.NODE_CONFS[index - 1]

    return f"{conf['access_address']}:{conf['port_base']}"


def principal_index():
    """The harness node with the highest node-id, the one asadm asks first."""
    indexes = {}

    for index, (container, conf) in enumerate(zip(lib.NODES, lib.NODE_CONFS), 1):
        if container is not None and conf is not None:
            reply = container.exec_run(
                f"asinfo -p {conf['port_base']} -U admin -P admin -v node"
            )
            indexes[reply.output.decode().strip().zfill(16)] = index

    return indexes[max(indexes)]


def collect_usage_with_the_principal_frozen(connect, num_nodes):
    """Runs 'collect usage' in a session that found every node, with the principal
    paused right after. Returns the output and the address of a node left running."""
    principal = principal_index()
    container = lib.NODES[principal - 1]
    other = next(
        index
        for index, conf in enumerate(lib.NODE_CONFS, 1)
        if conf is not None and index != principal
    )
    session = util.AsadmSession(connect)

    try:
        container.pause()

        try:
            output = session.run(
                f"collect usage --output-prefix {PREFIX}frozen_", timeout=120
            )
        finally:
            container.unpause()
    finally:
        session.close()

    lib.wait_for_cluster(num_nodes)
    wait_for_one_uuid(connect, num_nodes)

    return output, node_address(other)


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
        lib.stop()
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
            self.assertEqual(lines[0].split("|", 1)[1].strip(), uuid, lines)
        else:
            self.assertEqual(lines, [])

    def test_help_collect_lists_usage(self):
        cp = util.run_asadm(f"{self.connect} -e 'help collect'")
        lines = [util.remove_escape_sequence(line) for line in cp.stdout.splitlines()]

        self.assertTrue(any(line.split()[:1] == ["usage"] for line in lines), cp.stdout)


class CollectUsageTest(unittest.TestCase):
    NODES = 2

    @classmethod
    def setUpClass(cls):
        cls.connect = start_usage_server(cls.NODES)
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

        cls.new_dir = f"/tmp/{PREFIX}new_dir"
        shutil.rmtree(cls.new_dir, ignore_errors=True)
        cls.collect_into_new_dir = util.run_asadm(
            f"{cls.connect} -e 'collect usage --output-prefix {PREFIX}new_dir/'"
        )
        cls.frozen_output, cls.running_node = collect_usage_with_the_principal_frozen(
            cls.connect, cls.NODES
        )

    @classmethod
    def tearDownClass(cls):
        remove_outputs()
        lib.stop()

    def test_output_prefix_with_a_new_directory_creates_it(self):
        cp = self.collect_into_new_dir
        archive = saved_path(cp.stdout)

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertNotIn("ERROR", cp.stderr)
        self.assertEqual(os.path.dirname(archive), self.new_dir, cp.stdout)
        self.assertEqual(
            json.loads(archived(archive, "_usage.json"))["data"]["cluster"], self.uuid
        )

    def test_another_node_answers_while_the_principal_is_frozen(self):
        archive = saved_path(self.frozen_output)

        self.assertNotIn("ERROR", self.frozen_output)
        self.assertIsNotNone(archive, self.frozen_output)
        self.assertEqual(
            json.loads(archived(archive, "_usage_meta.json"))["usage_node"],
            self.running_node,
        )
        self.assertEqual(
            json.loads(archived(archive, "_usage.json"))["data"]["cluster"], self.uuid
        )

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
        self.assertEqual(len(self.meta["expected_nodes"]), self.NODES, self.meta)
        self.assertEqual(
            sorted(self.meta["responded_nodes"]), sorted(self.meta["expected_nodes"])
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
        self.assertEqual(lines[0].split("|", 1)[1].strip(), self.uuid, lines)

    def test_health_finds_no_uuid_mismatch(self):
        cp = util.run_asadm(f"{self.connect} -e 'health'")

        self.assertNotIn("Different Cluster UUID", cp.stdout)

    def test_health_compares_uuids_when_every_node_reports_one(self):
        cp = util.run_asadm(f"{self.connect} -e 'health'")
        lines = [
            util.remove_escape_sequence(line).strip()
            for line in cp.stdout.splitlines()
            if "Cluster UUID" in line
        ]

        self.assertEqual(lines, ["OPERATIONS:  Cluster UUID difference check."])


class CollectUsageWithoutPrivilegesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        admin_connect = start_usage_server(1)
        cls.addClassCleanup(lib.stop)
        cls.addClassCleanup(remove_outputs)
        created = util.run_asadm(
            f"{admin_connect} --enable -e "
            f"'manage acl create user {NO_ROLES_USER} password {PREFIX}'"
        )

        if f"Successfully created user {NO_ROLES_USER}" not in created.stdout:
            raise AssertionError(
                f"could not create a user:\n{created.stdout}\n{created.stderr}"
            )

        cls.connect = f"-h {lib.SERVER_IP}:{lib.PORT} -U{NO_ROLES_USER} -P{PREFIX}"
        cls.uuid = cluster_uuid(admin_connect)
        cls.collect_usage = util.run_asadm(
            f"{cls.connect} -e 'collect usage --output-prefix {PREFIX}'"
        )
        cls.show_usage = util.run_asadm(f"{cls.connect} -e 'show usage'")
        cls.collect_info = util.run_asadm(
            f"{cls.connect} -e 'collect info --output-prefix {PREFIX}info_'"
        )
        cls.bundle = util.get_collectinfo_path(cls.collect_info, f"/tmp/{PREFIX}info_")

    def test_collect_usage_writes_the_archive(self):
        self.assertEqual(self.collect_usage.returncode, 0, self.collect_usage.stderr)
        self.assertNotIn("ERROR", self.collect_usage.stderr)
        self.assertIn(f"Cluster {self.uuid}", self.collect_usage.stdout.splitlines())
        self.assertTrue(
            tarfile.is_tarfile(saved_path(self.collect_usage.stdout)),
            self.collect_usage.stdout,
        )

    def test_show_usage_reads_the_cluster(self):
        self.assertEqual(self.show_usage.returncode, 0, self.show_usage.stderr)
        self.assertNotIn("ERROR", self.show_usage.stderr)
        self.assertIn(f"Cluster {self.uuid}", self.show_usage.stdout.splitlines())

    def test_collect_info_bundle_carries_the_usage_file(self):
        members = bundle_members(self.bundle)
        meta_name = next(
            name for name in members if name.endswith("collectinfo_meta.json")
        )

        self.assertEqual(
            json.loads(members[meta_name])["collection"]["usage"]["status"], "written"
        )
        self.assertNotIn("'usage-export'", self.collect_info.stderr)


class CollectUsageMixedClusterTest(unittest.TestCase):
    """Node 1 runs the harness release without usage reporting. Node 2 runs RC1
    and has the higher node-id, so it is the principal usage-export goes to."""

    @classmethod
    def setUpClass(cls):
        template = service_template("\tnode-id ${node_id}")
        lib.stop()
        lib.start(num_nodes=1, template_content=template, mesh_over_bridge=True)
        lib.start_server(
            lib.PORT,
            2,
            docker_tag=USAGE_SERVER_TAG,
            template_content=template,
            mesh_over_bridge=True,
        )
        lib.wait_for_cluster(2)
        cls.connect = harness_connect()
        cls.builds = wait_for_builds(cls.connect, 2)
        statistics = util.run_asadm(
            f"{cls.connect} --enable -e 'asinfo -v statistics -l'"
        ).stdout
        cls.principal = re.findall(r"^cluster_principal=(\S+)$", statistics, re.M)
        cls.uuids = re.findall(r"^cluster_uuid=(\S+)$", statistics, re.M)
        cls.health = util.run_asadm(f"{cls.connect} -e 'health'")
        cls.collect_usage = util.run_asadm(
            f"{cls.connect} -e 'collect usage --output-prefix {PREFIX}'"
        )
        cls.collect_info = util.run_asadm(
            f"{cls.connect} -e 'collect info --output-prefix {PREFIX}info_'"
        )
        cls.bundle = util.get_collectinfo_path(cls.collect_info, f"/tmp/{PREFIX}info_")
        cls.server_logs = harness_server_logs()

    @classmethod
    def tearDownClass(cls):
        remove_outputs()
        lib.stop()

    def test_the_cluster_mixes_versions_under_the_newer_principal(self):
        self.assertEqual(
            sorted(
                version.LooseVersion(b) >= version.LooseVersion(FIRST_VERSION)
                for b in self.builds
            ),
            [False, True],
            self.builds,
        )
        self.assertEqual([p.upper() for p in self.principal], ["A2", "A2"])

    def test_health_does_not_compare_uuids_while_a_node_has_none(self):
        lines = [
            util.remove_escape_sequence(line).strip()
            for line in self.health.stdout.splitlines()
            if "Cluster UUID" in line
        ]

        self.assertEqual(len(self.uuids), 1, self.uuids)
        self.assertEqual(lines, [])

    def test_collect_usage_warns_and_writes_nothing(self):
        self.assertEqual(self.collect_usage.returncode, 0, self.collect_usage.stderr)
        self.assertIn(
            f"WARNING: 'collect usage' {OLDER_SERVERS}. Use 'collect info' instead.",
            self.collect_usage.stderr,
        )
        self.assertEqual(glob.glob(f"/tmp/{PREFIX}collect_usage_*"), [])

    def test_no_node_is_sent_the_usage_command(self):
        self.assertEqual(len(self.server_logs), 2)

        for log in self.server_logs:
            self.assertNotIn(UNKNOWN_USAGE_COMMAND, log)
            self.assertIsNone(re.search(r"exported \d+ days", log))

    def test_collect_info_bundle_says_why_it_has_no_usage_file(self):
        members = bundle_members(self.bundle)
        meta_name = next(
            name for name in members if name.endswith("collectinfo_meta.json")
        )

        self.assertEqual([name for name in members if name.endswith("_usage.json")], [])
        self.assertEqual(
            json.loads(members[meta_name])["collection"]["usage"],
            {"status": "unsupported", "min_version": FIRST_VERSION},
        )


class CollectUsageClusterNotFormedTest(unittest.TestCase):
    """Two nodes with min-cluster-size 2 form a cluster, then node 2 stops, so node 1
    is no longer clustered and the server refuses the export with ERROR:11."""

    NOT_FORMED = "ERROR:11:cluster not yet formed"

    @classmethod
    def setUpClass(cls):
        cls.connect = start_usage_server(2, service_template("\tmin-cluster-size 2"))
        lib.NODES[1].stop()
        cls.node = f"{lib.SERVER_IP}:{lib.PORT}"
        deadline = time.time() + 90

        reply = None

        while reply != cls.NOT_FORMED:
            if time.time() > deadline:
                raise AssertionError(f"node 1 never refused the export: {reply}")

            time.sleep(2)

            try:
                reply = usage_reply(cls.connect)
            except AssertionError as e:
                reply = str(e)

        cls.collect_usage = util.run_asadm(
            f"{cls.connect} -e 'collect usage --output-prefix {PREFIX}'"
        )
        cls.collect_info = util.run_asadm(
            f"{cls.connect} -e 'collect info --output-prefix {PREFIX}info_'"
        )
        cls.bundle = util.get_collectinfo_path(cls.collect_info, f"/tmp/{PREFIX}info_")

    @classmethod
    def tearDownClass(cls):
        remove_outputs()
        lib.stop()

    def test_collect_usage_prints_the_refusal_and_writes_nothing(self):
        self.assertEqual(self.collect_usage.returncode, 2, self.collect_usage.stderr)
        self.assertIn(
            f"ERROR: Failed to get usage from {self.node}: {self.NOT_FORMED}",
            self.collect_usage.stderr,
        )
        self.assertEqual(glob.glob(f"/tmp/{PREFIX}collect_usage_*"), [])

    def test_collect_info_records_the_refusal(self):
        members = bundle_members(self.bundle)
        meta_name = next(
            name for name in members if name.endswith("collectinfo_meta.json")
        )

        self.assertEqual(
            json.loads(members[meta_name])["collection"]["usage"],
            {"status": "failed", "node": self.node, "reply": self.NOT_FORMED},
        )

    def test_collect_info_lists_usage_export_as_a_failed_command(self):
        lines = self.collect_info.stderr.splitlines()
        heading = next(
            i
            for i, line in enumerate(lines)
            if "Following commands are either unavailable" in line
        )

        self.assertIn("'usage-export'", lines[heading + 1])

    def test_bundle_diagnostics_name_the_refusal(self):
        cp = util.run_asadm(f"-cf {self.bundle}", stdin_input="exit\n")
        output = cp.stdout + cp.stderr

        self.assertIn("The usage file was not collected", output)
        self.assertIn(f"{self.node} replied {self.NOT_FORMED}", output)


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
