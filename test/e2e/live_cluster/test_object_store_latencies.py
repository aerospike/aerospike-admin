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
import shutil
import time
import unittest

from test.e2e import lib, util as test_util

SERVER_TAG = "8.2.1.0-45_20261112T051802Z"
PREVIEW = ["backup-restore"]
OPS = ("put", "get", "list", "delete")
BACKUP_PATH = "/opt/aerospike/backup-e2e"


def object_store_template():
    """
    Microsecond histograms put the client tables in us while the object-store ones
    stay in ms. A short ticker gets the histograms past their baseline dump quickly.
    """
    with open(lib.absolute_path("aerospike_latest.conf")) as f:
        content = f.read()

    marker = "\tproto-fd-max 1024\n"

    if marker not in content:
        raise AssertionError("service stanza anchor missing from the template")

    return content.replace(
        marker, marker + "\tticker-interval 2\n\tmicrosecond-histograms true\n"
    )


def info(cmd):
    return "".join(response[1] or "" for response in lib.CLIENT.info_all(cmd).values())


def wait_for(predicate, what, timeout=90):
    deadline = time.time() + timeout

    while time.time() < deadline:
        if predicate():
            return

        time.sleep(1)

    raise AssertionError("timed out after {}s waiting for {}".format(timeout, what))


def assert_clean_run(tc, cp):
    tc.assertEqual(cp.returncode, 0, cp.stderr)
    tc.assertNotIn("ERROR", cp.stderr)
    tc.assertNotIn("Traceback", cp.stderr)
    tc.assertNotIn("bad hist name", cp.stdout + cp.stderr)


def latency_records(args):
    cp = test_util.run_asadm(args + " --no-config-file --json")
    out = test_util.get_separate_output(cp.stdout)

    if not out:
        raise AssertionError("no sheet in output:\n{}\n{}".format(cp.stdout, cp.stderr))

    _, _, names, values, _ = test_util.parse_output(out[0])

    return cp, [dict(zip(names, row)) for row in values]


def by_histogram(records):
    return {
        record["Histogram"]: record
        for record in records
        if record["Namespace"] == lib.NAMESPACE
    }


class TestObjectStoreLatencies(unittest.TestCase):
    """
    TOOLS-4583. The {ns}-object-store-* histograms (SERVER-698) need
    --preview backup-restore, which no release image has yet, so this class pins a
    server master build. Security is off since the e2e admin user lacks backup-admin.
    """

    @classmethod
    def setUpClass(cls):
        lib.stop()
        lib.start(
            num_nodes=1,
            docker_tag=SERVER_TAG,
            template_content=object_store_template(),
            preview_features=PREVIEW,
            enable_security=False,
        )
        lib.populate_db("object-store-latencies")

        info(
            "backup:namespace={};job-id=1;object-storage-type=fs;path={}".format(
                lib.NAMESPACE, BACKUP_PATH
            )
        )
        wait_for(
            lambda: "state=COMPLETE" in info("backup-status:job-id=1"),
            "the backup to complete",
        )
        wait_for(
            lambda: all(
                "msec,"
                in info("latencies:hist={%s}-object-store-%s" % (lib.NAMESPACE, op))
                for op in OPS
            ),
            "the object-store histograms to report",
        )
        wait_for(
            lambda: "{%s}-write:usec," % lib.NAMESPACE in info("latencies:"),
            "the write histogram to report",
        )

        cls.args = "-h {}:{}".format(lib.SERVER_IP, lib.PORT)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def assert_object_store_in_ms(self, records):
        hists = by_histogram(records)

        for op in OPS:
            record = hists["object-store-" + op]

            self.assertNotEqual(record[">1ms"], "--", record)
            self.assertEqual(record[">1us"], "--", record)

        self.assertNotEqual(hists["write"][">1us"], "--", hists["write"])
        self.assertEqual(hists["write"][">1ms"], "--", hists["write"])

    def test_show_latencies_verbose_labels_object_store_in_ms(self):
        cp, records = latency_records(self.args + " -e 'show latencies -v'")

        assert_clean_run(self, cp)
        self.assert_object_store_in_ms(records)

    def test_show_latencies_default_omits_object_store(self):
        _, records = latency_records(self.args + " -e 'show latencies'")

        self.assertFalse(
            [r for r in records if r["Histogram"].startswith("object-store-")]
        )

    def test_collectinfo_carries_object_store_latencies(self):
        cp = test_util.run_asadm(
            self.args
            + " --no-config-file -e 'collectinfo --output-prefix asadm_test_object_store_'"
        )
        bundle = test_util.get_collectinfo_path(cp, "/tmp/asadm_test_object_store_")
        self.addCleanup(shutil.rmtree, bundle[: -len(".tgz")], ignore_errors=True)
        self.addCleanup(os.remove, bundle)

        self.assertNotIn("bad hist name", cp.stdout + cp.stderr)

        _, records = latency_records("-cf {} -e 'show latencies'".format(bundle))

        self.assert_object_store_in_ms(records)


class TestObjectStoreLatenciesWithoutPreview(unittest.TestCase):
    """Without --preview backup-restore the server answers bad hist name."""

    @classmethod
    def setUpClass(cls):
        lib.stop()
        lib.start(num_nodes=1, docker_tag=SERVER_TAG)
        cls.args = "-h {}:{} -Uadmin -Padmin".format(lib.SERVER_IP, lib.PORT)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def test_server_refuses_the_histograms(self):
        with self.assertRaisesRegex(Exception, "bad hist name"):
            info("latencies:hist={%s}-object-store-put" % lib.NAMESPACE)

    def test_show_latencies_verbose_is_unaffected(self):
        cp = test_util.run_asadm(
            self.args + " --no-config-file -e 'show latencies -v' --json"
        )

        assert_clean_run(self, cp)
        self.assertNotIn("object-store", cp.stdout)
