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
"""Masking rules by AEL path (TOOLS-3973) against a server master build with
AER-6982. No release image has it yet, so the classes pin a nightly."""

import os
import re
import shlex
import shutil
import time
import unittest

from test.e2e import lib, util

SERVER_TAG = "8.2.1.0-63_20261123T052208Z"
OLDER_SERVER_TAG = "8.2.0.0_20260918T215052Z"
PREFIX = "asadm_test_masking_"
NS = lib.NAMESPACE
COLUMNS = ("Bin", "Type", "AEL", "Function", "Default", "Enforced")

RULES = (
    "redact position 0 length 4 value * default N/A namespace {ns} set demo ael '$.profile.ssn'",
    "constant value XXXX namespace {ns} set demo ael '$.cards.[0]'",
    "constant value 0 namespace {ns} set demo ael '$.profile.age' type integer",
    "redact position 0 length 4 value * namespace {ns} set demo bin ssn",
    "constant value 12:30 namespace {ns} set demo bin time",
)

SHOWN = {
    ("cards", "string", "$.cards.[0]", "constant value XXXX", "--", "True"),
    ("profile", "integer", "$.profile.age", "constant value 0", "--", "True"),
    (
        "profile",
        "string",
        "$.profile.ssn",
        "redact position 0 length 4 value *",
        "N/A",
        "True",
    ),
    ("ssn", "string", "--", "redact position 0 length 4 value *", "--", "True"),
    ("time", "string", "--", "constant value 12:30", "--", "True"),
}

REFUSED = (
    (
        "constant value x namespace {ns} set demo ael '$.a.[-1]'",
        "bad path, negative list index - spell the index from the front",
    ),
    (
        "constant value x namespace {ns} set demo ael '$.accounts.*.card'",
        "bad path, at offset 0: unresolved bin type, use $.bin:LIST or $.bin:MAP",
    ),
    (
        "redact namespace {ns} set demo ael '$.p.ssn'",
        "a path rule with function 'redact' needs 'default' - the value returned for a leaf of another type",
    ),
    (
        """constant value x namespace {ns} set demo ael '$."a;b".x'""",
        "bin name contains '|' or ';', which a masking rule can't store",
    ),
    (
        "constant value x namespace {ns} set demo ael_b64 not-base64",
        "'ael_b64' is not valid base64",
    ),
)


def asadm(args, command):
    return util.run_asadm(f"{args} --enable -e {shlex.quote(command)}")


def info(cmd):
    return "".join(response[1] or "" for response in lib.CLIENT.info_all(cmd).values())


def statistic(name):
    return int(re.search(rf"(?:^|;){name}=(\d+)", info("statistics")).group(1))


def masking_rows(args, command="show masking"):
    cp = util.run_asadm(f"{args} --json -e {shlex.quote(command)}")
    sheets = util.get_separate_output(cp.stdout)

    if not sheets:
        return cp, set()

    _, _, names, values, _ = util.parse_output(sheets[0])
    rows = [dict(zip(names, row)) for row in values]

    return cp, {tuple(str(row.get(c, "--")) for c in COLUMNS) for row in rows}


def wait_for_builds(args, count, timeout=90):
    deadline = time.time() + timeout
    cp = None

    while time.time() < deadline:
        cp = asadm(args, "asinfo -v build")
        builds = re.findall(r"^\d+\.\d+\.\d+\.\d+\S*$", cp.stdout, re.M)

        if len(builds) == count and "Offline" not in cp.stderr:
            return builds

        time.sleep(2)

    raise AssertionError(f"asadm never read {count} builds:\n{cp.stdout}\n{cp.stderr}")


class MaskingRulesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lib.stop()
        lib.start(num_nodes=1, docker_tag=SERVER_TAG)
        lib.CLIENT.admin_grant_roles("admin", ["masking-admin"])
        cls.args = f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin --no-config-file"
        cls.added = [
            asadm(cls.args, "manage masking add " + rule.format(ns=NS))
            for rule in RULES
        ]
        cls.refused = [
            (asadm(cls.args, "manage masking add " + rule.format(ns=NS)), message)
            for rule, message in REFUSED
        ]
        cls.show, cls.rows = masking_rows(cls.args)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def test_each_rule_is_added(self):
        for cp in self.added:
            self.assertIn("Successfully added masking rule", cp.stdout, cp.stderr)
            self.assertNotIn("ERROR", cp.stderr)

    def test_show_masking_lists_each_rule_once_in_its_columns(self):
        self.assertEqual(self.show.returncode, 0, self.show.stderr)
        self.assertEqual(self.rows, SHOWN)

    def test_server_refusals_print_in_full(self):
        for cp, message in self.refused:
            with self.subTest(message=message):
                self.assertIn(
                    f"ERROR: Failed to add masking rule : {message}.", cp.stderr
                )

    def test_drop_by_the_shown_path_removes_only_that_rule(self):
        add = asadm(
            self.args,
            "manage masking add constant value X namespace {} set drop ael '$.p.x'".format(
                NS
            ),
        )
        _, before = masking_rows(self.args, f"show masking namespace {NS} set drop")
        shown = [row[2] for row in before]
        drop = asadm(
            self.args,
            "manage masking drop namespace {} set drop ael '{}'".format(NS, shown[0]),
        )
        _, after = masking_rows(self.args, f"show masking namespace {NS} set drop")

        self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
        self.assertEqual(shown, ["$.p.x"])
        self.assertIn("Successfully dropped masking rule", drop.stdout, drop.stderr)
        self.assertEqual(after, set())
        self.assertEqual(masking_rows(self.args)[1], SHOWN)

    def test_namespace_filter_does_not_count_as_a_deprecated_request(self):
        before = statistic("deprecated_requests")
        cp, rows = masking_rows(self.args, f"show masking namespace {NS} set demo")
        after = statistic("deprecated_requests")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(rows, SHOWN)
        self.assertEqual(after, before)

    def test_collectinfo_bundle_shows_the_same_rules(self):
        cp = util.run_asadm(f"{self.args} -e 'collectinfo --output-prefix {PREFIX}'")
        bundle = util.get_collectinfo_path(cp, f"/tmp/{PREFIX}")
        self.addCleanup(shutil.rmtree, bundle[: -len(".tgz")], ignore_errors=True)
        self.addCleanup(os.remove, bundle)

        show, rows = masking_rows(f"-cf {bundle}")

        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertEqual(rows, SHOWN)


class MaskingMixedClusterTest(unittest.TestCase):
    """Node 1 runs the nightly, node 2 a release without path rules."""

    @classmethod
    def setUpClass(cls):
        lib.stop()
        lib.start(num_nodes=1, docker_tag=SERVER_TAG, mesh_over_bridge=True)
        lib.start_server(
            lib.PORT, 2, docker_tag=OLDER_SERVER_TAG, mesh_over_bridge=True
        )
        lib.wait_for_cluster(2)
        lib.CLIENT.admin_grant_roles("admin", ["masking-admin"])
        cls.args = f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin --no-config-file"
        cls.builds = wait_for_builds(cls.args, 2)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def test_add_by_path_is_refused_before_sending(self):
        cp = asadm(
            self.args,
            "manage masking add constant value X namespace {} set mixed ael '$.p.x'".format(
                NS
            ),
        )

        self.assertIn(
            "ERROR: The 'ael' modifier requires every node at server v. 8.2.1 or later.",
            cp.stderr,
        )
        self.assertEqual(masking_rows(self.args)[1], set())

    def test_whole_bin_add_is_not_gated(self):
        add = asadm(
            self.args,
            "manage masking add constant value X namespace {} set mixed bin b".format(
                NS
            ),
        )
        drop = asadm(
            self.args, "manage masking drop namespace {} set mixed bin b".format(NS)
        )

        self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
        self.assertIn("Successfully dropped masking rule", drop.stdout, drop.stderr)
