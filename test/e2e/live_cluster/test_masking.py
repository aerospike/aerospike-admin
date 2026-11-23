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
"""Masking rules by AEL path (TOOLS-3973) against the 8.2.1 RC1 build, which has
AER-6982. 8.2.1 is not released yet, so the classes pin the RC1 image."""

import base64
import os
import re
import shlex
import shutil
import time
import unittest

from test.e2e import lib, util

SERVER_TAG = "8.2.1.0-64_20261123T174538Z"
OLDER_SERVER_TAG = "8.2.0.0_20260918T215052Z"
PREFIX = "asadm_test_masking_"
NS = lib.NAMESPACE
COLUMNS = ("Bin", "Type", "AEL", "Function", "Default", "Enforced")
CDT_PATHS = ("$.cards.[0]", "$.profile.address.zip", "$.m.5", '$."café".x')

RULES = (
    "redact position 0 length 4 value * default N/A namespace {ns} set demo ael '$.profile.ssn'",
    "constant value XXXX namespace {ns} set demo ael '$.cards.[0]'",
    "constant value 0 namespace {ns} set demo ael '$.profile.age' type integer",
    "constant value X namespace {ns} set demo ael '$.profile.address.zip'",
    "constant value X namespace {ns} set demo ael '$.m.5'",
    """constant value X namespace {ns} set demo ael '$."café".x'""",
    "redact position 0 length 4 value * namespace {ns} set demo bin ssn",
    "constant value 12:30 namespace {ns} set demo bin time",
    "constant value X namespace {ns} set other bin name",
)

SHOWN_IN_DEMO = sorted(
    [
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
        (
            "profile",
            "string",
            "$.profile.address.zip",
            "constant value X",
            "--",
            "True",
        ),
        ("m", "string", "$.m.5", "constant value X", "--", "True"),
        ("café", "string", '$."café".x', "constant value X", "--", "True"),
        ("ssn", "string", "--", "redact position 0 length 4 value *", "--", "True"),
        ("time", "string", "--", "constant value 12:30", "--", "True"),
    ]
)
SHOWN_IN_OTHER = [("name", "string", "--", "constant value X", "--", "True")]
SHOWN = sorted(SHOWN_IN_DEMO + SHOWN_IN_OTHER)

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


def remove_rule(set_, bin_=None, ael=None):
    target = (
        f"bin={bin_}"
        if ael is None
        else "ael_b64=" + base64.b64encode(ael.encode()).decode()
    )
    info(f"masking:namespace={NS};set={set_};{target};type=string;function=remove")


def masking_rows(args, command="show masking"):
    cp = util.run_asadm(f"{args} --json -e {shlex.quote(command)}")
    sheets = util.get_separate_output(cp.stdout)

    if not sheets:
        return cp, []

    _, _, names, values, _ = util.parse_output(sheets[0])
    rows = [dict(zip(names, row)) for row in values]

    return cp, sorted(tuple(str(row.get(c, "--")) for c in COLUMNS) for row in rows)


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
        show_before, before = masking_rows(
            self.args, f"show masking namespace {NS} set drop"
        )
        shown = [row[2] for row in before]
        drop = asadm(
            self.args,
            "manage masking drop namespace {} set drop ael '{}'".format(NS, shown[0]),
        )
        show_after, after = masking_rows(
            self.args, f"show masking namespace {NS} set drop"
        )

        self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
        self.assertEqual(show_before.returncode, 0, show_before.stderr)
        self.assertEqual(shown, ["$.p.x"])
        self.assertIn("Successfully dropped masking rule", drop.stdout, drop.stderr)
        self.assertEqual(show_after.returncode, 0, show_after.stderr)
        self.assertEqual(after, [])
        self.assertEqual(masking_rows(self.args)[1], SHOWN)

    def test_namespace_filter_does_not_count_as_a_deprecated_request(self):
        before = statistic("deprecated_requests")
        cp, rows = masking_rows(self.args, f"show masking namespace {NS} set demo")
        after = statistic("deprecated_requests")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(rows, SHOWN_IN_DEMO)
        self.assertEqual(after, before)

    def test_collectinfo_bundle_shows_the_same_rules(self):
        cp = util.run_asadm(f"{self.args} -e 'collectinfo --output-prefix {PREFIX}'")
        bundle = util.get_collectinfo_path(cp, f"/tmp/{PREFIX}")
        self.addCleanup(shutil.rmtree, bundle[: -len(".tgz")], ignore_errors=True)
        self.addCleanup(os.remove, bundle)

        show, rows = masking_rows(f"-cf {bundle}")

        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertEqual(rows, SHOWN)

    def test_drop_by_the_shown_path_round_trips_each_cdt_path(self):
        for index, path in enumerate(CDT_PATHS):
            set_ = f"trip{index}"

            with self.subTest(path=path):
                self.addCleanup(remove_rule, set_, ael=path)
                add = asadm(
                    self.args,
                    f"manage masking add constant value X namespace {NS} set {set_} ael '{path}'",
                )
                show_before, before = masking_rows(
                    self.args, f"show masking namespace {NS} set {set_}"
                )
                shown = [row[2] for row in before]

                self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
                self.assertEqual(show_before.returncode, 0, show_before.stderr)
                self.assertEqual(shown, [path])

                drop = asadm(
                    self.args,
                    f"manage masking drop namespace {NS} set {set_} ael '{shown[0]}'",
                )
                show_after, after = masking_rows(
                    self.args, f"show masking namespace {NS} set {set_}"
                )

                self.assertIn(
                    "Successfully dropped masking rule", drop.stdout, drop.stderr
                )
                self.assertEqual(show_after.returncode, 0, show_after.stderr)
                self.assertEqual(after, [])

    def test_a_name_equal_to_a_keyword_is_taken_as_the_name(self):
        for set_, bin_ in (("kw_type", "type"), ("ael", "b"), ("ael_b64", "b")):
            with self.subTest(set=set_, bin=bin_):
                self.addCleanup(remove_rule, set_, bin_)
                add = asadm(
                    self.args,
                    f"manage masking add constant value X namespace {NS} set {set_} bin {bin_}",
                )
                show, rows = masking_rows(
                    self.args, f"show masking namespace {NS} set {set_}"
                )
                drop = asadm(
                    self.args,
                    f"manage masking drop namespace {NS} set {set_} bin {bin_}",
                )
                show_after, after = masking_rows(
                    self.args, f"show masking namespace {NS} set {set_}"
                )

                self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
                self.assertEqual(show.returncode, 0, show.stderr)
                self.assertEqual(
                    rows, [(bin_, "string", "--", "constant value X", "--", "True")]
                )
                self.assertIn(
                    "Successfully dropped masking rule", drop.stdout, drop.stderr
                )
                self.assertEqual(show_after.returncode, 0, show_after.stderr)
                self.assertEqual(after, [])

    def test_a_function_value_equal_to_a_keyword_is_the_value(self):
        for set_, value in (
            ("value_ael", "ael"),
            ("value_b64", "ael_b64"),
            ("value_type", "type"),
        ):
            with self.subTest(value=value):
                self.addCleanup(remove_rule, set_, "b")
                add = asadm(
                    self.args,
                    f"manage masking add constant value {value} namespace {NS} set {set_} bin b",
                )
                show, rows = masking_rows(
                    self.args, f"show masking namespace {NS} set {set_}"
                )

                self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
                self.assertEqual(show.returncode, 0, show.stderr)
                self.assertEqual(
                    rows,
                    [("b", "string", "--", f"constant value {value}", "--", "True")],
                )

    def test_function_parameters_after_the_target_are_sent(self):
        for set_, rule, shown in (
            (
                "after_default",
                "redact namespace {ns} set {set_} bin d type string default N/A",
                ("d", "string", "--", "redact", "N/A", "True"),
            ),
            (
                "after_position",
                "redact namespace {ns} set {set_} bin p position 0",
                ("p", "string", "--", "redact position 0", "--", "True"),
            ),
        ):
            with self.subTest(rule=rule):
                self.addCleanup(remove_rule, set_, shown[0])
                add = asadm(
                    self.args,
                    "manage masking add " + rule.format(ns=NS, set_=set_),
                )
                show, rows = masking_rows(
                    self.args, f"show masking namespace {NS} set {set_}"
                )

                self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
                self.assertEqual(show.returncode, 0, show.stderr)
                self.assertEqual(rows, [shown])

    def test_drop_with_words_after_the_target_removes_the_rule(self):
        self.addCleanup(remove_rule, "drop_extra", "d")
        add = asadm(
            self.args,
            f"manage masking add constant value X namespace {NS} set drop_extra bin d",
        )
        drop = asadm(
            self.args,
            f"manage masking drop namespace {NS} set drop_extra bin d position 0",
        )
        show, rows = masking_rows(
            self.args, f"show masking namespace {NS} set drop_extra"
        )

        self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
        self.assertIn("Successfully dropped masking rule", drop.stdout, drop.stderr)
        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertEqual(rows, [])

    def test_set_filter_without_namespace_lists_only_that_set(self):
        cp, rows = masking_rows(self.args, "show masking set other")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(rows, SHOWN_IN_OTHER)

    def test_collectinfo_set_filter_without_namespace_lists_only_that_set(self):
        cp = util.run_asadm(f"{self.args} -e 'collectinfo --output-prefix {PREFIX}'")
        bundle = util.get_collectinfo_path(cp, f"/tmp/{PREFIX}")
        self.addCleanup(shutil.rmtree, bundle[: -len(".tgz")], ignore_errors=True)
        self.addCleanup(os.remove, bundle)

        show, rows = masking_rows(f"-cf {bundle}", "show masking set other")

        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertEqual(rows, SHOWN_IN_OTHER)

    def test_a_repeated_function_parameter_shows_the_first_value(self):
        self.addCleanup(remove_rule, "repeat", "p")
        add = asadm(
            self.args,
            f"manage masking add redact position 0 position 1 length 2 value * namespace {NS} set repeat bin p",
        )
        show, rows = masking_rows(self.args, f"show masking namespace {NS} set repeat")

        self.assertIn("Successfully added masking rule", add.stdout, add.stderr)
        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertEqual(
            rows,
            [("p", "string", "--", "redact position 0 length 2 value *", "--", "True")],
        )


class MaskingMixedClusterTest(unittest.TestCase):
    """Node 1 runs RC1, node 2 a release without path rules."""

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
        show, rows = masking_rows(self.args)

        self.assertIn(
            "ERROR: The 'ael' modifier requires every node at server v. 8.2.1 or later.",
            cp.stderr,
        )
        self.assertEqual(show.returncode, 0, show.stderr)
        self.assertEqual(rows, [])

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
