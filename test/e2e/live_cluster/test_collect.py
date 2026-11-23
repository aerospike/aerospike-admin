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
"""The collect command group and info summary (TOOLS-4616), with the commands they
replace still working and warning."""

import glob
import os
import shutil
import tarfile
import unittest

from test.e2e import lib, util

COLLECT_PREFIX = "asadm_collect_test_"
COLLECTINFO_PREFIX = "asadm_collectinfo_test_"


RENAMED = (
    ("collectinfo", "collect info"),
    ("collectlogs", "collect logs"),
    ("summary", "info summary"),
)


def deprecation(command, replacement):
    return (
        f"'{command}' is deprecated and will be removed in a future release. "
        f"Use '{replacement}' instead."
    )


def rename_warnings(text):
    return [
        deprecation(command, replacement)
        for command, replacement in RENAMED
        if deprecation(command, replacement) in text
    ]


def run(commands, *flags):
    return util.run_asadm(
        f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin {' '.join(flags)} "
        f"-e '{commands}'"
    )


def without_volatile_lines(stdout):
    return [line for line in stdout.splitlines() if "License Usage" not in line]


class CollectTests(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        lib.start()

        cls.collect_cp = run(f"collect --output-prefix {COLLECT_PREFIX}")
        cls.collectinfo_cp = run(f"collectinfo --output-prefix {COLLECTINFO_PREFIX}")

    @classmethod
    def tearDownClass(cls):
        for prefix in (COLLECT_PREFIX, COLLECTINFO_PREFIX):
            for path in glob.glob(f"/tmp/{prefix}*"):
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)

        lib.stop()

    def bundle_names(self, cp, prefix):
        with tarfile.open(util.get_collectinfo_path(cp, "/tmp/" + prefix)) as tar:
            names = [os.path.basename(m.name) for m in tar.getmembers() if m.isfile()]

        return [name for name in names if not name.startswith("._")]

    def bundle_file(self, cp, prefix, suffix):
        with tarfile.open(util.get_collectinfo_path(cp, "/tmp/" + prefix)) as tar:
            for member in tar.getmembers():
                name = os.path.basename(member.name)

                if name.endswith(suffix) and not name.startswith("._"):
                    return tar.extractfile(member).read().decode()

        self.fail(f"no {suffix} in the bundle")

    def test_collect_writes_a_bundle_without_warning(self):
        self.assertEqual(self.collect_cp.returncode, 0, self.collect_cp.stderr)
        self.assertEqual(rename_warnings(self.collect_cp.stderr), [])

        names = self.bundle_names(self.collect_cp, COLLECT_PREFIX)

        for suffix in ("_ascinfo.json", "_summary.log", "_health.log"):
            self.assertTrue(any(n.endswith(suffix) for n in names), names)

    def test_collect_bundle_summary_log_comes_from_info_summary(self):
        summary_log = self.bundle_file(self.collect_cp, COLLECT_PREFIX, "_summary.log")

        self.assertIn("info summary", summary_log)
        self.assertEqual(rename_warnings(summary_log), [])

    def test_collectinfo_still_writes_the_same_bundle_and_warns(self):
        self.assertEqual(self.collectinfo_cp.returncode, 0, self.collectinfo_cp.stderr)
        self.assertIn(
            deprecation("collectinfo", "collect info"), self.collectinfo_cp.stderr
        )

        def kinds(names):
            return sorted(name.split("_", 2)[-1] for name in names)

        self.assertEqual(
            kinds(self.bundle_names(self.collectinfo_cp, COLLECTINFO_PREFIX)),
            kinds(self.bundle_names(self.collect_cp, COLLECT_PREFIX)),
        )

    def test_collect_info_writes_a_bundle(self):
        prefix = COLLECT_PREFIX + "info_"
        cp = run(f"collect info --output-prefix {prefix}")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertEqual(rename_warnings(cp.stderr), [])
        self.assertTrue(
            any(n.endswith("_ascinfo.json") for n in self.bundle_names(cp, prefix))
        )

    def test_collect_does_not_warn_about_the_health_check_it_runs_itself(self):
        self.assertNotIn("The 'health' command is deprecated", self.collect_cp.stderr)

    def test_collect_logs_runs_the_log_collection_without_warning(self):
        cp = run(f"collect logs --output-prefix {COLLECT_PREFIX}logs_")

        self.assertIn("Collecting logs from nodes", cp.stderr)
        self.assertEqual(rename_warnings(cp.stderr), [])

    def test_collectlogs_still_runs_and_warns(self):
        cp = run(f"collectlogs --output-prefix {COLLECTINFO_PREFIX}logs_")

        self.assertIn("Collecting logs from nodes", cp.stderr)
        self.assertIn(deprecation("collectlogs", "collect logs"), cp.stderr)

    def test_info_summary_prints_what_summary_printed(self):
        new = run("info summary")
        old = run("summary")

        self.assertEqual(new.returncode, 0, new.stderr)
        self.assertEqual(old.returncode, 0, old.stderr)
        self.assertEqual(rename_warnings(new.stderr), [])
        self.assertIn(deprecation("summary", "info summary"), old.stderr)
        self.assertEqual(
            without_volatile_lines(new.stdout), without_volatile_lines(old.stdout)
        )

    def test_info_summary_in_collectinfo_mode(self):
        bundle = util.get_collectinfo_path(
            self.collectinfo_cp, "/tmp/" + COLLECTINFO_PREFIX
        )

        new = util.run_asadm(f"-cf {bundle} -e 'info summary'")
        old = util.run_asadm(f"-cf {bundle} -e 'summary'")

        self.assertEqual(new.returncode, 0, new.stderr)
        self.assertEqual(rename_warnings(new.stderr), [])
        self.assertIn(deprecation("summary", "info summary"), old.stderr)
        self.assertEqual(new.stdout, old.stdout)

    def test_help_lists_collect_and_marks_the_old_commands(self):
        cp = run("help")
        lines = [util.remove_escape_sequence(line) for line in cp.stdout.splitlines()]

        def listed(command):
            for line in lines:
                if line.split()[:1] == [command]:
                    return line

            self.fail(f"'{command}' not in help:\n{cp.stdout}")

        self.assertNotIn("deprecated", listed("collect"))

        for command, replacement in (
            ("collectinfo", "collect info"),
            ("collectlogs", "collect logs"),
            ("summary", "info summary"),
        ):
            self.assertTrue(
                listed(command).endswith(f"(deprecated, use '{replacement}')")
            )
