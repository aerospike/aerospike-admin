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
"""End-to-end coverage for collectinfo provenance and analyzer diagnostics (TOOLS-4135).

Collects a real bundle from a real cluster, then asserts on what the bundle records
about its own collection and on what the analyzer says when reading it back. The
mutation tests rewrite a copy of the extracted bundle so the older-collector and
dropped-node paths can be exercised without a broken cluster.
"""

import json
import os
import shutil
import tarfile
import tempfile
import unittest

from lib.utils import constants
from test.e2e import lib, util

COLLECTINFO_PREFIX = "asadm_diag_test_"
META_SUFFIX = constants.COLLECTINFO_META_FILENAME


class TestCollectinfoDiagnostics(unittest.TestCase):
    maxDiff = None

    @classmethod
    def setUpClass(cls):
        lib.start()

        cls.asadm_version = cls._get_asadm_version()

        collect_cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin --timeout 20 "
            f"-e 'collectinfo --output-prefix {COLLECTINFO_PREFIX}'"
        )
        cls.bundle_tgz = util.get_collectinfo_path(
            collect_cp, "/tmp/" + COLLECTINFO_PREFIX
        )
        cls.extract_dir = tempfile.mkdtemp(prefix="asadm_diag_extract_")

        with tarfile.open(cls.bundle_tgz) as tar:
            tar.extractall(path=cls.extract_dir)

        cls.bundle_dir = cls._find_bundle_dir(cls.extract_dir)
        cls.meta_path = cls._find_file(cls.bundle_dir, META_SUFFIX)

        with open(cls.meta_path) as meta_file:
            cls.meta = json.load(meta_file)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.extract_dir, ignore_errors=True)
        lib.stop()

    @classmethod
    def _get_asadm_version(cls):
        version_cp = util.run_asadm("--version")

        for line in version_cp.stdout.splitlines():
            if line.startswith("Version "):
                return line.split(maxsplit=1)[1].strip()

        raise Exception("Could not determine asadm version:\n" + version_cp.stdout)

    @classmethod
    def _bundle_files(cls, directory):
        """Bundle files, minus the AppleDouble forks macOS tar writes alongside them."""
        return sorted(
            name for name in os.listdir(directory) if not name.startswith("._")
        )

    @classmethod
    def _find_bundle_dir(cls, root):
        for dirpath, _, _ in os.walk(root):
            if any(
                name.endswith("ascinfo.json") for name in cls._bundle_files(dirpath)
            ):
                return dirpath

        raise Exception("Extracted bundle has no ascinfo.json under " + root)

    @classmethod
    def _find_file(cls, directory, suffix):
        names = cls._bundle_files(directory)

        for name in names:
            if name.endswith(suffix):
                return os.path.join(directory, name)

        raise Exception("No file ending in %s in %s: %s" % (suffix, directory, names))

    def _snapshot_meta(self):
        snapshots = self.meta["snapshots"]
        self.assertEqual(len(snapshots), 1, snapshots)
        return snapshots[0]

    def _ascinfo(self):
        with open(self._find_file(self.bundle_dir, "ascinfo.json")) as ascinfo_file:
            return json.load(ascinfo_file)

    def _ascinfo_node_keys(self):
        ascinfo = self._ascinfo()
        timestamp = sorted(ascinfo)[-1]
        node_keys = []

        for cluster_data in ascinfo[timestamp].values():
            node_keys.extend(cluster_data)

        return node_keys

    def _mutated_ascinfo_bundle(self, mutate_node):
        """A copy of the bundle with every node's namespace statistics rewritten."""
        target = tempfile.mkdtemp(prefix="asadm_diag_ascinfo_")
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        bundle_copy = os.path.join(target, os.path.basename(self.bundle_dir))
        shutil.copytree(self.bundle_dir, bundle_copy)

        ascinfo_path = self._find_file(bundle_copy, "ascinfo.json")

        with open(ascinfo_path) as ascinfo_file:
            ascinfo = json.load(ascinfo_file)

        for cluster_data in ascinfo[sorted(ascinfo)[-1]].values():
            for node_data in cluster_data.values():
                mutate_node(node_data)

        with open(ascinfo_path, "w") as ascinfo_file:
            json.dump(ascinfo, ascinfo_file)

        return bundle_copy

    def _mutated_bundle(self, mutate_meta):
        """A copy of the extracted bundle whose meta has been rewritten."""
        target = tempfile.mkdtemp(prefix="asadm_diag_mutated_")
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        bundle_copy = os.path.join(target, os.path.basename(self.bundle_dir))
        shutil.copytree(self.bundle_dir, bundle_copy)

        meta_path = self._find_file(bundle_copy, META_SUFFIX)

        with open(meta_path) as meta_file:
            meta = json.load(meta_file)

        result = mutate_meta(meta)

        if result is None:
            with open(meta_path, "w") as meta_file:
                json.dump(meta, meta_file)
        elif result == "delete":
            os.remove(meta_path)

        return bundle_copy

    ###########################################################################
    # What the bundle records about its own collection.

    def test_meta_file_is_written(self):
        self.assertTrue(os.path.isfile(self.meta_path), self.meta_path)
        self.assertEqual(self.meta["meta_format_version"], 1)

    def test_bundle_records_collector_version(self):
        bundle = self.meta["bundle"]

        self.assertEqual(bundle["asadm_version"], self.asadm_version)
        self.assertEqual(bundle["generated_by"], "asadm collectinfo")
        self.assertNotIn("ascinfo_schema", bundle)

    def test_collection_records_host_flags_and_seeds(self):
        collection = self.meta["collection"]

        self.assertTrue(collection["host"])
        self.assertTrue(collection["start_ts_utc"])
        self.assertTrue(collection["end_ts_utc"])
        self.assertEqual(collection["snapshot_count"], 1)

        flags = collection["flags"]
        self.assertEqual(flags["enable_ssh"], False)
        self.assertEqual(flags["ignore_errors"], False)
        self.assertGreaterEqual(flags["effective_node_timeout_sec"], 5)
        self.assertEqual(flags["output_prefix"], COLLECTINFO_PREFIX)

        seeds = collection["seeds"]
        self.assertTrue(seeds)
        self.assertEqual(seeds[0]["port"], lib.PORT)

    def test_expected_nodes_match_the_dump_and_all_responded(self):
        snapshot = self._snapshot_meta()

        self.assertEqual(
            sorted(snapshot["expected_nodes"]), sorted(self._ascinfo_node_keys())
        )
        self.assertEqual(
            sorted(snapshot["responded_nodes"]), sorted(snapshot["expected_nodes"])
        )
        self.assertEqual(snapshot["no_data_nodes"], [])
        self.assertTrue(snapshot["cluster_name"])
        self.assertTrue(snapshot["timestamp"])

    def test_snapshot_timestamp_matches_ascinfo(self):
        ascinfo = self._ascinfo()

        self.assertIn(self._snapshot_meta()["timestamp"], ascinfo)

    def test_per_node_meta_is_complete(self):
        """A healthy collection records no failures.

        Entries classed as unsupported are allowed: masking-show and user-agents do
        not exist on every server the analyzer supports, and ACL calls are rejected
        outright when security is off. Those are absent sections, not lost data, and
        are kept in the meta for debugging.
        """
        snapshot = self._snapshot_meta()

        self.assertEqual(sorted(snapshot["nodes"]), sorted(snapshot["expected_nodes"]))

        for node_key, node_meta in snapshot["nodes"].items():
            self.assertTrue(node_meta["node_id"], node_key)
            self.assertTrue(node_meta["responded"], node_key)
            self.assertIn(
                node_meta["sysinfo_source"],
                (
                    constants.SysinfoSource.LOCAL,
                    constants.SysinfoSource.SSH,
                    constants.SysinfoSource.NONE,
                ),
            )

            failures = [
                error
                for error in node_meta["errors"]
                if error["error_class"] != constants.CollectinfoErrorClass.UNSUPPORTED
            ]
            self.assertEqual(failures, [], node_key)

    def test_collection_records_the_node_selection(self):
        self.assertEqual(
            self.meta["collection"]["flags"]["node_selection"],
            constants.NodeSelection.ALL,
        )

    def test_healthy_collection_reports_no_discrepancies(self):
        discrepancies = self._snapshot_meta()["discrepancies"]

        self.assertNotIn("detection_error", discrepancies)
        self.assertEqual(discrepancies["dropped_during_collection"], [])
        self.assertEqual(discrepancies["missing_from_collection"], [])

    def test_ascollectinfo_log_still_records_the_version(self):
        """The log scan is the analyzer's fallback for bundles with no meta file."""
        log_path = self._find_file(self.bundle_dir, "ascollectinfo.log")

        with open(log_path, errors="ignore") as log_file:
            head = log_file.read(65536)

        self.assertIn("asadm version " + self.asadm_version, head)

    ###########################################################################
    # What the analyzer says when it reads the bundle back.

    def test_meta_file_does_not_break_analysis_of_the_tgz(self):
        """A released asadm ignores collectinfo_meta.json; so must this one."""
        cp = util.run_asadm(f"-cf {self.bundle_tgz} -e 'info network'")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertNotIn("Multiple snapshots", cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    ENVIRONMENTAL_BANNER_WARNINGS = (
        "No system information in this bundle",
        "Bundle has no sysinfo.log or aerospike.conf",
        "violating Aerospike best-practices",
    )
    """Findings that describe where this test runs, not a defect in collection.

    asadm collects from the test host while the server runs elsewhere, so no
    host-level data is captured and neither host file is written. The server
    also reports the CI machine's kernel tuning - swappiness, thp-enabled,
    rmem-max and friends - as violated best practices, which is a property of
    the runner rather than of anything this suite controls.

    Kept as an explicit list: anything else in the banner is a regression, and a
    new environmental finding belongs here deliberately rather than as a looser
    check."""

    def _unexpected_banner_lines(self, stderr):
        return [
            line
            for line in stderr.splitlines()
            if ("WARNING:" in line or "ERROR:" in line)
            and not any(
                allowed in line for allowed in self.ENVIRONMENTAL_BANNER_WARNINGS
            )
        ]

    def test_healthy_bundle_emits_no_integrity_warnings(self):
        """Asserted positively: the command must succeed, print its own output,
        and leave no unexplained warning behind. A list of assertNotIn strings
        only catches the wordings someone thought to list, and passes for free
        when a finding is reworded or never fires at all."""
        cp = util.run_asadm(f"-cf {self.bundle_dir} -e 'info network'")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)
        self.assertEqual(self._unexpected_banner_lines(cp.stderr), [], cp.stderr)

    def test_the_healthy_bundle_guard_fires_on_a_broken_bundle(self):
        """Without this the guard above passes for a bundle that emits nothing at
        all, including one where diagnostics silently stopped running."""

        def break_the_namespaces(node_data):
            namespaces = (
                node_data.get("as_stat", {}).get("statistics", {}).get("namespace")
                or {}
            )

            for ns_data in namespaces.values():
                ns_data["service"]["stop_writes"] = "true"

        bundle = self._mutated_ascinfo_bundle(break_the_namespaces)

        cp = util.run_asadm(f"-cf {bundle} -e 'info network'")

        self.assertNotEqual(self._unexpected_banner_lines(cp.stderr), [], cp.stderr)

    def test_execute_mode_states_the_collector_version(self):
        """The provenance line is the point of the whole check, and execute mode
        prints no intro to carry it."""
        cp = util.run_asadm(f"-cf {self.bundle_dir} -e 'info network'")

        self.assertIn("Collected by asadm", cp.stderr)

    def test_an_unhealthy_cluster_does_not_fail_the_command(self):
        """Diagnostics describe the collected cluster, not the command the user ran:
        a script must not read a successful analysis as a tool failure."""

        def break_the_namespaces(node_data):
            namespaces = (
                node_data.get("as_stat", {}).get("statistics", {}).get("namespace")
                or {}
            )

            for ns_data in namespaces.values():
                ns_data["service"]["stop_writes"] = "true"
                ns_data["service"]["dead_partitions"] = "7"

        bundle = self._mutated_ascinfo_bundle(break_the_namespaces)

        cp = util.run_asadm(f"-cf {bundle} -e 'info network'")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("stop-writes", cp.stderr)
        self.assertIn("dead", cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def _comparable_version(self):
        """A development build has no numeric version to compare against, so the
        analyzer reports the collector version with no verdict; a release build
        must state the verdict. Each build type asserts its own specific outcome."""
        return self.asadm_version[:1].isdigit()

    def _assert_version_reported(self, bundle, collector_version, verdict):
        cp = util.run_asadm(f"-cf {bundle} -e 'info network'")

        if self._comparable_version():
            self.assertIn(verdict, cp.stderr)
        else:
            self.assertIn("Collected by asadm " + collector_version, cp.stderr)
            self.assertNotIn(verdict, cp.stderr)

        self.assertIn(collector_version, cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_older_collector_version_is_reported(self):
        def make_older(meta):
            meta["bundle"]["asadm_version"] = "1.0.0"

        self._assert_version_reported(
            self._mutated_bundle(make_older), "1.0.0", "older than this asadm"
        )

    def test_newer_collector_version_is_reported(self):
        def make_newer(meta):
            meta["bundle"]["asadm_version"] = "999.0.0"

        self._assert_version_reported(
            self._mutated_bundle(make_newer), "999.0.0", "newer than this asadm"
        )

    def test_dropped_node_recorded_in_meta_is_reported(self):
        def drop_a_node(meta):
            snapshot = meta["snapshots"][0]
            dropped = snapshot["expected_nodes"][0]
            snapshot["responded_nodes"] = [
                node for node in snapshot["responded_nodes"] if node != dropped
            ]
            snapshot["no_data_nodes"] = [dropped]
            snapshot["discrepancies"]["dropped_during_collection"] = [
                {"node_key": dropped, "error_class": "timeout"}
            ]

        dropped_node = self._snapshot_meta()["expected_nodes"][0]
        bundle = self._mutated_bundle(drop_a_node)

        cp = util.run_asadm(f"-cf {bundle} -e 'info network'")

        self.assertIn("missing from this bundle", cp.stderr)
        self.assertIn(dropped_node, cp.stderr)
        self.assertIn("timed out", cp.stderr)

    def test_per_node_collection_error_is_reported(self):
        def add_an_error(meta):
            snapshot = meta["snapshots"][0]
            node_key = snapshot["expected_nodes"][0]
            snapshot["nodes"][node_key]["errors"] = [
                {
                    "section": "latency",
                    "error_class": "timeout",
                    "message": "info call timed out",
                    "recovered_on_retry": False,
                }
            ]

        node_key = self._snapshot_meta()["expected_nodes"][0]
        bundle = self._mutated_bundle(add_an_error)

        cp = util.run_asadm(f"-cf {bundle} -e 'info network'")

        self.assertIn("Collection failed for some sections", cp.stderr)
        self.assertIn(node_key, cp.stderr)
        self.assertIn("latency", cp.stderr)

    def test_detection_error_in_meta_is_reported(self):
        def break_detection(meta):
            meta["snapshots"][0]["discrepancies"] = {
                "detection_error": "no route to host"
            }

        bundle = self._mutated_bundle(break_detection)

        cp = util.run_asadm(f"-cf {bundle} -e 'info network'")

        self.assertIn("did not complete during collection", cp.stderr)
        self.assertIn("no route to host", cp.stderr)

    def test_bundle_without_meta_falls_back_to_the_log_scan(self):
        bundle = self._mutated_bundle(lambda meta: "delete")

        for suffix in ("ascollectinfo.log", "summary.log"):
            log_path = self._find_file(bundle, suffix)

            with open(log_path, errors="ignore") as log_file:
                contents = log_file.read()

            with open(log_path, "w") as log_file:
                log_file.write(
                    contents.replace(
                        "asadm version " + self.asadm_version, "asadm version 1.0.0"
                    )
                )

        self._assert_version_reported(bundle, "1.0.0", "older than this asadm")

    def test_bundle_with_no_version_anywhere_is_reported_as_unknown(self):
        bundle = self._mutated_bundle(lambda meta: "delete")

        for suffix in ("ascollectinfo.log", "summary.log"):
            os.remove(self._find_file(bundle, suffix))

        cp = util.run_asadm(f"-cf {bundle} -e 'info network'")

        self.assertIn("Collected by an unknown asadm version", cp.stderr)
        self.assertIn("much older asadm", cp.stderr)
        self.assertIn("Network Information", cp.stdout)

    def test_analyzer_still_works_when_meta_is_corrupt(self):
        bundle = self._mutated_bundle(lambda meta: "delete")
        with open(os.path.join(bundle, "20000101_000000_" + META_SUFFIX), "w") as f:
            f.write("{not json")

        cp = util.run_asadm(f"-cf {bundle} -e 'info network'")

        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information", cp.stdout)


if __name__ == "__main__":
    unittest.main()
