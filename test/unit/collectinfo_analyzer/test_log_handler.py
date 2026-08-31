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

import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from mock import MagicMock, patch

# lib.utils.logger installs BaseLogger via logging.setLoggerClass, so it must be
# imported before any collectinfo module creates its module-level logger (asadm.py
# imports in this order); otherwise the exit-code regression test below is vacuous.
from lib.utils import log_util, logger

from lib.collectinfo_analyzer.collectinfo_handler.collectinfo_diagnostics import (
    BundleWarning,
    CollectinfoDiagnostics,
    DiagSeverity,
)
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
    LogHandlerException,
)


class LogUtilTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch("platform.system")
    def test_get_all_files_on_darwin(self, mock_system):
        # Simulate macOS platform
        mock_system.return_value = "Darwin"

        # Create test files
        regular_file = os.path.join(self.temp_dir, "test.log")
        resource_fork_file = os.path.join(self.temp_dir, "._test.log")

        with open(regular_file, "w") as f:
            f.write("log content")
        with open(resource_fork_file, "w") as f:
            f.write("resource fork content")

        # Test get_all_files method
        files = log_util.get_all_files(self.temp_dir)

        # Assert resource fork file is excluded on Darwin
        self.assertIn("test.log", [os.path.basename(f) for f in files])
        self.assertNotIn("._test.log", [os.path.basename(f) for f in files])

    @patch("platform.system")
    def test_get_all_files_on_linux(self, mock_system):
        # Simulate Linux platform
        mock_system.return_value = "Linux"

        # Create test files
        regular_file = os.path.join(self.temp_dir, "test.log")
        resource_fork_file = os.path.join(self.temp_dir, "._test.log")

        with open(regular_file, "w") as f:
            f.write("log content")
        with open(resource_fork_file, "w") as f:
            f.write("resource fork content")

        # Test get_all_files method
        files = log_util.get_all_files(self.temp_dir)

        # Assert both files are included on Linux
        self.assertIn("test.log", [os.path.basename(f) for f in files])
        self.assertIn("._test.log", [os.path.basename(f) for f in files])


class CollectinfoLogHandlerTest(unittest.TestCase):
    def test_info_masking_rules_method_exists(self):
        """Test that info_masking_rules method exists"""
        # Just test that the method exists and is callable
        self.assertTrue(hasattr(CollectinfoLogHandler, "info_masking_rules"))
        self.assertTrue(callable(getattr(CollectinfoLogHandler, "info_masking_rules")))

    @patch(
        "lib.collectinfo_analyzer.collectinfo_handler.log_handler.CollectinfoLogHandler._fetch_from_cinfo_log"
    )
    def test_info_masking_rules_calls_fetch(self, fetch_mock):
        """Test that info_masking_rules calls _fetch_from_cinfo_log with correct type"""
        from mock import MagicMock

        # Mock the _fetch_from_cinfo_log method
        fetch_mock.return_value = {"timestamp": {"node1": []}}

        # Create a mock handler instance
        handler = MagicMock(spec=CollectinfoLogHandler)
        handler._fetch_from_cinfo_log = fetch_mock

        # Call the actual method
        CollectinfoLogHandler.info_masking_rules(handler)

        # Verify it was called with the correct type
        fetch_mock.assert_called_once_with(type="masking")

    def test_info_release_method_exists(self):
        """Test that info_release method exists"""
        # Just test that the method exists and is callable
        self.assertTrue(hasattr(CollectinfoLogHandler, "info_release"))
        self.assertTrue(callable(getattr(CollectinfoLogHandler, "info_release")))

    @patch(
        "lib.collectinfo_analyzer.collectinfo_handler.log_handler.CollectinfoLogHandler._fetch_from_cinfo_log"
    )
    def test_info_release_calls_fetch(self, fetch_mock):
        """Test that info_release calls _fetch_from_cinfo_log with correct type and stanza"""
        from mock import MagicMock

        # Mock the _fetch_from_cinfo_log method
        fetch_mock.return_value = {
            "timestamp": {
                "node1": {
                    "arch": "linux-x64",
                    "edition": "enterprise",
                    "version": "8.1.1",
                    "os": "el9",
                }
            }
        }

        # Create a mock handler instance
        handler = MagicMock(spec=CollectinfoLogHandler)
        handler._fetch_from_cinfo_log = fetch_mock

        # Call the actual method
        CollectinfoLogHandler.info_release(handler)

        # Verify it was called with the correct type and stanza
        fetch_mock.assert_called_once_with(type="meta_data", stanza="release")


class BundleExtractionTest(unittest.TestCase):
    """Opening a bundle is opening a third party's archive."""

    def setUp(self):
        self.work_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work_dir, ignore_errors=True)
        self.dest_dir = os.path.join(self.work_dir, "dest")
        os.makedirs(self.dest_dir)

    def _handler(self):
        handler = MagicMock(spec=CollectinfoLogHandler)
        handler._extract_to = CollectinfoLogHandler._extract_to.__get__(handler)

        return handler

    def _tar_with(self, member_name, payload=b"pwned"):
        path = os.path.join(self.work_dir, "bundle.tgz")
        content = os.path.join(self.work_dir, "content")

        with open(content, "wb") as content_file:
            content_file.write(payload)

        with tarfile.open(path, "w:gz") as archive:
            archive.add(content, arcname=member_name)

        return path

    def test_a_traversing_member_is_not_written_outside_the_destination(self):
        """A tar member named ../escaped writes outside dest_dir on Python 3.12,
        whose default extraction filter is still fully_trusted."""
        archive = self._tar_with("../escaped.txt")
        escaped = os.path.join(self.work_dir, "escaped.txt")

        with self.assertLogs(
            "lib.collectinfo_analyzer.collectinfo_handler.log_handler", level="WARNING"
        ):
            extracted = self._handler()._extract_to(archive, self.dest_dir)

        self.assertFalse(extracted)
        self.assertFalse(os.path.exists(escaped), escaped)

    def test_an_absolute_member_is_not_written_outside_the_destination(self):
        """tarfile strips the leading separator when the archive is built, but
        the destination is what matters: nothing lands outside it."""
        outside = os.path.join(self.work_dir, "absolute.txt")
        archive = self._tar_with(outside)

        self._handler()._extract_to(archive, self.dest_dir)

        self.assertFalse(os.path.exists(outside), outside)

    def test_an_ordinary_bundle_still_extracts(self):
        """asadm's own bundles hold regular files only, so the filter must not
        cost the product anything."""
        archive = self._tar_with("20260720_100000_ascinfo.json", b"{}")

        extracted = self._handler()._extract_to(archive, self.dest_dir)

        self.assertTrue(extracted)
        self.assertTrue(
            os.path.exists(os.path.join(self.dest_dir, "20260720_100000_ascinfo.json"))
        )


class NoSnapshotReasonTest(unittest.TestCase):
    """What asadm says about a path it cannot read a cluster snapshot from.

    All three cases used to share "Multiple snapshots available without JSON
    dump.", which describes none of them: an archive that is not a collectinfo
    bundle at all is the common one, and it sends the reader looking for
    snapshots that were never there."""

    def setUp(self):
        self.bundle_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.bundle_dir, ignore_errors=True)

    def _write(self, name, text="{}"):
        path = os.path.join(self.bundle_dir, name)

        with open(path, "w") as handle:
            handle.write(text)

        return path

    def test_an_archive_that_is_not_a_bundle_says_so(self):
        files = [self._write("Chart.yaml"), self._write("values.yaml")]

        message = CollectinfoLogHandler._no_snapshot_reason(
            MagicMock(spec=CollectinfoLogHandler), self.bundle_dir, files
        )

        self.assertIn("No Aerospike collectinfo data found", message)
        self.assertIn(self.bundle_dir, message)
        self.assertIn("ascinfo.json", message)
        self.assertIn("2 other file(s)", message)

    def test_an_unparsable_bundle_names_the_file_it_found(self):
        files = [self._write("20260720_100000_ascinfo.json", "{not json")]

        message = CollectinfoLogHandler._no_snapshot_reason(
            MagicMock(spec=CollectinfoLogHandler), self.bundle_dir, files
        )

        self.assertIn("Could not read a cluster snapshot", message)
        self.assertIn("20260720_100000_ascinfo.json", message)
        self.assertNotIn("No Aerospike collectinfo data found", message)

    def test_a_directory_with_no_collectinfo_raises_the_new_message(self):
        self._write("Chart.yaml")

        with self.assertRaises(LogHandlerException) as raised:
            handler = CollectinfoLogHandler(self.bundle_dir)
            self.addCleanup(handler.close)

        self.assertIn("No Aerospike collectinfo data found", str(raised.exception))


class NodeIdMappingTest(unittest.TestCase):
    """TOOLS-3596: a bundle node whose meta_data has no usable node_id (its info calls
    failed during collection) must be skipped instead of crashing the mapping."""

    META_DATA = {
        "ts": {
            "1.1.1.1:3000": {"node_id": "A1"},
            "2.2.2.2:3000": {},  # degraded node: no node_id key at all
            "3.3.3.3:3000": {"node_id": ""},  # node_id call failed
        }
    }

    def _handler(self):
        from mock import MagicMock

        handler = MagicMock(spec=CollectinfoLogHandler)
        handler.info_meta_data = MagicMock(return_value=self.META_DATA)
        return handler

    def test_get_node_id_to_ip_mapping_skips_nodes_without_id(self):
        result = CollectinfoLogHandler.get_node_id_to_ip_mapping(self._handler(), "ts")

        self.assertEqual(result, {"A1": "1.1.1.1:3000"})

    def test_get_ip_to_node_id_mapping_skips_nodes_without_id(self):
        result = CollectinfoLogHandler.get_ip_to_node_id_mapping(self._handler(), "ts")

        self.assertEqual(result, {"1.1.1.1:3000": "A1"})


TS = "2026-07-20 10:00:00 UTC"
FILE_PREFIX = "20260720_100000_"

CINFO_DATA = {
    TS: {
        "prod": {
            "1.1.1.1:3000": {
                "as_stat": {
                    "statistics": {
                        "service": {
                            "cluster_size": "1",
                            "cluster_integrity": "true",
                            "cluster_is_member": "true",
                        },
                        "namespace": {},
                    },
                    "config": {"service": {"proto-fd-max": "15000"}, "namespace": {}},
                    "meta_data": {
                        "node_id": "BB1",
                        "asd_build": "8.0.0.0",
                        "edition": "Aerospike Enterprise Edition",
                        "ip": "1.1.1.1:3000",
                        "node_names": "host1",
                    },
                },
                "sys_stat": {"uname": {"nodename": "host1"}},
            }
        }
    }
}

META_DATA = {
    "meta_format_version": 1,
    "bundle": {"asadm_version": "3.1.0", "asadm_build": "abc123"},
    "collection": {"host": "collector", "flags": {"enable_ssh": False}},
    "snapshots": [
        {
            "timestamp": TS,
            "cluster_name": "prod",
            "expected_nodes": ["1.1.1.1:3000", "2.2.2.2:3000"],
            "responded_nodes": ["1.1.1.1:3000"],
            "no_data_nodes": ["2.2.2.2:3000"],
            "nodes": {},
            "discrepancies": {
                "missing_from_collection": [],
                "dropped_during_collection": [
                    {"node_key": "2.2.2.2:3000", "reason": "timed out"}
                ],
                "cluster_down_nodes": [],
                "visibility_error_nodes": [],
            },
        }
    ],
}


class BundleDiagnosticsWiringTest(unittest.TestCase):
    """TOOLS-4135: bundle provenance/diagnostics wiring on the log handler."""

    def setUp(self):
        self.bundle_dir = tempfile.mkdtemp()
        self._write_json("ascinfo.json", CINFO_DATA)

    def tearDown(self):
        shutil.rmtree(self.bundle_dir, ignore_errors=True)

    def _write_json(self, suffix, data):
        with open(os.path.join(self.bundle_dir, FILE_PREFIX + suffix), "w") as f:
            json.dump(data, f)

    def _write_text(self, suffix, text):
        with open(os.path.join(self.bundle_dir, FILE_PREFIX + suffix), "w") as f:
            f.write(text)

    def _handler(self, asadm_version="5.0.2"):
        handler = CollectinfoLogHandler(self.bundle_dir, asadm_version=asadm_version)
        self.addCleanup(handler.close)
        return handler

    def test_meta_is_loaded(self):
        self._write_json("collectinfo_meta.json", META_DATA)

        handler = self._handler()

        self.assertEqual(handler.collectinfo_meta["bundle"]["asadm_version"], "3.1.0")

    def test_missing_meta_is_tolerated_silently(self):
        """Mid-collection the analyzer runs over a bundle with no meta and no logs
        yet; that must not warn or raise."""
        with self.assertNoLogs(
            "lib.collectinfo_analyzer.collectinfo_handler.log_handler", level="WARNING"
        ):
            handler = self._handler()

        self.assertEqual(handler.collectinfo_meta, {})
        self.assertEqual(handler._scan_bundle_for_asadm_version(), "")

    def test_malformed_meta_is_tolerated(self):
        self._write_text("collectinfo_meta.json", "{not json")

        handler = self._handler()

        self.assertEqual(handler.collectinfo_meta, {})

    def test_meta_for_a_different_snapshot_is_ignored(self):
        """A meta describing another bundle would report its dropped nodes, per-node
        errors, and collector version against this snapshot."""
        other = copy.deepcopy(META_DATA)
        other["snapshots"][0]["timestamp"] = "2020-01-01 00:00:00 UTC"
        self._write_json("collectinfo_meta.json", other)

        handler = self._handler()

        self.assertEqual(handler.collectinfo_meta, {})
        self.assertNotIn("2.2.2.2:3000", handler.diagnostics_banner())

    def test_the_meta_carrying_the_analyzed_snapshot_wins(self):
        """Every archive under the path is extracted and every ascinfo.json merged,
        so more than one meta can be present while one snapshot is analyzed."""
        other = copy.deepcopy(META_DATA)
        other["snapshots"][0]["timestamp"] = "2020-01-01 00:00:00 UTC"
        other["bundle"]["asadm_version"] = "1.0.0"

        with open(
            os.path.join(self.bundle_dir, "other_collectinfo_meta.json"), "w"
        ) as f:
            json.dump(other, f)

        self._write_json("collectinfo_meta.json", META_DATA)

        handler = self._handler()

        self.assertEqual(handler.collectinfo_meta["bundle"]["asadm_version"], "3.1.0")

    def test_version_scan_reads_ascollectinfo_log(self):
        self._write_text(
            "ascollectinfo.log", "2026-07-20 10:00:00 UTC\nasadm version 2.9.0\n"
        )

        handler = self._handler()

        self.assertEqual(handler._scan_bundle_for_asadm_version(), "2.9.0")

    def test_version_scan_reads_summary_log(self):
        self._write_text("summary.log", "header\nasadm version 4.0.1\n")

        handler = self._handler()

        self.assertEqual(handler._scan_bundle_for_asadm_version(), "4.0.1")

    def test_version_scan_agreeing_logs_report_the_version(self):
        self._write_text("ascollectinfo.log", "asadm version 4.0.1\n")
        self._write_text("summary.log", "asadm version 4.0.1\n")

        handler = self._handler()

        self.assertEqual(handler._scan_bundle_for_asadm_version(), "4.0.1")

    def test_version_scan_disagreeing_logs_report_nothing(self):
        """A directory holding two bundles is a supported input, and the scan
        cannot tell which log belongs to the analyzed snapshot. Attributing one
        bundle's collector to another's data is worse than reporting the version
        as unrecorded."""
        self._write_text("ascollectinfo.log", "asadm version 2.9.0\n")
        self._write_text("summary.log", "asadm version 4.0.1\n")

        handler = self._handler()

        self.assertEqual(handler._scan_bundle_for_asadm_version(), "")

    def test_meta_version_drives_the_banner(self):
        self._write_json("collectinfo_meta.json", META_DATA)

        banner = self._handler().diagnostics_banner()

        self.assertIn("3.1.0", banner)
        self.assertIn("2.2.2.2:3000", banner)

    def test_banner_is_appended_to_str(self):
        self._write_json("collectinfo_meta.json", META_DATA)

        handler = self._handler()

        self.assertIn("Collectinfo Bundle Diagnostics", str(handler))
        self.assertIn("Found 1 nodes", str(handler))

    def test_collector_version_sits_with_the_found_and_online_lines(self):
        self._write_json("collectinfo_meta.json", META_DATA)

        intro = str(self._handler())

        self.assertIn("Collected by:  asadm 3.1.0", intro)
        self.assertLess(intro.index("Found 1 nodes"), intro.index("Collected by:"))

    def test_collector_version_comes_from_the_log_when_meta_is_absent(self):
        self._write_text("summary.log", "header\nasadm version 4.0.1\n")

        handler = self._handler()

        self.assertEqual(handler.collector_asadm_version(), "4.0.1")
        self.assertIn("Collected by:  asadm 4.0.1", str(handler))

    def test_meta_version_wins_over_the_log_scan(self):
        self._write_json("collectinfo_meta.json", META_DATA)
        self._write_text("summary.log", "header\nasadm version 4.0.1\n")

        self.assertEqual(self._handler().collector_asadm_version(), "3.1.0")

    def test_unrecorded_version_is_flagged_in_the_intro(self):
        """A bundle too old to stamp a version anywhere is a finding, not a blank."""
        intro = str(self._handler())

        self.assertIn("unrecorded asadm version", intro)
        self.assertIn("Collected by an unknown asadm version", intro)

    def test_matching_version_is_not_repeated_in_the_banner(self):
        self._write_json("collectinfo_meta.json", META_DATA)
        handler = self._handler(asadm_version="3.1.0")

        self.assertIn("Collected by:  asadm 3.1.0", str(handler))
        self.assertNotIn("Collected by asadm 3.1.0", handler.diagnostics_banner())

    def test_diagnostics_that_could_not_be_computed_say_so(self):
        """An empty finding list reads as a healthy bundle. When the analyzer
        itself failed, nothing was checked, and the banner must say that rather
        than print a clean bill of health."""
        self._write_json("collectinfo_meta.json", META_DATA)
        handler = self._handler()

        with patch.object(
            CollectinfoDiagnostics, "analyze", side_effect=ValueError("boom")
        ):
            warnings = handler.get_bundle_diagnostics()

        self.assertEqual([w.category for w in warnings], ["diagnostics-unavailable"])
        self.assertIn("Diagnostics could not be computed", str(warnings[0].title))

    def test_diagnostics_are_cached(self):
        handler = self._handler()

        first = handler.get_bundle_diagnostics()
        second = handler.get_bundle_diagnostics()

        self.assertIs(first, second)

    def test_print_diagnostics_banner_writes_the_findings(self):
        self._write_json("collectinfo_meta.json", META_DATA)
        handler = self._handler()
        stream = io.StringIO()

        handler.print_diagnostics_banner(stream)
        out = stream.getvalue()

        self.assertIn("Collectinfo Bundle Diagnostics", out)
        self.assertIn("2.2.2.2:3000", out)

    def test_print_diagnostics_banner_does_not_set_the_exit_code(self):
        """Diagnostics describe the collected cluster, not the command the user ran,
        so an ERROR-severity finding must not fail `asadm -cf ... -e ...`."""
        self._write_json("collectinfo_meta.json", META_DATA)
        handler = self._handler()
        handler._bundle_diagnostics = [
            BundleWarning(
                category="partition-availability",
                severity=DiagSeverity.ERROR,
                title="Partitions were dead or unavailable at collection time",
            )
        ]
        logger.set_exit_code(0)
        self.addCleanup(logger.set_exit_code, 0)

        handler.print_diagnostics_banner(io.StringIO())

        self.assertEqual(logger.get_exit_code(), 0)

    def test_an_unusable_bundle_fails_the_command(self):
        """A bundle with no readable node data makes every command print an empty
        table, so `asadm -e ... || handle_error` would read the failure as
        success."""
        self._write_json("collectinfo_meta.json", META_DATA)
        handler = self._handler()
        handler._bundle_diagnostics = [
            BundleWarning(
                category="no-usable-nodes",
                severity=DiagSeverity.ERROR,
                title="Bundle contains no nodes",
            )
        ]
        logger.set_exit_code(0)
        self.addCleanup(logger.set_exit_code, 0)

        handler.print_diagnostics_banner(io.StringIO())

        self.assertEqual(logger.get_exit_code(), 2)

    def test_importing_the_analyzer_does_not_load_the_client(self):
        """Reaching for BaseLogger used to pull lib.live_cluster.client, and
        OpenSSL with it, into a module graph that needs neither. Asserted by
        importing in a fresh interpreter: inside this process something else has
        already imported the client."""
        repo_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        )
        script = (
            "import sys;"
            "import lib.collectinfo_analyzer.collectinfo_handler.log_handler;"
            "print('lib.live_cluster.client' in sys.modules)"
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=repo_root,
        )

        self.assertEqual(result.stdout.strip(), "False", result.stderr)

    def test_print_diagnostics_banner_defaults_to_stderr(self):
        """Execute mode is built to be scripted: the banner must land on stderr by
        default and leave stdout untouched."""
        self._write_json("collectinfo_meta.json", META_DATA)
        handler = self._handler()
        err, out = io.StringIO(), io.StringIO()

        with patch("sys.stderr", err), patch("sys.stdout", out):
            handler.print_diagnostics_banner()

        self.assertIn("Collectinfo Bundle Diagnostics", err.getvalue())
        self.assertEqual(out.getvalue(), "")

    def test_bundle_files_finds_log_files(self):
        self._write_text("sysinfo.log", "sysinfo")
        handler = self._handler()

        found = handler.bundle_files(("sysinfo.log",))

        self.assertEqual(
            [os.path.basename(f) for f in found], ["20260720_100000_sysinfo.log"]
        )

    def test_bundle_snapshot_count(self):
        handler = self._handler()

        self.assertEqual(handler.bundle_snapshot_count, 1)
