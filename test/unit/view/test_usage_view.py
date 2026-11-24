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

import hashlib
import io
import re
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from lib.view import terminal
from lib.view.view import CliView

ANSI = re.compile(r"\x1b\[[0-9;]*m")
CLUSTER = "963fa489-71bd-46a9-af70-765ce26c5a62"


def ns_hash(name):
    return hashlib.sha256((CLUSTER + name).encode()).hexdigest()[:16]


def sample(date, slot, data_used, migrating=False, reported=3, extra_rows=()):
    return {
        "data": {
            "cluster": CLUSTER,
            "date": date,
            "feature_key_serial": "1",
            "migrating": migrating,
            "nodes": 3,
            "nodes_reported": reported,
            "rows": [
                {
                    "data_used": data_used,
                    "ns": ns_hash("test"),
                    "ratio": 1000,
                    "rf": 2,
                },
                *extra_rows,
            ],
            "schema": 1,
            "slot": slot,
            "time": "%sT%02d:00:05Z" % (date, (slot - 1) * 8),
        }
    }


def export_data(records=(), feature_key=None):
    return {
        "cluster": CLUSTER,
        "feature_key": (
            {"account-ID": "12345", "account-name": "Acme Corp"}
            if feature_key is None
            else feature_key
        ),
        "records": [
            {
                "data": {
                    "cluster": CLUSTER,
                    "date": date,
                    "samples": samples,
                    "schema": 1,
                }
            }
            for date, samples in records
        ],
        "schema": 1,
        "taken": "2026-10-04T10:15:02Z",
    }


class UsageSavedTest(unittest.TestCase):
    def lines(self, data):
        out = io.StringIO()

        with redirect_stdout(out):
            CliView.print_usage_saved(data, "/tmp/collect_usage_x.json", 2048)

        return out.getvalue().splitlines()

    def test_names_the_file_and_its_size(self):
        self.assertIn(
            "Saved   /tmp/collect_usage_x.json (2.000 KiB)", self.lines(export_data())
        )

    def test_a_size_under_1_kib_is_whole_bytes(self):
        out = io.StringIO()

        with redirect_stdout(out):
            CliView.print_usage_saved(export_data(), "/tmp/collect_usage_x.json", 752)

        self.assertIn(
            "Saved   /tmp/collect_usage_x.json (752 B)", out.getvalue().splitlines()
        )

    def test_leaves_out_the_account_when_the_feature_key_names_none(self):
        lines = self.lines(export_data(feature_key={"serial-number": "1"}))

        self.assertFalse([line for line in lines if line.startswith("Account")], lines)


class SummaryClusterUuidTest(unittest.TestCase):
    def cluster_lines(self, **extra):
        cluster_data = {
            "active_features": [],
            "active_ns": 1,
            "ns_count": 1,
            "migrations_in_progress": False,
            "cluster_name": ["prod"],
            "server_version": ["8.2.1.0"],
            "os_version": ["Linux"],
            "cluster_size": [3],
            "device_count": 0,
            "device_count_per_node": 0,
            "device_count_same_across_nodes": True,
            "license_data": {"latest": 0},
            "compression_enabled": False,
            **extra,
        }
        lines = []

        for line in CliView._summary_cluster_list_view(cluster_data):
            lines.extend(ANSI.sub("", str(line)).split("\n"))

        return lines

    def labelled(self, lines, label):
        return [line for line in lines if re.search(r"\d+\.\s+%s\s+:" % label, line)]

    def test_follows_the_cluster_name(self):
        lines = self.cluster_lines(cluster_uuid=[CLUSTER])
        labels = [
            re.split(r"\s{2,}", line.strip())[1]
            for line in lines
            if re.match(r"\s+\d+\.", line)
        ]

        self.assertEqual(labels[:3], ["Cluster Name", "Cluster UUID", "Server Version"])
        self.assertTrue(self.labelled(lines, "Cluster UUID")[0].endswith(CLUSTER))

    def test_lists_each_value_when_nodes_disagree(self):
        lines = self.cluster_lines(
            cluster_uuid=[CLUSTER, "11111111-2222-4333-8444-555555555555"]
        )

        self.assertTrue(
            self.labelled(lines, "Cluster UUID")[0].endswith(
                f"{CLUSTER}, 11111111-2222-4333-8444-555555555555"
            )
        )

    def test_left_out_when_no_node_reports_one(self):
        self.assertEqual(self.labelled(self.cluster_lines(), "Cluster UUID"), [])

    def table_rows(self, **extra):
        cluster_data = {
            "migrations_in_progress": False,
            "cluster_name": ["prod"],
            "server_version": ["8.2.1.0"],
            "os_version": ["Linux"],
            "cluster_size": [3],
            **extra,
        }

        with patch.object(CliView, "print_result") as print_result:
            CliView._summary_cluster_table_view(cluster_data)

        return [
            [cell.strip() for cell in line.split("|")]
            for line in ANSI.sub("", print_result.call_args.args[0]).splitlines()
            if "|" in line
        ]

    def test_table_view_follows_the_cluster_name(self):
        rows = self.table_rows(cluster_uuid=[CLUSTER])
        labels = [row[0] for row in rows]

        self.assertEqual(
            labels[labels.index("Cluster Name") + 1], "Cluster UUID", labels
        )
        self.assertIn(["Cluster UUID", CLUSTER], rows)

    def test_table_view_left_out_when_no_node_reports_one(self):
        self.assertNotIn("Cluster UUID", [row[0] for row in self.table_rows()])


class ShowUsageTest(unittest.TestCase):
    SAMPLES = "Usage Samples (UTC)"
    NAMESPACES = "Usage by Namespace"

    def setUp(self):
        self.addCleanup(setattr, CliView, "pager", CliView.pager)
        CliView.pager = CliView.NO_PAGER
        self.addCleanup(patch.stopall)
        self.output = ""

    def show(self, data, namespaces=()):
        out = io.StringIO()

        with redirect_stdout(out):
            CliView.show_usage(data, namespaces=namespaces)

        self.output = out.getvalue()

        return ANSI.sub("", self.output).splitlines()

    def table(self, title):
        text = ANSI.sub("", self.output)
        start = text.index(title)

        return text[start : text.index("Number of rows", start)]

    def rows(self, title):
        return [
            [cell.strip() for cell in line.split("|")]
            for line in self.table(title).splitlines()
            if re.match(r"\s*(\d{4}-|[0-9a-z]+\s*\||\s*\|)", line)
        ]

    def test_header_names_cluster_account_days_and_when_taken(self):
        lines = self.show(
            export_data(
                [
                    ("2026-10-02", [sample("2026-10-02", 1, 2048)]),
                    ("2026-10-03", [sample("2026-10-03", 1, 2048)]),
                ]
            )
        )

        self.assertEqual(
            lines[:4],
            [
                f"Cluster {CLUSTER}",
                "Account Acme Corp (12345)",
                "Days    2026-10-02 to 2026-10-03, 2 days",
                "Taken   2026-10-04 10:15:02 UTC",
            ],
        )

    def test_samples_table_has_one_row_per_sample(self):
        self.show(
            export_data(
                [
                    (
                        "2026-10-03",
                        [
                            sample("2026-10-03", 1, 2048),
                            sample("2026-10-03", 3, 4096, migrating=True, reported=2),
                        ],
                    )
                ]
            )
        )

        self.assertNotIn("Slot", self.table(self.SAMPLES))
        self.assertIn(
            ["2026-10-03", "00:00:05", "3", "3", "False", "2.000 KiB", "1.000 KiB"],
            self.rows(self.SAMPLES),
        )
        self.assertIn(
            ["2026-10-03", "16:00:05", "3", "2", "True", "4.000 KiB", "2.000 KiB"],
            self.rows(self.SAMPLES),
        )

    def test_namespace_table_names_the_latest_samples_namespaces(self):
        bar = {"data_used": 8192, "ns": ns_hash("bar"), "ratio": 500, "rf": 1}
        gone = {"data_used": 1024, "ns": ns_hash("gone"), "ratio": 1000, "rf": 1}

        self.show(
            export_data(
                [
                    (
                        "2026-10-03",
                        [
                            sample("2026-10-03", 1, 2048),
                            sample("2026-10-03", 3, 4096, extra_rows=(bar, gone)),
                        ],
                    )
                ]
            ),
            namespaces=["bar", "test"],
        )

        rows = {row[0]: row for row in self.rows(self.NAMESPACES)}

        self.assertIn(
            "Usage by Namespace (2026-10-03 16:00:05 UTC)", self.table(self.NAMESPACES)
        )
        self.assertEqual(rows["test"][1:], ["2", "1.0", "4.000 KiB", "2.000 KiB"])
        self.assertEqual(rows["bar"][1:], ["1", "0.5", "8.000 KiB", "16.000 KiB"])
        self.assertIn(ns_hash("gone"), rows)
        self.assertEqual(rows[""][-2:], ["13.000 KiB", "19.000 KiB"])

    def test_namespace_total_license_usage_is_blank_when_a_row_has_none(self):
        no_rf = {"data_used": 8192, "ns": ns_hash("bar"), "ratio": 1000, "rf": 0}

        self.show(
            export_data(
                [("2026-10-03", [sample("2026-10-03", 1, 4096, extra_rows=(no_rf,))])]
            ),
            namespaces=["bar", "test"],
        )

        rows = {row[0]: row for row in self.rows(self.NAMESPACES)}

        self.assertEqual(rows["test"][-1], "2.000 KiB")
        self.assertEqual(rows["bar"][-1], "--")
        self.assertEqual(rows[""][-2], "12.000 KiB")
        self.assertIn(rows[""][-1], ("", "--"))

    def test_with_the_pager_on_the_header_and_both_tables_page_together(self):
        CliView.pager = CliView.LESS
        pipepager = patch("lib.view.view.pipepager").start()

        lines = self.show(
            export_data([("2026-10-03", [sample("2026-10-03", 1, 2048)])])
        )

        self.assertEqual(lines, [])
        pipepager.assert_called_once()
        paged = ANSI.sub("", pipepager.call_args.args[0])
        self.assertTrue(paged.startswith(f"Cluster {CLUSTER}\n"), paged)
        self.assertIn("Taken   2026-10-04 10:15:02 UTC", paged)
        self.assertIn(self.SAMPLES, paged)
        self.assertIn(self.NAMESPACES, paged)

    def test_partial_and_migrating_samples_are_red(self):
        self.addCleanup(
            terminal.enable_color,
            sys.modules[terminal.__name__ + ".terminal"].color_enabled,
        )
        terminal.enable_color(True)

        self.show(
            export_data(
                [
                    (
                        "2026-10-03",
                        [
                            sample("2026-10-03", 1, 2048),
                            sample("2026-10-03", 2, 2048, reported=2),
                            sample("2026-10-03", 3, 2048, migrating=True),
                        ],
                    )
                ]
            )
        )

        samples = self.output[
            self.output.index(self.SAMPLES) : self.output.index(self.NAMESPACES)
        ]
        red_cells = {
            time: re.findall(r"\x1b\[31;91m\s*([^\s\x1b]+)\s*\x1b\[0;m", line)
            for line in samples.splitlines()
            for time in ("00:00:05", "08:00:05", "16:00:05")
            if time in line
        }

        self.assertEqual(
            red_cells, {"00:00:05": [], "08:00:05": ["2"], "16:00:05": ["True"]}
        )

    def test_no_closed_day_prints_no_table(self):
        lines = self.show(export_data())

        self.assertIn("Days    none closed yet", lines)
        self.assertNotIn(self.SAMPLES, self.output)
        self.assertNotIn(self.NAMESPACES, self.output)
