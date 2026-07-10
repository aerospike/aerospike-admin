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

import json
import unittest
from parameterized import parameterized

from lib.view import sheet, templates
from lib.view.sheet import SheetStyle
from lib.view.sheet.decleration import EntryData, Subgroup


class HelperTests(unittest.TestCase):
    @parameterized.expand(
        [
            ([0.5, 0.8, 0.3], [10, 15, 20], 0.511),
            ([0.5, 0.8, 0.3], [-1, 0, 1], 0),
            ([4.0, 10.59, 8.35], [65701.6, 64926.1, 65567.2], 7.635),
        ],
    )
    def test_weighted_avg(self, values, weights, expected):
        self.assertEqual(round(templates.weighted_avg(values, weights), 3), expected)

    @parameterized.expand(
        [
            (
                [
                    EntryData(0.5, None, {"ops/sec": 10}, None, False, False),
                    EntryData(0.8, None, {"ops/sec": 15}, None, False, False),
                    EntryData(0.3, None, {"ops/sec": 20}, None, False, False),
                ],
                0.511,
            ),
        ],
    )
    def test_latency_weighted_avg(self, edatas, expected):
        self.assertEqual(round(templates.latency_weighted_avg(edatas), 3), expected)

    @parameterized.expand(
        [
            (
                [
                    EntryData(0.5, None, {"type": {"Total": 10}}, None, False, False),
                    EntryData(0.8, None, {"type": {"Total": 15}}, None, False, False),
                    EntryData(0.3, None, {"type": {"Total": 20}}, None, False, False),
                ],
                0.511,
            ),
        ],
    )
    def test_create_usage_weighted_avg(self, edatas, expected):
        func = templates.create_usage_weighted_avg("type")
        self.assertEqual(round(func(edatas), 3), expected)

    @parameterized.expand(
        [
            # Test compression enabled with non-zero value
            ({"latest": 1000000}, True, "(976.562 KB) ?"),
            # Test compression disabled with non-zero value
            ({"latest": 1000000}, False, "976.562 KB"),
            # Test compression enabled with zero value (no parentheses)
            ({"latest": 0}, True, "0.000 B"),
            # Test compression disabled with zero value
            ({"latest": 0}, False, "0.000 B"),
            # Test empty license data
            ({}, True, "0.000 B"),
            # Test None license data
            (None, True, "0.000 B"),
        ]
    )
    def test_format_license_latest_with_compression(
        self, license_data, compression_enabled, expected
    ):
        """Test format_license_latest_with_compression function"""
        result = templates.format_license_latest_with_compression(
            license_data, compression_enabled
        )
        self.assertEqual(result, expected)


class InfoNamespaceUsageIndexFormattersTests(unittest.TestCase):
    """Covers the Used% alert tiers for the Primary/Secondary Index subgroups
    of 'info namespace usage': yellow when eviction is running, red when near
    the mounts/memory budget (TOOLS-3456)."""

    @staticmethod
    def _get_used_pct_field(subgroup_title):
        for field in templates.info_namespace_usage_sheet.fields:
            if isinstance(field, Subgroup) and field.title == subgroup_title:
                for sub_field in field.fields:
                    if sub_field.title == "Used%":
                        return sub_field
        raise AssertionError(f"Used% field not found in {subgroup_title}")

    @staticmethod
    def _applied_formatter(field, edata):
        # Mirrors sheet behavior: first formatter to not return None wins.
        for name, formatter_fn in field.formatters:
            if formatter_fn(edata) is not None:
                return name
        return None

    @parameterized.expand(
        [
            # (used ratio, evict pct, expected formatter)
            (0.50, 80, None),  # healthy
            (0.85, 80, "yellow-alert"),  # eviction running
            (0.92, 80, "red-alert"),  # near budget, red wins over yellow
            (0.92, 0, "red-alert"),  # near budget even with eviction disabled
            (0.89, 0, None),  # eviction disabled, below red threshold
        ]
    )
    def test_used_pct_alert_tiers(self, used_ratio, evict_pct, expected):
        for subgroup in ("Primary Index", "Secondary Index"):
            field = self._get_used_pct_field(subgroup)
            edata = EntryData(
                used_ratio, None, {subgroup: {"Evict%": evict_pct}}, None, False, False
            )
            self.assertEqual(
                self._applied_formatter(field, edata),
                expected,
                f"{subgroup} Used%={used_ratio} Evict%={evict_pct}",
            )


class ShowPmapSheetTest(unittest.TestCase):
    """Regression tests for TOOLS-3772: cluster keys shaped like an
    overflowing float literal (e.g. 9E0123456789) rendered as the error
    entry '~~' in 'show pmap'."""

    def render_pmap(self, cluster_key, style):
        node = "127.0.0.1:3000"
        sources = dict(
            node_names={node: "node-A"},
            node_ids={node: "BB9040011AC4202"},
            pmap={
                node: {
                    "test": {
                        "cluster_key": cluster_key,
                        "master_partition_count": 683,
                        "prole_partition_count": 1365,
                        "unavailable_partitions": 0,
                        "dead_partitions": 0,
                    }
                }
            },
        )
        common = dict(principal="BB9040011AC4202")

        return sheet.render(
            templates.show_pmap_sheet,
            "Partition Map Analysis",
            sources,
            common=common,
            style=style,
        )

    @parameterized.expand(
        [
            # <digit>E<digits> parses as overflowing scientific notation.
            ("9E0123456789",),
            # <digit>E<digits> that parses as a valid float without overflow.
            ("1E9",),
            # Hex key that cannot parse as a float at all.
            ("B40E9AE14C62",),
            # All-digit key must not be reformatted as a number.
            ("123456789012",),
            # Default when service statistics are unavailable for a node.
            ("N/E",),
        ]
    )
    def test_cluster_key_renders_verbatim(self, cluster_key):
        record = json.loads(self.render_pmap(cluster_key, SheetStyle.json))["groups"][
            0
        ]["records"][0]

        self.assertEqual(record["Cluster Key"]["raw"], cluster_key)
        self.assertEqual(record["Cluster Key"]["converted"], cluster_key)

        rendered = self.render_pmap(cluster_key, SheetStyle.columns)
        self.assertIn(cluster_key, rendered)

    def test_partition_counts_still_aggregate(self):
        render = json.loads(self.render_pmap("9E0123456789", SheetStyle.json))
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["Partitions"]["Primary"]["raw"], 683)
        self.assertEqual(record["Partitions"]["Secondary"]["raw"], 1365)
        self.assertEqual(record["Partitions"]["Unavailable"]["raw"], 0)
        self.assertEqual(record["Partitions"]["Dead"]["raw"], 0)


class NodeHighlightingTest(unittest.TestCase):
    """Behavioral coverage for the principal (green, "*") and self-node
    (cyan, "@") highlighting on info_network_sheet's Node / Node ID columns."""

    node_keys = ("1.1.1.1:3000", "2.2.2.2:3000", "3.3.3.3:3000")
    node_ids = ("NODE1", "NODE2", "NODE3")

    def render_network_sheet(self, principal, self_node):
        stats = {
            key: {
                "cluster_size": 3,
                "cluster_key": "CK",
                "cluster_integrity": True,
                "paxos_principal": "NODE1",
                "migrate_partitions_remaining": 0,
                "client_connections": 1,
                "uptime": 100,
            }
            for key in self.node_keys
        }
        sources = dict(
            node_names={key: key for key in self.node_keys},
            node_ids=dict(zip(self.node_keys, self.node_ids)),
            hosts={key: key for key in self.node_keys},
            builds={key: "7.1.0.0" for key in self.node_keys},
            versions={key: "7.1.0.0" for key in self.node_keys},
            stats=stats,
        )
        common = dict(
            principal=principal,
            self_node=self_node,
            common_size="3",
            common_key="CK",
            common_principal="NODE1",
        )
        render = json.loads(
            sheet.render(
                templates.info_network_sheet,
                "test",
                sources,
                common=common,
                style=SheetStyle.json,
            )
        )
        records = render["groups"][0]["records"]
        return {record["Node ID"]["raw"]: record for record in records}

    def test_principal_is_green_and_star_prefixed(self):
        records = self.render_network_sheet(principal="NODE1", self_node="NODE2")

        self.assertEqual(records["NODE1"]["Node"]["format"], "green-alert")
        self.assertEqual(records["NODE1"]["Node"]["converted"], "*1.1.1.1:3000")
        self.assertEqual(records["NODE1"]["Node ID"]["format"], "green-alert")
        self.assertEqual(records["NODE1"]["Node ID"]["converted"], "*NODE1")

    def test_self_node_is_cyan_and_at_prefixed(self):
        records = self.render_network_sheet(principal="NODE1", self_node="NODE2")

        self.assertEqual(records["NODE2"]["Node"]["format"], "bold-cyan-alert")
        self.assertEqual(records["NODE2"]["Node"]["converted"], "@2.2.2.2:3000")
        self.assertEqual(records["NODE2"]["Node ID"]["format"], "bold-cyan-alert")
        self.assertEqual(records["NODE2"]["Node ID"]["converted"], "@NODE2")

    def test_plain_node_has_no_format_or_prefix(self):
        records = self.render_network_sheet(principal="NODE1", self_node="NODE2")

        self.assertNotIn("format", records["NODE3"]["Node"])
        self.assertEqual(records["NODE3"]["Node"]["converted"], "3.3.3.3:3000")
        self.assertNotIn("format", records["NODE3"]["Node ID"])
        self.assertEqual(records["NODE3"]["Node ID"]["converted"], "NODE3")

    def test_principal_wins_when_node_is_both_principal_and_self(self):
        records = self.render_network_sheet(principal="NODE1", self_node="NODE1")

        self.assertEqual(records["NODE1"]["Node"]["format"], "green-alert")
        self.assertEqual(records["NODE1"]["Node"]["converted"], "*1.1.1.1:3000")
        self.assertEqual(records["NODE1"]["Node ID"]["format"], "green-alert")
        self.assertEqual(records["NODE1"]["Node ID"]["converted"], "*NODE1")

    def test_no_marker_when_self_node_unknown(self):
        """Empty self_node (collectinfo / no localhost node) must not mark anything."""
        records = self.render_network_sheet(principal="NODE1", self_node="")

        self.assertEqual(records["NODE2"]["Node"]["converted"], "2.2.2.2:3000")
        self.assertNotIn("format", records["NODE2"]["Node"])

    def test_sheet_without_node_id_column_renders_unmarked(self):
        """node_info_responses has no Node ID field; the Node converter must
        degrade to no marker instead of raising KeyError."""
        sources = dict(
            node_names={"1.1.1.1:3000": "node1"},
            data={"1.1.1.1:3000": "ok."},
        )
        common = dict(principal="NODE1", self_node="NODE2")

        render = json.loads(
            sheet.render(
                templates.node_info_responses,
                "test",
                sources,
                common=common,
                style=SheetStyle.json,
            )
        )
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["Node"]["converted"], "node1")
