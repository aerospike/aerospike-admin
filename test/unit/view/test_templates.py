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
from lib.view.sheet.decleration import EntryData


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
