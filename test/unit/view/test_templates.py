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
