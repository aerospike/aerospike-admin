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

import unittest
from parameterized import parameterized

from lib.view import templates
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
