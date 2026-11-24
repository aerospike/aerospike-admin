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
import json
import time
import unittest

from parameterized import parameterized

from lib.utils import common, usage_export

CLUSTER = "3f2b8c1e-9a4d-4e7b-8c21-5d6f7a8b9c0d"


def ns_hash(name, cluster=CLUSTER):
    return hashlib.sha256((cluster + name).encode()).hexdigest()[:16]


def sample(date, slot, rows, nodes=3, reported=3, migrating=False, names=None):
    names = names or ["ns%d" % i for i in range(len(rows))]

    return {
        "data": {
            "cluster": CLUSTER,
            "date": date,
            "feature_key_serial": "123456789",
            "migrating": migrating,
            "nodes": nodes,
            "nodes_reported": reported,
            "rows": [
                {"data_used": used, "ns": ns_hash(name), "ratio": ratio, "rf": rf}
                for name, (used, ratio, rf) in zip(names, rows)
            ],
            "schema": 1,
            "slot": slot,
            "time": "%sT%02d:00:05Z" % (date, (slot - 1) * 8),
        }
    }


def record(date, samples):
    return {"data": {"cluster": CLUSTER, "date": date, "samples": samples, "schema": 1}}


def export(records=(), feature_key=None):
    return {
        "data": {
            "cluster": CLUSTER,
            "feature_key": (
                {"account-ID": "12345", "account-name": "Acme Corp"}
                if feature_key is None
                else feature_key
            ),
            "records": list(records),
            "schema": 1,
            "taken": "2026-10-04T10:15:02Z",
        }
    }


def document(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class ParseTest(unittest.TestCase):
    def test_returns_the_data_object(self):
        self.assertEqual(usage_export.parse(document(export())), export()["data"])

    @parameterized.expand(
        [
            ("not_json", b"eyJkYXRhIjp7"),
            ("not_utf8", b"\xff\xfe"),
            ("a_list", b"[]"),
            ("no_data", b'{"records":[]}'),
            ("data_not_an_object", b'{"data":[]}'),
        ]
    )
    def test_refuses_what_is_not_an_export(self, _, value):
        with self.assertRaises(ValueError):
            usage_export.parse(value)


class AccountTest(unittest.TestCase):
    @parameterized.expand(
        [
            (
                "name_and_id",
                {"account-name": "Acme Corp", "account-ID": "12345"},
                "Acme Corp (12345)",
            ),
            ("name_only", {"account-name": "Acme Corp"}, "Acme Corp"),
            ("id_only", {"account-ID": "12345"}, "12345"),
            ("neither", {"serial-number": "1"}, ""),
        ]
    )
    def test_names_the_account_from_the_feature_key(self, _, feature_key, expected):
        self.assertEqual(
            usage_export.account(export(feature_key=feature_key)["data"]), expected
        )


class DaysTest(unittest.TestCase):
    def test_no_closed_day(self):
        self.assertEqual(usage_export.days(export()["data"]), "none closed yet")

    def test_one_day(self):
        data = export([record("2026-10-03", [])])["data"]

        self.assertEqual(usage_export.days(data), "2026-10-03, 1 day")

    def test_range_counts_the_days_recorded_not_the_calendar_span(self):
        data = export(
            [
                record("2026-10-05", []),
                record("2026-10-01", []),
                record("2026-10-02", []),
            ]
        )["data"]

        self.assertEqual(usage_export.days(data), "2026-10-01 to 2026-10-05, 3 days")


class SampleRowsTest(unittest.TestCase):
    def test_one_row_per_sample_oldest_first(self):
        data = export(
            [
                record(
                    "2026-10-03",
                    [
                        sample("2026-10-03", 3, [(10, 1000, 1)]),
                        sample("2026-10-03", 1, [(10, 1000, 1)]),
                    ],
                ),
                record("2026-10-02", [sample("2026-10-02", 2, [(10, 1000, 1)])]),
            ]
        )["data"]

        self.assertEqual(
            [(row["date"], row["time"]) for row in usage_export.sample_rows(data)],
            [
                ("2026-10-02", "08:00:05"),
                ("2026-10-03", "00:00:05"),
                ("2026-10-03", "16:00:05"),
            ],
        )

    def test_carries_the_sample_fields_as_the_server_sent_them(self):
        data = export(
            [
                record(
                    "2026-10-03",
                    [
                        sample(
                            "2026-10-03",
                            1,
                            [(100, 1000, 2), (300, 1000, 2)],
                            nodes=5,
                            reported=4,
                            migrating=True,
                        )
                    ],
                )
            ]
        )["data"]

        row = usage_export.sample_rows(data)[0]

        self.assertEqual(row["date"], "2026-10-03")
        self.assertEqual(row["time"], "00:00:05")
        self.assertEqual(row["nodes"], 5)
        self.assertEqual(row["nodes_reported"], 4)
        self.assertIs(row["migrating"], True)
        self.assertEqual(row["data_used"], 400)

    def test_license_usage_uses_the_contract_formula(self):
        rows = [(1234567890123, 512, 2), (98730000000, 1000, 2)]
        data = export([record("2026-10-03", [sample("2026-10-03", 1, rows)])])["data"]

        expected = sum(used / rf / (ratio / 1000) for used, ratio, rf in rows)

        self.assertAlmostEqual(
            usage_export.sample_rows(data)[0]["license_usage"], expected, places=3
        )

    @parameterized.expand([("zero_ratio", (10, 0, 2)), ("zero_rf", (10, 1000, 0))])
    def test_license_usage_is_unknown_when_a_row_cannot_be_divided(self, _, bad_row):
        data = export(
            [record("2026-10-03", [sample("2026-10-03", 1, [(10, 1000, 1), bad_row])])]
        )["data"]

        self.assertIsNone(usage_export.sample_rows(data)[0]["license_usage"])

    def test_no_records_no_rows(self):
        self.assertEqual(usage_export.sample_rows(export()["data"]), [])


class LatestSampleTest(unittest.TestCase):
    def test_the_newest_sample_of_the_newest_day(self):
        data = export(
            [
                record("2026-10-03", [sample("2026-10-03", 2, [(1, 1000, 1)])]),
                record(
                    "2026-10-02",
                    [
                        sample("2026-10-02", 3, [(2, 1000, 1)]),
                        sample("2026-10-02", 1, [(3, 1000, 1)]),
                    ],
                ),
            ]
        )["data"]

        self.assertEqual(
            usage_export.latest_sample(data)["time"], "2026-10-03T08:00:05Z"
        )

    def test_none_without_a_closed_day(self):
        self.assertIsNone(usage_export.latest_sample(export()["data"]))


class NamespaceRowsTest(unittest.TestCase):
    def rows(self, namespaces):
        latest = sample(
            "2026-10-03",
            3,
            [(1234698765432, 513, 2), (125000000000, 996, 3)],
            names=["test", "bar"],
        )["data"]

        return {
            row["namespace"]: row
            for row in usage_export.namespace_rows(latest, namespaces)
        }

    def test_names_each_namespace_the_cluster_knows(self):
        self.assertEqual(sorted(self.rows(["bar", "test", "other"])), ["bar", "test"])

    def test_a_namespace_it_cannot_name_keeps_its_hash(self):
        self.assertEqual(sorted(self.rows(["test"])), sorted([ns_hash("bar"), "test"]))

    def test_carries_the_inputs_and_the_license_usage(self):
        row = self.rows(["test", "bar"])["test"]

        self.assertEqual(row["rf"], 2)
        self.assertEqual(row["ratio"], 0.513)
        self.assertEqual(row["data_used"], 1234698765432)
        self.assertAlmostEqual(
            row["license_usage"], 1234698765432 / 2 / 0.513, places=3
        )

    def test_a_row_that_cannot_be_divided_has_no_license_usage(self):
        latest = sample("2026-10-03", 1, [(10, 0, 2)], names=["test"])["data"]

        self.assertIsNone(
            usage_export.namespace_rows(latest, ["test"])[0]["license_usage"]
        )


class NsHashTest(unittest.TestCase):
    @parameterized.expand([("test", "864f21805ef85437"), ("bar", "79f7abd171e32b56")])
    def test_matches_the_servers_hash(self, name, expected):
        self.assertEqual(usage_export.ns_hash(CLUSTER, name), expected)


class DisplayTimeTest(unittest.TestCase):
    def test_shows_utc_the_way_asadm_titles_do(self):
        self.assertEqual(
            usage_export.display_time("2026-10-04T10:15:02Z"), "2026-10-04 10:15:02 UTC"
        )

    def test_leaves_a_value_it_cannot_read_as_it_is(self):
        self.assertEqual(usage_export.display_time("soon"), "soon")


class UsageFilePathTest(unittest.TestCase):
    TS = time.strptime("20261004_101502", "%Y%m%d_%H%M%S")

    @parameterized.expand(
        [
            ("no_prefix", "", "/tmp/collect_usage_20261004_101502.tgz"),
            ("prefix", "acme", "/tmp/acme_collect_usage_20261004_101502.tgz"),
            (
                "prefix_with_dash",
                "acme-",
                "/tmp/acme-collect_usage_20261004_101502.tgz",
            ),
            (
                "prefix_with_underscore",
                "acme_",
                "/tmp/acme_collect_usage_20261004_101502.tgz",
            ),
        ]
    )
    def test_names_the_file_like_collect_info_names_its_directory(
        self, _, prefix, expected
    ):
        self.assertEqual(common.get_usage_file_path(self.TS, prefix), expected)
