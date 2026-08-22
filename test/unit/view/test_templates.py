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


class InfoNamespaceUsageIndexFormattersTests(unittest.TestCase):
    """Covers the Used% alert tiers for the Primary/Secondary Index subgroups
    of 'info namespace usage', rendered through the real sheet pipeline so
    formatter precedence is exercised: yellow when eviction is running, red
    when near the mounts/memory budget (TOOLS-3456)."""

    def render_usage(self, used_pct, evict_pct):
        node = "127.0.0.1:3000"
        budget = 100 * 1024**3
        used_bytes = int(budget * used_pct / 100)
        sources = dict(
            node_names={node: "node-A"},
            node_ids={node: "BB9040011AC4202"},
            ns_stats={
                node: {
                    "test": {
                        "index-type": "flash",
                        "index-type.mounts-budget": budget,
                        "index-type.evict-mounts-pct": evict_pct,
                        "index_used_bytes": used_bytes,
                        "index_mounts_used_pct": used_pct,
                        "sindex-type": "flash",
                        "sindex-type.mounts-budget": budget,
                        "sindex-type.evict-mounts-pct": evict_pct,
                        "sindex_used_bytes": used_bytes,
                        "sindex_mounts_used_pct": used_pct,
                    }
                }
            },
            service_stats={node: {}},
        )
        common = dict(principal="BB9040011AC4202")

        render = sheet.render(
            templates.info_namespace_usage_sheet,
            "Namespace Usage Information",
            sources,
            common=common,
            style=SheetStyle.json,
        )
        return json.loads(render)["groups"][0]["records"][0]

    @parameterized.expand(
        [
            (50, 80, None),  # healthy
            (85, 80, "yellow-alert"),  # eviction running
            (92, 80, "red-alert"),  # near budget, red wins over yellow
            (92, 0, "red-alert"),  # near budget even with eviction disabled
            (89, 0, None),  # eviction disabled, below red threshold
        ]
    )
    def test_used_pct_alert_tiers(self, used_pct, evict_pct, expected):
        record = self.render_usage(used_pct, evict_pct)

        for subgroup in ("Primary Index", "Secondary Index"):
            entry = record[subgroup]["Used%"]
            self.assertEqual(
                entry.get("format"),
                expected,
                f"{subgroup} Used%={used_pct} Evict%={evict_pct}",
            )

    @parameterized.expand(["shmem", "pmem", "flash"])
    def test_physical_alloc_by_backing_rendered(self, backing):
        node = "127.0.0.1:3000"
        sources = dict(
            node_names={node: "node-A"},
            node_ids={node: "BB9040011AC4202"},
            ns_stats={
                node: {
                    "test": {
                        "index-type": backing,
                        "index_{}_alloc_bytes".format(backing): 1073741824,
                        "index_{}_alloc_pct".format(backing): 100,
                        "sindex-type": backing,
                        "sindex_{}_alloc_bytes".format(backing): 536870912,
                        "sindex_{}_alloc_pct".format(backing): 50,
                    }
                }
            },
            service_stats={node: {}},
        )
        record = json.loads(
            sheet.render(
                templates.info_namespace_usage_sheet,
                "Namespace Usage Information",
                sources,
                common=dict(principal="BB9040011AC4202"),
                style=SheetStyle.json,
            )
        )["groups"][0]["records"][0]

        self.assertEqual(record["Primary Index"]["Alloc"]["raw"], 1073741824)
        self.assertEqual(record["Primary Index"]["Alloc%"]["raw"], 100)
        self.assertEqual(record["Secondary Index"]["Alloc"]["raw"], 536870912)
        self.assertEqual(record["Secondary Index"]["Alloc%"]["raw"], 50)


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


MEMORY_NODE = "127.0.0.1:3000"


def _render_memory(template, sources):
    sources = dict(
        node_names={MEMORY_NODE: "node-A"},
        node_ids={MEMORY_NODE: "BB9040011AC4202"},
        **sources,
    )
    rendered = sheet.render(
        template,
        "T",
        sources,
        common=dict(principal="BB9040011AC4202"),
        style=SheetStyle.json,
    )
    return json.loads(rendered)["groups"][0]["records"][0]


class InfoMemoryHeadlineSheetTest(unittest.TestCase):
    def render(self, **stats):
        return _render_memory(
            templates.info_memory_headline_sheet, dict(stats={MEMORY_NODE: stats})
        )

    def test_free_pct_alert_tiers(self):
        for free_pct, expected in (
            (5, "red-alert"),
            (9.9, "red-alert"),
            (10, "yellow-alert"),
            (19.9, "yellow-alert"),
            (20, None),
            (75, None),
        ):
            record = self.render(alloc_pct="50.0", free_pct=str(free_pct))
            self.assertEqual(record["Free%"].get("format"), expected, free_pct)

    def test_alloc_pct_never_alerts(self):
        for alloc_pct in (1, 50, 99, 150):
            record = self.render(alloc_pct=str(alloc_pct), free_pct="50")
            self.assertIsNone(record["Alloc%"].get("format"), alloc_pct)

    def test_allocated_subgroup_projects_each_component(self):
        record = self.render(
            capacity_bytes="1000",
            allocated_bytes="500",
            allocated_shmem_bytes="300",
            allocated_heap_bytes="200",
            allocated_heap_pct="40.0",
            alloc_pct="50.0",
            free_pct="50",
        )

        self.assertEqual(record["Capacity"]["raw"], 1000)
        self.assertEqual(record["Allocated"]["Total"]["raw"], 500)
        self.assertEqual(record["Allocated"]["Shmem"]["raw"], 300)
        self.assertEqual(record["Allocated"]["Heap"]["raw"], 200)
        self.assertEqual(record["Allocated"]["Heap%"]["raw"], 40.0)
        self.assertEqual(record["Alloc%"]["raw"], 50.0)


class InfoMemoryHostSheetTest(unittest.TestCase):
    def render(self, stats, configs=None):
        return _render_memory(
            templates.info_memory_sheet,
            dict(stats={MEMORY_NODE: stats}, configs={MEMORY_NODE: configs or {}}),
        )

    def test_free_sys_pct_alert_tiers(self):
        for free_pct, expected in ((5, "red-alert"), (10, "yellow-alert"), (20, None)):
            record = self.render({"system_free_mem_pct": str(free_pct)})
            self.assertEqual(record["Free"]["Sys%"].get("format"), expected, free_pct)

    def test_thp_alerts_when_non_zero(self):
        self.assertEqual(
            self.render({"system_thp_mem_bytes": "4096"})["THP"].get("format"),
            "yellow-alert",
        )
        self.assertIsNone(
            self.render({"system_thp_mem_bytes": "0"})["THP"].get("format")
        )

    def test_cgroup_subgroup_carries_tracking_and_effective_limit(self):
        record = self.render(
            {
                "cgroup_memory_used_bytes": "500",
                "cgroup_memory_limit_effective_bytes": "1000",
                "cgroup_memory_used_pct": "50.0",
                "host_total_mem_bytes": "2000",
            },
            configs={"cgroup-mem-tracking": "true"},
        )

        self.assertEqual(record["CGroup"]["Tracking"]["raw"], "true")
        self.assertEqual(record["CGroup"]["Used"]["raw"], 500)
        self.assertEqual(record["CGroup"]["Limit"]["raw"], 1000)
        self.assertEqual(record["CGroup"]["Used%"]["raw"], 50.0)
        self.assertEqual(record["Host Total"]["raw"], 2000)

    def test_free_subgroup_fields(self):
        record = self.render(
            {
                "system_free_mem_bytes": "100",
                "system_free_mem_pct": "50",
                "host_free_mem_bytes": "200",
                "host_free_mem_pct": "60",
            }
        )

        self.assertEqual(record["Free"]["System"]["raw"], 100)
        self.assertEqual(record["Free"]["Sys%"]["raw"], 50)
        self.assertEqual(record["Free"]["Host"]["raw"], 200)
        self.assertEqual(record["Free"]["Host%"]["raw"], 60)


class InfoMemoryProcessSheetTest(unittest.TestCase):
    def render(self, **stats):
        return _render_memory(
            templates.info_memory_process_sheet, dict(stats={MEMORY_NODE: stats})
        )

    def test_heap_efficiency_alert_tiers(self):
        for eff_pct, expected in (
            (5, "red-alert"),
            (49.9, "red-alert"),
            (50, "yellow-alert"),
            (59.9, "yellow-alert"),
            (60, None),
        ):
            record = self.render(heap_efficiency_pct=str(eff_pct))
            self.assertEqual(record["Heap"]["Eff%"].get("format"), expected, eff_pct)

    def test_heap_subgroup_fields(self):
        record = self.render(
            process_rss_bytes="4000",
            heap_allocated_bytes="1000",
            heap_active_bytes="2000",
            heap_mapped_bytes="3000",
            heap_efficiency_pct="80",
        )

        self.assertEqual(record["RSS"]["raw"], 4000)
        self.assertEqual(record["Heap"]["Alloc"]["raw"], 1000)
        self.assertEqual(record["Heap"]["Active"]["raw"], 2000)
        self.assertEqual(record["Heap"]["Mapped"]["raw"], 3000)


class InfoMemoryIndexSheetTest(unittest.TestCase):
    def test_each_subgroup_pairs_its_own_alloc_and_used(self):
        record = _render_memory(
            templates.info_memory_index_sheet,
            dict(
                ns_agg={
                    MEMORY_NODE: {
                        "total_alloc_bytes": "1000",
                        "total_used_bytes": "900",
                        "pi_alloc_bytes": "100",
                        "index_used_bytes": "90",
                        "si_alloc_bytes": "200",
                        "sindex_used_bytes": "190",
                        "set_alloc_bytes": "300",
                        "set_index_used_bytes": "290",
                        "data_alloc_bytes": "400",
                        "data_in_memory_used_bytes": "330",
                    }
                }
            ),
        )

        for subgroup, (alloc, used) in {
            "Total": (1000, 900),
            "Primary Index": (100, 90),
            "Secondary Index": (200, 190),
            "Set Index": (300, 290),
            "Data": (400, 330),
        }.items():
            self.assertEqual(record[subgroup]["Alloc"]["raw"], alloc, subgroup)
            self.assertEqual(record[subgroup]["Used"]["raw"], used, subgroup)
