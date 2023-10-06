# Copyright 2013-2023 Aerospike, Inc.
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

import datetime
import unittest
from mock import MagicMock, call, patch
from lib.utils.common import SummaryClusterDict, SummaryNamespacesDict

from lib.view import templates, terminal
from lib.view.view import CliView
from lib.view.sheet.const import SheetStyle
from lib.live_cluster.client.node import ASInfoResponseError


class CliViewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.live_cluster_root_controller.Cluster"
        ).start()
        self.render_mock = patch("lib.view.sheet.render").start()
        self.print_result_mock = patch("lib.view.view.CliView.print_result").start()
        self.addCleanup(patch.stopall)

    def test_show_roster(self):
        roster_data = {
            "1.1.1.1": {
                "test": {
                    "observed_nodes": [
                        "BB9070016AE4202",
                        "BB9060016AE4202",
                        "BB9050016AE4202",
                        "BB9040016AE4202",
                        "BB9020016AE4202",
                    ],
                    "ns": "test",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                }
            }
        }
        node_names = {"1.1.1.1": "1.1.1.1 is my name"}
        node_ids = {"1.1.1.1": "ABCD"}
        principal = "test-principal"
        common = {"principal": principal}
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        sources = {"node_names": node_names, "node_ids": node_ids, "data": roster_data}

        CliView.show_roster(
            roster_data, self.cluster_mock, flip=False, timestamp="test-stamp", **{}
        )

        self.render_mock.assert_called_with(
            templates.show_roster,
            "Roster (test-stamp)",
            sources,
            common=common,
            style=SheetStyle.columns,
            dynamic_diff=False,
        )

    def test_show_roster_with_mods(self):
        roster_data = {
            "1.1.1.1": {
                "test": {
                    "observed_nodes": [
                        "BB9070016AE4202",
                        "BB9060016AE4202",
                        "BB9050016AE4202",
                        "BB9040016AE4202",
                        "BB9020016AE4202",
                    ],
                    "ns": "test",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                },
                "bar": {
                    "observed_nodes": [
                        "BB90120016AE4202",
                        "BB90110016AE4202",
                        "BB90100016AE4202",
                        "BB9090016AE4202",
                        "BB9080016AE4202",
                    ],
                    "ns": "bar",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                },
            },
            "2.2.2.2": {
                "test": {
                    "observed_nodes": [
                        "BB9070016AE4202",
                        "BB9060016AE4202",
                        "BB9050016AE4202",
                        "BB9040016AE4202",
                        "BB9020016AE4202",
                    ],
                    "ns": "test",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                },
                "bar": {
                    "observed_nodes": [
                        "BB90120016AE4202",
                        "BB90110016AE4202",
                        "BB90100016AE4202",
                        "BB9090016AE4202",
                        "BB9080016AE4202",
                    ],
                    "ns": "bar",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                },
            },
        }
        filtered_data = {
            "1.1.1.1": {
                "bar": {
                    "observed_nodes": [
                        "BB90120016AE4202",
                        "BB90110016AE4202",
                        "BB90100016AE4202",
                        "BB9090016AE4202",
                        "BB9080016AE4202",
                    ],
                    "ns": "bar",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                },
            },
            "2.2.2.2": {
                "bar": {
                    "observed_nodes": [
                        "BB90120016AE4202",
                        "BB90110016AE4202",
                        "BB90100016AE4202",
                        "BB9090016AE4202",
                        "BB9080016AE4202",
                    ],
                    "ns": "bar",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                },
            },
        }

        node_names = {"1.1.1.1": "1.1.1.1 is my name", "2.2.2.2": "2.2.2.2 is my name"}
        node_ids = {"1.1.1.1": "ABCD", "2.2.2.2": "EFGH"}
        principal = "test-principal"
        common = {"principal": principal}
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        sources = {
            "node_names": node_names,
            "node_ids": node_ids,
            "data": filtered_data,
        }

        CliView.show_roster(
            roster_data,
            self.cluster_mock,
            flip=True,
            timestamp="test-stamp",
            **{"for": "ba", "with": ["foo"]},
        )

        self.cluster_mock.get_node_names.assert_called_with(["foo"])
        self.cluster_mock.get_node_ids.assert_called_with(["foo"])
        self.render_mock.assert_called_with(
            templates.show_roster,
            "Roster (test-stamp)",
            sources,
            common=common,
            style=SheetStyle.rows,
            dynamic_diff=False,
        )

    def test_show_best_practices(self):
        failed_practices = "foo"
        timestamp = "timestamp"
        self.cluster_mock.get_node_names.return_value = "node_names"
        self.cluster_mock.get_node_ids.return_value = "node_ids"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        sources = {
            "data": failed_practices,
            "node_names": "node_names",
            "node_ids": "node_ids",
        }
        common = {"principal": "principal"}

        CliView.show_best_practices(
            self.cluster_mock,
            failed_practices,
            timestamp=timestamp,
            **{"with": ["bar"]},
        )

        self.cluster_mock.get_node_names.assert_called_with(["bar"])
        self.cluster_mock.get_node_ids.assert_called_with(["bar"])
        self.render_mock.assert_called_with(
            templates.show_best_practices,
            "Best Practices (timestamp)",
            sources,
            common=common,
        )

    def test_show_jobs(self):
        jobs_data = {
            "1.1.1.1": {"1": "1 data", "2": "2 data"},
            "2.2.2.2": {"3": "3 data", "4": "4 data"},
            "3.3.3.3": {"5": "5 data", "6": "6 data"},
            "4.4.4.4": ASInfoResponseError("test", "error"),
        }
        filtered_data = {
            "1.1.1.1": {"1": "1 data"},
            "2.2.2.2": {"3": "3 data"},
            "3.3.3.3": {"5": "5 data"},
        }
        timestamp = "timestamp"
        self.cluster_mock.get_node_names.return_value = "node_names"
        self.cluster_mock.get_node_ids.return_value = "node_ids"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        sources = {
            "data": filtered_data,
            "node_names": "node_names",
            "node_ids": "node_ids",
        }
        common = {"principal": "principal"}

        CliView.show_jobs(
            "Jobs",
            self.cluster_mock,
            jobs_data,
            timestamp=timestamp,
            **{"trid": ["1", "3", "5"], "like": ["foo"], "with": ["bar"]},
        )

        self.cluster_mock.get_node_names.assert_called_with(["bar"])
        self.cluster_mock.get_node_ids.assert_called_with(["bar"])
        self.render_mock.assert_called_with(
            templates.show_jobs,
            "Jobs (timestamp)",
            sources,
            common=common,
            selectors=["foo"],
        )

    def test_show_racks(self):
        racks_data = {
            "1.1.1.1": {
                "test": {
                    "0": {
                        "rack-id": "0",
                        "nodes": [
                            "BB9060016AE4202",
                            "BB9050016AE4202",
                            "BB9040016AE4202",
                        ],
                    }
                }
            }
        }
        sources = {
            "data": {
                "1.1.1.1": {
                    ("test", "0"): {
                        "rack-id": "0",
                        "nodes": [
                            "BB9060016AE4202",
                            "BB9050016AE4202",
                            "BB9040016AE4202",
                        ],
                    }
                }
            }
        }

        CliView.show_racks(racks_data, timestamp="test-stamp", **{})

        self.render_mock.assert_called_with(
            templates.show_racks,
            "Racks (test-stamp)",
            sources,
        )

    def test_show_stop_writes(self):
        racks_data = {"1.1.1.1": {"test": "data"}}
        sources = {
            "node_names": {"1.1.1.1": "node-name"},
            "stop_writes": {"1.1.1.1": {"test": "data"}},
        }
        self.cluster_mock.get_node_names.return_value = {"1.1.1.1": "node-name"}

        CliView.show_stop_writes(racks_data, self.cluster_mock, timestamp="test-stamp", **{})  # type: ignore

        self.render_mock.assert_called_with(
            templates.show_stop_writes_sheet,
            "Stop Writes (test-stamp)",
            sources,
            description="Show all stop writes - add 'for <namespace> [<set>]' for a shorter list.",
        )

    def test_show_xdr_ns_config(self):
        configs = {
            "[::1]:3001": {
                "DC1": {
                    "test": {
                        "enabled": "true",
                    }
                },
                "DC2": {
                    "bar": {
                        "enabled": "true",
                    }
                },
            },
        }
        self.cluster_mock.get_node_names.return_value = "node_names"
        self.cluster_mock.get_node_ids.return_value = "node_ids"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        test_sources = {
            "data": {
                "[::1]:3001": {
                    "DC1": {
                        "enabled": "true",
                    }
                }
            },
            "node_names": "node_names",
            "node_ids": "node_ids",
        }
        bar_sources = {
            "data": {
                "[::1]:3001": {
                    "DC2": {
                        "enabled": "true",
                    }
                }
            },
            "node_names": "node_names",
            "node_ids": "node_ids",
        }
        self.render_mock.return_value = "table"

        CliView.show_xdr_ns_config(
            configs, self.cluster_mock, timestamp="test-stamp", flip_output=True
        )

        self.render_mock.assert_has_calls(
            [
                call(
                    templates.show_xdr_ns_sheet,
                    "XDR bar Namespace Configuration (test-stamp)",
                    bar_sources,
                    selectors=None,
                    style=SheetStyle.columns,
                    title_repeat=False,
                    dynamic_diff=False,
                    disable_aggregations=True,
                    common={"principal": "principal"},
                ),
                call(
                    templates.show_xdr_ns_sheet,
                    "XDR test Namespace Configuration (test-stamp)",
                    test_sources,
                    selectors=None,
                    style=SheetStyle.columns,
                    title_repeat=False,
                    dynamic_diff=False,
                    disable_aggregations=True,
                    common={"principal": "principal"},
                ),
            ],
            any_order=False,
        )
        self.print_result_mock.assert_called()

    def test_show_xdr_ns_stats_by_ns(self):
        stats = {
            "[::1]:3001": {
                "DC1": {
                    "test": {
                        "enabled": "true",
                    }
                },
                "DC2": {
                    "bar": {
                        "enabled": "true",
                    }
                },
            },
        }
        self.cluster_mock.get_node_names.return_value = "node_names"
        self.cluster_mock.get_node_ids.return_value = "node_ids"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        test_sources = {
            "data": {
                "[::1]:3001": {
                    "DC1": {
                        "enabled": "true",
                    }
                }
            },
            "node_names": "node_names",
            "node_ids": "node_ids",
        }
        bar_sources = {
            "data": {
                "[::1]:3001": {
                    "DC2": {
                        "enabled": "true",
                    }
                }
            },
            "node_names": "node_names",
            "node_ids": "node_ids",
        }
        self.render_mock.return_value = "table"

        CliView.show_xdr_ns_stats(
            stats, self.cluster_mock, timestamp="test-stamp", flip_output=True
        )

        self.render_mock.assert_has_calls(
            [
                call(
                    templates.show_xdr_ns_sheet,
                    "XDR bar Namespace Statistics (test-stamp)",
                    bar_sources,
                    selectors=None,
                    style=SheetStyle.columns,
                    title_repeat=False,
                    disable_aggregations=True,
                    common={"principal": "principal"},
                ),
                call(
                    templates.show_xdr_ns_sheet,
                    "XDR test Namespace Statistics (test-stamp)",
                    test_sources,
                    selectors=None,
                    style=SheetStyle.columns,
                    title_repeat=False,
                    disable_aggregations=True,
                    common={"principal": "principal"},
                ),
            ],
            any_order=False,
        )
        self.print_result_mock.assert_called()

    def test_show_xdr_ns_stats_by_dc(self):
        stats = {
            "[::1]:3001": {
                "DC1": {
                    "test": {
                        "enabled": "true",
                    }
                },
                "DC2": {
                    "bar": {
                        "enabled": "true",
                    }
                },
            },
        }
        self.cluster_mock.get_node_names.return_value = "node_names"
        self.cluster_mock.get_node_ids.return_value = "node_ids"
        self.cluster_mock.get_expected_principal.return_value = "principal"
        dc1_sources = {
            "data": {
                "[::1]:3001": {
                    "test": {
                        "enabled": "true",
                    }
                }
            },
            "node_names": "node_names",
            "node_ids": "node_ids",
        }
        dc2_sources = {
            "data": {
                "[::1]:3001": {
                    "bar": {
                        "enabled": "true",
                    }
                }
            },
            "node_names": "node_names",
            "node_ids": "node_ids",
        }
        self.render_mock.return_value = "table"

        CliView.show_xdr_ns_stats(
            stats,
            self.cluster_mock,
            timestamp="test-stamp",
            flip_output=True,
            by_dc=True,
        )

        self.render_mock.assert_has_calls(
            [
                call(
                    templates.show_xdr_ns_sheet_by_dc,
                    "XDR DC1 DC Namespace Statistics (test-stamp)",
                    dc1_sources,
                    selectors=None,
                    style=SheetStyle.columns,
                    title_repeat=False,
                    disable_aggregations=True,
                    common={"principal": "principal"},
                ),
                call(
                    templates.show_xdr_ns_sheet_by_dc,
                    "XDR DC2 DC Namespace Statistics (test-stamp)",
                    dc2_sources,
                    selectors=None,
                    style=SheetStyle.columns,
                    title_repeat=False,
                    disable_aggregations=True,
                    common={"principal": "principal"},
                ),
            ],
            any_order=False,
        )
        self.print_result_mock.assert_called()

    @patch("lib.view.view.CliView.show_config")
    def test_show_dc_config(self, show_config_mock: MagicMock):
        configs = {
            "[::1]:3001": {
                "DC1": {
                    "enabled": "true",
                },
                "DC2": {
                    "enabled": "true",
                },
            },
        }
        dc1_sources = {
            "[::1]:3001": {
                "enabled": "true",
            }
        }
        dc2_sources = {
            "[::1]:3001": {
                "enabled": "true",
            }
        }

        CliView.show_xdr_dc_config(
            configs, self.cluster_mock, timestamp="test-stamp", flip_output=True
        )

        show_config_mock.assert_has_calls(
            [
                call(
                    "XDR DC1 DC Configuration",
                    dc1_sources,
                    self.cluster_mock,
                    like=None,
                    diff=False,
                    with_=None,
                    show_total=False,
                    title_every_nth=0,
                    flip_output=True,
                    timestamp="test-stamp",
                ),
                call(
                    "XDR DC2 DC Configuration",
                    dc2_sources,
                    self.cluster_mock,
                    like=None,
                    diff=False,
                    with_=None,
                    show_total=False,
                    title_every_nth=0,
                    flip_output=True,
                    timestamp="test-stamp",
                ),
            ],
            any_order=False,
        )

    @patch("lib.view.view.CliView.show_config")
    def test_show_xdr_filters(self, show_config_mock: MagicMock):
        filters = {
            "[::1]:3001": {
                "DC1": {
                    "test": {
                        "enabled": "true",
                    }
                },
                "DC2": {
                    "bar": {
                        "enabled": "true",
                    }
                },
            },
        }
        formatted_filters = {
            "[::1]:3001": {
                ("DC1", "test"): {
                    "enabled": "true",
                },
                ("DC2", "bar"): {
                    "enabled": "true",
                },
            }
        }

        CliView.show_xdr_filters(filters, timestamp="test-stamp", flip_output=True)

        self.render_mock.assert_called_with(
            templates.show_xdr_filters,
            "XDR Filters (test-stamp)",
            dict(data=formatted_filters),
            selectors=None,
            style=SheetStyle.rows,
            title_repeat=False,
            dynamic_diff=False,
        )

    def test_show_users(self):
        users_data = {
            "admin": {"admin": "data"},
            "bob": {"bob": "data"},
        }
        formatted_users = {
            0: {"admin": {"admin": "data"}},
            1: {
                "bob": {"bob": "data"},
            },
        }

        CliView.show_users(users_data, timestamp="test-stamp")

        self.render_mock.assert_called_with(
            templates.show_users,
            "Users (test-stamp)",
            dict(data=formatted_users),
            description="To see individual users metrics run 'show user statistics'",
        )

    def test_show_users_stats(self):
        users_data = {
            0: {"admin": {"admin": "data"}},
            1: {
                "bob": {"bob": "data"},
            },
        }
        node_names = {"1.1.1.1": "1.1.1.1 is my name"}
        node_ids = {"1.1.1.1": "ABCD"}
        principal = "test-principal"
        common = {"principal": principal}
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        sources = {"data": users_data, "node_names": node_names, "node_ids": node_ids}

        CliView.show_users_stats(self.cluster_mock, users_data, timestamp="test-stamp")

        self.render_mock.assert_called_with(
            templates.show_users_stats,
            "Users Statistics (test-stamp)",
            sources,
            common=common,
        )

    def test_summary_cluster_list_view(self):
        cluster_data: SummaryClusterDict = {
            "active_features": ["Compression"],
            "ns_count": 1,
            "migrations_in_progress": True,
            "cluster_name": ["test-cluster"],
            "server_version": ["7.0.0.0"],
            "os_version": ["Linux 4.15.0-106-generic"],
            "cluster_size": [1],
            "device_count": 2,
            "device_count_per_node": 2,
            "device_count_same_across_nodes": True,
            "pmem_index": {
                "total": 1,
                "used": 2,
                "avail": 3,
                "used_pct": 4,
                "avail_pct": 5,
            },
            "flash_index": {
                "total": 1,
                "used": 2,
                "avail": 3,
                "used_pct": 4,
                "avail_pct": 5,
            },
            "shmem_index": {
                "total": 1,
                "used": 2,
                "avail": 3,
                "used_pct": 4,
                "avail_pct": 5,
            },
            "memory_data_and_indexes": {
                "total": 1,
                "used": 2,
                "avail": 3,
                "used_pct": 4,
                "avail_pct": 5,
            },
            "memory": {
                "total": 1,
                "used": 2,
                "avail": 3,
                "used_pct": 4,
                "avail_pct": 5,
            },
            "device": {
                "total": 1,
                "used": 2,
                "avail": 3,
                "used_pct": 4,
                "avail_pct": 5,
            },
            "pmem": {
                "total": 1,
                "used": 2,
                "avail": 3,
                "used_pct": 4,
                "avail_pct": 5,
            },
            "license_data": {
                "latest_time": datetime.datetime.fromtimestamp(
                    1696451742, tz=datetime.timezone.utc
                ),
                "latest": 2,
                "min": 3,
                "max": 4,
                "avg": 5,
            },
            "active_ns": 2,
            "ns_count": 2,
            "active_features": ["Compression", "Depression"],
        }
        expected = f"""Cluster  ({terminal.fg_red()}Migrations in Progress{terminal.fg_clear()})
=================================

   1.   Cluster Name       :  test-cluster
   2.   Server Version     :  7.0.0.0
   3.   OS Version         :  Linux 4.15.0-106-generic
   4.   Cluster Size       :  1
   5.   Devices            :  Total 2, per-node 2
   6.   Pmem Index         :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   7.   Flash Index        :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   8.   Shmem Index        :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   9.   Memory             :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B) includes data, pindex, and sindex
   10.  Memory             :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   11.  Device             :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   12.  Pmem               :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   13.  License Usage      :  Latest (2023-10-04T20:35:42+00:00): 2.000 B  Min: 3.000 B  Max: 4.000 B  Avg: 5.000 B 
   14.  Active Namespaces  :  2 of 2
   15.  Active Features    :  Compression, Depression

"""

        actual = CliView._summary_cluster_list_view(cluster_data)
        actual_str = []

        for line in actual:
            lines = str(line).split("\n")
            actual_str.extend(lines)

        self.assertListEqual(actual_str, expected.split("\n"))

    def test_summary_namespace_list_view(self):
        ns_data: SummaryNamespacesDict = {
            "test": {
                "devices_total": 2,
                "devices_per_node": 2,
                "device_count_same_across_nodes": True,
                "repl_factor": [1],
                "master_objects": 2,
                "migrations_in_progress": True,
                "rack_aware": True,
                "pmem_index": {
                    "total": 1,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "flash_index": {
                    "total": 2,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "shmem_index": {
                    "total": 3,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "memory_data_and_indexes": {
                    "total": 4,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "memory": {
                    "total": 5,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "device": {
                    "total": 6,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "pmem": {
                    "total": 7,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "license_data": {
                    "latest_time": datetime.datetime.fromtimestamp(
                        1696451742, tz=datetime.timezone.utc
                    ),
                    "latest": 2,
                    "min": 3,
                    "max": 4,
                    "avg": 5,
                },
                "cache_read_pct": 1,
                "rack_aware": True,
                "master_objects": 2,
                "compression_ratio": 0.5,
            },
            "bar": {
                "devices_total": 2,
                "devices_per_node": 2,
                "device_count_same_across_nodes": False,
                "repl_factor": [1],
                "master_objects": 2,
                "migrations_in_progress": False,
                "pmem_index": {
                    "total": 1,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "flash_index": {
                    "total": 2,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "shmem_index": {
                    "total": 3,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "memory_data_and_indexes": {
                    "total": 4,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "memory": {
                    "total": 5,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "device": {
                    "total": 6,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "pmem": {
                    "total": 7,
                    "used": 2,
                    "avail": 3,
                    "used_pct": 4,
                    "avail_pct": 5,
                },
                "license_data": {
                    "latest_time": datetime.datetime.fromtimestamp(
                        1696451742, tz=datetime.timezone.utc
                    ),
                    "latest": 2,
                    "min": 3,
                    "max": 4,
                    "avg": 5,
                },
                "cache_read_pct": 1,
                "rack_aware": False,
                "master_objects": 2,
                "compression_ratio": 0.5,
            },
        }
        expected = f"""Namespaces
==========

   {terminal.fg_red()}test{terminal.fg_clear()}
   ====
   1.   Devices            :  Total 2, per-node 2
   2.   Pmem Index         :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   3.   Flash Index        :  Total 2.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   4.   Shmem Index        :  Total 3.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   5.   Memory             :  Total 4.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B) includes data, pindex, and sindex
   6.   Memory             :  Total 5.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   7.   Device             :  Total 6.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   8.   Pmem               :  Total 7.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   9.   License Usage      :  Latest (2023-10-04T20:35:42+00:00): 2.000 B  Min: 3.000 B  Max: 4.000 B  Avg: 5.000 B 
   10.  Replication Factor :  1
   11.  Post-Write-Queue Hit-Rate:  1.000  
   12.  Rack-aware         :  True
   13.  Master Objects     :  2.000  
   14.  Compression-ratio  :  0.5

   {terminal.fg_red()}bar{terminal.fg_clear()}
   ===
   1.   Devices            :  Total 2, per-node 2 (number differs across nodes)
   2.   Pmem Index         :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   3.   Flash Index        :  Total 2.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   4.   Shmem Index        :  Total 3.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   5.   Memory             :  Total 4.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B) includes data, pindex, and sindex
   6.   Memory             :  Total 5.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   7.   Device             :  Total 6.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   8.   Pmem               :  Total 7.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   9.   License Usage      :  Latest (2023-10-04T20:35:42+00:00): 2.000 B  Min: 3.000 B  Max: 4.000 B  Avg: 5.000 B 
   10.  Replication Factor :  1
   11.  Post-Write-Queue Hit-Rate:  1.000  
   12.  Rack-aware         :  False
   13.  Master Objects     :  2.000  
   14.  Compression-ratio  :  0.5
"""

        actual = CliView._summary_namespace_list_view(ns_data)
        actual_str = []

        for line in actual:
            lines = str(line).split("\n")
            actual_str.extend(lines)

        self.assertListEqual(actual_str, expected.split("\n"))
