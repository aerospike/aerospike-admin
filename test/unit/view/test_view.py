# Copyright 2013-2025 Aerospike, Inc.
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

import io
from contextlib import redirect_stdout
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
            description="To see individual users metrics run 'show users statistics <username>'",
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

   1.   Cluster Name             :  test-cluster
   2.   Server Version           :  7.0.0.0
   3.   OS Version               :  Linux 4.15.0-106-generic
   4.   Cluster Size             :  1
   5.   Devices                  :  Total 2, per-node 2
   6.   Pmem Index               :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   7.   Flash Index              :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   8.   Shmem Index              :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   9.   Memory                   :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B) includes data, pindex, and sindex
   10.  Memory                   :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   11.  Device                   :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   12.  Pmem                     :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   13.  License Usage            :  Latest (2023-10-04T20:35:42+00:00): 2.000 B  Min: 3.000 B  Max: 4.000 B  Avg: 5.000 B 
   14.  Active Namespaces        :  2 of 2
   15.  Active Features          :  Compression, Depression

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
   1.   Devices                  :  Total 2, per-node 2
   2.   Pmem Index               :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   3.   Flash Index              :  Total 2.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   4.   Shmem Index              :  Total 3.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   5.   Memory                   :  Total 4.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B) includes data, pindex, and sindex
   6.   Memory                   :  Total 5.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   7.   Device                   :  Total 6.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   8.   Pmem                     :  Total 7.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   9.   License Usage            :  Latest (2023-10-04T20:35:42+00:00): 2.000 B  Min: 3.000 B  Max: 4.000 B  Avg: 5.000 B 
   10.  Replication Factor       :  1
   11.  Post-Write-Queue Hit-Rate:  1.000  
   12.  Rack-aware               :  True
   13.  Master Objects           :  2.000  
   14.  Compression-ratio        :  0.5

   {terminal.fg_red()}bar{terminal.fg_clear()}
   ===
   1.   Devices                  :  Total 2, per-node 2 (number differs across nodes)
   2.   Pmem Index               :  Total 1.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   3.   Flash Index              :  Total 2.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   4.   Shmem Index              :  Total 3.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B)
   5.   Memory                   :  Total 4.000 B, 4.00% used (2.000 B), 5.00% available (3.000 B) includes data, pindex, and sindex
   6.   Memory                   :  Total 5.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   7.   Device                   :  Total 6.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   8.   Pmem                     :  Total 7.000 B, 4.00% used (2.000 B), 5.00% available contiguous space (3.000 B)
   9.   License Usage            :  Latest (2023-10-04T20:35:42+00:00): 2.000 B  Min: 3.000 B  Max: 4.000 B  Avg: 5.000 B 
   10.  Replication Factor       :  1
   11.  Post-Write-Queue Hit-Rate:  1.000  
   12.  Rack-aware               :  False
   13.  Master Objects           :  2.000  
   14.  Compression-ratio        :  0.5
"""

        actual = CliView._summary_namespace_list_view(ns_data)
        actual_str = []

        for line in actual:
            lines = str(line).split("\n")
            actual_str.extend(lines)

        self.assertListEqual(actual_str, expected.split("\n"))

    def test_info_namespace_usage_server_7_0_with_mounts(self):
        """Test namespace usage view for server 7.0+ with mounts-budget metrics"""
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "index-type.mounts-budget": "2000000",
                    "indexes-memory-budget": "1000000",
                    "index-type.mounts-size-limit": "4000000",
                    "index_used_bytes": "1500000",
                    "index_mounts_used_pct": "75",
                    "sindex-type.mounts-budget": "1000000",
                    "sindex_used_bytes": "600000",
                    "sindex_mounts_used_pct": "60",
                    "storage-engine": "device",
                    "index-type": "flash",
                    "sindex-type": "flash"
                }
            }
        }
        service_stats = {"1.1.1.1": {}}
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "NODE1"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
            "service_stats": service_stats
        }
        common = {"principal": principal}

        CliView.info_namespace_usage(
            ns_stats, service_stats, self.cluster_mock, timestamp="test-stamp"
        )

        self.render_mock.assert_called_with(
            templates.info_namespace_usage_sheet,
            "Namespace Usage Information (test-stamp)",
            sources,
            common=common,
        )

    def test_info_namespace_usage_server_7_1_memory_only(self):
        """Test namespace usage view for server 7.1 memory-only configuration"""
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "indexes-memory-budget": "1000000",
                    "index-type.mounts-size-limit": "4000000",
                    "index_used_bytes": "800000",
                    "sindex_used_bytes": "200000",
                    "storage-engine": "memory",
                    "index-type": "shmem",
                    "sindex-type": "shmem"
                }
            }
        }
        service_stats = {"1.1.1.1": {}}
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "NODE1"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
            "service_stats": service_stats
        }
        common = {"principal": principal}

        CliView.info_namespace_usage(
            ns_stats, service_stats, self.cluster_mock, timestamp="test-stamp"
        )

        self.render_mock.assert_called_with(
            templates.info_namespace_usage_sheet,
            "Namespace Usage Information (test-stamp)",
            sources,
            common=common,
        )

    def test_info_namespace_usage_server_pre_7_0_legacy(self):
        """Test namespace usage view for pre-7.0 servers with legacy metrics only"""
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "index-type.mounts-size-limit": "2000000",
                    "sindex-type.mounts-size-limit": "1000000",
                    "memory_used_index_bytes": "600000",
                    "memory_used_sindex_bytes": "300000",
                    "storage-engine": "memory",
                    "index-type": "shmem",
                    "sindex-type": "shmem"
                }
            }
        }
        service_stats = {"1.1.1.1": {}}
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "NODE1"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
            "service_stats": service_stats
        }
        common = {"principal": principal}

        CliView.info_namespace_usage(
            ns_stats, service_stats, self.cluster_mock, timestamp="test-stamp"
        )

        self.render_mock.assert_called_with(
            templates.info_namespace_usage_sheet,
            "Namespace Usage Information (test-stamp)",
            sources,
            common=common,
        )

    def test_info_namespace_usage_mixed_metrics_priority(self):
        """Test namespace usage view with mixed metrics to verify template handles priority"""
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "index-type.mounts-budget": "1500000",
                    "indexes-memory-budget": "1000000",
                    "index-type.mounts-size-limit": "2000000",
                    "sindex-type.mounts-budget": "800000",
                    "sindex-type.mounts-size-limit": "1200000",
                    "index_used_bytes": "1125000",
                    "sindex_used_bytes": "480000",
                    "index_mounts_used_pct": "75",
                    "sindex_mounts_used_pct": "60",
                    "memory_used_index_bytes": "900000",
                    "memory_used_sindex_bytes": "400000",
                    "storage-engine": "device",
                    "index-type": "flash",
                    "sindex-type": "flash"
                }
            }
        }
        service_stats = {"1.1.1.1": {}}
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "NODE1"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
            "service_stats": service_stats
        }
        common = {"principal": principal}

        CliView.info_namespace_usage(
            ns_stats, service_stats, self.cluster_mock, timestamp="test-stamp"
        )

        self.render_mock.assert_called_with(
            templates.info_namespace_usage_sheet,
            "Namespace Usage Information (test-stamp)",
            sources,
            common=common,
        )

    def test_info_namespace_usage_partial_metrics(self):
        """Test namespace usage view with partial metrics (some missing)"""
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "index_used_bytes": "500000",
                    "sindex_used_bytes": "200000",
                    "storage-engine": "memory",
                    "index-type": "shmem",
                    "sindex-type": "shmem"
                    # Missing budget metrics
                }
            }
        }
        service_stats = {"1.1.1.1": {}}
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "NODE1"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
            "service_stats": service_stats
        }
        common = {"principal": principal}

        CliView.info_namespace_usage(
            ns_stats, service_stats, self.cluster_mock, timestamp="test-stamp"
        )

        self.render_mock.assert_called_with(
            templates.info_namespace_usage_sheet,
            "Namespace Usage Information (test-stamp)",
            sources,
            common=common,
        )

    def test_info_namespace_usage_server_8_1_enhanced(self):
        """Test namespace usage view for hypothetical server 8.1+ with enhanced metrics"""
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "index-type.mounts-budget": "3000000",
                    "indexes-memory-budget": "2000000",
                    "index_used_bytes": "2250000",
                    "index_mounts_used_pct": "75",
                    "sindex-type.mounts-budget": "1500000",
                    "sindex_used_bytes": "900000",
                    "sindex_mounts_used_pct": "60",
                    "storage-engine": "device",
                    "index-type": "pmem",
                    "sindex-type": "pmem"
                }
            }
        }
        service_stats = {"1.1.1.1": {}}
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "NODE1"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
            "service_stats": service_stats
        }
        common = {"principal": principal}

        CliView.info_namespace_usage(
            ns_stats, service_stats, self.cluster_mock, timestamp="test-stamp"
        )

        self.render_mock.assert_called_with(
            templates.info_namespace_usage_sheet,
            "Namespace Usage Information (test-stamp)",
            sources,
            common=common,
        )

    def test_info_namespace_usage_empty_namespace_data(self):
        """Test namespace usage view with empty namespace data"""
        ns_stats = {"1.1.1.1": {}}
        service_stats = {"1.1.1.1": {}}
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "NODE1"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
            "service_stats": service_stats
        }
        common = {"principal": principal}

        CliView.info_namespace_usage(
            ns_stats, service_stats, self.cluster_mock, timestamp="test-stamp"
        )

        self.render_mock.assert_called_with(
            templates.info_namespace_usage_sheet,
            "Namespace Usage Information (test-stamp)",
            sources,
            common=common,
        )

    def test_info_namespace_usage_actual_output_pre_7_0(self):
        """End-to-end test: verify actual output of info_namespace_usage for pre-7.0 (division) case."""

        ns_stats_pre = {
            "1.1.1.1": {
                "test": {
                    "index_flash_used_bytes": "250000", 
                    "sindex_flash_used_bytes": "500000",
                    "index-type.mounts-size-limit": "1000000",
                    "memory_used_index_bytes": "300000",
                    "sindex-type.mounts-size-limit": "1000000",
                    "memory_used_sindex_bytes": "100000",
                    "storage-engine": "memory",
                    "index-type": "shmem",
                    "sindex-type": "shmem"
                }
            }
        }
        service_stats = {"1.1.1.1": {}}
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "NODE1"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        patch.stopall()

        f = io.StringIO()
        with redirect_stdout(f):
            CliView.info_namespace_usage(
                ns_stats_pre, service_stats, self.cluster_mock, timestamp="test-stamp"
            )
        output = f.getvalue()

        self.assertIn("Namespace Usage Information (test-stamp)", output)
        self.assertIn("test", output)
        self.assertIn("node1", output)
        self.assertIn("244.141 KB", output) # index used bytes
        self.assertIn("488.281 KB", output) # sindex used bytes
        self.assertIn("25.0 %", output) # index used %
        self.assertIn("50.0 %", output) # sindex used %

    def test_info_namespace_usage_actual_output_post_7_0(self):
        """End-to-end test: verify actual output of info_namespace_usage for post-7.0 (percentage) case."""
        
        ns_stats_post = {
            "2.2.2.2": {
                "test": {
                    "index-type.mounts-budget": "1000000",
                    "index_used_bytes": "300000",
                    "index_mounts_used_pct": "38.46", # flash, pmem, and memory metrics were consolidated in 7.0
                    "sindex-type.mounts-budget": "500000",
                    "sindex_used_bytes": "100000",
                    "sindex_mounts_used_pct": "46.15", # flash, pmem, and memory metrics were consolidated in 7.0
                    "storage-engine": "device",
                    "index-type": "flash",
                    "sindex-type": "flash"
                }
            }
        }
        service_stats_post = {"2.2.2.2": {}}
        node_names_post = {"2.2.2.2": "node2"}
        node_ids_post = {"2.2.2.2": "NODE2"}
        principal_post = "test-principal"

        # Re-mock for new node
        self.cluster_mock = MagicMock()
        self.cluster_mock.get_node_names.return_value = node_names_post
        self.cluster_mock.get_node_ids.return_value = node_ids_post
        self.cluster_mock.get_expected_principal.return_value = principal_post

        patch.stopall()

        f2 = io.StringIO()
        with redirect_stdout(f2):
            CliView.info_namespace_usage(
                ns_stats_post, service_stats_post, self.cluster_mock, timestamp="test-stamp"
            )
        output = f2.getvalue()

        self.assertIn("Namespace Usage Information (test-stamp)", output)
        self.assertIn("test", output)
        self.assertIn("node2", output)
        self.assertIn("292.969 KB", output) # index used bytes
        self.assertIn("97.656 KB", output) # sindex used bytes
        self.assertIn("38.46 %", output) # index used %
        self.assertIn("46.15 %", output) # sindex used %

    def test_info_namespace_usage_in_memory_no_used_pct(self):
        """Test that for in-memory namespaces, if index-type.mounts-size-limit is not present, the Used% column is not rendered for index."""

        ns_stats = {
            "2.2.2.2": {
                "test": {
                    "index-type.mounts-budget": "1000000",
                    "index_used_bytes": "300000",
                    # 'index_mounts_used_pct' is intentionally missing
                    # 'sindex-type.mounts-size-limit' is intentionally missing
                    "sindex_used_bytes": "100000",
                    "storage-engine": "memory",  # explicitly in-memory
                    "index-type": "shmem",
                    "sindex-type": "shmem"
                }
            }
        }
        service_stats = {"2.2.2.2": {}}
        node_names = {"2.2.2.2": "node2"}
        node_ids = {"2.2.2.2": "NODE2"}
        principal = "test-principal"

        self.cluster_mock = MagicMock()
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal

        patch.stopall()

        f = io.StringIO()
        with redirect_stdout(f):
            CliView.info_namespace_usage(
                ns_stats, service_stats, self.cluster_mock, timestamp="test-stamp"
            )
        output = f.getvalue()

        self.assertIn("Namespace Usage Information (test-stamp)", output)
        self.assertIn("test", output)
        self.assertIn("node2", output)
        self.assertIn("292.969 KB", output) # index used bytes
        self.assertIn("97.656 KB", output) # sindex used bytes
        # Should not have a Used% column for sindex
        self.assertNotIn("Used%", output)
        self.assertNotIn("SIndex Used%", output)

    def test_info_transactions_monitors_with_with_modifier(self):
        ns_stats = {
            "1.1.1.1": {
                "test": {"mrt_monitors": 100}
            }
        }
        set_stats = {
            "1.1.1.1": {
                ("test", "<ERO~MRT"): {"data_used_bytes": 1024}
            }
        }
        
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "ABCD"}
        principal = "test-principal"
        
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        
        CliView.info_transactions_monitors(ns_stats, self.cluster_mock, with_=["node1"])
        
        self.cluster_mock.get_node_names.assert_called_once_with(["node1"])
        self.cluster_mock.get_node_ids.assert_called_once_with(["node1"])

    def test_info_transactions_monitors_empty_stats(self):
        ns_stats = None
        
        CliView.info_transactions_monitors(ns_stats, self.cluster_mock)
        
        # Should not call any cluster methods or render when stats are empty
        self.cluster_mock.get_node_names.assert_not_called()
        self.cluster_mock.get_node_ids.assert_not_called()
        self.cluster_mock.get_expected_principal.assert_not_called()
        self.render_mock.assert_not_called()

    @patch('lib.view.view.CliView._get_timestamp_suffix')
    def test_info_transactions_monitors_no_set_stats(self, mock_timestamp):
        mock_timestamp.return_value = " (test-timestamp)"
        
        ns_stats = {
            "1.1.1.1": {
                "test": {"mrt_monitors": 100}
            }
        }
        
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "ABCD"}
        principal = "test-principal"
        
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        
        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
        }
        common = {"principal": principal}
        
        CliView.info_transactions_monitors(ns_stats, self.cluster_mock)
        
        # Should still render but without set data merged
        self.render_mock.assert_called_once_with(
            templates.info_transactions_monitors_sheet,
            "Transaction Monitor Metrics (test-timestamp)",
            sources,
            common=common
        )

    @patch('lib.view.view.CliView._get_timestamp_suffix')
    def test_info_transactions_monitors_node_exception(self, mock_timestamp):
        mock_timestamp.return_value = " (test-timestamp)"
        
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "mrt_monitors": 100,
                    "pseudo_mrt_monitor_used_bytes": 1024,  # Already merged from set stats
                    "stop-writes-count": 0,
                    "stop-writes-size": 0
                }
            },
            "2.2.2.2": Exception("Node error")
        }
        
        node_names = {"1.1.1.1": "node1", "2.2.2.2": "node2"}
        node_ids = {"1.1.1.1": "ABCD", "2.2.2.2": "EFGH"}
        principal = "test-principal"
        
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        
        CliView.info_transactions_monitors(ns_stats, self.cluster_mock)
        
        # Check that render was called with the expected arguments
        self.render_mock.assert_called_once()
        args, kwargs = self.render_mock.call_args
        
        # Verify the title and common data
        self.assertEqual(args[1], "Transaction Monitor Metrics (test-timestamp)")
        self.assertEqual(kwargs.get('common'), {"principal": principal})
        
        # Verify the sources structure
        sources = args[2]
        self.assertEqual(sources["node_ids"], node_ids)
        self.assertEqual(sources["node_names"], node_names)
        
        # Verify the ns_stats structure - should only merge set data for valid nodes
        self.assertEqual(sources["ns_stats"]["1.1.1.1"]["test"]["mrt_monitors"], 100)
        self.assertEqual(sources["ns_stats"]["1.1.1.1"]["test"]["pseudo_mrt_monitor_used_bytes"], 1024)
        self.assertIsInstance(sources["ns_stats"]["2.2.2.2"], Exception)
        self.assertEqual(str(sources["ns_stats"]["2.2.2.2"]), "Node error")

    @patch('lib.view.view.CliView._get_timestamp_suffix')
    def test_info_transactions_monitors_multiple_namespaces_nodes(self, mock_timestamp):
        mock_timestamp.return_value = " (test-timestamp)"

        ns_stats = {
            "1.1.1.1": {
                "strong_ns_1": {
                    "mrt_monitors": 100,
                    "stop-writes-count": 1000,
                    "stop-writes-size": 100000,
                },
                "normal_ns_2": {  # Should be filtered out by controller's get_strong_consistency_namespace
                    "mrt_monitors": 50,
                    "strong-consistency": "false",
                },
            },
            "2.2.2.2": {
                "strong_ns_1": {
                    "mrt_monitors": 150,
                    "stop-writes-count": 1500,
                    "stop-writes-size": 150000,
                },
                "strong_ns_3": {
                    "mrt_monitors": 200,
                    "stop-writes-count": 2000,
                    "stop-writes-size": 200000,
                },
            },
            "3.3.3.3": Exception("Node down"),  # Node with exception
        }

        # Mock the info_set_statistics call that happens in the controller
        # This simulates the controller already filtering for strong consistency namespaces
        self.cluster_mock.info_set_statistics.side_effect = [
            # For strong_ns_1
            {
                "1.1.1.1": {"strong_ns_1": {"data_used_bytes": 1024, "stop-writes-count": 50, "stop-writes-size": 1000}},
                "2.2.2.2": {"strong_ns_1": {"data_used_bytes": 2048, "stop-writes-count": 75, "stop-writes-size": 2000}},
            },
            # For strong_ns_3
            {
                "2.2.2.2": {"strong_ns_3": {"data_used_bytes": 3072, "stop-writes-count": 100, "stop-writes-size": 3000}},
            },
        ]
        
        node_names = {"1.1.1.1": "node1", "2.2.2.2": "node2", "3.3.3.3": "node3"}
        node_ids = {"1.1.1.1": "ABCD", "2.2.2.2": "EFGH", "3.3.3.3": "IJKL"}
        principal = "test-principal"
        
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        self.cluster_mock.info_namespace_statistics.side_effect = [
            {"1.1.1.1": {"strong_ns_1": {"strong-consistency": "true", "mrt_monitors": 100, "stop-writes-count": 1000, "stop-writes-size": 100000}, "normal_ns_2": {"strong-consistency": "false", "mrt_monitors": 50}}},
            {"2.2.2.2": {"strong_ns_1": {"strong-consistency": "true", "mrt_monitors": 150, "stop-writes-count": 1500, "stop-writes-size": 150000}, "strong_ns_3": {"strong-consistency": "true", "mrt_monitors": 200, "stop-writes-count": 2000, "stop-writes-size": 200000}}},
            Exception("Node down"), # for node 3.3.3.3
        ]
        self.cluster_mock.info_namespaces.return_value = {
            "1.1.1.1": ["strong_ns_1", "normal_ns_2"],
            "2.2.2.2": ["strong_ns_1", "strong_ns_3"],
        }
        
        # Simulate the output of the controller's get_strong_consistency_namespace and subsequent set data merging
        final_ns_stats_for_view = {
            "1.1.1.1": {
                "strong_ns_1": {
                    "mrt_monitors": 100,
                    "stop-writes-count": 50, # Merged from set_stats
                    "stop-writes-size": 1000, # Merged from set_stats
                    "pseudo_mrt_monitor_used_bytes": 1024, # Merged from set_stats
                },
            },
            "2.2.2.2": {
                "strong_ns_1": {
                    "mrt_monitors": 150,
                    "stop-writes-count": 75, # Merged from set_stats
                    "stop-writes-size": 2000, # Merged from set_stats
                    "pseudo_mrt_monitor_used_bytes": 2048, # Merged from set_stats
                },
                "strong_ns_3": {
                    "mrt_monitors": 200,
                    "stop-writes-count": 100, # Merged from set_stats
                    "stop-writes-size": 3000, # Merged from set_stats
                    "pseudo_mrt_monitor_used_bytes": 3072, # Merged from set_stats
                },
            },
            "3.3.3.3": Exception("Node down"),
        }
    
        CliView.info_transactions_monitors(final_ns_stats_for_view, self.cluster_mock)
    
        self.render_mock.assert_called_once()
        args, kwargs = self.render_mock.call_args
    
        sources = args[2]
    
        # Verify that only strong consistency namespaces are in ns_stats and set data is merged
        self.assertIn("strong_ns_1", sources["ns_stats"]["1.1.1.1"])
        self.assertNotIn("normal_ns_2", sources["ns_stats"]["1.1.1.1"])
        self.assertEqual(sources["ns_stats"]["1.1.1.1"]["strong_ns_1"]["pseudo_mrt_monitor_used_bytes"], 1024)
        self.assertEqual(sources["ns_stats"]["1.1.1.1"]["strong_ns_1"]["stop-writes-count"], 50)
        self.assertEqual(sources["ns_stats"]["1.1.1.1"]["strong_ns_1"]["stop-writes-size"], 1000)

        self.assertIn("strong_ns_1", sources["ns_stats"]["2.2.2.2"])
        self.assertIn("strong_ns_3", sources["ns_stats"]["2.2.2.2"])
        self.assertEqual(sources["ns_stats"]["2.2.2.2"]["strong_ns_1"]["pseudo_mrt_monitor_used_bytes"], 2048)
        self.assertEqual(sources["ns_stats"]["2.2.2.2"]["strong_ns_3"]["pseudo_mrt_monitor_used_bytes"], 3072)
        
        # Verify that the node exception is preserved
        self.assertIsInstance(sources["ns_stats"]["3.3.3.3"], Exception)

    @patch('lib.view.view.CliView._get_timestamp_suffix')
    def test_info_transactions_monitors_set_data_variations(self, mock_timestamp):
        mock_timestamp.return_value = " (test-timestamp)"

        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "mrt_monitors": 100,
                    "stop-writes-count": 1000,
                    "stop-writes-size": 100000,
                }
            }
        }

        # Using a list for side_effect to run multiple scenarios sequentially
        set_data_scenarios = [
            # Scenario 1: missing data_used_bytes, stop-writes-count, stop-writes-size
            {"1.1.1.1": {("test", "<ERO~MRT"): {}}},
            # Scenario 2: non-numeric data_used_bytes, stop-writes-count, stop-writes-size
            {"1.1.1.1": {("test", "<ERO~MRT"): {"data_used_bytes": "abc", "stop-writes-count": "def", "stop-writes-size": "ghi"}}},
            # Scenario 3: None for data_used_bytes, stop-writes-count, stop-writes-size
            {"1.1.1.1": {("test", "<ERO~MRT"): {"data_used_bytes": None, "stop-writes-count": None, "stop-writes-size": None}}},
            # Scenario 4: all data present and valid
            {"1.1.1.1": {("test", "<ERO~MRT"): {"data_used_bytes": 500, "stop-writes-count": 60, "stop-writes-size": 700}}},
        ]

        self.cluster_mock.info_set_statistics.side_effect = set_data_scenarios

        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "ABCD"}
        principal = "test-principal"

        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        self.cluster_mock.info_namespaces.return_value = {"1.1.1.1": ["test"]}
        self.cluster_mock.info_namespace_statistics.return_value = {
            "1.1.1.1": {"test": {"strong-consistency": "true", "mrt_monitors": 100, "stop-writes-count": 1000, "stop-writes-size": 100000}}
        }

        # Run all scenarios in sequence and assert expectations
        expected_values = [
            (0, 0, 0),  # Scenario 1
            (0, 0, 0),  # Scenario 2
            (0, 0, 0),  # Scenario 3
            (500, 60, 700), # Scenario 4
        ]

        for i, expected_val_tuple in enumerate(expected_values):
            with self.subTest(scenario=i):
                # Because side_effect is a list, each call to info_set_statistics gets the next item in the list.
                # We need to re-mock the base ns_stats for each subtest or it will carry over from previous ones
                # However, CliView doesn't call info_set_statistics, the controller does.
                # So, for this view test, we need to manually inject the expected merged data into ns_stats.
                # Since the controller is now fixed, we can simulate its output more directly.
                simulated_ns_stats_after_controller_merge = {
                    "1.1.1.1": {
                        "test": {
                            "mrt_monitors": ns_stats["1.1.1.1"]["test"]["mrt_monitors"],
                            "stop-writes-count": expected_val_tuple[1], # Overridden by set_stats if present/valid
                            "stop-writes-size": expected_val_tuple[2], # Overridden by set_stats if present/valid
                            "pseudo_mrt_monitor_used_bytes": expected_val_tuple[0], # Added by set_stats if present/valid
                        }
                    }
                }

                CliView.info_transactions_monitors(simulated_ns_stats_after_controller_merge, self.cluster_mock)
                args, kwargs = self.render_mock.call_args
                rendered_ns_stats = args[2]["ns_stats"]["1.1.1.1"]["test"]

                # All values should default to 0 if missing or non-numeric
                self.assertEqual(rendered_ns_stats.get("pseudo_mrt_monitor_used_bytes"), expected_val_tuple[0])
                self.assertEqual(rendered_ns_stats.get("stop-writes-count"), expected_val_tuple[1])
                self.assertEqual(rendered_ns_stats.get("stop-writes-size"), expected_val_tuple[2])

    def test_info_transactions_provisionals(self):
        ns_stats = {
            "1.1.1.1": {
                "test": {
                    "mrt_provisionals": 50,
                    "fail_mrt_blocked": 5,
                    "fail_mrt_version_mismatch": 2,
                    "mrt_verify_read_success": 40,
                    "mrt_verify_read_error": 1,
                    "mrt_roll_back_success": 30,
                    "mrt_roll_back_error": 2,
                    "mrt_roll_forward_success": 35,
                    "mrt_roll_forward_error": 1,
                }
            },
            "2.2.2.2": {
                "test": {
                    "mrt_provisionals": 75,
                    "fail_mrt_blocked": 8,
                    "fail_mrt_version_mismatch": 3,
                    "mrt_verify_read_success": 60,
                    "mrt_verify_read_error": 2,
                    "mrt_roll_back_success": 45,
                    "mrt_roll_back_error": 3,
                    "mrt_roll_forward_success": 50,
                    "mrt_roll_forward_error": 2,
                }
            }
        }
        
        node_names = {"1.1.1.1": "node1", "2.2.2.2": "node2"}
        node_ids = {"1.1.1.1": "ABCD", "2.2.2.2": "EFGH"}
        principal = "test-principal"
        
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        
        sources = {
            "node_ids": node_ids,
            "node_names": node_names,
            "ns_stats": ns_stats,
        }
        common = {"principal": principal}
        
        CliView.info_transactions_provisionals(ns_stats, self.cluster_mock, timestamp="test-stamp")
        
        self.cluster_mock.get_node_names.assert_called_once_with(None)
        self.cluster_mock.get_node_ids.assert_called_once_with(None)
        self.cluster_mock.get_expected_principal.assert_called_once()
        
        self.render_mock.assert_called_once_with(
            templates.info_transactions_provisionals_sheet,
            "Transaction Provisionals Metrics (test-stamp)",
            sources,
            common=common
        )

    def test_info_transactions_provisionals_with_with_modifier(self):
        ns_stats = {
            "1.1.1.1": {
                "test": {"mrt_provisionals": 50}
            }
        }
        
        node_names = {"1.1.1.1": "node1"}
        node_ids = {"1.1.1.1": "ABCD"}
        principal = "test-principal"
        
        self.cluster_mock.get_node_names.return_value = node_names
        self.cluster_mock.get_node_ids.return_value = node_ids
        self.cluster_mock.get_expected_principal.return_value = principal
        
        CliView.info_transactions_provisionals(ns_stats, self.cluster_mock, with_=["node1"])
        
        self.cluster_mock.get_node_names.assert_called_once_with(["node1"])
        self.cluster_mock.get_node_ids.assert_called_once_with(["node1"])

    def test_info_transactions_provisionals_empty_stats(self):
        ns_stats = None
        
        CliView.info_transactions_provisionals(ns_stats, self.cluster_mock)
        
        # Should not call any cluster methods or render when stats are empty
        self.cluster_mock.get_node_names.assert_not_called()
        self.cluster_mock.get_node_ids.assert_not_called()
        self.cluster_mock.get_expected_principal.assert_not_called()
        self.render_mock.assert_not_called()