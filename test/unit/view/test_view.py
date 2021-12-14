# Copyright 2013-2021 Aerospike, Inc.
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
from mock import patch

from lib.view import templates
from lib.view.view import CliView
from lib.view.sheet.const import SheetStyle
from lib.live_cluster.client.node import ASInfoError


class CliViewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.live_cluster_root_controller.Cluster"
        ).start()
        self.sheet_mock = patch("lib.view.sheet.render").start()

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

        self.sheet_mock.assert_called_with(
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
            **{"for": "ba", "with": ["foo"]}
        )

        self.cluster_mock.get_node_names.assert_called_with(["foo"])
        self.cluster_mock.get_node_ids.assert_called_with(["foo"])
        self.sheet_mock.assert_called_with(
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
            **{"with": ["bar"]}
        )

        self.cluster_mock.get_node_names.assert_called_with(["bar"])
        self.cluster_mock.get_node_ids.assert_called_with(["bar"])
        self.sheet_mock.assert_called_with(
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
            "4.4.4.4": ASInfoError("test", "error"),
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
            **{"trid": ["1", "3", "5"], "like": ["foo"], "with": ["bar"]}
        )

        self.cluster_mock.get_node_names.assert_called_with(["bar"])
        self.cluster_mock.get_node_ids.assert_called_with(["bar"])
        self.sheet_mock.assert_called_with(
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

        self.sheet_mock.assert_called_with(
            templates.show_racks,
            "Racks (test-stamp)",
            sources,
        )
