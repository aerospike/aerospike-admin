# Copyright 2021-2025 Aerospike, Inc.
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

import copy
import warnings
from pytest import PytestUnraisableExceptionWarning
from mock import patch, MagicMock
from mock.mock import AsyncMock
from lib.base_controller import ShellException
from lib.live_cluster.client.cluster import Cluster

from lib.live_cluster.get_controller import (
    GetAclController,
    GetJobsController,
    GetPmapController,
    GetConfigController,
    GetStatisticsController,
    GetLatenciesController,
    GetUserAgentsController,
    _get_all_dcs,
    _get_all_namespaces,
)
from lib.utils import constants

import unittest


class GetLatenciesControllerTest(unittest.IsolatedAsyncioTestCase):
    latency_return_value = {
        "2.2.2.2": {
            "batch-index": {
                "total": {
                    "columns": ["ops/sec", ">1ms", ">8ms", ">16ms"],
                    "values": [[38.0, 37.05, 40.05, 43.05]],
                },
            },
            "write": {
                "namespace": {
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">16ms"],
                        "values": [[55.0, 56.0, 59.0, 62.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">8ms", ">16ms"],
                    "values": [[74.0, 46.76, 49.76, 52.76]],
                },
            },
        }
    }
    latencies_return_value = {
        "1.1.1.1": {
            "batch-index": {
                "total": {
                    "columns": [
                        "ops/sec",
                        ">1ms",
                        ">2ms",
                        ">4ms",
                        ">8ms",
                        ">16ms",
                    ],
                    "values": [[1.0, 2.0, 3.0, 5.0, 6.0, 7.0]],
                },
            },
            "write": {
                "namespace": {
                    "bar": {
                        "columns": [
                            "ops/sec",
                            ">1ms",
                            ">2ms",
                            ">4ms",
                            ">8ms",
                            ">16ms",
                        ],
                        "values": [[55.0, 56.0, 57.0, 58.0, 59.0, 60.0]],
                    },
                },
                "total": {
                    "columns": [
                        "ops/sec",
                        ">1ms",
                        ">2ms",
                        ">4ms",
                        ">8ms",
                        ">16ms",
                    ],
                    "values": [[61.0, 62.0, 63.0, 64.0, 65.0, 66.0]],
                },
            },
        }
    }

    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = self.cluster_mock = patch(
            "lib.live_cluster.client.cluster.Cluster", AsyncMock()
        ).start()
        # self.cluster_mock.info = AsyncMock()
        self.controller = GetLatenciesController(self.cluster_mock)

    async def test_get_latencies_and_latency_nodes(self):
        self.cluster_mock.info_build.return_value = {
            "1.1.1.1": "4.9.0.3",
            "2.2.2.2": "5.1.0.3",
            "3.3.3.3": "5.0.9.9",
            "4.4.4.4": "5.2.0.0",
            "5.5.5.5": Exception(),
        }
        expected = (["2.2.2.2", "4.4.4.4"], ["1.1.1.1", "3.3.3.3"])
        actual = await self.controller.get_latencies_and_latency_nodes(nodes="1234")

        self.assertCountEqual(expected[0], actual[0])
        self.assertCountEqual(expected[1], actual[1])

    async def test_get_all_latency_only(self):
        self.controller.get_latencies_and_latency_nodes = AsyncMock()
        self.controller.get_latencies_and_latency_nodes.return_value = (
            [],
            ["2.2.2.2"],
        )
        self.maxDiff = None
        self.cluster_mock.info_latency.return_value = self.latency_return_value
        expected = {}
        expected["2.2.2.2"] = {
            "batch-index": {
                "total": {
                    "columns": ["ops/sec", ">1ms", ">8ms", ">16ms"],
                    "values": [[38.0, 37.05, 40.05, 43.05]],
                },
            },
            "write": {
                "namespace": {
                    "bar": {
                        "columns": [
                            "ops/sec",
                            ">1ms",
                            ">8ms",
                            ">16ms",
                        ],
                        "values": [[55.0, 56.0, 59.0, 62.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">8ms", ">16ms"],
                    "values": [[74.0, 46.76, 49.76, 52.76]],
                },
            },
        }

        actual = await self.controller.get_all(
            nodes="nodes", buckets=5, exponent_increment=1, verbose=1, ns_set=None
        )

        self.assertDictEqual(expected, actual)
        self.cluster_mock.info_latency.assert_called_once_with(
            nodes="nodes", ns_set=None
        )
        self.cluster_mock.info_latencies.assert_not_called()

    async def test_get_all_scopes_the_build_query_to_the_requested_nodes(self):
        """The mixed-version branch fans out to the node lists this call returns,
        so an unscoped build query would make a single-node retry re-query the
        whole cluster."""
        self.controller.get_latencies_and_latency_nodes = AsyncMock(
            return_value=([], ["2.2.2.2"])
        )
        self.cluster_mock.info_latency.return_value = self.latency_return_value

        await self.controller.get_all(
            nodes=["2.2.2.2"], buckets=5, exponent_increment=1, verbose=1
        )

        self.controller.get_latencies_and_latency_nodes.assert_awaited_once_with(
            nodes=["2.2.2.2"]
        )

    async def test_get_all_keep_exceptions_preserves_per_node_failures(self):
        self.controller.get_latencies_and_latency_nodes = AsyncMock(
            return_value=(["1.1.1.1"], [])
        )
        exc = Exception("late")
        self.cluster_mock.info_latencies.return_value = {"1.1.1.1": exc}

        kept = await self.controller.get_all(
            nodes="all",
            buckets=5,
            exponent_increment=1,
            verbose=1,
            keep_exceptions=True,
        )

        self.assertIs(kept["1.1.1.1"], exc)

    async def test_get_all_latencies_only(self):
        self.controller.get_latencies_and_latency_nodes = AsyncMock()
        self.controller.get_latencies_and_latency_nodes.return_value = (
            ["1.1.1.1"],
            [],
        )
        self.maxDiff = None
        self.cluster_mock.info_latencies.return_value = self.latencies_return_value
        expected = copy.deepcopy(self.latencies_return_value)

        actual = await self.controller.get_all(
            nodes="nodes", buckets=5, exponent_increment=1, verbose=1, ns_set=None
        )

        self.assertDictEqual(expected, actual)
        self.cluster_mock.info_latency.assert_not_called()
        self.cluster_mock.info_latencies.assert_called_once_with(
            nodes="nodes",
            buckets=5,
            exponent_increment=1,
            verbose=1,
            ns_set=None,
        )

    async def test_get_all_mixed_versions(self):
        self.controller.get_latencies_and_latency_nodes = AsyncMock()
        self.controller.get_latencies_and_latency_nodes.return_value = (
            ["1.1.1.1"],
            ["2.2.2.2"],
        )
        self.maxDiff = None
        self.cluster_mock.info_latencies.return_value = self.latencies_return_value
        self.cluster_mock.info_latency.return_value = self.latency_return_value
        expected = copy.deepcopy(self.latencies_return_value)
        expected["2.2.2.2"] = {
            "batch-index": {
                "total": {
                    "columns": ["ops/sec", ">1ms", ">2ms", ">4ms", ">8ms", ">16ms"],
                    "values": [[38.0, 37.05, "N/A", "N/A", 40.05, 43.05]],
                },
            },
            "write": {
                "namespace": {
                    "bar": {
                        "columns": [
                            "ops/sec",
                            ">1ms",
                            ">2ms",
                            ">4ms",
                            ">8ms",
                            ">16ms",
                        ],
                        "values": [[55.0, 56.0, "N/A", "N/A", 59.0, 62.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">2ms", ">4ms", ">8ms", ">16ms"],
                    "values": [[74.0, 46.76, "N/A", "N/A", 49.76, 52.76]],
                },
            },
        }

        actual = await self.controller.get_all(
            "nodes", buckets=5, exponent_increment=1, verbose=1, ns_set=None
        )

        self.assertDictEqual(expected, actual)
        self.cluster_mock.info_latency.assert_called_once_with(
            nodes=["2.2.2.2"], ns_set=None
        )
        self.cluster_mock.info_latencies.assert_called_once_with(
            nodes=["1.1.1.1"],
            buckets=5,
            exponent_increment=1,
            verbose=1,
            ns_set=None,
        )

    async def test_get_all_mixed_versions_keeps_an_old_server_failure(self):
        """The merge builds an entry for every old-server node from a new-server
        template. Handing it the failure replaced that node's exception with a
        fabricated all-N/A table, so collectinfo recorded no error for a node whose
        latency call never answered."""
        self.controller.get_latencies_and_latency_nodes = AsyncMock(
            return_value=(["1.1.1.1"], ["2.2.2.2"])
        )
        exc = Exception("latency timed out")
        self.cluster_mock.info_latencies.return_value = copy.deepcopy(
            self.latencies_return_value
        )
        self.cluster_mock.info_latency.return_value = {"2.2.2.2": exc}

        kept = await self.controller.get_all(
            "nodes",
            buckets=5,
            exponent_increment=1,
            verbose=1,
            keep_exceptions=True,
        )

        self.assertIs(kept["2.2.2.2"], exc)
        self.assertIn("1.1.1.1", kept)

    async def test_get_all_mixed_versions_keeps_a_new_server_failure(self):
        """A new-server failure used to be picked as the merge template and then
        iterated, aborting the whole latency collection with a TypeError."""
        self.controller.get_latencies_and_latency_nodes = AsyncMock(
            return_value=(["1.1.1.1"], ["2.2.2.2"])
        )
        exc = Exception("latencies timed out")
        self.cluster_mock.info_latencies.return_value = {"1.1.1.1": exc}
        self.cluster_mock.info_latency.return_value = copy.deepcopy(
            self.latency_return_value
        )

        kept = await self.controller.get_all(
            "nodes",
            buckets=5,
            exponent_increment=1,
            verbose=1,
            keep_exceptions=True,
        )

        self.assertIs(kept["1.1.1.1"], exc)
        self.assertEqual(kept["2.2.2.2"], self.latency_return_value["2.2.2.2"])

    async def test_get_all_mixed_versions_drops_failures_by_default(self):
        """The interactive `show` paths must still never see an Exception."""
        self.controller.get_latencies_and_latency_nodes = AsyncMock(
            return_value=(["1.1.1.1"], ["2.2.2.2"])
        )
        self.cluster_mock.info_latencies.return_value = {"1.1.1.1": Exception("nope")}
        self.cluster_mock.info_latency.return_value = {"2.2.2.2": Exception("nope")}

        actual = await self.controller.get_all(
            "nodes", buckets=5, exponent_increment=1, verbose=1
        )

        self.assertDictEqual(actual, {})


class GetControllerStaticHelpersTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = AsyncMock()

    async def test_get_all_dcs(self):
        self.cluster_mock.info_dcs.return_value = {
            "1.1.1.1": ["aaa", "bbb"],
            "2.2.2.2": ["ccc", "bbb"],
        }
        expected = {"aaa", "bbb", "ccc"}

        actual = await _get_all_dcs(self.cluster_mock, "all")

        self.cluster_mock.info_dcs.assert_called_with(nodes="all")

        self.assertSetEqual(actual, expected)

    async def test_get_all_namespaces(self):
        self.cluster_mock.info_namespaces.return_value = {
            "1.1.1.1": ["aaa", "bbb"],
            "2.2.2.2": ["ccc", "bbb"],
        }
        expected = {"aaa", "bbb", "ccc"}

        actual = await _get_all_namespaces(self.cluster_mock, "all")

        self.cluster_mock.info_namespaces.assert_called_with(nodes="all")

        self.assertSetEqual(actual, expected)


class GetStatisticsControllerTest(unittest.IsolatedAsyncioTestCase):
    def mock_info_call(self, cmd, nodes="all"):
        if cmd == "version":
            return {"10.71.71.169:3000": "3.6.0"}

        if cmd == "node":
            return {"10.71.71.169:3000": "BB93039BC7AC40C"}

        if cmd == "partition-info":
            return self.partition_info

        return {}

    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.client.cluster.Cluster", AsyncMock()
        ).start()
        self.partition_info = {}
        self.cluster_mock.info = AsyncMock()
        self.cluster_mock.info.side_effect = self.mock_info_call
        self.controller = GetStatisticsController(self.cluster_mock)

    async def test_get_service_keep_exceptions_preserves_per_node_failures(self):
        """Without this the node whose statistics call failed is dropped from the
        map, and the bundle's meta records errors: [] for a node that failed."""
        exc = Exception("boom")
        self.cluster_mock.info_statistics.return_value = {
            "1.1.1.1": exc,
            "2.2.2.2": {"uptime": "10"},
        }

        kept = await self.controller.get_service(keep_exceptions=True)

        self.assertIs(kept["1.1.1.1"], exc)
        self.assertEqual(kept["2.2.2.2"], {"uptime": "10"})

    async def test_get_service_drops_failures_by_default(self):
        """The interactive show paths must never see an Exception value."""
        self.cluster_mock.info_statistics.return_value = {
            "1.1.1.1": Exception("boom"),
            "2.2.2.2": {"uptime": "10"},
        }

        dropped = await self.controller.get_service()

        self.assertEqual(dropped, {"2.2.2.2": {"uptime": "10"}})

    async def test_get_all_propagates_keep_exceptions_to_the_service_subsection(self):
        """get_all is what collectinfo calls; a keep_exceptions that stops at
        get_all's signature ships bundles whose meta records no error for a node
        whose statistics call failed."""
        exc = Exception("boom")
        self.cluster_mock.info_statistics.return_value = {"1.1.1.1": exc}

        for name in (
            "get_namespace",
            "get_sets",
            "get_bins",
            "get_sindex",
            "get_xdr",
            "get_xdr_dcs",
            "get_xdr_namespaces",
        ):
            patch.object(
                GetStatisticsController, name, AsyncMock(return_value={})
            ).start()
        self.addCleanup(patch.stopall)

        stat_map = await self.controller.get_all(keep_exceptions=True)

        self.assertIs(stat_map[constants.STAT_SERVICE]["1.1.1.1"], exc)

    async def test_get_all_drops_failures_by_default(self):
        self.cluster_mock.info_statistics.return_value = {"1.1.1.1": Exception("boom")}

        for name in (
            "get_namespace",
            "get_sets",
            "get_bins",
            "get_sindex",
            "get_xdr",
            "get_xdr_dcs",
            "get_xdr_namespaces",
        ):
            patch.object(
                GetStatisticsController, name, AsyncMock(return_value={})
            ).start()
        self.addCleanup(patch.stopall)

        stat_map = await self.controller.get_all()

        self.assertEqual(stat_map[constants.STAT_SERVICE], {})

    async def test_get_namespace(self):
        self.cluster_mock.info_namespaces.return_value = {
            "1.1.1.1": ["foo", "bar", ""],
            "2.2.2.2": Exception(),
            "3.3.3.3": ["bbb", "aaa"],
            "4.4.4.4": ["tar", "zip"],
        }

        async def side_effect(namespace, nodes):
            if namespace == "foo":
                return {
                    "1.1.1.1": {"stat1": 1, "stat2": 2},
                    "2.2.2.2": {"stat1": 1, "stat2": 2},
                }
            elif namespace == "bar":
                return {
                    "1.1.1.1": {"stat3": 3, "stat4": 4},
                    "2.2.2.2": {"stat3": 3, "stat4": 4},
                }
            if namespace == "aaa":
                return {
                    "1.1.1.1": {"stat1": 5, "stat2": 5},
                    "2.2.2.2": {"stat1": 6, "stat2": 6},
                }
            elif namespace == "bbb":
                return {
                    "1.1.1.1": {"stat3": 7, "stat4": 7},
                    "2.2.2.2": {"stat3": 7, "stat4": 7},
                }
            elif namespace == "tar":
                return Exception()
            elif namespace == "zip":
                return {"4.4.4.4": Exception()}

            self.fail()

        self.cluster_mock.info_namespace_statistics.side_effect = side_effect
        expected = {
            "1.1.1.1": {
                "foo": {"stat1": 1, "stat2": 2},
                "bar": {"stat3": 3, "stat4": 4},
            },
            "2.2.2.2": {
                "foo": {"stat1": 1, "stat2": 2},
                "bar": {"stat3": 3, "stat4": 4},
            },
        }

        result = await self.controller.get_namespace(for_mods=["foo", "bar"])

        self.assertDictEqual(result, expected)

    async def test_get_namespace_logs_failed_node_and_namespace(self):
        """TOOLS-3596: a node whose namespace stats failed, and a whole namespace that
        failed, are both excluded and logged at DEBUG so the missing data is diagnosable
        instead of vanishing silently."""
        self.cluster_mock.info_namespaces.return_value = {"1.1.1.1": ["foo", "bad"]}

        async def side_effect(namespace, nodes):
            if namespace == "bad":
                return Exception("namespace failed")
            return {
                "1.1.1.1": {"stat1": 1},
                "2.2.2.2": Exception("boom"),
                "3.3.3.3": {},  # empty (non-exception) result -> also excluded
            }

        self.cluster_mock.info_namespace_statistics.side_effect = side_effect

        with self.assertLogs("lib.live_cluster.get_controller", level="DEBUG") as cm:
            result = await self.controller.get_namespace(for_mods=["foo", "bad"])

        # Healthy node kept; failed node, empty node, and failed namespace excluded.
        self.assertDictEqual(result, {"1.1.1.1": {"foo": {"stat1": 1}}})
        # Per-node failure logged.
        self.assertTrue(
            any(
                "2.2.2.2" in msg and "Excluding statistics" in msg for msg in cm.output
            ),
            cm.output,
        )
        # Empty (non-exception) node result also excluded and logged.
        self.assertTrue(
            any(
                "3.3.3.3" in msg and "Excluding statistics" in msg for msg in cm.output
            ),
            cm.output,
        )
        # Whole-namespace failure logged.
        self.assertTrue(
            any(
                "'bad'" in msg and "Failed to get statistics" in msg
                for msg in cm.output
            ),
            cm.output,
        )

    async def test_get_strong_consistency_namespace_logs_failures(self):
        """TOOLS-3596: get_strong_consistency_namespace logs excluded failed nodes and
        failed namespaces, and still filters out non-SC nodes (without logging those).
        """
        self.cluster_mock.info_namespaces.return_value = {"1.1.1.1": ["foo", "bad"]}

        async def side_effect(namespace, nodes):
            if namespace == "bad":
                return Exception("namespace failed")
            return {
                "1.1.1.1": {"strong-consistency": "true", "stat1": 1},
                "2.2.2.2": Exception("boom"),  # failed -> logged + excluded
                "3.3.3.3": {
                    "strong-consistency": "false"
                },  # non-SC -> excluded silently
            }

        self.cluster_mock.info_namespace_statistics.side_effect = side_effect

        with self.assertLogs("lib.live_cluster.get_controller", level="DEBUG") as cm:
            result = await self.controller.get_strong_consistency_namespace(
                for_mods=["foo", "bad"]
            )

        # Only the SC node for the healthy namespace survives.
        self.assertDictEqual(
            result, {"1.1.1.1": {"foo": {"strong-consistency": "true", "stat1": 1}}}
        )
        self.assertTrue(
            any(
                "2.2.2.2" in msg and "Excluding statistics" in msg for msg in cm.output
            ),
            cm.output,
        )
        self.assertTrue(
            any(
                "'bad'" in msg and "Failed to get statistics" in msg
                for msg in cm.output
            ),
            cm.output,
        )

    async def test_get_sets(self):
        self.cluster_mock.info_all_set_statistics.return_value = {
            "1.1.1.1": {
                ("aaa", "sss"): {"stat1": 1, "stat2": 2},
                ("aab", "sst"): {"stat3": 3, "stat4": 4},
                ("abc", "stu"): {"stat3": 5, "stat4": 6},
            },
            "2.2.2.2": {
                ("aaa", "sss"): {"stat1": 1, "stat2": 2},
                ("aab", "sst"): {"stat3": 3, "stat4": 4},
                ("abc", "stu"): {"stat3": 5, "stat4": 6},
            },
        }
        expected = {
            "1.1.1.1": {
                ("aab", "sst"): {"stat3": 3, "stat4": 4},
            },
            "2.2.2.2": {
                ("aab", "sst"): {"stat3": 3, "stat4": 4},
            },
        }

        result = await self.controller.get_sets(for_mods=["ab", "ss"])

        self.assertDictEqual(result, expected)

    async def test_get_xdr(self):
        self.cluster_mock.info_XDR_statistics.return_value = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": Exception(),
        }
        expected = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": {},
        }

        actual = await self.controller.get_xdr()

        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.get_controller._get_all_dcs")
    async def test_get_xdr_dcs_with_filter(self, _get_all_dcs_mock: AsyncMock):
        _get_all_dcs_mock.return_value = ["aaa", "aab", "abc"]
        self.cluster_mock.info_all_dc_statistics.return_value = {
            "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}},
            "2.2.2.2": {"aaa": {"c"}, "aab": Exception()},
            "3.3.3.3": Exception(),
        }
        expected = {
            "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}},
            "2.2.2.2": {"aaa": {"c"}, "aab": {}},
            "3.3.3.3": {},
        }

        actual = await self.controller.get_xdr_dcs(for_mods=["aa"])

        self.cluster_mock.info_all_dc_statistics.assert_called_with(
            nodes="all", dcs=["aaa", "aab"]
        )
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.get_controller._get_all_dcs")
    async def test_get_xdr_dcs(self, _get_all_dcs_mock: AsyncMock):
        _get_all_dcs_mock.return_value = ["aaa", "aab", "abc"]
        self.cluster_mock.info_all_dc_statistics.return_value = {
            "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}},
            "2.2.2.2": {"aaa": {"c"}, "aab": Exception()},
            "3.3.3.3": Exception(),
        }
        expected = {
            "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}},
            "2.2.2.2": {"aaa": {"c"}, "aab": {}},
            "3.3.3.3": {},
        }

        actual = await self.controller.get_xdr_dcs()

        self.cluster_mock.info_all_dc_statistics.assert_called_with(
            nodes="all", dcs=["aaa", "aab", "abc"]
        )
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.get_controller._get_all_dcs")
    @patch("lib.live_cluster.get_controller._get_all_namespaces")
    async def test_get_xdr_namespaces(
        self, _get_all_namespaces: AsyncMock, _get_all_dcs_mock: AsyncMock
    ):
        _get_all_dcs_mock.return_value = ["aaa", "aab", "abc"]
        _get_all_namespaces.return_value = ["test", "test1", "bar"]
        self.cluster_mock.info_all_xdr_namespaces_statistics.return_value = {
            "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": Exception()},
            "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": Exception()}},
            "3.3.3.3": Exception(),
        }
        expected = {
            "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
            "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
            "3.3.3.3": {},
        }

        actual = await self.controller.get_xdr_namespaces()

        self.cluster_mock.info_all_xdr_namespaces_statistics.assert_called_with(
            nodes="all", dcs=["aaa", "aab", "abc"], namespaces=["test", "test1", "bar"]
        )
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.get_controller._get_all_dcs")
    @patch("lib.live_cluster.get_controller._get_all_namespaces")
    async def test_get_xdr_namespaces_with_filter(
        self, _get_all_namespaces: AsyncMock, _get_all_dcs_mock: AsyncMock
    ):
        _get_all_dcs_mock.return_value = ["aaa", "aab", "abc"]
        _get_all_namespaces.return_value = ["test", "test1", "bar"]
        self.cluster_mock.info_all_xdr_namespaces_statistics.return_value = {}

        actual = await self.controller.get_xdr_namespaces(for_mods=["test", "aa"])

        self.cluster_mock.info_all_xdr_namespaces_statistics.assert_called_with(
            nodes="all", dcs=["aaa", "aab"], namespaces=["test", "test1"]
        )
        self.assertDictEqual(actual, {})


class GetPmapControllerTest(unittest.IsolatedAsyncioTestCase):
    def mock_info_call(self, cmd, nodes="all"):
        if cmd == "version":
            return {"10.71.71.169:3000": "3.6.0"}

        if cmd == "node":
            return {"10.71.71.169:3000": "BB93039BC7AC40C"}

        if cmd == "partition-info":
            return self.partition_info

        return {}

    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        cluster_mock = patch(
            "lib.live_cluster.client.cluster.Cluster", AsyncMock()
        ).start()
        self.partition_info = {}
        cluster_mock.info_statistics.return_value = {
            "10.71.71.169:3000": {"cluster_key": "ck"}
        }
        cluster_mock.info_namespaces.return_value = {"10.71.71.169:3000": ["test"]}
        cluster_mock.info_namespace_statistics.return_value = {
            "10.71.71.169:3000": {
                "dead_partitions": "2000",
                "unavailable_partitions": "0",
            }
        }
        cluster_mock.info = AsyncMock()
        cluster_mock.info.side_effect = self.mock_info_call
        self.controller = GetPmapController(cluster_mock)

    async def test_get_pmap_data(self):
        self.partition_info = {
            "10.71.71.169:3000": "test:0:A:2:0:0:0:0:0:0:0:0;test:1:A:2:0:0:0:0:0:0:0:0;"
            "test:2:A:2:0:0:0:0:0:0:0:0;test:3:S:1:0:0:0:0:207069:3001:0:0;"
            "test:4:S:0:0:0:0:0:0:0:0:0;test:4094:S:0:0:0:0:0:206724:2996:0:0;"
            "test:4095:S:0:0:0:0:0:213900:3100:0:0"
        }
        expected_output = {}
        expected_output["10.71.71.169:3000"] = {}
        expected_output["10.71.71.169:3000"]["test"] = {}
        expected_output["10.71.71.169:3000"]["test"]["cluster_key"] = "ck"
        expected_output["10.71.71.169:3000"]["test"]["master_partition_count"] = 3
        expected_output["10.71.71.169:3000"]["test"]["prole_partition_count"] = 1
        expected_output["10.71.71.169:3000"]["test"]["dead_partitions"] = "2000"
        expected_output["10.71.71.169:3000"]["test"]["unavailable_partitions"] = "0"
        actual_output = await self.controller.get_pmap()
        self.assertEqual(expected_output, actual_output)

    async def test_get_pmap_data_with_migrations(self):
        self.partition_info = {
            "10.71.71.169:3000": "test:0:D:1:0:0:0:0:0:0:0:0;test:1:A:2:0:0:0:0:0:0:0:0;"
            "test:2:D:1:0:BB93039BC7AC40C:0:0:0:0:0:0;"
            "test:3:S:1:0:0:0:0:207069:3001:0:0;test:4:S:0:0:0:0:0:0:0:0:0;"
            "test:4094:S:0:BB93039BC7AC40C:0:0:0:206724:2996:0:0;test:4095:S:0:0:0:0:0:213900:3100:0:0"
        }
        expected_output = {}
        expected_output["10.71.71.169:3000"] = {}
        expected_output["10.71.71.169:3000"]["test"] = {}
        expected_output["10.71.71.169:3000"]["test"]["cluster_key"] = "ck"
        expected_output["10.71.71.169:3000"]["test"]["master_partition_count"] = 3
        expected_output["10.71.71.169:3000"]["test"]["prole_partition_count"] = 3
        expected_output["10.71.71.169:3000"]["test"]["dead_partitions"] = "2000"
        expected_output["10.71.71.169:3000"]["test"]["unavailable_partitions"] = "0"
        actual_output = await self.controller.get_pmap()
        self.assertEqual(expected_output, actual_output)

    async def test_get_pmap_data_with_working_master(self):
        self.partition_info = {
            "10.71.71.169:3000": "namespace:partition:state:replica:n_dupl:working_master:emigrates:immigrates:records:tombstones:version:final_version;"
            "test:0:D:1:0:0:0:0:0:0:0:0;test:1:A:2:0:0:0:0:0:0:0:0;"
            "test:2:D:1:0:BB93039BC7AC40C:0:0:0:0:0:0;"
            "test:3:S:1:0:0:0:0:207069:3001:0:0;test:4:S:0:0:0:0:0:0:0:0:0;"
            "test:4094:S:0:BB93039BC7AC40C:0:0:0:206724:2996:0:0;test:4095:S:0:0:0:0:0:213900:3100:0:0"
        }
        expected_output = {}
        expected_output["10.71.71.169:3000"] = {}
        expected_output["10.71.71.169:3000"]["test"] = {}
        expected_output["10.71.71.169:3000"]["test"]["cluster_key"] = "ck"
        expected_output["10.71.71.169:3000"]["test"]["master_partition_count"] = 1
        expected_output["10.71.71.169:3000"]["test"]["prole_partition_count"] = 5
        expected_output["10.71.71.169:3000"]["test"]["dead_partitions"] = "2000"
        expected_output["10.71.71.169:3000"]["test"]["unavailable_partitions"] = "0"
        actual_output = await self.controller.get_pmap()
        self.assertEqual(expected_output, actual_output)


class GetConfigControllerTest(unittest.IsolatedAsyncioTestCase):
    def mock_info_call(self, cmd, nodes="all"):
        if cmd == "version":
            return {"10.71.71.169:3000": "3.6.0"}

        if cmd == "node":
            return {"10.71.71.169:3000": "BB93039BC7AC40C"}

        if cmd == "partition-info":
            return self.partition_info

        return {}

    async def asyncSetUp(self):
        self.cluster_mock = patch(
            "lib.live_cluster.client.cluster.Cluster", AsyncMock()
        ).start()
        self.partition_info = {}
        self.controller = GetConfigController(self.cluster_mock)
        self.addCleanup(patch.stopall)
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

    async def test_get_logging(self):
        self.cluster_mock.info_logging_config.return_value = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": Exception(),
        }
        expected = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": {},
        }

        actual = await self.controller.get_logging()

        self.assertDictEqual(actual, expected)

    async def test_get_service_keep_exceptions_preserves_per_node_failures(self):
        exc = Exception("boom")
        self.cluster_mock.info_get_config.return_value = {"1.1.1.1": exc}

        kept = await self.controller.get_service(keep_exceptions=True)

        self.assertIs(kept["1.1.1.1"], exc)

    async def test_get_service_drops_failures_by_default(self):
        self.cluster_mock.info_get_config.return_value = {
            "1.1.1.1": Exception("boom"),
            "2.2.2.2": {"proto-fd-max": "15000"},
        }

        dropped = await self.controller.get_service()

        self.assertEqual(dropped["1.1.1.1"], {})

    async def test_get_network_keep_exceptions_preserves_per_node_failures(self):
        """network is served by every server, so a failure there is a real
        collection failure and must reach the bundle's meta."""
        exc = Exception("boom")
        self.cluster_mock.info_get_config.return_value = {"1.1.1.1": exc}

        kept = await self.controller.get_network(keep_exceptions=True)

        self.assertIs(kept["1.1.1.1"], exc)

    async def test_get_network_drops_failures_by_default(self):
        self.cluster_mock.info_get_config.return_value = {"1.1.1.1": Exception("boom")}

        dropped = await self.controller.get_network()

        self.assertEqual(dropped["1.1.1.1"], {})

    async def test_get_all_propagates_keep_exceptions_to_service_and_network(self):
        """get_all is what collectinfo calls. Security keeps substituting {} on
        the same run: it legitimately errors on a security-disabled or Community
        Edition cluster, and recording that as a failure would report a healthy
        cluster as a failed collection."""
        service_exc = Exception("service boom")
        network_exc = Exception("network boom")

        async def by_stanza(nodes="all", stanza=None, **kwargs):
            if stanza == "service":
                return {"1.1.1.1": service_exc}
            if stanza == "network":
                return {"1.1.1.1": network_exc}
            if stanza == "security":
                return {"1.1.1.1": Exception("security not supported")}
            return {}

        self.cluster_mock.info_get_config.side_effect = by_stanza

        for name in (
            "get_namespace",
            "get_sets",
            "get_xdr",
            "get_xdr_dcs",
            "get_xdr_namespaces",
            "get_xdr_filters",
            "get_roster",
            "get_racks",
            "get_rack_ids",
            "get_logging",
        ):
            patch.object(GetConfigController, name, AsyncMock(return_value={})).start()

        config_map = await self.controller.get_all(keep_exceptions=True)

        self.assertIs(config_map[constants.CONFIG_SERVICE]["1.1.1.1"], service_exc)
        self.assertIs(config_map[constants.CONFIG_NETWORK]["1.1.1.1"], network_exc)
        self.assertEqual(config_map[constants.CONFIG_SECURITY]["1.1.1.1"], {})

    async def test_get_all_drops_failures_by_default(self):
        async def by_stanza(nodes="all", stanza=None, **kwargs):
            return {"1.1.1.1": Exception("boom")}

        self.cluster_mock.info_get_config.side_effect = by_stanza

        for name in (
            "get_namespace",
            "get_sets",
            "get_xdr",
            "get_xdr_dcs",
            "get_xdr_namespaces",
            "get_xdr_filters",
            "get_roster",
            "get_racks",
            "get_rack_ids",
            "get_logging",
        ):
            patch.object(GetConfigController, name, AsyncMock(return_value={})).start()

        config_map = await self.controller.get_all()

        self.assertEqual(config_map[constants.CONFIG_SERVICE]["1.1.1.1"], {})
        self.assertEqual(config_map[constants.CONFIG_NETWORK]["1.1.1.1"], {})

    async def test_get_security_always_substitutes_failures(self):
        """Security legitimately errors on a security-disabled or Community
        Edition cluster; preserving the exception would let collectinfo record a
        healthy cluster as a failed collection on every such bundle."""
        self.cluster_mock.info_get_config.return_value = {
            "1.1.1.1": Exception("security not supported")
        }

        actual = await self.controller.get_security()

        self.assertDictEqual(actual, {"1.1.1.1": {}})

    async def test_get_namespace(self):
        self.cluster_mock.info_namespaces.return_value = {
            "10.71.71.169:3000": ["bar", "test"]
        }

        async def side_effect(stanza, namespace, nodes):
            if namespace == "test":
                return {
                    "10.71.71.169:3000": {
                        "test": {
                            "a": "1",
                            "b": "2",
                            "c": "3",
                        }
                    }
                }
            elif namespace == "bar":
                return {"10.71.71.169:3000": {"bar": {"d": "4", "e": "5", "f": "6"}}}

        self.cluster_mock.info_get_config.side_effect = side_effect

        expected_output = {
            "test": {
                "10.71.71.169:3000": {
                    "a": "1",
                    "b": "2",
                    "c": "3",
                }
            },
            "bar": {
                "10.71.71.169:3000": {
                    "d": "4",
                    "e": "5",
                    "f": "6",
                }
            },
        }

        actual_output = await self.controller.get_namespace(flip=True)
        self.assertDictEqual(expected_output, actual_output)

    async def test_get_namespace_with_for(self):
        self.cluster_mock.info_namespaces.return_value = {
            "10.71.71.169:3000": ["bar", "test"]
        }

        async def side_effect(stanza, namespace, nodes):
            if namespace == "test":
                return {
                    "10.71.71.169:3000": {
                        "test": {
                            "a": "1",
                            "b": "2",
                            "c": "3",
                        }
                    }
                }
            elif namespace == "bar":
                return {"10.71.71.169:3000": {"bar": {"d": "4", "e": "5", "f": "6"}}}

        self.cluster_mock.info_get_config.side_effect = side_effect

        expected_output = {
            "10.71.71.169:3000": {
                "bar": {
                    "d": "4",
                    "e": "5",
                    "f": "6",
                }
            },
        }

        actual_output = await self.controller.get_namespace(for_mods=["bar"])
        self.assertDictEqual(expected_output, actual_output)

    async def test_get_sets(self):
        self.cluster_mock.info_all_set_statistics.return_value = {
            "1.1.1.1": {
                ("aaa", "sss"): {"stat1": 1, "stat2": 2},
                ("aab", "sst"): {"stat3": 3, "stat4": 4},
                ("abc", "stu"): {"stat3": 5, "stat4": 6},
            },
            "2.2.2.2": {
                ("aaa", "sss"): {"stat1": 1, "stat2": 2},
                ("aab", "sst"): {"stat3": 3, "stat4": 4},
                ("abc", "stu"): {"stat3": 5, "stat4": 6},
            },
        }
        expected = {
            "1.1.1.1": {
                ("aab", "sst"): {"stat3": 3, "stat4": 4},
            },
            "2.2.2.2": {
                ("aab", "sst"): {"stat3": 3, "stat4": 4},
            },
        }

        result = await self.controller.get_sets(for_mods=["ab", "ss"])

        self.assertDictEqual(result, expected)

    async def test_get_security(self):
        self.cluster_mock.info_get_config.return_value = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": Exception(),
        }
        expected = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": {},
        }

        actual = await self.controller.get_security()

        self.assertDictEqual(actual, expected)

    async def test_get_service(self):
        self.cluster_mock.info_get_config.return_value = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": Exception(),
        }
        expected = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": {},
        }

        actual = await self.controller.get_service()

        self.assertDictEqual(actual, expected)

    async def test_get_network(self):
        self.cluster_mock.info_get_config.return_value = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": Exception(),
        }
        expected = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": {},
        }

        actual = await self.controller.get_network()

        self.assertDictEqual(actual, expected)

    async def test_get_xdr(self):
        self.cluster_mock.info_xdr_config.return_value = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": Exception(),
        }
        expected = {
            "1.1.1.1": "unfiltered",
            "2.2.2.2": {},
        }

        actual = await self.controller.get_xdr()

        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.get_controller._get_all_dcs")
    async def test_get_xdr_dcs(self, _get_all_dcs_mock: AsyncMock):
        _get_all_dcs_mock.return_value = ["aaa", "aab", "abc"]
        self.cluster_mock.info_xdr_dcs_config.return_value = {
            "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}},
            "2.2.2.2": {"aaa": {"c"}, "aab": Exception()},
            "3.3.3.3": Exception(),
        }
        expected = {
            "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}},
            "2.2.2.2": {"aaa": {"c"}, "aab": {}},
            "3.3.3.3": {},
        }

        actual = await self.controller.get_xdr_dcs(for_mods=["aa"])

        self.cluster_mock.info_xdr_dcs_config.assert_called_with(
            nodes="all", dcs=["aaa", "aab"]
        )
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.get_controller._get_all_dcs")
    @patch("lib.live_cluster.get_controller._get_all_namespaces")
    async def test_get_xdr_namespaces(
        self, _get_all_namespaces: AsyncMock, _get_all_dcs_mock: AsyncMock
    ):
        _get_all_dcs_mock.return_value = ["aaa", "aab", "abc"]
        _get_all_namespaces.return_value = ["test", "test1", "bar"]
        self.cluster_mock.info_xdr_namespaces_config.return_value = {
            "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": Exception()},
            "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": Exception()}},
            "3.3.3.3": Exception(),
        }
        expected = {
            "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
            "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
            "3.3.3.3": {},
        }

        actual = await self.controller.get_xdr_namespaces()

        self.cluster_mock.info_xdr_namespaces_config.assert_called_with(
            nodes="all", dcs=["aaa", "aab", "abc"], namespaces=["test", "test1", "bar"]
        )
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.get_controller._get_all_dcs")
    @patch("lib.live_cluster.get_controller._get_all_namespaces")
    async def test_get_xdr_namespaces_with_filter(
        self, _get_all_namespaces: AsyncMock, _get_all_dcs_mock: AsyncMock
    ):
        _get_all_dcs_mock.return_value = ["aaa", "aab", "abc"]
        _get_all_namespaces.return_value = ["test", "test1", "bar"]
        self.cluster_mock.info_xdr_namespaces_config.return_value = {}

        actual = await self.controller.get_xdr_namespaces(for_mods=["test", "aa"])

        self.cluster_mock.info_xdr_namespaces_config.assert_called_with(
            nodes="all", dcs=["aaa", "aab"], namespaces=["test", "test1"]
        )
        self.assertDictEqual(actual, {})

    @patch("lib.live_cluster.get_controller._get_all_dcs")
    @patch("lib.live_cluster.get_controller._get_all_namespaces")
    async def test_get_xdr_filter_with_filter(
        self, _get_all_namespaces: AsyncMock, _get_all_dcs_mock: AsyncMock
    ):
        _get_all_dcs_mock.return_value = ["aaa", "aab", "abc"]
        _get_all_namespaces.return_value = ["test", "test1", "bar"]
        self.cluster_mock.info_get_xdr_filter.return_value = {
            "1.1.1.1": {"aab": Exception()},
            "2.2.2.2": {"aab": {"bar": {}}},
            "3.3.3.3": Exception(),
        }
        expected = {
            "1.1.1.1": {"aab": {}},
            "2.2.2.2": {"aab": {}},
            "3.3.3.3": {},
        }

        actual = await self.controller.get_xdr_filters(for_mods=["aab", "test"])

        self.cluster_mock.info_get_xdr_filter.assert_called_with(
            nodes="all", dcs=["aab"]
        )
        self.assertDictEqual(actual, expected)


class GetJobsControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.client.cluster.Cluster", AsyncMock()
        ).start()
        self.controller = GetJobsController(self.cluster_mock)
        self.addCleanup(patch.stopall)

    async def test_get_all(self):
        expected = {
            "scan": {"inside-scan": "val"},
            "query": {"inside-query": "val"},
            "sindex-builder": {"inside-sindex-builder": "val"},
        }
        self.cluster_mock.info_scan_show.return_value = {"inside-scan": "val"}
        self.cluster_mock.info_query_show.return_value = {"inside-query": "val"}
        self.cluster_mock.info_jobs.return_value = {"inside-sindex-builder": "val"}

        actual = await self.controller.get_all()

        self.cluster_mock.info_scan_show.assert_called_with(nodes="all")
        self.cluster_mock.info_query_show.assert_called_with(nodes="all")
        self.cluster_mock.info_jobs.assert_called_with(
            module="sindex-builder", nodes="all"
        )

        self.assertDictEqual(actual, expected)

    async def test_get_all_flip(self):
        expected = {
            "inside-scan": {"scan": "val"},
            "inside-query": {"query": "val"},
            "inside-sindex-builder": {"sindex-builder": "val"},
        }
        self.cluster_mock.info_scan_show.return_value = {"inside-scan": "val"}
        self.cluster_mock.info_query_show.return_value = {"inside-query": "val"}
        self.cluster_mock.info_jobs.return_value = {"inside-sindex-builder": "val"}

        actual = await self.controller.get_all(flip=True)

        self.cluster_mock.info_scan_show.assert_called_with(nodes="all")
        self.cluster_mock.info_query_show.assert_called_with(nodes="all")
        self.cluster_mock.info_jobs.assert_called_with(
            module="sindex-builder", nodes="all"
        )

        self.assertDictEqual(actual, expected)

    async def test_get_query_filters_for_ns(self):
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "set": "myset", "status": "active(ok)"},
                "2": {"ns": "other", "set": "otherset", "status": "active(ok)"},
            }
        }

        actual = await self.controller.get_query(for_mods=["test"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "set": "myset", "status": "active(ok)"}}},
        )

    async def test_get_query_filters_for_ns_and_set(self):
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "set": "a", "status": "active(ok)"},
                "2": {"ns": "test", "set": "b", "status": "active(ok)"},
            }
        }

        actual = await self.controller.get_query(for_mods=["test", "a"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "set": "a", "status": "active(ok)"}}},
        )

    async def test_get_query_filters_where(self):
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "status": "active(ok)"},
                "2": {"ns": "test", "status": "done(ok)"},
            }
        }

        actual = await self.controller.get_query(where=["status=active"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "status": "active(ok)"}}},
        )

    async def test_get_query_filters_multiple_where_and(self):
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "status": "active(ok)"},
                "2": {"ns": "test", "status": "done(ok)"},
                "3": {"ns": "other", "status": "active(ok)"},
            }
        }

        actual = await self.controller.get_query(where=["ns=test", "status=active"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "status": "active(ok)"}}},
        )

    async def test_get_query_invalid_regex_raises_shell_exception(self):
        # Malformed regex like `-where status=(` must surface a ShellException
        # naming the offending clause — not crash with re.error.

        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {"1": {"ns": "test", "status": "active(ok)"}}
        }

        with self.assertRaises(ShellException) as ctx:
            await self.controller.get_query(where=["status=("])

        self.assertIn("status=(", str(ctx.exception))

    async def test_get_query_where_unknown_field_raises_shell_exception(self):
        # An unknown -where field must surface a ShellException rather than
        # silently filter every row, so users can tell typo-on-field from
        # zero-matches.

        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "status": "active(ok)"},
                "2": {"ns": "test", "status": "done(ok)"},
            }
        }

        with self.assertRaises(ShellException) as ctx:
            await self.controller.get_query(where=["nonexistent=foo"])

        self.assertIn("nonexistent", str(ctx.exception))
        self.assertIn("Known fields", str(ctx.exception))

    async def test_get_query_where_display_alias_namespace(self):
        # Users see `Namespace` in the rendered table; -where should accept it
        # (case-insensitively) and translate to the raw `ns` key.
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "status": "active(ok)"},
                "2": {"ns": "other", "status": "active(ok)"},
            }
        }

        actual = await self.controller.get_query(where=["Namespace=test"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "status": "active(ok)"}}},
        )

    async def test_get_query_where_display_alias_transaction_id(self):
        # `Transaction ID` (with space) must alias to raw key `trid`.
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "trid": "111", "status": "active(ok)"},
                "2": {"ns": "test", "trid": "222", "status": "active(ok)"},
            }
        }

        actual = await self.controller.get_query(where=["Transaction ID=111"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "trid": "111", "status": "active(ok)"}}},
        )

    async def test_get_query_where_raw_key_case_and_whitespace_insensitive(self):
        # A raw server key typed with different case / stray whitespace (here
        # "Status " for "status") must still resolve — not trip the
        # unknown-field check — matching the case-insensitivity offered to
        # display-header aliases.
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "status": "active(ok)"},
                "2": {"ns": "test", "status": "done(ok)"},
            }
        }

        actual = await self.controller.get_query(where=["Status =active"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "status": "active(ok)"}}},
        )

    async def test_get_query_where_known_alias_absent_in_data_filters_empty(self):
        # A legitimate alias/field (here `set`) that the current jobs simply
        # don't populate must filter to empty — NOT raise "unknown field" while
        # listing `set` as known. Distinguishes "field empty for these jobs"
        # from a real typo (which still raises, see below).
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "status": "active(ok)"},
                "2": {"ns": "test", "status": "done(ok)"},
            }
        }

        actual = await self.controller.get_query(where=["set=foo"])

        self.assertDictEqual(actual, {"1.1.1.1": {}})

    async def test_get_query_where_empty_data_does_not_raise(self):
        # When no hosts have job dicts to introspect, the unknown-field check
        # is skipped — we can't verify and a spurious error would be worse than
        # silent.
        self.cluster_mock.info_query_show.return_value = {"1.1.1.1": {}}

        actual = await self.controller.get_query(where=["nonexistent=foo"])

        self.assertDictEqual(actual, {"1.1.1.1": {}})

    async def test_get_query_where_alias_substring_match(self):
        # Display-name alias resolves to a raw key AND substring matching still
        # works against the raw value — guards against accidentally swapping in
        # an exact-equality comparison during alias resolution.
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "job-type": "aggregation-basic"},
                "2": {"ns": "test", "job-type": "udf-background"},
            }
        }

        actual = await self.controller.get_query(where=["Type=basic"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "job-type": "aggregation-basic"}}},
        )

    async def test_get_query_where_regex_anchors_enforced(self):
        # Help text promises regex metacharacters work; lock in that ^/$ anchors
        # really do anchor (i.e., we're using re.search on a parenthesized
        # alternation, not bare substring).
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {
                "1": {"ns": "test", "status": "active"},
                "2": {"ns": "test", "status": "active(ok)"},
            }
        }

        actual = await self.controller.get_query(where=["status=^active$"])

        self.assertDictEqual(
            actual,
            {"1.1.1.1": {"1": {"ns": "test", "status": "active"}}},
        )

    async def test_get_query_where_preserves_empty_hosts(self):
        # When every job at a host is filtered out, the host key must remain
        # (with an empty dict) so the renderer can still surface the node
        # rather than silently dropping it. Documented in filter_jobs docstring.
        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {"1": {"ns": "test", "status": "active(ok)"}},
            "2.2.2.2": {"1": {"ns": "test", "status": "done(ok)"}},
        }

        actual = await self.controller.get_query(where=["status=active"])

        self.assertEqual(set(actual.keys()), {"1.1.1.1", "2.2.2.2"})
        self.assertEqual(actual["2.2.2.2"], {})

    async def test_get_query_where_unknown_field_error_lists_known_names(self):
        # Error message must surface both raw keys present in data AND display
        # aliases so users can discover valid names without re-reading help.

        self.cluster_mock.info_query_show.return_value = {
            "1.1.1.1": {"1": {"ns": "test", "status": "active(ok)"}}
        }

        with self.assertRaises(ShellException) as ctx:
            await self.controller.get_query(where=["bogus=foo"])

        msg = str(ctx.exception)
        self.assertIn("bogus", msg)
        # Raw key from data
        self.assertIn("ns", msg)
        # Display alias from the alias map
        self.assertIn("namespace", msg)


class GetACLControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.client.cluster.Cluster", AsyncMock()
        ).start()
        self.controller = GetAclController(self.cluster_mock)
        self.addCleanup(patch.stopall)

    async def test_get_all(self):
        expected = {"users": "users", "roles": "roles"}
        self.cluster_mock.admin_query_users.return_value = "users"
        self.cluster_mock.admin_query_roles.return_value = "roles"

        actual = await self.controller.get_all(nodes="principal")

        self.cluster_mock.admin_query_users.assert_called_with(nodes="principal")
        self.cluster_mock.admin_query_roles.assert_called_with(nodes="principal")

        self.assertDictEqual(actual, expected)

    async def test_get_users(self):
        expected = "users"
        self.cluster_mock.admin_query_users.return_value = "users"

        actual = await self.controller.get_users(nodes="principal")

        self.cluster_mock.admin_query_users.assert_called_with(nodes="principal")

        self.assertEqual(actual, expected)

    async def test_get_user(self):
        expected = "users"
        self.cluster_mock.admin_query_user.return_value = "users"

        actual = await self.controller.get_user("bob", nodes="principal")

        self.cluster_mock.admin_query_user.assert_called_with("bob", nodes="principal")

        self.assertEqual(actual, expected)

    async def test_get_roles(self):
        expected = "role"
        self.cluster_mock.admin_query_roles.return_value = "role"

        actual = await self.controller.get_roles(nodes="principal")

        self.cluster_mock.admin_query_roles.assert_called_with(nodes="principal")

        self.assertEqual(actual, expected)

    async def test_get_role(self):
        expected = "role"
        self.cluster_mock.admin_query_role.return_value = "role"

        actual = await self.controller.get_role("bob", nodes="principal")

        self.cluster_mock.admin_query_role.assert_called_with("bob", nodes="principal")

        self.assertEqual(actual, expected)


class GetUserAgentsControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

        self.cluster_mock = MagicMock()
        self.controller = GetUserAgentsController(self.cluster_mock)

        self.addCleanup(patch.stopall)

    async def test_get_user_agents_success(self):
        """Test successful retrieval from multiple nodes"""
        expected = {
            "192.168.1.1:3000": [
                {"user-agent": "dGVzdA==", "count": "5"},
                {"user-agent": "YXNhZG0=", "count": "3"},
            ],
            "192.168.1.2:3000": [{"user-agent": "Y2xpZW50", "count": "2"}],
        }

        # Mock the async method properly
        async def mock_info_user_agents(**kwargs):
            return expected

        self.cluster_mock.info_user_agents = mock_info_user_agents

        actual = await self.controller.get_user_agents(nodes="all")

        self.assertEqual(actual, expected)

    async def test_get_user_agents_with_node_filtering(self):
        """Test with node filtering (specific nodes)"""
        expected = {"192.168.1.1:3000": [{"user-agent": "dGVzdA==", "count": "5"}]}

        # Mock the async method properly
        async def mock_info_user_agents(**kwargs):
            return expected

        self.cluster_mock.info_user_agents = mock_info_user_agents

        actual = await self.controller.get_user_agents(nodes=["192.168.1.1:3000"])

        self.assertEqual(actual, expected)

    async def test_get_user_agents_error_propagation(self):
        """Test error propagation from node level"""
        expected = {
            "192.168.1.1:3000": Exception("Node connection failed"),
            "192.168.1.2:3000": [{"user-agent": "dGVzdA==", "count": "5"}],
        }

        # Mock the async method properly
        async def mock_info_user_agents(**kwargs):
            return expected

        self.cluster_mock.info_user_agents = mock_info_user_agents

        actual = await self.controller.get_user_agents(nodes="all")

        self.assertEqual(actual, expected)
