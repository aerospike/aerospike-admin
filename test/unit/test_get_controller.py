import warnings
from pytest import PytestUnraisableExceptionWarning
from mock import patch
from mock.mock import AsyncMock

from lib.get_controller import GetJobsController, GetPmapController, GetConfigController

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import asynctest


class GetPmapControllerTest(asynctest.TestCase):
    def mock_info_call(self, cmd, nodes="all"):
        if cmd == "version":
            return {"10.71.71.169:3000": "3.6.0"}

        if cmd == "node":
            return {"10.71.71.169:3000": "BB93039BC7AC40C"}

        if cmd == "partition-info":
            return self.partition_info

        return {}

    def setUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        # cluster = Cluster(("10.71.71.169", "3000", None))
        cluster_mock = patch(
            "lib.live_cluster.client.cluster.Cluster", AsyncMock()
        ).start()
        # cluster.info_statistics = Mock()
        cluster_mock.info_statistics.return_value = {
            "10.71.71.169:3000": {"cluster_key": "ck"}
        }
        # cluster_mock.info_namespaces = Mock()
        cluster_mock.info_namespaces.return_value = {"10.71.71.169:3000": ["test"]}
        # cluster_mock.info_namespace_statistics = Mock()
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


class GetConfigControllerTest(asynctest.TestCase):
    def mock_info_call(self, cmd, nodes="all"):
        if cmd == "version":
            return {"10.71.71.169:3000": "3.6.0"}

        if cmd == "node":
            return {"10.71.71.169:3000": "BB93039BC7AC40C"}

        if cmd == "partition-info":
            return self.partition_info

        return {}

    def setUp(self):
        self.cluster_mock = patch("lib.live_cluster.client.cluster.Cluster").start()
        self.controller = GetConfigController(self.cluster_mock)
        self.addCleanup(patch.stopall)
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

    async def test_get_namespace(self):
        self.cluster_mock.info_namespaces.return_value = {
            "10.71.71.169:3000": ["bar", "test"]
        }

        def side_effect(stanza, namespace, nodes):
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


class GetJobsControllerTest(asynctest.TestCase):
    def setUp(self):
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
