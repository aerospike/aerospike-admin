import unittest
from mock import Mock, patch

from lib.get_controller import GetPmapController


class GetPmapControllerTest(unittest.TestCase):
    def mock_info_call(self, cmd, nodes="all"):
        if cmd == "version":
            return {"10.71.71.169:3000": "3.6.0"}

        if cmd == "node":
            return {"10.71.71.169:3000": "BB93039BC7AC40C"}

        if cmd == "partition-info":
            return self.partition_info

        return {}

    def setUp(self):
        # cluster = Cluster(("10.71.71.169", "3000", None))
        cluster_mock = patch("lib.live_cluster.client.cluster.Cluster").start()
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
        cluster_mock.info = Mock()
        cluster_mock.info.side_effect = self.mock_info_call
        self.controller = GetPmapController(cluster_mock)

    def test_get_pmap_data(self):
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
        actual_output = self.controller.get_pmap()
        self.assertEqual(expected_output, actual_output)

    def test_get_pmap_data_with_migrations(self):
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
        actual_output = self.controller.get_pmap()
        self.assertEqual(expected_output, actual_output)

    def test_get_pmap_data_with_working_master(self):
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
        actual_output = self.controller.get_pmap()
        self.assertEqual(expected_output, actual_output)
