# Copyright 2013-2020 Aerospike, Inc.
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

from mock import patch, Mock
import unittest

from lib.client.node import Node
from lib.basiccontroller import *
from lib.utils.lookupdict import LookupDict
from lib.view.view import *

real_stdout = sys.stdout


def reset_stdout():
    sys.stdout = real_stdout


class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.cluster_patch = patch("lib.client.cluster.Cluster")
        # self.view_patch = patch('lib.view.CliView')

        real_stdoup = sys.stdout
        sys.stdout = StringIO()

        self.addCleanup(patch.stopall)
        self.addCleanup(reset_stdout)

        self.MockCluster = self.cluster_patch.start()
        # self.MockView = self.view_patch.start()
        Cluster._crawl = classmethod(lambda self: None)
        Cluster.call_node_method = classmethod(
            lambda self, nodes, method_name, *args, **kwargs: {
                "test": IOError("test error")
            }
        )

        n = Node("172.99.99.99")
        Cluster.get_node = classmethod(lambda self, key: [n])

        pd = LookupDict()
        pd["test"] = "test"

        Cluster.get_node_displaynames = classmethod(lambda self: pd)

        self.rc = BasicRootController()

    def test_info_controller(self):
        ic = InfoController()

        ic.pre_command([""])

        ic.do_network(["network"])  # TODO: view.info_network needs a "real" node
        ic.do_xdr(["xdr"])

    def test_info_namespace_controller(self):
        inc = InfoNamespaceController()

        inc.pre_command([""])

        inc.do_usage(["namespace usage"])
        inc.do_object(["namespace object"])

    def test_show_distribution_controller(self):
        sdc = ShowDistributionController()

        sdc.pre_command([""])
        sdc.do_time_to_live(["time_to_live"])
        sdc.do_eviction(["evict"])
        sdc.do_object_size(["object_size"])
        sdc.do_object_size(["object_size", "-b"])

    def test_show_config_controller(self):
        scc = ShowConfigController()

        scc.pre_command([""])
        scc.do_service(["service"])
        scc.do_network(["network"])
        scc.do_namespace(["namespace"])
        scc.do_xdr(["xdr"])

    def test_show_latencies_controller(self):
        slc = ShowLatenciesController()

        slc.pre_command([""])
        util.capture_stdout_and_stderr(slc._do_default, ["latencies"])

    def test_ShowStatisticsController(self):
        ssc = ShowStatisticsController()

        ssc.pre_command([""])
        ssc.do_bins("bins")
        ssc.do_sets("sets")
        ssc.do_service("service")
        ssc.do_namespace("namespace")
        ssc.do_xdr("xdr")

    def test_ShowUsersController(self):
        ssc = ShowStatisticsController()

        ssc.pre_command([""])
        ssc.do_bins("bins")
        ssc.do_sets("sets")
        ssc.do_service("service")
        ssc.do_namespace("namespace")
        ssc.do_xdr("xdr")


class ShowPmapControllerTest(unittest.TestCase):
    def mock_info_call(self, cmd, nodes="all"):
        if cmd == "version":
            return {"10.71.71.169:3000": "3.6.0"}

        if cmd == "node":
            return {"10.71.71.169:3000": "BB93039BC7AC40C"}

        if cmd == "partition-info":
            return self.partition_info

        return {}

    def setUp(self):
        cluster = Cluster(("10.71.71.169", "3000", None))
        cluster.info_statistics = Mock()
        cluster.info_statistics.return_value = {
            "10.71.71.169:3000": {"cluster_key": "ck"}
        }
        cluster.info_namespaces = Mock()
        cluster.info_namespaces.return_value = {"10.71.71.169:3000": ["test"]}
        cluster.info_namespace_statistics = Mock()
        cluster.info_namespace_statistics.return_value = {
            "10.71.71.169:3000": {
                "dead_partitions": "2000",
                "unavailable_partitions": "0",
            }
        }
        cluster.info = Mock()
        cluster.info.side_effect = self.mock_info_call
        self.controller = GetPmapController(cluster)

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
