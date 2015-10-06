# Copyright 2013-2014 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from mock import patch, Mock
import unittest2 as unittest
from lib.controller import *
from lib.view import *
from lib.cluster import Cluster
from lib.prefixdict import PrefixDict
from lib.node import Node
import lib
import sys
from cStringIO import StringIO

real_stdout = sys.stdout

def reset_stdout():
    sys.stdout = real_stdout

class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.cluster_patch = patch('lib.cluster.Cluster')
        #self.view_patch = patch('lib.view.CliView')

        real_stdoup = sys.stdout
        sys.stdout = StringIO()

        self.addCleanup(patch.stopall)
        self.addCleanup(reset_stdout)

        self.MockCluster = self.cluster_patch.start()
        #self.MockView = self.view_patch.start()
        Cluster._crawl = classmethod(lambda self: None)
        Cluster._callNodeMethod = classmethod(
            lambda self, nodes, method_name, *args, **kwargs:
            {"test":IOError("test error")})

        n = Node("172.99.99.99")
        Cluster.getNode = classmethod(
            lambda self, key: [n])

        pd = PrefixDict()
        pd['test'] = 'test'

        Cluster.getPrefixes = classmethod(lambda self: pd)

        self.rc = RootController()

    def test_infoController(self):
        ic = InfoController()

        ic.preCommand([""])
    
        ic.do_service(["service"])
        #ic.do_network(["network"]) # TODO: view.infoNetwork needs a "real" node
        ic.do_namespace(["namespace"])
        ic.do_xdr(["xdr"])

    def test_showDistributionController(self):
        sdc = ShowDistributionController()
        
        sdc.preCommand([""])
        sdc.do_time_to_live(["time_to_live"])
        sdc.do_eviction(["evict"])
        sdc.do_object_size(["object_size"])

    def test_showConfigController(self):
        scc = ShowConfigController()

        scc.preCommand([""])
        scc.do_service(["service"])
        scc.do_network(["network"])
        scc.do_namespace(["namespace"])
        scc.do_xdr(["xdr"])

    def test_showLatencyController(self):
        slc = ShowLatencyController()

        slc.preCommand([""])
        slc._do_default(["latency"])
        
    def test_ShowStatisticsController(self):
        ssc = ShowStatisticsController()

        ssc.preCommand([""])
        ssc.do_bins("bins")
        ssc.do_sets("sets")
        ssc.do_service("service")
        ssc.do_namespace("namespace")
        ssc.do_xdr("xdr")

class ClusterControllerTest(unittest.TestCase):

    def setUp(self):
        self.controller =  ClusterController()

    def test_get_pmap_data_pos(self):
        input_config = {'10.71.71.169:3000': 'test:0:A:2:0:0:0:0:0:0:0:0;test:1:A:2:0:0:0:0:0:0:0:0;test:2:A:2:0:0:0:0:0:0:0:0;test:3:S:1:0:0:0:0:207069:3001:0:0;test:4:S:0:0:0:0:0:0:0:0:0;test:4094:S:0:0:0:0:0:206724:2996:0:0;test:4095:S:0:0:0:0:0:213900:3100:0:0'}
        expected_output = {'10.71.71.169:3000': {'test': {'missing_part': range(5, 4094), 'sec_index': 4, 'distribution_pct': 0, 'pri_index': 3}}}
        actual_output = self.controller.get_pmap_data(input_config)
        self.assertEqual(expected_output, actual_output)

    def test_get_pmap_data_neg(self):
        input_config = {'10.71.71.169:3000': 'test:0:A:2:0:0:0:0:0:0:0:0;test:1:A:2:0:0:0:0:0:0:0:0;test:2:A:2:0:0:0:0:0:0:0:0;test:3:S:1:0:0:0:0:207069:3001:0:0;test:4:S:0:0:0:0:0:0:0:0:0;test:4094:S:0:0:0:0:0:206724:2996:0:0;test:4095:S:0:0:0:0:0:213900:3100:0:0'}
        expected_output = {'10.71.71.169:3000': {'test': {'missing_part': range(0, 4096), 'sec_index': 4, 'distribution_pct': 0, 'pri_index': 3}}}
        actual_output = self.controller.get_pmap_data(input_config)
        self.assertNotEqual(expected_output, actual_output)

    def test_get_qnode_data_pos(self):
         input_config = {'10.71.71.169:3000':"dmp:510:97405:S:BB97EFD707AC40C:MQ:0:0;dmp:510:0:A:BB95883057AC40C:RQ:0:0;dmp:510:97405:S:BB95883057AC40C:M:0:97405;dmp:510:0:A:BB97EFD707AC40C:RQ:0:30",
                         '10.71.71.130:3000':"dmp:510:97405:S:BB97EFD707AC40C:MQ:0:0;dmp:510:0:A:BB95883057AC40C:RQ:0:0;dmp:510:97405:S:BB95883057AC40C:M:0:97405;dmp:510:0:A:BB97EFD707AC40C:RQ:0:30"}

         expected_output = {'10.71.71.130:3000': {'dmp': {'MQ_without_data': [510],
                               'RQ_data': [510, 510],
                               'RQ_without_data': [510]}},
                            '10.71.71.169:3000': {'dmp': {'MQ_without_data': [510],
                               'RQ_data': [510, 510],
                               'RQ_without_data': [510]}}}

         actual_output = self.controller.get_qnode_data(input_config)
         self.assertEqual(expected_output, actual_output)

    def test_get_qnode_data_neg(self):
         input_config = {'10.71.71.169:3000':"dmp:510:97405:S:BB97EFD707AC40C:MQ:0:0;dmp:510:0:A:BB95883057AC40C:RQ:0:0;dmp:510:97405:S:BB95883057AC40C:M:0:97405;dmp:510:0:A:BB97EFD707AC40C:RQ:0:30"}
         # 'RQ_data': [510, 510], is missing in below output
         expected_output = {'10.71.71.169:3000': {'dmp': {'MQ_without_data': [510],
                               'RQ_without_data': [510]}}}

         actual_output = self.controller.get_qnode_data(input_config)
         self.assertNotEqual(expected_output, actual_output)