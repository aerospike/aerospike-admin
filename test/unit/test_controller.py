# Copyright 2013-2017 Aerospike, Inc.
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
import sys
from cStringIO import StringIO
import unittest2 as unittest

from lib.client.cluster import Cluster
from lib.client.node import Node
from lib.basiccontroller import *
from lib.utils.prefixdict import PrefixDict
from lib.view.view import *

real_stdout = sys.stdout

def reset_stdout():
    sys.stdout = real_stdout

class ControllerTest(unittest.TestCase):
    def setUp(self):
        self.cluster_patch = patch('lib.client.cluster.Cluster')
        #self.view_patch = patch('lib.view.CliView')

        real_stdoup = sys.stdout
        sys.stdout = StringIO()

        self.addCleanup(patch.stopall)
        self.addCleanup(reset_stdout)

        self.MockCluster = self.cluster_patch.start()
        #self.MockView = self.view_patch.start()
        Cluster._crawl = classmethod(lambda self: None)
        Cluster.call_node_method = classmethod(
            lambda self, nodes, method_name, *args, **kwargs:
            {"test":IOError("test error")})

        n = Node("172.99.99.99")
        Cluster.get_node = classmethod(
            lambda self, key: [n])

        pd = PrefixDict()
        pd['test'] = 'test'

        Cluster.get_prefixes = classmethod(lambda self: pd)

        self.rc = BasicRootController()

    def test_info_controller(self):
        ic = InfoController()

        ic.pre_command([""])
    
        ic.do_network(["network"]) # TODO: view.info_network needs a "real" node
        ic.do_namespace(["namespace"])
        ic.do_xdr(["xdr"])

    def test_show_distribution_controller(self):
        sdc = ShowDistributionController()
        
        sdc.pre_command([""])
        sdc.do_time_to_live(["time_to_live"])
        sdc.do_eviction(["evict"])
        sdc.do_object_size(["object_size"])
        sdc.do_object_size(["object_size","-b"])

    def test_show_config_controller(self):
        scc = ShowConfigController()

        scc.pre_command([""])
        scc.do_service(["service"])
        scc.do_network(["network"])
        scc.do_namespace(["namespace"])
        scc.do_xdr(["xdr"])

    def test_show_latency_controller(self):
        slc = ShowLatencyController()

        slc.pre_command([""])
        slc._do_default(["latency"])
        
    def test_ShowStatisticsController(self):
        ssc = ShowStatisticsController()

        ssc.pre_command([""])
        ssc.do_bins("bins")
        ssc.do_sets("sets")
        ssc.do_service("service")
        ssc.do_namespace("namespace")
        ssc.do_xdr("xdr")

