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
