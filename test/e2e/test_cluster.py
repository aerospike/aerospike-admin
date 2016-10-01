# Copyright 2013-2016 Aerospike, Inc.
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

import test_util
import unittest2 as unittest
import lib.util as util
import lib.controller as controller

class TestCluster(unittest.TestCase):
    rc = None
    
    @classmethod
    def setUpClass(cls):
        TestCluster.rc = controller.RootController()
            
    @classmethod    
    def tearDownClass(self):
        self.rc = None

    def test_dun(self):
        exp_no_of_live_nodes = len(TestCluster.rc.cluster._live_nodes)
        exp_total_nodes = len(TestCluster.rc.cluster.nodes)
        
        actual_out = util.capture_stdout(TestCluster.rc.execute, ['cluster', 'dun', 'all'])
        if 'Invalid command' in actual_out:
            return
        actual_live_nodes = actual_out.count('ok')
        actual_total_nodes = actual_out.count('returned')
        
        self.assertEqual(exp_no_of_live_nodes, actual_live_nodes)
        self.assertEqual(exp_total_nodes, actual_total_nodes)
    
    def test_undun(self):
        exp_no_of_live_nodes = len(TestCluster.rc.cluster._live_nodes)
        exp_total_nodes = len(TestCluster.rc.cluster.nodes)
        actual_out = util.capture_stdout(TestCluster.rc.execute, ['cluster', 'undun', 'all'])
        if 'Invalid command' in actual_out:
            return
        actual_live_nodes = actual_out.count('ok')
        actual_total_nodes = actual_out.count('returned')
        
        self.assertEqual(exp_no_of_live_nodes, actual_live_nodes)
        self.assertEqual(exp_total_nodes, actual_total_nodes)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()