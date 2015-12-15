'''
Created on 15-Sep-2015

@author: gslab
'''
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
        actual_live_nodes = actual_out.count('ok')
        actual_total_nodes = actual_out.count('returned')
        
        self.assertEqual(exp_no_of_live_nodes, actual_live_nodes)
        self.assertEqual(exp_total_nodes, actual_total_nodes)
    
    def test_undun(self):
        exp_no_of_live_nodes = len(TestCluster.rc.cluster._live_nodes)
        exp_total_nodes = len(TestCluster.rc.cluster.nodes)
        actual_out = util.capture_stdout(TestCluster.rc.execute, ['cluster', 'undun', 'all'])
        actual_live_nodes = actual_out.count('ok')
        actual_total_nodes = actual_out.count('returned')
        
        self.assertEqual(exp_no_of_live_nodes, actual_live_nodes)
        self.assertEqual(exp_total_nodes, actual_total_nodes)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()