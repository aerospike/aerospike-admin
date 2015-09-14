'''
Created on 13-Sep-2015

@author: Pavan Gupta
'''
import test_util
import unittest2 as unittest
import lib.util as util
import lib.controller as controller


class TestInfo(unittest.TestCase):
    
    rc = None
    output_list = list()
    service_info = ''
    network_info = ''
    namespace_info = ''
    sindex_info = ''
    xdr_info = ''
    
    @classmethod
    def setUpClass(cls):
        TestInfo.rc = controller.RootController()
        actual_out = util.capture_stdout(TestInfo.rc.execute, ['info'])
        TestInfo.output_list = test_util.get_separate_output(actual_out, 'Information')
                          
        for item in TestInfo.output_list:
            if "~~Service Information~~" in item:
                TestInfo.service_info = item           
            elif "~~Network Information~~" in item:
                TestInfo.network_info = item           
            elif "~~Namespace Information~~" in item:
                TestInfo.namespace_info = item               
            elif "~~Sindex Information~~" in item:
                TestInfo.sindex_info = item              
            elif "~~XDR Information~~" in item:
                TestInfo.xdr_info = item
        
    @classmethod    
    def tearDownClass(self):
        self.rc = None    

    def test_service(self):
        """
        This test will assert <b> info Service </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        ToDo: test for values as well
        """
        exp_heading = "~~Service Information~~"
        exp_headerl1 = 'Node    Build   Cluster      Cluster     Cluster    Free   Free   Migrates   Principal   Objects     Uptime   '
        exp_headerl2 = '   .        .      Size   Visibility   Integrity   Disk%   Mem%          .           .         .          .   '
        exp_no_of_rows = len(TestInfo.rc.cluster._live_nodes)
        
        actual_heading, actual_headerl1, actual_headerl2, actual_no_of_rows = test_util.parse_output(TestInfo.service_info, horizontal = True)        
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_headerl1.strip() in actual_headerl1.strip())
        self.assertTrue(exp_headerl2.strip() in actual_headerl2.strip())
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    
    def test_network(self):
        """
        This test will assert <b> info Network </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        ToDo: test for values as well
        """
        exp_heading = "~~Network Information~~"
        exp_headerl1 = 'Node               Node             Fqdn               Ip   Client     Current     HB        HB   '
        exp_headerl2 = '   .                 Id                .                .    Conns        Time   Self   Foreign   '
        exp_no_of_rows = len(TestInfo.rc.cluster._live_nodes)
        
        actual_heading, actual_headerl1, actual_headerl2, actual_no_of_rows = test_util.parse_output(TestInfo.network_info, horizontal = True)        
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_headerl1.strip() in actual_headerl1.strip())
        self.assertTrue(exp_headerl2.strip() in actual_headerl2.strip())
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))
        
    def test_sindex(self):
            pass

    def test_namespace(self):
        """
        This test will assert <b> info Namespace </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        ToDo: test for values as well
        """
        exp_heading = "~~Namespace Information~~"
        exp_headerl1 = 'Node   Namespace   Evictions    Master   Replica     Repl     Stop     HWM         Mem     Mem    HWM      Stop   '
        exp_headerl2 = '   .           .           .   Objects   Objects   Factor   Writes   Disk%        Used   Used%   Mem%   Writes%   '
        exp_no_of_rows = len(TestInfo.rc.cluster._live_nodes)
        
        actual_heading, actual_headerl1, actual_headerl2, actual_no_of_rows = test_util.parse_output(TestInfo.namespace_info, horizontal = True)        
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_headerl1.strip() in actual_headerl1.strip())
        self.assertTrue(exp_headerl2.strip() in actual_headerl2.strip())
        # commenting below below line because no of row depends on namespaces not nodes
#         self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))
        
        pass
    @unittest.skip("Skipping for testing purpose")   
    def test_xdr(self):
        """
        This test will assert <b> info Namespace </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        ToDo: test for values as well
        """
        exp_heading = "~~XDR Information~~"
        exp_headerl1 = '      Node   Build        Data    Free        Lag           Req         Req         Req          Cur       Avg         Xdr   '
        exp_headerl2 = '         .       .     Shipped   Dlog%      (sec)   Outstanding       Relog     Shipped   Throughput   Latency      Uptime   '
        exp_no_of_rows = len(TestInfo.rc.cluster._live_nodes)
        
        actual_heading, actual_headerl1, actual_headerl2, actual_no_of_rows = test_util.parse_output(TestInfo.xdr_info, horizontal = True)        
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_headerl1.strip() in actual_headerl1.strip())
        self.assertTrue(exp_headerl2.strip() in actual_headerl2.strip())


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()