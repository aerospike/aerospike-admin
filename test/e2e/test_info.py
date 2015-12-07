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
        # TestInfo.output_list.append(util.capture_stdout(TestInfo.rc.execute, ['info', 'sindex']))            
        for item in TestInfo.output_list:
            if "~~Service Information~~" in item:
                TestInfo.service_info = item           
            elif "~~Network Information~~" in item:
                TestInfo.network_info = item           
            elif "~~Namespace Information~~" in item:
                TestInfo.namespace_info = item               
            elif "~~Secondary Index Information~~" in item:
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
        exp_header= ['Node',
                     'Build',
                     'Cluster Size',
                     'Cluster Visibility',
                     'Cluster Integrity',
                     'Free Disk%',
                     'Free Mem%',
                     'Migrates (tx,rx,a)',
                     'Principal',
                     'Objects',
                     'Uptime'] 
        exp_no_of_rows = len(TestInfo.rc.cluster.nodes)
        
        actual_heading, actual_header, actual_no_of_rows = test_util.parse_output(TestInfo.service_info, horizontal = True)        
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))
    
    def test_network(self):
        """
        This test will assert <b> info Network </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        ToDo: test for values as well
        """
        exp_heading = "~~Network Information~~"
        exp_header = [   'Node',
                         'Node Id',
                         'Fqdn',
                         'Ip',
                         'Client Conns',
                         'Current Time',
                         'HB Self',
                         'HB Foreign' ]
        exp_no_of_rows = len(TestInfo.rc.cluster.nodes)
        
        actual_heading, actual_header, actual_no_of_rows = test_util.parse_output(TestInfo.network_info, horizontal = True)        
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    @unittest.skip("Skipping by default, to make it work please enable in setupClass also")
    def test_sindex(self):
        """
        This test will assert <b> info sindex </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        ToDo: test for values as well
        """
        exp_heading = '~~Secondary Index Information~~'
        exp_header = ['Node', 
                      'Index Name', 
                      'Namespace', 
                      'Set', 
                      'Bins', 
                      'Num Bins', 
                      'Bin Type', 
                      'State', 
                      'Sync State']
        exp_no_of_rows = len(TestInfo.rc.cluster.nodes)
        
        actual_heading, actual_header, actual_no_of_rows = test_util.parse_output(TestInfo.sindex_info, horizontal = True)        
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)

    def test_namespace(self):
        """
        This test will assert <b> info Namespace </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        ToDo: test for values as well
        """
        exp_heading = "~~Namespace Information~~"
        exp_header = [   'Node',
                         'Namespace',
                         'Evictions',
                         'Master Objects',
                         'Replica Objects',
                         'Repl Factor',
                         'Stop Writes',
                         'HWM Disk%',
                         'Mem Used',
                         'Mem Used%',
                         'HWM Mem%',
                         'Stop Writes%']
        exp_no_of_rows = len(TestInfo.rc.cluster.nodes)
        
        actual_heading, actual_header, actual_no_of_rows = test_util.parse_output(TestInfo.namespace_info, horizontal = True)        
        self.assertTrue(set(exp_header).issubset(set(actual_header)))
        self.assertTrue(exp_heading in actual_heading)

    @unittest.skip("Will enable only when xdr is configuired")
    def test_xdr(self):
        """
        This test will assert <b> info Namespace </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        ToDo: test for values as well
        """
        exp_heading = "~~XDR Information~~"
        exp_header = ['Node', 
                      'Build', 
                      'Data Shipped', 
                      'Free Dlog%', 
                      'Lag (sec)', 
                      'Req Outstanding', 
                      'Req Relog', 
                      'Req Shipped', 
                      'Cur Throughput', 
                      'Avg Latency', 
                      'Xdr Uptime']
        exp_no_of_rows = len(TestInfo.rc.cluster.nodes)
        
        actual_heading, actual_header, actual_no_of_rows = test_util.parse_output(TestInfo.xdr_info, horizontal = True)        
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(exp_heading in actual_heading)
        


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
