'''
Created on 07-Sep-2015

@author: gslab
'''
import unittest2 as unittest
# from .. import *
import lib.util as util
import lib.controller as controller

# will remove this function once latency test is implemented without asinfo
def parse_latency(tdata = ""):
        tdata = tdata.split(';')[:-1]
        data = {}
        while tdata != []:
            columns = tdata.pop(0)
            row = tdata.pop(0)

            hist_name, columns = columns.split(':', 1)
            columns = columns.split(',')
            row = row.split(',')
            start_time = columns.pop(0)
            end_time = row.pop(0)
            columns.insert(0, 'Time Span')
            row = [float(r) for r in row]
            row.insert(0, "%s->%s"%(start_time, end_time))

            data[hist_name] = (columns, row)

        return data

def parse_output(actual_out = ""):
    """
        commmon parser for all show commands will return touple of following
        @param heading : first line of output
        @param header: Second line of output
        @param params: list of parameters 
    
    """
    data =  actual_out.split('\n')
    heading = data.pop(0)
    header = data.pop(0)
    params = [item.split(':')[0].strip() for item in  data if item.split(':')[0].strip()]
    
    # handled beast color code
    params = [item[4:] for item in params if "\x1b[0m" in item]
    return(heading, header, params)
    
    
class TestShowConfig(unittest.TestCase):
    
    def setUp(self):
        self.rc = controller.RootController()

    def tearDown(self):
        self.rc = None
    
    def test_network(self):
        """
        This test will assert network output on heading, header, parameters.
        ToDo: test for values as well
        """
        
        exp_heading = "~~~~~~Network Configuration~~~~~"
        exp_header = "NODE"
        exp_params = ['enable-fastpath', 
                    'fabric-keepalive-enabled', 
                    'fabric-keepalive-intvl', 
                    'fabric-keepalive-probes', 
                    'fabric-keepalive-time', 
                    'fabric-port', 
                    'heartbeat-address', 
                    'heartbeat-interval', 
                    'heartbeat-mode', 
                    'heartbeat-port', 
                    'heartbeat-protocol', 
                    'heartbeat-timeout', 
                    'network-info-port', 
                    'reuse-address', 
                    'service-address', 
                    'service-port']
        
        actual_out = util.capture_stdout(self.rc.execute, ['show', 'config', 'network'])
        actual_heading, actual_header, actual_params = parse_output(actual_out)
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params))
        pass
    
    
    @unittest.skip("need to implement without asinfo")
    def test_latency(self):        
        expected_out, err = util.shell_command(["asinfo", "-v", "latency:"])
        print expected_out, err
        self.assertTrue(True)
        
        rc = controller.RootController()
        actual_out = util.capture_stdout(rc.execute, ['show', 'latency'])
#         slc = controller.ShowLatencyController()
#         slc.nodes = "all"
#         slc._do_default([])
        print actual_out
        self.assertEqual(expected_out.strip(), actual_out.strip())


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()