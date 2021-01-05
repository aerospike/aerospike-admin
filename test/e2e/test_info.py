# Copyright 2013-2021 Aerospike, Inc.
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

from lib.view.sheet import set_style_json
import unittest

import lib.basiccontroller as controller
import lib.utils.util as util
from test.e2e import test_util

set_style_json()

class TestInfo(unittest.TestCase):
    
    rc = None
    output_list = list()
    service_info = ''
    network_info = ''
    namespace_usage_info = ''
    namespace_object_info = ''
    sindex_info = ''
    xdr_info = ''
    
    @classmethod
    def setUpClass(cls):
        TestInfo.rc = controller.BasicRootController()
        actual_out = util.capture_stdout(TestInfo.rc.execute, ['info'])
        actual_out += util.capture_stdout(TestInfo.rc.execute, ['info', 'sindex'])
        # print(actual_out)
        TestInfo.output_list = test_util.get_separate_output(actual_out)

        for item in TestInfo.output_list:
            title = item['title']
            if "Network Information" in title:
                TestInfo.network_info = item
            elif "Namespace Usage Information" in title:
                TestInfo.namespace_usage_info = item
            elif "Secondary Index Information" in title:
                TestInfo.sindex_info = item              
            elif "XDR Information" in title:
                TestInfo.xdr_info = item
            elif "Namespace Object Information" in title:
                TestInfo.namespace_object_info = item
        
    @classmethod    
    def tearDownClass(cls):
        cls.rc = None    

    def test_network(self):
        """
        This test will assert <b> info Network </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        TODO: test for values as well
        """
        exp_heading = "Network Information"
        exp_header = [   
            'Node',
            'Node ID',
            'IP',
            'Build',
            'Migrations',
            'Cluster Size',
            'Cluster Key',
            'Cluster Integrity',
            'Cluster Principal',
            'Client Conns',
            'Uptime'
        ]
        expected_num_records = len(TestInfo.rc.cluster.nodes)
        
        actual_heading, actual_description, actual_header, actual_data, actual_num_records = test_util.parse_output(TestInfo.network_info, horizontal = True)
        self.assertTrue(exp_heading in actual_heading)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(expected_num_records, actual_num_records)

    def test_sindex(self):
        """
        This test will assert <b> info sindex </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        TODO: test for values as well
        """
        exp_heading = 'Secondary Index Information'

        # Know to be up-to-date with server 5.1
        exp_header = [
            'Node', 
            'Index Name',
            'Index Type',
            'Namespace', 
            'Set', 
            'Bins', 
            'Num Bins', 
            'Bin Type', 
            'State', 
            'Keys',
            'Entries',
            'Si Accounted',
            'q',
            'w',
            'd',
            's'
        ]

        if TestInfo.sindex_info == '':
            self.skipTest('No sindex information found.')

        actual_heading, actual_description, actual_header, actual_data, num_records = test_util.parse_output(TestInfo.sindex_info, horizontal = True)        

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)

    def test_namespace_usage(self):
        """
        This test will assert <b> info namespace usage </b> output for heading, headerline1, headerline2
        displayed in output
        TODO: test for values as well
        """
        exp_heading = "Namespace Usage Information"
        exp_header = [   
            'Namespace',
            'Node',
            'Total Records',
            'Expirations',
            'Evictions',
            'Stop Writes',
            'Disk Used',
            'Disk Used%',
            'Disk HWM%',
            'Disk Avail%',
            'Memory Used',
            'Memory Used%',
            'Memory HWM%',
            'Memory Stop%',
            'Primary Index Type',
        ]

        actual_heading, actual_description, actual_header, actual_data, num_records = test_util.parse_output(TestInfo.namespace_usage_info, horizontal = True)
        self.assertListEqual(actual_header, exp_header)
        self.assertTrue(exp_heading in actual_heading)

    def test_namespace_object(self):
        """
        This test will assert <b> info namespace Object </b> output for heading, headerline1, headerline2
        displayed in output
        TODO: test for values as well
        """
        exp_heading = "Namespace Object Information"
        exp_header = [   
            'Namespace',
            'Node',
            'Rack ID',
            'Repl Factor',
            'Total Records',
            'Objects Master',
            'Objects Prole',
            'Objects Non-Replica',
            'Tombstones Master',
            'Tombstones Prole',
            'Tombstones Non-Replica',
            'Pending Migrates Tx',
            'Pending Migrates Rx',
        ]

        actual_heading, actual_description, actual_header, actual_data, num_records = test_util.parse_output(TestInfo.namespace_object_info, horizontal = True)
        self.assertListEqual(actual_header, exp_header)
        self.assertTrue(exp_heading in actual_heading)

    #@unittest.skip("Will enable only when xdr is configured")
    def test_xdr(self):
        """
        This test will assert info XDR output.
        and no of row displayed in output
        TODO: test for values as well
        """
        exp_heading = "XDR Information"

        # Left incase older server versions need testing

        exp_header = [
            'Node',
            'Success',
            'Retry Connection Reset',
            'Retry Destination',
            'Recoveries Pending',
            'Lag (hh:mm:ss)',
            'Avg Latency (ms)',
            'Throughput (rec/s)',
        ]
        
        actual_heading, actual_description, actual_header, actual_data, num_records = test_util.parse_output(TestInfo.xdr_info, horizontal = True, header_len=3)
        # print(actual_header)
        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        


if __name__ == "__main__":
    unittest.main()
