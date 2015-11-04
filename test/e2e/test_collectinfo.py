'''
Created on 18-Sep-2015

@author: gslab
'''
import test_util
import unittest2 as unittest
import lib.util as util
import lib.controller as controller


class TestCollectinfo(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        TestCollectinfo.rc = controller.RootController()
        # actual_out = util.capture_stdout(TestCollectinfo.rc.execute, ['collectinfo'])

    def test_collectinfo(self):
        expected = ['aerospike.log',
                    'aerospike.conf',
                    'collectSys.log',
                    'awsData.log',
                    'sysInformation/dmesg.log',
                    'sysInformation/cpu_stat.log',
                    'sysInformation/sysCmdOutput.log',
                    'asadmCmd.log',
                    'clusterCmd.log'
                    ]
        pass


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
