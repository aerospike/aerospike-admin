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
