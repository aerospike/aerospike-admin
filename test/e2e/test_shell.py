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

import unittest2 as unittest
from lib.controllerlib import *
from lib.controller import *
import lib.util as util
import subprocess 

class TestController(unittest.TestCase):
    
    def test_shell_command(self):
        sc = ShellController()
        actual_out = util.capture_stdout(sc._do_default, ["ls"])
        p = subprocess.Popen(['sh', '-c', "ls"]
                             , stdout=subprocess.PIPE
                             , stderr=subprocess.PIPE)
        
        expected_out, err = p.communicate()
        self.assertEqual(expected_out.strip(), actual_out.strip())
    
if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()