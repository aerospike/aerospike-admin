# Copyright 2013-2020 Aerospike, Inc.
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

import unittest

import lib.basiccontroller as controller
import lib.utils.util as util
from test.e2e import test_util


class TestWatch(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        TestWatch.rc = controller.BasicRootController(user='admin', password='admin')
        actual_out = util.capture_stdout(TestWatch.rc.execute, ['watch', '1', '3', 'info', 'network'])
        TestWatch.output_list = test_util.get_separate_output(actual_out)

    def test_watch(self):
        info_counter = 0
        for item in TestWatch.output_list:
            if "Network Information" in item['title']:
                info_counter += 1
        self.assertEqual(info_counter, 3)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
