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

import unittest

import asynctest

import lib.live_cluster.live_cluster_root_controller as controller
import lib.utils.util as util
from test.e2e import lib, util as test_util
from lib.view.sheet import set_style_json

set_style_json()


class TestWatch(asynctest.TestCase):
    async def setUp(self):
        lib.start()
        self.rc = await controller.LiveClusterRootController(
            user="admin", password="admin"
        )  # type: ignore

    def tearDown(self) -> None:
        lib.stop()

    async def test_watch(self):
        actual_out = await util.capture_stdout(
            self.rc.execute, ["watch", "1", "3", "info", "network"]
        )
        output_list = test_util.get_separate_output(actual_out)
        info_counter = 0
        for item in output_list:
            if "Network Information" in item["title"]:
                info_counter += 1
        self.assertEqual(info_counter, 3)


if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
