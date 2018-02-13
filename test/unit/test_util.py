# Copyright 2013-2018 Aerospike, Inc.
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

import unittest2 as unittest
import time

from lib.utils import timeout
from lib.client import util

class UtilTest(unittest.TestCase):
    def test_info_to_dict(self):
        value = "a=1;b=@;c=c;d=1@"
        expected = {'a':'1', 'b':'@', 'c':'c', 'd':'1@'}
        result = util.info_to_dict(value)
        self.assertEqual(result, expected)
        value = ":".join(value.split(";"))
        result = util.info_to_dict(value, ':')
        self.assertEqual(result, expected)

    def test_info_colon_to_dict(self):
        value = "a=1:b=@:c=c:d=1@"
        expected = {'a':'1', 'b':'@', 'c':'c', 'd':'1@'}
        result = util.info_colon_to_dict(value)
        self.assertEqual(result, expected)

    def test_info_to_list(self):
        value = "a=1;b=@;c=c;d=1@"
        expected = ['a=1', 'b=@', 'c=c', 'd=1@']
        result = util.info_to_list(value)
        self.assertEqual(result, expected)
        value = "a=1:b=@:c=c:d=1@"
        result = util.info_to_list(value, ':')
        self.assertEqual(result, expected)

    def test_info_to_tuple(self):
        value = "a=1;b=@;c=c;d=1@"
        expected = ('a=1', 'b=@', 'c=c', 'd=1@')
        result = util.info_to_tuple(value, ';')
        self.assertEqual(result, expected)
        value = "a=1:b=@:c=c:d=1@"
        result = util.info_to_tuple(value)
        self.assertEqual(result, expected)

    def test_concurrent_map(self):
        value = range(10)
        expected = map(lambda v: v*v, value)
        result = util.concurrent_map(lambda v: v*v, value)
        self.assertEqual(result, expected)

    def test_cached(self):
        def tester(arg1, arg2, sleep):
            time.sleep(sleep)
            return arg1 + arg2

        tester = util.cached(tester, ttl=5.0)


        tester(1,2,0.2)
        tester(2,2,0.2)
        tester(3,2,0.2)

        tester = timeout.call_with_timeout(tester, 0.1)
        self.assertEqual(3, tester(1,2,0.2))
        self.assertEqual(4, tester(2,2,0.2))
        self.assertEqual(5, tester(3,2,0.2))
        self.assertRaises(timeout.TimeoutException, tester, 1, 2, 5)
