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

from lib.utils.lookupdict import PrefixDict, LookupDict

class PrefixDictTest(unittest.TestCase):
    def setUp(self):
        self.test_dict = t = PrefixDict()

        t['u01.citrusleaf.local'] = 1
        t['u02.citrusleaf.local'] = 2
        t['u11.citrusleaf.local'] = 3
        t['u12'] = 4

    def test_len(self):
        self.assertEqual(len(self.test_dict), 4)

    def test_delete(self):
        def helper(prefix):
            del self.test_dict[prefix]

        helper('u12')
        self.assertEqual(len(self.test_dict), 3)

        self.assertRaises(KeyError, helper, 'u')
        self.assertRaises(KeyError, helper, 'asdf')

        value = self.test_dict.remove('u01')
        self.assertEqual(value, 1)

    def test_get(self):
        values = self.test_dict['u0']
        self.assertTrue(1 in values)
        self.assertTrue(2 in values)
        self.assertRaises(KeyError, self.test_dict.__getitem__, 'asdf')

    def test_getkey(self):
        keys = self.test_dict.get_key('u0')
        self.assertTrue('u01.citrusleaf.local' in keys)
        self.assertTrue('u02.citrusleaf.local' in keys)
        self.assertEqual(len(keys), 2)
        self.assertRaises(KeyError, self.test_dict.get_key, 'asdf')

    def test_keys(self):
        keys = list(self.test_dict.keys())
        self.assertTrue(len(keys), 4)
        self.assertTrue('u01.citrusleaf.local' in keys)
        self.assertTrue('u02.citrusleaf.local' in keys)

    def test_contains(self):
        self.assertTrue('u01.citrusleaf.local' in self.test_dict)
        self.assertFalse('asdf' in self.test_dict)

    def test_get_prefix(self):
        prefix = self.test_dict.get_prefix('u01')
        self.assertEqual(prefix, 'u01')

        prefix = self.test_dict.get_prefix('u01.cit')
        self.assertEqual(prefix, 'u01')

        self.assertRaises(KeyError, self.test_dict.get_prefix, 'asdf')

    def test_setitem(self):
        self.test_dict['u33'] = 5
        self.assertEqual(self.test_dict['u33'][0], 5)

        self.test_dict['u01'] = 10
        self.assertTrue(1 in self.test_dict['u01'])
        self.assertTrue(10 in self.test_dict['u01'])

class LookupDictTest(unittest.TestCase):
    def setUp(self):
        self.test_dict = t = LookupDict()

        t['192.168.0.11'] = 1
        t['192.168.0.12'] = 2
        t['192.168.0.21'] = 3
        t['192.168.0.22'] = 4

    def test_len(self):
        self.assertEqual(len(self.test_dict), 4)

    def test_delete(self):
        def helper(prefix):
            del self.test_dict[prefix]

        helper('11')
        self.assertEqual(len(self.test_dict), 3)

        self.assertRaises(KeyError, helper, '192')
        self.assertRaises(KeyError, helper, 'asdf')

        value = self.test_dict.remove('21')
        self.assertEqual(value, 3)

    def test_get(self):
        values = self.test_dict['1']

        self.assertTrue(1 in values)
        self.assertTrue(3 in values)
        self.assertRaises(KeyError, self.test_dict.__getitem__, 'asdf')

    def test_getkey(self):
        keys = self.test_dict.get_key('1')
        self.assertTrue('192.168.0.11' in keys)
        self.assertTrue('192.168.0.21' in keys)
        self.assertEqual(len(keys), 4)
        self.assertRaises(KeyError, self.test_dict.get_key, 'asdf')

    def test_keys(self):
        keys = list(self.test_dict.keys())
        self.assertTrue(len(keys), 4)
        self.assertTrue('192.168.0.11' in keys)
        self.assertTrue('192.168.0.12' in keys)

    def test_contains(self):
        self.assertTrue('192.168.0.11' in self.test_dict)
        self.assertFalse('asdf' in self.test_dict)

    def test_setitem(self):
        self.test_dict['192.168.0.31'] = 5
        self.assertEqual(self.test_dict['31'][0], 5)

        self.test_dict['11'] = 10
        self.assertTrue(1 in self.test_dict['11'])
        self.assertTrue(10 in self.test_dict['11'])

    def test_getshortname(self):
        short_name = self.test_dict.get_shortname('192.168.0.11')
        self.assertEqual(short_name, '192.168.0.11')

        self.test_dict['u01.test.com.b-india'] = 5
        self.test_dict['u02.test.com.usa'] = 5
        self.test_dict['u03.test.com.aus'] = 5
        self.test_dict['u04.test.com.a-india'] = 5
        self.test_dict['u05.test.com.c-india'] = 5

        short_name = self.test_dict.get_shortname('u01.test.com.b-india')
        self.assertEqual(short_name, 'u01...b-india')

        short_name = self.test_dict.get_shortname('u02.test.com.usa')
        self.assertEqual(short_name, 'u02...sa')

        self.assertRaises(KeyError, self.test_dict.get_shortname, 'asdf')
