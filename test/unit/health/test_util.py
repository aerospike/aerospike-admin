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

import unittest2 as unittest

from lib.health import constants, util

class UtilTest(unittest.TestCase):
    def test_deep_merge_dicts(self):
        arg1 = {('C1', 'CLUSTER'): {('N1', 'NODE'): {
                    ('NS1', 'NAMESPACE'): {
                        ('CONFIG1', 'KEY'): (1, [])
                    },
                    ('NS2', 'NAMESPACE'): {
                        ('CONFIG2', 'KEY'): (2, []),
                        ('CONFIG3', 'KEY'): (3, [])
                    }
                }}}
        arg2 = {('C1', 'CLUSTER'): {('N1', 'NODE'): {
                    ('NS3', 'NAMESPACE'): {
                        ('CONFIG1', 'KEY'): (3, [])
                    },
                    ('NS2', 'NAMESPACE'): {
                        ('CONFIG2', 'KEY'): (4, []),
                        ('CONFIG5', 'KEY'): (7, [])
                    }
                }}}
        expected = {('C1', 'CLUSTER'): {('N1', 'NODE'): {
                    ('NS1', 'NAMESPACE'): {
                        ('CONFIG1', 'KEY'): (1, [])
                    },
                    ('NS3', 'NAMESPACE'): {
                        ('CONFIG1', 'KEY'): (3, [])
                    },
                    ('NS2', 'NAMESPACE'): {
                        ('CONFIG2', 'KEY'): (2, []),
                        ('CONFIG3', 'KEY'): (3, []),
                        ('CONFIG5', 'KEY'): (7, [])
                    }
                }}}
        result = util.deep_merge_dicts(arg1, arg2)
        self.assertEqual(result, expected, "deep_merge_dicts did not return the expected result")

    def test_add_component_keys(self):
        comp_list = ["a", "b"]
        data = "no_dict"
        result = util.add_component_keys(data, comp_list)
        self.assertEqual(result, data, "add_component_keys did not return the expected result")

        data = {"a": { "b": { "c" : 1}}}
        result = util.add_component_keys(data, None)
        self.assertEqual(result, data, "add_component_keys did not return the expected result")

        result = util.add_component_keys(data, comp_list)
        expected = {"a": { "b": { "c" : 1}}}
        self.assertEqual(result, expected["a"]["b"], "add_component_keys did not return the expected result")
        self.assertEqual(data, expected, "add_component_keys did not return the expected result")

        comp_list.append("d")
        result = util.add_component_keys(data, comp_list)
        expected = {"a": { "b": { "c" :1, "d" :{}}}}
        self.assertEqual(result, {}, "add_component_keys did not return the expected result")
        self.assertEqual(data, expected, "add_component_keys did not return the expected result")

    def test_pop_tuple_keys_for_next_level(self):
        result, found = util.pop_tuple_keys_for_next_level([])
        self.assertEqual(result, [], "pop_tuple_keys_for_next_level did not return the expected result")
        self.assertEqual(found, False, "pop_tuple_keys_for_next_level did not return the expected result")

        key_list = [("CLUSTER", "C1"), ("NODE", "N1"), ("NAMESPACE", "NS1")]
        expected = [("CLUSTER", "C1"), ("NODE", "N1"), ("NAMESPACE", "NS1")]
        result, found = util.pop_tuple_keys_for_next_level(key_list)
        self.assertEqual(result, expected, "pop_tuple_keys_for_next_level did not return the expected result")
        self.assertEqual(found, False, "pop_tuple_keys_for_next_level did not return the expected result")

        key_list = [("CLUSTER", "C1"), ("NODE", "N1"), ("NAMESPACE", "NS1"), (None, None)]
        result, found = util.pop_tuple_keys_for_next_level(key_list)
        self.assertEqual(result, expected, "pop_tuple_keys_for_next_level did not return the expected result")
        self.assertEqual(found, True, "pop_tuple_keys_for_next_level did not return the expected result")

    def test_merge_dicts_with_new_tuple_keys(self):
        dict_from = {"a": { "b": { "c" :1}}}
        main_dict = {}
        key_list = [("CLUSTER", "C1"), ("NODE", "N1"), ("NAMESPACE", "NS1")]

        util.merge_dicts_with_new_tuple_keys(dict_from=dict_from, main_dict=main_dict, new_tuple_keys=key_list)
        expected = {('C1', 'CLUSTER'): {('N1', 'NODE'): {('NS1', 'NAMESPACE'): {'b': {('c', 'KEY'): 1}}}}}
        self.assertEqual(main_dict, expected, "merge_dicts_with_new_tuple_keys did not return the expected result")

        key_list = [("CLUSTER", "C1"), ("NODE", "N1"), (None, None), ("NAMESPACE", None)]
        util.merge_dicts_with_new_tuple_keys(dict_from=dict_from, main_dict=main_dict, new_tuple_keys=key_list)
        expected = {('C1', 'CLUSTER'): {('N1', 'NODE'): {('b', 'NAMESPACE'): {('c', 'KEY'): 1}, ('NS1', 'NAMESPACE'): {'b': {('c', 'KEY'): 1}}}}}
        self.assertEqual(main_dict, expected, "merge_dicts_with_new_tuple_keys did not return the expected result")

    def test_create_health_input_dict(self):
        dict_from = {"a": { "b": { "c" :1}}}
        main_dict = {}
        tuple_key_list = [("NODE", "N1"), ("NAMESPACE", "NS1")]
        comp_list = [("sn0", "SNAPSHOT"), ("cl1", "CLUSTER")]

        util.create_health_input_dict(dict_from=dict_from, main_dict=main_dict, new_tuple_keys=tuple_key_list, new_component_keys=comp_list)
        expected = {('sn0', 'SNAPSHOT'): {('cl1', 'CLUSTER'): {('N1', 'NODE'): {('NS1', 'NAMESPACE'): {'b': {('c', 'KEY'): 1}}}}}}
        self.assertEqual(main_dict, expected, "create_health_input_dict did not return the expected result")

    def test_h_eval(self):
        data = {('C1', 'CLUSTER'): {('N1', 'NODE'): {
                    ('NS1', 'NAMESPACE'): {
                        ('CONFIG1', 'KEY'): "false",
                        ('CONFIG2', 'KEY'): "TRUE",
                        ('CONFIG3', 'KEY'): "1",
                        ('CONFIG4', 'KEY'): "9.5",
                    },
                    ('NS2', 'NAMESPACE'): {
                        ('CONFIG1', 'KEY'): "abcd",
                        ('CONFIG2', 'KEY'): "100%",
                        ('CONFIG3', 'KEY'): "n/e"
                    }
                }
            }
        }

        expected = {('C1', 'CLUSTER'): {('N1', 'NODE'): {
                    ('NS1', 'NAMESPACE'): {
                        ('CONFIG1', 'KEY'): False,
                        ('CONFIG2', 'KEY'): True,
                        ('CONFIG3', 'KEY'): 1,
                        ('CONFIG4', 'KEY'): 9.5
                    },
                    ('NS2', 'NAMESPACE'): {
                        ('CONFIG1', 'KEY'): "abcd",
                        ('CONFIG2', 'KEY'): 100
                    }
                }
            }
        }

        self.assertEqual(util.h_eval(data), expected, "h_eval did not return the expected result")

    def test_merge_key(self):
        expected = " "
        result = util.merge_key("key", " ")
        self.assertEqual(result, expected, "merge_key did not return the expected result")

        expected = "abcd"
        result = util.merge_key("key", "abcd")
        self.assertEqual(result, expected, "merge_key did not return the expected result")

        expected = "key/test"
        result = util.merge_key("key", ("test", "NAMESPACE"), recurse=True)
        self.assertEqual(result, expected, "merge_key did not return the expected result")

        expected = "test"
        result = util.merge_key("", ("test", "NAMESPACE"), recurse=True)
        self.assertEqual(result, expected, "merge_key did not return the expected result")

    def test_make_map(self):
        self.assertEqual(util.make_map("key", 1), {("key", "KEY"): 1}, "make_map did not return the expected result")

    def test_make_key(self):
        self.assertEqual(util.make_key("key"), ("key", "KEY"), "make_key did not return the expected result")

    def test_create_value_list_to_save(self):
        op1 = [{('observed_nodes', 'KEY'): (6.0, [('conf2', 100, True)])}, {('c', 'KEY'): (106.0, [('conf1', 6.0, True)])}]
        op2 = [{('observed_nodes', 'KEY'): ("conf3", [('a', "abcd", True)])}, {('a', 'KEY'): ("testval", [('conf4', "testval", True)])}]

        key = "key"
        value = "value"

        result = util.create_value_list_to_save(save_param=None, key=key, value=value, op1=op1, op2=op2)
        expected = [('conf2', 100, True), ('conf1', 6.0, True), ('a', 'abcd', True), ('conf4', 'testval', True)]
        self.assertEqual(result, expected, "create_value_list_to_save did not return the expected result")

        result = util.create_value_list_to_save(save_param="", key=key, value=value, op1=op1, op2=op2)
        expected = [('conf2', 100, True), ('conf1', 6.0, True), ('a', 'abcd', True), ('conf4', 'testval', True), (key, value, True)]
        self.assertEqual(result, expected, "create_value_list_to_save did not return the expected result")

        result = util.create_value_list_to_save(save_param="save_key", key=key, value=value, op1=op1, op2=op2)
        expected = [('conf2', 100, True), ('conf1', 6.0, True), ('a', 'abcd', True), ('conf4', 'testval', True), ("save_key", value, True)]
        self.assertEqual(result, expected, "create_value_list_to_save did not return the expected result")

    def test_create_snapshot_key(self):
        self.assertEqual(util.create_snapshot_key(1), "SNAPSHOT001", "create_snapshot_key did not return the expected result")
        self.assertEqual(util.create_snapshot_key(10), "SNAPSHOT010", "create_snapshot_key did not return the expected result")
        self.assertEqual(util.create_snapshot_key(999), "SNAPSHOT999", "create_snapshot_key did not return the expected result")
        self.assertEqual(util.create_snapshot_key(1000, "testsnapshot"), "testsnapshot1000", "create_snapshot_key did not return the expected result")

    def test_create_health_internal_tuple(self):
        self.assertEqual(util.create_health_internal_tuple(1, [('conf2', 100, True), ('conf1', 6.0, True)]), (1, [('conf2', 100, True), ('conf1', 6.0, True)]), "create_health_internal_tuple did not return the expected result")

    def test_get_value_from_health_internal_tuple(self):
        self.assertEqual(util.get_value_from_health_internal_tuple((1, [('conf2', 100, True), ('conf1', 6.0, True)])), 1, "get_value_from_health_internal_tuple did not return the expected result")
        self.assertEqual(util.get_value_from_health_internal_tuple(9), 9, "get_value_from_health_internal_tuple did not return the expected result")
        self.assertEqual(util.get_value_from_health_internal_tuple(None), None, "get_value_from_health_internal_tuple did not return the expected result")

    def test_is_health_parser_variable(self):
        self.assertEqual(util.is_health_parser_variable(1), False, "is_health_parser_variable did not return the expected result")
        self.assertEqual(util.is_health_parser_variable(None), False, "is_health_parser_variable did not return the expected result")
        self.assertEqual(util.is_health_parser_variable(("a", "b")), False, "is_health_parser_variable did not return the expected result")
        self.assertEqual(util.is_health_parser_variable((constants.HEALTH_PARSER_VAR, "b")), True, "is_health_parser_variable did not return the expected result")

    def test_find_majority_element(self):
        value_list = [1, 2, 3, 1, 2, 1, 2, 2]
        self.assertEqual(util.find_majority_element(value_list), 2, "find_majority_element did not return the expected result")

        value_list.append(1)
        self.assertEqual(util.find_majority_element(value_list), 2, "find_majority_element did not return the expected result")

        value_list.append(1)
        self.assertEqual(util.find_majority_element(value_list), 1, "find_majority_element did not return the expected result")

        self.assertEqual(util.find_majority_element([]), None, "find_majority_element did not return the expected result")