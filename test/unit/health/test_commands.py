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

from lib.health import commands
from lib.health.exceptions import HealthException


class CommandsTest(unittest.TestCase):
    def test_do_operation(self):
        self.assertEqual(commands.do_operation("wrong_command"), None, "do_operation did not return the expected result")
        self.assertEqual(commands.do_operation("+", (1,[]), (2,[])), (3,[]), "do_operation did not return the expected result")

    def test_select_keys(self):
        data = {
            "SNAPSHOT000": {
                "NAMESPACE": {
                    "CONFIG": {
                        ("C1", "CLUSTER"):{
                            ("N1", "NODE"):{
                                ("NS1", "NAMESPACE"):{
                                    ("CONFIG1", "KEY"): 2,
                                    ("CONFIG2", "KEY"): "abcd"
                                }
                            }
                        }
                    }
                },
                "SERVICE": {
                    "CONFIG": {
                        ("C1", "CLUSTER"):{
                            ("N1", "NODE"):{
                                ("CONFIG2", "KEY"): 888
                            }
                        }
                    }
                }
            }

        }

        expected = {('C1', 'CLUSTER'): {('N1', 'NODE'): {('NS1', 'NAMESPACE'): {
                    ('CONFIG1', 'KEY'): (2, [])
                    }}}}
        self.assertEqual(commands.select_keys(data, select_keys=[(False, "CONFIG1", None)]), expected, "select_keys did not return the expected result")

        expected = {('C1', 'CLUSTER'): {('N1', 'NODE'): {('NS1', 'NAMESPACE'): {
                    ('CONFIG1', 'KEY'): (2, []),
                    ('CONFIG2', 'KEY'): ("abcd", [])
                    }}}}
        self.assertEqual(commands.select_keys(data, select_keys=[(True, "CONF", None)], select_from_keys=["NAMESPACE", "CONFIG"]), expected, "select_keys did not return the expected result")

        try:
            commands.select_keys(1, select_keys=[(True, "CONFING2", None)])
            self.fail("select_keys did not return the expected result")
        except HealthException:
            pass

        try:
            commands.select_keys(data, select_keys=[])
            self.fail("select_keys did not return the expected result")
        except HealthException:
            pass

        try:
            commands.select_keys(data, select_keys=[(False, "CONFIG3", None)])
            self.fail("select_keys did not return the expected result")
        except HealthException:
            pass

    def test_do_assert(self):
        expected = ('assert_result', {'Category': ['CATEGORY'], 'Description': 'description', 'Successmsg': 'success', 'Level': 'level', 'Failmsg': 'error', 'Keys': []})
        result = commands.do_assert(op="ASSERT", data=1, check_val=2, error="error", category="category", level="level", description="description", success_msg="success")
        self.assertEqual(result, expected, "do_assert did not return the expected result")

        result = commands.do_assert(op="ASSERT", data=1, check_val=1, error="error", category="category", level="level", description="description", success_msg="success")
        self.assertEqual(result, None, "do_assert did not return the expected result")

    def test_do_assert_if_check(self):
        arg1 = {('C1', 'CLUSTER'): {('N1', 'NODE'): {('NS1', 'NAMESPACE'): {
                    ('CONFIG1', 'KEY'): (2, [])
                    }}}}
        expected = (True, {('C1', 'CLUSTER'): {('N1', 'NODE'): {('NS1', 'NAMESPACE'): {('CONFIG1', 'KEY'): (True, [])}}}})
        result = commands.do_assert_if_check(op="==", arg1=arg1, arg2=(3, []))
        self.assertEqual(result, expected, "do_assert_if_check did not return the expected result")

        expected = (False, {('C1', 'CLUSTER'): {('N1', 'NODE'): {('NS1', 'NAMESPACE'): {('CONFIG1', 'KEY'): (False, [])}}}})
        result = commands.do_assert_if_check(op="==", arg1=arg1, arg2=(2, []))
        self.assertEqual(result, expected, "do_assert_if_check did not return the expected result")