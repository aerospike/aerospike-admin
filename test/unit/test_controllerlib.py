# Copyright 2013-2014 Aerospike, Inc.
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

from mock import patch, Mock
import unittest2 as unittest
from lib.controllerlib import *
import inspect

class CommandHelpTest(unittest.TestCase):
    def test_hasHelp(self):
        def tester():
            return

        self.assertFalse(CommandHelp.hasHelp(tester))

        msg = CommandHelp("test", "test", "test")
        tester = msg(tester)

        self.assertTrue(CommandHelp.hasHelp(tester))

class FakeRoot(BaseController):
    def __init__(self):
        self.modifiers = set()

        self.controller_map = {
            'fakea1':FakeCommand1
            , 'fakeb2':FakeCommand2
        }

class FakeCommand1(CommandController):
    def _do_default(self, line):
        return self.do_cmd(line[:])

    def do_cmd(self, line):
        return 'fake1', line

class FakeCommand2(CommandController):
    def _do_default(self, line):
        return self.do_cmd(line[:])

    def do_cmd(self, line):
        return 'fake2', line

    def do_foo(self, line):
        return 'foo', line

    def do_for(self, line):
        return 'for', line

    def do_zoo(self, line):
        return 'zoo', line

class ControllerLibTest(unittest.TestCase):
    def test_complete(self):
        test_lines = [
            ([], ['fakea1', 'fakeb2'])
            , (['fake'], ['fakea1', 'fakeb2'])
            , (['fakea1'], ['cmd'])
            , (['fakeb2'], ['cmd', 'foo', 'for', 'zoo'])
            , (['fakeb', 'c'], ['cmd'])
            , (['fakeb2', 'f'], ['foo', 'for'])
            , (['fakeb2', 'foo'], [])
            ]

        for line, expected_completions in test_lines:
            r = FakeRoot()

            actual_completions = r.complete(line[:])
            self.assertEqual(actual_completions, expected_completions)

    def test_findMethod(self):
        z = FakeCommand2()
        test_lines = [
            ([], '_do_default')
            , (['fake'], 'ShellException')
            , (['fakea1'], '_do_default')
            , (['fakeb2'], '_do_default')
            , (['fakeb', 'c'], 'do_cmd')
            , (['fakeb2', 'f'], 'ShellException')
            , (['fakeb2', 'foo'], 'do_foo')
            ]

        for line, expected_method in test_lines:
            r = FakeRoot()
            r._init()

            try:
                tline = line[:]

                actual_method = r._findMethod(tline)
                
                try:
                    while(True):
                        actual_method._init()
                        actual_method = actual_method._findMethod(tline)
                except AttributeError:
                    pass

                try:
                    self.assertEqual(actual_method.__name__, expected_method)
                except AttributeError:
                    self.assertEqual(actual_method.__class__.__name__
                                     , expected_method)
            except ShellException as actual_exception:
                self.assertEqual('ShellException'
                                 , expected_method)

    def test_execute(self):
        test_lines = [
            ([], 'ShellException')
            , (['fake'], 'ShellException')
            , (['fakea1'], 'fake1')
            , (['fakeb2'], 'fake2')
            , (['fakeb', 'c'], 'fake2')
            , (['fakeb2', 'f'], 'ShellException')
            , (['fakeb2', 'foo'], 'foo')
            ]

        r = FakeRoot()

        for line, expected_result in test_lines:
            try:
                actual_result = r(line)[0]
            except ShellException:
                self.assertEqual(expected_result, 'ShellException')
            else:
                self.assertEqual(expected_result, actual_result)

    def test_preCommand(self):
        test_lines = [
            ("cmd test like bar with a".split(' ')
             , [(set([]), {'line': "test like bar with a".split(' ')})
                , (set(['like'])
                   , {'line': ['test']
                      , 'like': "bar with a".split(' ')})
                , (set(['with'])
                   , {'line': "test like bar".split(' ')
                      , 'with' : ['a']})
                , (set(['with', 'like'])
                   , {'line': ['test']
                      , 'with': ['a']
                      , 'like': ['bar']})])
            , ("cmd info service with a b with a c".split(' ')
               , [(set(['with'])
                   , {'line': ['info', 'service']
                      , 'with': ['a', 'b', 'c']})
                  , (set(['with', 'like'])
                     , {'line': ['info', 'service']
                        , 'with': ['a', 'b', 'c']
                        , 'like': []})])
        ]

        for line, results in test_lines:
            for modifiers, expected in results:
                c = FakeCommand1()
                c.modifiers = modifiers
                retval = c(line[:]) # preCommand is a hook
                # print ""
                # print "modifiers ", c.modifiers
                # print "line:     ", line
                # print "expected: ", expected
                # print "actual:   ", c.mods
                self.assertEqual(c.mods, expected)
                self.assertEqual(retval[0], 'fake1')
