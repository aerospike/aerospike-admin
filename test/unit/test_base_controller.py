# Copyright 2013-2023 Aerospike, Inc.
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
import warnings
from parameterized import parameterized

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import asynctest

from lib.base_controller import (
    BaseController,
    CommandController,
    CommandHelp,
    ModifierHelp,
    ShellException,
)


class CommandHelpTest(unittest.TestCase):
    def test_has_help(self):
        def tester():
            return

        self.assertFalse(CommandHelp.has_help(tester))

        msg = CommandHelp("test", "test", "test")
        tester = msg(tester)

        self.assertTrue(CommandHelp.has_help(tester))


@CommandHelp(
    "I am ROOT!!!",
)
class FakeRoot(BaseController):
    def __init__(self):
        self.modifiers = set()

        self.controller_map = {"fakea1": FakeCommand1, "fakeb2": FakeCommand2}


@CommandHelp(
    "Fake Command 1 Help",
    short_msg="Fake Command 1 Help.",
    usage="<default usage>",
)
class FakeCommand1(CommandController):
    @CommandHelp(
        "Fake Command 1 Default",
    )
    async def _do_default(self, line):
        return await self.do_cmd(line[:])

    @CommandHelp(
        "Fake Command 1 cmd but is hidden so should not be in the list",
        hide=True,
    )
    async def do_cmd(self, line):
        return "fake1", line


@CommandHelp(
    "Fake Command 2 Help. Here is a really long line that should wrap around. Let's check if it does. We need to make sure it is long enough",
    short_msg="Fake Command 2 Help.",
    usage="<default usage>",
)
class FakeCommand2(CommandController):
    @CommandHelp("Fake Command 2 Default")
    async def _do_default(self, line):
        return await self.do_cmd(line[:])

    @CommandHelp(
        "cmd help",
    )
    async def do_cmd(self, line):
        return "fake2", line

    @CommandHelp(
        "foo help",
        usage="<foo usage>",
        modifiers=(
            ModifierHelp("one", "all about one", default="1"),
            ModifierHelp("two", "all about two", default="2"),
        ),
    )
    async def do_foo(self, line):
        return "foo", line

    async def do_for(self, line):
        return "for", line

    async def do_zoo(self, line):
        return "zoo", line


class BaseControllerTest(asynctest.TestCase):
    maxDiff = None

    def test_complete(self):
        test_lines = [
            ([], ["fakea1", "fakeb2"]),
            (["fake"], ["fakea1", "fakeb2"]),
            (["fakea1"], ["cmd"]),
            (["fakeb2"], ["cmd", "foo", "for", "zoo"]),
            (["fakeb", "c"], ["cmd"]),
            (["fakeb2", "f"], ["foo", "for"]),
            (["fakeb2", "foo"], []),
        ]

        for line, expected_completions in test_lines:
            r = FakeRoot()

            actual_completions = r.complete(line[:])
            self.assertEqual(actual_completions, expected_completions)

    def test_find_method(self):
        FakeCommand2()
        test_lines = [
            ([], "_do_default"),
            (["fake"], "ShellException"),
            (["fakea1"], "_do_default"),
            (["fakeb2"], "_do_default"),
            (["fakeb", "c"], "do_cmd"),
            (["fakeb2", "f"], "ShellException"),
            (["fakeb2", "foo"], "do_foo"),
        ]

        for line, expected_method in test_lines:
            r = FakeRoot()
            r._init()

            try:
                tline = line[:]

                actual_method = r._find_method(tline)

                try:
                    while True:
                        actual_method._init()
                        actual_method = actual_method._find_method(tline)
                except AttributeError:
                    pass

                try:
                    self.assertEqual(actual_method.__name__, expected_method)
                except AttributeError:
                    self.assertEqual(actual_method.__class__.__name__, expected_method)
            except ShellException:
                self.assertEqual("ShellException", expected_method)

    async def test_execute(self):
        test_lines = [
            ([], "ShellException"),
            (["fake"], "ShellException"),
            (["fakea1"], "fake1"),
            (["fakeb2"], "fake2"),
            (["fakeb", "c"], "fake2"),
            (["fakeb2", "f"], "ShellException"),
            (["fakeb2", "foo"], "foo"),
        ]

        r = FakeRoot()

        for line, expected_result in test_lines:
            try:
                actual_result = await r(line)
                actual_result = actual_result[0]
            except ShellException:
                self.assertEqual(expected_result, "ShellException")
            else:
                self.assertEqual(expected_result, actual_result)

    @parameterized.expand(
        [
            (
                [],
                """
I am ROOT!!!.

Usage:   COMMAND

Commands:

    Default     Print this help message
    fakea1      Fake Command 1 Help
    fakeb2      Fake Command 2 Help

Run 'help COMMAND' for more information on a command.
""",
            ),
            (["fake"], "ShellException"),
            (
                ["fakea1"],
                """
Fake Command 1 Help.

Usage:  fakea1 COMMAND
or
Usage:  fakea1 <default usage>

Commands:

    Default     Fake Command 1 Default

Run 'help fakea1 COMMAND' for more information on a command.
""",
            ),
            (
                ["fakeb2"],
                """
Fake Command 2 Help. Here is a really long line that should wrap around. Let's
check if it does. We need to make sure it is long enough.

Usage:  fakeb2 COMMAND
or
Usage:  fakeb2 <default usage>

Commands:

    Default     Fake Command 2 Default
    cmd         cmd help
    foo         foo help

Run 'help fakeb2 COMMAND' for more information on a command.
""",
            ),
            (
                ["fakeb2", "foo"],
                """
foo help.

Usage:  fakeb2 foo <foo usage>

        one     - all about one
                  Default: 1
        two     - all about two
                  Default: 2
""",
            ),
        ]
    )
    def test_execute_help(self, line, expected_result):
        r = FakeRoot()

        try:
            actual_result = r.execute_help(line)
            print(actual_result)
        except ShellException:
            self.assertEqual(expected_result, "ShellException")
        else:
            self.assertListEqual(expected_result.split("\n"), actual_result.split("\n"))

    async def test_pre_command(self):
        test_lines = [
            (
                "cmd test like bar with a".split(" "),
                [
                    (set([]), {"line": "test like bar with a".split(" ")}),
                    (
                        set(["like"]),
                        {"line": ["test"], "like": "bar with a".split(" ")},
                    ),
                    (
                        set(["with"]),
                        {"line": "test like bar".split(" "), "with": ["a"]},
                    ),
                    (
                        set(["with", "like"]),
                        {"line": ["test"], "with": ["a"], "like": ["bar"]},
                    ),
                ],
            ),
            (
                "cmd info service with a, b with a, c,".split(" "),
                [
                    (
                        set(["with"]),
                        {"line": ["info", "service"], "with": ["a", "b", "c"]},
                    ),
                    (
                        set(["with", "like"]),
                        {
                            "line": ["info", "service"],
                            "with": ["a", "b", "c"],
                            "like": [],
                        },
                    ),
                ],
            ),
        ]

        for line, results in test_lines:
            for modifiers, expected in results:
                c = FakeCommand1()
                c.modifiers = modifiers
                retval = await c(line[:])  # pre_command is a hook
                # print ""
                # print "modifiers ", c.modifiers
                # print "line:     ", line
                # print "expected: ", expected
                # print "actual:   ", c.mods
                self.assertEqual(c.mods, expected)
                self.assertEqual(retval[0], "fake1")
