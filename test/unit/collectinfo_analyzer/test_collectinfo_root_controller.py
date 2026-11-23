# Copyright 2026 Aerospike, Inc.
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

import re
import unittest
from unittest.mock import patch

from lib.base_controller import BaseController
from lib.collectinfo_analyzer import collectinfo_root_controller
from lib.collectinfo_analyzer.collectinfo_command_controller import (
    CollectinfoCommandController,
)
from lib.collectinfo_analyzer.collectinfo_root_controller import (
    CollectinfoRootController,
)
from lib.collectinfo_analyzer.summary_controller import SummaryController

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def help_line(help_text: str, command: str) -> str:
    for line in ANSI.sub("", help_text).splitlines():
        if line.split()[:1] == [command]:
            return line

    raise AssertionError(f"'{command}' not listed in:\n{help_text}")


class CollectinfoRootControllerTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        for cls, attr in (
            (BaseController, "asadm_version"),
            (BaseController, "asadm_build"),
            (CollectinfoRootController, "log_handler"),
            (CollectinfoRootController, "command"),
        ):
            patch.object(cls, attr, getattr(cls, attr)).start()

        patch.object(
            CollectinfoCommandController, "log_handler", None, create=True
        ).start()
        patch.object(collectinfo_root_controller, "CollectinfoLogHandler").start()
        self.summary = patch.object(
            SummaryController, "_do_default", autospec=True
        ).start()
        self.addCleanup(patch.stopall)

        self.root = CollectinfoRootController(clinfo_path="/no/such/bundle")

    async def test_info_summary_runs_summary_without_warning(self):
        with self.assertNoLogs("lib", level="WARNING"):
            await self.root.execute(["info", "summary", "-l"])

        self.summary.assert_called_once()
        self.assertEqual(self.summary.call_args.args[1], ["-l"])

    async def test_summary_warns_and_still_runs(self):
        with self.assertLogs("lib", level="WARNING") as cm:
            await self.root.execute(["summary", "-l"])

        self.summary.assert_called_once()
        self.assertEqual(self.summary.call_args.args[1], ["-l"])
        self.assertEqual(
            cm.records[0].getMessage(),
            "'summary' is deprecated and will be removed in a future release. "
            "Use 'info summary' instead.",
        )

    def test_help_marks_summary_deprecated(self):
        line = help_line(self.root.execute_help([]), "summary")

        self.assertTrue(line.endswith("(deprecated, use 'info summary')"), line)

    def test_help_info_lists_summary(self):
        help_line(self.root.execute_help(["info"]), "summary")
