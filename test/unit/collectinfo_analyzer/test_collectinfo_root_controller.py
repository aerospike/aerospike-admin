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

import contextlib
import io
import os
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from parameterized import parameterized

from lib.base_controller import BaseController, ShellException
from lib.collectinfo_analyzer import collectinfo_root_controller
from lib.collectinfo_analyzer.collectinfo_command_controller import (
    CollectinfoCommandController,
)
from lib.collectinfo_analyzer.collectinfo_root_controller import (
    CollectinfoRootController,
)
from lib.collectinfo_analyzer.summary_controller import SummaryController
from lib.view.view import CliView
from test.unit.collectinfo_analyzer.test_log_handler import write_usage_archive

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


class UsageArchiveCommandsTest(unittest.IsolatedAsyncioTestCase):
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
        self.work_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work_dir, ignore_errors=True)
        patch(
            "lib.collectinfo_analyzer.collectinfo_handler.log_handler.COLLECTINFO_DIR",
            os.path.join(self.work_dir, "extracted") + os.sep,
        ).start()
        self.addCleanup(patch.stopall)

    @parameterized.expand(
        [
            ("info_summary", ["info", "summary"]),
            ("health", ["health"]),
            ("info_network", ["info", "network"]),
            ("show_config", ["show", "config"]),
        ]
    )
    async def test_other_commands_say_the_archive_has_no_collectinfo_data(
        self, _, command
    ):
        try:
            root = CollectinfoRootController(
                clinfo_path=write_usage_archive(self.work_dir)
            )
        except ShellException as e:
            self.fail(f"-cf refused the usage archive: {e}")

        self.addCleanup(root.close)
        name = " ".join(command)

        with self.assertLogs("lib", level="WARNING") as cm:
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    await root.execute(list(command))
                except Exception as e:
                    self.fail(f"'{name}' raised {e!r}")

        messages = [(r.levelname, r.getMessage()) for r in cm.records]

        self.assertTrue(
            any("no collectinfo data" in message for _, message in messages),
            messages,
        )
        self.assertNotIn("ERROR", [level for level, _ in messages], messages)

    async def test_an_abbreviated_pager_command_turns_paging_on(self):
        patch.object(CliView, "pager", CliView.NO_PAGER).start()

        try:
            root = CollectinfoRootController(
                clinfo_path=write_usage_archive(self.work_dir)
            )
        except ShellException as e:
            self.fail(f"-cf refused the usage archive: {e}")

        self.addCleanup(root.close)

        with self.assertNoLogs("lib", level="WARNING"):
            await root.execute(["page", "on"])

        self.assertEqual(CliView.pager, CliView.LESS)
