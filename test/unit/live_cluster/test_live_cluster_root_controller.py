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
from unittest.mock import AsyncMock, MagicMock, patch

from parameterized import parameterized

from lib.live_cluster import live_cluster_root_controller
from lib.live_cluster.collectinfo_controller import CollectinfoController
from lib.live_cluster.collectlogs_controller import CollectlogsController
from lib.live_cluster.live_cluster_command_controller import (
    LiveClusterCommandController,
)
from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController
from lib.live_cluster.summary_controller import SummaryController

ANSI = re.compile(r"\x1b\[[0-9;]*m")


def help_line(help_text: str, command: str) -> str:
    for line in ANSI.sub("", help_text).splitlines():
        if line.split()[:1] == [command]:
            return line

    raise AssertionError(f"'{command}' not listed in:\n{help_text}")


class LiveClusterRootControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        patch.object(LiveClusterCommandController, "cluster", None).start()
        patch.object(LiveClusterRootController, "cluster", None, create=True).start()
        patch.object(
            live_cluster_root_controller,
            "Cluster",
            AsyncMock(return_value=MagicMock()),
        ).start()
        self.collectinfo = patch.object(
            CollectinfoController, "_do_default", autospec=True
        ).start()
        self.collectlogs = patch.object(
            CollectlogsController, "_do_default", autospec=True
        ).start()
        self.summary = patch.object(
            SummaryController, "_do_default", autospec=True
        ).start()
        self.addCleanup(patch.stopall)

        self.root = await LiveClusterRootController()

    async def test_collect_runs_collect_info(self):
        await self.root.execute(["collect"])

        self.collectinfo.assert_awaited_once()
        self.assertEqual(self.collectinfo.call_args.args[1], [])

    async def test_collect_passes_its_options_to_collect_info(self):
        await self.root.execute(["collect", "--output-prefix", "pre", "-n", "2"])

        self.collectinfo.assert_awaited_once()
        self.assertEqual(
            self.collectinfo.call_args.args[1], ["--output-prefix", "pre", "-n", "2"]
        )

    async def test_collect_passes_with_to_collect_info(self):
        await self.root.execute(["collect", "with", "1.2.3.4"])

        self.assertEqual(self.collectinfo.call_args.args[0].nodes, ["1.2.3.4"])

    async def test_collect_info_runs_collectinfo(self):
        await self.root.execute(["collect", "info", "--output-prefix", "pre"])

        self.collectinfo.assert_awaited_once()
        self.assertEqual(self.collectinfo.call_args.args[1], ["--output-prefix", "pre"])

    async def test_collect_info_passes_with(self):
        await self.root.execute(["collect", "info", "with", "1.2.3.4"])

        self.assertEqual(self.collectinfo.call_args.args[0].nodes, ["1.2.3.4"])

    async def test_collect_logs_runs_collectlogs(self):
        await self.root.execute(["collect", "logs", "--enable-ssh"])

        self.collectlogs.assert_awaited_once()
        self.assertEqual(self.collectlogs.call_args.args[1], ["--enable-ssh"])
        self.collectinfo.assert_not_awaited()

    async def test_info_summary_runs_summary(self):
        await self.root.execute(["info", "summary", "-l"])

        self.summary.assert_awaited_once()
        self.assertEqual(self.summary.call_args.args[1], ["-l"])

    async def test_new_commands_do_not_warn(self):
        with self.assertNoLogs("lib", level="WARNING"):
            await self.root.execute(["collect"])
            await self.root.execute(["collect", "info"])
            await self.root.execute(["collect", "logs"])
            await self.root.execute(["info", "summary"])

    @parameterized.expand(
        [
            ("collectinfo", "collect info", "collectinfo"),
            ("collectlogs", "collect logs", "collectlogs"),
            ("summary", "info summary", "summary"),
        ]
    )
    async def test_deprecated_command_warns_and_still_runs(
        self, command, replacement, mock_name
    ):
        with self.assertLogs("lib", level="WARNING") as cm:
            await self.root.execute([command, "--opt", "value"])

        mock = getattr(self, mock_name)
        mock.assert_awaited_once()
        self.assertEqual(mock.call_args.args[1], ["--opt", "value"])
        self.assertEqual(
            cm.records[0].getMessage(),
            f"'{command}' is deprecated and will be removed in a future release. "
            f"Use '{replacement}' instead.",
        )

    def test_help_lists_collect(self):
        line = help_line(self.root.execute_help([]), "collect")

        self.assertNotIn("deprecated", line)

    @parameterized.expand(
        [
            ("collectinfo", "collect info"),
            ("collectlogs", "collect logs"),
            ("summary", "info summary"),
        ]
    )
    def test_help_marks_deprecated_commands(self, command, replacement):
        line = help_line(self.root.execute_help([]), command)

        self.assertTrue(line.endswith(f"(deprecated, use '{replacement}')"), line)

    @parameterized.expand(
        [
            ("collectinfo", "collect info"),
            ("collectlogs", "collect logs"),
            ("summary", "info summary"),
        ]
    )
    def test_help_for_deprecated_command_names_its_replacement(
        self, command, replacement
    ):
        help_text = " ".join(ANSI.sub("", self.root.execute_help([command])).split())

        self.assertIn(
            f"Deprecated: use '{replacement}' instead. '{command}' will be removed "
            "in a future release.",
            help_text,
        )

    def test_help_for_deprecated_command_does_not_warn(self):
        with self.assertNoLogs("lib", level="WARNING"):
            self.root.execute_help(["collectinfo"])

    def test_help_collect_lists_info_and_logs(self):
        help_text = self.root.execute_help(["collect"])

        help_line(help_text, "info")
        help_line(help_text, "logs")

    def test_help_info_lists_summary(self):
        help_line(self.root.execute_help(["info"]), "summary")

    def test_help_collect_info_keeps_collectinfo_options(self):
        help_text = ANSI.sub("", self.root.execute_help(["collect", "info"]))

        self.assertIn("Usage:  collect info [-n <num-snapshots>]", help_text)
        self.assertIn("--output-prefix", help_text)
