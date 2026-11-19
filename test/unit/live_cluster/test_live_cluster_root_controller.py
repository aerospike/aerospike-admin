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

import inspect
import os
import re
import shutil
import tempfile
import unittest
from unittest.mock import ANY, AsyncMock, MagicMock, patch

from parameterized import parameterized

from lib.base_controller import ShellException
from lib.utils import logger as logger_util
from lib.live_cluster import collectusage_controller, live_cluster_root_controller
from lib.live_cluster.collectinfo_controller import CollectinfoController
from lib.live_cluster.collectlogs_controller import CollectlogsController
from lib.live_cluster.collectusage_controller import UsageExport
from lib.live_cluster.live_cluster_command_controller import (
    LiveClusterCommandController,
)
from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController
from lib.live_cluster.summary_controller import SummaryController
from lib.view.view import CliView

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

    @parameterized.expand(
        [
            (["collect", "lgos"], "lgos"),
            (["collect", "help"], "help"),
            (["collect", "lgos", "-n", "2"], "lgos"),
            (["collect", "-h"], "-h"),
            (["collect", "--help"], "--help"),
        ]
    )
    async def test_collect_refuses_an_unknown_subcommand(self, line, word):
        with self.assertRaisesRegex(
            ShellException,
            re.escape(
                f"collect: '{word}' is not a valid subcommand. "
                "See 'help collect' for available subcommands."
            ),
        ):
            await self.root.execute(line)

        self.collectinfo.assert_not_awaited()

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

    def test_help_collect_lists_usage(self):
        help_line(self.root.execute_help(["collect"]), "usage")

    def test_help_collect_usage_names_its_option_and_no_privilege(self):
        help_text = " ".join(
            ANSI.sub("", self.root.execute_help(["collect", "usage"])).split()
        )

        self.assertIn("collect usage [--output-prefix <prefix>]", help_text)
        self.assertIn("Needs server v. 8.2.1 or later.", help_text)
        self.assertNotIn("user-admin", help_text)
        self.assertNotIn("privilege", help_text)

    @parameterized.expand([("full", "usage"), ("prefix", "u")])
    async def test_collect_usage_runs_the_usage_export(self, _, name):
        usage = patch(
            "lib.live_cluster.collectusage_controller.CollectusageController._do_default",
            autospec=True,
        ).start()

        await self.root.execute(["collect", name, "--output-prefix", "pre"])

        usage.assert_awaited_once()
        self.assertEqual(usage.call_args.args[1], ["--output-prefix", "pre"])
        self.collectinfo.assert_not_awaited()

    def test_help_show_lists_usage(self):
        help_line(self.root.execute_help(["show"]), "usage")

    def test_help_show_usage_names_no_privilege(self):
        help_text = " ".join(
            ANSI.sub("", self.root.execute_help(["show", "usage"])).split()
        )

        self.assertIn("Needs server v. 8.2.1 or later.", help_text)
        self.assertNotIn("user-admin", help_text)
        self.assertNotIn("privilege", help_text)
        self.assertIn("License Usage", help_text)

    def test_help_info_lists_summary(self):
        help_line(self.root.execute_help(["info"]), "summary")

    def test_help_collect_info_keeps_collectinfo_options(self):
        help_text = ANSI.sub("", self.root.execute_help(["collect", "info"]))

        self.assertIn("Usage:  collect info [-n <num-snapshots>]", help_text)
        self.assertIn("--output-prefix", help_text)

    def test_help_collect_shows_collect_info_usage(self):
        help_text = ANSI.sub("", self.root.execute_help(["collect"]))

        self.assertIn("Usage:  collect [-n <num-snapshots>]", help_text)

    def test_help_collect_info_shows_ssh_key_pwd_takes_a_value(self):
        help_text = ANSI.sub("", self.root.execute_help(["collect", "info"]))

        self.assertIn("[--ssh-key-pwd <key-pwd>]", help_text)
        self.assertEqual(
            " ".join(help_line(help_text, "--ssh-key-pwd").split()),
            "--ssh-key-pwd - Password for the SSH key file.",
        )


RUN_COLLECTINFO = CollectinfoController._run_collectinfo
COLLECT_INFO_NAMES = [(["collectinfo"],), (["collect", "info"],), (["collect"],)]
COLLECT_LOGS_NAMES = [(["collectlogs"],), (["collect", "logs"],)]
USAGE_NODE = "10.0.0.1:3000"


class CollectOptionsTest(unittest.IsolatedAsyncioTestCase):
    """collect info, logs and usage parse their own options here. Only the
    collection, the log download and the usage fetch are stubbed."""

    async def asyncSetUp(self):
        patch.object(LiveClusterCommandController, "cluster", None).start()
        patch.object(LiveClusterRootController, "cluster", None, create=True).start()
        patch.object(
            live_cluster_root_controller,
            "Cluster",
            AsyncMock(return_value=MagicMock()),
        ).start()
        self.run_collectinfo = patch.object(
            CollectinfoController, "_run_collectinfo", autospec=True
        ).start()
        self.gather_logs = patch.object(
            CollectlogsController, "_gather_logs", autospec=True, return_value=False
        ).start()
        self.makedirs = patch(
            "lib.live_cluster.collectlogs_controller.os.makedirs"
        ).start()
        patch.object(CollectlogsController, "setup_loggers").start()
        patch.object(CollectlogsController, "teardown_loggers").start()
        patch.object(
            collectusage_controller, "usage_supported", AsyncMock(return_value=True)
        ).start()
        self.fetch_usage = patch.object(
            collectusage_controller,
            "fetch_usage",
            AsyncMock(return_value=UsageExport(USAGE_NODE, b"{}", {})),
        ).start()
        usage_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, usage_dir, ignore_errors=True)
        self.usage_path = patch.object(
            collectusage_controller.common,
            "get_usage_file_path",
            return_value=os.path.join(usage_dir, "collect_usage.tgz"),
        ).start()
        patch.object(CliView, "print_usage_saved").start()
        self.addCleanup(patch.stopall)
        self.addCleanup(logger_util.set_exit_code, 0)

        self.root = await LiveClusterRootController()
        self.root.cluster.info_build = AsyncMock(return_value={USAGE_NODE: "8.2.1.0"})
        self.root.cluster.info = AsyncMock(return_value={USAGE_NODE: "prod"})

    @parameterized.expand(
        [
            (["collect", "info", "-h"], "collect info", "-h"),
            (["collect", "info", "--help"], "collect info", "--help"),
            (["collectinfo", "-h"], "collectinfo", "-h"),
            (["collectinfo", "--help"], "collectinfo", "--help"),
        ]
    )
    async def test_help_flag_is_refused_without_collecting(self, line, command, flag):
        with self.assertRaisesRegex(
            ShellException,
            re.escape(
                f"{command}: '{flag}' is not a valid option. "
                f"See 'help {command}' for available options."
            ),
        ):
            await self.root.execute(line)

        self.run_collectinfo.assert_not_awaited()

    @parameterized.expand(
        [
            (["collect", "logs", "-h"], "collect logs", "-h"),
            (["collect", "logs", "--help"], "collect logs", "--help"),
            (["collectlogs", "-h"], "collectlogs", "-h"),
            (["collectlogs", "--help"], "collectlogs", "--help"),
        ]
    )
    async def test_help_flag_is_refused_without_downloading_logs(
        self, line, command, flag
    ):
        with self.assertRaisesRegex(
            ShellException,
            re.escape(
                f"{command}: '{flag}' is not a valid option. "
                f"See 'help {command}' for available options."
            ),
        ):
            await self.root.execute(line)

        self.gather_logs.assert_not_awaited()
        self.makedirs.assert_not_called()

    @parameterized.expand(
        [
            (["collect", "usage", "-h"], "-h"),
            (["collect", "usage", "--help"], "--help"),
            (["collect", "u", "-h"], "-h"),
        ]
    )
    async def test_help_flag_is_refused_without_exporting_usage(self, line, flag):
        with self.assertRaisesRegex(
            ShellException,
            re.escape(
                f"collect usage: '{flag}' is not a valid option. "
                "See 'help collect usage' for available options."
            ),
        ):
            await self.root.execute(line)

        self.fetch_usage.assert_not_awaited()
        self.root.cluster.info_build.assert_not_awaited()
        self.usage_path.assert_not_called()

    @parameterized.expand(
        [
            ("no_options", [], ""),
            ("output_prefix", ["--output-prefix", "pre"], "pre"),
        ]
    )
    async def test_collect_usage_options_still_reach_the_export(
        self, _, options, prefix
    ):
        with self.assertNoLogs("lib", level="ERROR"):
            await self.root.execute(["collect", "usage"] + options)

        self.fetch_usage.assert_awaited_once()
        self.usage_path.assert_called_once_with(ANY, prefix)

    async def test_collect_usage_unknown_option_is_reported_and_still_exports(self):
        with self.assertLogs("lib", level="ERROR") as logs:
            await self.root.execute(["collect", "usage", "--no-such-option"])

        self.assertEqual(
            [record.getMessage() for record in logs.records],
            ["Unrecognized option(s): --no-such-option"],
        )
        self.fetch_usage.assert_awaited_once()

    @parameterized.expand(COLLECT_INFO_NAMES)
    async def test_collect_info_options_still_reach_the_collection(self, command):
        with self.assertNoLogs("lib", level="ERROR"):
            await self.root.execute(
                command
                + [
                    "-n",
                    "2",
                    "-s",
                    "1",
                    "--output-prefix",
                    "pre",
                    "--enable-ssh",
                    "--ssh-user",
                    "admin",
                    "--ssh-port",
                    "2222",
                    "--asconfig-file",
                    "/etc/aerospike/aerospike.conf",
                ]
            )

        self.run_collectinfo.assert_awaited_once_with(
            ANY,
            ssh_user="admin",
            ssh_pwd=None,
            ssh_port=2222,
            ssh_key=None,
            ssh_key_pwd=None,
            snp_count=2,
            wait_time=1,
            ignore_errors=False,
            enable_ssh=True,
            output_prefix="pre",
            config_path="/etc/aerospike/aerospike.conf",
        )

    @parameterized.expand(COLLECT_INFO_NAMES)
    async def test_collect_info_with_still_selects_the_nodes(self, command):
        await self.root.execute(command + ["with", "1.2.3.4", "-n", "2"])

        self.run_collectinfo.assert_awaited_once()
        call = self.run_collectinfo.await_args
        args = inspect.signature(RUN_COLLECTINFO).bind(*call.args, **call.kwargs)
        self.assertEqual(args.arguments["self"].nodes, ["1.2.3.4"])
        self.assertEqual(args.arguments["snp_count"], 2)

    @parameterized.expand(COLLECT_INFO_NAMES)
    async def test_collect_info_unknown_option_is_reported_and_still_collects(
        self, command
    ):
        with self.assertLogs("lib", level="ERROR") as logs:
            await self.root.execute(command + ["--no-such-option"])

        self.assertEqual(
            [record.getMessage() for record in logs.records],
            ["Unrecognized option(s): --no-such-option"],
        )
        self.run_collectinfo.assert_awaited_once()

    @parameterized.expand(COLLECT_LOGS_NAMES)
    async def test_collect_logs_ssh_options_still_reach_the_download(self, command):
        await self.root.execute(
            command
            + [
                "--enable-ssh",
                "--ssh-user",
                "admin",
                "--ssh-pwd",
                "secret",
                "--ssh-port",
                "2222",
                "--ssh-key",
                "/keys/id_rsa",
                "--ssh-key-pwd",
                "keypass",
                "--output-prefix",
                "pre",
            ]
        )

        self.gather_logs.assert_awaited_once_with(
            ANY,
            ANY,
            enable_ssh=True,
            ssh_user="admin",
            ssh_pwd="secret",
            ssh_key="/keys/id_rsa",
            ssh_key_pwd="keypass",
            ssh_port=2222,
        )
        self.assertIn("/pre_collect_logs_", self.gather_logs.await_args.args[1])
