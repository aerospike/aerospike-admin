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

import binascii
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import ANY, AsyncMock, MagicMock, patch

from parameterized import parameterized

from lib.live_cluster import collectinfo_controller, collectusage_controller
from lib.live_cluster.client.types import ASInfoResponseError
from lib.live_cluster.collectinfo_controller import CollectinfoController
from lib.live_cluster.collectusage_controller import (
    CollectusageController,
    UsageExport,
    UsageUnavailable,
    fetch_usage,
    usage_supported,
)
from lib.live_cluster.live_cluster_command_controller import (
    LiveClusterCommandController,
)
from lib.utils import constants, file_size
from lib.utils import logger as logger_util
from test.unit.live_cluster.test_collectinfo_controller import RunCollectinfoTestCase

PRINCIPAL = "10.0.0.3:3000"
OTHER = "10.0.0.1:3000"
CLUSTER = "963fa489-71bd-46a9-af70-765ce26c5a62"
NO_COMMAND = "ERROR:4:unrecognized command"
ROLE_VIOLATION = "ERROR:81:role violation - requires permission 'user-admin'"
OLDER_SERVERS = "'collect usage' is not supported on aerospike versions < 8.2.1"


def export(records=()):
    return {
        "data": {
            "cluster": CLUSTER,
            "feature_key": {"account-ID": "12345", "account-name": "Acme Corp"},
            "records": [
                {"data": {"cluster": CLUSTER, "date": date, "samples": [], "schema": 1}}
                for date in records
            ],
            "schema": 1,
            "taken": "2026-11-16T19:11:36Z",
        }
    }


def document(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def info_error(reply):
    return ASInfoResponseError("Failed to get usage", reply)


class UsageSupportedTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cluster = MagicMock()
        self.cluster.info_build = AsyncMock()

    async def supported(self, builds):
        self.cluster.info_build.return_value = builds

        return await usage_supported(self.cluster)

    async def test_every_node_on_8_2_1_or_later(self):
        self.assertIs(
            await self.supported(
                {PRINCIPAL: "8.2.1.0", OTHER: "8.2.1.0-54-ga72532d3f"}
            ),
            True,
        )
        self.cluster.info_build.assert_awaited_once_with(nodes="all")

    async def test_one_older_node_is_enough_to_say_no(self):
        self.assertIs(
            await self.supported({PRINCIPAL: "8.2.1.0", OTHER: "8.2.0.3"}), False
        )

    async def test_a_build_that_cannot_be_read_is_left_out(self):
        self.assertIs(
            await self.supported(
                {PRINCIPAL: "8.2.1.0", OTHER: TimeoutError("info timed out after 1s")}
            ),
            True,
        )


class FetchUsageTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cluster = MagicMock()
        self.cluster.info_usage = AsyncMock()

    def replies(self, principal):
        self.cluster.info_usage.return_value = {PRINCIPAL: principal}

    async def unavailable(self):
        with self.assertRaises(UsageUnavailable) as cm:
            await fetch_usage(self.cluster)

        return cm.exception

    async def test_returns_the_principals_export(self):
        self.replies(document(export(["2026-10-03"])))

        result = await fetch_usage(self.cluster)

        self.assertEqual(result.node, PRINCIPAL)
        self.assertEqual(result.document, document(export(["2026-10-03"])))
        self.assertEqual(result.data, export(["2026-10-03"])["data"])
        self.cluster.info_usage.assert_awaited_once_with(nodes="principal")

    async def test_a_build_without_the_command_means_no_usage_reporting(self):
        self.replies(info_error(NO_COMMAND))

        error = await self.unavailable()

        self.assertEqual(
            (error.node, error.reply, error.supported), (PRINCIPAL, NO_COMMAND, False)
        )
        self.cluster.info_usage.assert_awaited_once_with(nodes="principal")

    async def test_community_edition_means_no_usage_reporting(self):
        self.replies(info_error("ERROR:25:enterprise only"))

        error = await self.unavailable()

        self.assertEqual(error.reply, "ERROR:25:enterprise only")
        self.assertIs(error.supported, False)
        self.cluster.info_usage.assert_awaited_once_with(nodes="principal")

    @parameterized.expand(
        [
            ("role_violation", ROLE_VIOLATION),
            ("not_formed", "ERROR::cluster not yet formed"),
            ("no_identity", "ERROR::cluster identifier not yet known"),
            ("upgrading", "ERROR::2 of 3 nodes run a version without usage reporting"),
        ]
    )
    async def test_server_errors_pass_through_verbatim(self, _, reply):
        self.replies(info_error(reply))

        error = await self.unavailable()

        self.assertEqual(
            (error.node, error.reply, error.supported), (PRINCIPAL, reply, True)
        )
        self.cluster.info_usage.assert_awaited_once_with(nodes="principal")

    async def test_a_reply_that_is_not_base64(self):
        self.replies(binascii.Error("Incorrect padding"))

        error = await self.unavailable()

        self.assertEqual(error.reply, "could not decode the reply: Incorrect padding")
        self.assertIs(error.supported, True)

    async def test_a_reply_that_is_not_an_export(self):
        self.replies(b"[]")

        error = await self.unavailable()

        self.assertTrue(
            error.reply.startswith("could not decode the reply: "), error.reply
        )

    async def test_a_connection_failure_gives_its_error(self):
        self.replies(TimeoutError("info timed out after 1s"))

        error = await self.unavailable()

        self.assertEqual(
            (error.node, error.reply), (PRINCIPAL, "info timed out after 1s")
        )

    async def test_no_live_node(self):
        self.cluster.info_usage.side_effect = IOError(
            "Unable to find any Aerospike nodes"
        )

        error = await self.unavailable()

        self.assertEqual(
            (error.node, error.reply), ("", "Unable to find any Aerospike nodes")
        )


class CollectUsageCommandTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        patch.object(LiveClusterCommandController, "cluster", MagicMock()).start()
        self.fetch = patch.object(
            collectusage_controller, "fetch_usage", AsyncMock()
        ).start()
        self.supported = patch.object(
            collectusage_controller, "usage_supported", AsyncMock(return_value=True)
        ).start()
        self.work_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work_dir, ignore_errors=True)
        self.path = os.path.join(self.work_dir, "collect_usage_20261116_191136.json")
        self.path_mock = patch.object(
            collectusage_controller.common,
            "get_usage_file_path",
            return_value=self.path,
        ).start()
        logger_util.set_exit_code(0)
        self.addCleanup(logger_util.set_exit_code, 0)
        self.addCleanup(patch.stopall)

        self.controller = CollectusageController()

    def exports(self, value):
        self.fetch.return_value = UsageExport(PRINCIPAL, document(value), value["data"])

    async def run_command(self, *args):
        out = io.StringIO()

        with contextlib.redirect_stdout(out):
            await self.controller.execute(list(args))

        return out.getvalue().splitlines()

    async def test_writes_the_export_byte_for_byte(self):
        self.exports(export(["2026-10-02", "2026-10-03"]))

        await self.run_command()

        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), document(export(["2026-10-02", "2026-10-03"])))

    async def test_prints_cluster_account_days_and_the_saved_file(self):
        self.exports(export(["2026-10-02", "2026-10-03"]))
        size = file_size.size(len(document(export(["2026-10-02", "2026-10-03"]))))

        lines = await self.run_command()

        self.assertEqual(
            lines[:4],
            [
                f"Cluster {CLUSTER}",
                "Account Acme Corp (12345)",
                "Days    2026-10-02 to 2026-10-03, 2 days",
                f"Saved   {self.path} ({size.strip()})",
            ],
        )
        self.assertEqual(logger_util.get_exit_code(), 0)

    async def test_no_closed_day_still_writes_the_file(self):
        self.exports(export())

        lines = await self.run_command()

        self.assertTrue(os.path.exists(self.path))
        self.assertIn("Days    none closed yet", lines)

    async def test_output_prefix_names_the_file(self):
        self.exports(export())

        await self.run_command("--output-prefix", "acme")

        self.path_mock.assert_called_once_with(ANY, "acme")

    async def test_an_older_server_is_a_warning_pointing_to_collect_info(self):
        self.supported.return_value = False

        with self.assertLogs("lib", level="WARNING") as cm:
            lines = await self.run_command()

        self.assertEqual(
            [(r.levelname, r.getMessage()) for r in cm.records],
            [("WARNING", f"{OLDER_SERVERS}. Use 'collect info' instead.")],
        )
        self.fetch.assert_not_awaited()
        self.assertEqual(lines, [])
        self.assertEqual(os.listdir(self.work_dir), [])
        self.assertEqual(logger_util.get_exit_code(), 0)

    async def test_a_server_without_usage_reporting_is_a_warning(self):
        self.fetch.side_effect = UsageUnavailable(
            PRINCIPAL, "ERROR:25:enterprise only", supported=False
        )

        with self.assertLogs("lib", level="WARNING") as cm:
            lines = await self.run_command()

        self.assertEqual(
            [(r.levelname, r.getMessage()) for r in cm.records],
            [
                (
                    "WARNING",
                    "'collect usage' is not supported on this cluster "
                    f"({PRINCIPAL} replied ERROR:25:enterprise only). "
                    "Use 'collect info' instead.",
                )
            ],
        )
        self.assertEqual(lines, [])
        self.assertEqual(os.listdir(self.work_dir), [])
        self.assertEqual(logger_util.get_exit_code(), 0)

    async def test_server_error_is_shown_verbatim_and_writes_nothing(self):
        self.fetch.side_effect = UsageUnavailable(PRINCIPAL, ROLE_VIOLATION)

        with self.assertLogs("lib", level="ERROR") as cm:
            lines = await self.run_command()

        self.assertEqual(
            cm.records[0].getMessage(),
            f"Failed to get usage from {PRINCIPAL}: {ROLE_VIOLATION}",
        )
        self.assertEqual(lines, [])
        self.assertEqual(os.listdir(self.work_dir), [])
        self.assertEqual(logger_util.get_exit_code(), 2)

    async def test_failure_before_any_node_answered(self):
        self.fetch.side_effect = UsageUnavailable(
            "", "Unable to find any Aerospike nodes"
        )

        with self.assertLogs("lib", level="ERROR") as cm:
            await self.run_command()

        self.assertEqual(
            cm.records[0].getMessage(),
            "Failed to get usage: Unable to find any Aerospike nodes",
        )

    async def test_does_not_overwrite_an_existing_file(self):
        self.exports(export())

        with open(self.path, "wb") as f:
            f.write(b"old")

        with self.assertLogs("lib", level="ERROR") as cm:
            lines = await self.run_command()

        self.assertIn(self.path, cm.records[0].getMessage())
        self.assertEqual(lines, [])

        with open(self.path, "rb") as f:
            self.assertEqual(f.read(), b"old")

    async def test_unrecognized_option_is_reported(self):
        self.exports(export())

        with self.assertLogs("lib", level="ERROR") as cm:
            await self.run_command("--bogus")

        self.assertEqual(cm.records[0].getMessage(), "Unrecognized option(s): --bogus")


class CollectinfoBundleUsageFileTest(RunCollectinfoTestCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()

        patch.object(
            CollectinfoController,
            "_get_collectinfo_data_json",
            AsyncMock(return_value=({"cluster": {"A": 1}}, {"no_data_nodes": []})),
        ).start()
        self.fetch = patch.object(
            collectinfo_controller, "fetch_usage", AsyncMock()
        ).start()
        self.supported = patch.object(
            collectinfo_controller, "usage_supported", AsyncMock(return_value=True)
        ).start()
        self.failed_cmds = patch(
            "lib.live_cluster.collectinfo_controller.common.print_collectinfo_failed_cmds"
        ).start()
        logger_util.set_exit_code(0)
        self.addCleanup(logger_util.set_exit_code, 0)

    def bundle_path(self, name):
        return os.path.join(self.work_dir, "prefix_" + name)

    def meta(self):
        with open(self.bundle_path(constants.COLLECTINFO_META_FILENAME)) as f:
            return json.load(f)

    def reported_failures(self):
        return self.failed_cmds.call_args.args[0]

    async def test_bundle_holds_the_export_byte_for_byte(self):
        value = export(["2026-10-03"])
        self.fetch.return_value = UsageExport(PRINCIPAL, document(value), value["data"])

        await self._run()

        with open(self.bundle_path(constants.COLLECTINFO_USAGE_FILENAME), "rb") as f:
            self.assertEqual(f.read(), document(value))

        self.assertEqual(
            self.meta()["collection"]["usage"],
            {
                "status": "written",
                "node": PRINCIPAL,
                "file": "prefix_" + constants.COLLECTINFO_USAGE_FILENAME,
            },
        )
        self.assertNotIn("usage", self.reported_failures())

    async def test_cluster_without_usage_reporting_bundles_as_before(self):
        self.fetch.side_effect = UsageUnavailable(
            PRINCIPAL, NO_COMMAND, supported=False
        )

        with self.assertNoLogs("lib", level="WARNING"):
            await self._run()

        self.assertFalse(
            os.path.exists(self.bundle_path(constants.COLLECTINFO_USAGE_FILENAME))
        )
        self.assertEqual(
            self.meta()["collection"]["usage"],
            {"status": "unsupported", "node": PRINCIPAL, "reply": NO_COMMAND},
        )
        self.assertNotIn("usage", self.reported_failures())
        self.archive_mock.assert_called_once_with(self.work_dir)

    async def test_an_older_server_is_never_asked_and_bundles_as_before(self):
        self.supported.return_value = False

        with self.assertNoLogs("lib", level="WARNING"):
            await self._run()

        self.fetch.assert_not_awaited()
        self.assertEqual(
            self.meta()["collection"]["usage"],
            {"status": "unsupported", "min_version": "8.2.1"},
        )
        self.assertNotIn("usage", self.reported_failures())

    async def test_a_server_error_is_recorded_and_listed_as_a_failed_command(self):
        self.fetch.side_effect = UsageUnavailable(PRINCIPAL, ROLE_VIOLATION)

        await self._run()

        self.assertFalse(
            os.path.exists(self.bundle_path(constants.COLLECTINFO_USAGE_FILENAME))
        )
        self.assertEqual(
            self.meta()["collection"]["usage"],
            {"status": "failed", "node": PRINCIPAL, "reply": ROLE_VIOLATION},
        )
        self.assertIn("usage", self.reported_failures())
        self.assertEqual(logger_util.get_exit_code(), 0)
        self.archive_mock.assert_called_once_with(self.work_dir)

    async def test_an_unexpected_error_does_not_stop_the_collection(self):
        self.fetch.side_effect = RuntimeError("boom")

        await self._run()

        self.assertEqual(
            self.meta()["collection"]["usage"],
            {"status": "failed", "node": "", "reply": "boom"},
        )
        self.assertIs(self.meta()["collection"]["aborted"], False)
        self.ascollectinfo_mock.assert_awaited_once()
        self.archive_mock.assert_called_once_with(self.work_dir)

    async def test_fetched_once_however_many_snapshots(self):
        value = export()
        self.fetch.return_value = UsageExport(PRINCIPAL, document(value), value["data"])

        await self._run(snp_count=2)

        self.fetch.assert_awaited_once()

    async def test_an_aborted_collection_records_no_usage(self):
        patch.object(
            CollectinfoController,
            "_get_collectinfo_data_json",
            AsyncMock(side_effect=OSError("cluster went away")),
        ).start()

        await self._run()

        self.fetch.assert_not_awaited()
        self.assertNotIn("usage", self.meta()["collection"])
