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
import tarfile
import tempfile
import time
import unittest
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

from parameterized import parameterized

from lib.base_controller import BaseController
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
SILENT = "10.0.0.5:3000"
CLUSTER = "963fa489-71bd-46a9-af70-765ce26c5a62"
ARCHIVE = "collect_usage_20261116_191136.tgz"
TS = time.strptime("20261116_191136", "%Y%m%d_%H%M%S")
NO_COMMAND = "ERROR:4:unrecognized command"
NOT_FORMED = "ERROR:11:cluster not yet formed"
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


def archive_members(path):
    with tarfile.open(path) as tar:
        return {
            os.path.basename(member.name): tar.extractfile(member).read()
            for member in tar.getmembers()
            if member.isfile() and not os.path.basename(member.name).startswith("._")
        }


def archived_export(path):
    members = archive_members(path)
    usage = [name for name in members if name.endswith("_usage.json")]

    if len(usage) != 1:
        raise AssertionError(f"{path} holds {sorted(members)}")

    return members[usage[0]]


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

    async def test_no_build_that_can_be_read_leaves_it_to_the_server(self):
        self.assertIs(
            await self.supported(
                {
                    PRINCIPAL: TimeoutError("info timed out after 1s"),
                    OTHER: TimeoutError("info timed out after 1s"),
                }
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
            ("not_authenticated", "ERROR:80:not authenticated"),
            ("not_formed", NOT_FORMED),
            ("no_identity", "ERROR:11:cluster identifier not yet known"),
            (
                "upgrading",
                "ERROR:11:2 of 3 nodes run a version without usage reporting",
            ),
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

        result = await fetch_usage(self.cluster)

        self.assertEqual((result.node, result.document), (PRINCIPAL, b"[]"))

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

    async def test_another_node_answers_when_the_principal_cannot(self):
        replies = {
            PRINCIPAL: TimeoutError("info timed out after 3s"),
            OTHER: document(export(["2026-10-03"])),
        }
        self.cluster.get_nodes.return_value = [
            MagicMock(key=PRINCIPAL, node_id="C3"),
            MagicMock(key=OTHER, node_id="A1"),
        ]
        self.cluster.info_usage.side_effect = lambda nodes: {
            node: replies[node]
            for node in ([PRINCIPAL] if nodes == "principal" else nodes)
        }

        result = await fetch_usage(self.cluster)

        self.assertEqual(
            (result.node, result.document), (OTHER, document(export(["2026-10-03"])))
        )
        self.assertEqual(
            self.cluster.info_usage.await_args_list,
            [call(nodes="principal"), call(nodes=[OTHER])],
        )

    async def test_stops_at_the_first_node_with_an_export(self):
        replies = {
            PRINCIPAL: info_error(NOT_FORMED),
            OTHER: document(export(["2026-10-03"])),
            SILENT: document(export(["2026-10-03"])),
        }
        self.cluster.get_nodes.return_value = [
            MagicMock(key=PRINCIPAL, node_id="C3"),
            MagicMock(key=OTHER, node_id="A1"),
            MagicMock(key=SILENT, node_id="B2"),
        ]
        self.cluster.info_usage.side_effect = lambda nodes: {
            node: replies[node]
            for node in ([PRINCIPAL] if nodes == "principal" else nodes)
        }

        result = await fetch_usage(self.cluster)

        self.assertEqual(self.cluster.info_usage.await_count, 2)
        self.assertEqual(
            self.cluster.info_usage.await_args_list[1], call(nodes=[result.node])
        )

    async def test_no_node_answers_gives_the_principals_reply(self):
        replies = {
            PRINCIPAL: info_error(NOT_FORMED),
            OTHER: TimeoutError("info timed out after 3s"),
            SILENT: info_error("ERROR:11:cluster identifier not yet known"),
        }
        self.cluster.get_nodes.return_value = [
            MagicMock(key=PRINCIPAL, node_id="C3"),
            MagicMock(key=OTHER, node_id="A1"),
            MagicMock(key=SILENT, node_id="B2"),
        ]
        self.cluster.info_usage.side_effect = lambda nodes: {
            node: replies[node]
            for node in ([PRINCIPAL] if nodes == "principal" else nodes)
        }

        error = await self.unavailable()

        self.assertEqual(
            (error.node, error.reply, error.supported), (PRINCIPAL, NOT_FORMED, True)
        )
        self.assertEqual(
            self.cluster.info_usage.await_args_list[0], call(nodes="principal")
        )
        self.assertCountEqual(
            self.cluster.info_usage.await_args_list[1:],
            [call(nodes=[OTHER]), call(nodes=[SILENT])],
        )


class CollectUsageCommandTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        cluster = MagicMock()
        cluster.info_build = AsyncMock(return_value={PRINCIPAL: "8.2.1.0"})
        cluster.info = AsyncMock(return_value={PRINCIPAL: "prod"})
        patch.object(LiveClusterCommandController, "cluster", cluster).start()
        self.fetch = patch.object(
            collectusage_controller, "fetch_usage", AsyncMock()
        ).start()
        self.supported = patch.object(
            collectusage_controller, "usage_supported", AsyncMock(return_value=True)
        ).start()
        self.work_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work_dir, ignore_errors=True)
        self.path = os.path.join(self.work_dir, ARCHIVE)
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

    def assert_archive(self):
        self.assertTrue(tarfile.is_tarfile(self.path), f"{self.path} is not a .tgz")

    async def test_writes_the_export_byte_for_byte(self):
        self.exports(export(["2026-10-02", "2026-10-03"]))

        await self.run_command()

        self.assert_archive()
        self.assertEqual(
            archived_export(self.path), document(export(["2026-10-02", "2026-10-03"]))
        )

    async def test_the_archive_holds_the_export_and_a_meta_file_only(self):
        self.exports(export(["2026-10-03"]))

        with patch("time.gmtime", return_value=TS):
            await self.run_command()

        self.assert_archive()
        self.assertEqual(
            sorted(archive_members(self.path)),
            ["20261116_191136_usage.json", "20261116_191136_usage_meta.json"],
        )
        self.assertEqual(os.listdir(self.work_dir), [ARCHIVE])

    async def test_an_export_of_1_mib_or_more_is_not_zipped(self):
        value = export(["2026-10-03"])
        value["data"]["padding"] = "x" * (1024 * 1024)
        self.exports(value)

        await self.run_command()

        self.assert_archive()
        self.assertEqual(archived_export(self.path), document(value))

    async def test_prints_cluster_account_days_and_the_saved_file(self):
        self.exports(export(["2026-10-02", "2026-10-03"]))

        lines = await self.run_command()
        size = file_size.size(os.path.getsize(self.path))

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

    async def test_output_prefix_with_a_directory_creates_it(self):
        self.exports(export())
        self.path = os.path.join(self.work_dir, "acme", ARCHIVE)
        self.path_mock.return_value = self.path

        with self.assertNoLogs("lib", level="ERROR"):
            await self.run_command("--output-prefix", "acme/")

        self.assert_archive()

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
        self.fetch.side_effect = UsageUnavailable(PRINCIPAL, NOT_FORMED)

        with self.assertLogs("lib", level="ERROR") as cm:
            lines = await self.run_command()

        self.assertEqual(
            cm.records[0].getMessage(),
            f"Failed to get usage from {PRINCIPAL}: {NOT_FORMED}",
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


class CollectUsageMetaFileTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.cluster = MagicMock()
        self.cluster.info_build = AsyncMock(
            side_effect=lambda **_: {
                PRINCIPAL: "8.2.1.0",
                OTHER: "8.2.1.0",
                SILENT: TimeoutError("info timed out after 1s"),
            }
        )
        self.cluster.info_usage = AsyncMock(
            return_value={PRINCIPAL: document(export(["2026-10-03"]))}
        )
        self.cluster.info = AsyncMock(return_value={PRINCIPAL: "prod"})
        patch.object(LiveClusterCommandController, "cluster", self.cluster).start()
        patch.object(BaseController, "asadm_version", "5.2.0").start()
        self.work_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.work_dir, ignore_errors=True)
        self.path = os.path.join(self.work_dir, ARCHIVE)
        patch.object(
            collectusage_controller.common,
            "get_usage_file_path",
            return_value=self.path,
        ).start()
        self.addCleanup(patch.stopall)

    async def meta(self):
        with patch("time.gmtime", return_value=TS):
            with contextlib.redirect_stdout(io.StringIO()):
                await CollectusageController().execute([])

        self.assertTrue(tarfile.is_tarfile(self.path), f"{self.path} is not a .tgz")

        return json.loads(archive_members(self.path)["20261116_191136_usage_meta.json"])

    async def test_names_asadm_the_time_the_cluster_and_the_nodes(self):
        self.assertEqual(
            await self.meta(),
            {
                "meta_format_version": 1,
                "asadm_version": "5.2.0",
                "collected_ts_utc": "2026-11-16 19:11:36 UTC",
                "cluster_name": "prod",
                "cluster_uuid": CLUSTER,
                "expected_nodes": [OTHER, PRINCIPAL, SILENT],
                "responded_nodes": [OTHER, PRINCIPAL],
                "usage_node": PRINCIPAL,
            },
        )

    async def test_a_cluster_name_or_uuid_it_cannot_learn_is_null(self):
        value = export()
        del value["data"]["cluster"]
        self.cluster.info_usage.return_value = {PRINCIPAL: document(value)}
        self.cluster.info.return_value = {
            PRINCIPAL: TimeoutError("info timed out after 1s")
        }

        meta = await self.meta()

        self.assertEqual(
            (meta["cluster_name"], meta["cluster_uuid"]), (None, None), meta
        )

    async def test_no_build_that_can_be_read_still_asks_the_server(self):
        self.cluster.info_build.side_effect = lambda **_: {
            PRINCIPAL: TimeoutError("info timed out after 1s"),
            OTHER: TimeoutError("info timed out after 1s"),
        }

        with self.assertNoLogs("lib", level="WARNING"):
            with contextlib.redirect_stdout(io.StringIO()):
                await CollectusageController().execute([])

        self.assertEqual(archived_export(self.path), document(export(["2026-10-03"])))

    @parameterized.expand(
        [
            ("no_data_object", b'{"schema":2}'),
            ("not_json", b"\x1f\x8b\x08\x00"),
        ]
    )
    async def test_a_reply_that_is_not_an_export_is_saved_unchanged(self, _, reply):
        self.cluster.info_usage.return_value = {PRINCIPAL: reply}

        with self.assertNoLogs("lib", level="ERROR"):
            with contextlib.redirect_stdout(io.StringIO()):
                await CollectusageController().execute([])

        self.assertEqual(archived_export(self.path), reply)


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
        self.assertNotIn("usage-export", self.reported_failures())

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
        self.assertNotIn("usage-export", self.reported_failures())
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
        self.assertNotIn("usage-export", self.reported_failures())

    async def test_a_server_error_is_recorded_and_listed_as_a_failed_command(self):
        self.fetch.side_effect = UsageUnavailable(PRINCIPAL, NOT_FORMED)

        await self._run()

        self.assertFalse(
            os.path.exists(self.bundle_path(constants.COLLECTINFO_USAGE_FILENAME))
        )
        self.assertEqual(
            self.meta()["collection"]["usage"],
            {"status": "failed", "node": PRINCIPAL, "reply": NOT_FORMED},
        )
        self.assertIn("usage-export", self.reported_failures())
        self.assertEqual(logger_util.get_exit_code(), 0)
        self.archive_mock.assert_called_once_with(self.work_dir)

    async def test_a_failed_fetch_stays_listed_when_localhost_is_a_node(self):
        self.controller.cluster.is_localhost_a_node.return_value = True
        patch(
            "lib.live_cluster.collectinfo_controller.common.collect_sys_info",
            return_value=["iostat"],
        ).start()
        patch.object(
            CollectinfoController, "_dump_collectinfo_aerospike_conf", AsyncMock()
        ).start()
        self.fetch.side_effect = UsageUnavailable(PRINCIPAL, NOT_FORMED)

        await self._run()

        self.assertEqual(sorted(self.reported_failures()), ["iostat", "usage-export"])

    async def test_an_unexpected_error_does_not_stop_the_collection(self):
        self.fetch.side_effect = RuntimeError("boom")

        await self._run()

        self.assertEqual(
            self.meta()["collection"]["usage"],
            {"status": "failed", "node": "", "reply": "boom"},
        )
        self.assertIn("usage-export", self.reported_failures())
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
