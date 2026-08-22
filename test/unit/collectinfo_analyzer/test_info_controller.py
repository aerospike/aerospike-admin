# Copyright 2025 Aerospike, Inc.
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

import asyncio
import unittest
from unittest.mock import MagicMock, create_autospec, patch

from parameterized import parameterized

from lib.collectinfo_analyzer.collectinfo_command_controller import (
    CollectinfoCommandController,
)
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)
from lib.collectinfo_analyzer.get_controller import (
    GetConfigController,
    GetStatisticsController,
)
from lib.base_controller import ShellException
from lib.collectinfo_analyzer.info_controller import InfoController

NODE = "1.1.1.1"


class CollectinfoInfoControllerMemoryTest(unittest.TestCase):
    def setUp(self):
        self.log_handler = create_autospec(CollectinfoLogHandler)
        # log_handler is a class attribute set by CollectinfoCommandController.__init__.
        # Set it before instantiating InfoController so __init__ can build its getters.
        CollectinfoCommandController.log_handler = self.log_handler
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.logger_mock = patch(
            "lib.collectinfo_analyzer.info_controller.logger"
        ).start()
        self.controller = InfoController()
        self.controller.log_handler = self.log_handler
        self.controller.mods = {}
        self.stats_getter_mock = self.controller.stats_getter = create_autospec(
            GetStatisticsController
        )
        self.config_getter_mock = self.controller.config_getter = create_autospec(
            GetConfigController
        )
        self.addCleanup(patch.stopall)

    def set_snapshot(self, builds=None, editions=None, node_names=None):
        cinfo_log_mock = MagicMock()
        cinfo_log_mock.get_asd_build.return_value = (
            builds if builds is not None else {NODE: "8.1.3"}
        )
        cinfo_log_mock.get_asd_version.return_value = (
            editions if editions is not None else {NODE: "Enterprise"}
        )
        cinfo_log_mock.get_node_names.return_value = (
            node_names if node_names is not None else {NODE: "node1"}
        )
        self.log_handler.get_cinfo_log_at.return_value = cinfo_log_mock
        return cinfo_log_mock

    def warnings(self):
        return [c[0][0] % c[0][1:] for c in self.logger_mock.warning.call_args_list]

    def test_do_memory_iterates_timestamps_and_calls_view(self):
        ts1 = "2025-01-01T00:00:00"
        ts2 = "2025-01-02T00:00:00"

        service_stats = {
            ts1: {
                NODE: {
                    "system_free_mem_kbytes": "8000000",
                    "system_free_mem_pct": "52",
                    "heap_efficiency_pct": "83",
                    "system_thp_mem_kbytes": "0",
                }
            },
            ts2: {
                NODE: {
                    "system_free_mem_kbytes": "7000000",
                    "system_free_mem_pct": "45",
                    "heap_efficiency_pct": "80",
                    "system_thp_mem_kbytes": "0",
                }
            },
        }
        service_configs = {
            ts1: {NODE: {"cgroup-mem-tracking": "false"}},
            ts2: {NODE: {"cgroup-mem-tracking": "true"}},
        }
        ns_stats = {
            ts1: {
                NODE: {
                    "test": {
                        "index_used_bytes": "1024",
                        "sindex_used_bytes": "2048",
                        "set_index_used_bytes": "0",
                    }
                }
            },
            ts2: {
                NODE: {
                    "test": {
                        "index_used_bytes": "4096",
                        "sindex_used_bytes": "8192",
                        "set_index_used_bytes": "512",
                    }
                }
            },
        }

        self.stats_getter_mock.get_service.return_value = service_stats
        self.config_getter_mock.get_service.return_value = service_configs
        self.stats_getter_mock.get_namespace.return_value = ns_stats
        self.set_snapshot()

        self.controller.do_memory([])

        self.stats_getter_mock.get_service.assert_called_once_with()
        self.config_getter_mock.get_service.assert_called_once_with()
        self.stats_getter_mock.get_namespace.assert_called_once_with()

        self.assertEqual(self.view_mock.info_memory.call_count, 2)

        calls = self.view_mock.info_memory.call_args_list
        self.assertEqual(calls[0].args[0], service_stats[ts1])
        self.assertEqual(calls[0].args[1], service_configs[ts1])
        self.assertEqual(calls[0].args[2][NODE]["index_used_bytes"], "1024")
        self.assertEqual(calls[0].args[2][NODE]["sindex_used_bytes"], "2048")
        self.assertEqual(calls[0].kwargs["timestamp"], ts1)

        self.assertEqual(calls[1].args[0], service_stats[ts2])
        self.assertEqual(calls[1].args[2][NODE]["index_used_bytes"], "4096")
        self.assertEqual(calls[1].kwargs["timestamp"], ts2)

    def test_do_memory_missing_config_timestamp_falls_back_to_empty(self):
        ts = "2025-01-01T00:00:00"
        service_stats = {ts: {NODE: {"system_free_mem_pct": "52"}}}

        self.stats_getter_mock.get_service.return_value = service_stats
        self.config_getter_mock.get_service.return_value = {}
        self.stats_getter_mock.get_namespace.return_value = {}
        cinfo_log_mock = self.set_snapshot()

        self.controller.do_memory([])

        self.view_mock.info_memory.assert_called_once_with(
            service_stats[ts],
            {},
            {},
            cluster=cinfo_log_mock,
            builds={NODE: "8.1.3"},
            timestamp=ts,
            verbose=False,
        )

    def test_do_memory_skips_snapshots_without_service_stats(self):
        self.stats_getter_mock.get_service.return_value = {
            "2025-01-01T00:00:00": {},
            "2025-01-02T00:00:00": {NODE: {"system_free_mem_pct": "52"}},
        }
        self.config_getter_mock.get_service.return_value = {}
        self.stats_getter_mock.get_namespace.return_value = {}
        self.set_snapshot()

        self.controller.do_memory([])

        self.assertEqual(self.view_mock.info_memory.call_count, 1)

    def test_do_memory_uses_snapshot_edition_for_data_fold(self):
        ts = "2025-01-01T00:00:00"
        ns_stats = {
            ts: {
                NODE: {
                    "test": {
                        "storage-engine": "memory",
                        "index_shmem_alloc_bytes": "100",
                        "data_total_bytes": "500",
                    }
                }
            }
        }

        self.stats_getter_mock.get_service.return_value = {ts: {NODE: {}}}
        self.config_getter_mock.get_service.return_value = {ts: {NODE: {}}}
        self.stats_getter_mock.get_namespace.return_value = ns_stats
        self.set_snapshot(editions={NODE: "Community"})

        self.controller.do_memory([])

        ns_agg = self.view_mock.info_memory.call_args.args[2]
        self.assertEqual(ns_agg[NODE]["shmem_alloc_bytes"], "100")
        self.assertEqual(ns_agg[NODE]["data_alloc_bytes"], "500")

    def test_do_memory_unknown_snapshot_edition_does_not_fold(self):
        ts = "2025-01-01T00:00:00"
        self.stats_getter_mock.get_service.return_value = {ts: {NODE: {}}}
        self.config_getter_mock.get_service.return_value = {ts: {NODE: {}}}
        self.stats_getter_mock.get_namespace.return_value = {
            ts: {
                NODE: {
                    "test": {
                        "storage-engine": "memory",
                        "index_shmem_alloc_bytes": "100",
                        "data_total_bytes": "500",
                    }
                }
            }
        }
        self.set_snapshot(editions={NODE: "N/E"})

        self.controller.do_memory([])

        ns_agg = self.view_mock.info_memory.call_args.args[2]
        self.assertEqual(ns_agg[NODE]["shmem_alloc_bytes"], "100")

    def _run_with_builds(self, builds):
        ts = "2025-01-01T00:00:00"
        self.stats_getter_mock.get_service.return_value = {ts: {NODE: {}}}
        self.config_getter_mock.get_service.return_value = {ts: {NODE: {}}}
        self.stats_getter_mock.get_namespace.return_value = {ts: {NODE: {}}}
        self.set_snapshot(builds=builds)

        self.controller.do_memory([])

    @parameterized.expand(
        [
            ("missing", {NODE: None}),
            ("empty", {NODE: ""}),
            ("not_entered", {NODE: "N/E"}),
            ("too_old", {NODE: "8.1.2"}),
            ("no_nodes", {}),
        ]
    )
    def test_do_memory_warns_once_when_alloc_stats_unsupported(self, _name, builds):
        self._run_with_builds(builds)

        warnings_logged = self.warnings()
        self.assertEqual(len(warnings_logged), 1)
        self.assertIn("Allocation figures require server 8.1.3", warnings_logged[0])
        self.view_mock.info_memory.assert_called_once()

    def _run_memory_line(self, line):
        ts = "2025-01-01T00:00:00"
        self.stats_getter_mock.get_service.return_value = {ts: {NODE: {}}}
        self.config_getter_mock.get_service.return_value = {ts: {NODE: {}}}
        self.stats_getter_mock.get_namespace.return_value = {ts: {NODE: {}}}
        self.set_snapshot()

        asyncio.run(self.controller.execute(line))

        return self.view_mock.info_memory.call_args

    def test_do_memory_verbose_flag_parsed_from_line(self):
        call_args = self._run_memory_line(["memory", "--verbose"])

        self.assertTrue(call_args.kwargs["verbose"])

    def test_do_memory_verbose_defaults_off(self):
        call_args = self._run_memory_line(["memory"])

        self.assertFalse(call_args.kwargs["verbose"])

    def test_do_memory_rejects_for_modifier(self):
        self.controller.mods = {"for": ["test"], "line": []}

        with self.assertRaises(ShellException):
            self.controller.do_memory([])

        self.view_mock.info_memory.assert_not_called()
