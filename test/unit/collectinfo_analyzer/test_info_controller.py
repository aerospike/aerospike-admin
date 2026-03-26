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

import unittest
from unittest.mock import MagicMock, create_autospec, patch

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
from lib.collectinfo_analyzer.info_controller import InfoController


class CollectinfoInfoControllerMemoryTest(unittest.TestCase):
    def setUp(self):
        self.log_handler = create_autospec(CollectinfoLogHandler)
        # log_handler is a class attribute set by CollectinfoCommandController.__init__.
        # Set it before instantiating InfoController so __init__ can build its getters.
        CollectinfoCommandController.log_handler = self.log_handler
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
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

    def test_do_memory_iterates_timestamps_and_calls_view(self):
        ts1 = "2025-01-01T00:00:00"
        ts2 = "2025-01-02T00:00:00"
        node = "1.1.1.1"

        service_stats = {
            ts1: {
                node: {
                    "system_free_mem_kbytes": "8000000",
                    "system_free_mem_pct": "52",
                    "heap_efficiency_pct": "83",
                    "system_thp_mem_kbytes": "0",
                }
            },
            ts2: {
                node: {
                    "system_free_mem_kbytes": "7000000",
                    "system_free_mem_pct": "45",
                    "heap_efficiency_pct": "80",
                    "system_thp_mem_kbytes": "0",
                }
            },
        }
        service_configs = {
            ts1: {node: {"cgroup-mem-tracking": "false"}},
            ts2: {node: {"cgroup-mem-tracking": "true"}},
        }
        ns_stats = {
            ts1: {
                node: {
                    "test": {
                        "index_used_bytes": "1024",
                        "sindex_used_bytes": "2048",
                        "set_index_used_bytes": "0",
                    }
                }
            },
            ts2: {
                node: {
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

        cinfo_log_mock = MagicMock()
        self.log_handler.get_cinfo_log_at.return_value = cinfo_log_mock

        self.controller.do_memory([])

        self.stats_getter_mock.get_service.assert_called_once_with()
        self.config_getter_mock.get_service.assert_called_once_with()
        self.stats_getter_mock.get_namespace.assert_called_once_with()

        self.assertEqual(self.view_mock.info_memory.call_count, 2)

        calls = self.view_mock.info_memory.call_args_list
        first_call_args = calls[0]
        self.assertEqual(first_call_args.args[0], service_stats[ts1])
        self.assertEqual(first_call_args.args[1], service_configs[ts1])
        ns_agg_ts1 = first_call_args.args[2]
        self.assertEqual(ns_agg_ts1[node]["index_used_bytes"], "1024")
        self.assertEqual(ns_agg_ts1[node]["sindex_used_bytes"], "2048")
        self.assertEqual(first_call_args.kwargs["timestamp"], ts1)

        second_call_args = calls[1]
        self.assertEqual(second_call_args.args[0], service_stats[ts2])
        self.assertEqual(second_call_args.args[1], service_configs[ts2])
        ns_agg_ts2 = second_call_args.args[2]
        self.assertEqual(ns_agg_ts2[node]["index_used_bytes"], "4096")
        self.assertEqual(second_call_args.kwargs["timestamp"], ts2)

    def test_do_memory_missing_config_timestamp_falls_back_to_empty(self):
        """When a stats timestamp has no matching config timestamp, use empty dict."""
        ts = "2025-01-01T00:00:00"
        node = "1.1.1.1"

        service_stats = {ts: {node: {"system_free_mem_pct": "52"}}}
        service_configs = {}  # no matching timestamp
        ns_stats = {}  # no matching timestamp

        self.stats_getter_mock.get_service.return_value = service_stats
        self.config_getter_mock.get_service.return_value = service_configs
        self.stats_getter_mock.get_namespace.return_value = ns_stats

        cinfo_log_mock = MagicMock()
        self.log_handler.get_cinfo_log_at.return_value = cinfo_log_mock

        self.controller.do_memory([])

        self.view_mock.info_memory.assert_called_once_with(
            service_stats[ts],
            {},
            {},
            cluster=cinfo_log_mock,
            timestamp=ts,
        )
