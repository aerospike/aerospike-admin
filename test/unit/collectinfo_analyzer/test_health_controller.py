# Copyright 2022-2025 Aerospike, Inc.
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
from unittest.mock import MagicMock, create_autospec

from lib.collectinfo_analyzer.health_check_controller import HealthCheckController
from lib.health.health_checker import HealthChecker
from lib.view.view import CliView


class HealthCheckControllerDeprecationTest(unittest.TestCase):
    def setUp(self) -> None:
        HealthCheckController.health_check_input_created = False
        self.controller = HealthCheckController()
        self.log_handler_mock = self.controller.log_handler = MagicMock()
        for method in (
            "info_statistics",
            "info_getconfig",
            "info_get_originalconfig",
            "info_meta_data",
            "get_sys_data",
        ):
            getattr(self.log_handler_mock, method).return_value = {}
        self.health_checker_mock = self.controller.health_checker = create_autospec(
            HealthChecker
        )
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.mods = {}

    def test_default_warns_deprecated_and_still_runs(self):
        with self.assertLogs(
            "lib.collectinfo_analyzer.health_check_controller", level="WARNING"
        ) as cm:
            self.controller._do_default([])

        self.assertTrue(any("deprecated" in msg for msg in cm.output))
        self.health_checker_mock.execute.assert_called_once()
        self.view_mock.print_health_output.assert_called_once()
