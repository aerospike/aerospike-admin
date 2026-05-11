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
from mock import create_autospec, patch, MagicMock

from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)
from lib.collectinfo_analyzer.show_controller import (
    ShowJobsController,
    ShowMaskingController,
)
from lib.base_controller import ShellException
from lib.utils import constants
from lib.utils.constants import Modifiers


class ShowMaskingControllerTest(unittest.TestCase):
    def setUp(self):
        self.log_handler = create_autospec(CollectinfoLogHandler)
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        # Configure view.show_masking_rules to return None (like the real method)
        self.view_mock.show_masking_rules.return_value = None
        self.controller = ShowMaskingController()
        self.controller.log_handler = self.log_handler
        self.controller.mods = {}

    def tearDown(self):
        patch.stopall()

    @patch("lib.collectinfo_analyzer.get_controller.GetMaskingRulesController")
    def test_do_default_success(self, getter_class_mock):
        """Test successful display of masking rules"""
        # Mock the getter class and its instance
        getter_mock = MagicMock()
        getter_class_mock.return_value = getter_mock

        mock_rules = [
            {
                "ns": "test",
                "set": "demo",
                "bin": "ssn",
                "type": "string",
                "function": "redact",
                "position": "0",
                "length": "4",
                "value": "*",
            }
        ]

        getter_mock.get_masking_rules.return_value = {
            "2023-01-01": {"192.168.1.1:3000": mock_rules}
        }

        result = self.controller._do_default([])

        self.assertIsNone(result)
        getter_class_mock.assert_called_once_with(self.log_handler)
        getter_mock.get_masking_rules.assert_called_once_with()
        self.view_mock.show_masking_rules.assert_called_once_with(
            mock_rules, timestamp="2023-01-01", **{}
        )

    @patch("lib.collectinfo_analyzer.get_controller.GetMaskingRulesController")
    def test_do_default_with_namespace_filter(self, getter_class_mock):
        """Test display with namespace filter"""
        getter_mock = MagicMock()
        getter_class_mock.return_value = getter_mock

        getter_mock.get_masking_rules.return_value = {
            "2023-01-01": {"192.168.1.1:3000": []}
        }

        line = ["namespace", "test"]
        result = self.controller._do_default(line)

        self.assertIsNone(result)
        getter_mock.get_masking_rules.assert_called_once_with()

    @patch("lib.collectinfo_analyzer.get_controller.GetMaskingRulesController")
    def test_do_default_with_namespace_and_set_filter(self, getter_class_mock):
        """Test display with both namespace and set filters"""
        getter_mock = MagicMock()
        getter_class_mock.return_value = getter_mock

        getter_mock.get_masking_rules.return_value = {
            "2023-01-01": {"192.168.1.1:3000": []}
        }

        line = ["namespace", "test", "set", "demo"]
        result = self.controller._do_default(line)

        self.assertIsNone(result)
        getter_mock.get_masking_rules.assert_called_once_with()

    def test_do_default_set_without_namespace_raises_error(self):
        """Test error when set is specified without namespace"""
        line = ["set", "demo"]

        with self.assertRaises(ShellException) as context:
            self.controller._do_default(line)

        self.assertIn(
            "Set filter can only be used with namespace filter", str(context.exception)
        )

    @patch("lib.collectinfo_analyzer.get_controller.GetMaskingRulesController")
    def test_do_default_empty_data(self, getter_class_mock):
        """Test handling of empty masking rules data"""
        getter_mock = MagicMock()
        getter_class_mock.return_value = getter_mock

        getter_mock.get_masking_rules.return_value = {}

        result = self.controller._do_default([])

        self.assertIsNone(result)
        getter_mock.get_masking_rules.assert_called_once_with()
        # Should return early without calling view
        self.view_mock.show_masking_rules.assert_not_called()

    @patch("lib.collectinfo_analyzer.get_controller.GetMaskingRulesController")
    def test_do_default_with_filtering(self, getter_class_mock):
        """Test filtering of rules by namespace and set"""
        getter_mock = MagicMock()
        getter_class_mock.return_value = getter_mock

        mock_rules = [
            {"ns": "test", "set": "demo", "bin": "ssn", "function": "redact"},
            {"ns": "prod", "set": "users", "bin": "email", "function": "constant"},
        ]

        getter_mock.get_masking_rules.return_value = {
            "2023-01-01": {"192.168.1.1:3000": mock_rules}
        }

        line = ["namespace", "test"]
        result = self.controller._do_default(line)

        self.assertIsNone(result)
        # Should filter to only the "test" namespace rule
        expected_filtered = [mock_rules[0]]  # Only the test namespace rule
        self.view_mock.show_masking_rules.assert_called_once_with(
            expected_filtered, timestamp="2023-01-01", **{}
        )


class ShowJobsControllerTest(unittest.TestCase):
    def setUp(self):
        self.log_handler = create_autospec(CollectinfoLogHandler)
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.controller = ShowJobsController()
        self.controller.log_handler = self.log_handler
        # parse_modifiers would normally populate these; do it manually for tests
        self.controller.mods = {Modifiers.LIKE: [], Modifiers.FOR: [], "trid": []}

    def tearDown(self):
        patch.stopall()

    def _set_jobs_data(self, per_host):
        self.log_handler.info_meta_data.return_value = {"ts": per_host}
        self.log_handler.get_cinfo_log_at.return_value = "cinfo"

    def test_job_helper_missing_module_passes_none(self):
        # Capture only has SCAN data; asking for QUERY yields None from
        # jobs_data.get(module). filter_jobs must not crash.
        self._set_jobs_data(
            {"1.1.1.1": {constants.JobType.SCAN: {"1": {"ns": "test"}}}}
        )

        self.controller._job_helper(constants.JobType.QUERY, "Query Jobs", [])

        self.view_mock.show_jobs.assert_called_once_with(
            "Query Jobs",
            "cinfo",
            None,
            flip_output=False,
            **self.controller.mods,
        )

    def test_job_helper_filters_where(self):
        self._set_jobs_data(
            {
                "1.1.1.1": {
                    constants.JobType.QUERY: {
                        "1": {"ns": "test", "status": "active(ok)"},
                        "2": {"ns": "test", "status": "done(ok)"},
                    }
                }
            }
        )

        self.controller._job_helper(
            constants.JobType.QUERY, "Query Jobs", ["-where", "status=active"]
        )

        self.view_mock.show_jobs.assert_called_once_with(
            "Query Jobs",
            "cinfo",
            {"1.1.1.1": {"1": {"ns": "test", "status": "active(ok)"}}},
            flip_output=False,
            **self.controller.mods,
        )

    def test_job_helper_flip(self):
        self._set_jobs_data(
            {"1.1.1.1": {constants.JobType.QUERY: {"1": {"ns": "test"}}}}
        )

        self.controller._job_helper(constants.JobType.QUERY, "Query Jobs", ["--flip"])

        _, kwargs = self.view_mock.show_jobs.call_args
        self.assertTrue(kwargs["flip_output"])

    def test_job_helper_for_ns_only(self):
        # One-element for_mods — exercises the len(for_mods) > 1 branch.
        self._set_jobs_data(
            {
                "1.1.1.1": {
                    constants.JobType.QUERY: {
                        "1": {"ns": "test", "set": "demo"},
                        "2": {"ns": "other", "set": "x"},
                    }
                }
            }
        )
        self.controller.mods[Modifiers.FOR] = ["test"]

        self.controller._job_helper(constants.JobType.QUERY, "Query Jobs", [])

        self.view_mock.show_jobs.assert_called_once_with(
            "Query Jobs",
            "cinfo",
            {"1.1.1.1": {"1": {"ns": "test", "set": "demo"}}},
            flip_output=False,
            **self.controller.mods,
        )

    def test_job_helper_invalid_where_raises(self):
        self._set_jobs_data({})

        with self.assertRaises(ShellException):
            self.controller._job_helper(
                constants.JobType.QUERY, "Query Jobs", ["-where", "status"]
            )

    def test_job_helper_trailing_where_no_value_raises(self):
        # Previously silently swallowed; new parser raises.
        self._set_jobs_data({})

        with self.assertRaises(ShellException):
            self.controller._job_helper(
                constants.JobType.QUERY, "Query Jobs", ["-where"]
            )
