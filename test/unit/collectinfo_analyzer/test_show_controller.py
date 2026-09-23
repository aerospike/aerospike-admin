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
import base64
import unittest
from mock import create_autospec, patch, MagicMock
from parameterized import parameterized

from lib.collectinfo_analyzer.collectinfo_command_controller import (
    CollectinfoCommandController,
)
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)
from lib.collectinfo_analyzer.show_controller import (
    ShowBestPracticesController,
    ShowConfigController,
    ShowController,
    ShowJobsController,
    ShowMaskingController,
    ShowRacksController,
    ShowStatisticsController,
    ShowUserAgentsController,
    ShowUsersController,
)
from lib.base_controller import ShellException
from lib.utils import constants
from lib.utils.constants import Modifiers

NO_DATA_LOGGER = "lib.collectinfo_analyzer.collectinfo_command_controller"


class ShowControllerAliasTest(unittest.TestCase):
    def setUp(self):
        # Sub-controllers read the log_handler off the class attribute during
        # _init(). Patch it so the mock is restored and doesn't leak into others.
        patch.object(
            CollectinfoCommandController,
            "log_handler",
            create_autospec(CollectinfoLogHandler),
            create=True,
        ).start()
        self.controller = ShowController()
        self.controller._init()
        self.addCleanup(patch.stopall)

    def test_stats_is_alias_for_statistics(self):
        self.assertEqual(self.controller.aliases, {"stats": "statistics"})

    def test_stats_alias_does_not_register_a_command(self):
        # The alias must not become a command key, otherwise the shared "stat"
        # prefix would resolve ambiguously.
        self.assertNotIn("stats", self.controller.commands.keys())
        self.assertIn("statistics", self.controller.commands.keys())

    def test_stats_alias_resolves_to_statistics_controller(self):
        method = self.controller._find_method(["stats"])
        self.assertIsInstance(method, ShowStatisticsController)

    @parameterized.expand([["stat"], ["statistics"]])
    def test_statistics_prefix_still_resolves(self, command):
        # Adding the alias must not break the existing prefix shorthand.
        method = self.controller._find_method([command])
        self.assertIsInstance(method, ShowStatisticsController)


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

        with self.assertLogs(NO_DATA_LOGGER, level="WARNING") as cm:
            result = self.controller._do_default([])

        self.assertIsNone(result)
        getter_mock.get_masking_rules.assert_called_once_with()
        # Should return early without calling view
        self.view_mock.show_masking_rules.assert_not_called()
        self.assertEqual(
            cm.records[0].getMessage(),
            "show masking: no masking rules in this collectinfo.",
        )

    @parameterized.expand(
        [
            ("not_collected", {"2023-01-01": {}}),
            ("no_rules", {"2023-01-01": {"192.168.1.1:3000": []}}),
        ]
    )
    @patch("lib.collectinfo_analyzer.get_controller.GetMaskingRulesController")
    def test_do_default_no_rules_in_bundle(self, _, masking_data, getter_class_mock):
        getter_class_mock.return_value.get_masking_rules.return_value = masking_data

        with self.assertLogs(NO_DATA_LOGGER, level="WARNING") as cm:
            self.controller._do_default([])

        self.assertEqual(
            [r.getMessage() for r in cm.records],
            ["show masking: no masking rules in this collectinfo."],
        )
        self.view_mock.show_masking_rules.assert_not_called()

    @parameterized.expand(
        [
            (["namespace", "prod"], "namespace prod"),
            (["namespace", "test", "set", "other"], "namespace test set other"),
        ]
    )
    @patch("lib.collectinfo_analyzer.get_controller.GetMaskingRulesController")
    def test_do_default_filter_matches_nothing(
        self, line, filter_desc, getter_class_mock
    ):
        getter_class_mock.return_value.get_masking_rules.return_value = {
            "2023-01-01": {
                "192.168.1.1:3000": [{"ns": "test", "set": "demo", "bin": "ssn"}]
            }
        }

        with self.assertLogs(NO_DATA_LOGGER, level="WARNING") as cm:
            self.controller._do_default(line)

        self.assertEqual(
            [r.getMessage() for r in cm.records],
            [
                f"show masking: no masking rules match {filter_desc} in this collectinfo."
            ],
        )
        self.view_mock.show_masking_rules.assert_called_once_with(
            [], timestamp="2023-01-01"
        )

    @patch("lib.collectinfo_analyzer.get_controller.GetMaskingRulesController")
    def test_do_default_rules_present_logs_nothing(self, getter_class_mock):
        getter_class_mock.return_value.get_masking_rules.return_value = {
            "2023-01-01": {"192.168.1.1:3000": [{"ns": "test", "set": "demo"}]}
        }

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default(["namespace", "test"])

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

        with self.assertLogs(NO_DATA_LOGGER, level="WARNING") as cm:
            self.controller._job_helper(constants.JobType.QUERY, "Query Jobs", [])

        self.view_mock.show_jobs.assert_called_once_with(
            "Query Jobs",
            "cinfo",
            None,
            flip_output=False,
            **self.controller.mods,
        )
        self.assertEqual(
            [r.getMessage() for r in cm.records],
            ["show jobs: no query jobs in this collectinfo."],
        )

    def test_job_helper_missing_module_quiet_under_show_jobs(self):
        self._set_jobs_data(
            {"1.1.1.1": {constants.JobType.QUERY: {"1": {"ns": "test"}}}}
        )

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._job_helper(
                constants.JobType.SCAN, "Scan Jobs", [], default=True
            )

        self.view_mock.show_jobs.assert_called_once()

    def test_job_helper_where_matches_nothing(self):
        self._set_jobs_data(
            {
                "1.1.1.1": {
                    constants.JobType.QUERY: {
                        "1": {"ns": "test", "status": "done(ok)"},
                    }
                }
            }
        )

        with self.assertLogs(NO_DATA_LOGGER, level="WARNING") as cm:
            self.controller._job_helper(
                constants.JobType.QUERY, "Query Jobs", ["-where", "status=active"]
            )

        self.assertEqual(
            [r.getMessage() for r in cm.records],
            ["show jobs: no query jobs match the given filters in this collectinfo."],
        )
        self.view_mock.show_jobs.assert_called_once()

    def test_job_helper_jobs_present_logs_nothing(self):
        self._set_jobs_data(
            {"1.1.1.1": {constants.JobType.QUERY: {"1": {"ns": "test"}}}}
        )

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._job_helper(constants.JobType.QUERY, "Query Jobs", [])

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


class AnalyzerControllerTestCase(unittest.TestCase):
    def setUp(self):
        self.log_handler = create_autospec(CollectinfoLogHandler)
        patch.object(
            CollectinfoCommandController,
            "log_handler",
            self.log_handler,
            create=True,
        ).start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.addCleanup(patch.stopall)

    def no_data_warnings(self, run):
        with self.assertLogs(NO_DATA_LOGGER, level="WARNING") as cm:
            run()

        return [r.getMessage() for r in cm.records]


class ShowUserAgentsControllerTest(AnalyzerControllerTestCase):
    def setUp(self):
        super().setUp()
        self.getter_mock = patch(
            "lib.collectinfo_analyzer.get_controller.GetUserAgentsController"
        ).start()
        self.controller = ShowUserAgentsController()
        self.controller.mods = {}

    def _run(self, user_agents_data):
        self.getter_mock.return_value.get_user_agents.return_value = user_agents_data
        asyncio.run(self.controller._do_default([]))

    @parameterized.expand(
        [
            ("not_collected", {"ts": {}}, {}),
            ("no_agents", {"ts": {"n1": []}}, {"n1": []}),
        ]
    )
    def test_warns_and_still_renders(self, _, user_agents_data, processed):
        warnings = self.no_data_warnings(lambda: self._run(user_agents_data))

        self.assertEqual(
            warnings, ["show user-agents: no user agents in this collectinfo."]
        )
        self.view_mock.show_user_agents.assert_called_once_with(
            self.log_handler.get_cinfo_log_at.return_value, processed
        )

    def test_agents_present_logs_nothing(self):
        user_agent = base64.b64encode(b"1.0,2.0,app").decode()

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self._run({"ts": {"n1": [{"user-agent": user_agent, "count": "5"}]}})


class ShowUsersControllerTest(AnalyzerControllerTestCase):
    def setUp(self):
        super().setUp()
        self.controller = ShowUsersController()
        self.controller.mods = {"like": []}

    def test_acl_not_collected(self):
        self.log_handler.admin_acl.return_value = {"ts": {}}

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(warnings, ["show users: no users in this collectinfo."])
        self.view_mock.show_users.assert_not_called()

    def test_named_user_not_in_bundle(self):
        self.log_handler.admin_acl.return_value = {
            "ts": {"n1": {"alice": {"roles": ["read"]}}}
        }

        warnings = self.no_data_warnings(lambda: self.controller._do_default(["bob"]))

        self.assertEqual(
            warnings, ["show users: no users match bob in this collectinfo."]
        )
        self.view_mock.show_users.assert_not_called()

    def test_users_present_logs_nothing(self):
        self.log_handler.admin_acl.return_value = {
            "ts": {"n1": {"alice": {"roles": ["read"]}}}
        }

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

        self.view_mock.show_users.assert_called_once()


class ShowRacksControllerTest(AnalyzerControllerTestCase):
    def setUp(self):
        super().setUp()
        self.controller = ShowRacksController()
        self.controller.mods = {}

    def test_no_nodes_in_snapshot_warns_instead_of_crashing(self):
        self.log_handler.info_getconfig.return_value = {"ts": {}}
        self.log_handler.get_node_id_to_ip_mapping.return_value = {}
        self.log_handler.get_principal.return_value = "A1"

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(warnings, ["show racks: no rack data in this collectinfo."])
        self.view_mock.show_racks.assert_not_called()


class ShowStatisticsNamespaceNoDataTest(AnalyzerControllerTestCase):
    def setUp(self):
        super().setUp()
        self.controller = ShowStatisticsController()
        self.log_handler.info_statistics.return_value = {
            "ts": {"test": {"n1": {"objects": "1"}}}
        }

    def test_for_filter_matches_nothing(self):
        self.controller.mods = {"like": [], "for": ["nope"]}

        warnings = self.no_data_warnings(lambda: self.controller.do_namespace([]))

        self.assertEqual(
            warnings,
            [
                "show statistics namespace: no namespace statistics match nope in this collectinfo."
            ],
        )
        self.view_mock.show_stats.assert_not_called()

    def test_for_filter_matches_logs_nothing(self):
        self.controller.mods = {"like": [], "for": ["test"]}

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller.do_namespace([])

        self.view_mock.show_stats.assert_called_once()


class ShowConfigServiceNoDataTest(AnalyzerControllerTestCase):
    def test_empty_stanza_warns_and_still_renders(self):
        controller = ShowConfigController()
        controller.mods = {"like": [], "diff": [], "for": []}
        self.log_handler.info_getconfig.return_value = {"ts": {"n1": {}}}

        warnings = self.no_data_warnings(lambda: controller.do_service([]))

        self.assertEqual(
            warnings,
            ["show config service: no service configuration in this collectinfo."],
        )
        self.view_mock.show_config.assert_called_once()


class ShowBestPracticesNoDataTest(AnalyzerControllerTestCase):
    def setUp(self):
        super().setUp()
        self.controller = ShowBestPracticesController()
        self.controller.mods = {}

    def test_no_violations_logs_nothing(self):
        self.log_handler.info_meta_data.return_value = {"ts": {"n1": []}}

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

        self.view_mock.show_best_practices.assert_called_once()

    @parameterized.expand(
        [
            ("not_collected", {"ts": {"n1": {}}}),
            ("failed_sub_call", {"ts": {"n1": ""}}),
        ]
    )
    def test_no_answer_in_bundle(self, _, best_practices):
        self.log_handler.info_meta_data.return_value = best_practices

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings,
            ["show best-practices: no best-practices data in this collectinfo."],
        )
