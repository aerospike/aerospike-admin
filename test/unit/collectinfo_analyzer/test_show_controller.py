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
    ShowConfigXDRController,
    ShowController,
    ShowDistributionController,
    ShowJobsController,
    ShowLatenciesController,
    ShowMaskingController,
    ShowPmapController,
    ShowRacksController,
    ShowRolesController,
    ShowRosterController,
    ShowSIndexController,
    ShowStatisticsController,
    ShowStatisticsXDRController,
    ShowStopWritesController,
    ShowUdfsController,
    ShowUserAgentsController,
    ShowUsersController,
    ShowUsersStatsController,
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
                f"show masking: no masking rules matching {filter_desc} in this collectinfo."
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
            [
                "show jobs: no query jobs matching the given filters in this collectinfo."
            ],
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

    def test_show_jobs_without_any_jobs_warns_once(self):
        self._set_jobs_data({"1.1.1.1": {}})

        with self.assertLogs(NO_DATA_LOGGER, level="WARNING") as cm:
            self.controller._do_default([])

        self.assertEqual(
            [r.getMessage() for r in cm.records],
            ["show jobs: no jobs in this collectinfo."],
        )

    def test_show_jobs_with_only_queries_logs_nothing(self):
        self._set_jobs_data(
            {"1.1.1.1": {constants.JobType.QUERY: {"1": {"ns": "test"}}}}
        )

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

        self.assertEqual(self.view_mock.show_jobs.call_count, 3)

    def test_show_jobs_where_matches_nothing_warns_once(self):
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
            self.controller._do_default(["-where", "status=active"])

        self.assertEqual(
            [r.getMessage() for r in cm.records],
            ["show jobs: no jobs matching the given filters in this collectinfo."],
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

    def test_no_snapshots_warns(self):
        warnings = self.no_data_warnings(lambda: self._run({}))

        self.assertEqual(
            warnings, ["show user-agents: no user agents in this collectinfo."]
        )
        self.view_mock.show_user_agents.assert_not_called()

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
            warnings, ["show users: no user named 'bob' in this collectinfo."]
        )
        self.view_mock.show_users.assert_not_called()

    def test_users_present_logs_nothing(self):
        self.log_handler.admin_acl.return_value = {
            "ts": {"n1": {"alice": {"roles": ["read"]}}}
        }

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

        self.view_mock.show_users.assert_called_once()

    def test_like_is_a_filter_not_a_username(self):
        """`show users like acs` reaches the command with the modifier still in
        line; taking it as the username asked the bundle for a user called like."""
        self.log_handler.admin_acl.return_value = {
            "ts": {"n1": {"acs-admin": {"roles": ["read"]}}}
        }
        self.controller.mods = {"like": ["acs"]}

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default(["like", "acs"])

        self.view_mock.show_users.assert_called_once_with(
            {"acs-admin": {"roles": ["read"]}}, timestamp="ts", like=["acs"]
        )

    def test_like_matching_no_user_warns(self):
        self.log_handler.admin_acl.return_value = {
            "ts": {"n1": {"acs-admin": {"roles": ["read"]}}}
        }
        self.controller.mods = {"like": ["zzz"]}

        warnings = self.no_data_warnings(
            lambda: self.controller._do_default(["like", "zzz"])
        )

        self.assertEqual(
            warnings, ["show users: no users matching zzz in this collectinfo."]
        )
        self.view_mock.show_users.assert_called_once()

    def test_named_user_filtered_out_by_like_names_the_filter(self):
        self.log_handler.admin_acl.return_value = {
            "ts": {"n1": {"acs-admin": {"roles": ["read"]}}}
        }
        self.controller.mods = {"like": ["zzz"]}

        warnings = self.no_data_warnings(
            lambda: self.controller._do_default(["acs-admin", "like", "zzz"])
        )

        self.assertEqual(
            warnings, ["show users: no users matching zzz in this collectinfo."]
        )


class ShowUsersStatsControllerTest(AnalyzerControllerTestCase):
    def setUp(self):
        super().setUp()
        self.controller = ShowUsersStatsController()
        self.controller.mods = {"like": []}
        self.log_handler.admin_acl.return_value = {
            "ts": {"n1": {"acs-admin": {"conns-in-use": 1}}}
        }

    def test_like_is_a_filter_not_a_username(self):
        self.controller.mods = {"like": ["acs"]}

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            asyncio.run(self.controller._do_default(["like", "acs"]))

        self.view_mock.show_users_stats.assert_called_once()

    def test_named_user_not_in_bundle(self):
        warnings = self.no_data_warnings(
            lambda: asyncio.run(self.controller._do_default(["bob"]))
        )

        self.assertEqual(
            warnings,
            ["show users statistics: no user named 'bob' in this collectinfo."],
        )
        self.view_mock.show_users_stats.assert_not_called()

    def test_like_matching_no_user_warns_and_renders_nothing(self):
        self.controller.mods = {"like": ["zzz"]}

        warnings = self.no_data_warnings(
            lambda: asyncio.run(self.controller._do_default(["like", "zzz"]))
        )

        self.assertEqual(
            warnings,
            ["show users statistics: no users matching zzz in this collectinfo."],
        )
        self.view_mock.show_users_stats.assert_not_called()

    def test_named_user_filtered_out_by_like_names_the_filter(self):
        self.controller.mods = {"like": ["zzz"]}

        warnings = self.no_data_warnings(
            lambda: asyncio.run(
                self.controller._do_default(["acs-admin", "like", "zzz"])
            )
        )

        self.assertEqual(
            warnings,
            ["show users statistics: no users matching zzz in this collectinfo."],
        )


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
                "show statistics namespace: no namespace statistics matching nope in this collectinfo."
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


class ShowPmapControllerTest(AnalyzerControllerTestCase):
    """A bundle with no pmap stanza, from an older asadm or a collection that failed
    on every node, must not render as a cluster with no partitions."""

    def setUp(self):
        super().setUp()
        self.controller = ShowPmapController()
        self.controller.mods = {}

    def test_do_default_renders_each_populated_timestamp(self):
        pmap = {"1.1.1.1:3000": {"test": {"master_partition_count": 4096}}}
        self.log_handler.info_pmap.return_value = {"2026-01-01 00:00:00 UTC": pmap}

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

        self.view_mock.show_pmap.assert_called_once()

    @parameterized.expand(
        [
            ("no_snapshot_has_pmap", {"2026-01-01 00:00:00 UTC": {}}),
            ("no_node_has_pmap", {"2026-01-01 00:00:00 UTC": {"1.1.1.1:3000": {}}}),
        ]
    )
    def test_do_default_warns_once_and_renders_nothing(self, _, pmap_data):
        self.log_handler.info_pmap.return_value = pmap_data

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings, ["show pmap: no partition map data in this collectinfo."]
        )
        self.view_mock.show_pmap.assert_not_called()


class ShowConfigDefaultTest(AnalyzerControllerTestCase):
    """Plain `show config` fans out to sub-commands; a section that is normally
    empty, like security on a CE bundle, must not warn under the aggregate."""

    def setUp(self):
        super().setUp()
        self.controller = ShowConfigController()
        self.controller.mods = {"like": [], "diff": [], "for": []}

    def test_plain_show_config_stays_quiet_about_missing_security(self):
        def getconfig(stanza, **kwargs):
            if stanza == constants.CONFIG_SECURITY:
                return {"ts": {"n1": {}}}

            if stanza == constants.CONFIG_NAMESPACE:
                return {"ts": {"test": {"n1": {"replication-factor": "2"}}}}

            return {"ts": {"n1": {"key": "value"}}}

        self.log_handler.info_getconfig.side_effect = getconfig

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

    def test_show_config_security_alone_warns(self):
        self.log_handler.info_getconfig.return_value = {"ts": {"n1": {}}}

        warnings = self.no_data_warnings(lambda: self.controller.do_security([]))

        self.assertEqual(
            warnings,
            ["show config security: no security configuration in this collectinfo."],
        )


class ShowConfigXDRDefaultTest(AnalyzerControllerTestCase):
    """`show config xdr` runs three sub-commands; a bundle without XDR gets one
    line, not one per sub-command."""

    def setUp(self):
        super().setUp()
        self.controller = ShowConfigXDRController()
        self.controller.mods = {"like": [], "diff": [], "for": []}
        self.controller.getter = MagicMock()

    def _set_xdr(self, xdr, dcs, namespaces):
        self.controller.getter.get_xdr.return_value = xdr
        self.controller.getter.get_xdr_dcs.return_value = dcs
        self.controller.getter.get_xdr_namespaces.return_value = namespaces

    def test_bundle_without_xdr_warns_once(self):
        self._set_xdr({"ts": {"n1": {}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {}}})

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings, ["show config xdr: no XDR configuration in this collectinfo."]
        )

    def test_bundle_with_only_dc_config_logs_nothing(self):
        self._set_xdr(
            {"ts": {"n1": {}}}, {"ts": {"n1": {"dc1": {}}}}, {"ts": {"n1": {}}}
        )

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

    def test_bundle_with_only_xdr_context_logs_nothing(self):
        self._set_xdr(
            {"ts": {"n1": {"src-id": "1"}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {}}}
        )

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

    def test_for_filter_matching_nothing_warns_despite_the_xdr_context(self):
        """The xdr context is never empty on a 5.x bundle and has no dc or
        namespace for a for filter to match, so it cannot vouch for one."""
        self._set_xdr(
            {"ts": {"n1": {"src-id": "1"}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {}}}
        )
        self.controller.mods["for"] = ["nope"]

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings,
            [
                "show config xdr: no XDR DC or namespace configuration matching nope in this collectinfo."
            ],
        )

    def test_for_filter_leaving_dcs_without_namespaces_warns(self):
        """The getter keeps a dc whose namespaces the filter removed."""
        self._set_xdr(
            {"ts": {"n1": {"src-id": "1"}}},
            {"ts": {"n1": {}}},
            {"ts": {"n1": {"dc1": {}}}},
        )
        self.controller.mods["for"] = ["nope"]

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings,
            [
                "show config xdr: no XDR DC or namespace configuration matching nope in this collectinfo."
            ],
        )

    def test_sub_command_alone_still_warns(self):
        self._set_xdr({"ts": {"n1": {}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {}}})

        warnings = self.no_data_warnings(lambda: self.controller.do_dc([]))

        self.assertEqual(
            warnings,
            ["show config xdr dc: no XDR DC configuration in this collectinfo."],
        )


class ShowStatisticsDefaultTest(AnalyzerControllerTestCase):
    """Plain `show statistics` must not warn about sets when every record is in
    the null set."""

    def setUp(self):
        super().setUp()
        self.controller = ShowStatisticsController()
        self.controller.mods = {"like": [], "for": []}
        self.controller.getter = MagicMock()
        self.controller.getter.get_sets.return_value = {"ts": {}}

    def test_plain_show_statistics_stays_quiet_about_missing_sets(self):
        def statistics(stanza, flip=False):
            if stanza == constants.STAT_NAMESPACE:
                return {"ts": {"test": {"n1": {"objects": "1"}}}}

            return {"ts": {"n1": {"uptime": "1"}}}

        self.log_handler.info_statistics.side_effect = statistics

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

    def test_show_statistics_sets_alone_warns(self):
        warnings = self.no_data_warnings(lambda: self.controller.do_sets([]))

        self.assertEqual(
            warnings, ["show statistics sets: no set statistics in this collectinfo."]
        )


class ShowStatisticsXDRDefaultTest(AnalyzerControllerTestCase):
    """`show statistics xdr` runs three sub-commands; a bundle without XDR gets
    one neutral line, and the old server-version guess is gone."""

    def setUp(self):
        super().setUp()
        self.controller = ShowStatisticsXDRController()
        self.controller.mods = {"like": [], "for": []}
        self.controller.getter = MagicMock()

    def _set_xdr(self, xdr, dcs, namespaces):
        self.controller.getter.get_xdr.return_value = xdr
        self.controller.getter.get_xdr_dcs.return_value = dcs
        self.controller.getter.get_xdr_namespaces.return_value = namespaces

    def test_bundle_without_xdr_warns_once(self):
        self._set_xdr({"ts": {"n1": {}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {}}})

        with self.assertNoLogs(
            "lib.collectinfo_analyzer.show_controller", level="WARNING"
        ):
            warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings, ["show statistics xdr: no XDR statistics in this collectinfo."]
        )

    def test_bundle_with_only_namespace_stats_logs_nothing(self):
        self._set_xdr(
            {"ts": {"n1": {}}},
            {"ts": {"n1": {}}},
            {"ts": {"n1": {"dc1": {"test": {"lag": "0"}}}}},
        )

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

    def test_bundle_with_only_xdr_context_stats_logs_nothing(self):
        self._set_xdr(
            {"ts": {"n1": {"uptime": "1"}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {}}}
        )

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

    def test_for_filter_matching_nothing_warns_despite_the_xdr_context(self):
        self._set_xdr(
            {"ts": {"n1": {"uptime": "1"}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {}}}
        )
        self.controller.mods["for"] = ["nope"]

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings,
            [
                "show statistics xdr: no XDR DC or namespace statistics matching nope in this collectinfo."
            ],
        )

    def test_namespace_filter_leaving_dcs_without_namespaces_warns(self):
        """The getter keeps a dc whose namespaces the filter removed."""
        self._set_xdr(
            {"ts": {"n1": {}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {"dc1": {}}}}
        )
        self.controller.mods["for"] = ["nope"]

        warnings = self.no_data_warnings(lambda: self.controller.do_namespace([]))

        self.assertEqual(
            warnings,
            [
                "show statistics xdr namespace: no XDR namespace statistics matching nope in this collectinfo."
            ],
        )

    def test_sub_command_alone_still_warns(self):
        self._set_xdr({"ts": {"n1": {}}}, {"ts": {"n1": {}}}, {"ts": {"n1": {}}})

        warnings = self.no_data_warnings(lambda: self.controller.do_namespace([]))

        self.assertEqual(
            warnings,
            [
                "show statistics xdr namespace: no XDR namespace statistics in this collectinfo."
            ],
        )


class ShowDistributionDefaultTest(AnalyzerControllerTestCase):
    """Plain `show distribution` runs ttl and object size over the same
    histogram snapshot; an empty one gets one line, and a for filter that
    matches no namespace is reported rather than rendering nothing."""

    HISTOGRAM = {"ts": {"n1": {"test": {"data": [1, 0], "width": 10}}}}

    def setUp(self):
        super().setUp()
        self.controller = ShowDistributionController()
        self.controller.mods = {"for": []}

    def test_empty_bundle_warns_once(self):
        self.log_handler.info_histogram.return_value = {"ts": {"n1": {}}}

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings, ["show distribution: no distribution data in this collectinfo."]
        )

    def test_sub_command_alone_still_warns(self):
        self.log_handler.info_histogram.return_value = {"ts": {"n1": {}}}

        warnings = self.no_data_warnings(lambda: self.controller.do_time_to_live([]))

        self.assertEqual(
            warnings,
            [
                "show distribution time_to_live: no TTL distribution data in this collectinfo."
            ],
        )

    def test_for_filter_matching_no_namespace_warns(self):
        self.log_handler.info_histogram.return_value = self.HISTOGRAM
        self.controller.mods = {"for": ["nope"]}

        warnings = self.no_data_warnings(lambda: self.controller._do_default([]))

        self.assertEqual(
            warnings,
            [
                "show distribution: no distribution data matching nope in this collectinfo."
            ],
        )
        self.assertEqual(self.view_mock.show_distribution.call_count, 2)

    def test_for_filter_matching_a_namespace_logs_nothing(self):
        self.log_handler.info_histogram.return_value = self.HISTOGRAM
        self.controller.mods = {"for": ["te"]}

        with self.assertNoLogs(NO_DATA_LOGGER, level="WARNING"):
            self.controller._do_default([])

        self.assertEqual(self.view_mock.show_distribution.call_count, 2)


EMPTY_NODE = {"ts": {"n1": {}}}
EMPTY_SNAPSHOT = {"ts": {}}
CONFIG_MODS = {"like": [], "diff": [], "for": []}
STAT_MODS = {"like": [], "for": []}


class AnalyzerShowNoDataSweepTest(AnalyzerControllerTestCase):
    """Every routed analyzer show command names itself when the bundle holds
    nothing for it, whether the section is absent or every node is empty."""

    def _controller(self, controller_class, mods, overrides):
        controller = controller_class()
        controller.mods = dict(mods)

        getter = MagicMock()
        for name in (
            "get_xdr",
            "get_xdr_dcs",
            "get_xdr_namespaces",
            "get_xdr_filters",
            "get_users",
            "get_namespace",
            "get_sets",
        ):
            getattr(getter, name).return_value = EMPTY_NODE
        getter.get_service.return_value = EMPTY_SNAPSHOT
        getter.get_builds.return_value = {"ts": {"n1": "6.0.0"}}

        for attr in ("getter", "stat_getter", "config_getter", "meta_getter"):
            if hasattr(controller, attr):
                setattr(controller, attr, getter)

        self.log_handler.info_getconfig.return_value = EMPTY_NODE
        self.log_handler.info_statistics.return_value = EMPTY_SNAPSHOT
        self.log_handler.info_histogram.return_value = EMPTY_NODE
        self.log_handler.info_latency.return_value = EMPTY_SNAPSHOT
        self.log_handler.admin_acl.return_value = EMPTY_SNAPSHOT
        self.log_handler.info_meta_data.return_value = EMPTY_SNAPSHOT

        for name, value in overrides.items():
            getattr(self.log_handler, name).return_value = value

        return controller

    @staticmethod
    def _run(controller, method):
        result = getattr(controller, method)([])

        if asyncio.iscoroutine(result):
            asyncio.run(result)

    @parameterized.expand(
        [
            (
                "config_network",
                ShowConfigController,
                "do_network",
                CONFIG_MODS,
                {},
                "show config network: no network configuration in this collectinfo.",
            ),
            (
                "config_namespace",
                ShowConfigController,
                "do_namespace",
                CONFIG_MODS,
                {"info_getconfig": EMPTY_SNAPSHOT},
                "show config namespace: no namespace configuration in this collectinfo.",
            ),
            (
                "config_dc",
                ShowConfigController,
                "do_dc",
                CONFIG_MODS,
                {},
                "show config dc: no XDR DC configuration in this collectinfo.",
            ),
            (
                "config_xdr",
                ShowConfigXDRController,
                "_do_xdr",
                CONFIG_MODS,
                {},
                "show config xdr: no XDR configuration in this collectinfo.",
            ),
            (
                "config_xdr_namespace",
                ShowConfigXDRController,
                "do_namespace",
                CONFIG_MODS,
                {},
                "show config xdr namespace: no XDR namespace configuration in this collectinfo.",
            ),
            (
                "config_xdr_filter",
                ShowConfigXDRController,
                "do_filter",
                CONFIG_MODS,
                {},
                "show config xdr filter: no XDR filters in this collectinfo.",
            ),
            (
                "distribution_time_to_live",
                ShowDistributionController,
                "do_time_to_live",
                {"for": []},
                {},
                "show distribution time_to_live: no TTL distribution data in this collectinfo.",
            ),
            (
                "distribution_object_size",
                ShowDistributionController,
                "do_object_size",
                {"for": []},
                {},
                "show distribution object_size: no object size distribution data in this collectinfo.",
            ),
            (
                "latencies",
                ShowLatenciesController,
                "_do_default",
                STAT_MODS,
                {},
                "show latencies: no latency data in this collectinfo.",
            ),
            (
                "statistics_service",
                ShowStatisticsController,
                "do_service",
                STAT_MODS,
                {},
                "show statistics service: no service statistics in this collectinfo.",
            ),
            (
                "statistics_bins",
                ShowStatisticsController,
                "do_bins",
                STAT_MODS,
                {},
                "show statistics bins: no bin statistics in this collectinfo.",
            ),
            (
                "statistics_dc",
                ShowStatisticsController,
                "do_dc",
                STAT_MODS,
                {},
                "show statistics dc: no XDR DC statistics in this collectinfo.",
            ),
            (
                "statistics_sindex",
                ShowStatisticsController,
                "do_sindex",
                STAT_MODS,
                {},
                "show statistics sindex: no sindex statistics in this collectinfo.",
            ),
            (
                "statistics_xdr_dc",
                ShowStatisticsXDRController,
                "do_dc",
                STAT_MODS,
                {},
                "show statistics xdr dc: no XDR DC statistics in this collectinfo.",
            ),
            (
                "users_statistics",
                ShowUsersStatsController,
                "_do_default",
                {"like": []},
                {},
                "show users statistics: no users in this collectinfo.",
            ),
            (
                "roles",
                ShowRolesController,
                "_do_default",
                {"like": []},
                {},
                "show roles: no roles in this collectinfo.",
            ),
            (
                "udfs",
                ShowUdfsController,
                "_do_default",
                {"like": []},
                {},
                "show udfs: no UDF modules in this collectinfo.",
            ),
            (
                "sindex",
                ShowSIndexController,
                "_do_default",
                {"like": []},
                {},
                "show sindex: no secondary indexes in this collectinfo.",
            ),
            (
                "roster",
                ShowRosterController,
                "_do_default",
                CONFIG_MODS,
                {},
                "show roster: no roster data in this collectinfo.",
            ),
            (
                "stop_writes",
                ShowStopWritesController,
                "_do_default",
                {"for": []},
                {},
                "show stop-writes: no service statistics in this collectinfo.",
            ),
        ]
    )
    def test_command_names_itself_when_the_bundle_has_nothing(
        self, _, controller_class, method, mods, overrides, expected
    ):
        controller = self._controller(controller_class, mods, overrides)

        warnings = self.no_data_warnings(lambda: self._run(controller, method))

        self.assertEqual(warnings, [expected])
