# Copyright 2013-2021 Aerospike, Inc.
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

from pytest import PytestUnraisableExceptionWarning
from lib.base_controller import ShellException
from mock import patch, AsyncMock
from mock.mock import call

from lib.live_cluster.show_controller import (
    ShowBestPracticesController,
    ShowConfigController,
    ShowJobsController,
    ShowRacksController,
    ShowRolesController,
    ShowRosterController,
    ShowStatisticsController,
    ShowUsersController,
)
from lib.live_cluster.client import ASProtocolError, ASResponse
from test.unit import util as test_util

import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import asynctest


class ShowConfigControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.show_controller.ShowConfigController.cluster"
        ).start()
        self.controller = ShowConfigController()
        self.getter_mock = patch(
            "lib.live_cluster.show_controller.GetConfigController", AsyncMock()
        ).start()
        self.controller.mods = (
            {}
        )  # For some reason they are being polluted from other tests
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.controller.getter = self.getter_mock
        self.mods = {}
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

        self.addCleanup(patch.stopall)

    async def test_do_security_default(self):
        line = ["security"]
        mods = {"diff": [], "for": [], "like": [], "with": [], "line": []}
        configs = {"security": "configs"}
        self.getter_mock.get_security.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_security.assert_called_with(nodes="all")
        self.view_mock.show_config.assert_called_with(
            "Security Configuration",
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_service_default(self):
        line = ["service"]
        mods = {"diff": [], "for": [], "like": [], "with": [], "line": []}
        configs = {"service": "configs"}
        self.getter_mock.get_service.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes="all")
        self.view_mock.show_config.assert_called_with(
            "Service Configuration",
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_network_default(self):
        line = ["network"]
        mods = {"diff": [], "for": [], "like": [], "with": [], "line": []}
        configs = {"network": "configs"}
        self.getter_mock.get_network.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_network.assert_called_with(nodes="all")
        self.view_mock.show_config.assert_called_with(
            "Network Configuration",
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_namespace_default(self):
        line = "namespace for for-mod"
        configs = {"foo": "foo-configs", "bar": "bar-configs"}
        self.getter_mock.get_namespace.return_value = configs

        await self.controller.execute(line.split())

        self.getter_mock.get_namespace.assert_called_with(
            flip=True, nodes="all", for_mods=["for-mod"]
        )
        self.view_mock.show_config.assert_has_calls(
            [
                call(
                    "foo Namespace Configuration",
                    "foo-configs",
                    self.cluster_mock,
                    title_every_nth=0,
                    flip_output=False,
                    **self.controller.mods,
                ),
                call(
                    "bar Namespace Configuration",
                    "bar-configs",
                    self.cluster_mock,
                    title_every_nth=0,
                    flip_output=False,
                    **self.controller.mods,
                ),
            ]
        )


@patch("lib.base_controller.BaseController.view")
class ShowStatisticsControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.show_controller.ShowStatisticsController.cluster"
        ).start()
        self.controller = ShowStatisticsController()
        self.getter_mock = patch(
            "lib.live_cluster.show_controller.GetStatisticsController", AsyncMock()
        ).start()
        self.controller.mods = (
            {}
        )  # For some reason they are being polluted from other tests
        self.controller.getter = self.getter_mock
        self.mods = {}
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

        self.addCleanup(patch.stopall)

    async def test_do_service_default(self, view_mock):
        line = ["service"]
        mods = {"like": [], "with": [], "for": [], "line": []}
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes="all")
        view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.cluster_mock,
            show_total=False,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_service_modifiers(self, view_mock):
        line = ["service", "with", "1.2.3.4", "like", "foo", "for", "bar"]
        mods = {"like": ["foo"], "with": ["1.2.3.4"], "for": ["bar"], "line": []}
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes=["1.2.3.4"])
        view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.cluster_mock,
            show_total=False,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_service_args(self, view_mock):
        line = ["service", "-t", "-r", "17", "-flip"]
        mods = {"like": [], "with": [], "for": [], "line": line[1:]}
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes="all")
        view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.cluster_mock,
            show_total=True,
            title_every_nth=17,
            flip_output=True,
            **mods,
        )

    async def test_do_sindex(self, view_mock):
        node_addr = "1.2.3.4"
        like = "foo"
        for_ = "bar"
        line = [
            "sindex",
            "with",
            node_addr,
            "like",
            like,
            "for",
            for_,
            "-t",
            "-r",
            "17",
            "-flip",
        ]
        mods = {"like": [like], "with": [node_addr], "for": [for_], "line": []}
        stats = {"sindex1": "stats1", "sindex2": "stats2", "sindex3": "stats3"}
        self.getter_mock.get_sindex.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_sindex.assert_called_with(
            flip=True, nodes=[node_addr], for_mods=[for_]
        )
        self.assertEqual(view_mock.show_stats.call_count, 3)

        for ns_set_sindex in stats:
            view_mock.show_stats.assert_any_call(
                "{} Sindex Statistics".format(ns_set_sindex),
                stats[ns_set_sindex],
                self.cluster_mock,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **mods,
            )

    async def test_do_sets(self, view_mock):
        node_addr = "1.2.3.4"
        like = "foo"
        for_ = "bar"
        line = [
            "sets",
            "with",
            node_addr,
            "like",
            like,
            "for",
            for_,
            "-t",
            "-r",
            "17",
            "-flip",
        ]
        mods = {"like": [like], "with": [node_addr], "for": [for_], "line": []}
        stats = {
            ("ns1", "set1"): "stats1",
            ("ns2", "set2"): "stats2",
            ("ns3", "set3"): "stats3",
        }
        self.getter_mock.get_sets.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_sets.assert_called_with(
            flip=True, nodes=[node_addr], for_mods=[for_]
        )
        self.assertEqual(view_mock.show_stats.call_count, 3)

        for namespace, set_ in stats:
            view_mock.show_stats.assert_any_call(
                "{} {} Set Statistics".format(namespace, set_),
                stats[(namespace, set_)],
                self.cluster_mock,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **mods,
            )

    async def test_do_bins(self, view_mock):
        node_addr = "1.2.3.4"
        like = "foo"
        for_ = "bar"
        line = [
            "bins",
            "with",
            node_addr,
            "like",
            like,
            "for",
            for_,
            "-t",
            "-r",
            "17",
            "-flip",
        ]
        mods = {"like": [like], "with": [node_addr], "for": [for_], "line": []}
        stats = {
            "ns1": "stats1",
            "ns2": "stats2",
            "ns3": "stats3",
        }
        self.getter_mock.get_bins.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_bins.assert_called_with(
            flip=True, nodes=[node_addr], for_mods=[for_]
        )
        self.assertEqual(view_mock.show_stats.call_count, 3)

        for namespace in stats:
            view_mock.show_stats.assert_any_call(
                "{} Bin Statistics".format(namespace),
                stats[namespace],
                self.cluster_mock,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **mods,
            )


class ShowUsersControllerTest(asynctest.TestCase):
    async def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.show_controller.ShowUsersController.cluster"
        ).start()
        self.controller = ShowUsersController()
        self.getter_mock = patch(
            "lib.live_cluster.show_controller.GetUsersController", AsyncMock()
        ).start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.controller.getter = self.getter_mock
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_calls_users_successfully(self):
        resp = {
            "admin": {
                "roles": ["user-admin"],
                "read-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "write-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "connections": 4294966442,
            },
            "alpha-reader": {
                "roles": ["alpha-reader"],
                "read-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "write-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
            },
        }
        self.getter_mock.get_users.return_value = {"1.1.1.1": resp}

        await self.controller.execute([])

        self.getter_mock.get_users.assert_called_with(nodes="principal")
        self.view_mock.show_users.assert_called_with(resp, line=[])

    async def test_calls_user_successfully(self):
        resp = {
            "admin": {
                "roles": ["user-admin"],
                "read-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "write-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "connections": 4294966442,
            }
        }
        self.getter_mock.get_user.return_value = {"1.1.1.1": resp}

        await self.controller.execute(["admin"])

        self.getter_mock.get_user.assert_called_with("admin", nodes="principal")
        self.view_mock.show_users.assert_called_with(resp, **self.controller.mods)

    async def test_logs_error(self):
        as_error = ASProtocolError(
            ASResponse.ROLE_OR_PRIVILEGE_VIOLATION, "test-message"
        )
        self.getter_mock.get_users.return_value = {"1.1.1.1": as_error}

        await self.controller.execute([])

        self.getter_mock.get_users.assert_called_with(nodes="principal")
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.show_users.assert_not_called()

    async def test_raises_error(self):
        as_error = IOError("test-message")
        self.getter_mock.get_users.return_value = {"1.1.1.1": as_error}

        await test_util.assert_exception_async(
            self,
            ShellException,
            "test-message",
            self.controller.execute,
            [],
        )

        self.getter_mock.get_users.assert_called_with(nodes="principal")
        self.view_mock.show_users.assert_not_called()


class ShowRolesControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.show_controller.ShowRolesController.cluster"
        ).start()
        self.controller = ShowRolesController()
        self.getter_mock = patch(
            "lib.live_cluster.show_controller.GetRolesController", AsyncMock()
        ).start()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.controller.getter = self.getter_mock
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_calls_roles_successfully(self):
        resp = {
            "admin": {
                "roles": ["user-admin"],
                "read-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "write-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "connections": 4294966442,
            },
            "alpha-reader": {
                "roles": ["alpha-reader"],
                "read-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "write-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
            },
        }
        self.getter_mock.get_roles.return_value = {"1.1.1.1": resp}

        await self.controller.execute([])

        self.getter_mock.get_roles.assert_called_with(nodes="principal")
        self.view_mock.show_roles.assert_called_with(resp, line=[])

    async def test_calls_role_successfully(self):
        resp = {
            "admin": {
                "roles": ["user-admin"],
                "read-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "write-info": {
                    "quota": 0,
                    "single-record-tps": 0,
                    "scan-query-rps-limited": 0,
                    "scan-query-limitless": 0,
                },
                "connections": 4294966442,
            }
        }
        self.getter_mock.get_role.return_value = {"1.1.1.1": resp}

        await self.controller.execute(["admin"])

        self.getter_mock.get_role.assert_called_with("admin", nodes="principal")
        self.view_mock.show_roles.assert_called_with(resp, **self.controller.mods)

    async def test_logs_error(self):
        as_error = ASProtocolError(
            ASResponse.ROLE_OR_PRIVILEGE_VIOLATION, "test-message"
        )
        self.getter_mock.get_roles.return_value = {"1.1.1.1": as_error}

        await self.controller.execute([])

        self.getter_mock.get_roles.assert_called_with(nodes="principal")
        self.logger_mock.error.assert_called_with(as_error)
        self.view_mock.assert_not_called()

    async def test_raises_error(self):
        as_error = IOError("test-message")
        self.getter_mock.get_roles.return_value = {"1.1.1.1": as_error}

        await test_util.assert_exception_async(
            self,
            ShellException,
            "test-message",
            self.controller.execute,
            [],
        )

        self.getter_mock.get_roles.assert_called_with(nodes="principal")
        self.view_mock.assert_not_called()


class ShowBestPracticesControllerTest(asynctest.TestCase):
    def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowBestPracticesController()
        self.controller.cluster = self.cluster_mock = AsyncMock()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()

    async def test_full_support(self):
        resp = {
            "1.1.1.1": [],
            "2.2.2.2": ["best1", "best2", "best3"],
        }
        self.cluster_mock.info_build.return_value = {
            "1.1.1.1": "5.7.0",
            "2.2.2.2": "6.7.0",
        }
        self.cluster_mock.info_best_practices.return_value = resp

        await self.controller.execute([])

        self.logger_mock.warning.assert_not_called()
        self.view_mock.show_best_practices.assert_called_with(
            self.cluster_mock, resp, **self.controller.mods
        )

    async def test_partial_support(self):
        resp = {
            "1.1.1.1": Exception(),
            "2.2.2.2": ["best1", "best2", "best3"],
        }
        self.cluster_mock.info_build.return_value = {
            "1.1.1.1": "5.6.11",
            "2.2.2.2": "5.0.0",
        }
        self.cluster_mock.info_best_practices.return_value = resp

        await self.controller.execute([])

        self.logger_mock.warning.assert_called_with(
            "'show best-practices' is not supported on aerospike versions < {}", "5.7"
        )
        self.view_mock.show_best_practices.assert_called_with(
            self.cluster_mock, resp, **self.controller.mods
        )


class ShowJobsControllerTest(asynctest.TestCase):
    def setUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = patch(
            "lib.live_cluster.show_controller.ShowJobsController.cluster", AsyncMock()
        ).start()
        self.controller = ShowJobsController()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.getter_mock = patch(
            "lib.live_cluster.show_controller.GetJobsController"
        ).start()
        self.getter_mock.get_scans = AsyncMock()
        self.getter_mock.get_query = AsyncMock()
        self.getter_mock.get_sindex_builder = AsyncMock()
        self.controller.getter = self.getter_mock
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()

    async def test_default_6_0(self):
        self.getter_mock.get_query.return_value = "queries"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "6.0"}

        await self.controller.execute([])

        self.getter_mock.get_query.assert_called_with(nodes="all")
        self.assertEqual(self.view_mock.show_jobs.call_count, 1)
        self.view_mock.show_jobs.assert_has_calls(
            [
                call(
                    "Query Jobs", self.cluster_mock, "queries", **self.controller.mods
                ),
            ]
        )

    async def test_default_5_7(self):
        self.getter_mock.get_query.return_value = "queries"
        self.getter_mock.get_scans.return_value = "scans"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "5.7"}

        await self.controller.execute([])

        self.getter_mock.get_query.assert_called_with(nodes="all")
        self.getter_mock.get_scans.assert_called_with(nodes="all")
        self.assertEqual(self.view_mock.show_jobs.call_count, 2)
        self.view_mock.show_jobs.assert_has_calls(
            [
                call(
                    "Query Jobs", self.cluster_mock, "queries", **self.controller.mods
                ),
                call("Scan Jobs", self.cluster_mock, "scans", **self.controller.mods),
            ]
        )

    async def test_default_5_6(self):
        self.getter_mock.get_query.return_value = "queries"
        self.getter_mock.get_scans.return_value = "scans"
        self.getter_mock.get_sindex_builder.return_value = "sindex-builder"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "5.6"}

        await self.controller.execute([])

        self.getter_mock.get_query.assert_called_with(nodes="all")
        self.getter_mock.get_scans.assert_called_with(nodes="all")
        self.getter_mock.get_sindex_builder.assert_called_with(nodes="all")
        self.view_mock.show_jobs.assert_has_calls(
            [
                call(
                    "Query Jobs", self.cluster_mock, "queries", **self.controller.mods
                ),
                call("Scan Jobs", self.cluster_mock, "scans", **self.controller.mods),
                call(
                    "SIndex Builder Jobs",
                    self.cluster_mock,
                    "sindex-builder",
                    **self.controller.mods,
                ),
            ]
        )
        self.assertEqual(self.view_mock.show_jobs.call_count, 3)

    async def test_queries(self):
        self.getter_mock.get_query.return_value = "queries"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "6.0"}

        await self.controller.execute(["queries"])

        self.getter_mock.get_query.assert_called_with(nodes="all")
        self.view_mock.show_jobs.assert_has_calls(
            [
                call(
                    "Query Jobs", self.cluster_mock, "queries", **self.controller.mods
                ),
            ]
        )

    async def test_scans(self):
        self.getter_mock.get_scans.return_value = "scans"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "5.7"}

        await self.controller.execute(["scans"])

        self.getter_mock.get_scans.assert_called_with(nodes="all")
        self.view_mock.show_jobs.assert_has_calls(
            [
                call("Scan Jobs", self.cluster_mock, "scans", **self.controller.mods),
            ]
        )

    async def test_scans_logs_errors(self):
        self.getter_mock.get_scans.return_value = "scans"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "6.0"}

        await self.controller.execute(["scans"])

        self.getter_mock.get_scans.assert_not_called()
        self.view_mock.show_jobs.assert_not_called()
        self.logger_mock.error.assert_called_with(
            "Scans were unified into queries in server v. 6.0 and later. User 'show queries' instead."
        )

    async def test_sindex_builder(self):
        self.getter_mock.get_sindex_builder.return_value = "sindex-builder"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "5.6"}

        await self.controller.execute(["sindex"])

        self.getter_mock.get_sindex_builder.assert_called_with(nodes="all")
        self.view_mock.show_jobs.assert_has_calls(
            [
                call(
                    "SIndex Builder Jobs",
                    self.cluster_mock,
                    "sindex-builder",
                    **self.controller.mods,
                ),
            ]
        )

    async def test_sindex_builder_logs_errors(self):
        self.getter_mock.get_sindex_builder.return_value = "sindex-builder"
        self.cluster_mock.info_build.return_value = {"1.1.1.1": "5.7"}

        await self.controller.execute(["sindex"])

        self.getter_mock.get_sindex_builder.assert_not_called()
        self.view_mock.show_jobs.assert_not_called()
        self.logger_mock.error.assert_called_with(
            "SIndex builder jobs were removed in server v. 5.7 and later."
        )


class ShowRosterControllerTest(asynctest.TestCase):
    async def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowRosterController()
        self.cluster_mock = patch(
            "lib.live_cluster.show_controller.ShowRosterController.cluster"
        ).start()
        self.getter_mock = patch(
            "lib.live_cluster.show_controller.GetConfigController"
        ).start()
        self.getter_mock.get_roster = AsyncMock()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.controller.getter = self.getter_mock
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    @asynctest.fail_on(active_handles=True)
    async def test_no_mods(self):
        resp = {
            "1.1.1.1": {
                "test": {
                    "observed_nodes": [
                        "BB9070016AE4202",
                        "BB9060016AE4202",
                        "BB9050016AE4202",
                        "BB9040016AE4202",
                        "BB9020016AE4202",
                    ],
                    "ns": "test",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                }
            }
        }
        self.getter_mock.get_roster.return_value = resp

        await self.controller.execute([])

        self.getter_mock.get_roster.assert_called_with(flip=False, nodes="all")
        self.view_mock.show_roster.assert_called_with(
            resp, self.cluster_mock, flip=False, **self.controller.mods
        )

    @asynctest.fail_on(active_handles=True)
    async def test_with_flip(self):
        resp = {
            "1.1.1.1": {
                "test": {
                    "observed_nodes": [
                        "BB9070016AE4202",
                        "BB9060016AE4202",
                        "BB9050016AE4202",
                        "BB9040016AE4202",
                        "BB9020016AE4202",
                    ],
                    "ns": "test",
                    "pending_roster": ["null"],
                    "roster": ["null"],
                }
            }
        }

        self.getter_mock.get_roster.return_value = resp

        await self.controller.execute(["-flip"])

        self.getter_mock.get_roster.assert_called_with(flip=False, nodes="all")
        self.view_mock.show_roster.assert_called_with(
            resp, self.cluster_mock, flip=True, **self.controller.mods
        )


class ShowRacksControllerTest(asynctest.TestCase):
    async def setUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowRacksController()
        self.cluster_mock = patch(
            "lib.live_cluster.show_controller.ShowRacksController.cluster"
        ).start()
        self.getter_mock = patch(
            "lib.live_cluster.show_controller.GetConfigController"
        ).start()
        self.getter_mock.get_racks = AsyncMock()
        self.view_mock = patch("lib.base_controller.BaseController.view").start()
        self.logger_mock = patch("lib.base_controller.BaseController.logger").start()
        self.controller.getter = self.getter_mock
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    @asynctest.fail_on(active_handles=True)
    async def test_default(self):
        resp = {"1.1.1.1": "FOO"}
        self.getter_mock.get_racks.return_value = resp

        await self.controller.execute([])

        self.getter_mock.get_racks.assert_called_with(nodes="principal", flip=False)
        self.view_mock.show_racks.assert_called_with(resp, **self.controller.mods)
