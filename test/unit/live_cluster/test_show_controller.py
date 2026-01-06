# Copyright 2013-2025 Aerospike, Inc.
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
import warnings
from unittest.mock import AsyncMock, MagicMock, call, create_autospec, patch

import unittest
from pytest import PytestUnraisableExceptionWarning

from lib.base_controller import ShellException
from lib.live_cluster.client import ASProtocolError, ASResponse
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.get_controller import (
    GetAclController,
    GetClusterMetadataController,
    GetConfigController,
    GetJobsController,
    GetMaskingRulesController,
    GetStatisticsController,
    GetUserAgentsController,
)
from lib.live_cluster.show_controller import (
    ShowBestPracticesController,
    ShowConfigController,
    ShowConfigXDRController,
    ShowJobsController,
    ShowMaskingController,
    ShowRacksController,
    ShowRolesController,
    ShowRosterController,
    ShowStatisticsController,
    ShowStatisticsXDRController,
    ShowStopWritesController,
    ShowUdfsController,
    ShowUserAgentsController,
    ShowUsersController,
    ShowUsersStatsController,
)
from lib.view.view import CliView
from test.unit import util as test_util

import unittest


class ShowConfigControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowConfigController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(GetConfigController)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.mods = (
            {}
        )  # For some reason they are being polluted from other tests
        self.mods = {}

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
                    "bar Namespace Configuration",
                    "bar-configs",
                    self.cluster_mock,
                    title_every_nth=0,
                    flip_output=False,
                    **self.controller.mods,
                ),
                call(
                    "foo Namespace Configuration",
                    "foo-configs",
                    self.cluster_mock,
                    title_every_nth=0,
                    flip_output=False,
                    **self.controller.mods,
                ),
            ]
        )


class ShowConfigXDRControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowConfigXDRController()
        self.cluster_mock = self.controller.cluster = AsyncMock()
        self.getter_mock = self.controller.getter = create_autospec(GetConfigController)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()
        self.controller.mods = (
            {}
        )  # For some reason they are being polluted from other tests
        self.controller.getter = self.getter_mock
        self.mods = {}

        self.addCleanup(patch.stopall)

    async def test_do_xdr(self):
        line = []
        mods = {"diff": [], "for": [], "like": [], "with": [], "line": []}
        configs = {"xdr": "configs"}
        self.getter_mock.get_xdr.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_xdr.assert_called_with(nodes="all")
        self.view_mock.show_config.assert_called_with(
            "XDR Configuration",
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_dc(self):
        line = "dc for blah".split()
        configs = {"dc": "configs"}
        self.getter_mock.get_xdr_dcs.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_xdr_dcs.assert_called_with(nodes="all", for_mods=["blah"])
        self.view_mock.show_xdr_dc_config.assert_called_with(
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            **self.controller.mods,
        )

    async def test_do_namespace(self):
        line = "namespace for blah".split()
        mods = {"diff": [], "for": ["blah"], "like": [], "with": [], "line": []}
        configs = {"dc": "configs"}
        self.getter_mock.get_xdr_namespaces.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_xdr_namespaces.assert_called_with(
            nodes="all", for_mods=["blah"]
        )
        self.view_mock.show_xdr_ns_config.assert_called_with(
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_filter(self):
        line = "filter for blah".split()
        mods = {
            "for": ["blah"],
            "diff": [],
            "like": [],
            "with": [],
            "line": [],
        }
        configs = {"dc": "configs"}
        self.getter_mock.get_xdr_filters.return_value = configs
        self.cluster_mock.info_build.return_value = {
            "1.1.1.1": "5.3.0.0",
            "2.2.2.2": "6.3.0.0",
        }

        await self.controller.execute(line)

        self.getter_mock.get_xdr_filters.assert_called_with(
            nodes="principal", for_mods=["blah"]
        )
        self.view_mock.show_xdr_filters.assert_called_with(
            configs,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_filter_warns(self):
        line = "filter for blah".split()
        mods = {
            "for": ["blah"],
            "diff": [],
            "like": [],
            "with": [],
            "line": [],
        }
        configs = {"dc": "configs"}
        self.getter_mock.get_xdr_filters.return_value = configs
        self.cluster_mock.info_build.return_value = {
            "2.2.2.2": "6.3.0.0",
            "1.1.1.1": "5.2.9.9",
        }

        await self.controller.execute(line)

        self.getter_mock.get_xdr_filters.assert_called_with(
            nodes="principal", for_mods=["blah"]
        )
        self.view_mock.show_xdr_filters.assert_called_with(
            configs,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )
        self.logger_mock.warning.assert_called_once_with(
            "Server version 5.3 or newer is required to run 'show config xdr filter'"
        )


class ShowStatisticsControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowStatisticsController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.stat_getter = create_autospec(
            GetStatisticsController
        )
        self.meta_mock = self.controller.meta_getter = create_autospec(
            GetClusterMetadataController
        )
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.mods = (
            {}
        )  # For some reason they are being polluted from other tests
        self.mods = {}

        self.addCleanup(patch.stopall)

    async def test_do_service_default(self):
        line = ["service"]
        mods = {"like": [], "with": [], "for": [], "line": []}
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes="all")
        self.view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.cluster_mock,
            show_total=False,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_service_modifiers(self):
        line = ["service", "with", "1.2.3.4", "like", "foo", "for", "bar"]
        mods = {"like": ["foo"], "with": ["1.2.3.4"], "for": ["bar"], "line": []}
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes=["1.2.3.4"])
        self.view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.cluster_mock,
            show_total=False,
            title_every_nth=0,
            flip_output=False,
            **mods,
        )

    async def test_do_service_args(self):
        line = ["service", "-t", "-r", "17", "-flip"]
        mods = {"like": [], "with": [], "for": [], "line": line[1:]}
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        await self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes="all")
        self.view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.cluster_mock,
            show_total=True,
            title_every_nth=17,
            flip_output=True,
            **mods,
        )

    async def test_do_sindex(self):
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
        self.assertEqual(self.view_mock.show_stats.call_count, 3)

        for ns_set_sindex in stats:
            self.view_mock.show_stats.assert_any_call(
                "{} SIndex Statistics".format(ns_set_sindex),
                stats[ns_set_sindex],
                self.cluster_mock,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **mods,
            )

    async def test_do_sets(self):
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
        self.assertEqual(self.view_mock.show_stats.call_count, 3)

        for namespace, set_ in stats:
            self.view_mock.show_stats.assert_any_call(
                "{} {} Set Statistics".format(namespace, set_),
                stats[(namespace, set_)],
                self.cluster_mock,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **mods,
            )

    async def test_do_bins(self):
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
        self.meta_mock.get_builds.return_value = {"1.2.3.4": "6.4.0.0"}

        await self.controller.execute(line)

        self.getter_mock.get_bins.assert_called_with(
            flip=True, nodes=[node_addr], for_mods=[for_]
        )
        self.assertEqual(self.view_mock.show_stats.call_count, 3)

        for namespace in stats:
            self.view_mock.show_stats.assert_any_call(
                "{} Bin Statistics".format(namespace),
                stats[namespace],
                self.cluster_mock,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **mods,
            )

    async def test_do_bins_logs_error(self):
        line = [
            "bins",
        ]
        mods = {"like": [], "with": [], "for": [], "line": []}
        stats = {
            "ns1": "stats1",
            "ns2": "stats2",
            "ns3": "stats3",
        }
        self.getter_mock.get_bins.return_value = stats
        self.meta_mock.get_builds.return_value = {
            "1.1.1.1": "6.4.0.0",
            "2.2.2.2": "7.0.0.0",
        }

        await self.controller.execute(line)

        self.logger_mock.error.assert_called_once_with(
            "Server version 7.0 removed namespace bin-name limits and statistics."
        )


class ShowStatisticsXDRControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowStatisticsXDRController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(
            GetStatisticsController
        )
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.mods = (
            {}
        )  # For some reason they are being polluted from other tests
        self.mods = {}

        self.addCleanup(patch.stopall)

    async def test_do_default(self):
        line = "-t".split()
        mods = {"diff": [], "for": [], "like": [], "with": [], "line": line}
        configs = {"xdr": "configs"}
        self.getter_mock.get_xdr.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_xdr.assert_called_with(nodes="all")
        self.view_mock.show_stats.assert_called_with(
            "XDR Statistics",
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            show_total=True,
            **mods,
        )

    async def test_do_dc(self):
        line = "dc -t for blah".split()
        mods = {"diff": [], "for": ["blah"], "like": [], "with": [], "line": ["-t"]}
        configs = {"dc": "configs"}
        self.getter_mock.get_xdr_dcs.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_xdr_dcs.assert_called_with(nodes="all", for_mods=["blah"])
        self.view_mock.show_xdr_dc_stats.assert_called_with(
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            show_total=True,
            **mods,
        )

    async def test_do_namespace(self):
        line = "namespace -t --by-dc for blah".split()
        mods = {
            "diff": [],
            "for": ["blah"],
            "like": [],
            "with": [],
            "line": ["-t", "--by-dc"],
        }
        configs = {"dc": "configs"}
        self.getter_mock.get_xdr_namespaces.return_value = configs

        await self.controller.execute(line)

        self.getter_mock.get_xdr_namespaces.assert_called_with(
            nodes="all", for_mods=["blah"]
        )
        self.view_mock.show_xdr_ns_stats.assert_called_with(
            configs,
            self.cluster_mock,
            title_every_nth=0,
            flip_output=False,
            show_total=True,
            by_dc=True,
            **mods,
        )


class ShowUsersControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowUsersController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(GetAclController)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()
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


class ShowUsersStatsControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowUsersStatsController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(GetAclController)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()
        self.controller.getter = self.getter_mock
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_calls_users_successfully(self):
        resp = {
            "1.1.1.1": {
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
        }
        self.getter_mock.get_users.return_value = resp

        await self.controller.execute([])

        self.getter_mock.get_users.assert_called_with(nodes=self.controller.nodes)
        self.view_mock.show_users_stats.assert_called_with(
            self.cluster_mock, resp, line=[]
        )

    async def test_calls_user_successfully(self):
        resp = {
            "1.1.1.1": {
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
        }
        self.getter_mock.get_user.return_value = resp

        await self.controller.execute(["admin"])

        self.getter_mock.get_user.assert_called_with(
            "admin", nodes=self.controller.nodes
        )
        self.view_mock.show_users_stats.assert_called_with(
            self.cluster_mock, resp, **self.controller.mods
        )

    async def test_raises_error(self):
        as_error = IOError("test-message")
        as_error2 = IOError("test-message2")
        self.getter_mock.get_users.return_value = {
            "1.1.1.1": as_error,
            "2.2.2.2": as_error2,
        }

        await test_util.assert_exception_async(
            self,
            ShellException,
            "test-message",
            self.controller.execute,
            [],
        )

        self.getter_mock.get_users.assert_called_with(nodes=self.controller.nodes)
        self.view_mock.show_users_stats.assert_not_called()

    async def test_calls_user_successfully_with_only_one_error(self):
        resp = {
            "1.1.1.1": {
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
            },
            "2.2.2.2": Exception(),
        }
        self.getter_mock.get_user.return_value = resp

        await self.controller.execute(["admin"])

        self.getter_mock.get_user.assert_called_with(
            "admin", nodes=self.controller.nodes
        )
        self.view_mock.show_users_stats.assert_called_with(
            self.cluster_mock, resp, **self.controller.mods
        )


class ShowRolesControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowRolesController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(GetAclController)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()
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


class ShowBestPracticesControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowBestPracticesController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.cluster = self.cluster_mock = AsyncMock()
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()

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


class ShowJobsControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowJobsController()
        self.cluster_mock = self.controller.cluster = (
            AsyncMock()
        )  # can't use autospec here because info_* cluster functions are not autospec-able
        self.getter_mock = self.controller.getter = create_autospec(GetJobsController)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()

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
            "Scans were unified into queries in server v. 6.0 and later. Use 'show jobs queries' instead."
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


class ShowRosterControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowRosterController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(GetConfigController)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()
        self.controller.getter = self.getter_mock
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

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


class ShowRacksControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowRacksController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(GetConfigController)
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_default(self):
        resp = {"1.1.1.1": "FOO"}
        self.getter_mock.get_racks.return_value = resp

        await self.controller.execute([])

        self.getter_mock.get_racks.assert_called_with(nodes="principal", flip=False)
        self.view_mock.show_racks.assert_called_with(resp, **self.controller.mods)


class ShowStopWritesControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowStopWritesController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.config_getter_mock = self.controller.config_getter = create_autospec(
            GetConfigController
        )
        self.stat_getter_mock = self.controller.stat_getter = create_autospec(
            GetStatisticsController
        )
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.create_stop_writes_summary_mock = self.log_handler = patch(
            "lib.utils.common.create_stop_writes_summary",
            MagicMock(),
        ).start()
        self.logger_mock = patch("lib.live_cluster.show_controller.logger").start()
        self.controller.mods = {}

        self.addCleanup(patch.stopall)

    async def test_default(self):
        self.config_getter_mock.get_namespace.return_value = conf_ns_resp = {
            "1.1.1.1": "a"
        }
        self.config_getter_mock.get_sets.return_value = conf_set_resp = {"1.1.1.1": "b"}
        self.stat_getter_mock.get_namespace.return_value = stat_ns_resp = {
            "1.1.1.1": "c"
        }
        self.stat_getter_mock.get_sets.return_value = stat_set_resp = {"1.1.1.1": "d"}
        self.stat_getter_mock.get_service.return_value = stat_service_resp = {
            "1.1.1.1": "e"
        }
        self.create_stop_writes_summary_mock.return_value = summary_resp = {
            "1.1.1.1": "f"
        }

        await self.controller.execute([])

        self.create_stop_writes_summary_mock.assert_called_with(
            stat_service_resp, stat_ns_resp, conf_ns_resp, stat_set_resp, conf_set_resp
        )
        self.view_mock.show_stop_writes.assert_called_with(
            summary_resp, self.cluster_mock, **self.controller.mods
        )

    async def test_for_mod(self):
        self.config_getter_mock.get_namespace.return_value = conf_ns_resp = {
            "1.1.1.1": "a"
        }
        self.config_getter_mock.get_sets.return_value = conf_set_resp = {"1.1.1.1": "b"}
        self.stat_getter_mock.get_namespace.return_value = stat_ns_resp = {
            "1.1.1.1": "c"
        }
        self.stat_getter_mock.get_sets.return_value = stat_set_resp = {"1.1.1.1": "d"}
        self.stat_getter_mock.get_service.return_value = stat_service_resp = {
            "1.1.1.1": "e"
        }
        self.create_stop_writes_summary_mock.return_value = summary_resp = {
            "1.1.1.1": "f"
        }

        await self.controller.execute(["for", "test", "testset"])

        self.create_stop_writes_summary_mock.assert_called_with(
            stat_service_resp, {}, {}, stat_set_resp, conf_set_resp
        )
        self.view_mock.show_stop_writes.assert_called_with(
            summary_resp, self.cluster_mock, **self.controller.mods
        )


class ShowUserAgentsControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowUserAgentsController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(
            GetUserAgentsController
        )
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.mods = {}
        self.controller.nodes = "all"  # Initialize nodes
        self.addCleanup(patch.stopall)

    async def test_do_default_success(self):
        """Test successful user agents display"""
        line = []
        # Use proper format: "format-version,client-version,app-id"
        user_agents_data = {
            "node1": [
                {
                    "user-agent": "MS4wLDIuMCx0ZXN0LWFwcA==",
                    "count": "5",
                },  # base64 for "1.0,2.0,test-app"
                {
                    "user-agent": "MS4wLDMuMCxhc2FkbQ==",
                    "count": "3",
                },  # base64 for "1.0,3.0,asadm"
            ]
        }
        self.getter_mock.get_user_agents.return_value = user_agents_data

        await self.controller.execute(line)

        self.getter_mock.get_user_agents.assert_called_with(nodes="all")
        expected_processed_data = {
            "node1": [
                {"client_version": "2.0", "app_id": "test-app", "count": 5},
                {"client_version": "3.0", "app_id": "asadm", "count": 3},
            ]
        }
        self.view_mock.show_user_agents.assert_called_with(
            self.cluster_mock, expected_processed_data, **self.controller.mods
        )

    async def test_do_default_with_modifier(self):
        """Test user agents display with 'with' modifier"""
        line = []
        self.controller.mods = {"with": ["node1"]}
        self.controller.nodes = ["node1"]  # Set nodes based on with modifier
        user_agents_data = {
            "node1": [{"user-agent": "MS4wLDIuMCx0ZXN0LWFwcA==", "count": "5"}]
        }
        self.getter_mock.get_user_agents.return_value = user_agents_data

        await self.controller.execute(line)

        self.getter_mock.get_user_agents.assert_called_with(nodes=["node1"])
        expected_processed_data = {
            "node1": [{"client_version": "2.0", "app_id": "test-app", "count": 5}]
        }
        self.view_mock.show_user_agents.assert_called_with(
            self.cluster_mock, expected_processed_data, **self.controller.mods
        )

    async def test_do_default_node_exception(self):
        """Test handling node exceptions"""
        line = []
        user_agents_data = {"node1": Exception("Node error")}
        self.getter_mock.get_user_agents.return_value = user_agents_data

        with self.assertRaises(ShellException) as cm:
            await self.controller.execute(line)

        self.assertIn("Error processing user agent data from node1", str(cm.exception))
        self.getter_mock.get_user_agents.assert_called_with(nodes="all")


class ShowUdfsControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.cluster_mock = MagicMock(spec=Cluster)
        self.view_mock = MagicMock(spec=CliView)
        self.controller = ShowUdfsController()
        self.controller.cluster = self.cluster_mock
        self.controller.view = self.view_mock
        self.controller.mods = {}

    def tearDown(self):
        warnings.resetwarnings()

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_udfs_list_success(self, mock_get_udf_controller):
        """Test showing UDF list successfully"""

        async def async_test():
            line = []

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            udfs_data = {
                "node1": {
                    "test.lua": {
                        "filename": "test.lua",
                        "hash": "abc123",
                        "type": "LUA",
                    },
                    "math.lua": {
                        "filename": "math.lua",
                        "hash": "def456",
                        "type": "LUA",
                    },
                }
            }
            mock_getter.get_udfs.return_value = udfs_data

            await self.controller._do_default(line)

            mock_getter.get_udfs.assert_called_with(nodes="principal")
            self.view_mock.show_udfs.assert_called_once()

        asyncio.run(async_test())

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_single_udf_success(self, mock_get_udf_controller):
        """Test showing single UDF content successfully"""

        async def async_test():
            line = ["test.lua"]

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            # Mock base64 encoded content
            test_content = "function test()\n  return 'hello'\nend"
            encoded_content = base64.b64encode(test_content.encode()).decode()

            udf_data = {"node1": {"type": "LUA", "content": encoded_content}}
            mock_getter.get_udf.return_value = udf_data

            await self.controller._do_default(line)

            mock_getter.get_udf.assert_called_with(
                nodes="principal", filename="test.lua"
            )
            self.view_mock.show_single_udf.assert_called_once()

            # Verify the call arguments contain decoded content
            call_args = self.view_mock.show_single_udf.call_args
            udf_info = call_args[0][0]  # First positional argument
            filename = call_args[0][1]  # Second positional argument

            self.assertEqual(filename, "test.lua")
            self.assertEqual(udf_info["Type"], "LUA")
            self.assertEqual(udf_info["Filename"], "test.lua")
            self.assertEqual(udf_info["Content"], test_content)

        asyncio.run(async_test())

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_single_udf_exception_error(self, mock_get_udf_controller):
        """Test handling exception when getting single UDF"""

        async def async_test():
            line = ["test.lua"]

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            udf_data = {"node1": Exception("Connection failed")}
            mock_getter.get_udf.return_value = udf_data

            with patch("lib.live_cluster.show_controller.logger") as mock_logger:
                await self.controller._do_default(line)

                mock_logger.error.assert_called_with(
                    "Failed to retrieve UDF '%s': %s", "test.lua", udf_data["node1"]
                )

            # View should not be called when there's an exception
            self.view_mock.show_single_udf.assert_not_called()

        asyncio.run(async_test())

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_single_udf_aerospike_error(self, mock_get_udf_controller):
        """Test handling Aerospike error response when getting single UDF"""

        async def async_test():
            line = ["nonexistent.lua"]

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            udf_data = {"node1": {"error": "not_found"}}
            mock_getter.get_udf.return_value = udf_data

            with patch("lib.live_cluster.show_controller.logger") as mock_logger:
                await self.controller._do_default(line)

                mock_logger.error.assert_called_with(
                    "Failed to retrieve UDF '%s' error: %s",
                    "nonexistent.lua",
                    "not_found",
                )

            # View should not be called when there's an error
            self.view_mock.show_single_udf.assert_not_called()

        asyncio.run(async_test())

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_single_udf_base64_decode_error(self, mock_get_udf_controller):
        """Test handling base64 decode error"""

        async def async_test():
            line = ["test.lua"]

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            udf_data = {"node1": {"type": "LUA", "content": "invalid_base64_content!"}}
            mock_getter.get_udf.return_value = udf_data

            with patch("lib.live_cluster.show_controller.logger") as mock_logger:
                await self.controller._do_default(line)

                mock_logger.error.assert_called()
                error_call = mock_logger.error.call_args[0]
                self.assertIn("Failed to decode UDF content", error_call[0])
                self.assertEqual(error_call[1], "test.lua")

            # View should not be called when there's a decode error
            self.view_mock.show_single_udf.assert_not_called()

        asyncio.run(async_test())

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_single_udf_with_modifiers(self, mock_get_udf_controller):
        """Test showing single UDF with modifiers (should ignore them)"""

        async def async_test():
            line = ["test.lua", "like", "test"]

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            # Mock base64 encoded content
            test_content = "function test()\n  return 'hello'\nend"
            encoded_content = base64.b64encode(test_content.encode()).decode()

            udf_data = {"node1": {"type": "LUA", "content": encoded_content}}
            mock_getter.get_udf.return_value = udf_data

            await self.controller._do_default(line)

            # Should still call get_udf with the filename, ignoring modifiers
            mock_getter.get_udf.assert_called_with(
                nodes="principal", filename="test.lua"
            )
            self.view_mock.show_single_udf.assert_called_once()

        asyncio.run(async_test())

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_single_udf_empty_content(self, mock_get_udf_controller):
        """Test showing single UDF with empty content"""

        async def async_test():
            line = ["empty.lua"]

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            udf_data = {"node1": {"type": "LUA", "content": ""}}  # Empty base64 content
            mock_getter.get_udf.return_value = udf_data

            await self.controller._do_default(line)

            mock_getter.get_udf.assert_called_with(
                nodes="principal", filename="empty.lua"
            )
            self.view_mock.show_single_udf.assert_called_once()

            # Verify the call arguments
            call_args = self.view_mock.show_single_udf.call_args
            udf_info = call_args[0][0]
            filename = call_args[0][1]

            self.assertEqual(filename, "empty.lua")
            self.assertEqual(
                udf_info["Content"], ""
            )  # Should be empty string after decode

        asyncio.run(async_test())

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_single_udf_missing_type(self, mock_get_udf_controller):
        """Test showing single UDF when type field is missing"""

        async def async_test():
            line = ["test.lua"]

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            test_content = "function test() end"
            encoded_content = base64.b64encode(test_content.encode()).decode()

            udf_data = {
                "node1": {
                    # Missing "type" field
                    "content": encoded_content
                }
            }
            mock_getter.get_udf.return_value = udf_data

            await self.controller._do_default(line)

            mock_getter.get_udf.assert_called_with(
                nodes="principal", filename="test.lua"
            )
            self.view_mock.show_single_udf.assert_called_once()

            # Verify the call arguments - should default to "Unknown" for missing type
            call_args = self.view_mock.show_single_udf.call_args
            udf_info = call_args[0][0]

            self.assertEqual(udf_info["Type"], "Unknown")
            self.assertEqual(udf_info["Content"], test_content)

        asyncio.run(async_test())

    @patch("lib.live_cluster.show_controller.GetUdfController")
    def test_show_single_udf_missing_content(self, mock_get_udf_controller):
        """Test showing single UDF when content field is missing"""

        async def async_test():
            line = ["test.lua"]

            # Mock the getter
            mock_getter = AsyncMock()
            mock_get_udf_controller.return_value = mock_getter
            self.controller.getter = mock_getter

            udf_data = {
                "node1": {
                    "type": "LUA"
                    # Missing "content" field
                }
            }
            mock_getter.get_udf.return_value = udf_data

            await self.controller._do_default(line)

            mock_getter.get_udf.assert_called_with(
                nodes="principal", filename="test.lua"
            )
            self.view_mock.show_single_udf.assert_called_once()

            # Verify the call arguments - should handle missing content gracefully
            call_args = self.view_mock.show_single_udf.call_args
            udf_info = call_args[0][0]

            self.assertEqual(udf_info["Type"], "LUA")
            self.assertEqual(
                udf_info["Content"], ""
            )  # Should be empty string for missing content

        asyncio.run(async_test())


class ShowMaskingControllerTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = ShowMaskingController()
        self.cluster_mock = self.controller.cluster = create_autospec(Cluster)
        self.getter_mock = self.controller.getter = create_autospec(
            GetMaskingRulesController
        )
        self.view_mock = self.controller.view = create_autospec(CliView)
        self.controller.mods = {}
        self.controller.nodes = "principal"
        self.addCleanup(patch.stopall)

    async def test_do_default_success(self):
        """Test successful masking rules display"""
        line = []
        masking_data = {
            "node1": [
                {
                    "ns": "test",
                    "set": "demo",
                    "bin": "ssn",
                    "type": "string",
                    "function": "redact",
                    "position": "0",
                    "length": "4",
                    "value": "*",
                },
                {
                    "ns": "test",
                    "set": "demo",
                    "bin": "email",
                    "type": "string",
                    "function": "constant",
                    "value": "REDACTED",
                },
            ]
        }
        self.getter_mock.get_masking_rules.return_value = masking_data

        await self.controller.execute(line)

        self.getter_mock.get_masking_rules.assert_called_with(
            nodes="principal", namespace=None, set_=None
        )
        self.view_mock.show_masking_rules.assert_called_with(
            masking_data["node1"], **self.controller.mods
        )

    async def test_do_default_with_namespace_filter(self):
        """Test masking rules display with namespace filter"""
        line = ["namespace", "test"]
        masking_data = {
            "node1": [
                {
                    "ns": "test",
                    "set": "demo",
                    "bin": "ssn",
                    "type": "string",
                    "function": "redact",
                }
            ]
        }
        self.getter_mock.get_masking_rules.return_value = masking_data

        await self.controller.execute(line)

        self.getter_mock.get_masking_rules.assert_called_with(
            nodes="principal", namespace="test", set_=None
        )
        self.view_mock.show_masking_rules.assert_called_with(
            masking_data["node1"], **self.controller.mods
        )

    async def test_do_default_with_namespace_and_set_filter(self):
        """Test masking rules display with namespace and set filters"""
        line = ["namespace", "test", "set", "demo"]
        masking_data = {
            "node1": [
                {
                    "ns": "test",
                    "set": "demo",
                    "bin": "ssn",
                    "type": "string",
                    "function": "redact",
                }
            ]
        }
        self.getter_mock.get_masking_rules.return_value = masking_data

        await self.controller.execute(line)

        self.getter_mock.get_masking_rules.assert_called_with(
            nodes="principal", namespace="test", set_="demo"
        )

    async def test_do_default_set_without_namespace_raises_error(self):
        """Test that using set filter without namespace raises error"""
        line = ["set", "demo"]

        with self.assertRaises(ShellException) as context:
            await self.controller.execute(line)

        self.assertEqual(
            str(context.exception), "Set filter can only be used with namespace filter"
        )

    async def test_do_default_protocol_error(self):
        """Test handling of protocol errors"""
        line = []
        protocol_error = ASProtocolError(1, "Connection failed")
        self.getter_mock.get_masking_rules.return_value = {"node1": protocol_error}

        # Should return None when there's a protocol error (early return)
        result = await self.controller._do_default(line)

        self.assertIsNone(result)
        self.view_mock.show_masking_rules.assert_not_called()

    async def test_do_default_exception_raised(self):
        """Test handling of general exceptions"""
        line = []
        exception = Exception("General error")
        self.getter_mock.get_masking_rules.return_value = {"node1": exception}

        with self.assertRaises(Exception) as context:
            await self.controller.execute(line)

        self.assertEqual(str(context.exception), "General error")

    async def test_do_default_empty_data(self):
        """Test handling of empty masking data"""
        line = []
        # Return empty list for a node (no masking rules)
        self.getter_mock.get_masking_rules.return_value = {"node1": []}

        result = await self.controller._do_default(line)

        # Should call view with empty list
        self.view_mock.show_masking_rules.assert_called_once_with(
            [], **self.controller.mods
        )


class InfoControllerTest(unittest.IsolatedAsyncioTestCase):
    """Test InfoController methods"""

    async def asyncSetUp(self):
        self.maxDiff = None

        # Mock cluster and view
        self.cluster_mock = MagicMock()
        self.view_mock = MagicMock()

        # Import and create controller instance
        from lib.live_cluster.info_controller import InfoController

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=RuntimeWarning)
            self.controller = InfoController()
            self.controller.cluster = self.cluster_mock
            self.controller.view = self.view_mock
            self.controller.nodes = ["node1", "node2"]
            self.controller.mods = {}

    def tearDown(self):
        patch.stopall()

    async def test_do_release_success(self):
        """Test do_release with supported server versions"""
        # Mock build versions that support release info
        build_data = {"node1": "8.1.1.0", "node2": "8.2.0.0"}
        self.cluster_mock.info_build = AsyncMock(return_value=build_data)

        # Mock release data
        release_data = {
            "node1": {
                "arch": "x86_64",
                "edition": "Aerospike Enterprise Edition",
                "os": "linux",
                "version": "8.1.1.0",
                "sha": "abc123",
                "ee-sha": "def456",
            },
            "node2": {
                "arch": "x86_64",
                "edition": "Aerospike Community Edition",
                "os": "linux",
                "version": "8.2.0.0",
                "sha": "xyz789",
                "ee-sha": "",
            },
        }
        self.cluster_mock.info_release = AsyncMock(return_value=release_data)

        # Mock view method
        self.view_mock.info_release = MagicMock()

        with patch("lib.utils.util.filter_exceptions", return_value=build_data):
            with patch("lib.utils.util.callable") as callable_mock:
                result = await self.controller.do_release("")

                # Verify cluster methods were called
                self.cluster_mock.info_build.assert_called_once_with(
                    nodes=["node1", "node2"]
                )
                self.cluster_mock.info_release.assert_called_once_with(
                    nodes=["node1", "node2"]
                )

                # Verify view method was called via util.callable
                callable_mock.assert_called_once()

    async def test_do_release_unsupported_versions(self):
        """Test do_release with unsupported server versions"""
        # Mock build versions that don't support release info
        build_data = {"node1": "8.0.0.1", "node2": "7.5.0.0"}
        self.cluster_mock.info_build = AsyncMock(return_value=build_data)

        with patch("lib.utils.util.filter_exceptions", return_value=build_data):
            with patch("lib.live_cluster.info_controller.logger") as logger_mock:
                result = await self.controller.do_release("")

                # Verify warning was logged
                logger_mock.warning.assert_called_once_with(
                    "'info release' is not supported on aerospike versions < %s",
                    "8.1.1",
                )

                # Verify early return (no release info call)
                self.cluster_mock.info_build.assert_called_once()
                self.assertIsNone(result)

    async def test_do_network_enhanced_version_success(self):
        """Test do_network uses enhanced version info for 8.1.1+ servers"""
        # Mock all required data
        stats_data = {"node1": {"stat1": "value1"}}
        cluster_names = {"node1": "test-cluster"}
        builds_data = {"node1": "8.1.1.0"}
        versions_data = {"node1": "Aerospike Enterprise Edition build 8.1.1.0"}

        self.cluster_mock.info_statistics = AsyncMock(return_value=stats_data)
        self.cluster_mock.info = AsyncMock(return_value=cluster_names)
        self.cluster_mock.info_build = AsyncMock(return_value=builds_data)
        self.cluster_mock.info_version = AsyncMock(return_value=versions_data)

        with patch("lib.utils.util.callable") as callable_mock:
            result = await self.controller.do_network("")

            # Verify all required data was fetched
            self.cluster_mock.info_statistics.assert_called_once_with(
                nodes=["node1", "node2"]
            )
            self.cluster_mock.info.assert_called_once_with(
                "cluster-name", nodes=["node1", "node2"]
            )
            self.cluster_mock.info_build.assert_called_once_with(
                nodes=["node1", "node2"]
            )
            self.cluster_mock.info_version.assert_called_once_with(
                nodes=["node1", "node2"]
            )

            # Verify view method was called
            callable_mock.assert_called_once()
