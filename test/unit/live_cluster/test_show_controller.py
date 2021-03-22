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

import unittest
from mock import patch

from lib.live_cluster.show_controller import ShowStatisticsController
from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController


@patch("lib.base_controller.BaseController.view")
class ShowStatisticsControllerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cluster_mock = patch(
            "lib.live_cluster.live_cluster_root_controller.Cluster"
        ).start()
        self.root_controller = LiveClusterRootController()
        self.controller = ShowStatisticsController()
        self.getter_mock = patch(
            "lib.live_cluster.show_controller.GetStatisticsController"
        ).start()
        self.controller.getter = self.getter_mock
        self.mods = {"like": [], "with": [], "for": [], "line": []}

        self.addCleanup(patch.stopall)

    def test_do_service_default(self, view_mock):
        line = ["service"]
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        # self.controller.pre_command(line[:])
        self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes="all")
        view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.root_controller.cluster,
            show_total=False,
            title_every_nth=0,
            flip_output=False,
            **self.mods,
        )

    def test_do_service_modifiers(self, view_mock):
        line = ["service", "with", "1.2.3.4", "like", "foo", "for", "bar"]
        self.mods.update({"like": ["foo"], "with": ["1.2.3.4"], "for": ["bar"]})
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes=["1.2.3.4"])
        view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.root_controller.cluster,
            show_total=False,
            title_every_nth=0,
            flip_output=False,
            **self.mods,
        )

    def test_do_service_args(self, view_mock):
        line = ["service", "-t", "-r", "17", "-flip"]
        self.mods.update({"line": line[1:]})
        stats = {"service": "stats"}
        self.getter_mock.get_service.return_value = stats

        self.controller.execute(line)

        self.getter_mock.get_service.assert_called_with(nodes="all")
        view_mock.show_stats.assert_called_with(
            "Service Statistics",
            stats,
            self.root_controller.cluster,
            show_total=True,
            title_every_nth=17,
            flip_output=True,
            **self.mods,
        )

    def test_do_sindex(self, view_mock):
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
        self.mods.update({"like": [like], "with": [node_addr], "for": [for_]})
        stats = {"sindex1": "stats1", "sindex2": "stats2", "sindex3": "stats3"}
        self.getter_mock.get_sindex.return_value = stats

        self.controller.execute(line)

        self.getter_mock.get_sindex.assert_called_with(
            nodes=[node_addr], for_mods=[for_]
        )
        self.assertEqual(view_mock.show_stats.call_count, 3)

        for ns_set_sindex in stats:
            view_mock.show_stats.assert_any_call(
                "{} Sindex Statistics".format(ns_set_sindex),
                stats[ns_set_sindex],
                self.root_controller.cluster,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **self.mods,
            )

    def test_do_sets(self, view_mock):
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
        self.mods.update({"like": [like], "with": [node_addr], "for": [for_]})
        stats = {
            ("ns1", "set1"): "stats1",
            ("ns2", "set2"): "stats2",
            ("ns3", "set3"): "stats3",
        }
        self.getter_mock.get_sets.return_value = stats

        self.controller.execute(line)

        self.getter_mock.get_sets.assert_called_with(nodes=[node_addr], for_mods=[for_])
        self.assertEqual(view_mock.show_stats.call_count, 3)

        for namespace, set_ in stats:
            view_mock.show_stats.assert_any_call(
                "{} {} Set Statistics".format(namespace, set_),
                stats[(namespace, set_)],
                self.root_controller.cluster,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **self.mods,
            )

    def test_do_bins(self, view_mock):
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
        self.mods.update({"like": [like], "with": [node_addr], "for": [for_]})
        stats = {
            "ns1": "stats1",
            "ns2": "stats2",
            "ns3": "stats3",
        }
        self.getter_mock.get_bins.return_value = stats

        self.controller.execute(line)

        self.getter_mock.get_bins.assert_called_with(nodes=[node_addr], for_mods=[for_])
        self.assertEqual(view_mock.show_stats.call_count, 3)

        for namespace in stats:
            view_mock.show_stats.assert_any_call(
                "{} Bin Statistics".format(namespace),
                stats[namespace],
                self.root_controller.cluster,
                show_total=True,
                title_every_nth=17,
                flip_output=True,
                **self.mods,
            )

    # def test_do_xdr(self, view_mock):
    #     node_addr = ["1.1.1.1", "2.2.2.2", "4.4.4.4"]
    #     like = "foo"
    #     for_ = ["dc2", "dc3"]
    #     line = [
    #         "xdr",
    #         "with",
    #         *node_addr,
    #         "like",
    #         like,
    #         "for",
    #         *for_,
    #         "-t",
    #         "-r",
    #         "17",
    #         "-flip",
    #     ]
    #     self.mods.update({"like": [like], "with": [node_addr], "for": [for_]})
    #     stats = {
    #         "1.1.1.1": {"dc1": "stats1", "dc2": "stats2", "dc3": "stats3"},
    #         "2.2.2.2": {"dc1": "stats14", "dc2": "stats5", "dc3": "stats6"},
    #         "3.3.3.3": {"dc1": "stats7", "dc2": "stats8", "dc3": "stats9"},
    #         "4.4.4.4": {"dc1": "stats11", "dc2": "stats12", "dc3": "stats15"},
    #     }
    #     self.getter_mock.get_bins.return_value = stats
    #     self.cluster_mock.info_build_version.return_value = {
    #         "1.1.1.1": "5.0.0",
    #         "2.2.2.2": "4.9.1",
    #         "3.3.3.3": "3.2.5",
    #         "4.4.4.4": "8.10.0",
    #     }
    #     expected_xdr_5_stats = {
    #         "dc1": {"1.1.1.1": {"stat1"}, "4.4.4.4": {"stat11"}},
    #         "dc2": {"1.1.1.1": {"stat2"}, "4.4.4.4": {"stat12"}},
    #         "dc3": {"1.1.1.1": {"stat3"}, "4.4.4.4": {"stat15"}},
    #     }
    #     expected_old_xdr_stats = {
    #         "2.2.2.2": {"dc1": "stats14", "dc2": "stats5", "dc3": "stats6"},
    #         "3.3.3.3": {"dc1": "stats7", "dc2": "stats8", "dc3": "stats9"},
    #     }

    #     self.controller.execute(line)

    #     self.getter_mock.get_bins.assert_called_with(nodes=[node_addr], for_mods=[for_])
    #     self.assertEqual(view_mock.show_stats.call_count, 4)
    #     view_mock.show_stats.assert_any_call(
    #         "XDR Statistics",
    #         expected_old_xdr_stats,
    #         self.root_controller.cluster,
    #         show_total=True,
    #         title_every_nth=17,
    #         flip_output=True,
    #         **self.mods,
    #     )
    #     for dc in expected_xdr_5_stats:
    #         view_mock.show_stats.assert_any_call(
    #             "XDR Statistics {}".format(dc),
    #             expected_xdr_5_stats[dc],
    #             self.root_controller.cluster,
    #             show_total=True,
    #             title_every_nth=17,
    #             flip_output=True,
    #             **self.mods,
    #         )


# class FakeCluster(unittest.TestCase):
#     def __init__(self, versions):
#         self.builds = {"10.0.2.15:3000": versions[0], "20.0.2.15:3000": versions[1]}

#     def info_build_version(self, nodes):
#         return self.builds


# class FakeGetStatisticsController(GetStatisticsController):
#     def __init__(self, cluster, xdr_5):
#         self.cluster = cluster
#         self.xdr_5 = xdr_5

#     def get_xdr(self, nodes):
#         if self.xdr_5:
#             return {
#                 "10.0.2.15:3000": {
#                     "DC1": {
#                         "in_queue": 21,
#                         "retry_dest": "3",
#                         "filtered_out": "3",
#                         "abandoned": "3",
#                         "success": "3",
#                         "in_progress": "3",
#                         "recoveries": "3",
#                         "lap_us": "388",
#                         "retry_conn_reset": "3",
#                         "uncompressed_pct": "50.000",
#                         "recoveries_pending": "3",
#                         "hot_keys": "3",
#                         "not_found": "3",
#                         "time_lag": "3",
#                         "compression_ratio": "1.000",
#                         "lag": 1,
#                         "throughput": 21300,
#                         "latency_ms": 2,
#                     },
#                     "DC2": {
#                         "in_queue": 17,
#                         "retry_dest": "0",
#                         "filtered_out": "0",
#                         "abandoned": "0",
#                         "success": "0",
#                         "in_progress": "0",
#                         "recoveries": "0",
#                         "lap_us": "388",
#                         "retry_conn_reset": "0",
#                         "uncompressed_pct": "0.000",
#                         "recoveries_pending": "0",
#                         "hot_keys": "0",
#                         "not_found": "0",
#                         "time_lag": "0",
#                         "compression_ratio": "1.000",
#                         "lag": 3,
#                         "throughput": 10200,
#                         "latency_ms": 6,
#                     },
#                 },
#                 "20.0.2.15:3000": {
#                     "DC1": {
#                         "in_queue": 21,
#                         "retry_dest": "3",
#                         "filtered_out": "3",
#                         "abandoned": "3",
#                         "success": "3",
#                         "in_progress": "3",
#                         "recoveries": "3",
#                         "lap_us": "388",
#                         "retry_conn_reset": "3",
#                         "uncompressed_pct": "50.000",
#                         "recoveries_pending": "3",
#                         "hot_keys": "3",
#                         "not_found": "3",
#                         "time_lag": "3",
#                         "compression_ratio": "1.000",
#                         "lag": 1,
#                         "throughput": 21300,
#                         "latency_ms": 2,
#                     },
#                     "DC2": {
#                         "in_queue": 17,
#                         "retry_dest": "0",
#                         "filtered_out": "0",
#                         "abandoned": "0",
#                         "success": "0",
#                         "in_progress": "0",
#                         "recoveries": "0",
#                         "lap_us": "388",
#                         "retry_conn_reset": "0",
#                         "uncompressed_pct": "0.000",
#                         "recoveries_pending": "0",
#                         "hot_keys": "0",
#                         "not_found": "0",
#                         "time_lag": "0",
#                         "compression_ratio": "1.000",
#                         "lag": 3,
#                         "throughput": 10200,
#                         "latency_ms": 6,
#                     },
#                 },
#             }
#         else:
#             # TODO fill in pre 5.0 stats
#             return {"place_holder": "place_holder"}


# class BasicControllerLibTest(unittest.Testcase):
#     def test_xdr_stats(self):
#         controller = ShowStatisticsController()


# class FakeView:
#     def __init__(self):
#         self.result = {}

#     @staticmethod
#     def show_stats(
#         title,
#         service_configs,
#         cluster,
#         like=None,
#         diff=None,
#         show_total=False,
#         title_every_nth=0,
#         flip_output=False,
#         timestamp="",
#         **ignore
#     ):
#         return (title, service_configs)


# class FakeShowStatisticsController(ShowStatisticsController):
#     def __init__(self):
#         self.modifiers = set(["with", "like", "for"])
#         self.mods = {"line": [], "with": [], "like": [], "for": []}
#         self.cluster = FakeCluster(("5.0.0.0-pre-5-gefcbfeb", "5.0.0.0-pre-5-gefcbfeb"))
#         self.getter = FakeGetStatisticsController(self.cluster, True)
#         self.nodes = ["10.0.2.15:3000", "20.0.2.15:3000"]
#         self.view = FakeView()


# def test():
#     s = FakeShowStatisticsController()
#     # print(s.getter.get_xdr())
#     f = s.do_xdr("xdr")
#     res = []
#     for future in f:
#         res.append(future.start())

#     expected = {
#         "10.0.2.15:3000": {
#             "DC1": {
#                 "in_queue": 21,
#                 "retry_dest": "3",
#                 "filtered_out": "3",
#                 "abandoned": "3",
#                 "success": "3",
#                 "in_progress": "3",
#                 "recoveries": "3",
#                 "lap_us": "388",
#                 "retry_conn_reset": "3",
#                 "uncompressed_pct": "50.000",
#                 "recoveries_pending": "3",
#                 "hot_keys": "3",
#                 "not_found": "3",
#                 "time_lag": "3",
#                 "compression_ratio": "1.000",
#                 "lag": 1,
#                 "throughput": 21300,
#                 "latency_ms": 2,
#             },
#             "DC2": {
#                 "in_queue": 17,
#                 "retry_dest": "0",
#                 "filtered_out": "0",
#                 "abandoned": "0",
#                 "success": "0",
#                 "in_progress": "0",
#                 "recoveries": "0",
#                 "lap_us": "388",
#                 "retry_conn_reset": "0",
#                 "uncompressed_pct": "0.000",
#                 "recoveries_pending": "0",
#                 "hot_keys": "0",
#                 "not_found": "0",
#                 "time_lag": "0",
#                 "compression_ratio": "1.000",
#                 "lag": 3,
#                 "throughput": 10200,
#                 "latency_ms": 6,
#             },
#         },
#         "20.0.2.15:3000": {
#             "DC1": {
#                 "in_queue": 21,
#                 "retry_dest": "3",
#                 "filtered_out": "3",
#                 "abandoned": "3",
#                 "success": "3",
#                 "in_progress": "3",
#                 "recoveries": "3",
#                 "lap_us": "388",
#                 "retry_conn_reset": "3",
#                 "uncompressed_pct": "50.000",
#                 "recoveries_pending": "3",
#                 "hot_keys": "3",
#                 "not_found": "3",
#                 "time_lag": "3",
#                 "compression_ratio": "1.000",
#                 "lag": 1,
#                 "throughput": 21300,
#                 "latency_ms": 2,
#             },
#             "DC2": {
#                 "in_queue": 17,
#                 "retry_dest": "0",
#                 "filtered_out": "0",
#                 "abandoned": "0",
#                 "success": "0",
#                 "in_progress": "0",
#                 "recoveries": "0",
#                 "lap_us": "388",
#                 "retry_conn_reset": "0",
#                 "uncompressed_pct": "0.000",
#                 "recoveries_pending": "0",
#                 "hot_keys": "0",
#                 "not_found": "0",
#                 "time_lag": "0",
#                 "compression_ratio": "1.000",
#                 "lag": 3,
#                 "throughput": 10200,
#                 "latency_ms": 6,
#             },
#         },
#     }

#     # for x in res:
#     #     print(x.result())
#     # TODO verify against real output

