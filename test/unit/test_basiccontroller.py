# Copyright 2013-2020 Aerospike, Inc.
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

from future import standard_library
standard_library.install_aliases()

from mock import patch, Mock
import unittest2 as unittest

import lib
from lib.utils import util
from lib.controllerlib import BaseController, CommandController, CommandHelp, ShellException
from lib.basiccontroller import ShowStatisticsController, InfoController, ShowConfigController, BasicCommandController
from lib.getcontroller import GetStatisticsController


class FakeCluster(unittest.TestCase):

    def __init__(self, versions):
        self.builds = {'10.0.2.15:3000': versions[0], '20.0.2.15:3000': versions[1]}

    def info_XDR_build_version(self, nodes):
        return self.builds


class FakeGetStatisticsController(GetStatisticsController):
    def __init__(self, cluster, xdr_5):
        self.cluster = cluster
        self.xdr_5 = xdr_5

    def get_xdr(self, nodes):
        if self.xdr_5:
            return {
            '10.0.2.15:3000': {'DC1': {'in_queue': 21, 'retry_dest': '3', 'filtered_out': '3', 'abandoned': '3', 'success': '3', 'in_progress': '3', 'recoveries': '3', 'lap_us': '388', 'retry_conn_reset': '3', 'uncompressed_pct': '50.000', 'recoveries_pending': '3', 'hot_keys': '3', 'not_found': '3', 'time_lag': '3', 'compression_ratio': '1.000', 'lag': 1, 'throughput': 21300, 'latency_ms': 2},
             'DC2': {'in_queue': 17, 'retry_dest': '0', 'filtered_out': '0', 'abandoned': '0', 'success': '0', 'in_progress': '0', 'recoveries': '0', 'lap_us': '388', 'retry_conn_reset': '0', 'uncompressed_pct': '0.000', 'recoveries_pending': '0', 'hot_keys': '0', 'not_found': '0', 'time_lag': '0', 'compression_ratio': '1.000', 'lag': 3, 'throughput': 10200, 'latency_ms': 6}},
            '20.0.2.15:3000': {'DC1': {'in_queue': 21, 'retry_dest': '3', 'filtered_out': '3', 'abandoned': '3', 'success': '3', 'in_progress': '3', 'recoveries': '3', 'lap_us': '388', 'retry_conn_reset': '3', 'uncompressed_pct': '50.000', 'recoveries_pending': '3', 'hot_keys': '3', 'not_found': '3', 'time_lag': '3', 'compression_ratio': '1.000', 'lag': 1, 'throughput': 21300, 'latency_ms': 2},
             'DC2': {'in_queue': 17, 'retry_dest': '0', 'filtered_out': '0', 'abandoned': '0', 'success': '0', 'in_progress': '0', 'recoveries': '0', 'lap_us': '388', 'retry_conn_reset': '0', 'uncompressed_pct': '0.000', 'recoveries_pending': '0', 'hot_keys': '0', 'not_found': '0', 'time_lag': '0', 'compression_ratio': '1.000', 'lag': 3, 'throughput': 10200, 'latency_ms': 6}}}
        else:
            #TODO fill in pre 5.0 stats
            return {"place_holder": "place_holder"}


# class BasicControllerLibTest(unittest.Testcase):
#     def test_xdr_stats(self):
#         controller = ShowStatisticsController()


class FakeView:
    def __init__(self):
        self.result = {}

    @staticmethod
    def show_stats(title, service_configs, cluster, like=None, diff=None, show_total=False, title_every_nth=0, flip_output=False, timestamp="", **ignore):
        return (title, service_configs)


class FakeShowStatisticsController(ShowStatisticsController):
    def __init__(self):
        self.modifiers = set(['with', 'like', 'for'])
        self.mods = {'line': [], 'with': [], 'like': [], 'for': []}
        self.cluster = FakeCluster(('5.0.0.0-pre-5-gefcbfeb', '5.0.0.0-pre-5-gefcbfeb'))
        self.getter = FakeGetStatisticsController(self.cluster, True)
        self.nodes = ['10.0.2.15:3000', '20.0.2.15:3000']
        self.view = FakeView()


def test():
    s = FakeShowStatisticsController()
    #print(s.getter.get_xdr())
    f = s.do_xdr("xdr")
    res = []
    for future in f:
        res.append(future.start())
    
    expected = {'10.0.2.15:3000': {'DC1': {'in_queue': 21, 'retry_dest': '3', 'filtered_out': '3', 'abandoned': '3', 'success': '3', 'in_progress': '3', 'recoveries': '3', 'lap_us': '388', 'retry_conn_reset': '3', 'uncompressed_pct': '50.000', 'recoveries_pending': '3', 'hot_keys': '3', 'not_found': '3', 'time_lag': '3', 'compression_ratio': '1.000', 'lag': 1, 'throughput': 21300, 'latency_ms': 2},
             'DC2': {'in_queue': 17, 'retry_dest': '0', 'filtered_out': '0', 'abandoned': '0', 'success': '0', 'in_progress': '0', 'recoveries': '0', 'lap_us': '388', 'retry_conn_reset': '0', 'uncompressed_pct': '0.000', 'recoveries_pending': '0', 'hot_keys': '0', 'not_found': '0', 'time_lag': '0', 'compression_ratio': '1.000', 'lag': 3, 'throughput': 10200, 'latency_ms': 6}},
            '20.0.2.15:3000': {'DC1': {'in_queue': 21, 'retry_dest': '3', 'filtered_out': '3', 'abandoned': '3', 'success': '3', 'in_progress': '3', 'recoveries': '3', 'lap_us': '388', 'retry_conn_reset': '3', 'uncompressed_pct': '50.000', 'recoveries_pending': '3', 'hot_keys': '3', 'not_found': '3', 'time_lag': '3', 'compression_ratio': '1.000', 'lag': 1, 'throughput': 21300, 'latency_ms': 2},
             'DC2': {'in_queue': 17, 'retry_dest': '0', 'filtered_out': '0', 'abandoned': '0', 'success': '0', 'in_progress': '0', 'recoveries': '0', 'lap_us': '388', 'retry_conn_reset': '0', 'uncompressed_pct': '0.000', 'recoveries_pending': '0', 'hot_keys': '0', 'not_found': '0', 'time_lag': '0', 'compression_ratio': '1.000', 'lag': 3, 'throughput': 10200, 'latency_ms': 6}}}

    for x in res:
        print(x.result())
    #TODO verify against real output


test()