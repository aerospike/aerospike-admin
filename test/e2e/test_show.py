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

import os
import sys
import unittest2 as unittest

import lib.basiccontroller as controller
import lib.utils.util as util
from test.e2e import test_util

sys.path.insert(1, os.getcwd())

class TestShowConfig(unittest.TestCase):
    output_list = list()
    service_config = ''
    network_config = ''
    test_namespace_config = ''
    bar_namespace_config = ''
    xdr_config = ''

    @classmethod
    def setUpClass(cls):
        TestShowConfig.rc = controller.BasicRootController()
        actual_out = util.capture_stdout(TestShowConfig.rc.execute, ['show', 'config'])
        TestShowConfig.output_list = test_util.get_separate_output(actual_out, 'Configuration')
        TestShowConfig.output_list.append(util.capture_stdout(TestShowConfig.rc.execute, ['show', 'config', 'xdr']))
        TestShowConfig.is_bar_present = False

        for item in TestShowConfig.output_list:
            if "~~Service Configuration" in item:
                TestShowConfig.service_config = item
            elif "~~Network Configuration" in item:
                TestShowConfig.network_config = item
            elif "~~test Namespace Configuration" in item:
                TestShowConfig.test_namespace_config = item
            elif "~~bar Namespace Configuration" in item:
                TestShowConfig.bar_namespace_config = item
                TestShowConfig.is_bar_present = True
            elif "~XDR Configuration" in item:
                TestShowConfig.xdr_config = item

    @classmethod
    def tearDownClass(cls):
        cls.rc = None

    def test_network(self):
        """
        This test will assert network output on heading, header, parameters.
        TODO: test for values as well
        """

        exp_heading = "~~Network Configuration"
        exp_header = "NODE"
        exp_params = [
            ('fabric-keepalive-enabled', 'fabric.keepalive-enabled'),
            ('fabric-keepalive-intvl', 'fabric.keepalive-intvl'),
            ('fabric-keepalive-probes', 'fabric.keepalive-probes'),
            ('fabric-keepalive-time', 'fabric.keepalive-time'),
            ('fabric-port', 'fabric.port'),
            ('heartbeat-address', 'heartbeat.address', 'heartbeat.addresses', None),
            ('heartbeat-interval', 'heartbeat.interval'),
            ('heartbeat-mode', 'heartbeat.mode'),
            ('heartbeat-port', 'heartbeat.port', None),
            ('heartbeat-protocol', 'heartbeat.protocol'),
            ('heartbeat-timeout', 'heartbeat.timeout'),
            ('network-info-port', 'info.port'),
            ('reuse-address', 'service.reuse-address', None),
            ('service-address', 'service.address'),
            ('service-port','service.port')
        ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.network_config)
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params))

    def test_service(self):
        """
        Asserts service config output with heading, header & parameters.
        TODO: test for values as well
        """

        exp_heading = "~~Service Configuration"
        exp_header = "NODE"
        exp_params = [  
            ('allow-inline-transactions', None),
            'batch-max-requests',
            ('batch-priority', None),
            ('batch-threads', None),
            ('fabric-workers', None),
            'info-threads',
            ('ldt-benchmarks', None),
            ('max-msgs-per-type', None),
            ('memory-accounting', None),
            ('microbenchmarks', None),
            'migrate-max-num-incoming',
            ('migrate-rx-lifetime-ms', None),
            'migrate-threads',
            ('nsup-startup-evict', None),
            ('paxos-max-cluster-size', None),
            ('paxos-protocol', None),
            ('paxos-retransmit-period', None),
            'paxos-single-replica-limit',
            'proto-fd-idle-ms',
            'proto-fd-max',
            'proto-slow-netio-sleep-ms',
            'query-batch-size',
            'query-bufpool-size',
            'query-in-transaction-thread',
            'query-long-q-max-size',
            'query-priority',
            'query-rec-count-bound',
            'query-req-in-query-thread',
            'query-req-max-inflight',
            'query-short-q-max-size',
            'query-threads',
            'query-threshold',
            'query-worker-threads',
            ('replication-fire-and-forget', None),
            ('respond-client-on-master-completion', None),
            'service-threads',
            ('sindex-data-max-memory', None),
            ('snub-nodes', None),
            ('storage-benchmarks', None),
            'ticker-interval',
            'transaction-max-ms',
            ('transaction-pending-limit', None),
            ('transaction-queues', None),
            ('transaction-repeatable-read', None),
            'transaction-retry-ms',
            ('transaction-threads-per-queue', None),
            ('udf-runtime-gmax-memory', None),
            ('udf-runtime-max-memory', None),
            ('use-queue-per-device', None),
            ('write-duplicate-resolution-disable', None)
        ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.service_config)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params))

    def test_test_namespace(self):
        """
        Asserts namespace config output with heading, header & parameters.
        TODO: test for values as well
        """

        exp_heading = "~~test Namespace Configuration"
        exp_header = "NODE"
        exp_params_test = [  
            ('allow-nonxdr-writes', 'reject-non-xdr-writes'),
            ('allow-xdr-writes', 'reject-xdr-writes'),
            'conflict-resolution-policy',
            'default-ttl',
            'disallow-null-setname',
            ('enable-xdr', None),
            'evict-tenths-pct',
            'high-water-disk-pct',
            'high-water-memory-pct',
            ('ldt-enabled', None),
            ('ldt-page-size', None),
            'memory-size',
            ('ns-forward-xdr-writes', None),
            'read-consistency-level-override',
            ('repl-factor', 'replication-factor'),
            ('sets-enable-xdr', None),
            'single-bin',
            'stop-writes-pct',
            ('total-bytes-memory', None),
            'write-commit-level-override'
        ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.test_namespace_config)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params_test))

    def test_bar_namespace(self):
        """
        Asserts namespace config output with heading, header & parameters.
        TODO: test for values as well
        """
        if not TestShowConfig.is_bar_present:
            return

        exp_heading = "~~bar Namespace Configuration"
        exp_header = "NODE"
        exp_params_bar = [  
            ('allow-nonxdr-writes', 'reject-non-xdr-writes'),
            ('allow-xdr-writes', 'reject-xdr-writes'),
            'conflict-resolution-policy',
            'default-ttl',
            'disallow-null-setname',
            ('enable-xdr', None),
            'evict-tenths-pct',
            'high-water-disk-pct',
            'high-water-memory-pct',
            ('ldt-enabled', None),
            ('ldt-page-size', None),
            'memory-size',
            ('ns-forward-xdr-writes', None),
            'read-consistency-level-override',
            ('repl-factor', 'replication-factor'),
            ('sets-enable-xdr', None),
            'single-bin',
            'stop-writes-pct',
            ('total-bytes-memory', None),
            'write-commit-level-override'
        ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.bar_namespace_config)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params_bar))

    # Needs updating after XDR config parsing has been fixed.
    # Tracked here: https://aerospike.atlassian.net/browse/TOOLS-1521
    @unittest.skip("Will enable only when xdr is configuired")
    def test_xdr(self):
        """
        Asserts XDR config output with heading, header & parameters.
        TODO: test for values as well
        """
        exp_heading = "~XDR Configuration"
        exp_header = "NODE"
        exp_params = [  
            'enable-xdr',
            'forward',
            'xdr-batch-num-retry',
            'xdr-batch-retry-sleep',
            'xdr-check-data-before-delete',
            'xdr-compression-threshold',
            'xdr-digestlog-size',
            'xdr-forward-with-gencheck',
            'xdr-hotkey-maxskip',
            'xdr-info-timeout',
            'xdr-local-port',
            'xdr-max-recs-inflight',
            'xdr-namedpipe-path',
            'xdr-nw-timeout',
            'xdr-read-mode',
            'xdr-read-threads',
            'xdr-ship-delay',
            'xdr-shipping-enabled',
            'xdr-timeout',
            'xdr-write-batch-size'
        ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.xdr_config)
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(set(exp_params).issubset(set(actual_params)))

class TestShowLatency(unittest.TestCase):
    output_list = list()
    proxy_latency = ''
    query_latency = ''
    reads_latency = ''
    udf_latency = ''
    writes_master_latency = ''
    writes_reply_latency = ''
    write_latency = ''

    @classmethod
    def setUpClass(cls):
        TestShowLatency.rc = controller.BasicRootController()
        actual_out = util.capture_stdout(TestShowLatency.rc.execute, ['show', 'latency'])
        TestShowLatency.output_list = test_util.get_separate_output(actual_out, 'Latency')

        for item in TestShowLatency.output_list:
            if "~~~proxy Latency" in item:
                TestShowLatency.proxy_latency = item
            elif "~~query Latency" in item:
                TestShowLatency.query_latency = item
            elif "~~reads Latency" in item or "~~read Latency" in item:
                TestShowLatency.reads_latency = item
            elif "~~udf Latency" in item:
                TestShowLatency.udf_latency = item
            elif "~~writes_master Latency" in item:
                TestShowLatency.writes_master_latency = item
            elif "~~writes_reply Latency" in item:
                TestShowLatency.writes_reply_latency = item
            elif "~~write Latency" in item:
                TestShowLatency.write_latency = item
            else:
                raise Exception('A latency table is unaccounted for in test setUp')

    @classmethod
    def tearDownClass(cls):
        cls.rc = None

    def test_proxy_latency(self):
        """
        Asserts <b> proxy latency <b> output with heading, header & no of node processed(based on row count).
        TODO: test for values as well
        """
        exp_heading = "~~proxy Latency"

        # Kept in case a server pre 5.1 needs to be tested
        # exp_header_old = [
        #     'Node',
        #     'Time Span',
        #     'Ops/Sec',
        #     '%>1ms',
        #     '%>8ms',
        #     '%>64ms'
        # ]

        exp_header= [
            'Node',
            'Time Span',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_no_of_rows = len(TestShowLatency.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatency.proxy_latency, horizontal = True)

        if actual_heading:
            self.assertTrue(exp_heading in actual_heading)

        if actual_header:
            self.assertEqual(exp_header, actual_header)

        if actual_no_of_rows:
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_query_latency(self):
        """
        Asserts <b> query latency <b> output with heading, header & no of node processed(based on row count).
        TODO: test for values as well
        """
        exp_heading = "~~query Latency~~"

        # Kept in case a server pre 5.1 needs to be tested
        # exp_header_old = [
        #     'Node',
        #     'Time Span',
        #     'Ops/Sec',
        #     '%>1Ms',
        #     '%>8Ms',
        #     '%>64Ms'
        # ]

        exp_header= [
            'Node',
            'Time Span',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]

        exp_no_of_rows = len(TestShowLatency.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatency.query_latency, horizontal = True)

        if actual_heading:
            self.assertTrue(exp_heading in actual_heading)

        if actual_header:
            self.assertEqual(exp_header, actual_header)

        if actual_no_of_rows:
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_reads_latency(self):
        """
        Asserts <b> reads latency <b> output with heading, header & no of node processed(based on row count).
        TODO: test for values as well
        """
        exp_heading = [("~~reads Latency", "~~read Latency")]

        # Kept in case a server pre 5.1 needs to be tested
        # exp_header= [
        #     'Node',
        #     'Time Span',
        #     'Ops/Sec',
        #     '%>1Ms',
        #     '%>8Ms',
        #     '%>64Ms'
        # ]

        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]

        exp_no_of_rows = len(TestShowLatency.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatency.reads_latency, horizontal = True, header_len=1)

        self.assertTrue(test_util.check_for_subset(actual_heading, exp_heading))
        self.assertEqual(exp_header, actual_header)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_udf_latency(self):
        """
        Asserts <b> udf latency <b> output with heading, header & no of node processed(based on row count).
        TODO: test for values as well
        """
        exp_heading = "~~udf Latency~~"
        exp_header= ['Node',
                     'Time Span',
                     'Ops/Sec',
                     '%>1Ms',
                     '%>8Ms',
                     '%>64Ms']

        exp_no_of_rows = len(TestShowLatency.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatency.udf_latency, horizontal = True)

        if actual_heading:
            self.assertTrue(exp_heading in actual_heading)

        if actual_header:
            self.assertEqual(exp_header, actual_header)

        if actual_no_of_rows:
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_writes_master_latency(self):
        """
        Asserts <b> writes_master latency <b> output with heading, header & no of node processed(based on row count).
        TODO: test for values as well
        """
        exp_heading = "~~writes_master Latency~~"
        exp_header= ['Node',
                     'Time Span',
                     'Ops/Sec',
                     '%>1Ms',
                     '%>8Ms',
                     '%>64Ms']

        exp_no_of_rows = len(TestShowLatency.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatency.writes_master_latency, horizontal = True)

        if actual_heading:
            self.assertTrue(exp_heading in actual_heading)

        if actual_header:
            self.assertEqual(exp_header, actual_header)

        if actual_no_of_rows:
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_write_latencies(self):
        """
        Asserts <b> writes latency <b> output with heading, header & no of node processed(based on row count).
        TODO: test for values as well
        """
        exp_heading = "~~write Latency"

        # Kept incase a server version pre 5.1 needs testing
        # exp_header_old = [
        #     'Node',
        #     'Time Span',
        #     'Ops/Sec',
        #     '%>1Ms',
        #     '%>8Ms',
        #     '%>64Ms'
        # ]

        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]

        exp_no_of_rows = len(TestShowLatency.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatency.write_latency, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

class TestShowLatenciesDefault(unittest.TestCase):
    output_list = list()
    batch_index_latencies = ''
    query_latencies = ''
    query_rec_count_latencies = ''
    re_repl_latencies = ''
    read_latencies = ''
    read_dup_res_latencies = ''
    read_local_latencies = ''
    read_repl_ping_latencies = ''
    read_response_latencies = ''
    read_restart_latencies = ''
    read_start_latencies = ''
    udf_latencies = ''
    write_latencies = ''
    write_dup_res_latencies = ''
    write_master_latencies = ''
    write_repl_write_latencies = ''
    write_response_latencies = ''
    write_restart_latencies = ''
    write_start_latencies = ''

    @classmethod
    def setUpClass(cls):
        TestShowLatenciesDefault.rc = controller.BasicRootController()
        actual_out = util.capture_stdout(TestShowLatenciesDefault.rc.execute, ['show', 'latencies', '-v'])
        TestShowLatenciesDefault.output_list = test_util.get_separate_output(actual_out, 'Latency')
        for item in TestShowLatenciesDefault.output_list:
            if "~batch-index Latency" in item:
                TestShowLatenciesDefault.batch_index_latencies = item
            elif "~query Latency" in item:
                TestShowLatenciesDefault.query_latencies = item
            elif "~query-rec-count Latency" in item:
                TestShowLatenciesDefault.query_rec_count_latencies = item
            elif "~re-repl Latency" in item:
                TestShowLatenciesDefault.re_repl_latencies = item
            elif "~read Latency" in item:
                TestShowLatenciesDefault.read_latencies = item
            elif "~read-dup-res Latency" in item:
                TestShowLatenciesDefault.read_dup_res_latencies = item
            elif "~read-local Latency" in item:
                TestShowLatenciesDefault.read_local_latencies = item
            elif "~read-repl-ping Latency" in item:
                TestShowLatenciesDefault.read_repl_ping_latencies = item
            elif "~read-response Latency" in item:
                TestShowLatenciesDefault.read_response_latencies = item
            elif "~read-restart Latency" in item:
                TestShowLatenciesDefault.read_restart_latencies = item
            elif "~read-start Latency" in item:
                TestShowLatenciesDefault.read_start_latencies = item
            elif "~udf Latency" in item:
                TestShowLatenciesDefault.udf_latencies = item
            elif "~write Latency" in item:
                TestShowLatenciesDefault.write_latencies = item
            elif "~write-dup-res Latency" in item:
                TestShowLatenciesDefault.write_dup_res_latencies = item
            elif "~write-master Latency" in item:
                TestShowLatenciesDefault.write_master_latencies = item
            elif "~write-repl-write Latency" in item:
                TestShowLatenciesDefault.write_repl_write_latencies = item
            elif "~write-response Latency" in item:
                TestShowLatenciesDefault.write_response_latencies = item
            elif "~write-restart Latency" in item:
                TestShowLatenciesDefault.write_restart_latencies = item
            elif "~write-start Latency" in item:
                TestShowLatenciesDefault.write_start_latencies = item
            else:
                raise Exception('A latencies table is unaccounted for in test setUp')

            # TODO:These will be used when tests for ops-sub-are created
            # elif "~ops-sub-start Latency" in item:
            #     TestShowLatenciesDefault.ops_sub_start = item
            # elif "~ops-sub-restart Latency" in item:
            #     TestShowLatenciesDefault.ops_sub_restart = item
            # elif "~ops-sub-dup-res Latency" in item:
            #     TestShowLatenciesDefault.ops_sub_dup_res = item
            # elif "~ops-sub-master Latency" in item:
            #     TestShowLatenciesDefault.ops_sub_master = item
            # elif "~ops-sub-repl-write Latency" in item:
            #     TestShowLatenciesDefault.ops_sub_repl_write = item
            # elif "~ops-sub-response Latency" in item:
            #     TestShowLatenciesDefault.ops_sub_response = item

    @classmethod
    def tearDownClass(cls):
        cls.rc = None

    def test_read_latencies(self):
        """
        Asserts <b> read latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~read Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)
        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.read_latencies, horizontal = True, header_len=1)
        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_read_dup_res_latencies(self):
        """
        Asserts <b> read-dup-res latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~read-dup-res Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.read_dup_res_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_read_local_latencies(self):
        """
        Asserts <b> read-local latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~read-local Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.read_local_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_read_repl_ping_latencies(self):
        """
        Asserts <b> read-repl-ping latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~read-repl-ping Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.read_repl_ping_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_read_response_latencies(self):
        """
        Asserts <b> read-response latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~read-response Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.read_response_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_read_restart_latencies(self):
        """
        Asserts <b> read-restart latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~read-restart Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.read_restart_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_read_start_latencies(self):
        """
        Asserts <b> read-start latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~~read-start Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.read_start_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_write_latencies(self):
        """
        Asserts <b> writes latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~write Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.write_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_write_dup_res_latencies(self):
        """
        Asserts <b> write-dup-res latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~write-dup-res Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.write_dup_res_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_write_master_latencies(self):
        """
        Asserts <b> write-master latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~write-master Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.write_master_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_write_repl_write_latencies(self):
        """
        Asserts <b> write-repl-write latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~write-repl-write Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.write_repl_write_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_write_response_latencies(self):
        """
        Asserts <b> write-response latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~write-response Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.write_response_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_write_restart_latencies(self):
        """
        Asserts <b> write-restart latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~write-restart Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)

        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.write_restart_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_write_start_latencies(self):
        """
        Asserts <b> write-start latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "~write-start Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesDefault.rc.cluster._live_nodes)
        actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(TestShowLatenciesDefault.write_start_latencies, horizontal = True, header_len=1)

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "%s returned the wrong data types" % exp_heading)
        self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))


class TestShowLatenciesWithArguments(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        TestShowLatenciesWithArguments.rc = controller.BasicRootController()

    def test_latencies_e_1_b_17(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 1 -b 17 display the correct header 
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>2ms',
            '%>4ms',
            '%>8ms',
            '%>16ms',
            '%>32ms',
            '%>64ms',
            '%>128ms',
            '%>256ms',
            '%>512ms',
            '%>1024ms',
            '%>2048ms',
            '%>4096ms',
            '%>8192ms',
            '%>16384ms',
            '%>32768ms',
            '%>65536ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesWithArguments.rc.cluster._live_nodes)
        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-e', '1', '-b', '17'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')

        for output in output_list:
            actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(output, horizontal = True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_latencies_e_1_b_18(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 1 -b 18 display the correct header 
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>2ms',
            '%>4ms',
            '%>8ms',
            '%>16ms',
            '%>32ms',
            '%>64ms',
            '%>128ms',
            '%>256ms',
            '%>512ms',
            '%>1024ms',
            '%>2048ms',
            '%>4096ms',
            '%>8192ms',
            '%>16384ms',
            '%>32768ms',
            '%>65536ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesWithArguments.rc.cluster._live_nodes)
        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-e', '1', '-b', '18'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')
        
        for output in output_list:
            actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(output, horizontal = True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_latencies_e_0_b_17(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 0 -b 17 display the correct header 
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>2ms',
            '%>4ms',
            '%>8ms',
            '%>16ms',
            '%>32ms',
            '%>64ms',
            '%>128ms',
            '%>256ms',
            '%>512ms',
            '%>1024ms',
            '%>2048ms',
            '%>4096ms',
            '%>8192ms',
            '%>16384ms',
            '%>32768ms',
            '%>65536ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesWithArguments.rc.cluster._live_nodes)
        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-e', '0', '-b', '17'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')
        
        for output in output_list:
            actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(output, horizontal = True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_latencies_e_17_b_1(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 17 -b 1 display the correct header 
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms'
        ]
        exp_data_types = [
            str,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesWithArguments.rc.cluster._live_nodes)
        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-e', '17', '-b', '1'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')
        
        for output in output_list:
            actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(output, horizontal = True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_latencies_e_100_b_200(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 100 -b 200 display the correct header 
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
        ]

        exp_no_of_rows = len(TestShowLatenciesWithArguments.rc.cluster._live_nodes)
        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-e', '100', '-b', '200'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')

        for output in output_list:
            actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(output, horizontal = True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_latencies_e_16_b_2(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 16 -b 2 display the correct header 
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>65536ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesWithArguments.rc.cluster._live_nodes)
        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-e', '16', '-b', '2'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')

        for output in output_list:
            actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(output, horizontal = True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_latencies_e_4_b_7(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 4 -b 7 display the correct header 
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            'Node',
            'Ops/Sec',
            '%>1ms',
            '%>16ms',
            '%>256ms',
            '%>4096ms',
            '%>65536ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float,
            float,
            float
        ]

        exp_no_of_rows = len(TestShowLatenciesWithArguments.rc.cluster._live_nodes)
        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-e', '4', '-b', '7'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')

        for output in output_list:
            actual_heading, actual_header, actual_data, actual_no_of_rows = test_util.parse_output(output, horizontal = True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_latencies_group_by_machine_name(self):
        """
        Asserts <b> show latencies <b> with a -m argument which groups tables by machine name
        """
        exp_header = [
            'Histogram',
            'Ops/Sec',
            '%>1ms',
            '%>8ms',
            '%>64ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float
        ]

        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-m'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')

        for output in output_list:
                actual_heading, actual_header, actual_data, _ = test_util.parse_output(output, horizontal = True, header_len=1)
                self.assertEqual(exp_header, actual_header)
                self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")


    def test_latencies_group_by_machine_name_e_2_8(self):
        """
        Asserts <b> show latencies <b> with a -m argument which groups tables by machine name
        """
        exp_header = [
            'Histogram',
            'Ops/Sec',
            '%>1ms',
            '%>4ms',
            '%>16ms',
            '%>64ms',
            '%>256ms',
            '%>1024ms',
            '%>4096ms',
            '%>16384ms'
        ]
        exp_data_types = [
            str,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float
        ]

        actual_out = util.capture_stdout(TestShowLatenciesWithArguments.rc.execute, ['show', 'latencies','-m','-e','2','-b','8'])
        output_list = test_util.get_separate_output(actual_out, 'Latency')

        for output in output_list:
            actual_heading, actual_header, actual_data, _ = test_util.parse_output(output, horizontal = True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(test_util.check_for_types(actual_data, exp_data_types), "returned the wrong data types")

class TestShowDistribution(unittest.TestCase):
    output_list = list()
    test_ttl_distri = ''
    bar_ttl_distri = ''

    @classmethod
    def setUpClass(cls):
        rc = controller.BasicRootController()
        actual_out = util.capture_stdout(rc.execute, ['show', 'distribution'])
        # use regex in get_separate_output(~.+Distribution.*~.+)
        #if you are changing below Distribution keyword
        TestShowDistribution.output_list = test_util.get_separate_output(actual_out, 'Distribution in Seconds')
        TestShowDistribution.is_bar_present = False

        for item in TestShowDistribution.output_list:
            if "~~test - TTL Distribution in Seconds" in item:
                TestShowDistribution.test_ttl_distri = item
            elif "~~bar - TTL Distribution in Seconds" in item:
                TestShowDistribution.bar_ttl_distri = item
                TestShowDistribution.is_bar_present = True
            elif "~~~~" in item:
                TestShowDistribution.test_namespace_config = item


    @classmethod
    def tearDownClass(cls):
        cls.rc = None

    def test_test_ttl(self):
        """
        Asserts TTL Distribution in Seconds for test namespace with heading, header & parameters.
        TODO: test for values as well
        """
        exp_heading = "~~test - TTL Distribution in Seconds"
        exp_header = """Percentage of records having ttl less than or equal
                        to value measured in Seconds
                        Node   10%   20%   30%   40%   50%   60%   70%   80%   90%   100%"""

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowDistribution.test_ttl_distri, horizontal=True, merge_header = False)
        if 'Node' not in actual_header:
            actual_header += ' ' + TestShowDistribution.test_ttl_distri.split('\n')[3]
        exp_header = ' '.join(exp_header.split())
        actual_header = ' '.join([item for item in actual_header.split()
                                  if not item.startswith('\x1b')])

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header.strip(), actual_header.strip())

    def test_bar_ttl(self):
        """
        Asserts TTL Distribution in Seconds for bar namespace with heading, header & parameters.
        TODO: test for values as well
        """
        if not TestShowDistribution.is_bar_present:
            return
        exp_heading = "~~bar - TTL Distribution in Seconds"
        exp_header = """Percentage of records having ttl less than or equal
                        to value measured in Seconds
                        Node   10%   20%   30%   40%   50%   60%   70%   80%   90%   100%"""

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowDistribution.bar_ttl_distri, horizontal=True, mearge_header = False)
        if 'Node' not in actual_header:
            actual_header += ' ' + TestShowDistribution.bar_ttl_distri.split('\n')[3]
        exp_header = ' '.join(exp_header.split())
        actual_header = ' '.join([item for item in actual_header.split()
                                  if not item.startswith('\x1b')])

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header.strip(), actual_header.strip())

class TestShowStatistics(unittest.TestCase):
    output_list = list()
    test_bin_stats = ''
    bar_bin_stats = ''
    service_stats = ''
    bar_namespace_stats = ''
    test_namespace_stats = ''
    xdr_stats = ''

    @classmethod
    def setUpClass(cls):
        rc = controller.BasicRootController()
        actual_out = util.capture_stdout(rc.execute, ['show', 'statistics'])
        TestShowStatistics.output_list = test_util.get_separate_output(actual_out, 'Statistics')
        TestShowStatistics.output_list.append(util.capture_stdout(rc.execute, ['show', 'statistics', 'xdr']))
        TestShowStatistics.is_bar_present = False
        for item in TestShowStatistics.output_list:
            if "~test Bin Statistics" in item:
                TestShowStatistics.test_bin_stats = item
            elif "~bar Bin Statistics" in item:
                TestShowStatistics.bar_bin_stats = item
                TestShowStatistics.is_bar_present = True
            elif "~Service Statistics" in item:
                TestShowStatistics.service_stats = item
            elif "~bar Namespace Statistics" in item:
                TestShowStatistics.bar_namespace_stats = item
                TestShowStatistics.is_bar_present = True
            elif "~test Namespace Statistics" in item:
                TestShowStatistics.test_namespace_stats = item
            elif "~XDR Statistics" in item:
                TestShowStatistics.xdr_stats = item
            # TODO: Add missing tests
            # else:
            #     raise Exception('A statistics table is unaccounted for in test setUp', item)

    @classmethod
    def tearDownClass(cls):
        cls.rc = None

    def test_test_bin(self):
        """
        This test will assert <b> test Bin Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        exp_heading = "~test Bin Statistics"
        exp_header = "NODE"
        exp_params = [('bin-names-quota','bin_names_quota'), ('num-bin-names','bin_names')]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.test_bin_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params))

    def test_bar_bin(self):
        """
        This test will assert <b> bar Bin Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        if not TestShowStatistics.is_bar_present:
            return
        exp_heading = "~bar Bin Statistics"
        exp_header = "NODE"
        exp_params = [('bin-names-quota','bin_names_quota'), ('num-bin-names','bin_names')]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.bar_bin_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params))

    def test_service(self):
        """
        This test will assert <b> Service Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        exp_heading = "~Service Statistics"
        exp_header = "NODE"

        # Kept in case an older server needs to be tested
        # exp_params = [  
        #     ('batch_errors', 'batch_error', None),
        #     ('batch_initiate', None),
        #     ('batch_queue', None),
        #     ('batch_timeout', None),
        #     ('batch_tree_count', None),
        #     'client_connections',
        #     'cluster_integrity',
        #     'cluster_key',
        #     'cluster_size',
        #     ('data-used-bytes-memory', None),
        #     ('err_duplicate_proxy_request', None),
        #     ('err_out_of_space', None),
        #     ('err_replica_non_null_node', None),
        #     ('err_replica_null_node', None),
        #     ('err_rw_cant_put_unique', None),
        #     ('err_rw_pending_limit', None),
        #     ('err_rw_request_not_found', None),
        #     ('err_storage_queue_full', None),
        #     ('err_sync_copy_null_master', None),
        #     ('err_tsvc_requests', None),
        #     ('err_write_fail_bin_exists', None),
        #     ('err_write_fail_bin_name', None),
        #     ('err_write_fail_bin_not_found', None),
        #     ('err_write_fail_forbidden', None),
        #     ('err_write_fail_generation', None),
        #     ('err_write_fail_incompatible_type', None),
        #     ('err_write_fail_key_exists', None),
        #     ('err_write_fail_key_mismatch', None),
        #     ('err_write_fail_not_found', None),
        #     ('err_write_fail_parameter', None),
        #     ('err_write_fail_prole_delete', None),
        #     ('err_write_fail_prole_generation', None),
        #     ('err_write_fail_prole_unknown', None),
        #     ('err_write_fail_record_too_big', None),
        #     ('err_write_fail_unknown', None),
        #     ('fabric_msgs_rcvd', None),
        #     ('fabric_msgs_sent', None),
        #     ('free-pct-disk', None),
        #     ('free-pct-memory', None),
        #     'heartbeat_received_foreign',
        #     'heartbeat_received_self',
        #     ('index-used-bytes-memory', None),
        #     'info_queue',
        #     'objects',
        #     ('ongoing_write_reqs', None),
        #     ('partition_absent', None),
        #     ('partition_actual', None),
        #     ('partition_desync', None),
        #     ('partition_object_count', None),
        #     ('partition_ref_count', None),
        #     ('partition_replica', None),
        #     'paxos_principal',
        #     ('proxy_action', None),
        #     'proxy_in_progress',
        #     ('proxy_initiate', None),
        #     ('proxy_retry', None),
        #     ('proxy_retry_new_dest', None),
        #     ('proxy_retry_q_full', None),
        #     ('proxy_retry_same_dest', None),
        #     ('proxy_unproxy', None),
        #     ('query_abort', None),
        #     ('query_agg', None),
        #     ('query_agg_abort', None),
        #     ('query_agg_avg_rec_count', None),
        #     ('query_agg_err', None),
        #     ('query_agg_success', None),
        #     ('query_avg_rec_count', None),
        #     ('query_fail', None),
        #     ('query_long_queue_full', None),
        #     'query_long_running',
        #     ('query_lookup_abort', None),
        #     ('query_lookup_avg_rec_count', None),
        #     ('query_lookup_err', None),
        #     ('query_lookup_success', None),
        #     ('query_lookups', None),
        #     ('query_reqs', None),
        #     ('query_short_queue_full', None),
        #     'query_short_running',
        #     ('query_success', None),
        #     ('queue', 'tsvc_queue', None),
        #     ('read_dup_prole', None),
        #     'reaped_fds',
        #     ('record_locks', None),
        #     ('record_refs', None),
        #     ('rw_err_ack_badnode', None),
        #     ('rw_err_ack_internal', None),
        #     ('rw_err_ack_nomatch', None),
        #     ('rw_err_dup_cluster_key', None),
        #     ('rw_err_dup_internal', None),
        #     ('rw_err_dup_send', None),
        #     ('rw_err_write_cluster_key', None),
        #     ('rw_err_write_internal', None),
        #     ('rw_err_write_send', None),
        #     ('sindex-used-bytes-memory', None),
        #     ('sindex_gc_activity_dur', None),
        #     'sindex_gc_garbage_cleaned',
        #     'sindex_gc_garbage_found',
        #     ('sindex_gc_inactivity_dur', None),
        #     'sindex_gc_list_creation_time',
        #     'sindex_gc_list_deletion_time',
        #     'sindex_gc_objects_validated',
        #     'sindex_ucgarbage_found',
        #     ('stat_cluster_key_err_ack_dup_trans_reenqueue', None),
        #     ('stat_delete_success', None),
        #     ('stat_deleted_set_objects', None),
        #     ('stat_duplicate_operation', None),
        #     ('stat_evicted_objects', None),
        #     ('stat_evicted_objects_time', None),
        #     ('stat_expired_objects', None),
        #     ('stat_ldt_proxy', None),
        #     ('stat_nsup_deletes_not_shipped', None),
        #     ('stat_proxy_errs', None),
        #     ('stat_proxy_reqs', None),
        #     ('stat_proxy_reqs_xdr', None),
        #     ('stat_proxy_success', None),
        #     ('stat_read_errs_notfound', None),
        #     ('stat_read_errs_other', None),
        #     ('stat_read_reqs', None),
        #     ('stat_read_reqs_xdr', None),
        #     ('stat_read_success', None),
        #     ('stat_rw_timeout', None),
        #     ('stat_write_errs', None),
        #     ('stat_write_errs_notfound', None),
        #     ('stat_write_errs_other', None),
        #     ('stat_write_reqs', None),
        #     ('stat_write_reqs_xdr', None),
        #     ('stat_write_success', None),
        #     ('stat_zero_bin_records', None),
        #     ('storage_defrag_corrupt_record', None),
        #     ('sub-records', 'sub_objects', None),
        #     'system_free_mem_pct',
        #     ('system_swapping', None),
        #     ('total-bytes-disk', None),
        #     ('total-bytes-memory', None),
        #     ('transactions', None),
        #     ('tree_count', None),
        #     ('udf_delete_err_others', None),
        #     ('udf_delete_reqs', None),
        #     ('udf_delete_success', None),
        #     ('udf_lua_errs', None),
        #     ('udf_query_rec_reqs', None),
        #     ('udf_read_errs_other', None),
        #     ('udf_read_reqs', None),
        #     ('udf_read_success', None),
        #     ('udf_replica_writes', None),
        #     ('udf_scan_rec_reqs', None),
        #     ('udf_write_err_others', None),
        #     ('udf_write_reqs', None),
        #     ('udf_write_success', None),
        #     'uptime',
        #     ('used-bytes-disk', None),
        #     ('used-bytes-memory', None),
        #     ('waiting_transactions', None),
        #     ('write_master', None),
        #     ('write_prole', None)
        # ]

        # TODO: Add possibly missing params.  This is only verified as a subset
        exp_params = [  
            'client_connections',
            'cluster_integrity',
            'cluster_key',
            'cluster_size',
            'heartbeat_received_foreign',
            'heartbeat_received_self',
            'info_queue',
            'objects',
            'paxos_principal',
            'proxy_in_progress',
            'query_long_running',
            'query_short_running',
            'reaped_fds',
            'sindex_gc_garbage_cleaned',
            'sindex_gc_garbage_found',
            'sindex_gc_list_creation_time',
            'sindex_gc_list_deletion_time',
            'sindex_gc_objects_validated',
            'sindex_ucgarbage_found',
            'uptime',
        ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.service_stats)
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params))

    def test_bar_namespace(self):
        """
        This test will assert <b> bar Namespace Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        if not TestShowStatistics.is_bar_present:
            return
        exp_heading = "~bar Namespace Statistics"
        exp_header = "NODE"

        # Kept in case an older version of the server needs testing
        # exp_params = [  
        #     ('allow-nonxdr-writes', 'reject-non-xdr-writes'),
        #     ('allow-xdr-writes', 'reject-xdr-writes'),
        #     ('available-bin-names','available_bin_names'),
        #     'conflict-resolution-policy',
        #     ('current-time','current_time'),
        #     ('data-used-bytes-memory','memory_used_data_bytes'),
        #     'default-ttl',
        #     'disallow-null-setname',
        #     ('enable-xdr', None),
        #     'evict-tenths-pct',
        #     ('evicted-objects','evicted_objects'),
        #     ('expired-objects','expired_objects'),
        #     ('free-pct-memory','memory_free_pct'),
        #     'high-water-disk-pct',
        #     'high-water-memory-pct',
        #     ('hwm-breached','hwm_breached'),
        #     ('index-used-bytes-memory','memory_used_index_bytes'),
        #     ('ldt-enabled', None),
        #     ('ldt-page-size', None),
        #     ('master-objects','master_objects'),
        #     ('master-sub-objects','master_sub_objects', None),
        #     ('max-void-time','max_void_time', None),
        #     'memory-size',
        #     ('migrate-rx-partitions-initial','migrate_rx_partitions_initial', None),
        #     ('migrate-rx-partitions-remaining','migrate_rx_partitions_remaining', None),
        #     ('migrate-tx-partitions-imbalance','migrate_tx_partitions_imbalance', None),
        #     ('migrate-tx-partitions-initial','migrate_tx_partitions_initial', None),
        #     ('migrate-tx-partitions-remaining','migrate_tx_partitions_remaining', None),
        #     ('non-expirable-objects','non_expirable_objects'),
        #     ('ns-forward-xdr-writes', None),
        #     ('nsup-cycle-duration','nsup_cycle_duration'),
        #     ('nsup-cycle-sleep-pct','nsup_cycle_sleep_pct', None),
        #     'objects',
        #     ('prole-objects','prole_objects'),
        #     ('prole-sub-objects','prole_sub_objects', None),
        #     'read-consistency-level-override',
        #     ('repl-factor', 'replication-factor'),
        #     ('set-deleted-objects','set_deleted_objects', None),
        #     'sets-enable-xdr',
        #     ('sindex-used-bytes-memory','memory_used_sindex_bytes'),
        #     'single-bin',
        #     ('stop-writes','stop_writes'),
        #     'stop-writes-pct',
        #     ('sub-objects','sub_objects', None),
        #     ('total-bytes-memory',None),
        #     ('type',None),
        #     ('used-bytes-memory','memory_used_bytes'),
        #     'write-commit-level-override',
        # ]

        # TODO: Add possibly missing params.  This is only verified as a subset
        exp_params = [  
            'reject-non-xdr-writes',
            'reject-xdr-writes',
            'available_bin_names',
            'conflict-resolution-policy',
            'current_time',
            'memory_used_data_bytes',
            'default-ttl',
            'disallow-null-setname',
            'evict-tenths-pct',
            'evicted_objects',
            'expired_objects',
            'memory_free_pct',
            'high-water-disk-pct',
            'high-water-memory-pct',
            'hwm_breached',
            'memory_used_index_bytes',
            'master_objects',
            'memory-size',
            'non_expirable_objects',
            'nsup_cycle_duration',
            'objects',
            'prole_objects',
            'read-consistency-level-override',
            'replication-factor',
            'memory_used_sindex_bytes',
            'single-bin',
            'stop_writes',
            'stop-writes-pct',
            'memory_used_bytes',
            'write-commit-level-override',
        ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.bar_namespace_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params,exp_params))

    def test_test_namespace(self):
        """
        This test will assert <b> test Namespace Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        exp_heading = "~test Namespace Statistics"
        exp_header = "NODE"

        # Kept in case an older version of the server needs testing
        # exp_params = [  
        #     'allow-nonxdr-writes',
        #     'allow-xdr-writes',
        #     ('available-bin-names', 'available_bin_names'),
        #     'conflict-resolution-policy',
        #     'current_time',
        #     'memory_used_data_bytes',
        #     'default-ttl',
        #     'disallow-null-setname',
        #     'evict-tenths-pct',
        #     'evicted_objects',
        #     'expired_objects',
        #     'memory_free_pct',
        #     'high-water-disk-pct',
        #     'high-water-memory-pct',
        #     'hwm_breached',
        #     'memory_used_index_bytes',
        #     'master_objects',
        #     'memory-size',
        #     'non_expirable_objects',
        #     'nsup_cycle_duration',
        #     'objects',
        #     'prole_objects',
        #     'read-consistency-level-override',
        #     'replication-factor',
        #     'memory_used_sindex_bytes',
        #     'single-bin',
        #     'stop_writes',
        #     'stop-writes-pct',
        #     'memory_used_bytes',
        #     'write-commit-level-override',
        # ]

        # TODO: Add possibly missing params.  This is only verified as a subset
        exp_params = [  
            'reject-non-xdr-writes',
            'reject-xdr-writes',
            'available_bin_names',
            'conflict-resolution-policy',
            'current_time',
            'memory_used_data_bytes',
            'default-ttl',
            'disallow-null-setname',
            'evict-tenths-pct',
            'evicted_objects',
            'expired_objects',
            'memory_free_pct',
            'high-water-disk-pct',
            'high-water-memory-pct',
            'hwm_breached',
            'memory_used_index_bytes',
            'master_objects',
            'memory-size',
            'non_expirable_objects',
            'nsup_cycle_duration',
            'objects',
            'prole_objects',
            'read-consistency-level-override',
            'replication-factor',
            'memory_used_sindex_bytes',
            'single-bin',
            'stop_writes',
            'stop-writes-pct',
            'memory_used_bytes',
            'write-commit-level-override',
        ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.test_namespace_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params))

    #@unittest.skip("Will enable only when xdr is configuired")
    def test_xdr(self):
        """
        This test will assert <b> xdr Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        exp_heading = "~XDR Statistics"
        exp_header = "NODE"

        # Left in case an older server version needs to be tested
        # exp_params_old = [  
        #     'cur_throughput',
        #     'err_ship_client',
        #     'err_ship_conflicts',
        #     'err_ship_server',
        #     'esmt-bytes-shipped',
        #     'esmt-bytes-shipped-compression',
        #     'esmt-ship-compression',
        #     'free-dlog-pct',
        #     'latency_avg_dlogread',
        #     'latency_avg_dlogwrite',
        #     'latency_avg_ship',
        #     'local_recs_fetch_avg_latency',
        #     'local_recs_fetched',
        #     'local_recs_migration_retry',
        #     'local_recs_notfound',
        #     'noship_recs_dup_intrabatch',
        #     'noship_recs_expired',
        #     'noship_recs_genmismatch',
        #     'noship_recs_notmaster',
        #     'noship_recs_unknown_namespace',
        #     'perdc_timediff_lastship_cur_secs',
        #     'stat_dlog_fread',
        #     'stat_dlog_fseek',
        #     'stat_dlog_fwrite',
        #     'stat_dlog_read',
        #     'stat_dlog_write',
        #     'stat_pipe_reads_diginfo',
        #     'stat_recs_dropped',
        #     'stat_recs_localprocessed',
        #     'stat_recs_logged',
        #     'stat_recs_outstanding',
        #     'stat_recs_relogged',
        #     'stat_recs_replprocessed',
        #     'stat_recs_shipped',
        #     'stat_recs_shipping',
        #     'timediff_lastship_cur_secs',
        #     'total-recs-dlog',
        #     'used-recs-dlog',
        #     'xdr-uptime',
        #     'xdr_deletes_canceled',
        #     'xdr_deletes_relogged',
        #     'xdr_deletes_shipped',
        # ]

        # 5.0+
        exp_params = [
            "abandoned",
            "compression_ratio",
            "filtered_out",
            "hot_keys",
            "in_progress",
            "in_queue",
            "lag",
            "lap_us",
            "latency_ms",
            "not_found",
            "recoveries",
            "recoveries_pending",
            "retry_conn_reset",
            "retry_dest",
            "retry_no_node",
            "success",
            "throughput",
            "uncompressed_pct"
        ]
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.xdr_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(test_util.check_for_subset(actual_params, exp_params))

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
#     suite = unittest.TestLoader().loadTestsFromTestCase(TestShowConfig)
#     unittest.TextTestRunner(verbosity=2).run(suite)
    unittest.main()
