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

import os
import sys
import time
import unittest

import lib.live_cluster.live_cluster_root_controller as controller
import lib.utils.util as util
from test.e2e import util as test_util

sys.path.insert(1, os.getcwd())

from lib.view.sheet import set_style_json

set_style_json()


def print_header(actual_header):
    for item in actual_header:
        print('"' + item + '",')


class TestShowConfig(unittest.TestCase):
    real_stdout = None
    output_list = list()
    service_config = ""
    network_config = ""
    test_namespace_config = ""
    bar_namespace_config = ""
    xdr_config = ""

    @classmethod
    def setUpClass(cls):
        cls.real_stdout = sys.stdout
        TestShowConfig.rc = controller.LiveClusterRootController(
            user="admin", password="admin"
        )

        actual_out = util.capture_stdout(TestShowConfig.rc.execute, ["show", "config"])
        actual_out += util.capture_stdout(
            TestShowConfig.rc.execute, ["show", "config", "xdr"]
        )
        TestShowConfig.output_list = test_util.get_separate_output(actual_out)
        TestShowConfig.is_bar_present = False

        for item in TestShowConfig.output_list:
            title = item["title"]

            if "Service Configuration" in title:
                TestShowConfig.service_config = item
            elif "Network Configuration" in title:
                TestShowConfig.network_config = item
            elif "test Namespace Configuration" in title:
                TestShowConfig.test_namespace_config = item
            elif "bar Namespace Configuration" in title:
                TestShowConfig.bar_namespace_config = item
                TestShowConfig.is_bar_present = True
            elif "XDR Configuration" in title:
                TestShowConfig.xdr_config = item

    @classmethod
    def tearDownClass(cls):
        cls.rc = None
        sys.stdout = cls.real_stdout

    def test_network(self):
        """
        This test will assert network output on heading, header, parameters.
        TODO: test for values as well
        """

        exp_heading = "Network Configuration"
        exp_header = [
            "Node",
            "fabric.channel-bulk-fds",
            "fabric.channel-bulk-recv-threads",
            "fabric.channel-ctrl-fds",
            "fabric.channel-ctrl-recv-threads",
            "fabric.channel-meta-fds",
            "fabric.channel-meta-recv-threads",
            "fabric.channel-rw-fds",
            "fabric.channel-rw-recv-pools",
            "fabric.channel-rw-recv-threads",
            "fabric.keepalive-enabled",
            "fabric.keepalive-intvl",
            "fabric.keepalive-probes",
            "fabric.keepalive-time",
            "fabric.latency-max-ms",
            "fabric.port",
            "fabric.recv-rearm-threshold",
            "fabric.send-threads",
            "fabric.tls-name",
            "fabric.tls-port",
            "heartbeat.connect-timeout-ms",
            "heartbeat.interval",
            "heartbeat.mode",
            "heartbeat.mtu",
            "heartbeat.multicast-group",
            "heartbeat.port",
            "heartbeat.protocol",
            "heartbeat.timeout",
            "info.port",
            "service.access-port",
            "service.address",
            "service.alternate-access-port",
            "service.port",
            "service.tls-access-port",
            "service.tls-alternate-access-port",
            "service.tls-name",
            "service.tls-port",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowConfig.network_config)

        self.assertTrue(exp_heading in actual_heading)
        self.assertListEqual(exp_header, actual_header)

    def test_service(self):
        """
        Asserts service config output with heading, header & parameters.
        TODO: test for values as well
        """

        exp_heading = "Service Configuration"
        exp_header = [
            "Node",
            "paxos-single-replica-limit",
            "pidfile",
            "proto-fd-max",
            "advertise-ipv6",
            "auto-pin",
            "batch-index-threads",
            "batch-max-buffers-per-queue",
            "batch-max-requests",
            "batch-max-unused-buffers",
            "batch-without-digests",
            "cluster-name",
            "disable-udf-execution",
            "enable-benchmarks-fabric",
            "enable-health-check",
            "enable-hist-info",
            "feature-key-file",
            "info-threads",
            "keep-caps-ssd-health",
            "log-local-time",
            "log-millis",
            "microsecond-histograms",
            "migrate-fill-delay",
            "migrate-max-num-incoming",
            "migrate-threads",
            "min-cluster-size",
            "node-id",
            "node-id-interface",
            "proto-fd-idle-ms",
            "proto-slow-netio-sleep-ms",
            "query-batch-size",
            "query-buf-size",
            "query-bufpool-size",
            "query-in-transaction-thread",
            "query-long-q-max-size",
            "query-microbenchmark",
            "query-pre-reserve-partitions",
            "query-priority",
            "query-priority-sleep-us",
            "query-rec-count-bound",
            "query-req-in-query-thread",
            "query-req-max-inflight",
            "query-short-q-max-size",
            "query-threads",
            "query-threshold",
            "query-untracked-time-ms",
            "query-worker-threads",
            "run-as-daemon",
            "scan-max-done",
            "scan-threads-limit",
            "service-threads",
            "sindex-builder-threads",
            "sindex-gc-max-rate",
            "sindex-gc-period",
            "stay-quiesced",
            "ticker-interval",
            "transaction-max-ms",
            "transaction-retry-ms",
            "vault-ca",
            "vault-path",
            "vault-token-file",
            "vault-url",
            "work-directory",
            "debug-allocations",
            "indent-allocations",
            "service.port",
            "service.address",
            "service.access-port",
            "service.alternate-access-port",
            "service.tls-port",
            "service.tls-access-port",
            "service.tls-alternate-access-port",
            "service.tls-name",
            "heartbeat.mode",
            "heartbeat.multicast-group",
            "heartbeat.port",
            "heartbeat.interval",
            "heartbeat.timeout",
            "heartbeat.mtu",
            "heartbeat.protocol",
            "fabric.port",
            "fabric.tls-port",
            "fabric.tls-name",
            "fabric.channel-bulk-fds",
            "fabric.channel-bulk-recv-threads",
            "fabric.channel-ctrl-fds",
            "fabric.channel-ctrl-recv-threads",
            "fabric.channel-meta-fds",
            "fabric.channel-meta-recv-threads",
            "fabric.channel-rw-fds",
            "fabric.channel-rw-recv-pools",
            "fabric.channel-rw-recv-threads",
            "fabric.keepalive-enabled",
            "fabric.keepalive-intvl",
            "fabric.keepalive-probes",
            "fabric.keepalive-time",
            "fabric.latency-max-ms",
            "fabric.recv-rearm-threshold",
            "fabric.send-threads",
            "info.port",
            "enable-ldap",
            "enable-security",
            "ldap-login-threads",
            "privilege-refresh-period",
            "ldap.disable-tls",
            "ldap.polling-period",
            "ldap.query-base-dn",
            "ldap.query-user-dn",
            "ldap.query-user-password-file",
            "ldap.role-query-base-dn",
            "ldap.role-query-search-ou",
            "ldap.server",
            "ldap.session-ttl",
            "ldap.tls-ca-file",
            "ldap.token-hash-method",
            "ldap.user-dn-pattern",
            "ldap.user-query-pattern",
            "report-authentication-sinks",
            "report-data-op-sinks",
            "report-sys-admin-sinks",
            "report-user-admin-sinks",
            "report-violation-sinks",
            "syslog-local",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowConfig.service_config)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(actual_header, exp_header)

    def test_test_namespace(self):
        """
        Asserts namespace config output with heading, header & parameters.
        TODO: test for values as well
        """
        exp_heading = "test Namespace Configuration"
        exp_header_test = [
            "Node",
            "allow-ttl-without-nsup",
            "background-scan-max-rps",
            "conflict-resolution-policy",
            "data-in-index",
            "default-ttl",
            "disable-cold-start-eviction",
            "disable-write-dup-res",
            "disallow-null-setname",
            "enable-benchmarks-batch-sub",
            "enable-benchmarks-ops-sub",
            "enable-benchmarks-read",
            "enable-benchmarks-udf",
            "enable-benchmarks-udf-sub",
            "enable-benchmarks-write",
            "enable-hist-proxy",
            "evict-hist-buckets",
            "evict-tenths-pct",
            "geo2dsphere-within.earth-radius-meters",
            "geo2dsphere-within.level-mod",
            "geo2dsphere-within.max-cells",
            "geo2dsphere-within.max-level",
            "geo2dsphere-within.min-level",
            "geo2dsphere-within.strict",
            "high-water-disk-pct",
            "high-water-memory-pct",
            "ignore-migrate-fill-delay",
            "index-stage-size",
            "index-type",
            "memory-size",
            "migrate-order",
            "migrate-retransmit-ms",
            "migrate-sleep",
            "nsid",
            "nsup-hist-period",
            "nsup-period",
            "nsup-threads",
            "partition-tree-sprigs",
            "prefer-uniform-balance",
            "rack-id",
            "read-consistency-level-override",
            "reject-non-xdr-writes",
            "reject-xdr-writes",
            "replication-factor",
            "single-bin",
            "single-scan-threads",
            "stop-writes-pct",
            "strong-consistency",
            "strong-consistency-allow-expunge",
            "tomb-raider-eligible-age",
            "tomb-raider-period",
            "transaction-pending-limit",
            "truncate-threads",
            "write-commit-level-override",
            "xdr-bin-tombstone-ttl",
            "xdr-tomb-raider-period",
            "xdr-tomb-raider-threads",
            "storage-engine",
            "sindex.num-partitions",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowConfig.test_namespace_config)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(test_util.check_for_subset(actual_header, exp_header_test))

    def test_bar_namespace(self):
        """
        Asserts namespace config output with heading, header & parameters.
        TODO: test for values as well
        """
        if not TestShowConfig.is_bar_present:
            return

        exp_heading = "bar Namespace Configuration"
        exp_header_bar = [
            "Node",
            "allow-ttl-without-nsup",
            "background-scan-max-rps",
            "conflict-resolution-policy",
            "conflict-resolve-writes",
            "data-in-index",
            "default-ttl",
            "disable-cold-start-eviction",
            "disable-write-dup-res",
            "disallow-null-setname",
            "enable-benchmarks-batch-sub",
            "enable-benchmarks-ops-sub",
            "enable-benchmarks-read",
            "enable-benchmarks-udf",
            "enable-benchmarks-udf-sub",
            "enable-benchmarks-write",
            "enable-hist-proxy",
            "evict-hist-buckets",
            "evict-tenths-pct",
            "geo2dsphere-within.earth-radius-meters",
            "geo2dsphere-within.level-mod",
            "geo2dsphere-within.max-cells",
            "geo2dsphere-within.max-level",
            "geo2dsphere-within.min-level",
            "geo2dsphere-within.strict",
            "high-water-disk-pct",
            "high-water-memory-pct",
            "ignore-migrate-fill-delay",
            "index-stage-size",
            "index-type",
            "memory-size",
            "migrate-order",
            "migrate-retransmit-ms",
            "migrate-sleep",
            "nsid",
            "nsup-hist-period",
            "nsup-period",
            "nsup-threads",
            "partition-tree-sprigs",
            "prefer-uniform-balance",
            "rack-id",
            "read-consistency-level-override",
            "reject-non-xdr-writes",
            "reject-xdr-writes",
            "replication-factor",
            "sindex.num-partitions",
            "single-bin",
            "single-scan-threads",
            "stop-writes-pct",
            "storage-engine",
            "strong-consistency",
            "strong-consistency-allow-expunge",
            "tomb-raider-eligible-age",
            "tomb-raider-period",
            "transaction-pending-limit",
            "truncate-threads",
            "write-commit-level-override",
            "xdr-bin-tombstone-ttl",
            "xdr-tomb-raider-period",
            "xdr-tomb-raider-threads",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowConfig.bar_namespace_config)
        self.assertTrue(exp_heading in actual_heading)
        self.assertListEqual(exp_header_bar, actual_header)

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
            "enable-xdr",
            "forward",
            "xdr-batch-num-retry",
            "xdr-batch-retry-sleep",
            "xdr-check-data-before-delete",
            "xdr-compression-threshold",
            "xdr-digestlog-size",
            "xdr-forward-with-gencheck",
            "xdr-hotkey-maxskip",
            "xdr-info-timeout",
            "xdr-local-port",
            "xdr-max-recs-inflight",
            "xdr-namedpipe-path",
            "xdr-nw-timeout",
            "xdr-read-mode",
            "xdr-read-threads",
            "xdr-ship-delay",
            "xdr-shipping-enabled",
            "xdr-timeout",
            "xdr-write-batch-size",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
        ) = test_util.parse_output(TestShowConfig.xdr_config)
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertTrue(set(exp_params).issubset(set(actual_data)))


class TestShowLatenciesDefault(unittest.TestCase):
    output_list = list()

    @classmethod
    def setUpClass(cls):
        TestShowLatenciesDefault.rc = controller.LiveClusterRootController(
            user="admin", password="admin"
        )
        actual_out = util.capture_stdout(
            TestShowLatenciesDefault.rc.execute, ["show", "latencies", "-v"]
        )
        TestShowLatenciesDefault.output_list = test_util.get_separate_output(actual_out)

    @classmethod
    def tearDownClass(cls):
        cls.rc = None

    def test_latencies(self):
        """
        Asserts <b> read latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">8ms",
            ">64ms",
        ]
        exp_data = [
            ("bar", "test"),
            (
                "read",
                "read-dup-res",
                "read-local",
                "read-repl-ping",
                "read-response",
                "read-restart",
                "read-start",
                "write",
                "write-dup-res",
                "write-master",
                "write-repl-write",
                "write-response",
                "write-restart",
                "write-start",
            ),
        ]
        exp_data_types = [str, str, str, float, float, float, float]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            actual_no_of_rows,
        ) = test_util.parse_output(
            TestShowLatenciesDefault.output_list[0], horizontal=True, header_len=1
        )
        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(
            test_util.check_for_types(actual_data, exp_data_types),
            "%s returned the wrong data types" % exp_heading,
        )

        for data in actual_data:
            self.assertTrue(test_util.check_for_subset(data, exp_data))


class TestShowLatenciesWithArguments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        TestShowLatenciesWithArguments.rc = controller.LiveClusterRootController(
            user="admin", password="admin"
        )

    def test_latencies_e_1_b_17(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 1 -b 17 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">2ms",
            ">4ms",
            ">8ms",
            ">16ms",
            ">32ms",
            ">64ms",
            ">128ms",
            ">256ms",
            ">512ms",
            ">1024ms",
            ">2048ms",
            ">4096ms",
            ">8192ms",
            ">16384ms",
            ">32768ms",
            ">65536ms",
        ]
        exp_data_types = [
            str,
            str,
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
            float,
        ]

        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute,
            ["show", "latencies", "-e", "1", "-b", "17"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output, horizontal=True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    def test_latencies_e_1_b_18(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 1 -b 18 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">2ms",
            ">4ms",
            ">8ms",
            ">16ms",
            ">32ms",
            ">64ms",
            ">128ms",
            ">256ms",
            ">512ms",
            ">1024ms",
            ">2048ms",
            ">4096ms",
            ">8192ms",
            ">16384ms",
            ">32768ms",
            ">65536ms",
        ]
        exp_data_types = [
            str,
            str,
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
            float,
        ]

        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute,
            ["show", "latencies", "-e", "1", "-b", "18"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output, horizontal=True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    def test_latencies_e_0_b_17(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 0 -b 17 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">2ms",
            ">4ms",
            ">8ms",
            ">16ms",
            ">32ms",
            ">64ms",
            ">128ms",
            ">256ms",
            ">512ms",
            ">1024ms",
            ">2048ms",
            ">4096ms",
            ">8192ms",
            ">16384ms",
            ">32768ms",
            ">65536ms",
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
            float,
        ]

        exp_no_of_rows = len(TestShowLatenciesWithArguments.rc.cluster._live_nodes)
        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute,
            ["show", "latencies", "-e", "0", "-b", "17"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output, horizontal=True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )
            self.assertEqual(exp_no_of_rows, int(actual_no_of_rows.strip()))

    def test_latencies_e_17_b_1(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 17 -b 1 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = ["Namespace", "Histogram", "Node", "ops/sec", ">1ms"]
        exp_data_types = [str, str, str, float, float]

        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute,
            ["show", "latencies", "-e", "17", "-b", "1"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output, horizontal=True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    def test_latencies_e_100_b_200(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 100 -b 200 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = ["Namespace", "Histogram", "Node", "ops/sec", ">1ms"]
        exp_data_types = [
            str,
            str,
            str,
            float,
            float,
        ]

        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute,
            ["show", "latencies", "-e", "100", "-b", "200"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output, horizontal=True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    def test_latencies_e_16_b_2(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 16 -b 2 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = ["Namespace", "Histogram", "Node", "ops/sec", ">1ms", ">65536ms"]
        exp_data_types = [str, str, str, float, float, float]

        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute,
            ["show", "latencies", "-e", "16", "-b", "2"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output, horizontal=True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    def test_latencies_e_4_b_7(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 4 -b 7 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">16ms",
            ">256ms",
            ">4096ms",
            ">65536ms",
        ]
        exp_data_types = [str, str, str, float, float, float, float, float, float]

        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute,
            ["show", "latencies", "-e", "4", "-b", "7"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output, horizontal=True, header_len=1)
            self.assertListEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    def test_latencies_group_by_machine_name(self):
        """
        Asserts <b> show latencies <b> with a -m argument which groups tables by machine name
        """
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">8ms",
            ">64ms",
        ]
        exp_data_types = [str, str, str, float, float, float, float]

        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute, ["show", "latencies", "-m"]
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                _,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    def test_latencies_group_by_machine_name_e_2_8(self):
        """
        Asserts <b> show latencies <b> with a -m argument which groups tables by machine name
        """
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">4ms",
            ">16ms",
            ">64ms",
            ">256ms",
            ">1024ms",
            ">4096ms",
            ">16384ms",
        ]
        exp_data_types = [
            str,
            str,
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
        ]

        actual_out = util.capture_stdout(
            TestShowLatenciesWithArguments.rc.execute,
            ["show", "latencies", "-m", "-e", "2", "-b", "8"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                _,
            ) = test_util.parse_output(output, horizontal=True, header_len=1)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )


class TestShowDistribution(unittest.TestCase):
    output_list = list()
    test_ttl_distri = ""
    bar_ttl_distri = ""

    @classmethod
    def setUpClass(cls):
        rc = controller.LiveClusterRootController(user="admin", password="admin")
        actual_out = util.capture_stdout(rc.execute, ["show", "distribution"])
        # use regex in get_separate_output(~.+Distribution.*~.+)
        # if you are changing below Distribution keyword
        TestShowDistribution.output_list = test_util.get_separate_output(actual_out)
        TestShowDistribution.is_bar_present = False
        for item in TestShowDistribution.output_list:
            title = item["title"]
            if "test - TTL Distribution in Seconds" in title:
                TestShowDistribution.test_ttl_distri = item
            elif "bar - TTL Distribution in Seconds" in title:
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
        exp_heading = "test - TTL Distribution in Seconds"
        exp_description = """Percentage of records having ttl less than or equal to value measured in Seconds"""

        exp_header = [
            "Node",
            "10%",
            "20%",
            "30%",
            "40%",
            "50%",
            "60%",
            "70%",
            "80%",
            "90%",
            "100%",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(
            TestShowDistribution.test_ttl_distri, horizontal=True, merge_header=False
        )

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_description, actual_description)
        self.assertListEqual(exp_header, actual_header)

    def test_bar_ttl(self):
        """
        Asserts TTL Distribution in Seconds for bar namespace with heading, header & parameters.
        TODO: test for values as well
        """
        if not TestShowDistribution.is_bar_present:
            return
        exp_heading = "bar - TTL Distribution in Seconds"
        exp_description = """Percentage of records having ttl less than or equal to value measured in Seconds"""
        exp_header = [
            "Node",
            "10%",
            "20%",
            "30%",
            "40%",
            "50%",
            "60%",
            "70%",
            "80%",
            "90%",
            "100%",
        ]
        exp_types = [str, int, int, int, int, int, int, int, int, int, int]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(
            TestShowDistribution.bar_ttl_distri, horizontal=True, merge_header=False
        )

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_description, actual_description)
        self.assertListEqual(exp_header, actual_header)
        self.assertTrue(test_util.check_for_types(actual_data, exp_types))


class TestShowStatistics(unittest.TestCase):
    output_list = list()
    test_bin_stats = ""
    bar_bin_stats = ""
    service_stats = ""
    bar_namespace_stats = ""
    test_namespace_stats = ""
    xdr_stats = ""

    @classmethod
    def setUpClass(cls):
        rc = controller.LiveClusterRootController(user="admin", password="admin")
        actual_out = util.capture_stdout(rc.execute, ["show", "statistics"])
        actual_out += util.capture_stdout(rc.execute, ["show", "statistics", "xdr"])
        TestShowStatistics.output_list = test_util.get_separate_output(actual_out)
        TestShowStatistics.is_bar_present = False

        for item in TestShowStatistics.output_list:
            title = item["title"]
            if "test Bin Statistics" in title:
                TestShowStatistics.test_bin_stats = item
            elif "bar Bin Statistics" in title:
                TestShowStatistics.bar_bin_stats = item
                TestShowStatistics.is_bar_present = True
            elif "Service Statistics" in title:
                TestShowStatistics.service_stats = item
            elif "bar Namespace Statistics" in title:
                TestShowStatistics.bar_namespace_stats = item
                TestShowStatistics.is_bar_present = True
            elif "test Namespace Statistics" in title:
                TestShowStatistics.test_namespace_stats = item
            elif "XDR Statistics" in title:
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
        exp_heading = "test Bin Statistics"
        exp_header = [
            ("Node"),
            ("bin-names-quota", "bin_names_quota"),
            ("num-bin-names", "bin_names"),
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowStatistics.test_bin_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(test_util.check_for_subset(actual_header, exp_header))

    def test_bar_bin(self):
        """
        This test will assert <b> bar Bin Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        if not TestShowStatistics.is_bar_present:
            return
        exp_heading = "bar Bin Statistics"
        exp_header = [
            ("Node"),
            ("bin-names-quota", "bin_names_quota"),
            ("num-bin-names", "bin_names"),
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowStatistics.bar_bin_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(test_util.check_for_subset(actual_header, exp_header))

    def test_service(self):
        """
        This test will assert <b> Service Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        exp_heading = "Service Statistics"

        # TODO: Add possibly missing params.  This is only verified as a subset
        exp_header = [
            "Node",
            "client_connections",
            "cluster_integrity",
            "cluster_key",
            "cluster_size",
            "heartbeat_received_foreign",
            "heartbeat_received_self",
            "info_queue",
            "objects",
            "paxos_principal",
            "proxy_in_progress",
            "query_long_running",
            "query_short_running",
            "reaped_fds",
            "sindex_gc_garbage_cleaned",
            "sindex_gc_garbage_found",
            "sindex_gc_list_creation_time",
            "sindex_gc_list_deletion_time",
            "sindex_gc_objects_validated",
            "sindex_ucgarbage_found",
            "uptime",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowStatistics.service_stats)
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(test_util.check_for_subset(actual_header, exp_header))

    def test_bar_namespace(self):
        """
        This test will assert <b> bar Namespace Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        if not TestShowStatistics.is_bar_present:
            return
        exp_heading = "bar Namespace Statistics"

        # TODO: Add possibly missing params.  This is only verified as a subset
        exp_header = [
            "Node",
            "reject-non-xdr-writes",
            "reject-xdr-writes",
            "available_bin_names",
            "conflict-resolution-policy",
            "current_time",
            "memory_used_data_bytes",
            "default-ttl",
            "disallow-null-setname",
            "evict-tenths-pct",
            "evicted_objects",
            "expired_objects",
            "memory_free_pct",
            "high-water-disk-pct",
            "high-water-memory-pct",
            "hwm_breached",
            "memory_used_index_bytes",
            "master_objects",
            "memory-size",
            "non_expirable_objects",
            "nsup_cycle_duration",
            "objects",
            "prole_objects",
            "read-consistency-level-override",
            "replication-factor",
            "memory_used_sindex_bytes",
            "single-bin",
            "stop_writes",
            "stop-writes-pct",
            "memory_used_bytes",
            "write-commit-level-override",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowStatistics.bar_namespace_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(test_util.check_for_subset(actual_header, exp_header))

    def test_test_namespace(self):
        """
        This test will assert <b> test Namespace Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        exp_heading = "test Namespace Statistics"

        # TODO: Add possibly missing params.  This is only verified as a subset
        exp_header = [
            "Node",
            "allow-ttl-without-nsup",
            "appeals_records_exonerated",
            "appeals_rx_active",
            "appeals_tx_active",
            "appeals_tx_remaining",
            "available_bin_names",
            "background-scan-max-rps",
            "batch_sub_proxy_complete",
            "batch_sub_proxy_error",
            "batch_sub_proxy_timeout",
            "batch_sub_read_error",
            "batch_sub_read_filtered_out",
            "batch_sub_read_not_found",
            "batch_sub_read_success",
            "batch_sub_read_timeout",
            "batch_sub_tsvc_error",
            "batch_sub_tsvc_timeout",
            "cache_read_pct",
            "client_delete_error",
            "client_delete_filtered_out",
            "client_delete_not_found",
            "client_delete_success",
            "client_delete_timeout",
            "client_lang_delete_success",
            "client_lang_error",
            "client_lang_read_success",
            "client_lang_write_success",
            "client_proxy_complete",
            "client_proxy_error",
            "client_proxy_timeout",
            "client_read_error",
            "client_read_filtered_out",
            "client_read_not_found",
            "client_read_success",
            "client_read_timeout",
            "client_tsvc_error",
            "client_tsvc_timeout",
            "client_udf_complete",
            "client_udf_error",
            "client_udf_filtered_out",
            "client_udf_timeout",
            "client_write_error",
            "client_write_filtered_out",
            "client_write_success",
            "client_write_timeout",
            "clock_skew_stop_writes",
            "conflict-resolution-policy",
            "current_time",
            "data-in-index",
            "dead_partitions",
            "default-ttl",
            "deleted_last_bin",
            "device_available_pct",
            "device_compression_ratio",
            "device_free_pct",
            "device_total_bytes",
            "device_used_bytes",
            "disable-cold-start-eviction",
            "disable-write-dup-res",
            "disallow-null-setname",
            "effective_is_quiesced",
            "effective_prefer_uniform_balance",
            "effective_replication_factor",
            "enable-benchmarks-batch-sub",
            "enable-benchmarks-ops-sub",
            "enable-benchmarks-read",
            "enable-benchmarks-udf",
            "enable-benchmarks-udf-sub",
            "enable-benchmarks-write",
            "enable-hist-proxy",
            "evict-hist-buckets",
            "evict-tenths-pct",
            "evict_ttl",
            "evict_void_time",
            "evicted_objects",
            "expired_objects",
            "fail_generation",
            "fail_key_busy",
            "fail_record_too_big",
            "fail_xdr_forbidden",
            "from_proxy_batch_sub_read_error",
            "from_proxy_batch_sub_read_filtered_out",
            "from_proxy_batch_sub_read_not_found",
            "from_proxy_batch_sub_read_success",
            "from_proxy_batch_sub_read_timeout",
            "from_proxy_batch_sub_tsvc_error",
            "from_proxy_batch_sub_tsvc_timeout",
            "from_proxy_delete_error",
            "from_proxy_delete_filtered_out",
            "from_proxy_delete_not_found",
            "from_proxy_delete_success",
            "from_proxy_delete_timeout",
            "from_proxy_lang_delete_success",
            "from_proxy_lang_error",
            "from_proxy_lang_read_success",
            "from_proxy_lang_write_success",
            "from_proxy_read_error",
            "from_proxy_read_filtered_out",
            "from_proxy_read_not_found",
            "from_proxy_read_success",
            "from_proxy_read_timeout",
            "from_proxy_tsvc_error",
            "from_proxy_tsvc_timeout",
            "from_proxy_udf_complete",
            "from_proxy_udf_error",
            "from_proxy_udf_filtered_out",
            "from_proxy_udf_timeout",
            "from_proxy_write_error",
            "from_proxy_write_filtered_out",
            "from_proxy_write_success",
            "from_proxy_write_timeout",
            "geo2dsphere-within.earth-radius-meters",
            "geo2dsphere-within.level-mod",
            "geo2dsphere-within.max-cells",
            "geo2dsphere-within.max-level",
            "geo2dsphere-within.min-level",
            "geo2dsphere-within.strict",
            "geo_region_query_cells",
            "geo_region_query_falsepos",
            "geo_region_query_points",
            "geo_region_query_reqs",
            "high-water-disk-pct",
            "high-water-memory-pct",
            "hwm_breached",
            "ignore-migrate-fill-delay",
            "index-stage-size",
            "index-type",
            "master_objects",
            "master_tombstones",
            "memory-size",
            "memory_free_pct",
            "memory_used_bytes",
            "memory_used_data_bytes",
            "memory_used_index_bytes",
            "memory_used_sindex_bytes",
            "migrate-order",
            "migrate-retransmit-ms",
            "migrate-sleep",
            "migrate_record_receives",
            "migrate_record_retransmits",
            "migrate_records_skipped",
            "migrate_records_transmitted",
            "migrate_rx_instances",
            "migrate_rx_partitions_active",
            "migrate_rx_partitions_initial",
            "migrate_rx_partitions_remaining",
            "migrate_signals_active",
            "migrate_signals_remaining",
            "migrate_tx_instances",
            "migrate_tx_partitions_active",
            "migrate_tx_partitions_imbalance",
            "migrate_tx_partitions_initial",
            "migrate_tx_partitions_lead_remaining",
            "migrate_tx_partitions_remaining",
            "nodes_quiesced",
            "non_expirable_objects",
            "non_replica_objects",
            "non_replica_tombstones",
            "ns_cluster_size",
            "nsup-hist-period",
            "nsup-period",
            "nsup-threads",
            "nsup_cycle_duration",
            "objects",
            "ops_sub_tsvc_error",
            "ops_sub_tsvc_timeout",
            "ops_sub_write_error",
            "ops_sub_write_filtered_out",
            "ops_sub_write_success",
            "ops_sub_write_timeout",
            "partition-tree-sprigs",
            "pending_quiesce",
            "prefer-uniform-balance",
            "prole_objects",
            "prole_tombstones",
            "query_agg",
            "query_agg_abort",
            "query_agg_avg_rec_count",
            "query_agg_error",
            "query_agg_success",
            "query_fail",
            "query_long_queue_full",
            "query_long_reqs",
            "query_lookup_abort",
            "query_lookup_avg_rec_count",
            "query_lookup_error",
            "query_lookup_success",
            "query_lookups",
            "query_ops_bg_failure",
            "query_ops_bg_success",
            "query_proto_compression_ratio",
            "query_proto_uncompressed_pct",
            "query_reqs",
            "query_short_queue_full",
            "query_short_reqs",
            "query_udf_bg_failure",
            "query_udf_bg_success",
            "rack-id",
            "re_repl_error",
            "re_repl_success",
            "re_repl_timeout",
            "read-consistency-level-override",
            "record_proto_compression_ratio",
            "record_proto_uncompressed_pct",
            "reject-non-xdr-writes",
            "reject-xdr-writes",
            "replication-factor",
            "retransmit_all_batch_sub_dup_res",
            "retransmit_all_delete_dup_res",
            "retransmit_all_delete_repl_write",
            "retransmit_all_read_dup_res",
            "retransmit_all_udf_dup_res",
            "retransmit_all_udf_repl_write",
            "retransmit_all_write_dup_res",
            "retransmit_all_write_repl_write",
            "retransmit_ops_sub_dup_res",
            "retransmit_ops_sub_repl_write",
            "retransmit_udf_sub_dup_res",
            "retransmit_udf_sub_repl_write",
            "scan_aggr_abort",
            "scan_aggr_complete",
            "scan_aggr_error",
            "scan_basic_abort",
            "scan_basic_complete",
            "scan_basic_error",
            "scan_ops_bg_abort",
            "scan_ops_bg_complete",
            "scan_ops_bg_error",
            "scan_proto_compression_ratio",
            "scan_proto_uncompressed_pct",
            "scan_udf_bg_abort",
            "scan_udf_bg_complete",
            "scan_udf_bg_error",
            "sindex.num-partitions",
            "single-bin",
            "single-scan-threads",
            "smd_evict_void_time",
            "stop-writes-pct",
            "stop_writes",
            "storage-engine",
            "strong-consistency",
            "strong-consistency-allow-expunge",
            "tomb-raider-eligible-age",
            "tomb-raider-period",
            "tombstones",
            "transaction-pending-limit",
            "truncate-threads",
            "truncate_lut",
            "truncated_records",
            "udf_sub_lang_delete_success",
            "udf_sub_lang_error",
            "udf_sub_lang_read_success",
            "udf_sub_lang_write_success",
            "udf_sub_tsvc_error",
            "udf_sub_tsvc_timeout",
            "udf_sub_udf_complete",
            "udf_sub_udf_error",
            "udf_sub_udf_filtered_out",
            "udf_sub_udf_timeout",
            "unavailable_partitions",
            "write-commit-level-override",
            "xdr-bin-tombstone-ttl",
            "xdr-tomb-raider-period",
            "xdr-tomb-raider-threads",
            "xdr_client_delete_error",
            "xdr_client_delete_not_found",
            "xdr_client_delete_success",
            "xdr_client_delete_timeout",
            "xdr_client_write_error",
            "xdr_client_write_success",
            "xdr_client_write_timeout",
            "xdr_from_proxy_delete_error",
            "xdr_from_proxy_delete_not_found",
            "xdr_from_proxy_delete_success",
            "xdr_from_proxy_delete_timeout",
            "xdr_from_proxy_write_error",
            "xdr_from_proxy_write_success",
            "xdr_from_proxy_write_timeout",
            "xdr_tombstones",
            "xmem_id",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowStatistics.test_namespace_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(test_util.check_for_subset(actual_header, exp_header))

    # @unittest.skip("Will enable only when xdr is configuired")
    def test_xdr(self):
        """
        This test will assert <b> xdr Statistics </b> output for heading, header and parameters.
        TODO: test for values as well
        """
        exp_heading = "XDR Statistics"

        # 5.0+
        exp_header = [
            "Node",
            "abandoned",
            "compression_ratio",
            "filtered_out",
            "hot_keys",
            "in_progress",
            "in_queue",
            "lag",
            "lap_us",
            "latency_ms",
            "nodes",
            "not_found",
            "recoveries",
            "recoveries_pending",
            "retry_conn_reset",
            "retry_dest",
            "retry_no_node",
            "success",
            "throughput",
            "uncompressed_pct",
        ]
        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(TestShowStatistics.xdr_stats)

        self.assertTrue(exp_heading in actual_heading)
        self.assertListEqual(exp_header, actual_header)
        # self.assertTrue(test_util.check_for_subset(actual_data, exp_header))


def capture_separate_and_parse_output(rc, commands):
    actual_stdout = util.capture_stdout(rc.execute, commands)
    separated_stdout = test_util.get_separate_output(actual_stdout)
    result = test_util.parse_output(separated_stdout[0])

    return result


def get_data(exp_first, data):
    found_values = None

    for values in data:
        if len(data) and values.pop(0) == exp_first:
            found_values = values
            break

    return found_values


class TestShowUsers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rc = controller.LiveClusterRootController(user="admin", password="admin")
        util.capture_stdout(cls.rc.execute, ["enable"])

    @classmethod
    def tearDownClass(cls):
        cls.rc = None

    @classmethod
    def setUp(cls):
        # Added since tests were failing.  I assume because the server response
        # comes before the request is commited to SMD or security layer.
        time.sleep(0.25)
        util.capture_stdout_and_stderr(
            cls.rc.execute, ["manage", "acl", "delete", "user", "foo"]
        )

    def test_show_users(self):
        exp_title = "Users"
        exp_header = ["User", "Roles"]

        actual_title, _, actual_header, _, _ = capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    def test_create_user_with_no_roles(self):
        exp_user = "foo"
        exp_roles = ["--"]
        exp_title = "Users"
        exp_header = ["User", "Roles"]

        _, _, _, _, num_records = capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        exp_num_rows = num_records + 1

        util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "create", "user", exp_user, "password", "bar"],
        )

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = capture_separate_and_parse_output(self.rc, ["show", "users"])

        actual_roles = get_data(exp_user, actual_data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertListEqual(exp_roles, actual_roles)

    def test_create_user_with_roles(self):
        exp_user = "foo"
        exp_roles = ["sys-admin", "user-admin"]
        exp_title = "Users"
        exp_header = ["User", "Roles"]

        _, _, _, _, num_records = capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        exp_num_rows = num_records + 1

        time.sleep(0.5)
        util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "user",
                exp_user,
                "password",
                "bar",
                "roles",
                *exp_roles,
            ],
        )
        time.sleep(2)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = capture_separate_and_parse_output(self.rc, ["show", "users"])

        actual_roles = get_data(exp_user, actual_data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertListEqual([", ".join(exp_roles)], actual_roles)

    def test_delete_a_user(self):
        exp_user = "foo"
        exp_roles = ["sys-admin", "user-admin"]
        exp_title = "Users"
        exp_header = ["User", "Roles"]

        _, _, _, _, num_records = capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "user",
                exp_user,
                "password",
                "bar",
                "roles",
                *exp_roles,
            ],
        )

        _, _, _, _, num_records = capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        exp_num_rows = num_records - 1

        util.capture_stdout(
            self.rc.execute, ["manage", "acl", "delete", "user", exp_user]
        )

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = capture_separate_and_parse_output(self.rc, ["show", "users"])

        for data in actual_data:
            self.assertNotIn(exp_user, data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    def test_revoke_user_role(self):
        exp_user = "foo"
        exp_roles = ["sys-admin", "user-admin"]
        exp_title = "Users"
        exp_header = ["User", "Roles"]

        util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "user",
                exp_user,
                "password",
                "bar",
                "roles",
                *exp_roles,
                "to-remove",
            ],
        )
        time.sleep(0.25)
        util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "revoke", "user", exp_user, "roles", "to-remove"],
        )
        time.sleep(0.25)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            _,
        ) = capture_separate_and_parse_output(self.rc, ["show", "users"])

        actual_roles = get_data(exp_user, actual_data)

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(", ".join(exp_roles), actual_roles[0])


class TestShowRoles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rc = controller.LiveClusterRootController(user="admin", password="admin")
        util.capture_stdout(cls.rc.execute, ["enable"])
        util.capture_stdout_and_stderr(
            cls.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "role",
                "temp",
                "priv",
                "sys-admin",
                "allow",
                "1.1.1.1",
            ],
        )

    @classmethod
    def tearDownClass(cls):
        util.capture_stdout_and_stderr(
            cls.rc.execute, ["manage", "acl", "delete", "role", "foo"]
        )
        util.capture_stdout_and_stderr(
            cls.rc.execute, ["manage", "acl", "delete", "role", "temp"]
        )
        cls.rc = None

    @classmethod
    def setUp(cls):
        # Added since tests were failing.  I assume because the server response
        # comes before the request is commited to SMD or security layer.
        time.sleep(0.25)
        util.capture_stdout_and_stderr(
            cls.rc.execute, ["manage", "acl", "delete", "role", "foo"]
        )
        time.sleep(0.25)

    def test_show_roles(self):
        exp_title = "Roles"
        exp_header = [
            "Role",
            "Privileges",
            "Allowlist",
        ]

        actual_title, _, actual_header, _, _ = capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    def test_create_role_with_privileges(self):
        exp_role = "foo"
        exp_privilege = "sys-admin"
        exp_allowlist = ["--"]
        exp_data = [exp_privilege, ", ".join(exp_allowlist)]
        exp_title = "Roles"
        exp_header = ["Role", "Privileges", "Allowlist"]

        _, _, _, _, num_records = capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        exp_num_rows = num_records + 1

        util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "create", "role", exp_role, "priv", exp_privilege],
        )
        time.sleep(0.5)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = capture_separate_and_parse_output(self.rc, ["show", "roles"])

        actual_data = get_data(exp_role, actual_data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertListEqual(exp_data, actual_data)

    def test_create_role_with_allowlist(self):
        exp_role = "foo"
        exp_privileges = "write"
        exp_allowlist = ["1.1.1.1", "2.2.2.2"]
        exp_data = [exp_privileges, ", ".join(exp_allowlist)]
        exp_title = "Roles"
        exp_header = ["Role", "Privileges", "Allowlist"]

        _, _, _, _, num_records = capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        exp_num_rows = num_records + 1

        util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "role",
                exp_role,
                "priv",
                "write",
                "allow",
                *exp_allowlist,
            ],
        )
        time.sleep(0.25)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = capture_separate_and_parse_output(self.rc, ["show", "roles"])

        actual_data = get_data(exp_role, actual_data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertListEqual(exp_data, actual_data)

    def test_delete_a_role(self):
        exp_role = "foo"
        exp_privilege = "sys-admin"
        exp_title = "Roles"
        exp_header = ["Role", "Privileges", "Allowlist"]

        _, _, _, _, num_records = capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "create", "role", exp_role, "priv", exp_privilege],
        )
        time.sleep(0.25)

        _, _, _, _, num_records = capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        exp_num_rows = num_records - 1

        util.capture_stdout(
            self.rc.execute, ["manage", "acl", "delete", "role", exp_role]
        )
        time.sleep(0.25)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = capture_separate_and_parse_output(self.rc, ["show", "roles"])

        for data in actual_data:
            self.assertNotIn(exp_role, data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    def test_revoke_role(self):
        exp_role = "foo"
        exp_privilege = "read"
        exp_title = "Roles"
        exp_header = ["Role", "Privileges", "Allowlist"]

        util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "create", "role", exp_role, "priv", exp_privilege],
        )
        util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "grant", "role", exp_role, "priv", "write"],
        )
        time.sleep(0.5)
        util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "revoke", "role", exp_role, "priv", "write"],
        )
        time.sleep(0.5)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            _,
        ) = capture_separate_and_parse_output(self.rc, ["show", "roles"])

        actual_privileges = get_data(exp_role, actual_data)

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(exp_privilege, actual_privileges[0])


class TestShowUdfs(unittest.TestCase):
    exp_module = "test__.lua"
    path = "test/e2e/test.lua"

    @classmethod
    def setUpClass(cls):
        cls.rc = controller.LiveClusterRootController(user="admin", password="admin")
        util.capture_stdout(cls.rc.execute, ["enable"])
        util.capture_stdout_and_stderr(
            cls.rc.execute, ["manage", "udfs", "add", "filler_.lua", "path", cls.path]
        )

    @classmethod
    def tearDownClass(cls):
        util.capture_stdout_and_stderr(
            cls.rc.execute, ["manage", "udfs", "remove", cls.exp_module]
        )
        util.capture_stdout_and_stderr(
            cls.rc.execute, ["manage", "udfs", "remove", "filler_.lua"]
        )
        cls.rc = None

    @classmethod
    def setUp(cls):
        util.capture_stdout_and_stderr(
            cls.rc.execute, ["manage", "udfs", "remove", cls.exp_module]
        )

    def test_show_udfs(self):
        exp_title = "UDF Modules"
        exp_header = ["Filename", "Hash", "Type"]

        actual_title, _, actual_header, _, _ = capture_separate_and_parse_output(
            self.rc, ["show", "udfs"]
        )

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    def test_add_udf(self):
        exp_title = "UDF Modules"
        exp_header = ["Filename", "Hash", "Type"]
        exp_module = ["61e9c132a6a4c1a14852dc1641a35b420664c4a1", "LUA"]

        _, _, _, _, num_rows = capture_separate_and_parse_output(
            self.rc, ["show", "udfs"]
        )

        exp_num_rows = num_rows + 1

        util.capture_stdout(
            self.rc.execute,
            ["manage", "udfs", "add", self.exp_module, "path", self.path],
        )

        time.sleep(1)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_rows,
        ) = capture_separate_and_parse_output(self.rc, ["show", "udfs"])

        actual_module = get_data(self.exp_module, actual_data)

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(exp_num_rows, actual_num_rows)
        self.assertListEqual(exp_module, actual_module)

    def test_remove_udf(self):
        exp_title = "UDF Modules"
        exp_header = ["Filename", "Hash", "Type"]

        util.capture_stdout(
            self.rc.execute,
            ["manage", "udfs", "add", self.exp_module, "path", self.path],
        )
        time.sleep(0.50)
        _, _, _, _, num_rows = capture_separate_and_parse_output(
            self.rc, ["show", "udfs"]
        )

        exp_num_rows = num_rows - 1

        util.capture_stdout(
            self.rc.execute, ["manage", "udfs", "remove", self.exp_module]
        )
        time.sleep(0.50)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_rows,
        ) = capture_separate_and_parse_output(self.rc, ["show", "udfs"])

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(exp_num_rows, actual_num_rows)


if __name__ == "__main__":
    unittest.main()
