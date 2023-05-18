# Copyright 2021-2023 Aerospike, Inc.
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

from unittest.mock import call
from test.unit import util
from lib.live_cluster.client.config_handler import (
    BoolConfigType,
    EnumConfigType,
    IntConfigType,
    JsonDynamicConfigHandler,
    StringConfigType,
    configTypeFactory,
)
import unittest
from mock import patch


class IntConfigTypeTest(unittest.TestCase):
    def test_validate(self):
        config_type = IntConfigType(0, 0, True)

        input_output = [(0, True), (1, False), (-1, False)]

        for input, output in input_output:
            self.assertEqual(config_type.validate(input), output)

        config_type = IntConfigType(-500, 3000, True)

        input_output = [
            (10, True),
            (-55, True),
            (-500, True),
            (3000, True),
            (-501, False),
            (-3001, False),
        ]

        for input, output in input_output:
            self.assertEqual(config_type.validate(input), output)

    def test_eq(self):
        config_type = IntConfigType(0, 0, True)

        self.assertTrue(config_type == IntConfigType(0, 0, True))
        self.assertFalse(config_type == IntConfigType(1, 0, True))
        self.assertFalse(config_type == IntConfigType(0, -1, True))
        self.assertFalse(config_type == IntConfigType(0, 0, False))
        self.assertFalse(config_type == IntConfigType(0, 0, True, "default"))


class StringConfigTypeTest(unittest.TestCase):
    def test_validate(self):
        config_type = StringConfigType(
            r"^(?:(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])(\.(?!$)|$)){4}$",
            True,
            "default",
        )

        input_output = [
            ("192.1.1.1", True),
            ("192.168.4.255", True),
            ("1.254.1.254", True),
            ("0.1.0.1", True),
            ("1.254.1.01", False),
            ("1.1.256.0", False),
            ("1.500.255.1", False),
        ]

        for input, output in input_output:
            self.assertEqual(
                config_type.validate(input),
                output,
                "Incorrect result for input {} and output {}".format(input, output),
            )

        config_type = IntConfigType(-500, 3000, True)

        input_output = [
            (10, True),
            (-55, True),
            (-500, True),
            (3000, True),
            (-501, False),
            (-3001, False),
        ]

        for input, output in input_output:
            self.assertEqual(
                config_type.validate(input),
                output,
                "Incorrect result for input {} and output {}".format(input, output),
            )

    def test_eq(self):
        config_type = StringConfigType(r"abcd*", True, "default")

        self.assertTrue(config_type == StringConfigType(r"abcd*", True, "default"))
        self.assertFalse(config_type == StringConfigType(r"abc*", True, "default"))
        self.assertFalse(config_type == StringConfigType(r"abcd*", False, "default"))
        self.assertFalse(
            config_type == StringConfigType(r"abcd*", True, "not-=default")
        )


class EnumConfigTypeTest(unittest.TestCase):
    def test_validate(self):
        config_type = EnumConfigType([], True)

        input_output = [("foo", False), ("bar", False), ("blah", False)]

        for input, output in input_output:
            self.assertEqual(config_type.validate(input), output)

        config_type = EnumConfigType(["a", "big", "fat", "cat", "sat"], True)

        input_output = [
            ("a", True),
            ("fat", True),
            ("cat", True),
            ("foo", False),
            ("bar", False),
            ("char", False),
        ]

        for input, output in input_output:
            self.assertEqual(config_type.validate(input), output)

    def test_eq(self):
        config_type = EnumConfigType(["sat", "cat", "fat", "big", "a"], True)

        self.assertTrue(
            config_type == EnumConfigType(["a", "big", "fat", "cat", "sat"], True)
        )
        self.assertTrue(
            config_type == EnumConfigType(["sat", "cat", "fat", "big", "a"], True)
        )
        self.assertFalse(
            config_type == EnumConfigType(["big", "fat", "cat", "sat"], True)
        )
        self.assertFalse(config_type == EnumConfigType([], True))
        self.assertFalse(
            config_type == EnumConfigType(["sat", "cat", "fat", "big", "a"], False)
        )
        self.assertFalse(
            config_type
            == EnumConfigType(["sat", "cat", "fat", "big", "a"], True, "default")
        )


class BoolConfigTypeTest(unittest.TestCase):
    def test_validate(self):
        config_type = BoolConfigType(True)

        input_output = [
            ("true", True),
            ("false", True),
            ("TRUE", True),
            ("FALSE", True),
            (-1, False),
            ("foo", False),
        ]

        for input, output in input_output:
            self.assertEqual(config_type.validate(input), output)

    def test_eq(self):
        config_type = BoolConfigType(True)

        self.assertTrue(config_type == BoolConfigType(True))
        self.assertFalse(config_type == BoolConfigType(False))
        self.assertFalse(config_type == BoolConfigType(False, "default"))


class ConfigTypeFactoryTest(unittest.TestCase):
    def test_creates_int(self):
        input = {
            "type": "integer",
            "default": 2,
            "minimum": 0,
            "maximum": 2147483647,
            "description": "",
            "dynamic": True,
        }
        expected = IntConfigType(0, 2147483647, True, 2)

        actual = configTypeFactory(input)

        self.assertEqual(expected, actual)

    def test_creates_string(self):
        input = {
            "type": "string",
            "default": "blah blah",
            "description": "",
            "dynamic": False,
        }
        expected = StringConfigType(None, False, "blah blah")

        actual = configTypeFactory(input)

        self.assertEqual(expected, actual)

    def test_creates_enum(self):
        input = {
            "type": "string",
            "default": "cat",
            "description": "",
            "enum": ["foo", "bar", "cat"],
            "dynamic": False,
        }
        expected = EnumConfigType(["foo", "bar", "cat"], False, "cat")

        actual = configTypeFactory(input)

        self.assertEqual(expected, actual)

    def test_creates_bool(self):
        input = {
            "type": "boolean",
            "default": False,
            "description": "",
            "dynamic": False,
        }
        expected = BoolConfigType(False, False)

        actual = configTypeFactory(input)

        self.assertEqual(expected, actual)

    def test_raise_error_for_unsupported_type(self):
        input = {
            "type": "array",
            "default": [],
            "description": "",
            "dynamic": False,
        }

        util.assert_exception(self, ValueError, None, configTypeFactory, input)

        input = {
            "default": [],
            "description": "",
            "dynamic": False,
        }

        util.assert_exception(self, ValueError, None, configTypeFactory, input)


# Tests with server version 5.5.0 json
class JsonDynamicConfig55HandlerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.maxDiff = None
        cls.handler = JsonDynamicConfigHandler("config-schemas", "5.5.0")

    def pkgutil_side_effect(self, name, path):
        if path.endswith("schema_map.json"):
            return """
{
    "4.0.0": "4_0_0.json",
    "4.1.0": "4_1_0.json",
    "4.2.0": "4_2_0.json",
    "4.3.0": "4_3_0.json",
    "4.3.1": "4_3_1.json",
    "4.4.0": "4_4_0.json",
    "4.5.0": "4_5_0.json",
    "4.5.1": "4_5_1.json",
    "4.5.2": "4_5_2.json",
    "4.5.3": "4_5_3.json",
    "4.6.0": "4_6_0.json",
    "4.7.0": "4_7_0.json",
    "4.8.0": "4_8_0.json",
    "4.9.0": "4_9_0.json",
    "5.0.0": "5_0_0.json",
    "5.1.0": "5_1_0.json",
    "5.2.0": "5_2_0.json",
    "5.3.0": "5_3_0.json",
    "5.4.0": "5_4_0.json",
    "5.5.0": "5_5_0.json",
    "5.6.0": "5_6_0.json",
    "5.7.0": "5_7_0.json",
    "6.0.0": "6_0_0.json"
}
                """

        return None

    def test_loads_correct_file(self):
        isfile_mock = patch("os.path.isfile").start()
        isfile_mock.side_effect = lambda *arg: True
        pkgutil_mock = patch("pkgutil.get_data").start()
        pkgutil_mock.side_effect = self.pkgutil_side_effect

        JsonDynamicConfigHandler("dir", "0.0.0")
        pkgutil_mock.assert_has_calls(
            [
                call("lib.live_cluster.client.config_handler", "dir/schema_map.json"),
                call("lib.live_cluster.client.config_handler", "dir/4_0_0.json"),
            ]  # type: ignore
        )
        JsonDynamicConfigHandler("dir", "4.0.1")
        pkgutil_mock.assert_called_with(
            "lib.live_cluster.client.config_handler", "dir/4_0_0.json"
        )

        JsonDynamicConfigHandler("dir", "10.9.0.1")
        pkgutil_mock.assert_called_with(
            "lib.live_cluster.client.config_handler",
            "dir/6_0_0.json",
        )

        JsonDynamicConfigHandler("dir", "5.4.9")
        pkgutil_mock.assert_called_with(
            "lib.live_cluster.client.config_handler", "dir/5_4_0.json"
        )

        JsonDynamicConfigHandler("dir", "4.2.1")
        pkgutil_mock.assert_called_with(
            "lib.live_cluster.client.config_handler", "dir/4_2_0.json"
        )

        patch.stopall()

    def test_get_service_params(self):
        expected = [
            "advertise-ipv6",
            "downgrading",
            "cluster-name",
            "query-microbenchmark",
            "proto-fd-max",
            "proto-slow-netio-sleep-ms",
            "query-bufpool-size",
            "query-pre-reserve-partitions",
            "query-rec-count-bound",
            "query-req-in-query-thread",
            "query-buf-size",
            "microsecond-histograms",
            "min-cluster-size",
            "migrate-threads",
            "migrate-fill-delay",
            "enable-health-check",
            "migrate-max-num-incoming",
            "transaction-retry-ms",
            "transaction-max-ms",
            "query-in-transaction-thread",
            "query-priority-sleep-us",
            "query-priority",
            "query-threads",
            "query-worker-threads",
            "query-batch-size",
            "query-req-max-inflight",
            "query-long-q-max-size",
            "query-short-q-max-size",
            "query-threshold",
            "query-untracked-time-ms",
            "batch-max-requests",
            "batch-without-digests",
            "batch-index-threads",
            "batch-max-buffers-per-queue",
            "batch-max-unused-buffers",
            "info-threads",
            "proto-fd-idle-ms",
            "scan-max-done",
            "scan-threads-limit",
            "enable-benchmarks-fabric",
            "enable-hist-info",
            "ticker-interval",
            "service-threads",
            "sindex-builder-threads",
            "sindex-gc-period",
            "sindex-gc-max-rate",
        ]

        params = self.handler.get_params(["service"])
        # print(params)
        self.assertCountEqual(expected, params)

    def test_get_service_value(self):
        values = self.handler.get_types(
            ["service"], ["proto-fd-max", "advertise-ipv6", "dne"]
        )

        self.assertEqual(
            values["proto-fd-max"], IntConfigType(0, 2147483647, True, 15000)
        )
        self.assertEqual(values["advertise-ipv6"], BoolConfigType(True, False))
        self.assertIsNone(values["dne"])

    def test_get_logging_params(self):
        expected = [
            "any",
            "misc",
            "alloc",
            "arenax",
            "hardware",
            "msg",
            "rbuffer",
            "socket",
            "tls",
            "vault",
            "vmapx",
            "xmem",
            "aggr",
            "appeal",
            "as",
            "batch",
            "bin",
            "config",
            "clustering",
            "drv_pmem",
            "drv_ssd",
            "exchange",
            "exp",
            "fabric",
            "flat",
            "geo",
            "hb",
            "health",
            "hlc",
            "index",
            "info",
            "info-port",
            "job",
            "migrate",
            "mon",
            "namespace",
            "nsup",
            "particle",
            "partition",
            "paxos",
            "proto",
            "proxy",
            "proxy-divert",
            "query",
            "record",
            "roster",
            "rw",
            "rw-client",
            "scan",
            "security",
            "service",
            "service-list",
            "sindex",
            "skew",
            "smd",
            "storage",
            "truncate",
            "tsvc",
            "udf",
            "xdr",
            "xdr-client",
        ]

        params = self.handler.get_params(["logging"])
        self.assertCountEqual(expected, params)

    def test_get_logging_value(self):
        values = self.handler.get_types(["logging"], ["misc", "alloc", "dne"])

        self.assertEqual(
            values["misc"],
            EnumConfigType(
                ["critical", "warning", "info", "debug", "detail"],
                True,
                "INFO",
            ),
        )
        self.assertEqual(
            values["alloc"],
            EnumConfigType(
                ["critical", "warning", "info", "debug", "detail"],
                True,
                "INFO",
            ),
        )
        self.assertIsNone(values["dne"])

    def test_get_network_subcontext(self):
        expected = ["heartbeat", "fabric", "service", "tls", "info"]

        subcontext = self.handler.get_subcontext(["network"])

        self.assertCountEqual(expected, subcontext)

    def test_get_network_params(self):
        expected = []

        params = self.handler.get_params(["network"])

        self.assertCountEqual(expected, params)

    def test_get_network_values(self):
        values = self.handler.get_types(["network"], ["dne"])

        self.assertIsNone(values["dne"])

    def test_get_network_heatbeat_params(self):
        expected = ["interval", "timeout", "connect-timeout-ms", "protocol", "mtu"]

        params = self.handler.get_params(["network", "heartbeat"])

        self.assertCountEqual(expected, params)

    def test_get_network_heartbeat_subcontext(self):
        expected = []

        subcontext = self.handler.get_subcontext(["network", "heartbeat"])

        self.assertCountEqual(expected, subcontext)

    def test_get_network_heartbeat_values(self):
        values = self.handler.get_types(
            ["network", "heartbeat"], ["timeout", "protocol"]
        )

        self.assertEqual(values["timeout"], IntConfigType(3, 4294967295, True, 10))
        self.assertEqual(values["protocol"], EnumConfigType(["none", "v3"], True, "v3"))

    def test_get_network_fabric_params(self):
        expected = [
            "channel-bulk-recv-threads",
            "channel-ctrl-recv-threads",
            "channel-meta-recv-threads",
            "channel-rw-recv-threads",
            "recv-rearm-threshold",
        ]

        params = self.handler.get_params(["network", "fabric"])
        self.assertCountEqual(expected, params)

    def test_get_network_fabric_values(self):
        values = self.handler.get_types(
            ["network", "fabric"], ["channel-bulk-recv-threads"]
        )

        self.assertEqual(
            values["channel-bulk-recv-threads"], IntConfigType(1, 128, True, 4)
        )

    def test_get_namespace_subcontext(self):
        expected = [
            "storage-engine",
            "index-type",
            "set",
            "sindex",
            "geo2dsphere-within",
        ]

        subcontext = self.handler.get_subcontext(["namespace"])

        self.assertCountEqual(expected, subcontext)

    def test_get_namespace_params(self):
        expected = [
            "reject-non-xdr-writes",
            "reject-xdr-writes",
            "prefer-uniform-balance",
            "ignore-migrate-fill-delay",
            "transaction-pending-limit",
            "strong-consistency-allow-expunge",
            "disable-write-dup-res",
            "enable-benchmarks-batch-sub",
            "enable-benchmarks-ops-sub",
            "enable-benchmarks-read",
            "enable-benchmarks-udf",
            "enable-benchmarks-udf-sub",
            "enable-benchmarks-write",
            "enable-hist-proxy",
            "migrate-order",
            "migrate-retransmit-ms",
            "migrate-sleep",
            "nsup-hist-period",
            "nsup-period",
            "nsup-threads",
            "truncate-threads",
            "high-water-memory-pct",
            "allow-ttl-without-nsup",
            "high-water-disk-pct",
            "evict-hist-buckets",
            "evict-tenths-pct",
            "background-scan-max-rps",
            "single-scan-threads",
            "stop-writes-pct",
            "memory-size",
            "rack-id",
            "default-ttl",
            "read-consistency-level-override",
            "write-commit-level-override",
            "conflict-resolution-policy",
            "conflict-resolve-writes",
            "tomb-raider-eligible-age",
            "tomb-raider-period",
            "xdr-tomb-raider-period",
            "xdr-tomb-raider-threads",
            "disallow-null-setname",
            "xdr-bin-tombstone-ttl",
        ]

        params = self.handler.get_params(["namespace"])
        self.assertCountEqual(expected, params)

    def test_get_namespace_values(self):
        values = self.handler.get_types(["namespace"], ["name"])

        self.assertEqual(values["name"], StringConfigType(None, False, " "))

    def test_get_namespace_storage_engine_params(self):
        expected = [
            "read-page-cache",
            "post-write-queue",
            "cache-replica-writes",
            "max-write-cache",
            "defrag-lwm-pct",
            "defrag-sleep",
            "defrag-queue-min",
            "compression",
            "compression-level",
            "flush-max-ms",
            "enable-benchmarks-storage",
            "min-avail-pct",
            "tomb-raider-sleep",
        ]

        params = self.handler.get_params(["namespace", "storage-engine"])

        self.assertCountEqual(expected, params)

    def test_get_namespace_storage_engine_values(self):
        values = self.handler.get_types(
            ["namespace", "storage-engine"], ["compression"]
        )

        self.assertEqual(
            values["compression"],
            EnumConfigType(["none", "lz4", "snappy", "zstd"], True, "none"),
        )

    def test_get_namespace_set_params(self):
        expected = ["set-disable-eviction", "set-stop-writes-count"]

        params = self.handler.get_params(["namespace", "set"])

        self.assertCountEqual(expected, params)

    def test_get_namespace_set_values(self):
        values = self.handler.get_types(["namespace", "set"], ["set-disable-eviction"])

        self.assertEqual(
            values["set-disable-eviction"],
            BoolConfigType(True, False),
        )

    def test_get_namespace_geo2dsphere_within_params(self):
        expected = ["max-cells", "max-level", "min-level"]

        params = self.handler.get_params(["namespace", "geo2dsphere-within"])

        self.assertCountEqual(expected, params)

    def test_get_namespace_geo2dsphere_within_values(self):
        values = self.handler.get_types(
            ["namespace", "geo2dsphere-within"], ["max-level"]
        )

        self.assertEqual(
            values["max-level"],
            IntConfigType(0, 30, True, 30),
        )

    def test_get_xdr_params(self):
        expected = ["src-id"]

        params = self.handler.get_params(["xdr"])

        self.assertCountEqual(expected, params)

    def test_get_xdr_values(self):
        values = self.handler.get_types(["xdr"], ["src-id"])

        self.assertEqual(
            values["src-id"],
            IntConfigType(0, 255, True, 0),
        )

    def test_get_xdr_dc_params(self):
        expected = [
            "auth-mode",
            "auth-password-file",
            "auth-user",
            "connector",
            "max-recoveries-interleaved",
            "max-used-service-threads",
            "period-ms",
            "tls-name",
            "use-alternate-access-address",
        ]

        params = self.handler.get_params(["xdr", "dc"])

        self.assertCountEqual(expected, params)

    def test_get_xdr_dc_values(self):
        values = self.handler.get_types(["xdr", "dc"], ["auth-user"])

        self.assertEqual(
            values["auth-user"],
            StringConfigType(None, True, ""),
        )

    def test_get_xdr_dc_namespace_params(self):
        expected = [
            "bin-policy",
            "compression-level",
            "delay-ms",
            "enable-compression",
            "forward",
            "hot-key-ms",
            "ignore-bin",
            "ignore-expunges",
            "ignore-set",
            "max-throughput",
            "remote-namespace",
            "sc-replication-wait-ms",
            "ship-bin",
            "ship-bin-luts",
            "ship-nsup-deletes",
            "ship-only-specified-sets",
            "ship-set",
            "transaction-queue-limit",
            "write-policy",
        ]

        params = self.handler.get_params(["xdr", "dc", "namespace"])

        self.assertCountEqual(expected, params)

    def test_get_xdr_dc_namespace_values(self):
        values = self.handler.get_types(["xdr", "dc", "namespace"], ["write-policy"])

        self.assertEqual(
            values["write-policy"],
            EnumConfigType(["auto", "update", "replace"], True, "auto"),
        )

    def test_get_security_params(self):
        expected = ["privilege-refresh-period"]

        params = self.handler.get_params(["security"])

        self.assertCountEqual(expected, params)

    def test_get_security_values(self):
        values = self.handler.get_types(["security"], ["privilege-refresh-period"])

        self.assertEqual(
            values["privilege-refresh-period"],
            IntConfigType(10, 86400, True, 300),
        )

    def test_get_security_ldap_params(self):
        expected = ["polling-period", "session-ttl"]

        params = self.handler.get_params(["security", "ldap"])

        self.assertCountEqual(expected, params)

    def test_get_security_ldap_values(self):
        values = self.handler.get_types(["security", "ldap"], ["session-ttl"])

        self.assertEqual(
            values["session-ttl"],
            IntConfigType(120, 864000, True, 86400),
        )
