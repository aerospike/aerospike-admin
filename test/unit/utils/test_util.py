# Copyright 2021-2025 Aerospike, Inc.
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
import warnings

import unittest

from parameterized import parameterized

from lib.utils import constants, util


class UtilTest(unittest.IsolatedAsyncioTestCase):
    def test_has_content(self):
        for empty in [{}, [], (), set(), "", None, {"a": {}}, {"a": ""}, [{}, []]]:
            with self.subTest(value=empty):
                self.assertFalse(util.has_content(empty))

        for full in [0, False, "x", ["", "y"], {"a": {"b": 1}}, {"a": "", "b": "v"}]:
            with self.subTest(value=full):
                self.assertTrue(util.has_content(full))

    def test_stanza_has_server_data(self):
        self.assertTrue(
            util.stanza_has_server_data(
                constants.CollectinfoSection.STATISTICS, {"service": {"a": "1"}}
            )
        )
        self.assertFalse(
            util.stanza_has_server_data(constants.CollectinfoSection.STATISTICS, {})
        )

        self.assertFalse(
            util.stanza_has_server_data(
                constants.CollectinfoSection.METADATA,
                {"node_names": "host1", "ip": "1.1.1.1:3000", "asd_build": ""},
            )
        )
        self.assertTrue(
            util.stanza_has_server_data(
                constants.CollectinfoSection.METADATA,
                {"node_names": "host1", "asd_build": "8.0.0.0"},
            )
        )

        for malformed in [None, "meta_data", ["node_names"]]:
            with self.subTest(value=malformed):
                self.assertFalse(
                    util.stanza_has_server_data(
                        constants.CollectinfoSection.METADATA, malformed
                    )
                )

    def test_get_value_from_dict(self):
        value = {"a": 123, "b": "8.9", "c": "abc"}

        self.assertEqual(
            util.get_value_from_dict(value, "a"),
            123,
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(value, ("b",), return_type=float),
            8.9,
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(
                value, "c", default_value="default", return_type=int
            ),
            "default",
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(value, "d", default_value="default"),
            "default",
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(
                value, ("unknown1", "unknown2", "b"), default_value="default"
            ),
            "8.9",
            "get_value_from_dict did not return the expected result",
        )

    async def test_async_cached(self):
        tester_count = 0

        async def tester(arg1: int, arg2: int, sleep: float) -> int:
            nonlocal tester_count
            tester_count += 1
            await asyncio.sleep(sleep)
            return arg1 + arg2

        cached_tester = util.async_cached(tester, ttl=5.0)

        # insert into cache
        await cached_tester(1, 2, 0.2)
        await cached_tester(2, 2, 0.2)
        await cached_tester(3, 2, 0.2)

        # all cache hits.  Should return faster because in cache
        self.assertEqual(3, await asyncio.wait_for(cached_tester(1, 2, 0.2), 0.1))
        self.assertEqual(4, await asyncio.wait_for(cached_tester(2, 2, 0.2), 0.1))
        self.assertEqual(5, await asyncio.wait_for(cached_tester(3, 2, 0.2), 0.1))

        # not in the cache because it has a different sleep value
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(cached_tester(1, 2, 5), 0.1)

        # Key is in the cache but it is dirty because of the sleep. So it is a miss.
        await asyncio.sleep(5)
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(cached_tester(1, 2, 0.2), 0.1)
        self.assertEqual(tester_count, 5)

        tester_exc_count = 0

        async def tester_exc() -> bool:
            nonlocal tester_exc_count
            if tester_exc_count == 0:
                tester_exc_count += 1
                raise Exception()
            tester_exc_count += 1

            return True

        cached_tester_exc = util.async_cached(tester_exc, ttl=5.0)
        with self.assertRaises(Exception):
            await cached_tester_exc()
        self.assertTrue(await cached_tester_exc())

    def test_deep_merge_dicts(self):
        arg1 = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (1, [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (2, []),
                        ("CONFIG3", "KEY"): (3, []),
                    },
                }
            }
        }
        arg2 = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS3", "NAMESPACE"): {("CONFIG1", "KEY"): (3, [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (4, []),
                        ("CONFIG5", "KEY"): (7, []),
                    },
                }
            }
        }
        expected = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (1, [])},
                    ("NS3", "NAMESPACE"): {("CONFIG1", "KEY"): (3, [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (2, []),
                        ("CONFIG3", "KEY"): (3, []),
                        ("CONFIG5", "KEY"): (7, []),
                    },
                }
            }
        }
        result = util.deep_merge_dicts(arg1, arg2)
        self.assertEqual(
            result, expected, "deep_merge_dicts did not return the expected result"
        )

    def test_filter_exceptions_removes_and_logs(self):
        """TOOLS-3596: exception-valued keys are removed (existing behavior) and logged at
        DEBUG so the missing data is diagnosable."""
        err = TimeoutError("boom")
        data = {
            "node_a": {"stat": 1},
            "node_b": err,
        }

        with self.assertLogs("lib.utils.util", level="DEBUG") as cm:
            result = util.filter_exceptions(data)

        self.assertEqual(result, {"node_a": {"stat": 1}})
        self.assertTrue(
            any("node_b" in msg and "due to error" in msg for msg in cm.output),
            cm.output,
        )

    def test_filter_exceptions_keeps_clean_data(self):
        data = {"node_a": {"stat": 1}, "node_b": {"stat": 2}}
        result = util.filter_exceptions(data)
        self.assertEqual(result, {"node_a": {"stat": 1}, "node_b": {"stat": 2}})

    def test_is_valid_base64(self):
        # Test valid base64 string
        try:
            util.is_valid_base64("dGVzdA==")  # "test" in base64
        except ValueError:
            self.fail("is_valid_base64 raised ValueError for valid base64 string")

        # Test valid base64 bytes
        try:
            util.is_valid_base64(b"dGVzdA==")
        except ValueError:
            self.fail("is_valid_base64 raised ValueError for valid base64 bytes")

        # Test invalid base64 string
        with self.assertRaises(ValueError):
            util.is_valid_base64("invalid_base64!")

        # Test empty string
        with self.assertRaises(ValueError):
            util.is_valid_base64("")

        # Test None
        with self.assertRaises(ValueError):
            util.is_valid_base64(None)

        # Test string with invalid characters
        with self.assertRaises(ValueError):
            util.is_valid_base64("dGVzd@#$%A==")

    async def test_check_version_support_all_features_supported(self):
        """Test when all features are supported across all nodes."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0",
            "blob_indexing": "6.0.0",
        }

        builds = {"node1": "6.1.0", "node2": "6.2.0", "node3": "6.0.1"}

        result = await util.check_version_support(feature_versions, builds)

        expected = {
            "cdt_indexing": True,  # 6.0.1 >= 5.6.0
            "expression_indexing": True,  # 6.0.1 >= 5.7.0
            "blob_indexing": True,  # 6.0.1 >= 6.0.0
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_mixed_support(self):
        """Test when some features are supported and others are not."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0",
            "blob_indexing": "6.0.0",
        }

        builds = {"node1": "6.1.0", "node2": "5.8.0", "node3": "6.2.0"}  # Oldest node

        result = await util.check_version_support(feature_versions, builds)

        expected = {
            "cdt_indexing": True,  # 5.8.0 >= 5.6.0
            "expression_indexing": True,  # 5.8.0 >= 5.7.0
            "blob_indexing": False,  # 5.8.0 < 6.0.0
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_no_features_supported(self):
        """Test when no features are supported due to old nodes."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0",
            "blob_indexing": "6.0.0",
        }

        builds = {
            "node1": "5.5.0",  # Very old node
            "node2": "5.4.0",  # Even older
            "node3": "5.6.0",  # Just at the edge
        }

        result = await util.check_version_support(feature_versions, builds)

        expected = {
            "cdt_indexing": False,  # 5.4.0 < 5.6.0
            "expression_indexing": False,  # 5.4.0 < 5.7.0
            "blob_indexing": False,  # 5.4.0 < 6.0.0
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_empty_builds(self):
        """Test when no builds are provided (empty cluster)."""
        feature_versions = {"cdt_indexing": "5.6.0", "expression_indexing": "5.7.0"}

        builds = {}

        result = await util.check_version_support(feature_versions, builds)

        expected = {
            "cdt_indexing": False,  # No nodes = no support
            "expression_indexing": False,  # No nodes = no support
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_single_node(self):
        """Test with a single node cluster."""
        feature_versions = {"cdt_indexing": "5.6.0", "expression_indexing": "5.7.0"}

        builds = {"node1": "5.8.0"}

        result = await util.check_version_support(feature_versions, builds)

        expected = {
            "cdt_indexing": True,  # 5.8.0 >= 5.6.0
            "expression_indexing": True,  # 5.8.0 >= 5.7.0
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_exact_version_match(self):
        """Test when node version exactly matches feature requirement."""
        feature_versions = {"cdt_indexing": "5.6.0", "expression_indexing": "5.7.0"}

        builds = {
            "node1": "5.6.0",  # Exact match for cdt_indexing
            "node2": "5.7.0",  # Exact match for expression_indexing
        }

        result = await util.check_version_support(feature_versions, builds)

        # Minimum build version is 5.6.0
        expected = {
            "cdt_indexing": True,  # 5.6.0 >= 5.6.0
            "expression_indexing": False,  # 5.6.0 < 5.7.0
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_complex_version_strings(self):
        """Test with complex version strings including pre-release versions."""
        feature_versions = {
            "feature_a": "5.6.0",
            "feature_b": "5.7.0",
            "feature_c": "6.0.0",
        }

        builds = {
            "node1": "5.6.0a1",  # Pre-release version
            "node2": "5.7.0b2",  # Beta version
            "node3": "6.0.0rc1",  # Release candidate
        }

        result = await util.check_version_support(feature_versions, builds)

        # Minimum build version is 5.6.0a1
        # LooseVersion handles pre-release versions correctly
        expected = {
            "feature_a": True,  # 5.6.0a1 >= 5.6.0
            "feature_b": False,  # 5.6.0a1 < 5.7.0
            "feature_c": False,  # 5.6.0a1 < 6.0.0
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_edge_case_versions(self):
        """Test edge cases with unusual version formats."""
        feature_versions = {"feature_a": "1.0.0", "feature_b": "2.0.0"}

        builds = {
            "node1": "1.0.0.0",  # Extra version component
            "node2": "2.0",  # Missing patch version
            "node3": "1.9.9",  # Just below 2.0.0
        }

        result = await util.check_version_support(feature_versions, builds)

        expected = {
            "feature_a": True,  # 1.0.0.0 >= 1.0.0
            "feature_b": False,  # 1.9.9 < 2.0.0
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_empty_feature_versions(self):
        """Test with empty feature versions dictionary."""
        feature_versions = {}
        builds = {"node1": "6.1.0", "node2": "6.2.0"}

        result = await util.check_version_support(feature_versions, builds)

        expected = {}
        self.assertEqual(result, expected)

    async def test_check_version_support_large_cluster(self):
        """Test with a large number of nodes."""
        feature_versions = {"cdt_indexing": "5.6.0", "expression_indexing": "5.7.0"}

        # Create a large cluster with mixed versions
        builds = {}
        for i in range(100):
            if i < 50:
                builds[f"node{i}"] = "6.1.0"  # Newer nodes
            else:
                builds[f"node{i}"] = "5.5.0"  # Older nodes

        result = await util.check_version_support(feature_versions, builds)

        expected = {
            "cdt_indexing": False,  # 5.5.0 < 5.6.0
            "expression_indexing": False,  # 5.5.0 < 5.7.0
        }

        self.assertEqual(result, expected)

    async def test_check_version_support_invalid_version_strings(self):
        """Test with invalid version strings - should raise exception."""
        feature_versions = {"feature_a": "5.6.0", "feature_b": "invalid_version"}

        builds = {"node1": "5.8.0", "node2": "also_invalid"}

        # Should raise TypeError when LooseVersion can't handle invalid strings
        with self.assertRaises(TypeError):
            await util.check_version_support(feature_versions, builds)

    async def test_check_version_support_none_values(self):
        """Test with None values in builds - should raise exception."""
        feature_versions = {"cdt_indexing": "5.6.0"}

        builds = {"node1": "6.1.0", "node2": None, "node3": "5.8.0"}

        # Should raise AttributeError when trying to create LooseVersion from None
        with self.assertRaises(AttributeError):
            await util.check_version_support(feature_versions, builds)

    async def test_check_version_support_unicode_versions(self):
        """Test with unicode version strings."""
        feature_versions = {"feature_a": "5.6.0", "feature_b": "6.0.0"}

        builds = {"node1": "5.8.0", "node2": "6.1.0", "node3": "5.7.0"}

        result = await util.check_version_support(feature_versions, builds)

        expected = {
            "feature_a": True,  # 5.7.0 >= 5.6.0
            "feature_b": False,  # 5.7.0 < 6.0.0
        }

        self.assertEqual(result, expected)

    def test_normalize_masking_rule_data_redact_function(self):
        """Test normalize_masking_rule_data with redact function"""
        rule = {
            "ns": "test",
            "set": "demo",
            "bin": "ssn",
            "type": "string",
            "function": "redact",
            "position": "0",
            "length": "4",
            "value": "*",
        }

        result = util.normalize_masking_rule_data(rule)

        expected = {
            "ns": "test",
            "set": "demo",
            "bin": "ssn",
            "type": "string",
            "function": "redact position 0 length 4 value *",
        }

        self.assertEqual(result, expected)

    def test_normalize_masking_rule_data_constant_function(self):
        """Test normalize_masking_rule_data with constant function"""
        rule = {
            "ns": "test",
            "set": "demo",
            "bin": "email",
            "type": "string",
            "function": "constant",
            "value": "REDACTED",
        }

        result = util.normalize_masking_rule_data(rule)

        expected = {
            "ns": "test",
            "set": "demo",
            "bin": "email",
            "type": "string",
            "function": "constant value REDACTED",
        }

        self.assertEqual(result, expected)

    def test_normalize_masking_rule_data_namespace_field_variations(self):
        """Test normalize_masking_rule_data handles both 'ns' and 'namespace' fields"""
        rule_with_namespace = {
            "namespace": "test",
            "set": "demo",
            "bin": "ssn",
            "type": "string",
            "function": "redact",
        }

        result = util.normalize_masking_rule_data(rule_with_namespace)

        expected = {
            "ns": "test",
            "set": "demo",
            "bin": "ssn",
            "type": "string",
            "function": "redact",
        }

        self.assertEqual(result, expected)

    def test_normalize_masking_rule_data_missing_fields(self):
        """Test normalize_masking_rule_data with missing fields"""
        rule = {"ns": "test", "bin": "ssn"}

        result = util.normalize_masking_rule_data(rule)

        expected = {"ns": "test", "set": "", "bin": "ssn", "type": "", "function": ""}

        self.assertEqual(result, expected)

    def test_normalize_masking_rule_data_unknown_function(self):
        """Test normalize_masking_rule_data with unknown function"""
        rule = {
            "ns": "test",
            "set": "demo",
            "bin": "ssn",
            "type": "string",
            "function": "unknown_func",
        }

        result = util.normalize_masking_rule_data(rule)

        expected = {
            "ns": "test",
            "set": "demo",
            "bin": "ssn",
            "type": "string",
            "function": "unknown_func",
        }

        self.assertEqual(result, expected)

    def test_normalize_masking_rule_data_dynamic_function_params(self):
        """Test normalize_masking_rule_data with dynamic function parameters"""
        rule = {
            "ns": "test",
            "set": "demo",
            "bin": "ssn",
            "type": "string",
            "function": "custom_func",
            "param1": "value1",
            "param2": "value2",
            "custom_arg": "custom_value",
        }

        result = util.normalize_masking_rule_data(rule)

        expected = {
            "ns": "test",
            "set": "demo",
            "bin": "ssn",
            "type": "string",
            "function": "custom_func param1 value1 param2 value2 custom_arg custom_value",
        }

        self.assertEqual(result, expected)

    def test_is_valid_aerospike_name_valid_names(self):
        """Test is_valid_aerospike_name with valid names"""
        valid_names = [
            "read",
            "write",
            "admin",
            "read-write",
            "user_admin",
            "sys-admin",
            "data_admin",
            "test123",
            "role$1",
            "MyRole",
            "UPPERCASE",
            "mixed_Case-123$",
            "a",  # single character
            "a1b2c3",
            "test_role_with_underscores",
            "test-role-with-hyphens",
            "role$with$dollars",
            "123numeric_start",
            "role_123_end",
        ]

        for name in valid_names:
            with self.subTest(name=name):
                self.assertTrue(util.is_valid_aerospike_name(name, "role"))

    def test_is_valid_aerospike_name_invalid_names(self):
        """Test is_valid_aerospike_name with invalid names"""
        invalid_names = [
            "",  # empty
            "read,write",  # comma
            "role with spaces",  # spaces
            "role@domain",  # @ symbol
            "role#1",  # # symbol
            "role!",  # exclamation
            "role%admin",  # percent
            "role&user",  # ampersand
            "role*",  # asterisk
            "role+admin",  # plus
            "role=value",  # equals
            "role[0]",  # brackets
            "role{admin}",  # braces
            "role|pipe",  # pipe
            "role\\path",  # backslash
            "role:admin",  # colon
            "role;admin",  # semicolon
            'role"quoted"',  # quotes
            "role'quoted'",  # single quotes
            "role<admin>",  # angle brackets
            "role?admin",  # question mark
            "role/path",  # forward slash
            "role.admin",  # period
            "role~admin",  # tilde
            "role`admin",  # backtick
            "café",  # accented characters
            "rôle",  # accented characters
            "角色",  # non-latin characters
        ]

        for name in invalid_names:
            with self.subTest(name=name):
                self.assertFalse(util.is_valid_aerospike_name(name, "role"))

    def test_is_valid_aerospike_name_different_object_types(self):
        """Test is_valid_aerospike_name with different object types"""
        test_cases = [
            ("myuser", "user", True),
            ("myrole", "role", True),
            ("my_namespace", "namespace", True),
            ("my-set", "set", True),
            ("my$bin", "bin", True),
            ("my,invalid", "user", False),
            ("", "namespace", False),
            ("invalid space", "set", False),
        ]

        for name, obj_type, expected in test_cases:
            with self.subTest(name=name, obj_type=obj_type):
                result = util.is_valid_aerospike_name(name, obj_type)
                self.assertEqual(result, expected)

    def test_is_valid_role_name_convenience_wrapper(self):
        """Test is_valid_role_name convenience wrapper"""
        # Valid role names
        valid_roles = ["admin", "read-write", "user_admin", "role123"]
        for role in valid_roles:
            with self.subTest(role=role):
                self.assertTrue(util.is_valid_role_name(role))

        # Invalid role names
        invalid_roles = ["admin,user", "role with spaces", "role@domain", ""]
        for role in invalid_roles:
            with self.subTest(role=role):
                self.assertFalse(util.is_valid_role_name(role))

    def test_is_valid_aerospike_name_edge_cases(self):
        """Test edge cases for is_valid_aerospike_name"""
        # Very long name with valid characters
        long_name = "a" * 100
        self.assertTrue(util.is_valid_aerospike_name(long_name, "role"))

        # Name with all valid special characters
        all_valid_chars = "abc123_-$"
        self.assertTrue(util.is_valid_aerospike_name(all_valid_chars, "role"))

        # Name starting with number
        number_start = "123role"
        self.assertTrue(util.is_valid_aerospike_name(number_start, "role"))

        # Name ending with special chars
        special_end = "role_-$"
        self.assertTrue(util.is_valid_aerospike_name(special_end, "role"))

        # Mixed case with all valid chars
        mixed_case = "MyRole_123-Test$"
        self.assertTrue(util.is_valid_aerospike_name(mixed_case, "role"))

    def test_is_valid_aerospike_name_comma_variations(self):
        """Test various comma-related invalid names"""
        comma_cases = [
            "role1,role2",  # comma in middle
            ",role",  # comma at start
            "role,",  # comma at end
            "role1,role2,role3",  # multiple commas
            "role,,double",  # double comma
            "role, space",  # comma with space
            " ,role",  # space and comma at start
        ]

        for name in comma_cases:
            with self.subTest(name=name):
                self.assertFalse(util.is_valid_aerospike_name(name, "role"))


class AggregateNsMemoryStatsTest(unittest.TestCase):
    def test_aggregates_across_namespaces(self):
        ns_stats = {
            "node1": {
                "ns1": {
                    "index_used_bytes": "100",
                    "sindex_used_bytes": "200",
                    "set_index_used_bytes": "50",
                },
                "ns2": {
                    "index_used_bytes": "300",
                    "sindex_used_bytes": "400",
                    "set_index_used_bytes": "150",
                },
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["index_used_bytes"], "400")
        self.assertEqual(result["node1"]["sindex_used_bytes"], "600")
        self.assertEqual(result["node1"]["set_index_used_bytes"], "200")

    def test_device_backed_index_used_excluded(self):
        ns_stats = {
            "node1": {
                "flash_ns": {
                    "index-type": "flash",
                    "index_used_bytes": "40000",
                    "sindex-type": "shmem",
                    "sindex_used_bytes": "512",
                    "set_index_used_bytes": "8",
                },
                "pmem_ns": {
                    "index-type": "pmem",
                    "index_used_bytes": "90000",
                    "sindex-type": "pmem",
                    "sindex_used_bytes": "99999",
                },
                "shmem_ns": {
                    "index_used_bytes": "100",
                    "sindex_used_bytes": "200",
                },
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["index_used_bytes"], "100")
        self.assertEqual(result["node1"]["sindex_used_bytes"], "712")
        self.assertEqual(result["node1"]["set_index_used_bytes"], "8")

    def test_skips_malformed_namespace_bodies(self):
        ns_stats = {
            "strnode": "oops",
            "listnode": ["a"],
            "nonenode": None,
            "node1": {
                "nullns": None,
                "strns": "corrupt",
                "listns": ["x"],
                "ns1": {"index_used_bytes": "100"},
            },
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(list(result.keys()), ["node1"])
        self.assertEqual(result["node1"]["index_used_bytes"], "100")

    def test_skips_exception_nodes(self):
        ns_stats = {
            "node1": Exception("connection error"),
            "node2": {
                "ns1": {
                    "index_used_bytes": "100",
                    "sindex_used_bytes": "0",
                    "set_index_used_bytes": "0",
                }
            },
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertNotIn("node1", result)
        self.assertEqual(result["node2"]["index_used_bytes"], "100")

    def test_skips_exception_namespaces(self):
        ns_stats = {
            "node1": {
                "ns1": Exception("timeout"),
                "ns2": {
                    "index_used_bytes": "500",
                    "sindex_used_bytes": "600",
                    "set_index_used_bytes": "0",
                },
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["index_used_bytes"], "500")
        self.assertEqual(result["node1"]["sindex_used_bytes"], "600")

    def test_absent_metrics_are_omitted(self):
        ns_stats = {"node1": {"ns1": {"index_used_bytes": "100"}}}
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["index_used_bytes"], "100")
        self.assertNotIn("sindex_used_bytes", result["node1"])
        self.assertNotIn("set_index_used_bytes", result["node1"])
        self.assertNotIn("shmem_alloc_bytes", result["node1"])

    def test_aggregates_shmem_alloc_and_ignores_device_backings(self):
        ns_stats = {
            "node1": {
                "ns1": {
                    "index_shmem_alloc_bytes": "100",
                    "sindex_shmem_alloc_bytes": "10",
                },
                "ns2": {
                    "index_pmem_alloc_bytes": "200",
                    "sindex_flash_alloc_bytes": "5",
                },
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["shmem_alloc_bytes"], "110")
        self.assertNotIn("pmem_alloc_bytes", result["node1"])
        self.assertNotIn("flash_alloc_bytes", result["node1"])

    def test_device_backed_index_arenas_excluded_from_components(self):
        ns_stats = {
            "node1": {
                "ns1": {
                    "index_flash_alloc_bytes": "900",
                    "sindex_pmem_alloc_bytes": "800",
                }
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        for key in ("pi_alloc_bytes", "si_alloc_bytes", "total_alloc_bytes"):
            with self.subTest(key=key):
                self.assertNotIn(key, result["node1"])

    def test_data_in_memory_only_for_memory_storage_engine(self):
        ns_stats = {
            "node1": {
                "mem_ns": {"storage-engine": "memory", "data_used_bytes": "300"},
                "dev_ns": {"storage-engine": "device", "data_used_bytes": "999"},
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["data_in_memory_used_bytes"], "300")

    def test_memory_data_total_folds_into_shmem_alloc(self):
        ns_stats = {
            "node1": {
                "mem_ns": {
                    "storage-engine": "memory",
                    "index_shmem_alloc_bytes": "100",
                    "data_total_bytes": "500",
                    "data_used_bytes": "50",
                },
                "dev_ns": {
                    "storage-engine": "device",
                    "index_shmem_alloc_bytes": "200",
                    "data_total_bytes": "9999",
                },
            }
        }
        result = util.aggregate_ns_memory_stats(
            ns_stats, editions={"node1": "Enterprise"}
        )
        self.assertEqual(result["node1"]["shmem_alloc_bytes"], "800")
        self.assertEqual(result["node1"]["data_in_memory_used_bytes"], "50")

    def _memory_engine_ns_stats(self):
        return {
            "node1": {
                "mem_ns": {
                    "storage-engine": "memory",
                    "index_shmem_alloc_bytes": "100",
                    "data_total_bytes": "500",
                }
            }
        }

    def test_community_data_total_not_folded_into_shmem_alloc(self):
        result = util.aggregate_ns_memory_stats(
            self._memory_engine_ns_stats(), editions={"node1": "Community"}
        )
        self.assertEqual(result["node1"]["shmem_alloc_bytes"], "100")
        self.assertEqual(result["node1"]["data_alloc_bytes"], "500")

    def test_enterprise_data_total_folded_into_shmem_alloc(self):
        for edition in ("Enterprise", "Federal"):
            with self.subTest(edition=edition):
                result = util.aggregate_ns_memory_stats(
                    self._memory_engine_ns_stats(), editions={"node1": edition}
                )
                self.assertEqual(result["node1"]["shmem_alloc_bytes"], "600")

    def test_unknown_edition_does_not_fold_data_total(self):
        for editions in ({}, {"node1": "N/E"}, {"other": "Community"}):
            with self.subTest(editions=editions):
                result = util.aggregate_ns_memory_stats(
                    self._memory_engine_ns_stats(), editions=editions
                )
                self.assertEqual(result["node1"]["shmem_alloc_bytes"], "100")
                self.assertEqual(result["node1"]["data_alloc_bytes"], "500")

    def test_community_with_no_index_stats_omits_shmem_alloc(self):
        ns_stats = {
            "node1": {"mem_ns": {"storage-engine": "memory", "data_total_bytes": "500"}}
        }
        result = util.aggregate_ns_memory_stats(
            ns_stats, editions={"node1": "Community"}
        )
        self.assertNotIn("shmem_alloc_bytes", result["node1"])
        self.assertEqual(result["node1"]["data_alloc_bytes"], "500")

    def test_component_alloc_sums_across_namespaces(self):
        ns_stats = {
            "node1": {
                "ns1": {
                    "index_shmem_alloc_bytes": "100",
                    "sindex_shmem_alloc_bytes": "10",
                    "set_index_alloc_bytes": "4",
                },
                "ns2": {
                    "index_shmem_alloc_bytes": "200",
                    "sindex_shmem_alloc_bytes": "20",
                    "set_index_alloc_bytes": "6",
                },
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["pi_alloc_bytes"], "300")
        self.assertEqual(result["node1"]["si_alloc_bytes"], "30")
        self.assertEqual(result["node1"]["set_alloc_bytes"], "10")

    def test_data_alloc_only_for_memory_storage_engine(self):
        ns_stats = {
            "node1": {
                "mem_ns": {"storage-engine": "memory", "data_total_bytes": "500"},
                "dev_ns": {"storage-engine": "device", "data_total_bytes": "9999"},
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["data_alloc_bytes"], "500")

    def test_component_alloc_keys_omitted_without_sources(self):
        ns_stats = {"node1": {"ns1": {"index_used_bytes": "100"}}}
        result = util.aggregate_ns_memory_stats(ns_stats)
        for key in (
            "pi_alloc_bytes",
            "si_alloc_bytes",
            "set_alloc_bytes",
            "data_alloc_bytes",
            "total_alloc_bytes",
        ):
            with self.subTest(key=key):
                self.assertNotIn(key, result["node1"])

    def test_total_alloc_omitted_when_only_data_alloc_is_known(self):
        ns_stats = {
            "node1": {
                "mem_ns": {
                    "storage-engine": "memory",
                    "data_total_bytes": "500",
                    "data_used_bytes": "400",
                }
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)

        self.assertEqual(result["node1"]["data_alloc_bytes"], "500")
        self.assertEqual(result["node1"]["total_used_bytes"], "400")
        self.assertNotIn("total_alloc_bytes", result["node1"])

    def test_total_alloc_published_once_an_arena_stat_arrives(self):
        for arena_key in (
            "index_shmem_alloc_bytes",
            "sindex_shmem_alloc_bytes",
            "set_index_alloc_bytes",
        ):
            with self.subTest(arena_key=arena_key):
                ns_stats = {
                    "node1": {
                        "mem_ns": {
                            "storage-engine": "memory",
                            "data_total_bytes": "500",
                            arena_key: "100",
                        }
                    }
                }
                result = util.aggregate_ns_memory_stats(ns_stats)
                self.assertEqual(result["node1"]["total_alloc_bytes"], "600")

    def test_totals_sum_every_present_component(self):
        ns_stats = {
            "node1": {
                "ns1": {
                    "storage-engine": "memory",
                    "index_shmem_alloc_bytes": "100",
                    "sindex_shmem_alloc_bytes": "10",
                    "set_index_alloc_bytes": "4",
                    "data_total_bytes": "500",
                    "index_used_bytes": "90",
                    "sindex_used_bytes": "9",
                    "set_index_used_bytes": "3",
                    "data_used_bytes": "400",
                }
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)

        self.assertEqual(result["node1"]["total_alloc_bytes"], "614")
        self.assertEqual(result["node1"]["total_used_bytes"], "502")

    def test_total_alloc_does_not_double_count_folded_shmem(self):
        ns_stats = {
            "node1": {
                "ns1": {
                    "storage-engine": "memory",
                    "index_shmem_alloc_bytes": "100",
                    "data_total_bytes": "500",
                }
            }
        }
        result = util.aggregate_ns_memory_stats(
            ns_stats, editions={"node1": constants.EDITION_ENTERPRISE}
        )

        self.assertEqual(result["node1"]["shmem_alloc_bytes"], "600")
        self.assertEqual(result["node1"]["total_alloc_bytes"], "600")

    def test_data_in_memory_absent_without_memory_namespace(self):
        ns_stats = {
            "node1": {"dev_ns": {"storage-engine": "device", "data_used_bytes": "999"}}
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertNotIn("data_in_memory_used_bytes", result["node1"])

    def test_stop_writes_threshold_is_the_lowest_across_namespaces(self):
        ns_stats = {
            "node1": {
                "ns1": {"stop-writes-sys-memory-pct": "90"},
                "ns2": {"stop-writes-sys-memory-pct": "75"},
                "ns3": {"stop-writes-sys-memory-pct": "80"},
            }
        }
        result = util.aggregate_ns_memory_stats(ns_stats)
        self.assertEqual(result["node1"]["stop_writes_sys_memory_pct"], "75")

    def test_stop_writes_threshold_omitted_when_absent_or_unusable(self):
        for value in (None, "0", "-1", "101", "garbage"):
            with self.subTest(value=value):
                ns_data = {} if value is None else {"stop-writes-sys-memory-pct": value}
                result = util.aggregate_ns_memory_stats({"node1": {"ns1": ns_data}})
                self.assertNotIn("stop_writes_sys_memory_pct", result["node1"])

    def test_empty_input(self):
        self.assertEqual(util.aggregate_ns_memory_stats({}), {})


class DeriveMemoryStatsTest(unittest.TestCase):
    def test_kbytes_converted_to_bytes(self):
        stats = {
            "node1": {
                "system_free_mem_kbytes": "1000",
                "heap_active_kbytes": "2",
                "heap_mapped_kbytes": "3",
                "system_thp_mem_kbytes": "4",
            }
        }
        result = util.derive_memory_stats(stats)
        self.assertEqual(result["node1"]["system_free_mem_bytes"], str(1000 * 1024))
        self.assertEqual(result["node1"]["heap_active_bytes"], str(2 * 1024))
        self.assertEqual(result["node1"]["heap_mapped_bytes"], str(3 * 1024))
        self.assertEqual(result["node1"]["system_thp_mem_bytes"], str(4 * 1024))

    def test_total_memory_is_never_inferred_from_free_stats(self):
        for prefix in ("host", "system"):
            for pct in ("1", "5", "50", "99", "0"):
                with self.subTest(prefix=prefix, pct=pct):
                    stats = {
                        "node1": {
                            f"{prefix}_free_mem_kbytes": "8000000",
                            f"{prefix}_free_mem_pct": pct,
                        }
                    }
                    result = util.derive_memory_stats(stats)
                    for key in result["node1"]:
                        self.assertNotIn("total", key)

    def test_host_free_stats_are_still_relayed(self):
        stats = {
            "node1": {"host_free_mem_kbytes": "8000000", "host_free_mem_pct": "50"}
        }
        result = util.derive_memory_stats(stats)
        self.assertEqual(result["node1"]["host_free_mem_bytes"], str(8000000 * 1024))
        self.assertEqual(result["node1"]["host_free_mem_pct"], "50")

    def test_cgroup_used_pct_derived(self):
        stats = {
            "node1": {
                "cgroup_memory_used_bytes": "50",
                "cgroup_memory_limit_bytes": "200",
            }
        }
        result = util.derive_memory_stats(stats)
        self.assertEqual(float(result["node1"]["cgroup_memory_used_pct"]), 25.0)
        self.assertEqual(result["node1"]["cgroup_memory_limit_effective_bytes"], "200")

    def test_cgroup_used_pct_skipped_without_limit(self):
        stats = {"node1": {"cgroup_memory_used_bytes": "50"}}
        result = util.derive_memory_stats(stats)
        self.assertNotIn("cgroup_memory_used_pct", result["node1"])

    def test_cgroup_used_pct_skipped_on_invalid_used(self):
        for used in ("N/E", "notanumber", "-500"):
            with self.subTest(used=used):
                stats = {
                    "node1": {
                        "cgroup_memory_used_bytes": used,
                        "cgroup_memory_limit_bytes": "200",
                    }
                }
                result = util.derive_memory_stats(stats)
                self.assertNotIn("cgroup_memory_used_pct", result["node1"])

    def test_cgroup_no_limit_sentinels_rejected(self):
        for limit in ("9223372036854771712", "max", "-1", "0"):
            with self.subTest(limit=limit):
                stats = {
                    "node1": {
                        "cgroup_memory_limit_bytes": limit,
                        "cgroup_memory_used_bytes": "50",
                    }
                }
                result = util.derive_memory_stats(stats)
                self.assertNotIn("cgroup_memory_limit_effective_bytes", result["node1"])
                self.assertNotIn("cgroup_memory_used_pct", result["node1"])

    def test_measured_cgroup_limit_passes_through_regardless_of_free_stats(self):
        host_total = int(8000000 * 1024 * 100 / 50)

        for limit in (host_total // 2, host_total, host_total * 2, 1 << 50):
            with self.subTest(limit=limit):
                stats = {
                    "node1": {
                        "host_free_mem_kbytes": "8000000",
                        "host_free_mem_pct": "50",
                        "cgroup_memory_limit_bytes": str(limit),
                    }
                }
                result = util.derive_memory_stats(stats)

                self.assertEqual(
                    result["node1"]["cgroup_memory_limit_effective_bytes"], str(limit)
                )

    def test_no_limit_sentinels_rejected_without_a_host_total(self):
        for value in ("max", "-1", "0", "9223372036854771712", "9223372036854775807"):
            with self.subTest(value=value):
                self.assertEqual(util.cgroup_limit_or_zero(value), 0)

    def test_real_limits_pass_through_verbatim(self):
        for value in ("1", str(1 << 30), str((1 << 62) - 1)):
            with self.subTest(value=value):
                self.assertEqual(util.cgroup_limit_or_zero(value), int(value))

    def test_garbage_values_tolerated(self):
        for value in ("notanumber", "inf", "-inf", "nan", "1e400", "9E0123456789"):
            with self.subTest(value=value):
                stats = {"node1": {"system_free_mem_kbytes": value}}
                result = util.derive_memory_stats(stats)
                self.assertEqual(result["node1"]["system_free_mem_bytes"], "0")

    def test_absurd_magnitudes_rejected_as_zero(self):
        stats = {"node1": {"heap_allocated_kbytes": "1" + "0" * 400}}
        result = util.derive_memory_stats(stats)
        self.assertEqual(result["node1"]["heap_allocated_bytes"], "0")

    def test_exception_node_skipped(self):
        stats = {"node1": Exception("boom"), "node2": {"heap_mapped_kbytes": "4"}}
        result = util.derive_memory_stats(stats)
        self.assertEqual(result["node2"]["heap_mapped_bytes"], str(4 * 1024))


class IntOrZeroTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("int", 5, 5),
            ("str", "5", 5),
            ("float_str", "5.9", 5),
            ("negative", "-5", -5),
            ("none", None, 0),
            ("garbage", "notanumber", 0),
            ("inf", "inf", 0),
            ("neg_inf", "-inf", 0),
            ("nan", "nan", 0),
            ("overflow_exp", "1e400", 0),
            ("hex_looking", "9E0123456789", 0),
            ("digit_bomb", "1" + "0" * 400, 0),
        ]
    )
    def test_int_or_zero(self, _name, value, expected):
        self.assertEqual(util.int_or_zero(value), expected)


class SummarizeNodesTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("small_cluster_named", ["a", "b", "c"], 3, "a, b, c"),
            ("single_node_named", ["a"], 1, "a"),
            ("one_of_many", ["b"], 14, "b"),
            ("under_limit", ["c", "a", "b"], 14, "a, b, c"),
            ("over_limit", ["e", "d", "c", "b", "a"], 14, "a, b, c and 2 more"),
            ("all_of_many", list("abcde"), 5, "all 5 nodes"),
            ("unknown_total", ["b", "a"], 0, "a, b"),
        ]
    )
    def test_summarize_nodes(self, _name, names, total, expected):
        self.assertEqual(util.summarize_nodes(names, total), expected)

    def test_a_full_cluster_never_lists_every_name(self):
        names = ["node-%02d.very.long.fqdn.example.com:3000" % i for i in range(14)]

        self.assertEqual(util.summarize_nodes(names, 14), "all 14 nodes")

    def test_accepts_a_generator(self):
        self.assertEqual(util.summarize_nodes((n for n in ["b", "a"]), 5), "a, b")


class DeriveMemoryHeadlineTest(unittest.TestCase):
    def headline(self, stats, configs=None, ns_agg=None, nodes=None):
        return util.derive_memory_headline(
            util.derive_memory_stats(stats),
            configs if configs is not None else {},
            ns_agg if ns_agg is not None else {},
            nodes=nodes,
        )

    def test_capacity_is_the_tracked_cgroup_limit(self):
        headline, untracked, no_capacity, missing = self.headline(
            {
                "node1": {
                    "host_free_mem_kbytes": "8000000",
                    "host_free_mem_pct": "50",
                    "host_total_mem_kbytes": "16000000",
                    "cgroup_memory_limit_bytes": "10000",
                }
            },
            configs={"node1": {"cgroup-mem-tracking": "true"}},
            ns_agg={"node1": {}},
        )
        self.assertEqual(headline["node1"]["capacity_bytes"], "10000")
        self.assertEqual(untracked, [])
        self.assertEqual(no_capacity, [])
        self.assertEqual(missing, [])

    def test_capacity_is_the_host_total_without_a_cgroup_limit(self):
        headline, untracked, no_capacity, _ = self.headline(
            {"node1": {"host_total_mem_kbytes": "16000000"}},
            configs={"node1": {}},
            ns_agg={"node1": {}},
        )
        self.assertEqual(headline["node1"]["capacity_bytes"], str(16000000 * 1024))
        self.assertEqual(untracked, [])
        self.assertEqual(no_capacity, [])

    def test_untracked_cgroup_limit_falls_back_to_host_total_and_warns(self):
        """
        An untracked limit still caps the node, but asadm has no measurement
        of it, so Capacity reports what the server did measure - the host
        total - and the node is named so the caller can say which figure it
        got.
        """
        headline, untracked, no_capacity, _ = self.headline(
            {
                "node1": {
                    "host_free_mem_kbytes": "8000000",
                    "host_free_mem_pct": "50",
                    "host_total_mem_kbytes": "16000000",
                    "cgroup_memory_limit_bytes": "10000",
                }
            },
            configs={"node1": {"cgroup-mem-tracking": "false"}},
            ns_agg={"node1": {}},
        )
        self.assertEqual(headline["node1"]["capacity_bytes"], str(16000000 * 1024))
        self.assertEqual(untracked, ["node1"])
        self.assertEqual(no_capacity, [])

    def test_capacity_is_never_estimated_from_free_stats(self):
        """
        Capacity comes from a reported total (host_total_mem_kbytes) or a
        tracked cgroup limit, never from the free pair: a node reporting only
        free memory gets no Capacity and no Alloc%, and is reported so the
        caller can say why.
        """
        for prefix in ("host", "system"):
            with self.subTest(prefix=prefix):
                headline, untracked, no_capacity, _ = self.headline(
                    {
                        "node1": {
                            f"{prefix}_free_mem_kbytes": "8000000",
                            f"{prefix}_free_mem_pct": "50",
                            "heap_allocated_kbytes": "1000",
                        }
                    },
                    configs={"node1": {}},
                    ns_agg={"node1": {"shmem_alloc_bytes": "500"}},
                )
                self.assertNotIn("capacity_bytes", headline["node1"])
                self.assertNotIn("alloc_pct", headline["node1"])
                self.assertEqual(untracked, [])
                self.assertEqual(no_capacity, ["node1"])
                self.assertEqual(
                    headline["node1"]["allocated_bytes"], str(1000 * 1024 + 500)
                )

    def test_tracked_cgroup_limit_is_used_despite_free_stats(self):
        headline, _, no_capacity, _ = self.headline(
            {
                "node1": {
                    "system_free_mem_kbytes": "8000000",
                    "system_free_mem_pct": "50",
                    "cgroup_memory_limit_bytes": "10000",
                    "heap_allocated_kbytes": "0",
                }
            },
            configs={"node1": {"cgroup-mem-tracking": "true"}},
            ns_agg={"node1": {"shmem_alloc_bytes": "2500"}},
        )
        self.assertEqual(headline["node1"]["capacity_bytes"], "10000")
        self.assertEqual(float(headline["node1"]["alloc_pct"]), 25.0)
        self.assertEqual(no_capacity, [])

    def test_untracked_warning_covers_every_unreadable_tracking_config(self):
        """
        A limit asadm cannot attribute to the cgroup must name the node, in
        exactly one list. An unreadable tracking config is still an untracked
        limit, and staying silent there would leave a host-wide Capacity next
        to a cgroup-capped node with nothing explaining it.
        """
        for configs in ({"node1": {}}, {"node1": {"cgroup-mem-tracking": "false"}}, {}):
            with self.subTest(configs=configs):
                headline, untracked, no_capacity, _ = self.headline(
                    {
                        "node1": {
                            "cgroup_memory_limit_bytes": "10000",
                            "host_total_mem_kbytes": "16000000",
                            "system_free_mem_kbytes": "8000000",
                            "system_free_mem_pct": "50",
                        }
                    },
                    configs=configs,
                    ns_agg={"node1": {}},
                )
                self.assertEqual(untracked, ["node1"])
                self.assertEqual(no_capacity, [])
                self.assertEqual(
                    headline["node1"]["capacity_bytes"], str(16000000 * 1024)
                )

    def test_cgroup_sentinel_falls_back_to_host_total(self):
        """
        An uncapped cgroup is not a capacity, but the host total still is.
        """
        headline, untracked, no_capacity, _ = self.headline(
            {
                "node1": {
                    "cgroup_memory_limit_bytes": "9223372036854771712",
                    "host_total_mem_kbytes": "16000000",
                }
            },
            configs={"node1": {"cgroup-mem-tracking": "true"}},
            ns_agg={"node1": {}},
        )
        self.assertEqual(headline["node1"]["capacity_bytes"], str(16000000 * 1024))
        self.assertEqual(untracked, [])
        self.assertEqual(no_capacity, [])

    def test_cgroup_sentinel_without_host_total_leaves_capacity_blank(self):
        headline, untracked, no_capacity, _ = self.headline(
            {"node1": {"cgroup_memory_limit_bytes": "9223372036854771712"}},
            configs={"node1": {"cgroup-mem-tracking": "true"}},
            ns_agg={"node1": {}},
        )
        self.assertNotIn("capacity_bytes", headline["node1"])
        self.assertNotIn("alloc_pct", headline["node1"])
        self.assertEqual(untracked, [])
        self.assertEqual(no_capacity, ["node1"])

    def test_old_build_is_not_reported_as_limitless(self):
        """
        A pre-8.1.3 node reports neither cgroup_memory_limit_bytes nor
        host_total_mem_kbytes, so Capacity is blank and the node is named for
        that reason alone. Its cgroup is unobserved, so it is never called
        untracked.
        """
        headline, untracked, no_capacity, _ = util.derive_memory_headline(
            util.derive_memory_stats({"n1": {"heap_allocated_kbytes": "1000"}}),
            {},
            {"n1": {"shmem_alloc_bytes": "500"}},
            builds={"n1": "8.1.2.0"},
        )
        self.assertEqual(untracked, [])
        self.assertEqual(no_capacity, ["n1"])
        self.assertNotIn("capacity_bytes", headline["n1"])

    def test_allocated_is_shmem_plus_heap(self):
        headline, _, _, _ = self.headline(
            {
                "node1": {
                    "host_free_mem_kbytes": "8000000",
                    "host_free_mem_pct": "50",
                    "heap_allocated_kbytes": "500000",
                }
            },
            ns_agg={"node1": {"shmem_alloc_bytes": "2048000"}},
        )
        heap = 500000 * 1024
        allocated = heap + 2048000
        row = headline["node1"]
        self.assertEqual(row["allocated_bytes"], str(allocated))
        self.assertEqual(row["allocated_shmem_bytes"], "2048000")
        self.assertEqual(row["allocated_heap_bytes"], str(heap))
        self.assertEqual(float(row["allocated_heap_pct"]), heap * 100 / allocated)

    def test_missing_ns_stats_omits_total_and_reports_node(self):
        headline, _, _, missing = self.headline(
            {
                "good": {"heap_allocated_kbytes": "1000"},
                "nsfail": {"heap_allocated_kbytes": "1000"},
            },
            ns_agg={"good": {"shmem_alloc_bytes": "500"}},
        )
        self.assertEqual(missing, ["nsfail"])
        self.assertNotIn("allocated_bytes", headline["nsfail"])
        self.assertNotIn("alloc_pct", headline["nsfail"])
        self.assertNotIn("allocated_heap_pct", headline["nsfail"])
        self.assertNotIn("allocated_shmem_bytes", headline["nsfail"])
        self.assertEqual(headline["nsfail"]["allocated_heap_bytes"], str(1000 * 1024))
        self.assertIn("allocated_bytes", headline["good"])

    def test_old_build_omits_allocated_total(self):
        stats = {"old": {"heap_allocated_kbytes": "1000"}}
        headline, _, _, _ = util.derive_memory_headline(
            util.derive_memory_stats(stats),
            {},
            {"old": {"index_used_bytes": "500", "shmem_alloc_bytes": "500"}},
            builds={"old": "8.1.2"},
        )
        row = headline["old"]
        self.assertNotIn("allocated_bytes", row)
        self.assertNotIn("alloc_pct", row)
        self.assertNotIn("allocated_heap_pct", row)
        self.assertNotIn("allocated_shmem_bytes", row)
        self.assertEqual(row["allocated_heap_bytes"], str(1000 * 1024))

    def test_unreadable_build_omits_allocated_total(self):
        for build in (None, "", "N/E", Exception("connection refused")):
            with self.subTest(build=repr(build)):
                headline, _, _, _ = util.derive_memory_headline(
                    util.derive_memory_stats({"n1": {"heap_allocated_kbytes": "1000"}}),
                    {},
                    {"n1": {"shmem_alloc_bytes": "500"}},
                    builds={"n1": build},
                )
                self.assertNotIn("allocated_bytes", headline["n1"])
                self.assertNotIn("allocated_shmem_bytes", headline["n1"])

    def test_build_gate_is_per_node_not_cluster_wide(self):
        stats = {node: {"heap_allocated_kbytes": "1000"} for node in ("new", "old")}
        headline, _, _, _ = util.derive_memory_headline(
            util.derive_memory_stats(stats),
            {},
            {node: {"shmem_alloc_bytes": "500"} for node in ("new", "old")},
            builds={"new": "8.1.3", "old": "8.1.2"},
        )

        self.assertEqual(headline["new"]["allocated_bytes"], str(1000 * 1024 + 500))
        self.assertEqual(headline["new"]["allocated_shmem_bytes"], "500")
        self.assertNotIn("allocated_bytes", headline["old"])
        self.assertNotIn("allocated_shmem_bytes", headline["old"])

    def test_supported_build_keeps_allocated_total(self):
        headline, _, _, _ = util.derive_memory_headline(
            util.derive_memory_stats({"n1": {"heap_allocated_kbytes": "1000"}}),
            {},
            {"n1": {"shmem_alloc_bytes": "500"}},
            builds={"n1": "8.1.3"},
        )
        self.assertEqual(headline["n1"]["allocated_bytes"], str(1000 * 1024 + 500))

    def test_heap_pct_omitted_when_heap_stat_absent(self):
        headline, _, _, _ = self.headline(
            {"node1": {"system_free_mem_pct": "50"}},
            ns_agg={"node1": {"shmem_alloc_bytes": "500"}},
        )
        self.assertEqual(headline["node1"]["allocated_bytes"], "500")
        self.assertNotIn("allocated_heap_pct", headline["node1"])
        self.assertNotIn("allocated_heap_bytes", headline["node1"])

    def test_empty_service_payload_yields_no_capacity_bucket_and_no_total(self):
        """A node that answered with {} observed neither a cgroup limit nor a
        heap, so shmem alone must not render as its allocation total."""
        headline, untracked, no_capacity, _ = self.headline(
            {"node1": {}},
            ns_agg={"node1": {"shmem_alloc_bytes": "500"}},
            nodes=["node1"],
        )
        self.assertEqual(no_capacity, [])
        self.assertEqual(untracked, [])
        self.assertNotIn("allocated_bytes", headline["node1"])
        self.assertEqual(headline["node1"]["allocated_shmem_bytes"], "500")

    def test_node_absent_from_stats_gets_no_row(self):
        headline, untracked, no_capacity, _ = self.headline(
            {}, ns_agg={"node1": {"shmem_alloc_bytes": "500"}}, nodes=["node1"]
        )
        self.assertEqual(no_capacity, [])
        self.assertEqual(untracked, [])
        self.assertNotIn("node1", headline)

    def test_negative_shmem_clamped(self):
        headline, _, _, _ = self.headline(
            {"node1": {"heap_allocated_kbytes": "1000"}},
            ns_agg={"node1": {"shmem_alloc_bytes": "-999999999"}},
        )
        heap = 1000 * 1024
        self.assertEqual(headline["node1"]["allocated_bytes"], str(heap))
        self.assertEqual(float(headline["node1"]["allocated_heap_pct"]), 100.0)

    def test_huge_values_do_not_raise(self):
        headline, _, _, _ = self.headline(
            {
                "node1": {
                    "heap_allocated_kbytes": "1" + "0" * 400,
                    "cgroup_memory_limit_bytes": "1",
                }
            },
            configs={"node1": {"cgroup-mem-tracking": "true"}},
            ns_agg={"node1": {}},
        )
        self.assertNotIn("allocated_bytes", headline["node1"])

    def test_non_dict_inputs_skipped(self):
        headline, _, _, _ = self.headline(
            {"node1": Exception("boom"), "node2": {"heap_allocated_kbytes": "4"}},
            configs={"node2": "not-a-dict"},
            ns_agg={"node2": {}},
        )
        self.assertNotIn("node1", headline)
        self.assertIn("node2", headline)

    def test_restricted_to_given_nodes(self):
        headline, _, _, _ = self.headline(
            {"node1": {"heap_allocated_kbytes": "4"}, "node2": {}},
            ns_agg={"node1": {}, "node2": {}},
            nodes=["node1"],
        )
        self.assertEqual(list(headline.keys()), ["node1"])

    def test_stop_writes_threshold_carried_onto_the_row(self):
        headline, _, _, _ = self.headline(
            {"node1": {"system_free_mem_pct": "12"}},
            ns_agg={"node1": {"stop_writes_sys_memory_pct": "75"}},
        )
        self.assertEqual(headline["node1"]["stop_writes_sys_memory_pct"], "75")

    def test_stop_writes_threshold_absent_when_unconfigured(self):
        headline, _, _, _ = self.headline(
            {"node1": {"system_free_mem_pct": "12"}}, ns_agg={"node1": {}}
        )
        self.assertNotIn("stop_writes_sys_memory_pct", headline["node1"])


class NodesMissingMemoryAllocStatsTest(unittest.TestCase):
    def test_unsupported_builds_are_named(self):
        builds = {
            "new": "8.1.3",
            "newer": "8.2.0",
            "old": "8.1.2",
            "missing": None,
            "empty": "",
            "not_entered": "N/E",
            "unparseable": "not-a-version",
            "errored": Exception("connection refused"),
        }
        self.assertEqual(
            sorted(util.nodes_missing_memory_alloc_stats(builds)),
            ["empty", "errored", "missing", "not_entered", "old", "unparseable"],
        )

    def test_empty_build_map_names_nobody(self):
        for builds in ({}, None):
            with self.subTest(builds=builds):
                self.assertEqual(util.nodes_missing_memory_alloc_stats(builds), [])

    def test_does_not_mutate_its_input(self):
        builds = {"errored": Exception("boom"), "new": "8.1.3"}
        util.nodes_missing_memory_alloc_stats(builds)
        self.assertEqual(sorted(builds), ["errored", "new"])


class MemoryTablesAgreeTest(unittest.TestCase):
    """
    The headline table and the verbose index table must not disagree about
    whether a node's allocation is knowable.
    """

    def _pre_8_1_3_memory_engine_node(self):
        return {
            "node1": {
                "mem_ns": {
                    "storage-engine": "memory",
                    "data_total_bytes": "500",
                    "data_used_bytes": "400",
                    "index_used_bytes": "100",
                }
            }
        }

    def test_both_tables_suppress_their_total_on_an_old_build(self):
        ns_stats = self._pre_8_1_3_memory_engine_node()
        ns_agg = util.aggregate_ns_memory_stats(
            ns_stats, editions={"node1": constants.EDITION_ENTERPRISE}
        )

        self.assertNotIn("total_alloc_bytes", ns_agg["node1"])
        self.assertEqual(ns_agg["node1"]["total_used_bytes"], "500")

        headline, _, _, _ = util.derive_memory_headline(
            util.derive_memory_stats({"node1": {"heap_allocated_kbytes": "1000"}}),
            {},
            ns_agg,
            builds={"node1": "8.1.2"},
        )

        self.assertNotIn("allocated_bytes", headline["node1"])
        self.assertNotIn("allocated_shmem_bytes", headline["node1"])

    def test_both_tables_publish_their_total_on_a_supported_build(self):
        ns_stats = self._pre_8_1_3_memory_engine_node()
        ns_stats["node1"]["mem_ns"]["index_shmem_alloc_bytes"] = "300"
        ns_agg = util.aggregate_ns_memory_stats(
            ns_stats, editions={"node1": constants.EDITION_ENTERPRISE}
        )

        self.assertEqual(ns_agg["node1"]["total_alloc_bytes"], "800")

        headline, _, _, _ = util.derive_memory_headline(
            util.derive_memory_stats({"node1": {"heap_allocated_kbytes": "1000"}}),
            {},
            ns_agg,
            builds={"node1": "8.1.3"},
        )

        self.assertEqual(headline["node1"]["allocated_shmem_bytes"], "800")
        self.assertEqual(headline["node1"]["allocated_bytes"], str(800 + 1000 * 1024))
