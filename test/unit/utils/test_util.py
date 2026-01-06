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

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import unittest

from lib.utils import util


class UtilTest(unittest.IsolatedAsyncioTestCase):
    def test_get_value_from_dict(self):
        value = {"a": 123, "b": "8.9", "c": "abc"}

        self.assertEqual(
            util.get_value_from_dict(value, "a"),
            123,
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(value, ("b"), return_type=float),
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
