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
    import asynctest

from lib.utils import util


class UtilTest(asynctest.TestCase):
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
        await self.assertAsyncRaises(
            asyncio.TimeoutError, asyncio.wait_for(cached_tester(1, 2, 5), 0.1)
        )

        # Key is in the cache but it is dirty because of the sleep. So it is a miss.
        await asyncio.sleep(5)
        await self.assertAsyncRaises(
            asyncio.TimeoutError, asyncio.wait_for(cached_tester(1, 2, 0.2), 0.1)
        )
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
        await self.assertAsyncRaises(
            Exception, asyncio.wait_for(cached_tester_exc(), 0.1)
        )
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
            "blob_indexing": "6.0.0"
        }
        
        builds = {
            "node1": "6.1.0",
            "node2": "6.2.0",
            "node3": "6.0.1"
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {
            "cdt_indexing": True,        # 6.0.1 >= 5.6.0
            "expression_indexing": True, # 6.0.1 >= 5.7.0
            "blob_indexing": True        # 6.0.1 >= 6.0.0
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_mixed_support(self):
        """Test when some features are supported and others are not."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0",
            "blob_indexing": "6.0.0"
        }
        
        builds = {
            "node1": "6.1.0",
            "node2": "5.8.0",  # Oldest node
            "node3": "6.2.0"
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {
            "cdt_indexing": True,        # 5.8.0 >= 5.6.0
            "expression_indexing": True, # 5.8.0 >= 5.7.0
            "blob_indexing": False       # 5.8.0 < 6.0.0
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_no_features_supported(self):
        """Test when no features are supported due to old nodes."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0",
            "blob_indexing": "6.0.0"
        }
        
        builds = {
            "node1": "5.5.0",  # Very old node
            "node2": "5.4.0",  # Even older
            "node3": "5.6.0"   # Just at the edge
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {
            "cdt_indexing": False,       # 5.4.0 < 5.6.0
            "expression_indexing": False, # 5.4.0 < 5.7.0
            "blob_indexing": False       # 5.4.0 < 6.0.0
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_empty_builds(self):
        """Test when no builds are provided (empty cluster)."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0"
        }
        
        builds = {}
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {
            "cdt_indexing": False,       # No nodes = no support
            "expression_indexing": False  # No nodes = no support
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_single_node(self):
        """Test with a single node cluster."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0"
        }
        
        builds = {
            "node1": "5.8.0"
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {
            "cdt_indexing": True,        # 5.8.0 >= 5.6.0
            "expression_indexing": True  # 5.8.0 >= 5.7.0
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_exact_version_match(self):
        """Test when node version exactly matches feature requirement."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0"
        }
        
        builds = {
            "node1": "5.6.0",  # Exact match for cdt_indexing
            "node2": "5.7.0"   # Exact match for expression_indexing
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        # Minimum build version is 5.6.0
        expected = {
            "cdt_indexing": True,        # 5.6.0 >= 5.6.0
            "expression_indexing": False # 5.6.0 < 5.7.0
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_complex_version_strings(self):
        """Test with complex version strings including pre-release versions."""
        feature_versions = {
            "feature_a": "5.6.0",
            "feature_b": "5.7.0",
            "feature_c": "6.0.0"
        }
        
        builds = {
            "node1": "5.6.0a1",  # Pre-release version
            "node2": "5.7.0b2",  # Beta version
            "node3": "6.0.0rc1"  # Release candidate
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        # Minimum build version is 5.6.0a1
        # LooseVersion handles pre-release versions correctly
        expected = {
            "feature_a": True,   # 5.6.0a1 >= 5.6.0
            "feature_b": False,  # 5.6.0a1 < 5.7.0
            "feature_c": False   # 5.6.0a1 < 6.0.0
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_edge_case_versions(self):
        """Test edge cases with unusual version formats."""
        feature_versions = {
            "feature_a": "1.0.0",
            "feature_b": "2.0.0"
        }
        
        builds = {
            "node1": "1.0.0.0",  # Extra version component
            "node2": "2.0",      # Missing patch version
            "node3": "1.9.9"     # Just below 2.0.0
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {
            "feature_a": True,   # 1.0.0.0 >= 1.0.0
            "feature_b": False   # 1.9.9 < 2.0.0
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_empty_feature_versions(self):
        """Test with empty feature versions dictionary."""
        feature_versions = {}
        builds = {
            "node1": "6.1.0",
            "node2": "6.2.0"
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {}
        self.assertEqual(result, expected)

    async def test_check_version_support_large_cluster(self):
        """Test with a large number of nodes."""
        feature_versions = {
            "cdt_indexing": "5.6.0",
            "expression_indexing": "5.7.0"
        }
        
        # Create a large cluster with mixed versions
        builds = {}
        for i in range(100):
            if i < 50:
                builds[f"node{i}"] = "6.1.0"  # Newer nodes
            else:
                builds[f"node{i}"] = "5.5.0"  # Older nodes
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {
            "cdt_indexing": False,       # 5.5.0 < 5.6.0
            "expression_indexing": False  # 5.5.0 < 5.7.0
        }
        
        self.assertEqual(result, expected)

    async def test_check_version_support_invalid_version_strings(self):
        """Test with invalid version strings - should raise exception."""
        feature_versions = {
            "feature_a": "5.6.0",
            "feature_b": "invalid_version"
        }
        
        builds = {
            "node1": "5.8.0",
            "node2": "also_invalid"
        }
        
        # Should raise TypeError when LooseVersion can't handle invalid strings
        with self.assertRaises(TypeError):
            await util.check_version_support(feature_versions, builds)

    async def test_check_version_support_none_values(self):
        """Test with None values in builds - should raise exception."""
        feature_versions = {
            "cdt_indexing": "5.6.0"
        }
        
        builds = {
            "node1": "6.1.0",
            "node2": None,
            "node3": "5.8.0"
        }
        
        # Should raise AttributeError when trying to create LooseVersion from None
        with self.assertRaises(AttributeError):
            await util.check_version_support(feature_versions, builds)

    async def test_check_version_support_unicode_versions(self):
        """Test with unicode version strings."""
        feature_versions = {
            "feature_a": "5.6.0",
            "feature_b": "6.0.0"
        }
        
        builds = {
            "node1": "5.8.0",
            "node2": "6.1.0",
            "node3": "5.7.0"
        }
        
        result = await util.check_version_support(feature_versions, builds)
        
        expected = {
            "feature_a": True,   # 5.7.0 >= 5.6.0
            "feature_b": False   # 5.7.0 < 6.0.0
        }
        
        self.assertEqual(result, expected)
    
