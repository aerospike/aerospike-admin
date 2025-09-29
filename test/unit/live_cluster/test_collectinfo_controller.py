# Copyright 2025 Aerospike, Inc.
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
import warnings
import asyncio
from pytest import PytestUnraisableExceptionWarning
from mock import create_autospec, patch, AsyncMock, MagicMock
from lib.live_cluster.collectinfo_controller import CollectinfoController
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.get_controller import GetUdfController


class CollectinfoControllerUdfTest(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.controller = CollectinfoController()
        self.cluster_mock = create_autospec(Cluster)
        self.controller.cluster = self.cluster_mock

    def tearDown(self):
        warnings.resetwarnings()

    async def test_collect_udf_content_success(self):
        """Test successful UDF content collection"""
        # Mock UDF list data
        udf_data = {
            "node1": {
                "test.lua": {"filename": "test.lua", "hash": "abc123", "type": "LUA"},
                "math.lua": {"filename": "math.lua", "hash": "def456", "type": "LUA"},
            }
        }

        # Mock UDF content responses
        test_udf_content = {
            "node1": {
                "type": "LUA",
                "content": "ZnVuY3Rpb24gdGVzdCgpCmVuZA==",  # base64 encoded "function test()\nend"
            }
        }

        math_udf_content = {
            "node1": {
                "type": "LUA",
                "content": "ZnVuY3Rpb24gbWF0aCgpCmVuZA==",  # base64 encoded "function math()\nend"
            }
        }

        with patch.object(self.controller, "cluster") as cluster_mock:
            # Mock GetUdfController
            with patch(
                "lib.live_cluster.collectinfo_controller.GetUdfController"
            ) as mock_udf_controller_class:
                mock_udf_controller = AsyncMock()
                mock_udf_controller_class.return_value = mock_udf_controller

                # Mock the get_udf calls
                mock_udf_controller.get_udf.side_effect = [
                    test_udf_content,
                    math_udf_content,
                ]

                result = await self.controller._collect_udf_content(udf_data)

                # Verify GetUdfController was created with cluster
                mock_udf_controller_class.assert_called_once_with(cluster_mock)

                # Verify get_udf was called for each UDF
                self.assertEqual(mock_udf_controller.get_udf.call_count, 2)
                mock_udf_controller.get_udf.assert_any_call(
                    nodes="principal", filename="test.lua"
                )
                mock_udf_controller.get_udf.assert_any_call(
                    nodes="principal", filename="math.lua"
                )

                # Verify result structure
                self.assertIn("node1", result)
                self.assertIn("test.lua", result["node1"])
                self.assertIn("math.lua", result["node1"])
                self.assertEqual(result["node1"]["test.lua"]["type"], "LUA")
                self.assertEqual(result["node1"]["math.lua"]["type"], "LUA")

    async def test_collect_udf_content_no_udfs(self):
        """Test UDF content collection when no UDFs exist"""
        udf_data = {"node1": {}}

        result = await self.controller._collect_udf_content(udf_data)

        # Should return empty content map
        self.assertEqual(result, {"node1": {}})

    async def test_collect_udf_content_exception_in_udf_data(self):
        """Test UDF content collection when UDF data contains exceptions"""
        udf_data = {
            "node1": Exception("Connection failed"),
            "node2": {
                "test.lua": {"filename": "test.lua", "hash": "abc123", "type": "LUA"}
            },
        }

        # Mock UDF content response for node2
        test_udf_content = {
            "node2": {"type": "LUA", "content": "ZnVuY3Rpb24gdGVzdCgpCmVuZA=="}
        }

        with patch.object(self.controller, "cluster") as cluster_mock:
            with patch(
                "lib.live_cluster.collectinfo_controller.GetUdfController"
            ) as mock_udf_controller_class:
                mock_udf_controller = AsyncMock()
                mock_udf_controller_class.return_value = mock_udf_controller
                mock_udf_controller.get_udf.return_value = test_udf_content

                result = await self.controller._collect_udf_content(udf_data)

                # Should only collect from node2, skip node1 with exception
                mock_udf_controller.get_udf.assert_called_once_with(
                    nodes="principal", filename="test.lua"
                )

                # Both nodes should have content map (node1 gets copy of collected content)
                self.assertIn("node1", result)
                self.assertIn("node2", result)
                self.assertIn("test.lua", result["node1"])
                self.assertIn("test.lua", result["node2"])

    async def test_collect_udf_content_get_udf_exception(self):
        """Test UDF content collection when get_udf raises exception"""
        udf_data = {
            "node1": {
                "test.lua": {"filename": "test.lua", "hash": "abc123", "type": "LUA"}
            }
        }

        with patch.object(self.controller, "cluster") as cluster_mock:
            with patch(
                "lib.live_cluster.collectinfo_controller.GetUdfController"
            ) as mock_udf_controller_class:
                mock_udf_controller = AsyncMock()
                mock_udf_controller_class.return_value = mock_udf_controller
                mock_udf_controller.get_udf.return_value = Exception("UDF get failed")

                with patch(
                    "lib.live_cluster.collectinfo_controller.logger"
                ) as mock_logger:
                    result = await self.controller._collect_udf_content(udf_data)

                    # Should log warning about failed UDF collection
                    mock_logger.warning.assert_called()
                    warning_call = mock_logger.warning.call_args[0]
                    self.assertIn("Failed to collect content for UDF", warning_call[0])
                    self.assertEqual(warning_call[1], "test.lua")

                    # Should return empty content for the node
                    self.assertEqual(result, {"node1": {}})

    async def test_collect_udf_content_asyncio_gather_exception(self):
        """Test UDF content collection when asyncio.gather raises exception"""
        udf_data = {
            "node1": {
                "test.lua": {"filename": "test.lua", "hash": "abc123", "type": "LUA"}
            }
        }

        with patch.object(self.controller, "cluster") as cluster_mock:
            with patch(
                "lib.live_cluster.collectinfo_controller.GetUdfController"
            ) as mock_udf_controller_class:
                mock_udf_controller = AsyncMock()
                mock_udf_controller_class.return_value = mock_udf_controller

                # Mock asyncio.gather to raise exception
                with patch(
                    "lib.live_cluster.collectinfo_controller.asyncio.gather"
                ) as mock_gather:
                    mock_gather.side_effect = Exception("Gather failed")

                    with patch(
                        "lib.live_cluster.collectinfo_controller.logger"
                    ) as mock_logger:
                        result = await self.controller._collect_udf_content(udf_data)

                        # Should log warning about failed UDF content collection
                        mock_logger.warning.assert_called_with(
                            "Failed to collect UDF content: %s", mock_gather.side_effect
                        )

                        # Should return empty content map
                        self.assertEqual(result, {"node1": {}})

    async def test_collect_udf_content_principal_node_exception(self):
        """Test UDF content collection when principal node returns exception"""
        udf_data = {
            "node1": {
                "test.lua": {"filename": "test.lua", "hash": "abc123", "type": "LUA"}
            }
        }

        # Mock UDF content response with exception from principal node
        test_udf_content = {"principal_node": Exception("Principal node failed")}

        with patch.object(self.controller, "cluster") as cluster_mock:
            with patch(
                "lib.live_cluster.collectinfo_controller.GetUdfController"
            ) as mock_udf_controller_class:
                mock_udf_controller = AsyncMock()
                mock_udf_controller_class.return_value = mock_udf_controller
                mock_udf_controller.get_udf.return_value = test_udf_content

                result = await self.controller._collect_udf_content(udf_data)

                # Should skip UDF with exception from principal node
                self.assertEqual(result, {"node1": {}})


# Test runner for async tests
def run_async_test(test_func):
    """Helper to run async test functions"""

    def wrapper(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(test_func(self))
        finally:
            loop.close()

    return wrapper


# Apply async test runner to all async test methods
for attr_name in dir(CollectinfoControllerUdfTest):
    attr = getattr(CollectinfoControllerUdfTest, attr_name)
    if (
        callable(attr)
        and attr_name.startswith("test_")
        and asyncio.iscoroutinefunction(attr)
    ):
        setattr(CollectinfoControllerUdfTest, attr_name, run_async_test(attr))
