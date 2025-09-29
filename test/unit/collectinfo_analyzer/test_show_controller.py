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
from pytest import PytestUnraisableExceptionWarning
from mock import create_autospec, patch, MagicMock
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)
from lib.collectinfo_analyzer.show_controller import ShowUdfsController
from lib.view.view import CliView
from lib.utils import constants


class ShowUdfsControllerTest(unittest.TestCase):
    def setUp(self):
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)
        self.log_handler_mock = create_autospec(CollectinfoLogHandler)
        self.view_mock = create_autospec(CliView)
        self.controller = ShowUdfsController()
        self.controller.log_handler = self.log_handler_mock
        self.controller.view = self.view_mock
        self.controller.mods = {"like": []}

    def tearDown(self):
        warnings.resetwarnings()

    def test_do_default_list_udfs(self):
        """Test showing UDF list (existing functionality)"""
        line = []

        # Mock UDF metadata
        udf_data = {
            "2025-01-01 12:00:00": {
                "192.168.1.1": {
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
        }

        self.log_handler_mock.info_meta_data.return_value = udf_data
        self.log_handler_mock.get_node_id_to_ip_mapping.return_value = {
            "node1": "192.168.1.1"
        }
        self.log_handler_mock.get_principal.return_value = "node1"

        self.controller._do_default(line)

        self.log_handler_mock.info_meta_data.assert_called_with(
            stanza=constants.METADATA_UDF
        )
        self.view_mock.show_udfs.assert_called_once()
        call_args = self.view_mock.show_udfs.call_args
        # Check that the UDF data was passed correctly
        udf_data_arg = call_args[0][0]  # First positional argument
        self.assertIn("test.lua", udf_data_arg)
        self.assertIn("math.lua", udf_data_arg)
        self.assertEqual(call_args[1]["timestamp"], "2025-01-01 12:00:00")

    def test_do_default_single_udf_success(self):
        """Test showing single UDF content successfully"""
        line = ["test.lua"]

        # Mock UDF content data
        udf_content_data = {
            "2025-01-01 12:00:00": {
                "192.168.1.1": {
                    "test.lua": {
                        "type": "LUA",
                        "content": "ZnVuY3Rpb24gdGVzdCgpCiAgcmV0dXJuICJoZWxsbyIKZW5k",  # base64 encoded "function test()\n  return \"hello\"\nend"
                    }
                }
            }
        }

        self.log_handler_mock.info_meta_data.return_value = udf_content_data
        self.log_handler_mock.get_node_id_to_ip_mapping.return_value = {
            "node1": "192.168.1.1"
        }
        self.log_handler_mock.get_principal.return_value = "node1"

        self.controller._do_default(line)

        self.log_handler_mock.info_meta_data.assert_called_with(
            stanza=constants.METADATA_UDF_CONTENT
        )
        self.view_mock.show_single_udf.assert_called_once()

        # Verify the call arguments
        call_args = self.view_mock.show_single_udf.call_args
        udf_info = call_args[0][0]  # First positional argument
        filename = call_args[0][1]  # Second positional argument

        self.assertEqual(filename, "test.lua")
        self.assertEqual(udf_info["Type"], "LUA")
        self.assertEqual(udf_info["Filename"], "test.lua")
        self.assertEqual(udf_info["Content"], 'function test()\n  return "hello"\nend')
        self.assertEqual(call_args[1]["timestamp"], "2025-01-01 12:00:00")

    def test_do_default_single_udf_not_found(self):
        """Test showing single UDF when content not found"""
        line = ["nonexistent.lua"]

        # Mock empty UDF content data
        self.log_handler_mock.info_meta_data.return_value = {}

        with patch("lib.collectinfo_analyzer.show_controller.logger") as mock_logger:
            self.controller._do_default(line)

            mock_logger.error.assert_called_with(
                "UDF content for '%s' not found in collectinfo data", "nonexistent.lua"
            )
            mock_logger.info.assert_called_with(
                "Note: Individual UDF content is only available if collectinfo was generated with UDF content collection enabled"
            )

        # View should not be called when UDF not found
        self.view_mock.show_single_udf.assert_not_called()

    def test_do_default_single_udf_missing_from_content_data(self):
        """Test showing single UDF when filename not in content data"""
        line = ["missing.lua"]

        # Mock UDF content data without the requested file
        udf_content_data = {
            "2025-01-01 12:00:00": {
                "192.168.1.1": {
                    "other.lua": {
                        "type": "LUA",
                        "content": "ZnVuY3Rpb24gb3RoZXIoKQplbmQ=",
                    }
                }
            }
        }

        self.log_handler_mock.info_meta_data.return_value = udf_content_data
        self.log_handler_mock.get_node_id_to_ip_mapping.return_value = {
            "node1": "192.168.1.1"
        }
        self.log_handler_mock.get_principal.return_value = "node1"

        with patch("lib.collectinfo_analyzer.show_controller.logger") as mock_logger:
            self.controller._do_default(line)

            mock_logger.error.assert_called_with(
                "UDF content for '%s' not found in collectinfo data", "missing.lua"
            )

        # View should not be called when UDF not found
        self.view_mock.show_single_udf.assert_not_called()

    def test_do_default_single_udf_base64_decode_error(self):
        """Test handling base64 decode error"""
        line = ["test.lua"]

        # Mock UDF content data with invalid base64
        udf_content_data = {
            "2025-01-01 12:00:00": {
                "192.168.1.1": {
                    "test.lua": {"type": "LUA", "content": "invalid_base64_content!"}
                }
            }
        }

        self.log_handler_mock.info_meta_data.return_value = udf_content_data
        self.log_handler_mock.get_node_id_to_ip_mapping.return_value = {
            "node1": "192.168.1.1"
        }
        self.log_handler_mock.get_principal.return_value = "node1"

        with patch("lib.collectinfo_analyzer.show_controller.logger") as mock_logger:
            self.controller._do_default(line)

            mock_logger.error.assert_called()
            error_call = mock_logger.error.call_args[0]
            self.assertIn("Failed to decode UDF content", error_call[0])
            self.assertEqual(error_call[1], "test.lua")

        # View should not be called when there's a decode error
        self.view_mock.show_single_udf.assert_not_called()

    def test_do_default_single_udf_no_principal_node(self):
        """Test showing single UDF when principal node not found"""
        line = ["test.lua"]

        # Mock UDF content data
        udf_content_data = {
            "2025-01-01 12:00:00": {
                "192.168.1.2": {  # Different IP than principal
                    "test.lua": {
                        "type": "LUA",
                        "content": "ZnVuY3Rpb24gdGVzdCgpCmVuZA==",  # base64 encoded "function test()\nend"
                    }
                }
            }
        }

        self.log_handler_mock.info_meta_data.return_value = udf_content_data
        self.log_handler_mock.get_node_id_to_ip_mapping.return_value = {
            "node1": "192.168.1.1"
        }  # Principal not in data
        self.log_handler_mock.get_principal.return_value = "node1"

        with patch("lib.collectinfo_analyzer.show_controller.logger") as mock_logger:
            self.controller._do_default(line)

            mock_logger.warning.assert_called_with(
                "No UDF content data found for principal node %s. Using a random node instead.",
                "node1",
            )

        # View should still be called with data from available node
        self.view_mock.show_single_udf.assert_called_once()

    def test_do_default_single_udf_empty_content(self):
        """Test showing single UDF with empty content"""
        line = ["empty.lua"]

        # Mock UDF content data with empty content
        udf_content_data = {
            "2025-01-01 12:00:00": {
                "192.168.1.1": {
                    "empty.lua": {"type": "LUA", "content": ""}  # Empty base64 content
                }
            }
        }

        self.log_handler_mock.info_meta_data.return_value = udf_content_data
        self.log_handler_mock.get_node_id_to_ip_mapping.return_value = {
            "node1": "192.168.1.1"
        }
        self.log_handler_mock.get_principal.return_value = "node1"

        self.controller._do_default(line)

        self.view_mock.show_single_udf.assert_called_once()

        # Verify the call arguments
        call_args = self.view_mock.show_single_udf.call_args
        udf_info = call_args[0][0]
        filename = call_args[0][1]

        self.assertEqual(filename, "empty.lua")
        self.assertEqual(udf_info["Content"], "")  # Should be empty string after decode

    def test_do_default_single_udf_missing_type(self):
        """Test showing single UDF when type field is missing"""
        line = ["test.lua"]

        # Mock UDF content data without type field
        udf_content_data = {
            "2025-01-01 12:00:00": {
                "192.168.1.1": {
                    "test.lua": {
                        # Missing "type" field
                        "content": "ZnVuY3Rpb24gdGVzdCgpCmVuZA=="
                    }
                }
            }
        }

        self.log_handler_mock.info_meta_data.return_value = udf_content_data
        self.log_handler_mock.get_node_id_to_ip_mapping.return_value = {
            "node1": "192.168.1.1"
        }
        self.log_handler_mock.get_principal.return_value = "node1"

        self.controller._do_default(line)

        self.view_mock.show_single_udf.assert_called_once()

        # Verify the call arguments - should default to "Unknown" for missing type
        call_args = self.view_mock.show_single_udf.call_args
        udf_info = call_args[0][0]

        self.assertEqual(udf_info["Type"], "Unknown")
        self.assertEqual(udf_info["Content"], "function test()\nend")

    def test_do_default_single_udf_with_modifiers(self):
        """Test showing single UDF with modifiers (should ignore them)"""
        line = ["test.lua", "like", "test"]

        # Mock UDF content data
        udf_content_data = {
            "2025-01-01 12:00:00": {
                "192.168.1.1": {
                    "test.lua": {
                        "type": "LUA",
                        "content": "ZnVuY3Rpb24gdGVzdCgpCmVuZA==",
                    }
                }
            }
        }

        self.log_handler_mock.info_meta_data.return_value = udf_content_data
        self.log_handler_mock.get_node_id_to_ip_mapping.return_value = {
            "node1": "192.168.1.1"
        }
        self.log_handler_mock.get_principal.return_value = "node1"

        self.controller._do_default(line)

        # Should still call show_single_udf with the filename, ignoring modifiers
        self.view_mock.show_single_udf.assert_called_once()
        call_args = self.view_mock.show_single_udf.call_args
        filename = call_args[0][1]
        self.assertEqual(filename, "test.lua")

    def test_get_udf_content_from_collectinfo_exception_handling(self):
        """Test exception handling in _get_udf_content_from_collectinfo"""
        # Mock an exception when accessing log handler
        self.log_handler_mock.info_meta_data.side_effect = Exception("Connection error")

        with patch("lib.collectinfo_analyzer.show_controller.logger") as mock_logger:
            result = self.controller._get_udf_content_from_collectinfo("test.lua")

            self.assertIsNone(result)
            mock_logger.warning.assert_called_with(
                "Failed to retrieve UDF content for '%s' from collectinfo: %s",
                "test.lua",
                self.log_handler_mock.info_meta_data.side_effect,
            )
