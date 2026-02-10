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

import os
import shutil
import tempfile
import unittest

from mock import patch

from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)
from lib.utils import log_util


class LogUtilTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    @patch("platform.system")
    def test_get_all_files_on_darwin(self, mock_system):
        # Simulate macOS platform
        mock_system.return_value = "Darwin"

        # Create test files
        regular_file = os.path.join(self.temp_dir, "test.log")
        resource_fork_file = os.path.join(self.temp_dir, "._test.log")

        with open(regular_file, "w") as f:
            f.write("log content")
        with open(resource_fork_file, "w") as f:
            f.write("resource fork content")

        # Test get_all_files method
        files = log_util.get_all_files(self.temp_dir)

        # Assert resource fork file is excluded on Darwin
        self.assertIn("test.log", [os.path.basename(f) for f in files])
        self.assertNotIn("._test.log", [os.path.basename(f) for f in files])

    @patch("platform.system")
    def test_get_all_files_on_linux(self, mock_system):
        # Simulate Linux platform
        mock_system.return_value = "Linux"

        # Create test files
        regular_file = os.path.join(self.temp_dir, "test.log")
        resource_fork_file = os.path.join(self.temp_dir, "._test.log")

        with open(regular_file, "w") as f:
            f.write("log content")
        with open(resource_fork_file, "w") as f:
            f.write("resource fork content")

        # Test get_all_files method
        files = log_util.get_all_files(self.temp_dir)

        # Assert both files are included on Linux
        self.assertIn("test.log", [os.path.basename(f) for f in files])
        self.assertIn("._test.log", [os.path.basename(f) for f in files])


class CollectinfoLogHandlerTest(unittest.TestCase):
    def test_info_masking_rules_method_exists(self):
        """Test that info_masking_rules method exists"""
        # Just test that the method exists and is callable
        self.assertTrue(hasattr(CollectinfoLogHandler, "info_masking_rules"))
        self.assertTrue(callable(getattr(CollectinfoLogHandler, "info_masking_rules")))

    @patch(
        "lib.collectinfo_analyzer.collectinfo_handler.log_handler.CollectinfoLogHandler._fetch_from_cinfo_log"
    )
    def test_info_masking_rules_calls_fetch(self, fetch_mock):
        """Test that info_masking_rules calls _fetch_from_cinfo_log with correct type"""
        from mock import MagicMock

        # Mock the _fetch_from_cinfo_log method
        fetch_mock.return_value = {"timestamp": {"node1": []}}

        # Create a mock handler instance
        handler = MagicMock(spec=CollectinfoLogHandler)
        handler._fetch_from_cinfo_log = fetch_mock

        # Call the actual method
        CollectinfoLogHandler.info_masking_rules(handler)

        # Verify it was called with the correct type
        fetch_mock.assert_called_once_with(type="masking")

    def test_info_release_method_exists(self):
        """Test that info_release method exists"""
        # Just test that the method exists and is callable
        self.assertTrue(hasattr(CollectinfoLogHandler, "info_release"))
        self.assertTrue(callable(getattr(CollectinfoLogHandler, "info_release")))

    @patch(
        "lib.collectinfo_analyzer.collectinfo_handler.log_handler.CollectinfoLogHandler._fetch_from_cinfo_log"
    )
    def test_info_release_calls_fetch(self, fetch_mock):
        """Test that info_release calls _fetch_from_cinfo_log with correct type and stanza"""
        from mock import MagicMock

        # Mock the _fetch_from_cinfo_log method
        fetch_mock.return_value = {
            "timestamp": {
                "node1": {
                    "arch": "linux-x64",
                    "edition": "enterprise",
                    "version": "8.1.1",
                    "os": "el9",
                }
            }
        }

        # Create a mock handler instance
        handler = MagicMock(spec=CollectinfoLogHandler)
        handler._fetch_from_cinfo_log = fetch_mock

        # Call the actual method
        CollectinfoLogHandler.info_release(handler)

        # Verify it was called with the correct type and stanza
        fetch_mock.assert_called_once_with(type="meta_data", stanza="release")
