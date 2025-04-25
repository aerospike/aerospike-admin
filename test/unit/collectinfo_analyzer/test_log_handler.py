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
import os
import tempfile
import shutil
from mock import patch
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