# Copyright 2026 Aerospike, Inc.
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

import types
import unittest

from lib.view import terminal
from lib.view.terminal import terminal as terminal_module


class TerminalExportsTest(unittest.TestCase):
    def test_package_exposes_every_public_name_of_terminal_module(self):
        public = {
            name
            for name, value in vars(terminal_module).items()
            if not name.startswith("_") and not isinstance(value, types.ModuleType)
        }

        self.assertEqual(set(terminal_module.__all__), public)
        self.assertEqual(set(terminal.__all__), public | {"get_terminal_size"})
        for name in terminal.__all__:
            self.assertTrue(hasattr(terminal, name), name)


if __name__ == "__main__":
    unittest.main()
