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

from parameterized import parameterized

from lib.utils import file_size


class FileSizeTest(unittest.TestCase):
    @parameterized.expand(
        [
            (0, "0.000 B  "),
            (2, "2.000 B  "),
            (2 * 1024, "2.000 KiB"),
            (2 * 1024**2, "2.000 MiB"),
            (2 * 1024**3, "2.000 GiB"),
            (2 * 1024**4, "2.000 TiB"),
            (2 * 1024**5, "2.000 PiB"),
            (1000000, "976.562 KiB"),
        ]
    )
    def test_size_byte(self, value, expected):
        self.assertEqual(file_size.size(value), expected)

    def test_byte_suffixes_equal_width(self):
        widths = {len(suffix) for _, suffix in file_size.byte}
        self.assertEqual(len(widths), 1)

    @parameterized.expand(
        [
            (2000, "2.000 K"),
            (2 * 1000**3, "2.000 G"),
        ]
    )
    def test_size_si_float(self, value, expected):
        self.assertEqual(file_size.size(value, file_size.si_float), expected)

    @parameterized.expand(
        [
            ("2",),
            ("2.5",),
            (3,),
            ("2.000 B  ",),
            ("2.000 KiB",),
            ("2.000 MiB",),
            ("2.000 GiB",),
            ("2.000 TiB",),
            ("2.000 PiB",),
            ("2.000 B ",),
            ("2.000 KB",),
            ("2.000 MB",),
            ("2.000 GB",),
            ("2.000 TB",),
            ("2.000 PB",),
            ("2.000 K",),
            ("2.000 secs",),
        ]
    )
    def test_is_file_size_true(self, value):
        self.assertTrue(file_size.is_file_size(value))

    @parameterized.expand(
        [
            ("abc",),
            ("2.000 XB",),
            ("N/E",),
            ("",),
        ]
    )
    def test_is_file_size_false(self, value):
        self.assertFalse(file_size.is_file_size(value))
