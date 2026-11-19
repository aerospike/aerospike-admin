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

import hashlib
import os
import shutil
import tempfile
import unittest

from mock import patch

from lib.log_analyzer.log_handler.log_handler import LogHandler
from lib.log_analyzer.log_handler.log_reader import LogReader
from lib.log_analyzer.log_handler.server_log import ServerLog

_real_md5 = hashlib.md5

FIRST = "Nov 16 2026 08:00:00 GMT: INFO (info): (ticker.c:160) cluster-size 1"
REPEAT = "Nov 16 2026 08:00:01 GMT: INFO (info): (ticker.c:160) cluster-size 1"
OTHER = "Nov 16 2026 08:00:02 GMT: INFO (info): (ticker.c:160) cluster-size 2"


def _fips_md5(data=b"", *, usedforsecurity=True):
    """MD5 as OpenSSL serves it on a FIPS host: refused unless marked non-security."""
    if usedforsecurity:
        raise ValueError("[digital envelope routines] unsupported")
    return _real_md5(data, usedforsecurity=False)


class Md5InFipsModeTest(unittest.TestCase):
    def setUp(self):
        self.log_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.log_dir)
        self.log_file = os.path.join(self.log_dir, "aerospike.log")
        with open(self.log_file, "w") as f:
            f.write("\n".join([FIRST, REPEAT, OTHER]) + "\n")

    def _unique_lines(self):
        log = ServerLog("node", self.log_file, LogReader())
        self.addCleanup(log.file_stream.close)
        log.set_input(
            search_strs="cluster-size", start_tm=log.get_start_tm("head"), uniq=True
        )
        lines = []
        line = log.next_line()
        while line:
            lines.append(line.strip())
            line = log.next_line()
        return lines

    def test_log_without_node_id_is_keyed_by_md5_in_fips_mode(self):
        expected = ("MD5_" + _real_md5(self.log_file.encode("utf-8")).hexdigest())[
            :15
        ] + " "

        with patch(
            "lib.log_analyzer.log_handler.log_handler.hashlib.md5",
            side_effect=_fips_md5,
        ):
            handler = LogHandler(self.log_dir)

        self.assertEqual([expected], list(handler.all_logs))

    def test_unique_lines_skip_repeats(self):
        self.assertEqual([FIRST, OTHER], self._unique_lines())

    def test_unique_lines_in_fips_mode(self):
        with patch(
            "lib.log_analyzer.log_handler.server_log.hashlib.md5",
            side_effect=_fips_md5,
        ):
            self.assertEqual([FIRST, OTHER], self._unique_lines())
