# Copyright 2013-2021 Aerospike, Inc.
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

import datetime
import re
import time
import logging

from lib.utils import util, constants

DT_TO_MINUTE_FMT = "%b %d %Y %H:%M"
DT_TIME_FMT = "%H:%M:%S"
DATE_SEG = 0
DATE_SEPARATOR = "-"
YEAR = 0
MONTH = 1
DATE = 2

TIME_SEG = 1
TIME_SEPARATOR = ":"
HH = 0
MM = 1
SS = 2

INDEX_DT_LEN = 4
STEP = 1000

SERVER_ID_FETCH_READ_SIZE = 10000
FILE_READ_ENDS = ["tail", "head"]


class LogReader(object):
    server_log_ext = "/aerospike.log"
    server_log_file_identifier = ["thr_info.c::", "heartbeat_received", "Cluster_size"]
    server_log_file_identifier_pattern = r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{2} \d{4} \d{2}:\d{2}:\d{2}(\.\d+){0,3} GMT([-+]\d+){0,1}: (?:INFO|WARNING|DEBUG|DETAIL) \([a-z_:]+\): \([A-Za-z_\.\[\]]+:{1,2}-?[\d]+\)"
    logger = logging.getLogger("asadm")

    def get_server_node_id(
        self, file, fetch_end="tail", read_block_size=SERVER_ID_FETCH_READ_SIZE
    ):
        if not fetch_end or fetch_end not in FILE_READ_ENDS:
            fetch_end = "tail"
        if not read_block_size:
            read_block_size = SERVER_ID_FETCH_READ_SIZE
        not_found = ""
        # pattern for logs of old server (< 3.9) is "node id "
        # pattern for logs of new server (>= 3.9) is "NODE-ID "
        server_log_node_identifiers = ["node id ", "NODE-ID "]
        server_node_id_pattern = r"%s([0-9a-fA-F]+(\s|$))"

        block_to_check = 100

        if not file:
            return not_found
        try:
            out, err = util.shell_command(
                ['%s -n %d "%s"' % (fetch_end, read_block_size, file)]
            )
        except Exception:
            return not_found
        if err or not out:
            return not_found
        lines = out.strip().split("\n")
        try:
            if lines:
                fetched_line_count = len(lines)
                end_index = fetched_line_count
                start_index = end_index - (
                    block_to_check if block_to_check < end_index else end_index
                )
                while start_index >= 0 and start_index < end_index:
                    one_string = " ".join(lines[start_index:end_index])
                    if any(id in one_string for id in server_log_node_identifiers):
                        for line in reversed(lines[start_index:end_index]):
                            for id in server_log_node_identifiers:
                                if id in line:
                                    try:
                                        node_id = re.search(
                                            server_node_id_pattern % (id), line.strip()
                                        ).group(1)
                                        if node_id:
                                            return node_id
                                    except Exception:
                                        pass
                    end_index = start_index
                    start_index = end_index - (
                        block_to_check if block_to_check < end_index else end_index
                    )
        except Exception:
            pass
        if fetch_end == "tail":
            return self.get_server_node_id(
                file=file, fetch_end="head", read_block_size=read_block_size
            )
        return not_found

    def is_server_log_file(self, file=""):
        if not file:
            return False
        try:
            out, err = util.shell_command(['head -n 10 "%s"' % (file)])
        except Exception:
            return False
        if err or not out:
            return False
        lines = out.strip().split("\n")
        matched_count = 0
        for line in lines:
            try:
                if re.search(self.server_log_file_identifier_pattern, line):
                    matched_count += 1
            except Exception:
                pass
        if matched_count > (len(lines) // 2):
            return True
        return False

    def get_grep_string(self, strs, file, is_and=False, is_casesensitive=True):
        search_str = ""
        if not strs:
            return search_str
        if not isinstance(strs, list):
            return search_str

        grep_cmd = "grep "
        if not is_casesensitive:
            grep_cmd += "-i "
        g_str = strs[0]
        if is_and:
            search_str = '%s "%s" "%s"' % (grep_cmd, g_str, file)
            for str in strs[1 : len(strs)]:
                search_str += "|" + '%s "%s"' % (grep_cmd, str)
        else:
            for str in strs[1 : len(strs)]:
                g_str += "\\|" + str
            search_str = '%s "%s" "%s"' % (grep_cmd, g_str, file)
        return search_str

    def parse_timedelta(self, arg):
        toks = arg.split(":")
        num_toks = len(toks)
        if num_toks > 3:
            return 0
        toks.reverse()
        try:
            arg_seconds = int(toks[0].strip())
            if num_toks > 1:
                arg_seconds = arg_seconds + (60 * int(toks[1].strip()))
            if num_toks > 2:
                arg_seconds = arg_seconds + (3600 * int(toks[2].strip()))
        except Exception:
            return 0
        return datetime.timedelta(seconds=arg_seconds)

    def parse_init_dt(self, arg_from, tail_dt):
        if arg_from.startswith("-"):
            # Relative start time:
            try:
                init_dt = tail_dt - self.parse_timedelta(arg_from.strip("- "))
            except Exception:
                self.logger.warning(
                    "Ignoring relative start time. Can't parse relative start time "
                    + arg_from
                )
                return 0
        else:
            # Absolute start time:
            try:
                init_dt = datetime.datetime(
                    *(time.strptime(arg_from, constants.DT_FMT)[0:6])
                )
            except Exception as e:
                self.logger.warning(
                    "Ignoring absolute start time. Can't parse absolute start time "
                    + arg_from
                    + " "
                    + str(e)
                )
                return 0
        return init_dt

    def _get_dt(self, line):
        return line[0 : line.find(" GMT")]

    def parse_dt(self, line, dt_len=6):
        line = util.bytes_to_str(line)
        prefix = line[0 : line.find(" GMT")].split(",")[0]
        # remove milliseconds if available
        prefix = prefix.split(".")[0]
        return datetime.datetime(*(time.strptime(prefix, constants.DT_FMT)[0:dt_len]))

    def _seek_to(self, file_stream, char):
        if file_stream and char:
            if file_stream.tell() <= 0:
                file_stream.seek(0, 0)
            else:
                tmp = file_stream.read(1)
                while tmp != char:
                    if file_stream.tell() <= 1:
                        file_stream.seek(0, 0)
                        break
                    file_stream.seek(-2, 1)
                    tmp = file_stream.read(1)

    def set_next_line(self, file_stream, jump=STEP, whence=1):
        file_stream.seek(int(jump), whence)
        self._seek_to(file_stream, b"\n")

    def read_next_line(self, file_stream, jump=STEP, whence=1):
        file_stream.seek(int(jump), whence)
        self._seek_to(file_stream, b"\n")
        ln = self.read_line(file_stream)
        return ln

    def _get_next_timestamp(self, f, min, max, last):
        self.set_next_line(f, max, 0)
        max = f.tell()
        self.set_next_line(f, min, 0)
        min = f.tell()
        if min >= max:
            f.seek(max)
            tm = self.parse_dt(self.read_line(f), dt_len=INDEX_DT_LEN)

            if tm > last:
                return max, tm
            else:
                return None, None
        if min == max:
            f.seek(min)
            tm = self.parse_dt(self.read_line(f), dt_len=INDEX_DT_LEN)

            if tm > last:
                return min, tm
            else:
                return None, None

        jump = (max - min) // 2
        f.seek(int(jump) + min, 0)
        self._seek_to(f, b"\n")
        last_read = f.tell()
        ln = self.read_line(f)
        tm = self.parse_dt(ln, dt_len=INDEX_DT_LEN)

        if tm <= last:
            return self._get_next_timestamp(f, f.tell(), max, last)
        else:
            return self._get_next_timestamp(f, min, last_read, last)

    def generate_server_log_indices(self, file_path):
        indices = {}
        f = open(file_path, "rb")  # binary mode to enable relative seeks in Python3
        start_timestamp = self.parse_dt(self.read_line(f), dt_len=INDEX_DT_LEN)
        indices[start_timestamp.strftime(constants.DT_FMT)] = 0
        min_seek_pos = 0
        f.seek(0, 2)
        self.set_next_line(f, 0)
        last_pos = f.tell()
        f.seek(0, 0)
        last_timestamp = start_timestamp

        while True:
            if last_pos < (min_seek_pos + STEP):
                ln = self.read_next_line(f, last_pos, 0)
            else:
                ln = self.read_next_line(f)
            current_jump = 1000
            while self.parse_dt(ln, dt_len=INDEX_DT_LEN) <= last_timestamp:
                min_seek_pos = f.tell()
                if last_pos < (min_seek_pos + current_jump):
                    ln = self.read_next_line(f, last_pos, 0)
                    break
                else:
                    ln = self.read_next_line(f, current_jump)
                current_jump *= 2

            if self.parse_dt(ln, dt_len=INDEX_DT_LEN) <= last_timestamp:
                break

            max_seek_pos = f.tell()
            pos, tm = self._get_next_timestamp(
                f, min_seek_pos, max_seek_pos, last_timestamp
            )
            if not tm and not pos:
                break
            indices[tm.strftime(constants.DT_FMT)] = pos
            f.seek(pos)
            min_seek_pos = pos
            last_timestamp = tm

        return indices

    def read_line(self, f):
        if not f:
            return None

        ln = None
        while True:
            try:
                # checking for valid line with timestamp
                ln = f.readline()
                if isinstance(
                    ln, bytes
                ):  # need this check for serverlog.py's reading in binary mode
                    ln = util.bytes_to_str(ln)
                self.parse_dt(ln)
                break
            except Exception:
                pass

        return ln
