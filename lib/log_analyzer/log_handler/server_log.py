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
import hashlib
import pipes
import re
import subprocess
from collections import OrderedDict

from lib import utils
from lib.utils import constants

from .log_latency import LogLatency
from . import util

READ_BLOCK_BYTES = 4096
RETURN_REQUIRED_EVERY_NTH_BLOCK = 5
TIME_ZONE = "GMT"
SERVER_LOG_LINE_WRITER_INFO_PATTERN = (
    r"(?:INFO|WARNING|DEBUG|DETAIL) \([a-z_:]+\): \(([^\)]+)\)"
)


class ServerLog:
    def __init__(self, display_name, file_name, reader):
        self.display_name = display_name.strip()
        self.file_name = file_name
        self.reader = reader
        self.indices = self.reader.generate_server_log_indices(self.file_name)
        self.file_stream = open(
            self.file_name, "rb"
        )  # binary mode to enable relative seeks in Python3
        self.file_stream.seek(0, 0)

        self.server_start_tm = self.reader.parse_dt(
            self.reader.read_line(self.file_stream)
        )

        self.server_end_tm = self.reader.parse_dt(
            self.reader.read_next_line(self.file_stream, jump=0, whence=2)
        )
        self.log_latency = LogLatency(self.reader)

        # re
        self.server_log_line_writer_info_re = re.compile(
            SERVER_LOG_LINE_WRITER_INFO_PATTERN
        )

    def destroy(self):
        try:
            if self.file_stream:
                self.file_stream.close()
            del self.display_name
            del self.file_name
            del self.reader
            del self.indices
            del self.file_stream
            del self.server_start_tm
            del self.server_end_tm
            del self.log_latency
            del self.indices
            del self.file_stream
            del self.search_strings
            del self.ignore_strs
            del self.is_and
            del self.is_casesensitive
            del self.slice_duration
            del self.upper_limit_check
            del self.read_all_lines
            del self.diff_itr
            del self.show_itr
            del self.latency_itr
            del self.count_itr
            del self.slice_show_count
            del self.uniq_lines_track
        except Exception:
            pass

    def get_start_tm(self, start_tm="head"):
        if start_tm == "head":
            return self.server_start_tm
        else:
            return self.reader.parse_init_dt(start_tm, self.server_end_tm)

    def set_start_and_end_tms(self, start_tm, duration=""):
        self.process_start_tm = start_tm
        if self.process_start_tm > self.server_end_tm:
            self.process_start_tm = self.server_end_tm + self.reader.parse_timedelta(
                "10"
            )

        if duration:
            duration_tm = self.reader.parse_timedelta(duration)
            self.process_end_tm = self.process_start_tm + duration_tm
        if not duration or self.process_end_tm > self.server_end_tm:
            self.process_end_tm = self.server_end_tm + self.reader.parse_timedelta("10")

    def run_linux_cmd(self, cmd):
        cmd = pipes.quote(" ".join(cmd))
        cmd = ["sh", "-c", "'%s'" % (cmd)]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for line in iter(process.stdout.readline, ""):
            yield line

    def set_file_stream(self, system_grep=False):
        if system_grep:
            try:
                grep_str = self.reader.get_grep_string(
                    strs=self.search_strings,
                    file=self.file_name,
                    is_and=self.is_and,
                    is_casesensitive=self.is_casesensitive,
                )
                # cmd = shlex.split(grep_str)
                cmd = [grep_str]
                if self.ignore_strs:
                    g_cmd = "grep "
                    if not self.is_casesensitive:
                        g_cmd += "-i "
                    for i_str in self.ignore_strs:
                        cmd.extend([" |", '%s -v "%s"' % (g_cmd, i_str)])
                self.system_grep_itr = self.run_linux_cmd(cmd)
            except Exception:
                # print "Error in system grep command, reading file line by
                # line.\n"
                self.set_file_stream(system_grep=False)
        else:
            self.start_hr_tm = self.neglect_minutes_seconds_time(self.process_start_tm)
            self.server_start_hr_tm = self.neglect_minutes_seconds_time(
                self.server_start_tm
            )
            self.server_end_hr_tm = self.neglect_minutes_seconds_time(
                self.server_end_tm
            )

            if self.start_hr_tm.strftime(constants.DT_FMT) in self.indices:
                self.file_stream.seek(
                    self.indices[self.start_hr_tm.strftime(constants.DT_FMT)]
                )

            elif self.start_hr_tm < self.server_start_hr_tm:
                self.file_stream.seek(0)

            elif self.start_hr_tm > self.server_end_hr_tm:
                self.file_stream.seek(0, 2)

            else:
                while self.start_hr_tm < self.server_end_hr_tm:
                    if self.start_hr_tm.strftime(constants.DT_FMT) in self.indices:
                        self.file_stream.seek(
                            self.indices[self.start_hr_tm.strftime(constants.DT_FMT)]
                        )
                        return
                    self.start_hr_tm = self.start_hr_tm + datetime.timedelta(hours=1)

                self.file_stream.seek(0, 2)

    # system_grep parameter added to test and compare with system_grep. We are
    # not using this but keeping it here for future reference.
    def set_input(
        self,
        search_strs,
        ignore_strs=[],
        is_and=False,
        is_casesensitive=True,
        start_tm="",
        duration="",
        slice_duration="10",
        every_nth_slice=1,
        upper_limit_check="",
        bucket_count=3,
        every_nth_bucket=1,
        read_all_lines=False,
        rounding_time=True,
        system_grep=False,
        uniq=False,
        ns=None,
        show_relative_stats=False,
    ):
        if isinstance(search_strs, str):
            search_strs = [search_strs]
        self.search_strings = [search_str for search_str in search_strs]
        if isinstance(ignore_strs, str):
            ignore_strs = [ignore_strs]
        self.ignore_strs = ignore_strs
        self.is_and = is_and
        self.is_casesensitive = is_casesensitive
        self.slice_duration = self.reader.parse_timedelta(slice_duration)
        self.upper_limit_check = upper_limit_check
        self.read_all_lines = read_all_lines
        self.set_start_and_end_tms(start_tm=start_tm, duration=duration)
        self.read_block = []
        self.read_block_index = 0
        self.read_block_size = 0
        self.read_block_count = 0
        self.system_grep = system_grep
        self.set_file_stream(system_grep=system_grep)
        self.diff_itr = self.diff()
        self.show_itr = self.show()
        latency_start_tm = self.process_start_tm
        if latency_start_tm < self.server_start_tm:
            latency_start_tm = self.server_start_tm
        self.latency_itr = self.log_latency.compute_latency(
            self.show_itr,
            self.search_strings[0],
            self.slice_duration,
            latency_start_tm,
            self.process_end_tm,
            bucket_count,
            every_nth_bucket,
            arg_rounding_time=rounding_time,
            arg_ns=ns,
            arg_relative_stats=show_relative_stats,
        )
        self.count_itr = self.count()
        self.slice_show_count = every_nth_slice
        self.uniq = uniq
        self.uniq_lines_track = {}
        self.read_prev_line = False
        self.prev_line = None

    def read_line_block(self):
        try:
            while True:
                self.read_block = []
                self.read_block = self.file_stream.readlines(READ_BLOCK_BYTES)
                self.read_block = [
                    utils.util.bytes_to_str(line) for line in self.read_block
                ]  # convert bytes from rb file to string for Python3
                self.read_block_count += 1
                if not self.read_block or self.read_all_lines:
                    break
                if self.search_strings:
                    one_string = " ".join(self.read_block)
                    if self.is_and:
                        if self.is_casesensitive:
                            if all(
                                substring in one_string
                                for substring in self.search_strings
                            ):
                                break
                        else:
                            if all(
                                re.search(substring, one_string, re.IGNORECASE)
                                for substring in self.search_strings
                            ):
                                break
                    else:
                        if self.is_casesensitive:
                            if any(
                                substring in one_string
                                for substring in self.search_strings
                            ):
                                break
                        else:
                            if any(
                                re.search(substring, one_string, re.IGNORECASE)
                                for substring in self.search_strings
                            ):
                                break

                    if self.read_block_count % RETURN_REQUIRED_EVERY_NTH_BLOCK == 0:
                        line = self.read_block[-1]
                        self.read_block = []
                        self.read_block.append(line)
                        break
                else:
                    break
        except Exception:
            self.read_block = []
        self.read_block_count = 0
        self.read_block_index = 0
        self.read_block_size = len(self.read_block)

    def read_line(self):
        line = None
        if self.system_grep:
            try:
                if self.read_prev_line:
                    self.read_prev_line = False
                    if self.prev_line:
                        return self.prev_line
                line = next(self.system_grep_itr)
                self.prev_line = line
                # if line:
                #     line = line + "\n"
                # self.greped_lines_index += 1
            except Exception:
                pass
        else:
            if not self.read_block or self.read_block_index + 1 > self.read_block_size:
                self.read_line_block()
            if self.read_block and self.read_block_index + 1 <= self.read_block_size:
                line = self.read_block[self.read_block_index]
                self.read_block_index += 1

        return line

    def seek_back_line(self, line_lenght=1):
        if self.system_grep:
            self.read_prev_line = True
        else:
            # self.reader.set_next_line(file_stream=self.file_stream, jump=-(line_lenght))
            self.read_block_index -= 1

    def next_line(self, read_start_tm=None, read_end_tm=None):
        seek_back_line = False
        if not read_start_tm:
            read_start_tm = self.process_start_tm
        if not read_end_tm:
            read_end_tm = self.process_end_tm
        else:
            seek_back_line = True
        while True:
            fail = True
            line = self.read_line()
            if not line:
                return None

            try:
                # checking for valid line with timestamp
                line_tm = self.reader.parse_dt(line)
            except Exception:
                continue

            if line_tm > read_end_tm:
                try:
                    if seek_back_line:
                        self.seek_back_line(line_lenght=len(line))
                except Exception:
                    pass
                return None
            if line_tm < read_start_tm:
                continue
            if self.read_all_lines:
                return line
            if not self.system_grep:
                if self.search_strings:
                    if self.is_and:
                        if self.is_casesensitive:
                            if all(
                                substring in line for substring in self.search_strings
                            ):
                                fail = False
                        else:
                            if all(
                                re.search(substring, line, re.IGNORECASE)
                                for substring in self.search_strings
                            ):
                                fail = False
                    else:
                        if self.is_casesensitive:
                            if any(
                                substring in line for substring in self.search_strings
                            ):
                                fail = False
                        else:
                            if any(
                                re.search(substring, line, re.IGNORECASE)
                                for substring in self.search_strings
                            ):
                                fail = False
                if fail:
                    continue
                if self.ignore_strs:
                    if self.is_casesensitive:
                        if any(substring in line for substring in self.ignore_strs):
                            continue
                    else:
                        if any(
                            re.search(substring, line, re.IGNORECASE)
                            for substring in self.ignore_strs
                        ):
                            continue
            else:
                fail = False
            if self.uniq:
                if TIME_ZONE in line:
                    try:
                        line_data = line.split(TIME_ZONE)[1]
                    except Exception:
                        line_data = line
                else:
                    line_data = line
                m = hashlib.md5(line_data)
                if m.hexdigest() in self.uniq_lines_track:
                    fail = True
                    continue
                else:
                    self.uniq_lines_track[m.hexdigest()] = True
            if not fail:
                break

        return line

    def show(self):
        while True:
            tm = None
            line = self.next_line()

            if line:
                tm = self.reader.parse_dt(line)
            yield tm, line

    def show_iterator(self):
        return self.show_itr

    def neglect_minutes_seconds_time(self, tm):
        if not tm or type(tm) is not datetime.datetime:
            return None
        return tm + datetime.timedelta(
            minutes=-tm.minute, seconds=-tm.second, microseconds=-tm.microsecond
        )

    def count(self):
        count_result = {}
        count_result[constants.COUNT_RESULT_KEY] = OrderedDict()
        slice_start = self.process_start_tm
        slice_end = slice_start + self.slice_duration
        if slice_end > self.process_end_tm:
            slice_end = self.process_end_tm
        total_count = 0
        current_slice_count = 0

        while slice_start < self.process_end_tm:
            line = self.next_line(read_start_tm=slice_start, read_end_tm=slice_end)
            if not line:
                count_result[constants.COUNT_RESULT_KEY][
                    slice_start.strftime(constants.DT_FMT)
                ] = current_slice_count
                total_count += current_slice_count
                yield slice_start, count_result
                count_result[constants.COUNT_RESULT_KEY] = {}
                current_slice_count = 0
                slice_start = slice_end
                slice_end = slice_start + self.slice_duration
                if slice_end > self.process_end_tm:
                    slice_end = self.process_end_tm
                continue

            current_slice_count += 1

        count_result[constants.COUNT_RESULT_KEY][
            constants.TOTAL_ROW_HEADER
        ] = total_count
        yield constants.END_ROW_KEY, count_result

    def count_iterator(self):
        return self.count_itr

    def _get_next_slice_start_and_end_tm(
        self, old_slice_start, old_slice_end, slice_duration, current_line_tm
    ):
        slice_jump = 0

        if current_line_tm < old_slice_end and current_line_tm >= old_slice_start:
            return old_slice_start, old_slice_end, slice_jump
        if current_line_tm >= old_slice_end and current_line_tm < (
            old_slice_end + slice_duration
        ):
            return old_slice_end, old_slice_end + slice_duration, 1
        if current_line_tm >= old_slice_end:
            d = current_line_tm - old_slice_start
            slice_jump = int((d.seconds + 86400 * d.days) // slice_duration.seconds)
            slice_start = old_slice_start + slice_duration * slice_jump
            slice_end = slice_start + slice_duration
            return slice_start, slice_end, slice_jump
        return None, None, None

    def _get_value_and_diff(self, prev, slice_val):
        diff = []
        value = []
        under_limit = True
        if self.upper_limit_check:
            under_limit = False
        if prev:
            temp = [b - a for b, a in zip(slice_val, prev)]
            if not self.upper_limit_check or any(
                i >= self.upper_limit_check for i in temp
            ):
                diff = [b for b in temp]
                under_limit = True
        else:
            if not self.upper_limit_check or any(
                i >= self.upper_limit_check for i in slice_val
            ):
                diff = [b for b in slice_val]
                under_limit = True

        if under_limit:
            value = [b for b in slice_val]
        return value, diff

    def _fetch_writer_info(self, line):
        if not line:
            return None

        m1 = self.server_log_line_writer_info_re.search(line)
        if not m1:
            return None

        return m1.group(1)

    def diff(self):
        latency_pattern1 = "%s (\d+)"
        latency_pattern2 = "%s \(([0-9,\s]+)\)"
        latency_pattern3 = "(\d+)\((\d+)\) %s"
        latency_pattern4 = "%s \((\d+)"

        different_writer_info = False

        grep_str = self.search_strings[-1]
        line = self.next_line()
        if line:

            value = []
            diff = []

            # ignore lines till slice_start time
            slice_start = self.process_start_tm
            slice_end = slice_start + self.slice_duration
            while self.reader.parse_dt(line) < slice_start:
                line = self.next_line()
                if not line:
                    break

        if line:
            # check line has all strings as per given order
            if util.contains_substrings_in_order(line=line, strs=self.search_strings):
                if self.is_casesensitive:
                    m1 = re.search(latency_pattern1 % (grep_str), line)
                    m2 = re.search(latency_pattern2 % (grep_str), line)
                    m3 = re.search(latency_pattern3 % (grep_str), line)
                    m4 = re.search(latency_pattern4 % (grep_str), line)
                else:
                    m1 = re.search(latency_pattern1 % (grep_str), line, re.IGNORECASE)
                    m2 = re.search(latency_pattern2 % (grep_str), line, re.IGNORECASE)
                    m3 = re.search(latency_pattern3 % (grep_str), line, re.IGNORECASE)
                    m4 = re.search(latency_pattern4 % (grep_str), line, re.IGNORECASE)

            # check for possible key-value pattern and fix pattern for next process
            while not m1 and not m2 and not m3 and not m4:
                try:
                    line = self.next_line()
                    if not line:
                        break
                    if not util.contains_substrings_in_order(
                        line=line, strs=self.search_strings
                    ):
                        continue
                except Exception:
                    break

                if self.is_casesensitive:
                    m1 = re.search(latency_pattern1 % (grep_str), line)
                    m2 = re.search(latency_pattern2 % (grep_str), line)
                    m3 = re.search(latency_pattern3 % (grep_str), line)
                    m4 = re.search(latency_pattern4 % (grep_str), line)
                else:
                    m1 = re.search(latency_pattern1 % (grep_str), line, re.IGNORECASE)
                    m2 = re.search(latency_pattern2 % (grep_str), line, re.IGNORECASE)
                    m3 = re.search(latency_pattern3 % (grep_str), line, re.IGNORECASE)
                    m4 = re.search(latency_pattern4 % (grep_str), line, re.IGNORECASE)

        if line:
            writer_info = self._fetch_writer_info(line)
            slice_count = 0
            if self.reader.parse_dt(line) >= slice_end:
                (
                    slice_start,
                    slice_end,
                    slice_count,
                ) = self._get_next_slice_start_and_end_tm(
                    slice_start,
                    slice_end,
                    self.slice_duration,
                    self.reader.parse_dt(line),
                )
                # slice_count -= 1
            if slice_end > self.process_end_tm:
                slice_end = self.process_end_tm
            pattern = ""
            prev = []
            slice_val = []
            pattern_type = 0
            if m1:
                pattern = latency_pattern1 % (grep_str)
                if not slice_count % self.slice_show_count:
                    slice_val.append(int(m1.group(1)))
            elif m2:
                pattern = latency_pattern2 % (grep_str)
                if not slice_count % self.slice_show_count:
                    slice_val = [int(x) for x in m2.group(1).split(",")]
                pattern_type = 1
            elif m3:
                pattern = latency_pattern3 % (grep_str)
                if not slice_count % self.slice_show_count:
                    slice_val = [int(x) for x in list(m3.groups())]
                pattern_type = 2
            elif m4:
                pattern = latency_pattern4 % (grep_str)
                if not slice_count % self.slice_show_count:
                    slice_val.append(int(m4.group(1)))
                pattern_type = 3

            result = {}
            result["value"] = {}
            result["diff"] = {}

            for line_tm, line in self.show_itr:
                if not line:
                    break

                if not util.contains_substrings_in_order(
                    line=line, strs=self.search_strings
                ):
                    continue

                if line_tm >= self.process_end_tm:
                    if not slice_count % self.slice_show_count:
                        value, diff = self._get_value_and_diff(prev, slice_val)
                        if value and diff:
                            tm = slice_start.strftime(constants.DT_FMT)
                            result["value"][tm] = value
                            result["diff"][tm] = diff
                            yield slice_start, result
                            result["value"] = {}
                            result["diff"] = {}
                            value = []
                            diff = []
                    slice_val = []
                    break

                if line_tm >= slice_end:
                    if not slice_count % self.slice_show_count:
                        value, diff = self._get_value_and_diff(prev, slice_val)
                        if value and diff:
                            tm = slice_start.strftime(constants.DT_FMT)
                            result["value"][tm] = value
                            result["diff"][tm] = diff
                            yield slice_start, result
                            result["value"] = {}
                            result["diff"] = {}
                            value = []
                            diff = []
                        prev = slice_val
                    (
                        slice_start,
                        slice_end,
                        slice_count_jump,
                    ) = self._get_next_slice_start_and_end_tm(
                        slice_start, slice_end, self.slice_duration, line_tm
                    )
                    slice_count = (
                        slice_count + slice_count_jump
                    ) % self.slice_show_count
                    slice_val = []
                    if slice_end > self.process_end_tm:
                        slice_end = self.process_end_tm

                if not slice_count % self.slice_show_count:
                    if self.is_casesensitive:
                        m = re.search(pattern, line)
                    else:
                        m = re.search(pattern, line, re.IGNORECASE)

                    if m:
                        if self._fetch_writer_info(line) != writer_info:
                            different_writer_info = True

                        if pattern_type == 2:
                            current = [int(x) for x in list(m.groups())]
                        else:
                            current = [int(x) for x in m.group(1).split(",")]
                        if slice_val:
                            slice_val = [b + a for b, a in zip(current, slice_val)]
                        else:
                            slice_val = [b for b in current]

            if not slice_count % self.slice_show_count and slice_val:
                value, diff = self._get_value_and_diff(prev, slice_val)
                if value and diff:
                    tm = slice_start.strftime(constants.DT_FMT)
                    result["value"][tm] = value
                    result["diff"][tm] = diff
                    yield slice_start, result

            result["value"]["diff_end"] = different_writer_info
            yield constants.END_ROW_KEY, result

    def diff_iterator(self):
        return self.diff_itr

    def latency_iterator(self):
        return self.latency_itr

    def get_filename(self):
        return self.file_name
