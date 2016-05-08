__author__ = 'aerospike'

import copy
import datetime
import re
from lib.logreader import COUNT_RESULT_KEY, TOTAL_ROW_HEADER, END_ROW_KEY
from lib.loglatency import LogLatency

DT_FMT = "%b %d %Y %H:%M:%S"

class ServerLog(object):
    def __init__(self, display_name, server_file, log_reader):
        self.display_name = display_name
        self.server_file = server_file
        self.log_reader = log_reader
        self.indices = self.log_reader.generate_server_log_indices(self.server_file)
        self.file_stream = open(self.server_file, "r")
        self.file_stream.seek(0,0)
        self.server_start_tm = self.log_reader.parse_dt(self.file_stream.readline())
        self.server_end_tm = self.log_reader.parse_dt(self.log_reader.read_next_line(self.file_stream, jump=0, whence=2))
        self.log_latency = LogLatency(self.log_reader)

    def destroy(self):
        try:
            del self.display_name
            del self.server_file
            del self.log_reader
            del self.indices
            del self.file_stream
            del self.prefixes
            del self.server_start_tm
            del self.server_end_tm
            del self.log_latency
            del self.indices
            del self.file_stream
            del self.search_strings
            del self.ignore_str
            del self.is_and
            del self.is_casesensitive
            del self.slice_duration
            del self.upper_limit_check
            del self.read_all_lines
            del self.diff_it
            del self.show_it
            del self.latency_it
            del self.count_it
            del self.slice_show_count
        except:
            pass

    def get_start_tm(self, start_tm="head"):
        if start_tm == "head":
            return self.server_start_tm
        else:
            return self.log_reader.parse_init_dt(start_tm, self.server_end_tm)

    def set_start_and_end_tms(self, start_tm, duration=""):
        self.process_start_tm = start_tm
        if self.process_start_tm > self.server_end_tm:
            self.process_start_tm = self.server_end_tm + self.log_reader.parse_timedelta("10")

        if duration:
            duration_tm = self.log_reader.parse_timedelta(duration)
            self.process_end_tm = self.process_start_tm + duration_tm
        if not duration or self.process_end_tm > self.server_end_tm:
            self.process_end_tm = self.server_end_tm + self.log_reader.parse_timedelta("10")

    def set_file_stream(self):
        self.start_hr_tm = self.neglect_minutes_seconds_time(self.process_start_tm)
        self.server_start_hr_tm = self.neglect_minutes_seconds_time(self.server_start_tm)
        self.server_end_hr_tm = self.neglect_minutes_seconds_time(self.server_end_tm)

        if self.start_hr_tm.strftime(DT_FMT) in self.indices:
            self.file_stream.seek(self.indices[self.start_hr_tm.strftime(DT_FMT)])
        elif self.start_hr_tm < self.server_start_hr_tm:
            self.file_stream.seek(0)
        elif self.start_hr_tm > self.server_end_hr_tm:
            self.file_stream.seek(0,2)
        else:
            while(self.start_hr_tm < self.server_end_hr_tm):
                if self.start_hr_tm.strftime(DT_FMT) in self.indices:
                    self.file_stream.seek(self.indices[self.start_hr_tm.strftime(DT_FMT)])
                    return
                self.start_hr_tm = self.start_hr_tm + datetime.timedelta(hours=1)
            self.file_stream.seek(0,2)

    def set_input(self, search_strs, ignore_str="", is_and=False, is_casesensitive=True, start_tm="", duration="",
                  slice_duration="10", every_nth_slice=1, upper_limit_check="", bucket_count=3, every_nth_bucket=1, read_all_lines=False, rounding_time=True):
        if isinstance(search_strs, str):
            search_strs = [search_strs]
        if is_casesensitive:
            self.search_strings=[search_str for search_str in search_strs]
        else:
            self.search_strings=[search_str.lower() for search_str in search_strs]
        self.ignore_str = ignore_str
        self.is_and = is_and
        self.is_casesensitive = is_casesensitive
        self.slice_duration = self.log_reader.parse_timedelta(slice_duration)
        self.upper_limit_check = upper_limit_check
        self.read_all_lines = read_all_lines
        self.set_start_and_end_tms(start_tm=start_tm, duration=duration)
        self.set_file_stream()
        self.diff_it = self.diff()
        self.show_it = self.show()
        latency_start_tm = self.process_start_tm
        if latency_start_tm < self.server_start_tm:
            latency_start_tm = self.server_start_tm
        self.latency_it = self.log_latency.compute_latency(self.show_it, self.search_strings[0], self.slice_duration, latency_start_tm,
                                                           self.process_end_tm, bucket_count, every_nth_bucket, arg_rounding_time=rounding_time)
        self.count_it = self.count()
        self.slice_show_count = every_nth_slice

    def next_line(self, read_start_tm = None, read_end_tm = None):
        seek_back_line = False
        if not read_start_tm:
            read_start_tm = self.process_start_tm
        if not read_end_tm:
            read_end_tm = self.process_end_tm
        else:
            seek_back_line = True
        while True:
            fail = False
            line = self.file_stream.readline()
            if not line or self.log_reader.parse_dt(line) > read_end_tm:
                if seek_back_line and line:
                    self.log_reader.set_next_line(file_stream=self.file_stream, jump=-(len(line)))
                return None
            if self.log_reader.parse_dt(line) < read_start_tm:
                continue
            if self.read_all_lines:
                return line
            if self.search_strings:
                tmp_line = copy.deepcopy(line)
                if not self.is_casesensitive:
                    tmp_line = tmp_line.lower()
                for search_str in self.search_strings:
                    if search_str in tmp_line:
                        if not self.is_and:
                            fail = False
                            break
                    else:
                        fail = True
                        if self.is_and:
                            break
                if fail:
                    continue
            if self.ignore_str and self.ignore_str in line:
                continue
            if not fail:
                break

        return line

    def show(self):
        while True:
            tm = None
            line = self.next_line()
            if line:
                tm = self.log_reader.parse_dt(line)
            yield tm, line

    def show_iterator(self):
        return self.show_it

    def neglect_minutes_seconds_time(self, tm):
        if not tm or type(tm) is not datetime.datetime:
            return None
        return tm + datetime.timedelta(minutes=-tm.minute, seconds=-tm.second, microseconds=-tm.microsecond)

    def get_next_slice_start_and_end_tm(self, old_slice_start, old_slice_end, slice_duration, current_line_tm):
        slice_jump = 0

        if current_line_tm < old_slice_end and current_line_tm >=old_slice_start:
            return old_slice_start, old_slice_end, slice_jump
        if current_line_tm >= old_slice_end and current_line_tm < (old_slice_end + slice_duration):
            return old_slice_end, old_slice_end+slice_duration, 1
        if current_line_tm >= old_slice_end:
            d = current_line_tm-old_slice_start
            slice_jump = int((d.seconds+ 86400 * d.days)/slice_duration.seconds)
            slice_start = old_slice_start + slice_duration * slice_jump
            slice_end = slice_start + slice_duration
            return slice_start, slice_end, slice_jump
        return None, None, None

    def count(self):
        count_result = {}
        count_result[COUNT_RESULT_KEY] = {}
        slice_start = self.process_start_tm
        slice_end = slice_start + self.slice_duration
        if slice_end > self.process_end_tm:
            slice_end = self.process_end_tm
        total_count = 0
        current_slice_count = 0

        while slice_start < self.process_end_tm:
            line = self.next_line(read_start_tm=slice_start, read_end_tm=slice_end)
            if not line:
                count_result[COUNT_RESULT_KEY][slice_start.strftime(DT_FMT)] = current_slice_count
                total_count += current_slice_count
                yield slice_start, count_result
                count_result[COUNT_RESULT_KEY] = {}
                current_slice_count = 0
                slice_start = slice_end
                slice_end = slice_start + self.slice_duration
                if slice_end > self.process_end_tm:
                    slice_end = self.process_end_tm
                continue

            current_slice_count += 1

        count_result[COUNT_RESULT_KEY][TOTAL_ROW_HEADER] = total_count
        yield END_ROW_KEY, count_result

    def count_iterator(self):
        return self.count_it

    def get_value_and_diff(self, prev, slice_val):
        diff  = []
        value = []
        under_limit = True
        if self.upper_limit_check:
            under_limit = False
        if prev:
            temp = ([b - a for b, a in zip(slice_val, prev)])
            if not self.upper_limit_check or any(i >= self.upper_limit_check for i in temp):
                diff = ([b for b in temp])
                under_limit = True
        else:
            if not self.upper_limit_check or any(i >= self.upper_limit_check for i in slice_val):
                diff = ([b for b in slice_val])
                under_limit = True

        if under_limit:
            value = ([b for b in slice_val])
        return value,diff

    def diff(self):
        latencyPattern1 = '%s (\d+)'
        latencyPattern2 = '%s \(([0-9,\s]+)\)'
        latencyPattern3 = '(\d+)\((\d+)\) %s'
        latencyPattern4 = '%s \((\d+)'
        grep_str = self.search_strings[0]
        line = self.next_line()
        if line:

            value = []
            diff = []

            slice_start = self.process_start_tm
            slice_end = slice_start + self.slice_duration
            while(self.log_reader.parse_dt(line) < slice_start):
                line = self.next_line()
                if not line:
                    break

        if line:
            if self.is_casesensitive:
                m1 = re.search(latencyPattern1 % (grep_str), line)
                m2 = re.search(latencyPattern2 % (grep_str), line)
                m3 = re.search(latencyPattern3 % (grep_str), line)
                m4 = re.search(latencyPattern4 % (grep_str), line)
            else:
                m1 = re.search(latencyPattern1 % (grep_str), line, re.IGNORECASE)
                m2 = re.search(latencyPattern2 % (grep_str), line, re.IGNORECASE)
                m3 = re.search(latencyPattern3 % (grep_str), line, re.IGNORECASE)
                m4 = re.search(latencyPattern4 % (grep_str), line, re.IGNORECASE)

            while(not m1 and not m2 and not m3 and not m4):
                try:
                    line = self.next_line()
                    if not line:
                        break
                except:
                    break

                if self.is_casesensitive:
                    m1 = re.search(latencyPattern1 % (grep_str), line)
                    m2 = re.search(latencyPattern2 % (grep_str), line)
                    m3 = re.search(latencyPattern3 % (grep_str), line)
                    m4 = re.search(latencyPattern4 % (grep_str), line)
                else:
                    m1 = re.search(latencyPattern1 % (grep_str), line, re.IGNORECASE)
                    m2 = re.search(latencyPattern2 % (grep_str), line, re.IGNORECASE)
                    m3 = re.search(latencyPattern3 % (grep_str), line, re.IGNORECASE)
                    m4 = re.search(latencyPattern4 % (grep_str), line, re.IGNORECASE)

        if line:
            slice_count = 0
            if (self.log_reader.parse_dt(line) >= slice_end):
                slice_start, slice_end, slice_count = self.get_next_slice_start_and_end_tm(slice_start, slice_end, self.slice_duration,self.log_reader.parse_dt(line))
                slice_count -= 1
            if slice_end > self.process_end_tm:
                slice_end = self.process_end_tm
            pattern = ""
            prev = []
            slice_val = []
            pattern_type = 0
            if m1:
                pattern = latencyPattern1 % (grep_str)
                if not slice_count%self.slice_show_count:
                    slice_val.append(int(m1.group(1)))
            elif m2:
                pattern = latencyPattern2 % (grep_str)
                if not slice_count%self.slice_show_count:
                    slice_val = map(lambda x: int(x), m2.group(1).split(","))
                pattern_type = 1
            elif m3:
                pattern = latencyPattern3 % (grep_str)
                if not slice_count%self.slice_show_count:
                    slice_val = map(lambda x: int(x), list(m3.groups()))
                pattern_type = 2
            elif m4:
                pattern = latencyPattern4 % (grep_str)
                if not slice_count%self.slice_show_count:
                    slice_val.append(int(m4.group(1)))
                pattern_type = 3

            result = {}
            result["value"] = {}
            result["diff"] = {}

            for line_tm, line in self.show_it:
                if not line:
                    break
                if line_tm >= self.process_end_tm:
                    if not slice_count%self.slice_show_count:
                        value, diff = self.get_value_and_diff(prev, slice_val)
                        if value and diff:
                            tm = slice_start.strftime(DT_FMT)
                            result["value"][tm]=value
                            result["diff"][tm]=diff
                            yield slice_start, result
                            result["value"] = {}
                            result["diff"] = {}
                            value = []
                            diff = []
                    slice_val = []
                    break

                if line_tm >= slice_end:
                    if not slice_count%self.slice_show_count:
                        value, diff = self.get_value_and_diff(prev, slice_val)
                        if value and diff:
                            tm = slice_start.strftime(DT_FMT)
                            result["value"][tm]=value
                            result["diff"][tm]=diff
                            yield slice_start, result
                            result["value"] = {}
                            result["diff"] = {}
                            value = []
                            diff = []
                        prev = slice_val
                    slice_start, slice_end, slice_count_jump = self.get_next_slice_start_and_end_tm(slice_start, slice_end, self.slice_duration,line_tm)
                    slice_count = (slice_count+slice_count_jump)%self.slice_show_count
                    slice_val = []
                    if slice_end > self.process_end_tm:
                        slice_end = self.process_end_tm

                if not slice_count%self.slice_show_count:
                    if self.is_casesensitive:
                        m = re.search(pattern, line)
                    else:
                        m = re.search(pattern, line, re.IGNORECASE)

                    if m:
                        if pattern_type == 2:
                            current = map(lambda x: int(x), list(m.groups()))
                        else:
                            current = map(lambda x: int(x), m.group(1).split(","))
                        if slice_val:
                            slice_val = ([b + a for b, a in zip(current, slice_val)])
                        else:
                            slice_val = ([b for b in current])

            if not slice_count%self.slice_show_count and slice_val:
                value, diff = self.get_value_and_diff(prev, slice_val)
                if value and diff:
                    tm = slice_start.strftime(DT_FMT)
                    result["value"][tm]=value
                    result["diff"][tm]=diff
                    yield slice_start, result

    def diff_iterator(self):
        return self.diff_it

    def latency_iterator(self):
        return self.latency_it



