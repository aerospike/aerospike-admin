#!/usr/bin/python
####
#
# Copyright 2013-2017 Aerospike, Inc.
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
#
####

#===========================================================
# Imports
#

import datetime
import re


#===========================================================
# Constants
#
from lib.utils.constants import END_ROW_KEY, DT_FMT

DT_TO_MINUTE_FMT = "%b %d %Y %H:%M"
DT_TIME_FMT = "%H:%M:%S"
HIST_TAG_PREFIX = "histogram dump: "
HIST_WITH_NS_PATTERN = "{.+}-[a-zA-Z0-9_-]+"
HIST_TAG_PATTERNS = [HIST_TAG_PREFIX + "%s ", HIST_TAG_PREFIX + "{[a-zA-Z0-9_-]+}-%s "]
NS_HIST_TAG_PATTERNS = [HIST_TAG_PREFIX + "{%s}-%s "]
NS_SLICE_SECONDS = 5
SCAN_SIZE = 1024 * 1024
HIST_BUCKET_LINE_SUBSTRING = "hist.c:"
SIZE_HIST_LIST = ["device-read-size", "device-write-size"]
COUNT_HIST_LIST = ["query-rec-count"]

#===========================================================


class LogLatency(object):

    def __init__(self, reader):
        self.reader = reader

    #------------------------------------------------
    # Read a complete line from the log file.
    #

    #------------------------------------------------
    # Set bucket details.
    #
    def _set_bucket_details(self, hist):
        if any(ht in hist for ht in SIZE_HIST_LIST):
            self._bucket_labels = ("00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
                                   "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
                                   "21", "22", "23", "24", "25")
            self._all_buckets = len(self._bucket_labels)
            self._bucket_unit = "bytes"
        elif any(ht in hist for ht in COUNT_HIST_LIST):
            self._bucket_labels = ("00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
                                   "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20",
                                   "21", "22", "23", "24", "25")
            self._all_buckets = len(self._bucket_labels)
            self._bucket_unit = "records"
        else:
            self._bucket_labels = ("00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
                                   "10", "11", "12", "13", "14", "15", "16")
            self._all_buckets = len(self._bucket_labels)
            self._bucket_unit = "ms"

    def _read_line(self, file_itr):
        line = ""
        try:
            tm, line = file_itr.next()
            if not line:
                return None
            return line
        except Exception:
            return None

    #------------------------------------------------
    # Parse a histogram total from a log line.
    #

    def _parse_total_ops(self, line):
        return long(line[line.rfind("(") + 1: line.rfind(" total)")])

    #------------------------------------------------
    # Get one set of bucket values.
    #

    def _read_bucket_values(self, line, file_itr):
        values = {}
        for b in range(self._all_buckets):
            values[b] = 0
        total = self._parse_total_ops(line)
        line = self._read_line(file_itr)
        if not line:
            return 0, 0, 0
        b_min = 0
        b_total = 0
        while True:
            found = 0
            if HIST_BUCKET_LINE_SUBSTRING in line:
                for b in range(b_min, self._all_buckets):
                    pattern = '.*?\(' + self._bucket_labels[b] + ': (.*?)\).*?'
                    r = re.compile(pattern)
                    if r.search(line):
                        found = found + 1
                        values[b] = long(r.search(line).group(1))
                        b_total = b_total + values[b]
                if found == 0:
                    break
            line = self._read_line(file_itr)
            if not line:
                if b_total < total:
                    # Incomplete bucket details
                    return 0, 0, 0
                else:
                    line = 0
                    break
            if b_total >= total:
                break
            b_min = b_min + found
        return total, values, line

    #------------------------------------------------
    # Subtract one set of bucket values from another.
    #

    def _subtract_buckets(self, new_values, old_values):
        slice_values = {}
        for b in range(self._all_buckets):
            if new_values[b] < old_values[b]:
                new_values[b] = old_values[b]
            slice_values[b] = new_values[b] - old_values[b]
        return slice_values

    #------------------------------------------------
    # Add one set of bucket values to another.
    #

    def _add_buckets(self, b1_values, b2_values):
        slice_values = {}
        for b in range(self._all_buckets):
            slice_values[b] = b1_values[b] + b2_values[b]
        return slice_values

    #------------------------------------------------
    # Get the percentage of operations within every bucket.
    #

    def _bucket_percentages(self, total, values):
        percentages = [0.0] * self._all_buckets
        if total > 0:
            for b in range(self._all_buckets):
                percentages[b] = (float(values[b]) / total) * 100
        return percentages

    #------------------------------------------------
    # Get the percentage of operations in all buckets > bucket.
    #

    def _percentage_over(self, bucket, percentages):
        percentage = 0.0
        for b in range(self._all_buckets):
            if b > bucket:
                percentage = percentage + percentages[b]
        return percentage

    def ceil_time(self, dt):
        seconds = 10 - (dt.second % 10)
        if seconds == 10:
            return dt
        return dt + datetime.timedelta(0, seconds, -dt.microsecond)

    #------------------------------------------------
    # Get a histogram at or just after the specified datetime.
    #

    def _read_hist(self, hist_tags, after_dt, file_itr, line=0, end_dt=None,
                   before_dt=None, read_all_dumps=False):
        if not line:
            line = self._read_line(file_itr)
        while True:
            if not line:
                return 0, 0, 0, 0
            dt = self.reader.parse_dt(line)
            if dt < after_dt:
                line = self._read_line(file_itr)
                continue
            if end_dt and dt > end_dt:
                return 0, 0, dt, line
            if before_dt and dt > before_dt:
                return 0, 0, dt, line
            if any(re.search(ht, line) for ht in hist_tags):
                break
            line = self._read_line(file_itr)

        total, values, line = self._read_bucket_values(line, file_itr)
        if not line:
            return 0, 0, 0, 0

        if read_all_dumps:
            if not before_dt:
                before_dt = dt + datetime.timedelta(seconds=NS_SLICE_SECONDS)
            r_total, r_values, r_dt, line = self._read_hist(
                hist_tags, after_dt, file_itr, line, end_dt, before_dt, read_all_dumps=read_all_dumps)
            total += r_total
            if r_values:
                values = self._add_buckets(values, r_values)

        return total, values, dt, line

    #------------------------------------------------
    # Get a timedelta in seconds.
    #

    def _elapsed_seconds(self, td):
        return td.seconds + (td.days * 24 * 3600)

    #------------------------------------------------
    # Generate padding.
    #

    def _repeat(self, what, n):
        pad = ""
        for i in range(n):
            pad = pad + what
        return pad

    def compute_latency(self, arg_log_itr, arg_hist, arg_slice, arg_from,
                        arg_end_date, arg_num_buckets, arg_every_nth,
                        arg_rounding_time=True, arg_ns=None):

        latency = {}
        tps_key = ("ops/sec", None)
        latency[tps_key] = {}

        # Sanity-check some arguments:
        if (arg_hist is None or arg_num_buckets < 1 or arg_every_nth < 1
                or not arg_slice):
            yield None, None
        else:
            # Set buckets
            self._set_bucket_details(arg_hist)

            slice_timedelta = arg_slice
            # Find index + 1 of last bucket to display:
            for b in range(self._all_buckets):
                if b % arg_every_nth == 0:
                    max_bucket = b + 1
                    if arg_num_buckets == 1:
                        break
                    else:
                        arg_num_buckets = arg_num_buckets - 1
            file_itr = arg_log_itr

            # By default reading one bucket dump for 10 second slice,
            # In case of multiple namespaces, it will read all bucket dumps for all namepspaces for same slice
            read_all_dumps = False

            # Set histogram tag:
            if arg_ns:
                # Analysing latency for histogram arg_hist for specific namespace arg_ns
                # It needs to read single bucket dump for a slice
                hist_tags = [s % (arg_ns, arg_hist) for s in NS_HIST_TAG_PATTERNS]

            elif re.match(HIST_WITH_NS_PATTERN, arg_hist):
                # Analysing latency for specific histogram for specific namespace ({namespace}-histogram)
                # It needs to read single bucket dump for a slice
                hist_tags = [HIST_TAG_PREFIX+"%s "%(arg_hist)]

            else:
                # Analysing latency for histogram arg_hist
                # It needs to read all bucket dumps for a slice
                hist_tags = [s % (arg_hist) for s in HIST_TAG_PATTERNS]
                read_all_dumps = True

            init_dt = arg_from
            # Find first histogram:
            old_total, old_values, old_dt, line = self._read_hist(
                hist_tags, init_dt, file_itr, end_dt=arg_end_date, read_all_dumps=read_all_dumps)
            if line:
                end_dt = arg_end_date

                labels = []
                for i in range(max_bucket):
                    labels.append(0)
                    if i % arg_every_nth == 0:
                        labels[i] = pow(2, i)
                        latency[(pow(2, i), self._bucket_unit)] = {}

                # Other initialization before processing time slices:
                which_slice = 0
                after_dt = old_dt + slice_timedelta
                overs, avg_overs, max_overs = [
                    0.0] * max_bucket, [0.0] * max_bucket, [0.0] * max_bucket
                total_ops, total_seconds = 0, 0
                max_rate = 0.0

                # Process all the time slices:
                while end_dt > old_dt:
                    new_total, new_values, new_dt, line = self._read_hist(
                        hist_tags, after_dt, file_itr, line, end_dt=arg_end_date, read_all_dumps=read_all_dumps)
                    if not new_values:
                        # This can happen in either eof or end of input time
                        # range
                        break

                    # Get the "deltas" for this slice:
                    slice_total = new_total - old_total
                    slice_values = self._subtract_buckets(
                        new_values, old_values)
                    slice_seconds_actual = self._elapsed_seconds(
                        new_dt - old_dt)

                    # Get the rate for this slice:
                    rate = round(float(slice_total) / slice_seconds_actual, 1)
                    total_ops = total_ops + slice_total
                    total_seconds = total_seconds + slice_seconds_actual
                    if rate > max_rate:
                        max_rate = rate

                    # Convert bucket values for this slice to percentages:
                    percentages = self._bucket_percentages(
                        slice_total, slice_values)

                    # For each (displayed) threshold, accumulate percentages
                    # over threshold:
                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        overs[i] = round(
                            self._percentage_over(i, percentages), 2)
                        avg_overs[i] = avg_overs[i] + overs[i]
                        if overs[i] > max_overs[i]:
                            max_overs[i] = overs[i]

                    key_dt = new_dt
                    if arg_rounding_time:
                        key_dt = self.ceil_time(key_dt)
                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        latency[(labels[i], self._bucket_unit)][
                            key_dt.strftime(DT_FMT)] = "%.2f" % (overs[i])

                    latency[tps_key][key_dt.strftime(DT_FMT)] = "%.1f" % (rate)
                    yield key_dt, latency
                    for key in latency:
                        latency[key] = {}
                    # Prepare for next slice:
                    which_slice = which_slice + 1
                    after_dt = new_dt + slice_timedelta
                    old_total, old_values, old_dt = new_total, new_values, new_dt

                # Compute averages and maximums:
                if which_slice > 0:
                    for i in range(max_bucket):
                        if i % arg_every_nth == 0:
                            avg_overs[i] = avg_overs[i] / which_slice
                    avg_rate = total_ops / total_seconds
                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        latency[(labels[i], self._bucket_unit)][
                            "avg"] = "%.2f" % (avg_overs[i])
                        latency[(labels[i], self._bucket_unit)][
                            "max"] = "%.2f" % (max_overs[i])
                    latency[tps_key]["avg"] = "%.1f" % (avg_rate)
                    latency[tps_key]["max"] = "%.1f" % (max_rate)

                yield END_ROW_KEY, latency
