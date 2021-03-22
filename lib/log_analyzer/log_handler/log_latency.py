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
#
####

# ===========================================================
# Imports
#

import datetime
import re

from lib.utils import constants

from . import util

# ===========================================================
# Constants
#

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

# Unit map
UNITS_MAP = {"msec": "ms", "usec": "\u03bcs"}


# relative stats to input histogram
# format:
# histogram: (
# 	[in order path for stat with stat name],
# 	[(index of value, "name of output column")]
# )
relative_stat_info = {"batch-index": (["batch-sub:", "read"], [(0, "recs/sec")])}

# ===========================================================


class LogLatency(object):
    def __init__(self, reader):
        self.reader = reader

    # ------------------------------------------------
    # Read a complete line from the log file.
    #

    # ------------------------------------------------
    # Set bucket details.
    #
    def _set_bucket_details(self, hist):
        if any(ht in hist for ht in SIZE_HIST_LIST):
            self._bucket_labels = (
                "00",
                "01",
                "02",
                "03",
                "04",
                "05",
                "06",
                "07",
                "08",
                "09",
                "10",
                "11",
                "12",
                "13",
                "14",
                "15",
                "16",
                "17",
                "18",
                "19",
                "20",
                "21",
                "22",
                "23",
                "24",
                "25",
            )
            self._all_buckets = len(self._bucket_labels)
            self._bucket_unit = "bytes"
        elif any(ht in hist for ht in COUNT_HIST_LIST):
            self._bucket_labels = (
                "00",
                "01",
                "02",
                "03",
                "04",
                "05",
                "06",
                "07",
                "08",
                "09",
                "10",
                "11",
                "12",
                "13",
                "14",
                "15",
                "16",
                "17",
                "18",
                "19",
                "20",
                "21",
                "22",
                "23",
                "24",
                "25",
            )
            self._all_buckets = len(self._bucket_labels)
            self._bucket_unit = "records"
        else:
            self._bucket_labels = (
                "00",
                "01",
                "02",
                "03",
                "04",
                "05",
                "06",
                "07",
                "08",
                "09",
                "10",
                "11",
                "12",
                "13",
                "14",
                "15",
                "16",
            )
            self._all_buckets = len(self._bucket_labels)
            # histogram bucket units are set on a per line basis

    def _read_line(self, file_itr):
        line = ""
        try:
            tm, line = next(file_itr)
            if not line:
                return None
            return line
        except Exception:
            return None

    # ------------------------------------------------
    # Parse a histogram total from a log line.
    #

    def _parse_total_ops(self, line):
        return int(line[line.rfind("(") + 1 : line.rfind(" total)")])

    # ------------------------------------------------
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
                    pattern = r".*?\(" + self._bucket_labels[b] + r": (.*?)\).*?"
                    r = re.compile(pattern)
                    if r.search(line):
                        found = found + 1
                        values[b] = int(r.search(line).group(1))
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

    # ------------------------------------------------
    # Subtract one set of bucket values from another.
    #

    def _subtract_buckets(self, new_values, old_values):
        slice_values = {}
        for b in range(self._all_buckets):
            if new_values[b] < old_values[b]:
                new_values[b] = old_values[b]
            slice_values[b] = new_values[b] - old_values[b]
        return slice_values

    # ------------------------------------------------
    # Add one set of bucket values to another.
    #

    def _add_buckets(self, b1_values, b2_values):
        slice_values = {}
        for b in range(self._all_buckets):
            slice_values[b] = b1_values[b] + b2_values[b]
        return slice_values

    # ------------------------------------------------
    # Get the percentage of operations within every bucket.
    #

    def _bucket_percentages(self, total, values):
        percentages = [0.0] * self._all_buckets
        if total > 0:
            for b in range(self._all_buckets):
                percentages[b] = (float(values[b]) / total) * 100
        return percentages

    # ------------------------------------------------
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

    # -------------------------------------------------
    # Get a stat value from line.
    #
    def _read_stat(self, line, stat=[]):
        values = []
        if not stat:
            return values

        latency_pattern1 = r"%s (\d+)"
        latency_pattern2 = r"%s \(([0-9,\s]+)\)"
        latency_pattern3 = r"(\d+)\((\d+)\) %s"
        latency_pattern4 = r"%s \((\d+)"

        grep_str = stat[-1]

        m = re.search(latency_pattern1 % (grep_str), line)
        if m:
            values.append(int(m.group(1)))
            return values

        m = re.search(latency_pattern2 % (grep_str), line)
        if m:
            values = [int(x) for x in m.group(1).split(",")]
            return values

        m = re.search(latency_pattern3 % (grep_str), line)
        if m:
            values = [int(x) for x in list(m.groups())]

        m = re.search(latency_pattern4 % (grep_str), line)
        if m:
            values.append(int(m.group(1)))
            return values

        return values

    # ------------------------------------------------
    # Add one list of stat values to another.
    #
    def _add_stat_values(self, v1, v2):
        if not v1:
            return v2

        if not v2:
            return v1

        l1 = len(v1)
        l2 = len(v2)

        values = []
        for i in range(max(l1, l2)):
            val = 0
            if i < l1:
                val += v1[i]

            if i < l2:
                val += v2[i]

            values.append(val)

        return values

    # ------------------------------------------------
    # Subtract one list of stat values from another.
    #
    def _subtract_stat_values(self, new_values, old_values):
        values = []

        newl = len(new_values)
        oldl = len(old_values)

        for i in range(max(newl, oldl)):
            if i < newl:
                # next item from new_values
                newval = new_values[i]
                if i < oldl:
                    # item available for same index in old_values
                    values.append(newval - old_values[i])

                else:
                    # item not available for same index in old_values
                    values.append(newval)

            else:
                # item not available in new_values
                # add 0
                values.append(0)

        return values

    # ------------------------------------------------
    # Find max from two lists of stat values.
    #
    def _get_max_stat_values(self, new_values, old_values):
        values = []

        newl = len(new_values)
        oldl = len(old_values)

        for i in range(max(newl, oldl)):
            if i >= newl:
                # no item in new_values
                values.append(old_values[i])
            elif i >= oldl:
                # no item in old_values
                values.append(new_values[i])
            else:
                # items available for index i in both list
                values.append(max(old_values[i], new_values[i]))

        return values

    # ------------------------------------------------
    # Get a histogram at or just after the specified datetime.
    #

    def _read_hist(
        self,
        hist_tags,
        after_dt,
        file_itr,
        line=0,
        end_dt=None,
        before_dt=None,
        read_all_dumps=False,
        relative_stat_path=[],
    ):
        if not line:
            # read next line
            line = self._read_line(file_itr)

        total = 0
        values = 0
        stat_values = []
        dt = ""
        unit = "msec"

        while True:
            if not line:
                return total, values, 0, 0, stat_values, unit

            dt = self.reader.parse_dt(line)

            if dt < after_dt:
                # ignore lines with timestamp before before_dt
                line = self._read_line(file_itr)
                continue

            if end_dt and dt > end_dt:
                # found line with timestamp after end_dt
                return total, values, dt, line, stat_values, unit

            if before_dt and dt > before_dt:
                # found line with timestamp after before_dt
                return total, values, dt, line, stat_values, unit

            if relative_stat_path and util.contains_substrings_in_order(
                line, relative_stat_path
            ):
                temp_sval = self._read_stat(line, relative_stat_path)
                stat_values = self._add_stat_values(stat_values, temp_sval)

            elif any(re.search(ht, line) for ht in hist_tags):
                break

            line = self._read_line(file_itr)

        if "usec" in line:
            unit = "usec"
        elif "msec" in line:
            unit = "msec"

        total, values, line = self._read_bucket_values(line, file_itr)

        if not line:
            return 0, 0, 0, 0, stat_values, unit

        if read_all_dumps or relative_stat_path:
            if not before_dt:
                before_dt = dt + datetime.timedelta(seconds=NS_SLICE_SECONDS)

            r_total, r_values, r_dt, line, r_stat_values, _ = self._read_hist(
                hist_tags,
                after_dt,
                file_itr,
                line,
                end_dt,
                before_dt,
                read_all_dumps=read_all_dumps,
                relative_stat_path=relative_stat_path,
            )

            total += r_total
            if r_values:
                values = self._add_buckets(values, r_values)

            if r_stat_values:
                stat_values = self._add_stat_values(stat_values, r_stat_values)

        return total, values, dt, line, stat_values, unit

    # ------------------------------------------------
    # Get a timedelta in seconds.
    #

    def _elapsed_seconds(self, td):
        return td.seconds + (td.days * 24 * 3600)

    # ------------------------------------------------
    # Generate padding.
    #

    def _repeat(self, what, n):
        pad = ""
        for i in range(n):
            pad = pad + what
        return pad

    def compute_latency(
        self,
        arg_log_itr,
        arg_hist,
        arg_slice,
        arg_from,
        arg_end_date,
        arg_num_buckets,
        arg_every_nth,
        arg_rounding_time=True,
        arg_ns=None,
        arg_relative_stats=False,
    ):

        latency = {}
        tps_key = ("ops/sec", None)
        latency[tps_key] = {}

        # Sanity-check some arguments:
        if (
            arg_hist is None
            or arg_num_buckets < 1
            or arg_every_nth < 1
            or not arg_slice
        ):
            yield None, None
        else:
            # Set buckets
            self._set_bucket_details(arg_hist)

            slice_timedelta = arg_slice
            max_bucket = 0

            # sometimes slice timestamps are not perfect, there might be some delta
            if slice_timedelta > self.reader.parse_timedelta("1"):
                slice_timedelta -= self.reader.parse_timedelta("1")

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
                hist_tags = [HIST_TAG_PREFIX + "%s " % (arg_hist)]

            else:
                # Analysing latency for histogram arg_hist
                # It needs to read all bucket dumps for a slice
                hist_tags = [s % (arg_hist) for s in HIST_TAG_PATTERNS]
                read_all_dumps = True

            init_dt = arg_from

            relative_stat_path = []
            relative_stat_index = []
            if arg_relative_stats and arg_hist in relative_stat_info:
                info = relative_stat_info[arg_hist]
                relative_stat_path = info[0]
                relative_stat_index = info[1]

                for idx_name in relative_stat_index:
                    latency[(idx_name[1], None)] = {}

            # Find first histogram:
            old_total, old_values, old_dt, line, old_stat_values, _ = self._read_hist(
                hist_tags,
                init_dt,
                file_itr,
                end_dt=arg_end_date,
                read_all_dumps=read_all_dumps,
                relative_stat_path=relative_stat_path,
            )

            if line:
                end_dt = arg_end_date
                labels = []

                # Other initialization before processing time slices:
                which_slice = 0
                after_dt = old_dt + slice_timedelta
                overs, avg_overs, max_overs = (
                    [0.0] * max_bucket,
                    [0.0] * max_bucket,
                    [0.0] * max_bucket,
                )
                total_ops, total_seconds = 0, 0
                max_rate = 0.0

                total_stat_values = [0.0] * len(old_stat_values)
                max_stat_values = [0.0] * len(old_stat_values)

                # Process all the time slices:
                while end_dt > old_dt:
                    (
                        new_total,
                        new_values,
                        new_dt,
                        line,
                        new_stat_values,
                        new_unit,
                    ) = self._read_hist(
                        hist_tags,
                        after_dt,
                        file_itr,
                        line,
                        end_dt=arg_end_date,
                        read_all_dumps=read_all_dumps,
                        relative_stat_path=relative_stat_path,
                    )

                    self._bucket_unit = UNITS_MAP[new_unit]

                    if not new_values:
                        # This can happen in either eof or end of input time
                        # range
                        break

                    # Get the "deltas" for this slice:
                    slice_total = new_total - old_total
                    slice_values = self._subtract_buckets(new_values, old_values)
                    slice_seconds_actual = self._elapsed_seconds(new_dt - old_dt)

                    slice_stat_values = []
                    slice_stat_rates = []
                    if relative_stat_path:
                        slice_stat_values = self._subtract_stat_values(
                            new_stat_values, old_stat_values
                        )
                        slice_stat_rates = [
                            round(float(v) / slice_seconds_actual, 1)
                            for v in slice_stat_values
                        ]

                    # Get the rate for this slice:
                    rate = round(float(slice_total) / slice_seconds_actual, 1)
                    total_ops = total_ops + slice_total
                    total_seconds = total_seconds + slice_seconds_actual
                    if rate > max_rate:
                        max_rate = rate

                    if relative_stat_path:
                        total_stat_values = self._add_stat_values(
                            total_stat_values, slice_stat_values
                        )
                        max_stat_values = self._get_max_stat_values(
                            max_stat_values, slice_stat_rates
                        )

                    # Convert bucket values for this slice to percentages:
                    percentages = self._bucket_percentages(slice_total, slice_values)

                    # For each (displayed) threshold, accumulate percentages
                    # over threshold:
                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        overs[i] = round(self._percentage_over(i, percentages), 2)
                        avg_overs[i] = avg_overs[i] + overs[i]
                        if overs[i] > max_overs[i]:
                            max_overs[i] = overs[i]

                    key_dt = new_dt
                    if arg_rounding_time:
                        key_dt = self.ceil_time(key_dt)

                    for i in range(max_bucket):
                        labels.append(0)
                        if i % arg_every_nth == 0:
                            labels[i] = (2 ** i, self._bucket_unit)
                            latency[(2 ** i, self._bucket_unit)] = {}

                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        latency[labels[i]][
                            key_dt.strftime(constants.DT_FMT)
                        ] = "%.2f" % (overs[i])

                    latency[tps_key][key_dt.strftime(constants.DT_FMT)] = "%.1f" % (
                        rate
                    )

                    if relative_stat_index:
                        for idx_name in relative_stat_index:
                            if idx_name[0] < len(slice_stat_rates):
                                latency[(idx_name[1], None)][
                                    key_dt.strftime(constants.DT_FMT)
                                ] = "%.1f" % (slice_stat_rates[idx_name[0]])
                            else:
                                latency[(idx_name[1], None)][
                                    key_dt.strftime(constants.DT_FMT)
                                ] = "-"

                    yield key_dt, latency

                    # Prepare for next slice:
                    for key in latency:
                        latency[key] = {}

                    which_slice = which_slice + 1
                    after_dt = new_dt + slice_timedelta
                    old_total, old_values, old_dt = new_total, new_values, new_dt
                    old_stat_values = new_stat_values

                # Compute averages and maximums:
                if which_slice > 0:
                    for i in range(max_bucket):
                        if i % arg_every_nth == 0:
                            avg_overs[i] = avg_overs[i] / which_slice
                    avg_rate = total_ops / total_seconds
                    avg_stat_values = []
                    if relative_stat_path:
                        avg_stat_values = [v / total_seconds for v in total_stat_values]

                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        latency[labels[i]]["avg"] = "%.2f" % (avg_overs[i])
                        latency[labels[i]]["max"] = "%.2f" % (max_overs[i])

                    latency[tps_key]["avg"] = "%.1f" % (avg_rate)
                    latency[tps_key]["max"] = "%.1f" % (max_rate)

                    if relative_stat_index:
                        for idx_name in relative_stat_index:
                            if idx_name[0] < len(avg_stat_values):
                                latency[(idx_name[1], None)]["avg"] = "%.1f" % (
                                    avg_stat_values[idx_name[0]]
                                )

                            if idx_name[0] < len(max_stat_values):
                                latency[(idx_name[1], None)]["max"] = "%.1f" % (
                                    max_stat_values[idx_name[0]]
                                )

                yield constants.END_ROW_KEY, latency
