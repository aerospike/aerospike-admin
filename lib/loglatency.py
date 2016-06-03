#!/usr/bin/python
####
#
#  Copyright (c) 2008-2012 Aerospike, Inc. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####

#===========================================================
# Imports
#

import datetime
import getopt
import os
import re
import select
import signal
import sys
import termios
import threading
import time
import types


#===========================================================
# Constants
#
from lib.logreader import END_ROW_KEY

BUCKET_LABELS = ("00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
                 "10", "11", "12", "13", "14", "15", "16")
ALL_BUCKETS = len(BUCKET_LABELS)
DT_FMT = "%b %d %Y %H:%M:%S"
DT_TO_MINUTE_FMT = "%b %d %Y %H:%M"
DT_TIME_FMT = "%H:%M:%S"
HIST_TAG_PREFIX = "histogram dump: "
SCAN_SIZE = 1024 * 1024

class LogLatency(object):

    def __init__(self, log_reader):
        self.log_reader = log_reader
    #------------------------------------------------
    # Read a complete line from the log file.
    #


    def read_line(self, file_itr):
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


    def parse_total_ops(self, line):
        return long(line[line.rfind("(") + 1: line.rfind(" total)")])

    #------------------------------------------------
    # Get one set of bucket values.
    #


    def read_bucket_values(self, line, file_itr):
        values = {}
        for b in range(ALL_BUCKETS):
            values[b] = 0
        total = self.parse_total_ops(line)
        line = self.read_line(file_itr)
        if not line:
            return 0, 0, 0
        b_min = 0
        while True:
            found = 0
            for b in range(b_min, ALL_BUCKETS):
                pattern = '.*?\(' + BUCKET_LABELS[b] + ': (.*?)\).*?'
                r = re.compile(pattern)
                if r.search(line):
                    found = found + 1
                    values[b] = long(r.search(line).group(1))
            if found == 0:
                break
            line = self.read_line(file_itr)
            if not line:
                return 0, 0, 0
            b_min = b_min + found
        return total, values, line

    #------------------------------------------------
    # Subtract one set of bucket values from another.
    #


    def subtract_buckets(self, new_values, old_values):
        slice_values = {}
        for b in range(ALL_BUCKETS):
            if new_values[b] < old_values[b]:
                new_values[b] = old_values[b]
            slice_values[b] = new_values[b] - old_values[b]
        return slice_values

    #------------------------------------------------
    # Get the percentage of operations within every bucket.
    #


    def bucket_percentages(self, total, values):
        percentages = [0.0] * ALL_BUCKETS
        if total > 0:
            for b in range(ALL_BUCKETS):
                percentages[b] = (float(values[b]) / total) * 100
        return percentages

    #------------------------------------------------
    # Get the percentage of operations in all buckets > bucket.
    #


    def percentage_over(self, bucket, percentages):
        percentage = 0.0
        for b in range(ALL_BUCKETS):
            if b > bucket:
                percentage = percentage + percentages[b]
        return percentage


    def ceilTime(self, dt):
       seconds = 10 - (dt.second  % 10)
       if seconds == 10:
           return dt
       return dt + datetime.timedelta(0, seconds, -dt.microsecond)

    #------------------------------------------------
    # Get a histogram at or just after the specified datetime.
    #


    def read_hist(self, hist_tag, after_dt, file_itr, line=0):
        prefix_to_minute = after_dt.strftime(DT_TO_MINUTE_FMT)
        if not line:
            line = self.read_line(file_itr)
        while True:
            if not line:
                return 0, 0, 0, 0
            if line.startswith(prefix_to_minute):
                break
            line = self.read_line(file_itr)
        while True:
            if hist_tag in line:
                dt = self.log_reader.parse_dt(line)
                if dt >= after_dt:
                    break
            line = self.read_line(file_itr)
            if not line:
                return 0, 0, 0, 0
        total, values, line = self.read_bucket_values(line, file_itr)
        if not line:
            return 0, 0, 0, 0
        return total, values, dt, line

    #------------------------------------------------
    # Get a timedelta in seconds.
    #


    def elapsed_seconds(self, td):
        return td.seconds + (td.days * 24 * 3600)

    #------------------------------------------------
    # Generate padding.
    #


    def repeat(self, what, n):
        pad = ""
        for i in range(n):
            pad = pad + what
        return pad

    def compute_latency(self, arg_log_itr, arg_hist, arg_slice, arg_from, arg_end_date, arg_num_buckets, arg_every_nth, arg_rounding_time=True):
        latency = {}
        latency["ops/sec"] = {}

        # Sanity-check some arguments:
        if arg_hist is None or arg_num_buckets < 1 or arg_every_nth < 1 or not arg_slice:
            yield None, None
        else:
            slice_timedelta = arg_slice
            # Find index + 1 of last bucket to display:
            for b in range(ALL_BUCKETS):
                if b % arg_every_nth == 0:
                    max_bucket = b + 1
                    if arg_num_buckets == 1:
                        break
                    else:
                        arg_num_buckets = arg_num_buckets - 1
            file_itr = arg_log_itr

            # Set histogram tag:
            hist_tag = HIST_TAG_PREFIX + arg_hist + " "

            init_dt = arg_from
            # Find first histogram:
            old_total, old_values, old_dt, line = self.read_hist(hist_tag, init_dt, file_itr)
            if line:
                end_dt = arg_end_date

                labels = []
                for i in range(max_bucket):
                    labels.append(0)
                    if i % arg_every_nth == 0:
                        labels[i] = pow(2, i)
                        latency[pow(2, i)] = {}

                # Other initialization before processing time slices:
                which_slice = 0
                after_dt = old_dt + slice_timedelta
                overs, avg_overs, max_overs = [0.0] * max_bucket, [0.0] * max_bucket, [0.0] * max_bucket
                total_ops, total_seconds = 0, 0
                max_rate = 0.0

                # Process all the time slices:
                while end_dt > old_dt:
                    new_total, new_values, new_dt, line = self.read_hist(hist_tag, after_dt, file_itr, line)
                    if not line:
                        # Note - we ignore the (possible) incomplete slice at the end.
                        break

                    # Get the "deltas" for this slice:
                    slice_total = new_total - old_total
                    slice_values = self.subtract_buckets(new_values, old_values)
                    slice_seconds_actual = self.elapsed_seconds(new_dt - old_dt)

                    # Get the rate for this slice:
                    rate = round(float(slice_total) / slice_seconds_actual, 1)
                    total_ops = total_ops + slice_total
                    total_seconds = total_seconds + slice_seconds_actual
                    if rate > max_rate:
                        max_rate = rate

                    # Convert bucket values for this slice to percentages:
                    percentages = self.bucket_percentages(slice_total, slice_values)

                    # For each (displayed) threshold, accumulate percentages over threshold:
                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        overs[i] = round(self.percentage_over(i, percentages), 2)
                        avg_overs[i] = avg_overs[i] + overs[i]
                        if overs[i] > max_overs[i]:
                            max_overs[i] = overs[i]

                    key_dt = new_dt
                    if arg_rounding_time:
                        key_dt = self.ceilTime(key_dt)
                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        latency[labels[i]][key_dt.strftime(DT_FMT)] = "%.2f" % (overs[i])

                    latency["ops/sec"][key_dt.strftime(DT_FMT)] = "%.1f" % (rate)
                    yield key_dt, latency
                    for key in latency:
                        latency[key] = {}
                    # Prepare for next slice:
                    which_slice = which_slice + 1
                    after_dt = new_dt + slice_timedelta
                    old_total, old_values, old_dt = new_total, new_values, new_dt

                # Print averages and maximums:
                if which_slice > 0:
                    for i in range(max_bucket):
                        if i % arg_every_nth == 0:
                            avg_overs[i] = avg_overs[i] / which_slice
                    avg_rate = total_ops / total_seconds
                    for i in range(max_bucket):
                        if i % arg_every_nth:
                            continue
                        latency[labels[i]]["avg"] = "%.2f" % (avg_overs[i])
                        latency[labels[i]]["max"] = "%.2f" % (max_overs[i])
                    latency["ops/sec"]["avg"] = "%.1f" % (avg_rate)
                    latency["ops/sec"]["max"] = "%.1f" % (max_rate)

                yield END_ROW_KEY, latency
