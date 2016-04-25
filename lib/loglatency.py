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
#------------------------------------------------
# log_latency.py
#
# Analyze histograms in a server log file.
# Typical usage:
#	$ ./log_latency.py -h reads
# which uses defaults:
# -l /var/log/aerospike/aerospike.log
# -t 10
# -f tail
# -n 3
# -e 3
# (-d - not set, infinite duration)
# (-r - automatic with -f tail)
#------------------------------------------------


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

BUCKET_LABELS = ("00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
                 "10", "11", "12", "13", "14", "15", "16")
ALL_BUCKETS = len(BUCKET_LABELS)
DT_FMT = "%b %d %Y %H:%M:%S"
DT_TO_MINUTE_FMT = "%b %d %Y %H:%M"
DT_TIME_FMT = "%H:%M:%S"
HIST_TAG_PREFIX = "histogram dump: "
SCAN_SIZE = 1024 * 1024


#===========================================================
# Globals
#

g_rolling = False


#===========================================================
# Function Definitions
#

#------------------------------------------------
# Wait (in another thread) for user to hit return key.
#

def wait_for_user_input():
    global g_rolling
    # Save terminal settings:
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    # Turn terminal echo off temporarily:
    new = old[:]
    new[3] &= ~termios.ECHO
    set_flags = termios.TCSAFLUSH
    if hasattr(termios, "TCSASOFT"):
        set_flags |= termios.TCSASOFT
    termios.tcsetattr(fd, set_flags, new)
    # Using non-blocking input method since daemons don't work in Python 2.4:
    while g_rolling:
        r, w, x = select.select([fd], [], [], 0.1)
        if len(r) != 0:
            g_rolling = False
    # Restore terminal echo:
    termios.tcsetattr(fd, set_flags, old)

#------------------------------------------------
# Also wait for user to hit ctrl-c.
#


def signal_handler(signal, frame):
    global g_rolling
    g_rolling = False

#------------------------------------------------
# Read a complete line from the log file.
#


def read_line(file_id):
    global g_rolling
    line = ""
    while True:
        line = line + file_id.readline()
        if line.endswith("\n"):
            return line
        if not g_rolling:
            break
        time.sleep(0.1)

#------------------------------------------------
# Parse a histogram total from a log line.
#


def parse_total_ops(line, file_id):
    return long(line[line.rfind("(") + 1: line.rfind(" total)")])

#------------------------------------------------
# Get one set of bucket values.
#


def read_bucket_values(line, file_id):
    values = {}
    for b in range(ALL_BUCKETS):
        values[b] = 0
    total = parse_total_ops(line, file_id)
    line = read_line(file_id)
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
        line = read_line(file_id)
        if not line:
            return 0, 0, 0
        b_min = b_min + found
    return total, values, line

#------------------------------------------------
# Subtract one set of bucket values from another.
#


def subtract_buckets(new_values, old_values):
    slice_values = {}
    for b in range(ALL_BUCKETS):
        if new_values[b] < old_values[b]:
            new_values[b] = old_values[b]
        slice_values[b] = new_values[b] - old_values[b]
    return slice_values

#------------------------------------------------
# Get the percentage of operations within every bucket.
#


def bucket_percentages(total, values):
    percentages = [0.0] * ALL_BUCKETS
    if total > 0:
        for b in range(ALL_BUCKETS):
            percentages[b] = (float(values[b]) / total) * 100
    return percentages

#------------------------------------------------
# Get the percentage of operations in all buckets > bucket.
#


def percentage_over(bucket, percentages):
    percentage = 0.0
    for b in range(ALL_BUCKETS):
        if b > bucket:
            percentage = percentage + percentages[b]
    return percentage


def ceilTime(dt):
   seconds = 10 - (dt.second  % 10)
   if seconds == 10:
       return dt
   return dt + datetime.timedelta(0, seconds, -dt.microsecond)

#------------------------------------------------
# Parse a datetime from a log line.
#


def parse_dt(line):
    prefix = line[0: line.find(" GMT")]
    return datetime.datetime(
        *(time.strptime(prefix.split(",")[0], DT_FMT)[0:6]))

#------------------------------------------------
# Get a histogram at or just after the specified datetime.
#


def read_hist(hist_tag, after_dt, file_id, line=0):
    prefix_to_minute = after_dt.strftime(DT_TO_MINUTE_FMT)
    if not line:
        line = read_line(file_id)
    while True:
        if not line:
            return 0, 0, 0, 0
        if line.startswith(prefix_to_minute):
            break
        line = read_line(file_id)
    while True:
        if hist_tag in line:
            dt = parse_dt(line)
            if dt >= after_dt:
                break
        line = read_line(file_id)
        if not line:
            return 0, 0, 0, 0
    total, values, line = read_bucket_values(line, file_id)
    if not line:
        return 0, 0, 0, 0
    return total, values, dt, line

#------------------------------------------------
# Find first log line datetime.
#


def read_head_dt(file_id):
    line = read_line(file_id)
    if not line:
        print "empty log file"
        return 0
    return parse_dt(line)

#------------------------------------------------
# Find last (complete) log line datetime.
#


def read_tail_dt(file_id, file_name):
    line_size = 2048
    while True:
        if line_size > os.stat(file_name)[6]:
            file_id.seek(0, 0)
            lines = file_id.read().rsplit("\n", 2)
            if len(lines) == 1:
                print "shouldn't get here - shrinking file?"
                return 0
            break
        file_id.seek(-line_size, 2)
        lines = file_id.read().rsplit("\n", 2)
        if len(lines) > 2:
            break
        line_size = line_size + 2048
    return parse_dt(lines[1])

#------------------------------------------------
# Parse (positive) timedelta from user input.
#


def parse_timedelta(arg):
    toks = arg.split(":")
    num_toks = len(toks)
    if num_toks > 3:
        return 0
    toks.reverse()
    try:
        arg_seconds = long(toks[0].strip())
        if num_toks > 1:
            arg_seconds = arg_seconds + (60 * long(toks[1].strip()))
        if num_toks > 2:
            arg_seconds = arg_seconds + (3600 * long(toks[2].strip()))
    except:
        return 0
    return datetime.timedelta(seconds=arg_seconds)


#------------------------------------------------
# Parse absolute or relative datetime from user input.
#
def parse_init_dt(arg_from, tail_dt):
    if arg_from.startswith("-"):
        # Relative start time:
        try:
            init_dt = tail_dt - parse_timedelta(arg_from.strip("- "))
        except:
            print "can't parse relative start time " + arg_from
            return 0
    else:
        # Absolute start time:
        try:
            init_dt = datetime.datetime(
                *(time.strptime(arg_from, DT_FMT)[0:6]))
        except:
            print "can't parse absolute start time " + arg_from
            return 0
    return init_dt

#------------------------------------------------
# Get a timedelta in seconds.
#


def elapsed_seconds(td):
    return td.seconds + (td.days * 24 * 3600)

#------------------------------------------------
# Seek backwards to first log line with time before init_dt.
#


def seek_back(init_dt, head_dt, tail_dt, file_id, file_name):
    if init_dt == head_dt:
        file_id.seek(0, 0)
        return
    file_seconds = elapsed_seconds(tail_dt - head_dt)
    if file_seconds < 3600:
        file_id.seek(0, 0)
        return
    back_seconds = elapsed_seconds(tail_dt - init_dt)
    file_size = os.stat(file_name)[6]
    seek_size = (file_size * back_seconds) / file_seconds
    if seek_size < SCAN_SIZE:
        seek_size = SCAN_SIZE
    if seek_size >= file_size - SCAN_SIZE:
        file_id.seek(0, 0)
        return
    file_id.seek(-seek_size, 2)
    while True:
        file_id.readline()
        dt = parse_dt(file_id.readline())
        if dt < init_dt:
            return
        if SCAN_SIZE >= file_id.tell():
            file_id.seek(0, 0)
            return
        file_id.seek(-SCAN_SIZE, 1)

#------------------------------------------------
# Generate padding.
#


def repeat(what, n):
    pad = ""
    for i in range(n):
        pad = pad + what
    return pad

#------------------------------------------------
# Print a latency data output line.
#


def print_line(slice_tag, overs, num_buckets, every_nth, rate=0,
               slice_seconds_actual=0):
    output = "%8s" % (slice_tag)
    if slice_seconds_actual != 0:
        output = output + "%6s" % (slice_seconds_actual)
    else:
        output = output + repeat(" ", 6)
    for i in range(num_buckets):
        if i % every_nth == 0:
            output = output + "%7.2f" % (overs[i])
    output = output + "%9.1f" % (rate)
    print output

#------------------------------------------------
# Print usage.
#


def usage():
    print "Usage:"
    print " -l log file"
    print "    default: /var/log/aerospike/aerospike.log"
    print " -h histogram name"
    print "    MANDATORY - NO DEFAULT"
    print "    e.g. 'reads nonet'"
    print " -t analysis slice interval"
    print "    default: 10"
    print "    other e.g. 3600 or 1:00:00"
    print " -f log time from which to analyze"
    print "    default: tail"
    print "    other e.g. head or 'Sep 22 2011 22:40:14' or -3600 or -1:00:00"
    print " -d maximum duration for which to analyze"
    print "    default: not set"
    print "    e.g. 3600 or 1:00:00"
    print " -n number of buckets to display"
    print "    default: 3"
    print " -e show 0-th then every n-th bucket"
    print "    default: 3"
    print " -r (roll until user hits return key or ctrl-c)"
    print "    default: set if -f tail, otherwise not set"

#------------------------------------------------
# Main function.
#


def loglatency(arg_log, arg_hist, arg_slice, arg_from, arg_duration,
               arg_num_buckets, arg_every_nth, arg_rounding_time=True):
    global g_rolling
    latency = {}
    latency["ops/sec"] = {}

    # Sanity-check some arguments:
    if arg_hist is None:
        usage()
        #sys.exit(-1)
        return arg_from,latency
    if arg_num_buckets < 1:
        #print "num_buckets must be more than 0"
        #sys.exit(-1)
        return arg_from,latency
    if arg_every_nth < 1:
        #print "every_nth must be more than 0"
        #sys.exit(-1)
        return arg_from,latency

    # Set slice timedelta:
    slice_timedelta = parse_timedelta(arg_slice)
    if not slice_timedelta:
        #print "invalid slice time " + arg_slice
        #sys.exit(-1)
        return arg_from,latency

    # Find index + 1 of last bucket to display:
    for b in range(ALL_BUCKETS):
        if b % arg_every_nth == 0:
            max_bucket = b + 1
            if arg_num_buckets == 1:
                break
            else:
                arg_num_buckets = arg_num_buckets - 1

    # Open the log file:
    try:
        file_id = open(arg_log, "r")
    except:
        print "log file " + arg_log + " not found."
        #sys.exit(-1)
        return arg_from,latency

    # Set histogram tag:
    hist_tag = HIST_TAG_PREFIX + arg_hist + " "

    # After this point we may need user input to stop:
    if arg_from == "tail":
        g_rolling = True
    if g_rolling:
        input_thread = threading.Thread(target=wait_for_user_input)
        # Note - apparently daemon threads just don't work in Python 2.4.
        # For Python versions where daemons work, set thread as non-daemon so
        # non-blocking input method can restore terminal echo when g_rolling is
        # set False via ctrl-c.
        input_thread.daemon = False
        input_thread.start()
        # Also wait for ctrl-c:
        signal.signal(signal.SIGINT, signal_handler)

    # Print first line of output table header to let user know we're live:
    # print arg_hist

    # Find datetime at which to start, and seek to starting point:
    head_dt = read_head_dt(file_id)
    if arg_from == "head":
        init_dt = head_dt
        file_id.seek(0, 0)
    else:
        tail_dt = read_tail_dt(file_id, arg_log)
        if arg_from == "tail":
            init_dt = tail_dt
        else:
            init_dt = parse_init_dt(arg_from, tail_dt)
            if not init_dt:
                g_rolling = False
                #sys.exit(-1)
                return arg_from,latency
            if init_dt < head_dt:
                init_dt = head_dt
        seek_back(init_dt, head_dt, tail_dt, file_id, arg_log)

    # Find first histogram:
    old_total, old_values, old_dt, line = \
        read_hist(hist_tag, init_dt, file_id)
    if not line:
        #print "can't find histogram " + arg_hist + \
        #    " from start time " + arg_from
        g_rolling = False
        return arg_from,latency
        #sys.exit(-1)

    # Find datetime at which to stop, if any:
    if arg_duration is not None:
        duration_td = parse_timedelta(arg_duration)
        if not duration_td:
            #print "invalid duration " + arg_duration
            g_rolling = False
            #sys.exit(-1)
            return arg_from,latency
        end_dt = old_dt + duration_td

    # Print the output table header:
    labels_prefix = "slice-to (sec)"
    # print old_dt.strftime(DT_FMT)
    # print repeat(" ", len(labels_prefix)) + " % > (ms)"
    labels = []
    for i in range(max_bucket):
        labels.append(0)
        if i % arg_every_nth == 0:
            labels[i] = pow(2, i)
            latency[pow(2, i)] = {}
    # print labels
    underline = repeat("-", len(labels_prefix))
    for i in range(max_bucket):
        if i % arg_every_nth == 0:
            underline = underline + " ------"
    underline = underline + " --------"
    # print underline

    # Other initialization before processing time slices:
    which_slice = 0
    after_dt = old_dt + slice_timedelta
    overs, avg_overs, max_overs = \
        [0.0] * max_bucket, [0.0] * max_bucket, [0.0] * max_bucket
    total_ops, total_seconds = 0, 0
    max_rate = 0.0

    # Process all the time slices:
    while arg_duration is None or end_dt > old_dt:
        new_total, new_values, new_dt, line = \
            read_hist(hist_tag, after_dt, file_id, line)
        if not line:
            # Note - we ignore the (possible) incomplete slice at the end.
            break

        # Get the "deltas" for this slice:
        slice_total = new_total - old_total
        slice_values = subtract_buckets(new_values, old_values)
        slice_seconds_actual = elapsed_seconds(new_dt - old_dt)

        # Get the rate for this slice:
        rate = round(float(slice_total) / slice_seconds_actual, 1)
        total_ops = total_ops + slice_total
        total_seconds = total_seconds + slice_seconds_actual
        if rate > max_rate:
            max_rate = rate

        # Convert bucket values for this slice to percentages:
        percentages = bucket_percentages(slice_total, slice_values)

        # For each (displayed) theshold, accumulate percentages over threshold:
        for i in range(max_bucket):
            if i % arg_every_nth:
                continue
            overs[i] = round(percentage_over(i, percentages), 2)
            avg_overs[i] = avg_overs[i] + overs[i]
            if overs[i] > max_overs[i]:
                max_overs[i] = overs[i]

        # Print this slice's data:
        slice_to = new_dt.strftime(DT_TIME_FMT)
        #latency[new_dt.strftime(DT_FMT)] = get_line(overs, max_bucket, arg_every_nth, rate)
        key_dt = new_dt
        if arg_rounding_time:
            key_dt = ceilTime(new_dt)

        for i in range(max_bucket):
            if i % arg_every_nth:
                continue
            latency[labels[i]][key_dt.strftime(DT_FMT)] = "%.2f" % (overs[i])

        latency["ops/sec"][key_dt.strftime(DT_FMT)] = "%.1f" % (rate)

        #print_line(slice_to, overs, max_bucket, arg_every_nth, rate, slice_seconds_actual)

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
        # print underline
        #print_line("avg", avg_overs, max_bucket, arg_every_nth, avg_rate)
        #print_line("max", max_overs, max_bucket, arg_every_nth, max_rate)
        for i in range(max_bucket):
            if i % arg_every_nth:
                continue
            latency[labels[i]]["avg"] = "%.2f" % (avg_overs[i])
            latency[labels[i]]["max"] = "%.2f" % (max_overs[i])
        latency["ops/sec"]["avg"] = "%.1f" % (avg_rate)
        latency["ops/sec"]["max"] = "%.1f" % (max_rate)
        #latency["avg"] = get_line(avg_overs, max_bucket, arg_every_nth, avg_rate)
        #latency["max"] = get_line(max_overs, max_bucket, arg_every_nth, max_rate)
    else:
        print "could not find " + str(slice_timedelta) + " of data"

    # Should not need this, but daemon threads don't work in Python 2.4:
    # (Only needed when both -d and -r options are set.)
    g_rolling = False
    return arg_from, latency
