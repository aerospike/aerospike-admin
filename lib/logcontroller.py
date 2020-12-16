# Copyright 2013-2020 Aerospike, Inc.
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

import logging

from lib.controllerlib import BaseController, CommandController, CommandHelp, ShellException
from lib.log.loghdlr import Loghdlr
from lib.utils import util
from lib.utils.constants import SHOW_RESULT_KEY
from lib.view import terminal
from lib.view.view import CliView


class LogCommandController(CommandController):

    loghdlr = None

    def __init__(self, loghdlr):
        LogCommandController.loghdlr = loghdlr


@CommandHelp('Aerospike Admin')
class LogRootController(BaseController):

    loghdlr = None

    def __init__(self, asadm_version='', log_path=" "):

        super(LogRootController, self).__init__(asadm_version)

        # Create static instance of loghdlr
        LogRootController.loghdlr = Loghdlr(log_path)

        LogRootController.command = LogCommandController(self.loghdlr)

        self.controller_map = {
            'add': AddController,
            'list': ListController,
            'select': SelectController,
            'remove': RemoveController,
            'grep': GrepController,
            'diff': DiffController,
            'count': CountController,
            'histogram': HistogramController,
            'pager': PagerController}

    @CommandHelp('Terminate session')
    def do_exit(self, line):
        # This function is a hack for autocomplete
        return "EXIT"

    @CommandHelp(
        'Returns documentation related to a command',
        'for example, to retrieve documentation for the "info"',
        'command use "help info".')
    def do_help(self, line):
        self.execute_help(line)


@CommandHelp(
    'Displays all lines from server logs matched with input strings.',
    '  Options:',
    '    -s <string>  - Space seprated Strings to search in log files, MANDATORY - NO DEFAULT',
    '                   Format -s \'string1\' \'string2\'... \'stringn\'',
    '    -a           - Set \'AND\'ing of search strings (provided with -s): Finding lines with all search strings in it.',
    '                   Default is \'OR\'ing: Finding lines with atleast one search string in it.',
    '    -v <string>  - Non-matching strings (space separated).',
    '    -i           - Perform case insensitive matching of search strings (-s) and non-matching strings (-v).',
    '                   By default it is case sensitive.',
    '    -u           - Set to find unique lines.',
    '    -f <string>  - Log time from which to analyze.',
    '                   May use the following formats:  \'Sep 22 2011 22:40:14\', -3600, or \'-1:00:00\'.',
    '                   Default: head',
    '    -d <string>  - Maximum time period to analyze.',
    '                   May use the following formats: 3600 or 1:00:00.',
    '    -n <string>  - Comma separated node numbers. You can get these numbers by list command. Ex. : -n \'1,2,5\'.',
    '                   If not set then runs on all server logs in selected list.',
    '    -p <int>     - Showing output in pages with p entries per page. default: 10.')
class GrepController(LogCommandController):

    def __init__(self):
        self.modifiers = set()
        self.grep_file = _GrepFile(self.modifiers)

    def _do_default(self, line):
        self.grep_file.do_show(line)


@CommandHelp(
    'Displays count of lines from server logs matched with input strings.',
    '  Options:',
    '    -s <string>  - Space seprated Strings to search in log files, MANDATORY - NO DEFAULT',
    '                   Format -s \'string1\' \'string2\'... \'stringn\'',
    '    -a           - Set \'AND\'ing of search strings (provided with -s): Finding lines with all serach strings in it.',
    '                   Default is \'OR\'ing: Finding lines with atleast one search string in it.',
    '    -v <string>  - Non-matching strings (space separated).',
    '    -i           - Perform case insensitive matching of search strings (-s) and non-matching strings (-v).',
    '                   By default it is case sensitive.',
    '    -u           - Set to find unique lines.',
    '    -f <string>  - Log time from which to analyze.',
    '                   May use the following formats:  \'Sep 22 2011 22:40:14\', -3600, or \'-1:00:00\'.',
    '                   default: head',
    '    -d <string>  - Maximum time period to analyze.',
    '                   May use the following formats: 3600 or 1:00:00.',
    '    -t <string>  - Counting matched lines per interval of t.',
    '                   May use the following formats: 60 or 1:00:00. default: 600 seconds.',
    '    -n <string>  - Comma separated node numbers. You can get these numbers by list command. Ex. : -n \'1,2,5\'.',
    '                   If not set then runs on all server logs in selected list.',
    '    -p <int>     - Showing output in pages with p entries per page. default: 10.',
    '    -r           - Repeat output table title and row header after every <terminal width> columns.',
    '                   default: False, no repetition.')
class CountController(LogCommandController):

    def __init__(self):
        self.modifiers = set()
        self.grep_file = _GrepFile(self.modifiers)

    def _do_default(self, line):
        self.grep_file.do_count(line)


@CommandHelp(
    'Displays set of values and difference between consecutive values for input string in server logs.',
    'Currently it is working for following KEY and VALUE patterns:',
    '        1) KEY<space>VALUE',
    '        2) KEY<space>(VALUE)',
    '        3) KEY<space>(Comma separated VALUE list)',
    '        4) KEY<space>(VALUE',
    '        5) VALUE1(VALUE2)<space>KEY',
    '  Options:',
    '    -s <string>  - The Key to search in log files, MANDATORY - NO DEFAULT',
    '                   Multiple strings can be given to analyse actual context, but these multiple search strings should',
    '                   present in same line and in same order as they mentioned here.',
    '                   Ex. to analyse key "avail pct" across all namespace : -s "avail pct" ',
    '                       to analyse key "avail pct" for namespace test : -s test "avail pct"',
    '    -i           - Perform case insensitive matching. By default it is case sensitive.',
    '    -f <string>  - Log time from which to analyze.',
    '                   May use the following formats:  \'Sep 22 2011 22:40:14\', -3600, or \'-1:00:00\'.',
    '                   default: head',
    '    -d <string>  - Maximum time period to analyze.',
    '                   May use the following formats: 3600 or 1:00:00.',
    '    -t <string>  - Analysis slice interval in seconds or time format (hh:mm:ss). default: 10 seconds.',
    '    -l <string>  - Show results with at least one diff value greater than or equal to limit.',
    '    -k <string>  - Show 0-th then every k-th result. default: 1.',
    '    -n <string>  - Comma separated node numbers. You can get these numbers by list command. Ex. : -n \'1,2,5\'.',
    '                   If not set then runs on all server logs in selected list.',
    '    -p <int>     - Showing output in pages with p entries per page. default: 10.',
    '    -r <int>     - Repeating output table title and row header after every r node columns.',
    '                   default: 0, no repetition.')
class DiffController(LogCommandController):

    def __init__(self):
        self.modifiers = set()
        self.grep_file = _GrepFile(self.modifiers)

    def _do_default(self, line):
        self.grep_file.do_diff(line)


@CommandHelp(
    'Displays histogram information for Aerospike server log.',
    '  Options:',
    '    -h <string>  - Histogram Name, MANDATORY - NO DEFAULT',
    '    -f <string>  - Log time from which to analyze e.g. head or "Sep 22 2011 22:40:14" or -3600 or -1:00:00,',
    '                   default: head',
    '    -d <string>  - Maximum duration for which to analyze, e.g. 3600 or 1:00:00',
    '    -t <string>  - Analysis slice interval, default: 10,  e.g. 3600 or 1:00:00',
    '    -b <string>  - Number of buckets to display, default: 3',
    '    -e <string>  - Show 0-th then every e-th bucket, default: 3',
    '    -o           - Showing original time range for slices. Default is showing time with seconds value rounded to next nearest multiple of 10.',
    '    -n <string>  - Comma separated node numbers. You can get these numbers by list command. Ex. : -n \'1,2,5\'',
    '                   If not set then runs on all server logs in selected list.',
    '    -p <int>     - Showing output in pages with p entries per page. default: 10.',
    '    -r <int>     - Repeating output table title and row header after every r node columns.',
    '                   default: 0, no repetition.',
    '    -N <string>  - Namespace name. It will display histogram latency for ns namespace.',
    '                   This feature is available for namespace level histograms in server >= 3.9.')
class HistogramController(LogCommandController):

    def __init__(self):
        self.modifiers = set()
        self.grep_file = _GrepFile(self.modifiers)

    def _do_default(self, line):
        self.grep_file.do_latency(line)


@CommandHelp(
    "Adds server logs.",
    "For log file of server (version >=3.7.1), "
    "asadm fetches node id from log and set it as a display name. Otherwise uses MD5_<MD5_hash_of_path>.",
    "Format : add \'server log path1\' \'server log path2\' \'server log directory path\' ...")
class AddController(LogCommandController):

    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        length = len(line)
        if length < 1:
            return

        for index in range(0, length, 1):
            if index == length:
                break

            path = util.strip_string(line[index])

            n_log_added, error = self.loghdlr.add_log_files_at_path(path)

            if n_log_added == 1:
                print("%d server log added for server analysis." % (n_log_added))
            elif n_log_added > 1:
                print("%d server logs added for server analysis." % (n_log_added))

            if error:
                self.logger.error(error)


@CommandHelp('Displays list of all server logs.')
class ListController(LogCommandController):

    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_default(self, line):
        print(terminal.bold() + "Added Logs:" + terminal.unbold(), end=' ')
        index = 1
        all_log_files = self.loghdlr.get_log_files(all_list=True)
        for key in sorted(all_log_files.keys()):
            print("\n" + str(index) + "  : " + key.ljust(20) + all_log_files[key], end=' ')
            index += 1
        if index == 1:
            print(" None", end=' ')
        print("\n")


        print("\n" + terminal.bold() + "Selected Logs:" + terminal.unbold(), end=' ')
        index = 1
        selected_log_files = self.loghdlr.get_log_files(all_list=False)
        for key in sorted(selected_log_files.keys()):
            print("\n" + " ".ljust(5) + key.ljust(20) + selected_log_files[key], end=' ')
            index += 1
        if index == 1:
            print(" None", end=' ')

        print("\n")


@CommandHelp(
    'Select list of server logs. Use \'all\' to add all server logs.',
    'or specify server log numbers',
    'Use \'list\' command for list of server logs and respective numbers.',
    'Format : select all  OR  select 1 2 3')
class SelectController(LogCommandController):

    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_default(self, line):
        self.loghdlr.select_logs_by_index(line)


@CommandHelp(
    'Remove Logs from list of server logs. Use \'all\' to remove all server logs.',
    'or specify server log numbers',
    'Use \'list\' command for list of server logs and respective numbers.',
    'Format : remove all   OR remove 1 2 3')
class RemoveController(LogCommandController):

    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.loghdlr.remove_logs_by_index(line)


@CommandHelp("Set pager for output")
class PagerController(LogCommandController):

    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)

    @CommandHelp("Displays output with vertical and horizontal paging for each output table same as linux 'less' command.",
                 "Use arrow keys to scroll output and 'q' to end page for table.",
                 "All linux less commands can work in this pager option.")
    def do_on(self, line):
        CliView.pager = CliView.LESS

    @CommandHelp("Removes pager and prints output normally")
    def do_off(self, line):
        CliView.pager = CliView.NO_PAGER

    @CommandHelp("Display output in scrolling mode")
    def do_scroll(self, line):
        CliView.pager = CliView.SCROLL



class _GrepFile(LogCommandController):

    def __init__(self, modifiers):
        self.modifiers = modifiers
        self.logger = logging.getLogger('asadm')

    def do_show(self, line):
        if not line:
            raise ShellException("Could not understand log request, " +
                                 "see 'help log'")

        mods = self.parse_modifiers(line, duplicates_in_line_allowed=True)
        line = mods['line']

        tline = line[:]
        search_strs = []
        ignore_strs = []
        output_page_size = 10
        start_tm = "head"
        duration = ""
        sources = []
        is_and = False
        is_casesensitive = True
        reading_strings = None
        uniq = False
        system_grep = False
        while tline:
            string_read = False
            word = tline.pop(0)
            if word == '-s':
                reading_strings = search_strs
                string_read = True
            elif word == '-a':
                is_and = True
            elif word == '-v':
                reading_strings = ignore_strs
                string_read = True
            elif word == '-i':
                is_casesensitive = False
            elif word == '-u':
                uniq = True
            elif word == '-sg':
                system_grep = True
            elif word == '-f':
                start_tm = tline.pop(0)
                start_tm = util.strip_string(start_tm)
            elif word == '-d':
                duration = tline.pop(0)
                duration = util.strip_string(duration)
            elif word == '-p':
                try:
                    output_page_size = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output page size, setting default value")
            elif word == '-n':
                try:
                    sources = [
                        int(i) for i in util.strip_string(
                            tline.pop(0)).split(",")]
                except Exception:
                    sources = []
            elif reading_strings is not None:
                try:
                    reading_strings.append(util.strip_string(word))
                except Exception:
                    pass
                string_read = True
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'" % (word, " ".join(line)))
            if not string_read:
                reading_strings = None

        if not search_strs:
            return

        logs = self.loghdlr.get_logs_by_index(sources)

        if not logs:
            self.logger.info("No log files added. Use add command to add log files.")

        show_results = self.loghdlr.grep(logs, search_strs, ignore_strs=ignore_strs, is_and=is_and,
                                         is_casesensitive=is_casesensitive, start_tm_arg=start_tm, duration_arg=duration, uniq=uniq,
                                         output_page_size=output_page_size, system_grep=system_grep)

        page_index = 1
        for show_res in show_results:
            if show_res:
                self.view.show_grep("", show_res[SHOW_RESULT_KEY])
                page_index += 1
        show_results.close()

    def do_count(self, line):
        if not line:
            raise ShellException("Could not understand log request, " +
                                 "see 'help log'")

        mods = self.parse_modifiers(line, duplicates_in_line_allowed=True)
        line = mods['line']

        tline = line[:]
        search_strs = []
        ignore_strs = []
        output_page_size = 10
        is_and = False
        is_casesensitive = True
        start_tm = "head"
        duration = ""
        slice_duration = "600"
        sources = []
        reading_strings = None
        title_every_nth = 0
        uniq = False
        system_grep = False
        while tline:
            string_read = False
            word = tline.pop(0)
            if word == '-s':
                reading_strings = search_strs
                string_read = True
            elif word == '-a':
                is_and = True
            elif word == '-v':
                reading_strings = ignore_strs
                string_read = True
            elif word == '-i':
                is_casesensitive = False
            elif word == '-u':
                uniq = True
            elif word == '-sg':
                system_grep = True
            elif word == '-p':
                try:
                    output_page_size = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output page size, setting default value")
            elif word == '-r':
                try:
                    title_every_nth = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output title repetition value, setting default value")
            elif word == '-f':
                start_tm = tline.pop(0)
                start_tm = util.strip_string(start_tm)
            elif word == '-d':
                duration = tline.pop(0)
                duration = util.strip_string(duration)
            elif word == '-t':
                slice_duration = tline.pop(0)
                slice_duration = util.strip_string(slice_duration)
            elif word == '-n':
                try:
                    sources = [
                        int(i) for i in util.strip_string(
                            tline.pop(0)).split(",")]
                except Exception:
                    sources = []
            elif reading_strings is not None:
                try:
                    reading_strings.append(util.strip_string(word))
                except Exception:
                    pass
                string_read = True
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'" % (word, " ".join(line)))
            if not string_read:
                reading_strings = None

        if not search_strs:
            return

        logs = self.loghdlr.get_logs_by_index(sources)

        if not logs:
            self.logger.info("No log files added. Use add command to add log files.")

        count_results = self.loghdlr.grep_count(logs, search_strs, ignore_strs=ignore_strs,
                                                is_and=is_and, is_casesensitive=is_casesensitive, start_tm_arg=start_tm, duration_arg=duration,
                                                uniq=uniq, slice_duration=slice_duration, output_page_size=output_page_size, system_grep=system_grep)

        page_index = 1
        for count_res in count_results:
            if count_res:
                self.view.show_grep_count("%s(Page-%d)" %
                                          ("cluster ", page_index), count_res,
                                          title_every_nth=title_every_nth)

                page_index += 1
        count_results.close()

    def do_diff(self, line):
        if not line:
            raise ShellException("Could not understand log request, " +
                                 "see 'help log'")

        mods = self.parse_modifiers(line, duplicates_in_line_allowed=True)
        line = mods['line']

        tline = line[:]
        search_strs = []
        start_tm = "head"
        duration = ""
        slice_tm = "10"
        output_page_size = 10
        show_count = 1
        limit = ""
        sources = []
        is_casesensitive = True
        title_every_nth = 0
        reading_search_strings = False
        search_string_read = False

        while tline:
            search_string_read = False
            word = tline.pop(0)
            if word == '-s':
                try:
                    search_strs.append(util.strip_string(tline.pop(0)))
                    reading_search_strings = True
                    search_string_read = True
                except Exception:
                    search_strs = []
            elif word == '-f':
                start_tm = tline.pop(0)
                start_tm = util.strip_string(start_tm)
            elif word == '-d':
                duration = tline.pop(0)
                duration = util.strip_string(duration)
            elif word == '-t':
                slice_tm = tline.pop(0)
                slice_tm = util.strip_string(slice_tm)
            elif word == '-k':
                show_count = tline.pop(0)
                show_count = int(util.strip_string(show_count))
            elif word == '-i':
                is_casesensitive = False
            elif word == '-p':
                try:
                    output_page_size = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output page size, setting default value")
            elif word == '-r':
                try:
                    title_every_nth = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output title repetition value, setting default value")
            elif word == '-n':
                try:
                    sources = [
                        int(i) for i in util.strip_string(
                            tline.pop(0)).split(",")]
                except Exception:
                    sources = []
            elif word == '-l' and tline:
                limit = tline.pop(0)
                limit = int(util.strip_string(limit))
            elif reading_search_strings:
                try:
                    search_strs.append(util.strip_string(word))
                except Exception:
                    pass
                search_string_read = True
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'" % (word, " ".join(line)))
            if not search_string_read:
                reading_search_strings = False

        if not search_strs:
            return

        logs = self.loghdlr.get_logs_by_index(sources)

        if not logs:
            self.logger.info("No log files added. Use add command to add log files.")

        diff_results = self.loghdlr.grep_diff(logs, search_strs, is_casesensitive=is_casesensitive, start_tm_arg=start_tm,
                                              duration_arg=duration, slice_duration=slice_tm, every_nth_slice=show_count,
                                              upper_limit_check=limit, output_page_size=output_page_size)

        page_index = 1
        for diff_res in diff_results:
            if diff_res:
                self.view.show_grep_diff("%s Diff (Page-%d)" %
                                         (search_strs[-1], page_index),
                                         diff_res, title_every_nth=title_every_nth)

                page_index += 1
        diff_results.close()

    def do_latency(self, line):
        if not line:
            raise ShellException(
                "Could not understand latency request, " +
                "see 'help log'")
        mods = self.parse_modifiers(line, duplicates_in_line_allowed=True)
        line = mods['line']
        tline = line[:]
        hist = ""
        start_tm = "head"
        duration = ""
        slice_tm = "10"
        output_page_size = 10
        bucket_count = 3
        every_nth_bucket = 3
        sources = []
        time_rounding = True
        title_every_nth = 0
        ns = None
        show_relative_stats = False

        while tline:
            word = tline.pop(0)
            if word == '-h':
                hist = tline.pop(0)
                hist = util.strip_string(hist)
            elif word == '-f':
                start_tm = tline.pop(0)
                start_tm = util.strip_string(start_tm)
            elif word == '-d':
                duration = tline.pop(0)
                duration = util.strip_string(duration)
            elif word == '-t':
                slice_tm = tline.pop(0)
                slice_tm = util.strip_string(slice_tm)
            elif word == '-e':
                every_nth_bucket = tline.pop(0)
                every_nth_bucket = int(util.strip_string(every_nth_bucket))
            elif word == '-b':
                bucket_count = tline.pop(0)
                bucket_count = int(util.strip_string(bucket_count))
            elif word == '-p':
                try:
                    output_page_size = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output page size, setting default value")
            elif word == '-r':
                try:
                    title_every_nth = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output title repetition value, setting default value")
            elif word == '-n':
                try:
                    sources = [
                        int(i) for i in util.strip_string(
                            tline.pop(0)).split(",")]
                except Exception:
                    sources = []
            elif word == '-o':
                time_rounding = False
            elif word == '-N':
                try:
                    ns = tline.pop(0)
                    ns = util.strip_string(ns)
                except:
                    pass
            elif word == '--relative-stats':
                show_relative_stats = True
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'" % (word, " ".join(line)))

        if not hist:
            return

        ns_hist = ""
        if ns:
            ns_hist += "%s - " % (ns)
        ns_hist += "%s" % (hist)

        logs = self.loghdlr.get_logs_by_index(sources)

        if not logs:
            self.logger.info("No log files added. Use 'add /path/to/log' command to add log files.")

        latency_results = self.loghdlr.loglatency(logs, hist, start_tm_arg=start_tm, duration_arg=duration,
                                                  slice_duration=slice_tm, bucket_count=bucket_count,
                                                  every_nth_bucket=every_nth_bucket, rounding_time=time_rounding,
                                                  output_page_size=output_page_size, ns=ns,
                                                  show_relative_stats=show_relative_stats)

        page_index = 1
        for latency_res in latency_results:
            if latency_res:
                if not self.view.show_log_latency(
                    "%s Latency (Page-%d)" % (ns_hist, page_index),
                    latency_res, title_every_nth=title_every_nth):
                    break
                page_index += 1
        latency_results.close()
