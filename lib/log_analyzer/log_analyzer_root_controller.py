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

from lib.base_controller import BaseController, CommandHelp
from lib.utils import util
from lib.view import terminal
from lib.view.view import CliView

from .log_analyzer_command_controller import LogAnalyzerCommandController
from .grep_file_controller import _GrepFile
from .log_handler.log_handler import LogHandler


@CommandHelp("Aerospike Admin")
class LogAnalyzerRootController(BaseController):

    log_handler = None

    def __init__(self, asadm_version="", log_path=" "):

        super(LogAnalyzerRootController, self).__init__(asadm_version)

        # Create static instance of log_handler
        LogAnalyzerRootController.log_handler = LogHandler(log_path)

        LogAnalyzerRootController.command = LogAnalyzerCommandController(
            self.log_handler
        )

        self.controller_map = {
            "add": AddController,
            "list": ListController,
            "select": SelectController,
            "remove": RemoveController,
            "grep": GrepController,
            "diff": DiffController,
            "count": CountController,
            "histogram": HistogramController,
            "pager": PagerController,
        }

    @CommandHelp("Terminate session")
    def do_exit(self, line):
        # This function is a hack for autocomplete
        return "EXIT"

    @CommandHelp(
        "Returns documentation related to a command",
        'for example, to retrieve documentation for the "info"',
        'command use "help info".',
    )
    def do_help(self, line):
        self.execute_help(line)


@CommandHelp(
    "Displays all lines from server logs matched with input strings.",
    "  Options:",
    "    -s <string>  - Space seprated Strings to search in log files, MANDATORY - NO DEFAULT",
    "                   Format -s 'string1' 'string2'... 'stringn'",
    "    -a           - Set 'AND'ing of search strings (provided with -s): Finding lines with all search strings in it.",
    "                   Default is 'OR'ing: Finding lines with atleast one search string in it.",
    "    -v <string>  - Non-matching strings (space separated).",
    "    -i           - Perform case insensitive matching of search strings (-s) and non-matching strings (-v).",
    "                   By default it is case sensitive.",
    "    -u           - Set to find unique lines.",
    "    -f <string>  - Log time from which to analyze.",
    "                   May use the following formats:  'Sep 22 2011 22:40:14', -3600, or '-1:00:00'.",
    "                   Default: head",
    "    -d <string>  - Maximum time period to analyze.",
    "                   May use the following formats: 3600 or 1:00:00.",
    "    -n <string>  - Comma separated node numbers. You can get these numbers by list command. Ex. : -n '1,2,5'.",
    "                   If not set then runs on all server logs in selected list.",
    "    -p <int>     - Showing output in pages with p entries per page. default: 10.",
)
class GrepController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()
        self.grep_file = _GrepFile(self.modifiers)

    def _do_default(self, line):
        self.grep_file.do_show(line)


@CommandHelp(
    "Displays count of lines from server logs matched with input strings.",
    "  Options:",
    "    -s <string>  - Space seprated Strings to search in log files, MANDATORY - NO DEFAULT",
    "                   Format -s 'string1' 'string2'... 'stringn'",
    "    -a           - Set 'AND'ing of search strings (provided with -s): Finding lines with all serach strings in it.",
    "                   Default is 'OR'ing: Finding lines with atleast one search string in it.",
    "    -v <string>  - Non-matching strings (space separated).",
    "    -i           - Perform case insensitive matching of search strings (-s) and non-matching strings (-v).",
    "                   By default it is case sensitive.",
    "    -u           - Set to find unique lines.",
    "    -f <string>  - Log time from which to analyze.",
    "                   May use the following formats:  'Sep 22 2011 22:40:14', -3600, or '-1:00:00'.",
    "                   default: head",
    "    -d <string>  - Maximum time period to analyze.",
    "                   May use the following formats: 3600 or 1:00:00.",
    "    -t <string>  - Counting matched lines per interval of t.",
    "                   May use the following formats: 60 or 1:00:00. default: 600 seconds.",
    "    -n <string>  - Comma separated node numbers. You can get these numbers by list command. Ex. : -n '1,2,5'.",
    "                   If not set then runs on all server logs in selected list.",
    "    -p <int>     - Showing output in pages with p entries per page. default: 10.",
    "    -r           - Repeat output table title and row header after every <terminal width> columns.",
    "                   default: False, no repetition.",
)
class CountController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()
        self.grep_file = _GrepFile(self.modifiers)

    def _do_default(self, line):
        self.grep_file.do_count(line)


@CommandHelp(
    "Displays set of values and difference between consecutive values for input string in server logs.",
    "Currently it is working for following KEY and VALUE patterns:",
    "        1) KEY<space>VALUE",
    "        2) KEY<space>(VALUE)",
    "        3) KEY<space>(Comma separated VALUE list)",
    "        4) KEY<space>(VALUE",
    "        5) VALUE1(VALUE2)<space>KEY",
    "  Options:",
    "    -s <string>  - The Key to search in log files, MANDATORY - NO DEFAULT",
    "                   Multiple strings can be given to analyse actual context, but these multiple search strings should",
    "                   present in same line and in same order as they mentioned here.",
    '                   Ex. to analyse key "avail pct" across all namespace : -s "avail pct" ',
    '                       to analyse key "avail pct" for namespace test : -s test "avail pct"',
    "    -i           - Perform case insensitive matching. By default it is case sensitive.",
    "    -f <string>  - Log time from which to analyze.",
    "                   May use the following formats:  'Sep 22 2011 22:40:14', -3600, or '-1:00:00'.",
    "                   default: head",
    "    -d <string>  - Maximum time period to analyze.",
    "                   May use the following formats: 3600 or 1:00:00.",
    "    -t <string>  - Analysis slice interval in seconds or time format (hh:mm:ss). default: 10 seconds.",
    "    -l <string>  - Show results with at least one diff value greater than or equal to limit.",
    "    -k <string>  - Show 0-th then every k-th result. default: 1.",
    "    -n <string>  - Comma separated node numbers. You can get these numbers by list command. Ex. : -n '1,2,5'.",
    "                   If not set then runs on all server logs in selected list.",
    "    -p <int>     - Showing output in pages with p entries per page. default: 10.",
    "    -r <int>     - Repeating output table title and row header after every r node columns.",
    "                   default: 0, no repetition.",
)
class DiffController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()
        self.grep_file = _GrepFile(self.modifiers)

    def _do_default(self, line):
        self.grep_file.do_diff(line)


@CommandHelp(
    "Displays histogram information for Aerospike server log.",
    "  Options:",
    "    -h <string>  - Histogram Name, MANDATORY - NO DEFAULT",
    '    -f <string>  - Log time from which to analyze e.g. head or "Sep 22 2011 22:40:14" or -3600 or -1:00:00,',
    "                   default: head",
    "    -d <string>  - Maximum duration for which to analyze, e.g. 3600 or 1:00:00",
    "    -t <string>  - Analysis slice interval, default: 10,  e.g. 3600 or 1:00:00",
    "    -b <string>  - Number of buckets to display, default: 3",
    "    -e <string>  - Show 0-th then every e-th bucket, default: 3",
    "    -o           - Showing original time range for slices. Default is showing time with seconds value rounded to next nearest multiple of 10.",
    "    -n <string>  - Comma separated node numbers. You can get these numbers by list command. Ex. : -n '1,2,5'",
    "                   If not set then runs on all server logs in selected list.",
    "    -p <int>     - Showing output in pages with p entries per page. default: 10.",
    "    -r <int>     - Repeating output table title and row header after every r node columns.",
    "                   default: 0, no repetition.",
    "    -N <string>  - Namespace name. It will display histogram latency for ns namespace.",
    "                   This feature is available for namespace level histograms in server >= 3.9.",
)
class HistogramController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()
        self.grep_file = _GrepFile(self.modifiers)

    def _do_default(self, line):
        self.grep_file.do_latency(line)


@CommandHelp(
    "Adds server logs.",
    "For log file of server (version >=3.7.1), "
    "asadm fetches node ID from log and set it as a display name. Otherwise uses MD5_<MD5_hash_of_path>.",
    "Format : add 'server log path1' 'server log path2' 'server log directory path' ...",
)
class AddController(LogAnalyzerCommandController):
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

            n_log_added, error = self.log_handler.add_log_files_at_path(path)

            if n_log_added == 1:
                print("%d server log added for server analysis." % (n_log_added))
            elif n_log_added > 1:
                print("%d server logs added for server analysis." % (n_log_added))

            if error:
                self.logger.error(error)


@CommandHelp("Displays list of all server logs.")
class ListController(LogAnalyzerCommandController):
    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_default(self, line):
        print(terminal.bold() + "Added Logs:" + terminal.unbold(), end=" ")
        index = 1
        all_log_files = self.log_handler.get_log_files(all_list=True)
        for key in sorted(all_log_files.keys()):
            print(
                "\n" + str(index) + "  : " + key.ljust(20) + all_log_files[key], end=" "
            )
            index += 1
        if index == 1:
            print(" None", end=" ")
        print("\n")

        print("\n" + terminal.bold() + "Selected Logs:" + terminal.unbold(), end=" ")
        index = 1
        selected_log_files = self.log_handler.get_log_files(all_list=False)
        for key in sorted(selected_log_files.keys()):
            print(
                "\n" + " ".ljust(5) + key.ljust(20) + selected_log_files[key], end=" "
            )
            index += 1
        if index == 1:
            print(" None", end=" ")

        print("\n")


@CommandHelp(
    "Select list of server logs. Use 'all' to add all server logs.",
    "or specify server log numbers",
    "Use 'list' command for list of server logs and respective numbers.",
    "Format : select all  OR  select 1 2 3",
)
class SelectController(LogAnalyzerCommandController):
    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_default(self, line):
        self.log_handler.select_logs_by_index(line)


@CommandHelp(
    "Remove Logs from list of server logs. Use 'all' to remove all server logs.",
    "or specify server log numbers",
    "Use 'list' command for list of server logs and respective numbers.",
    "Format : remove all   OR remove 1 2 3",
)
class RemoveController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.log_handler.remove_logs_by_index(line)


@CommandHelp("Set pager for output")
class PagerController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)

    @CommandHelp(
        "Displays output with vertical and horizontal paging for each output table same as linux 'less' command.",
        "Use arrow keys to scroll output and 'q' to end page for table.",
        "All linux less commands can work in this pager option.",
    )
    def do_on(self, line):
        CliView.pager = CliView.LESS

    @CommandHelp("Removes pager and prints output normally")
    def do_off(self, line):
        CliView.pager = CliView.NO_PAGER

    @CommandHelp("Display output in scrolling mode")
    def do_scroll(self, line):
        CliView.pager = CliView.SCROLL
