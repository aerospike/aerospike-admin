# Copyright 2013-2023 Aerospike, Inc.
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

from lib.base_controller import BaseController, CommandHelp, ModifierHelp
from lib.utils import util
from lib.view import terminal
from lib.view.view import CliView

from .log_analyzer_command_controller import LogAnalyzerCommandController
from .grep_file_controller import GrepFile
from .log_handler.log_handler import LogHandler


@CommandHelp("Aerospike Admin")
class LogAnalyzerRootController(BaseController):
    log_handler = None

    def __init__(self, asadm_version="", log_path=" "):
        BaseController.asadm_version = asadm_version

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
        "Displays the documentation for the specified command.",
        "For example, to see the documentation for the 'count' command,",
        "use the command 'help count'.",
        short_msg="Displays the documentation for the specified command",
        hide=True,
    )
    def do_help(self, line):
        self.view.print_result(self.execute_help(line))


@CommandHelp(
    "Displays all lines from server logs matched with input strings.",
    modifiers=(
        ModifierHelp(
            "-s",
            "Space-separated strings to search in log files. Format: -s 'string1' 'string2' ... 'stringn'",
        ),
        ModifierHelp(
            "-a",
            "Set 'AND'ing of search strings (provided with -s): Finding lines with all search strings in it. Default is 'OR'ing: Finding lines with at least one search string in it.",
        ),
        ModifierHelp("-v", "Non-matching strings (space separated)."),
        ModifierHelp(
            "-i",
            "Perform case-insensitive matching of search strings (-s) and non-matching strings (-v)",
        ),
        ModifierHelp("-u", "Set to find unique lines."),
        ModifierHelp(
            "-f",
            "Log time from which to analyze. May use the following formats: 'Sep 22 2011 22:40:14', -3600, or '-1:00:00'",
            default="head",
        ),
        ModifierHelp(
            "-d",
            "Maximum time period to analyze. May use the following formats: 3600 or 1:00:00.",
        ),
        ModifierHelp(
            "-n",
            "Comma-separated node numbers. You can get these numbers by the list command. Example: -n '1,2,5'. If not set, then runs on all server logs in the selected list.",
        ),
        ModifierHelp(
            "-p", "Showing output in pages with p entries per page", default="10"
        ),
    ),
)
class GrepController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()
        self.required_modifiers = set()
        self.grep_file = GrepFile(self.modifiers, self.required_modifiers)

    def _do_default(self, line):
        self.grep_file.do_show(line)


@CommandHelp(
    "Displays count of lines from server logs matched with input strings.",
    modifiers=(
        ModifierHelp(
            "-s",
            "Space separated strings to search in log files. Format: -s 'string-1' 'string-2' ... 'string-n'",
        ),
        ModifierHelp(
            "-a",
            "Set 'AND'ing of search strings (provided with -s): Finding lines with all search strings in it. Default is 'OR'ing: Finding lines with at least one search string in it.",
        ),
        ModifierHelp("-v", "Non-matching strings (space separated)."),
        ModifierHelp(
            "-i",
            "Perform case insensitive matching of search strings (-s) and non-matching strings (-v)",
        ),
        ModifierHelp("-u", "Set to find unique lines."),
        ModifierHelp(
            "-f",
            "Log time from which to analyze. May use the following formats: 'Sep 22 2011 22:40:14', -3600, or '-1:00:00'.",
            default="head",
        ),
        ModifierHelp(
            "-d",
            "Maximum time period to analyze. May use the following formats: 3600 or 1:00:00.",
        ),
        ModifierHelp(
            "-t",
            "Counting matched lines per interval of t. May use the following formats: 60 or 1:00:00",
            default="600 seconds",
        ),
        ModifierHelp(
            "-n",
            "Comma separated node numbers. You can get these numbers by the list command. Example: -n '1,2,5'. If not set, then runs on all server logs in the selected list.",
        ),
        ModifierHelp(
            "-p", "Showing output in pages with p entries per page.", default="10"
        ),
        ModifierHelp(
            "-r",
            "Repeat output table title and row header after every <terminal width> columns",
            default="False, no repetition.",
        ),
    ),
)
class CountController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()
        self.required_modifiers = set()
        self.grep_file = GrepFile(self.modifiers, self.required_modifiers)

    def _do_default(self, line):
        self.grep_file.do_count(line)


@CommandHelp(
    "Displays set of values and difference between consecutive values for input string in server logs.",
    usage="-s <string> [-i] [-f <string>] [-d <string>] [-t <string>] [-l <int>] [-k <int>] [-n <string>] [-p <int>] [-r <int>]",
    modifiers=(
        ModifierHelp(
            "-s",
            "The Key to search in log files. Multiple strings can be given to analyze actual context, but these multiple search strings should be present in the same line and in the same order as they are mentioned here. Example: to analyze key 'avail pct' across all namespaces: -s 'avail pct', to analyze key 'avail pct' for namespace test: -s test 'avail pct'. Currently it is working for the following KEY and VALUE patterns: 'KEY<space>VALUE', 'KEY<space>(VALUE)', 'KEY<space>(Comma separated VALUE list)', 'KEY<space>(VALUE', and 'VALUE1(VALUE2)<space>KEY'",
        ),
        ModifierHelp("-i", "Perform case insensitive matching"),
        ModifierHelp(
            "-f",
            "Log time from which to analyze. May use the following formats: 'Sep 22 2011 22:40:14', -3600, or '-1:00:00'",
            default="head",
        ),
        ModifierHelp(
            "-d",
            "Maximum time period to analyze. May use the following formats: 3600 or 1:00:00.",
        ),
        ModifierHelp(
            "-t",
            "Analysis slice interval in seconds or time format (hh:mm:ss)",
            default="10",
        ),
        ModifierHelp(
            "-l",
            "Show results with at least one diff value greater than or equal to the limit.",
        ),
        ModifierHelp("-k", "Show 0-th then every k-th result", default="1"),
        ModifierHelp(
            "-n",
            "Comma separated node numbers. You can get these numbers by the list command. Example: -n '1,2,5'. If not set, then runs on all server logs in the selected list.",
        ),
        ModifierHelp(
            "-p", "Showing output in pages with p entries per page", default="10."
        ),
        ModifierHelp(
            "-r",
            "Repeating output table title and row header after every r node columns",
            default="0, no repetition.",
        ),
    ),
)
class DiffController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()
        self.required_modifiers = set()
        self.grep_file = GrepFile(self.modifiers, self.required_modifiers)

    def _do_default(self, line):
        self.grep_file.do_diff(line)


@CommandHelp(
    "Displays histogram information for Aerospike server log.",
    usage="-h <histogram-name> [-f <start-time>] [-d <duration>] [-t <interval>] [-b <bucket-count>] [-e <exponent-increment>] [-o] [-n <nodes>] [-p <entries-per-page>] [-r <int>] [-N <ns>]",
    modifiers=(
        ModifierHelp("-h", "Histogram Name"),
        ModifierHelp(
            "-f",
            'Log time from which to analyze e.g. head or "Sep 22 2011 22:40:14" or -3600 or -1:00:00.',
            default="head",
        ),
        ModifierHelp(
            "-d", "Maximum duration for which to analyze, e.g. 3600 or 1:00:00"
        ),
        ModifierHelp(
            "-t", "Analysis slice interval, e.g. 3600 or 1:00:00", default="10"
        ),
        ModifierHelp("-b", "Number of buckets to display", default="3"),
        ModifierHelp("-e", "Show 0-th then every 2^e-th bucket", default="3"),
        ModifierHelp(
            "-o",
            "Showing original time range for slices. Default is showing time with seconds value rounded to next nearest multiple of 10.",
        ),
        ModifierHelp(
            "-n",
            "Comma separated node numbers. You can get these numbers using the 'list' command. If not set, then runs on all server logs in selected list.",
            default="all",
        ),
        ModifierHelp(
            "-p", "Showing output in pages with p entries per page", default="10"
        ),
        ModifierHelp(
            "-r",
            "Repeating output table title and row header after every r node columns",
            default="0, no repetition.",
        ),
        ModifierHelp(
            "-N",
            "Namespace name. It will display histogram latency for ns namespace.",
        ),
    ),
)
class HistogramController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()
        self.required_modifiers = set()
        self.grep_file = GrepFile(self.modifiers, self.required_modifiers)

    def _do_default(self, line):
        self.grep_file.do_latency(line)


@CommandHelp(
    "Adds server logs for analysis",
    usage="log/file/path.log [log/file/path2.log ...]",
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
    "Select list of server logs",
    modifiers=(
        ModifierHelp("all", "Select all server logs"),
        ModifierHelp(
            "<server-log-num>",
            "Select server log with given number.  Use the 'list' command for list of server logs and respective numbers",
        ),
    ),
    usage="all | <server-log-num> [<server-log-num> ...]",
)
class SelectController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.log_handler.select_logs_by_index(line)


@CommandHelp(
    "Remove Logs from list of server logs",
    modifiers=(
        ModifierHelp("all", "Deselect all server logs"),
        ModifierHelp(
            "<server-log-num>",
            "Deselect server log with given number.  Use the 'list' command for list of server logs and respective numbers",
        ),
    ),
    usage="all | <server-log-num> [<server-log-num> ...]",
)
class RemoveController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.log_handler.remove_logs_by_index(line)


@CommandHelp("Turn terminal pager on and off")
class PagerController(LogAnalyzerCommandController):
    def __init__(self):
        self.modifiers = set()

    @CommandHelp(
        "Displays output with vertical and horizontal paging for each output table same as linux 'less' command. Use arrow keys to scroll output and 'q' to end page for table. All linux less commands can work in this pager option.",
        short_msg="Enables output paging. Similar to linux 'less'",
    )
    def do_on(self, line):
        CliView.pager = CliView.LESS

    @CommandHelp("Disables paging and prints output normally")
    def do_off(self, line):
        CliView.pager = CliView.NO_PAGER

    @CommandHelp("Display output in scrolling mode")
    def do_scroll(self, line):
        CliView.pager = CliView.SCROLL
