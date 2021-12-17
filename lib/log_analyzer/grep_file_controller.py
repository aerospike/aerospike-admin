import logging

from lib.utils import util, constants
from lib.base_controller import ShellException

from .log_analyzer_command_controller import LogAnalyzerCommandController


class _GrepFile(LogAnalyzerCommandController):
    def __init__(self, modifiers):
        self.modifiers = modifiers
        self.logger = logging.getLogger("asadm")

    def do_show(self, line):
        if not line:
            raise ShellException(
                "Could not understand log request, " + "see 'help log'"
            )

        mods = self.parse_modifiers(line, duplicates_in_line_allowed=True)
        line = mods["line"]

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
            if word == "-s":
                reading_strings = search_strs
                string_read = True
            elif word == "-a":
                is_and = True
            elif word == "-v":
                reading_strings = ignore_strs
                string_read = True
            elif word == "-i":
                is_casesensitive = False
            elif word == "-u":
                uniq = True
            elif word == "-sg":
                system_grep = True
            elif word == "-f":
                start_tm = tline.pop(0)
                start_tm = util.strip_string(start_tm)
            elif word == "-d":
                duration = tline.pop(0)
                duration = util.strip_string(duration)
            elif word == "-p":
                try:
                    output_page_size = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning("Wrong output page size, setting default value")
            elif word == "-n":
                try:
                    sources = [
                        int(i) for i in util.strip_string(tline.pop(0)).split(",")
                    ]
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
                    "Do not understand '%s' in '%s'" % (word, " ".join(line))
                )
            if not string_read:
                reading_strings = None

        if not search_strs:
            return

        logs = self.log_handler.get_logs_by_index(sources)

        if not logs:
            self.logger.info("No log files added. Use add command to add log files.")

        show_results = self.log_handler.grep(
            logs,
            search_strs,
            ignore_strs=ignore_strs,
            is_and=is_and,
            is_casesensitive=is_casesensitive,
            start_tm_arg=start_tm,
            duration_arg=duration,
            uniq=uniq,
            output_page_size=output_page_size,
            system_grep=system_grep,
        )

        page_index = 1
        for show_res in show_results:
            if show_res:
                self.view.show_grep("", show_res[constants.SHOW_RESULT_KEY])
                page_index += 1
        show_results.close()

    def do_count(self, line):
        if not line:
            raise ShellException(
                "Could not understand log request, " + "see 'help log'"
            )

        mods = self.parse_modifiers(line, duplicates_in_line_allowed=True)
        line = mods["line"]

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
            if word == "-s":
                reading_strings = search_strs
                string_read = True
            elif word == "-a":
                is_and = True
            elif word == "-v":
                reading_strings = ignore_strs
                string_read = True
            elif word == "-i":
                is_casesensitive = False
            elif word == "-u":
                uniq = True
            elif word == "-sg":
                system_grep = True
            elif word == "-p":
                try:
                    output_page_size = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning("Wrong output page size, setting default value")
            elif word == "-r":
                try:
                    title_every_nth = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output title repetition value, setting default value"
                    )
            elif word == "-f":
                start_tm = tline.pop(0)
                start_tm = util.strip_string(start_tm)
            elif word == "-d":
                duration = tline.pop(0)
                duration = util.strip_string(duration)
            elif word == "-t":
                slice_duration = tline.pop(0)
                slice_duration = util.strip_string(slice_duration)
            elif word == "-n":
                try:
                    sources = [
                        int(i) for i in util.strip_string(tline.pop(0)).split(",")
                    ]
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
                    "Do not understand '%s' in '%s'" % (word, " ".join(line))
                )
            if not string_read:
                reading_strings = None

        if not search_strs:
            return

        logs = self.log_handler.get_logs_by_index(sources)

        if not logs:
            self.logger.info("No log files added. Use add command to add log files.")

        count_results = self.log_handler.grep_count(
            logs,
            search_strs,
            ignore_strs=ignore_strs,
            is_and=is_and,
            is_casesensitive=is_casesensitive,
            start_tm_arg=start_tm,
            duration_arg=duration,
            uniq=uniq,
            slice_duration=slice_duration,
            output_page_size=output_page_size,
            system_grep=system_grep,
        )

        page_index = 1
        for count_res in count_results:
            if count_res:
                self.view.show_grep_count(
                    "%s(Page-%d)" % ("cluster ", page_index),
                    count_res,
                    title_every_nth=title_every_nth,
                )

                page_index += 1
        count_results.close()

    def do_diff(self, line):
        if not line:
            raise ShellException(
                "Could not understand log request, " + "see 'help log'"
            )

        mods = self.parse_modifiers(line, duplicates_in_line_allowed=True)
        line = mods["line"]

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
            if word == "-s":
                try:
                    search_strs.append(util.strip_string(tline.pop(0)))
                    reading_search_strings = True
                    search_string_read = True
                except Exception:
                    search_strs = []
            elif word == "-f":
                start_tm = tline.pop(0)
                start_tm = util.strip_string(start_tm)
            elif word == "-d":
                duration = tline.pop(0)
                duration = util.strip_string(duration)
            elif word == "-t":
                slice_tm = tline.pop(0)
                slice_tm = util.strip_string(slice_tm)
            elif word == "-k":
                show_count = tline.pop(0)
                show_count = int(util.strip_string(show_count))
            elif word == "-i":
                is_casesensitive = False
            elif word == "-p":
                try:
                    output_page_size = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning("Wrong output page size, setting default value")
            elif word == "-r":
                try:
                    title_every_nth = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output title repetition value, setting default value"
                    )
            elif word == "-n":
                try:
                    sources = [
                        int(i) for i in util.strip_string(tline.pop(0)).split(",")
                    ]
                except Exception:
                    sources = []
            elif word == "-l" and tline:
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
                    "Do not understand '%s' in '%s'" % (word, " ".join(line))
                )
            if not search_string_read:
                reading_search_strings = False

        if not search_strs:
            return

        logs = self.log_handler.get_logs_by_index(sources)

        if not logs:
            self.logger.info("No log files added. Use add command to add log files.")

        diff_results = self.log_handler.grep_diff(
            logs,
            search_strs,
            is_casesensitive=is_casesensitive,
            start_tm_arg=start_tm,
            duration_arg=duration,
            slice_duration=slice_tm,
            every_nth_slice=show_count,
            upper_limit_check=limit,
            output_page_size=output_page_size,
        )

        page_index = 1
        for diff_res in diff_results:
            if diff_res:
                self.view.show_grep_diff(
                    "%s Diff (Page-%d)" % (search_strs[-1], page_index),
                    diff_res,
                    title_every_nth=title_every_nth,
                )

                page_index += 1
        diff_results.close()

    def do_latency(self, line):
        if not line:
            raise ShellException(
                "Could not understand latency request, " + "see 'help log'"
            )
        mods = self.parse_modifiers(line, duplicates_in_line_allowed=True)
        line = mods["line"]
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
            if word == "-h":
                hist = tline.pop(0)
                hist = util.strip_string(hist)
            elif word == "-f":
                start_tm = tline.pop(0)
                start_tm = util.strip_string(start_tm)
            elif word == "-d":
                duration = tline.pop(0)
                duration = util.strip_string(duration)
            elif word == "-t":
                slice_tm = tline.pop(0)
                slice_tm = util.strip_string(slice_tm)
            elif word == "-e":
                every_nth_bucket = tline.pop(0)
                every_nth_bucket = int(util.strip_string(every_nth_bucket))
            elif word == "-b":
                bucket_count = tline.pop(0)
                bucket_count = int(util.strip_string(bucket_count))
            elif word == "-p":
                try:
                    output_page_size = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning("Wrong output page size, setting default value")
            elif word == "-r":
                try:
                    title_every_nth = int(util.strip_string(tline.pop(0)))
                except Exception:
                    self.logger.warning(
                        "Wrong output title repetition value, setting default value"
                    )
            elif word == "-n":
                try:
                    sources = [
                        int(i) for i in util.strip_string(tline.pop(0)).split(",")
                    ]
                except Exception:
                    sources = []
            elif word == "-o":
                time_rounding = False
            elif word == "-N":
                try:
                    ns = tline.pop(0)
                    ns = util.strip_string(ns)
                except Exception:
                    pass
            elif word == "--relative-stats":
                show_relative_stats = True
            else:
                raise ShellException(
                    "Do not understand '%s' in '%s'" % (word, " ".join(line))
                )

        if not hist:
            return

        ns_hist = ""
        if ns:
            ns_hist += "%s - " % (ns)
        ns_hist += "%s" % (hist)

        logs = self.log_handler.get_logs_by_index(sources)

        if not logs:
            self.logger.info(
                "No log files added. Use 'add /path/to/log' command to add log files."
            )

        latency_results = self.log_handler.loglatency(
            logs,
            hist,
            start_tm_arg=start_tm,
            duration_arg=duration,
            slice_duration=slice_tm,
            bucket_count=bucket_count,
            every_nth_bucket=every_nth_bucket,
            rounding_time=time_rounding,
            output_page_size=output_page_size,
            ns=ns,
            show_relative_stats=show_relative_stats,
        )

        page_index = 1
        for latency_res in latency_results:
            if latency_res:
                if not self.view.show_log_latency(
                    "%s Latency (Page-%d)" % (ns_hist, page_index),
                    latency_res,
                    title_every_nth=title_every_nth,
                ):
                    break
                page_index += 1
        latency_results.close()
