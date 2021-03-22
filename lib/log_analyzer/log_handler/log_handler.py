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

import os
import re
import hashlib
import logging

from lib.utils import constants, log_util
from lib.view import terminal

from .log_reader import LogReader
from .server_log import ServerLog


###### Constants ######
DT_TO_MINUTE_FMT = "%b %d %Y %H:%M"
DT_TIME_FMT = "%H:%M:%S"
DATE_SEG = 0
DATE_SEPARATOR = "-"
YEAR = 0
MONTH = 1
DATE = 2

TIME_SEG = 1
TIME_SEPARATOR = ":"
HH = 0
MM = 1
SS = 2


######################


class LogHandler(object):
    all_logs = {}
    selected_logs = {}
    all_system_files = {}
    selected_system_files = {}

    def __init__(self, log_path):
        self.log_path = log_path
        self.logger = logging.getLogger("asadm")

        self.reader = LogReader()

        log_added, err = self.add_log_files_at_path(log_path)

        # Continue in case of error as well. Files
        # can be added later
        if log_added == 0:
            self.logger.info(err)

        fg_color_re = re.compile("^(fg_(.*))$")
        self.fg_colors = [
            (
                fg_color_re.match(v).groups()[1],
                getattr(terminal, fg_color_re.match(v).group(1)),
            )
            for v in [
                x for x in dir(terminal) if fg_color_re.search(x) and "clear" not in x
            ]
        ]

        bg_color_re = re.compile("^(bg_(.*))$")
        self.bg_colors = [
            (
                bg_color_re.match(v).groups()[1],
                getattr(terminal, bg_color_re.match(v).group(1)),
            )
            for v in [
                x for x in dir(terminal) if bg_color_re.search(x) and "clear" not in x
            ]
        ]

    def __str__(self):
        return ""

    def add_log_files_at_path(self, log_path=""):

        if not log_path:
            return 0, "No valid log file added"

        server_logs_added = 0
        if os.path.isdir(log_path):
            for log_file in self._get_valid_log_files(log_path):
                status, err_str = self._add_log_file(log_file)
                if status:
                    self.logger.info("Added Log File " + str(log_file) + ".")
                    server_logs_added += 1

        elif os.path.isfile(log_path):
            status, err_str = self._add_log_file(log_path)
            if status:
                self.logger.info("Added Log File " + str(log_path) + ".")
                server_logs_added += 1
            else:
                return server_logs_added, err_str
        else:
            return (
                0,
                "Incorrect log file path '"
                + str(log_path)
                + "' specified. Use add command to add log files.",
            )

        return server_logs_added, ""

    def get_log_files(self, all_list=True):

        log_entries = {}

        if all_list:
            server_list = self.all_logs
        else:
            server_list = self.selected_logs

        for server in server_list.keys():
            log_entries[server] = server_list[server].file_name

        return log_entries

    def get_logs_by_index(self, indices=[]):

        logs = []
        if indices:
            keys = sorted(self.all_logs.keys())
            for index in indices:
                try:
                    logs.append(self.all_logs[keys[int(index) - 1]])
                except Exception:
                    continue

        else:
            for key in sorted(self.selected_logs.keys()):
                try:
                    logs.append(self.selected_logs[key])
                except Exception:
                    continue

        return logs

    def remove_logs_by_index(self, indices="all"):

        if not indices or not isinstance(indices, list):
            return

        log_names = sorted(self.all_logs.keys())

        if indices == "all" or "all" in indices:
            indices = range(len(self.all_logs))

        for index in indices:
            try:
                print(index)
                log = log_names[int(index) - 1]

                if log in self.all_logs:
                    self.logger.info(
                        "Removed Log File " + str(self.all_logs[log].file_name) + "."
                    )
                    self.all_logs[log].destroy()
                    del self.all_logs[log]

                if log in self.selected_logs:
                    del self.selected_logs[log]

            except Exception as e:
                self.logger.warning(
                    "Ignoring remove operation for index %s. Error: %s"
                    % (str(index), str(e))
                )
                continue

    def select_logs_by_index(self, indices="all"):
        if not indices or not isinstance(indices, list):
            return

        all_list = self.all_logs
        selected_list = {}

        all_log_keys = sorted(all_list.keys())
        if indices == "all" or "all" in indices:
            indices = range(len(all_log_keys))

        for index in indices:
            try:
                selected_list[all_log_keys[int(index) - 1]] = all_list[
                    all_log_keys[int(index) - 1]
                ]
            except Exception:
                continue

        self.selected_logs = selected_list

    def grep(
        self,
        logs,
        search_strs,
        ignore_strs=[],
        is_and=False,
        is_casesensitive=True,
        start_tm_arg="head",
        duration_arg="",
        uniq=False,
        output_page_size=10,
        system_grep=False,
    ):
        """
        Function takes a server log logs, search strings, enable casesensitive, start time, duration, enable uniq,
        slice_duratiion, output page size

        It collects grep_show iterators from all handlers and merge output from them and returns merged lines

        """

        if not logs or not search_strs:
            return

        show_itrs = {}
        min_start_tm = min(s.get_start_tm(start_tm=start_tm_arg) for s in logs)

        for log in logs:
            log.set_input(
                search_strs=search_strs,
                ignore_strs=ignore_strs,
                is_and=is_and,
                is_casesensitive=is_casesensitive,
                start_tm=min_start_tm,
                duration=duration_arg,
                system_grep=system_grep,
                uniq=uniq,
            )

            show_itrs[log.display_name] = log.show_iterator()

        merger = self._server_log_output_merger(
            show_itrs, return_strings=True, output_page_size=output_page_size
        )

        for val in merger:
            yield val

        for itr in show_itrs:
            show_itrs[itr].close()

        merger.close()

    def grep_count(
        self,
        logs,
        search_strs,
        ignore_strs=[],
        is_and=False,
        is_casesensitive=True,
        start_tm_arg="head",
        duration_arg="",
        uniq=False,
        slice_duration="600",
        output_page_size=10,
        system_grep=False,
    ):
        """
        Function takes a server log logs, search strings, enable casesensitive, start time, duration, enable uniq,
        slice_duratiion, output page size

        It collects grep_count iterators from all handlers and merge output from them and returns merged lines

        """

        try:
            if not logs or not search_strs:
                return

            try:
                count_itrs = {}
                min_start_tm = min(s.get_start_tm(start_tm=start_tm_arg) for s in logs)

                for log in logs:
                    log.set_input(
                        search_strs=search_strs,
                        ignore_strs=ignore_strs,
                        is_and=is_and,
                        is_casesensitive=is_casesensitive,
                        start_tm=min_start_tm,
                        duration=duration_arg,
                        slice_duration=slice_duration,
                        uniq=uniq,
                        system_grep=system_grep,
                    )

                    count_itrs[log.display_name] = log.count_iterator()

                merger = self._server_log_output_merger(
                    count_itrs, output_page_size=output_page_size, default_value=0
                )

                for val in merger:
                    yield val

                for itr in count_itrs:
                    count_itrs[itr].close()

                merger.close()

            except Exception:
                pass

        except Exception:
            pass

    def grep_diff(
        self,
        logs,
        search_strs,
        is_casesensitive=True,
        start_tm_arg="head",
        duration_arg="",
        slice_duration="600",
        every_nth_slice=1,
        upper_limit_check="",
        output_page_size=10,
    ):
        """
        Function takes a serverlog logs, search strings, enable casesensitive, start time, duration, slice_duratiion, nth_slice to show,
        output page size

        It collects grep_diff iterators from all handlers and merge output from them and returns merged lines

        """

        try:
            if not logs or not search_strs:
                return

            diff_itrs = {}
            min_start_tm = min(s.get_start_tm(start_tm=start_tm_arg) for s in logs)

            for log in logs:
                log.set_input(
                    search_strs=search_strs,
                    is_casesensitive=is_casesensitive,
                    is_and=True,
                    start_tm=min_start_tm,
                    duration=duration_arg,
                    slice_duration=slice_duration,
                    upper_limit_check=upper_limit_check,
                    every_nth_slice=every_nth_slice,
                )

                diff_itrs[log.display_name] = log.diff_iterator()

            merger = self._server_log_output_merger(
                diff_itrs, output_page_size=output_page_size
            )

            for val in merger:
                yield val

            for itr in diff_itrs:
                diff_itrs[itr].close()

            merger.close()

        except Exception:
            pass

    def loglatency(
        self,
        logs,
        hist,
        start_tm_arg="head",
        duration_arg="",
        slice_duration="10",
        bucket_count=3,
        every_nth_bucket=1,
        rounding_time=True,
        output_page_size=10,
        ns=None,
        show_relative_stats=False,
    ):
        """
        Function takes a serverlog logs, histogram, start time, duration, slice_duratiion, number of buckets, nth_bucket to show, rounding_time,
        output page size, namespace name

        It collects latency iterators from all handlers and merge output from them and returns merged lines

        """

        try:
            if not logs or not hist:
                return

            latency_itrs = {}
            min_start_tm = min(s.get_start_tm(start_tm=start_tm_arg) for s in logs)

            for log in logs:
                log.set_input(
                    search_strs=hist,
                    start_tm=min_start_tm,
                    duration=duration_arg,
                    slice_duration=slice_duration,
                    bucket_count=bucket_count,
                    every_nth_bucket=every_nth_bucket,
                    read_all_lines=True,
                    rounding_time=rounding_time,
                    ns=ns,
                    show_relative_stats=show_relative_stats,
                )

                latency_itrs[log.display_name] = log.latency_iterator()

            merger = self._server_log_output_merger(
                latency_itrs, output_page_size=output_page_size
            )

            for val in merger:
                yield val

            for itr in latency_itrs:
                latency_itrs[itr].close()

            merger.close()

        except Exception:
            pass

    def _get_valid_log_files(self, log_path=""):

        if not log_path:
            log_path = self.log_path

        try:
            server_log_files = []
            log_files = log_util.get_all_files(log_path)
            for log_file in log_files:
                try:
                    if self.reader.is_server_log_file(log_file):
                        server_log_files.append(log_file)
                except Exception:
                    pass
            return server_log_files

        except Exception:
            return []

    def _add_log_file(self, log_file=""):

        for key in self.all_logs:
            if self.all_logs[key].get_filename() == log_file:
                # Skip already added files. No error
                return False, str(log_file) + " is already added."

        if not self.reader.is_server_log_file(log_file):
            return False, str(log_file) + " is not an aerospike log file."

        file_key = self.reader.get_server_node_id(log_file)

        if not file_key:
            file_key = "MD5_" + str(hashlib.md5(log_file).hexdigest())
            file_key = file_key[:15] + " "

        log = ServerLog(file_key, log_file, self.reader)
        self.all_logs[file_key] = log

        # Automatically selected on addition
        self.selected_logs[file_key] = log
        return True, ""

    def _get_diff_fg_bg_color(self, old_fg_index, old_bg_index):
        new_fg_index = old_fg_index + 1
        new_bg_index = old_bg_index
        if new_fg_index >= len(self.fg_colors):
            new_fg_index = 0
            new_bg_index = (new_bg_index + 1) % len(self.bg_colors)

        while self.bg_colors[new_bg_index][0] == self.fg_colors[new_fg_index][0]:
            new_fg_index += 1
            if new_fg_index >= len(self.fg_colors):
                new_fg_index = 0
                new_bg_index = (new_bg_index + 1) % len(self.bg_colors)

        return new_fg_index, new_bg_index

    def _get_fg_bg_color_index_list(self, list_size):
        fg_color = 2
        bg_color = 6
        colors = []

        for i in range(list_size):
            fg_color, bg_color = self._get_diff_fg_bg_color(fg_color, bg_color)
            colors.append((fg_color, bg_color))

        return colors

    def _server_log_output_merger(
        self,
        file_streams,
        output_page_size=3,
        return_strings=False,
        end_key=constants.END_ROW_KEY,
        default_value=[],
    ):
        latency_end = {}
        result = {}
        merge_result = {}
        tm_keys = {}
        need_to_process = False
        keys_in_input = []
        result_count = 0

        for key in file_streams.keys():
            if not return_strings:
                merge_result[key] = {}

            try:
                tm, res = next(file_streams[key])
                if not tm:
                    continue

                if tm == end_key:
                    latency_end[key] = res
                    continue

            except Exception:
                continue

            need_to_process = True
            result[key] = {}
            tm_keys[key] = {}
            if not return_strings:
                if not keys_in_input:
                    keys_in_input = list(res.keys())

            tm_keys[key] = tm
            result[key] = res

        if return_strings:
            colors = self._get_fg_bg_color_index_list(len(file_streams))

        while need_to_process:
            need_to_process = False
            try:
                min_keys = [
                    k
                    for k, x in tm_keys.items()
                    if not any(y < x for y in tm_keys.values())
                ]
            except Exception:
                break

            if not min_keys:
                break

            current_tm = tm_keys[min_keys[0]]
            for file_key in sorted(file_streams.keys()):
                if file_key in min_keys:
                    if return_strings:
                        try:
                            merge_result[constants.SHOW_RESULT_KEY] += "%s  %s%s::" % (
                                self.bg_colors[
                                    colors[(list(file_streams.keys()).index(file_key))][
                                        0
                                    ]
                                ][1](),
                                terminal.reset(),
                                file_key,
                            )
                        except Exception:
                            merge_result[constants.SHOW_RESULT_KEY] = "%s  %s%s::" % (
                                self.bg_colors[
                                    colors[(list(file_streams.keys()).index(file_key))][
                                        0
                                    ]
                                ][1](),
                                terminal.reset(),
                                file_key,
                            )

                        merge_result[constants.SHOW_RESULT_KEY] += result[file_key]

                    else:
                        if merge_result[file_key]:
                            for k in keys_in_input:
                                merge_result[file_key][k].update(result[file_key][k])

                        else:
                            merge_result[file_key].update(result[file_key])

                    del result[file_key]
                    del tm_keys[file_key]

                    try:
                        tm, res = next(file_streams[file_key])
                        if not tm:
                            continue

                        if tm == end_key:
                            latency_end[file_key] = res
                            continue

                    except Exception:
                        continue

                    need_to_process = True
                    tm_keys[file_key] = tm
                    result[file_key] = res

                else:
                    if file_key in tm_keys and tm_keys[file_key]:
                        need_to_process = True

                    if return_strings:
                        continue

                    for k in keys_in_input:
                        if k not in merge_result[file_key]:
                            merge_result[file_key][k] = {}
                        merge_result[file_key][k][
                            current_tm.strftime(constants.DT_FMT)
                        ] = default_value

            result_count += 1
            if result_count == output_page_size:
                yield merge_result
                result_count = 0
                merge_result = {}
                if return_strings:
                    continue

                for key in file_streams.keys():
                    merge_result[key] = {}

        if not latency_end:
            yield merge_result
        else:
            self._balance_dict(latency_end, file_streams.keys(), default_value)
            for file_key in latency_end:
                if file_key not in merge_result or not merge_result[file_key]:
                    merge_result[file_key] = latency_end[file_key]
                else:
                    for sub_key in latency_end[file_key]:
                        if (
                            sub_key not in merge_result[file_key]
                            or not merge_result[file_key][sub_key]
                        ):
                            merge_result[file_key][sub_key] = latency_end[file_key][
                                sub_key
                            ]
                        else:
                            merge_result[file_key][sub_key].update(
                                latency_end[file_key][sub_key]
                            )

            yield merge_result

    def _balance_dict(self, data, keys, default_value):
        if not data or not isinstance(data, dict):
            return data

        structure = self._get_dict_structure(data[list(data.keys())[0]], default_value)

        for _key in keys:
            if _key not in data.keys() or not data[_key]:
                data[_key] = structure

    def _get_dict_structure(self, data, val=[]):
        if not isinstance(data, dict):
            return val
        structure = {}

        for _key in data.keys():
            if not isinstance(data[_key], dict):
                structure[_key] = val
            else:
                structure[_key] = self._get_dict_structure(data[_key], val)

        return structure
