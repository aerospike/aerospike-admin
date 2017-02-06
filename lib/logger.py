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

import copy
import ntpath
from lib import logutil
import os
from lib.logsnapshot import LogSnapshot
from lib.serverlog import ServerLog
from lib.logreader import LogReader, SHOW_RESULT_KEY, COUNT_RESULT_KEY, END_ROW_KEY, TOTAL_ROW_HEADER
from lib import terminal
import re

DT_FMT = "%b %d %Y %H:%M:%S"
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

class Logger(object):
    logInfo = {}
    all_cluster_files = {}
    selected_cluster_files = {}
    all_server_files = {}
    selected_server_files = {}

    def __init__(self, log_path):
        self.log_path = log_path
        self.log_reader = LogReader()
        self.add_cluster_snapshots(path=log_path)

        fg_color_re = re.compile("^(fg_(.*))$")
        self.fg_colors = map(
            lambda v: (
                fg_color_re.match(v).groups()[1], getattr(
                    terminal, fg_color_re.match(v).group(1))), filter(
                lambda x: fg_color_re.search(x) and "clear" not in x, dir(terminal)))

        bg_color_re = re.compile("^(bg_(.*))$")
        self.bg_colors = map(
            lambda v: (
                bg_color_re.match(v).groups()[1], getattr(
                    terminal, bg_color_re.match(v).group(1))), filter(
                lambda x: bg_color_re.search(x) and "clear" not in x, dir(terminal)))

    def __str__(self):
        files = self.get_list(cluster_snapshot=True, all_list=True)
        retval = ""

        i = 1
        for timestamp in sorted(files.keys()):
            nodes = self.log_reader.get_nodes(files[timestamp])
            if len(nodes) == 0:
                continue
            retval += "\n " + str(i) + ": "
            retval += ntpath.basename(files[timestamp])
            retval += " ("
            retval += str(timestamp)
            retval += ")"
            retval += "\n\tFound %s nodes" % (len(nodes))
            retval += "\n\tOnline:  %s" % (", ".join(nodes))
            retval += "\n"
            i = i + 1

        return retval

    def create_log_snapshot(self, timestamp="", file=""):
        if not file:
            return None
        if not timestamp:
            timestamp = self.log_reader.get_timestamp(file)
        if not timestamp:
            return None
        return LogSnapshot(timestamp=timestamp, cluster_file=file, log_reader=self.log_reader)

    def create_server_log(self, display_name="", file=""):
        if not file:
            return None
        if not display_name:
            display_name = self.log_reader.get_server_node_id(file)
        if not display_name:
            return None
        return ServerLog(display_name=display_name, server_file=file, log_reader=self.log_reader)

    def get_log_snapshot(self, timestamp=""):
        if not timestamp or timestamp not in self.all_cluster_files:
            return None
        return self.all_cluster_files[timestamp]

    def get_server_log(self, display_name=""):
        if not display_name or display_name not in self.all_server_files:
            return None
        return self.all_server_files[display_name]

    def get_node(self, path):
        for node, fpath in self.selected_server_files.iteritems():
            if path == fpath:
                return node
        return path

    def get_files_by_index(self, clusterMode, indices=[]):
        if clusterMode:
            files = {}
            if indices:
                timestamps = sorted(self.all_cluster_files.keys())
                for index in indices:
                    try:
                        files[timestamps[index -1]] = [self.all_cluster_files[timestamps[index-1]]]
                    except Exception:
                        continue
            else:
                for timestamp in self.selected_cluster_files:
                    try:
                        files[timestamp] = [self.selected_cluster_files[timestamp]]
                    except Exception:
                        continue
            return files
        else:
            files = []
            if indices:
                nodes = sorted(self.all_server_files.keys())
                for index in indices:
                    try:
                        files.append(self.all_server_files[nodes[index - 1]])
                    except Exception:
                        continue
            else:
                for node in sorted(self.selected_server_files.keys()):
                    try:
                        files.append(self.selected_server_files[node])
                    except Exception:
                        continue
            return {"cluster": files}

    def get_files(self, clusterMode, dir_path=""):
        try:
            if not dir_path:
                dir_path = self.log_path
            files = logutil.get_all_files(dir_path)
            if clusterMode:
                cluster_files = []
                for file in files:
                    try:
                        if self.log_reader.is_cluster_log_file(file):
                            cluster_files.append(file)
                    except Exception:
                        pass
                return cluster_files
            else:
                server_files = []
                for file in files:
                    try:
                        if self.log_reader.is_server_log_file(file):
                            server_files.append(file)
                    except Exception:
                        pass
                return server_files
        except Exception:
            return []

    def add_cluster_snapshots(self, path=""):
        snapshots_added = 0
        if not path:
            return snapshots_added, ">>> Wrong path <<<"
        error = ""
        if os.path.isdir(path):
            for file in self.get_files(True, path):
                timestamp = self.log_reader.get_timestamp(file)
                if timestamp:
                    log_snapshot = self.create_log_snapshot(timestamp, file)
                    self.selected_cluster_files[timestamp] = log_snapshot
                    self.all_cluster_files[timestamp] = log_snapshot
                    snapshots_added += 1
                else:
                    error += ">>> Cannot add collectinfo file from asmonitor or any other log file other than collectinfo. Use the one generated by asadm (>=0.0.13). Ignoring " + file + " <<<\n"
            if snapshots_added==0:
                error += ">>> No aerospike collectinfo file available in " + path + ". <<<\n"
        elif os.path.isfile(path) and self.log_reader.is_cluster_log_file(path):
            timestamp = self.log_reader.get_timestamp(path)
            if timestamp:
                log_snapshot = self.create_log_snapshot(timestamp, path)
                self.selected_cluster_files[timestamp] = log_snapshot
                self.all_cluster_files[timestamp] = log_snapshot
                snapshots_added += 1
            else:
                error += ">>> Missing Timestamp in file. Use the collectinfo generated by asadm (>=0.0.13). <<<\n"
        else:
            error += ">>> " + path + " is incorrect path or not an aerospike collectinfo file <<<\n"
        return snapshots_added, error

    def add_server_logs(self, prefix="", path=""):
        server_logs_added = 0
        if not path:
            return server_logs_added, ">>> Wrong path <<<"
        error = ""
        if os.path.isdir(path):
            count = 0
            for file in self.get_files(False, path):
                file_key = self.log_reader.get_server_node_id(file)
                if not file_key:
                    if not prefix:
                        error += ">>> " + file + " is not new aerospike server log file with node id. Please provide prefix to set name for it. <<<\n"
                        continue
                    file_key = prefix + str(count)
                    count += 1
                server_log = self.create_server_log(display_name=file_key, file=file)
                self.all_server_files[file_key] = server_log
                self.selected_server_files[file_key] = server_log
                server_logs_added += 1
            if server_logs_added==0:
                error += ">>> No aerospike server log file available in " + path + ". <<<\n"
        elif os.path.isfile(path) and self.log_reader.is_server_log_file(path):
            file_key = self.log_reader.get_server_node_id(path)
            if file_key or prefix:
                if not file_key:
                    file_key = prefix
                server_log = self.create_server_log(display_name=file_key, file=path)
                self.all_server_files[file_key] = server_log
                self.selected_server_files[file_key] = server_log
                server_logs_added += 1
            else:
                error += ">>> " + path + " is not new aerospike server log file with node id. Please provide prefix to set name for it. <<<\n"
        else:
            error += ">>> " + path + " is incorrect path or not an aerospike server log file. <<<\n"
        return server_logs_added, error

    def get_name_by_index(self, indices, cluster_snapshot=True, from_all_list=True):
        selected_names = []
        if not indices:
            return selected_names

        if cluster_snapshot:
            if from_all_list:
                log_names = sorted(self.all_cluster_files.keys())
            else:
                log_names = sorted(self.selected_cluster_files.keys())
        else:
            if from_all_list:
                log_names = sorted(self.all_server_files.keys())
            else:
                log_names = sorted(self.selected_server_files.keys())

        if isinstance(indices, int):
            indices = [indices]
        if indices=='all' or 'all' in indices:
            indices = range(len(log_names))
        if isinstance(indices, list):
            for index in indices:
                try:
                    selected_names.append(log_names[index])
                except Exception:
                    continue
        return selected_names

    def remove_logs(self, logs, cluster_snapshot=True, from_all_list=True):
        if not logs:
            return
        for log in logs:
            try:
                if cluster_snapshot:
                    if from_all_list:
                        if log in self.all_cluster_files:
                            self.all_cluster_files[log].destroy()
                            del self.all_cluster_files[log]
                    if log in self.selected_cluster_files:
                            del self.selected_cluster_files[log]
                else:
                    if from_all_list:
                        if log in self.all_server_files:
                            self.all_server_files[log].destroy()
                            del self.all_server_files[log]
                    if log in self.selected_server_files:
                            del self.selected_server_files[log]
            except Exception:
                continue

    def get_list(self, cluster_snapshot=True, all_list=True):
        log_entries = {}
        if cluster_snapshot:
            if all_list:
                snapshot_list = self.all_cluster_files
            else:
                snapshot_list = self.selected_cluster_files
            for snapshot in snapshot_list:
                log_entries[snapshot] = snapshot_list[snapshot].cluster_file
        else:
            if all_list:
                server_list = self.all_server_files
            else:
                server_list = self.selected_server_files
            for server in server_list:
                log_entries[server] = server_list[server].server_file
        return log_entries

    def select_cluster_snapshots(self, year="", month="", date="", hr="", minutes="", sec=""):
        snapshots = self.all_cluster_files.keys()

        if year:
            snapshots = filter(lambda timestamp: logutil.check_time(year,self.log_reader.get_time(timestamp),DATE_SEG,YEAR),snapshots)
        if month:
            snapshots = filter(lambda timestamp: logutil.check_time(month,self.log_reader.get_time(timestamp),DATE_SEG,MONTH),snapshots)
        if date:
            snapshots = filter(lambda timestamp: logutil.check_time(date,self.log_reader.get_time(timestamp),DATE_SEG,DATE),snapshots)
        if hr:
            snapshots = filter(lambda timestamp: logutil.check_time(hr,self.log_reader.get_time(timestamp),TIME_SEG,HH),snapshots)
        if minutes:
            snapshots = filter(lambda timestamp: logutil.check_time(minutes,self.log_reader.get_time(timestamp),TIME_SEG,MM),snapshots)
        if sec:
            snapshots = filter(lambda timestamp: logutil.check_time(sec,self.log_reader.get_time(timestamp),TIME_SEG,SS),snapshots)

        self.selected_cluster_files.clear()
        for snapshot in snapshots:
            self.selected_cluster_files[snapshot] = self.all_cluster_files[snapshot]

    def select_logs(self, indices="all", cluster_snapshot=True):
        if not indices or not isinstance(indices,list):
            return
        if cluster_snapshot:
            all_list = self.all_cluster_files
            selected_list = self.selected_cluster_files
        else:
            all_list = self.all_server_files
            selected_list = self.selected_server_files

        all_log_keys = sorted(all_list.keys())
        if indices=='all' or 'all' in indices:
            indices = range(len(all_log_keys))
        #selected_list.clear()

        for index in indices:
            try:
                selected_list[all_log_keys[int(index) - 1]] = all_list[all_log_keys[int(index) - 1]]
            except Exception:
                continue

    def get_data(self, type="", stanza=""):
        res_dic = {}
        if not stanza or not type:
            return res_dic

        for timestamp in sorted(self.selected_cluster_files.keys()):
            try:
                res_dic[timestamp] = self.selected_cluster_files[timestamp].get_data(type=type, stanza=stanza)
            except Exception:
                continue

        return res_dic

    def infoGetConfig(self, stanza=""):
        return self.get_data(type="config", stanza=stanza)

    def infoStatistics(self, stanza=""):
        return self.get_data(type="statistics", stanza=stanza)

    def infoGetHistogram(self, stanza=""):
        return self.get_data(type="distribution", stanza=stanza)

    def infoSummary(self, stanza=""):
        return self.get_data(type="summary", stanza=stanza)

    def get_diff_fg_bg_color(self, old_fg_index, old_bg_index):
        new_fg_index = old_fg_index + 1
        new_bg_index = old_bg_index
        if new_fg_index >= len(self.fg_colors):
            new_fg_index = 0
            new_bg_index = (new_bg_index + 1) % len(self.bg_colors)

        while(self.bg_colors[new_bg_index][0] == self.fg_colors[new_fg_index][0]):
            new_fg_index += 1
            if new_fg_index >= len(self.fg_colors):
                new_fg_index = 0
                new_bg_index = (new_bg_index + 1) % len(self.bg_colors)

        return new_fg_index, new_bg_index

    def get_fg_bg_color_index_list(self, list_size):
        fg_color = 2
        bg_color = 6
        colors = []
        for i in range(list_size):
            fg_color, bg_color = self.get_diff_fg_bg_color(fg_color, bg_color)
            colors.append((fg_color, bg_color))
        return colors


    def grep(
            self,
            file_handlers, search_strs, ignore_strs=[], is_and=False, is_casesensitive=True, start_tm_arg="head", duration_arg="",
            uniq=False, grep_cluster_logs=True, output_page_size = 10, system_grep=False
            ):
        if file_handlers and search_strs:
            if grep_cluster_logs:
                for file_handler in file_handlers:
                    file_handler.set_input(search_strs=search_strs, ignore_strs=ignore_strs, is_and=is_and, is_casesensitive=is_casesensitive)
                    show_it = file_handler.show_iterator()
                    show_result = {}
                    show_result[SHOW_RESULT_KEY] = show_it.next()
                    yield show_result
                    show_it.close()
            else:
                show_its = {}
                min_start_tm = min(s.get_start_tm(start_tm=start_tm_arg) for s in file_handlers)
                for file_handler in file_handlers:
                    file_handler.set_input(search_strs=search_strs, ignore_strs=ignore_strs, is_and=is_and, is_casesensitive=is_casesensitive,
                                           start_tm=min_start_tm, duration=duration_arg, system_grep=system_grep, uniq=uniq)
                    show_its[file_handler.display_name] = file_handler.show_iterator()
                merger = self.server_log_merger(show_its, return_strings=True, output_page_size=output_page_size)
                for val in merger:
                    yield val
                for it in show_its:
                    show_its[it].close()
                merger.close()


    def grepCount(self,
                  file_handlers, search_strs, ignore_strs=[], is_and=False, is_casesensitive=True, start_tm_arg="head", duration_arg="",
                  uniq=False, slice_duration="600", grep_cluster_logs=True, output_page_size=10, system_grep=False
                  ):
        try:
            if file_handlers and search_strs:
                try:
                    if grep_cluster_logs:
                        for file_handler in file_handlers:
                            file_handler.set_input(search_strs=search_strs, ignore_strs=ignore_strs, is_and=is_and, is_casesensitive=is_casesensitive)
                            count_it = file_handler.count_iterator()
                            count_result = {}
                            count_result[file_handler.timestamp] = {}
                            count_result[file_handler.timestamp][COUNT_RESULT_KEY] = {}
                            count_result[file_handler.timestamp][COUNT_RESULT_KEY][TOTAL_ROW_HEADER] = count_it.next()
                            yield count_result
                            count_it.close()
                    else:
                        count_its = {}
                        min_start_tm = min(s.get_start_tm(start_tm=start_tm_arg) for s in file_handlers)
                        for file_handler in file_handlers:
                            file_handler.set_input(search_strs=search_strs, ignore_strs=ignore_strs, is_and=is_and, is_casesensitive=is_casesensitive,
                                                   start_tm=min_start_tm, duration=duration_arg, slice_duration=slice_duration, uniq=uniq, system_grep=system_grep)
                            count_its[file_handler.display_name] = file_handler.count_iterator()

                        merger = self.server_log_merger(count_its, output_page_size=output_page_size, default_value=0)
                        for val in merger:
                            yield val
                        for it in count_its:
                            count_its[it].close()
                        merger.close()
                except Exception:
                    pass
        except Exception:
            pass

    def grepDiff(self,
                 file_handlers, search_strs, is_casesensitive=True, start_tm_arg="head", duration_arg="",
                 slice_duration="600", every_nth_slice=1, upper_limit_check="", output_page_size=10
                 ):
        try:
            if file_handlers and search_strs:
                diff_its = {}
                min_start_tm = min(s.get_start_tm(start_tm=start_tm_arg) for s in file_handlers)
                for file_handler in file_handlers:
                    file_handler.set_input(search_strs=search_strs, is_casesensitive=is_casesensitive, is_and=True,
                                           start_tm=min_start_tm, duration=duration_arg, slice_duration=slice_duration, upper_limit_check=upper_limit_check,
                                           every_nth_slice=every_nth_slice)
                    diff_its[file_handler.display_name] = file_handler.diff_iterator()

                merger = self.server_log_merger(diff_its, output_page_size=output_page_size)
                for val in merger:
                    yield val
                for it in diff_its:
                    diff_its[it].close()
                merger.close()
        except Exception:
            pass

    def loglatency(self,
                   file_handlers, hist, start_tm_arg="head", duration_arg="", slice_duration="10",
                   bucket_count=3, every_nth_bucket=1, rounding_time=True, output_page_size=10, ns=None
                   ):
        try:
            if file_handlers and hist:
                latency_its = {}
                min_start_tm = min(s.get_start_tm(start_tm=start_tm_arg) for s in file_handlers)
                for file_handler in file_handlers:
                    file_handler.set_input(search_strs=hist, start_tm=min_start_tm, duration=duration_arg, slice_duration=slice_duration,
                                           bucket_count=bucket_count, every_nth_bucket=every_nth_bucket,
                                           read_all_lines=True, rounding_time=rounding_time, ns=ns)
                    latency_its[file_handler.display_name] = file_handler.latency_iterator()

                merger = self.server_log_merger(latency_its, output_page_size=output_page_size)
                for val in merger:
                    yield val
                for it in latency_its:
                    latency_its[it].close()
                merger.close()
        except Exception:
            pass

    def server_log_merger(self, file_streams, output_page_size=3, return_strings=False, end_key=END_ROW_KEY, default_value=[]):
        latency_end={}
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
                tm, res = file_streams[key].next()
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
                    keys_in_input = res.keys()
            tm_keys[key] = tm
            result[key] = res

        if return_strings:
            colors = self.get_fg_bg_color_index_list(len(file_streams))

        while need_to_process:
            need_to_process = False
            try:
                min_keys = [k for k, x in tm_keys.items() if not any(y < x for y in tm_keys.values())]
            except Exception:
                break
            if not min_keys:
                break
            current_tm = tm_keys[min_keys[0]]
            for file_key in sorted(file_streams.keys()):
                if file_key in min_keys:
                    if return_strings:
                        try:
                            merge_result[SHOW_RESULT_KEY] += "%s  %s%s::" % (self.bg_colors[colors[(file_streams.keys().index(file_key))][0]][1](), terminal.reset(), file_key)
                        except Exception:
                            merge_result[SHOW_RESULT_KEY] = "%s  %s%s::" % (self.bg_colors[colors[(file_streams.keys().index(file_key))][0]][1](), terminal.reset(), file_key)
                        merge_result[SHOW_RESULT_KEY] += result[file_key]
                    else:
                        if merge_result[file_key]:
                            for k in keys_in_input:
                                merge_result[file_key][k].update(result[file_key][k])
                        else:
                            merge_result[file_key].update(result[file_key])
                    del result[file_key]
                    del tm_keys[file_key]
                    try:
                        tm, res = file_streams[file_key].next()
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
                        merge_result[file_key][k][current_tm.strftime(DT_FMT)] = default_value
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
            self.balance_dict(latency_end, file_streams.keys(), default_value)
            for file_key in latency_end:
                if file_key not in merge_result or not merge_result[file_key]:
                    merge_result[file_key] = latency_end[file_key]
                else:
                    for sub_key in latency_end[file_key]:
                        if sub_key not in merge_result[file_key] or not merge_result[file_key][sub_key]:
                            merge_result[file_key][sub_key] = latency_end[file_key][sub_key]
                        else:
                            merge_result[file_key][sub_key].update(latency_end[file_key][sub_key])
            yield merge_result

    def balance_dict(self, d, keys, default_value):
        if not d or not isinstance(d, dict):
            return d
        structure = self.get_dict_structure(d[d.keys()[0]], default_value)
        for key in keys:
            if not key in d.keys() or not d[key]:
                d[key] = structure

    def get_dict_structure(self, d, val=[]):
        if not isinstance(d, dict):
            return val
        structure = {}
        for key in d:
            if not isinstance(d[key], dict):
                structure[key] = val
            else:
                structure[key] = self.get_dict_structure(d[key], val)
        return structure
