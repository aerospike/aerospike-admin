import copy
import ntpath
from lib import logutil
import os
from lib.loglatency import loglatency
from lib.logsnapshot import LogSnapshot

__author__ = 'aerospike'

from lib.logreader import LogReader
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

    def get_log_snapshot(self, timestamp=""):
        if not timestamp or timestamp not in self.all_cluster_files:
            return None
        return self.all_cluster_files[timestamp]

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
                        files[timestamps[index -1]] = [self.all_cluster_files[timestamps[index-1]].cluster_file]
                    except:
                        continue
            else:
                for timestamp in self.selected_cluster_files:
                    try:
                        files[timestamp] = [self.selected_cluster_files[timestamp].cluster_file]
                    except:
                        continue
            return files
        else:
            files = []
            if indices:
                nodes = sorted(self.all_server_files.keys())
                for index in indices:
                    try:
                        files.append(self.all_server_files[nodes[index - 1]])
                    except:
                        continue
            else:
                for node in sorted(self.selected_server_files.keys()):
                    try:
                        files.append(self.selected_server_files[node])
                    except:
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
                    except:
                        pass
                return cluster_files
            else:
                server_files = []
                for file in files:
                    try:
                        if self.log_reader.is_server_log_file(file):
                            server_files.append(file)
                    except:
                        pass
                return server_files
        except:
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
                self.all_server_files[file_key] = file
                self.selected_server_files[file_key] = file
                server_logs_added += 1
            if server_logs_added==0:
                error += ">>> No aerospike server log file available in " + path + ". <<<\n"
        elif os.path.isfile(path) and self.log_reader.is_server_log_file(path):
            file_key = self.log_reader.get_server_node_id(path)
            if file_key or prefix:
                if not file_key:
                    file_key = prefix
                self.all_server_files[file_key] = path
                self.selected_server_files[file_key] = path
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
        if isinstance(indices, list):
            for index in indices:
                selected_names.append(log_names[index])
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
                            del self.all_server_files[log]
                    if log in self.selected_server_files:
                            del self.selected_server_files[log]
            except:
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
                log_entries = copy.deepcopy(self.all_server_files)
            else:
                log_entries = copy.deepcopy(self.selected_server_files)
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
        selected_list.clear()

        for index in indices:
            try:
                selected_list[all_log_keys[int(index) - 1]] = all_list[all_log_keys[int(index) - 1]]
            except:
                continue

    def get_data(self, type="", stanza=""):
        res_dic = {}
        if not stanza or not type:
            return res_dic

        for timestamp in sorted(self.selected_cluster_files.keys()):
            try:
                res_dic[timestamp] = self.selected_cluster_files[timestamp].get_data(type=type, stanza=stanza)
            except:
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

    def get_diff_bg_fg_color(self, old_fg_index, old_bg_index):
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

    def grep(
            self,
            files,
            search_strs,
            ignore_str,
            unique,
            grep_cluster_logs,
            start_tm_arg="head",
            duration_arg="",
            is_and=False, is_casesensitive=True):
        grep_res = {}
        if not files:
            return {}
        if grep_cluster_logs:
            grep_res["key"] = self.log_reader.grep(
                search_strs,
                ignore_str,
                unique,
                files[0],
                is_and, is_casesensitive)
        else:
            fg_color_index, bg_color_index = self.get_diff_bg_fg_color(2, 6)
            for file in sorted(files):
                start_tm = copy.deepcopy(start_tm_arg)
                duration = copy.deepcopy(duration_arg)
                node = "[" + str(self.get_node(file)) + "]->"

                lines = self.log_reader.grep(
                    search_strs,
                    ignore_str,
                    unique,
                    file,
                    is_and, is_casesensitive).strip().split('\n')
                if not lines:
                    continue

                try:
                    tail_tm = self.log_reader.parse_dt(lines[-1])
                    if start_tm == "head":
                        start_tm = self.log_reader.parse_dt(lines[0])
                    else:
                        start_tm = self.log_reader.parse_init_dt(
                            start_tm,
                            tail_tm)
                        if start_tm > tail_tm:
                            continue

                    if duration:
                        duration_tm = self.log_reader.parse_timedelta(duration)
                        end_tm = start_tm + duration_tm
                    else:
                        end_tm = tail_tm + \
                            self.log_reader.parse_timedelta("10")

                    for line in lines:
                        line_tm = self.log_reader.parse_dt(line)
                        if line_tm < start_tm:
                            continue
                        if line_tm > end_tm:
                            break
                        key = self.log_reader.get_dt(line)
                        try:
                            grep_res[
                                key] += "\n%s%s%s::" % (self.fg_colors[fg_color_index][1](), node, terminal.reset())
                        except:
                            grep_res[key] = "%s%s%s::" % (
                                self.fg_colors[fg_color_index][1](), node, terminal.reset())
                        grep_res[key] += line

                    fg_color_index, bg_color_index = self.get_diff_bg_fg_color(
                        fg_color_index, bg_color_index)
                except:
                    continue

        return grep_res

    def grepCount(self, files, search_str, ignore_str,
                  unique, grep_cluster_logs, start_tm="", duration="", is_and=False, is_casesensitive=True):
        res_dic = {}
        try:
            for file in files:
                try:
                    if start_tm or duration:
                        if not start_tm:
                            start_tm = "head"
                        res_lines = self.grep([file], search_str, ignore_str, unique, grep_cluster_logs, start_tm, duration, is_and, is_casesensitive)
                        if res_lines:
                            res_dic[self.get_node(file)] = len(res_lines)
                        else:
                            res_dic[self.get_node(file)] = 0
                    else:
                        res_dic[self.get_node(file)] = int(
                            self.log_reader.grepCount(
                                search_str,
                                ignore_str,
                                unique,
                                file,
                                is_and, is_casesensitive))
                except:
                    res_dic[self.get_node(file)] = 0
            return res_dic
        except:
            return res_dic

    def grepDiff(self, files, search_str, grep_cluster_logs,
                 start_tm, duration, slice_tm, show_count, limit, is_casesensitive=True):
        grep_diff_res = {}

        global_start_time = ""
        union_keys = []
        for file in files:
            node = self.get_node(file)
            global_start_time, grep_diff_res[node] = self.log_reader.grepDiff(
                search_str, file, start_tm, duration, slice_tm, global_start_time, limit, is_casesensitive)
            if grep_diff_res[node]["value"]:
                union_keys = list(
                    set(union_keys) | set(
                        grep_diff_res[node]["value"].keys()))

        index_count = 0
        for key in sorted(union_keys):
            skip = index_count % show_count
            for file in files:
                node = self.get_node(file)
                if skip:
                    if grep_diff_res[node]["value"] and key in grep_diff_res[
                            node]["value"].keys():
                        del grep_diff_res[node]["value"][key]
                        del grep_diff_res[node]["diff"][key]
                else:
                    if not grep_diff_res[node][
                            "value"] or key not in grep_diff_res[node]["value"].keys():
                        grep_diff_res[node]["value"][key] = []
                        grep_diff_res[node]["diff"][key] = []
            index_count += 1

        return grep_diff_res

    def loglatency(
            self,
            files,
            hist,
            slice_tm,
            start_tm,
            duration,
            max_bucket,
            show_count,
            no_time_rounding):
        line_show_count = 1
        latency_res = {}
        union_keys = []
        need_to_merge = False
        if len(files) > 1:
            need_to_merge = True

        for file in files:
            node = self.get_node(file)
            start_tm, latency_res[node] = loglatency(
                file, hist, slice_tm, start_tm, duration, max_bucket, show_count, not no_time_rounding)
            if latency_res[node] and latency_res[node]["ops/sec"] and need_to_merge:
                union_keys = list(
                    set(union_keys) | set(
                        latency_res[node]["ops/sec"].keys()))

        if need_to_merge:
            index_count = 0
            for key in sorted(union_keys):
                skip = index_count % line_show_count
                for file in files:
                    node = self.get_node(file)
                    if skip:
                        if latency_res[node][
                                "ops/sec"] and key in latency_res[node]["ops/sec"].keys():
                            del latency_res[node]["ops/sec"][key]
                    else:
                        if not latency_res[node][
                                "ops/sec"] or key not in latency_res[node]["ops/sec"].keys():
                            latency_res[node]["ops/sec"][key] = []
                index_count += 1

        return latency_res
