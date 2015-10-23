import copy
import ntpath

__author__ = 'aerospike'

from lib.logreader import LogReader
from lib import terminal
import re

class Logger(object):
    logInfo = {}

    def __init__(self, log_path):
        self.log_path = log_path
        self.log_reader = LogReader(log_path)
        fg_color_re = re.compile("^(fg_(.*))$")
        self.fg_colors = map(lambda v:
                             (fg_color_re.match(v).groups()[1],getattr(terminal, fg_color_re.match(v).group(1)))
                       , filter(lambda x:fg_color_re.search(x) and "clear" not in x, dir(terminal)))

        bg_color_re = re.compile("^(bg_(.*))$")
        self.bg_colors = map(lambda v:
                       (bg_color_re.match(v).groups()[1],getattr(terminal, bg_color_re.match(v).group(1)))
                       , filter(lambda x:bg_color_re.search(x) and "clear" not in x, dir(terminal)))

    def __str__(self):
        files = self.log_reader.getFiles(True);
        retval =""

        i = 1
        for file in sorted(files):
            nodes = self.log_reader.getNodes(file)
            retval += "\n "+str(i)+": "
            retval += ntpath.basename(file)
            retval += " (" 
            retval += self.log_reader.getTime(file)
            retval += ")" 
            retval += "\n\tFound %s nodes"%(len(nodes))
            retval += "\n\tOnline:  %s"%(", ".join(nodes))
            retval += "\n"
            i  = i + 1

        return retval

    def infoGetConfig(self, stanza = ""):
        resDic = {}
        files = self.log_reader.getFiles(True);

        for file in sorted(files):
            if(not self.logInfo.has_key(file)):
                self.logInfo[file] = self.log_reader.read(file)

            if (stanza == "service"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["config"]["service"])
            elif (stanza == "network"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["config"]["network"])
            elif (stanza == "namespace"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["config"]["namespace"])

        return resDic

    def infoStatistics(self, stanza = ""):
        resDic = {}
        files = self.log_reader.getFiles(True);

        for file in sorted(files):
            if(not self.logInfo.has_key(file)):
                self.logInfo[file] = self.log_reader.read(file)

            if (stanza == "service"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["statistics"]["stats"]["service"])
            elif (stanza == "sets"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["statistics"]["sets"])
            elif (stanza == "bins"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["statistics"]["bins"])
            elif (stanza == "namespace"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["statistics"]["namespace"])

        return resDic

    def get_diff_bg_fg_color(self, old_fg_index, old_bg_index):
        new_fg_index = old_fg_index + 1
        new_bg_index = old_bg_index
        if new_fg_index >= len(self.fg_colors):
            new_fg_index = 0
            new_bg_index = (new_bg_index + 1)%len(self.bg_colors)

        while(self.bg_colors[new_bg_index][0]==self.fg_colors[new_fg_index][0]):
            new_fg_index += 1
            if new_fg_index >= len(self.fg_colors):
                new_fg_index = 0
                new_bg_index = (new_bg_index + 1)%len(self.bg_colors)

        return new_fg_index,new_bg_index

    def grep(self,dir_path, search_str, grep_cluster_logs, start_tm_arg="head", duration_arg=""):
        grep_res = {}
        files = self.log_reader.getFiles(grep_cluster_logs, dir_path)
        if grep_cluster_logs:
            grep_res["key"] = self.log_reader.grep(search_str, files[0])
        else:
            fg_color_index,bg_color_index  = self.get_diff_bg_fg_color(2,6)
            for file in sorted(files):
                start_tm = copy.deepcopy(start_tm_arg)
                duration = copy.deepcopy(duration_arg)
                node = file.split("/")[-2]

                lines = self.log_reader.grep(search_str, file).strip().split('\n')
                if not lines:
                    continue

                tail_tm = self.log_reader.parse_dt(lines[-1])
                if start_tm=="head":
                    start_tm = self.log_reader.parse_dt(lines[0])
                else:
                    start_tm = self.log_reader.parse_init_dt(start_tm, tail_tm)
                    if start_tm>tail_tm:
                        continue

                if duration:
                    duration_tm = self.log_reader.parse_timedelta(duration)
                    end_tm = start_tm + duration_tm
                else:
                    end_tm = tail_tm + self.log_reader.parse_timedelta("10")

                for line in lines:
                    line_tm = self.log_reader.parse_dt(line)
                    if line_tm < start_tm:
                        continue
                    if line_tm > end_tm:
                        break
                    key = self.log_reader.get_dt(line)
                    try:
                        grep_res[key] += "\n%s%s%s%s::"%(self.bg_colors[bg_color_index][1](),self.fg_colors[fg_color_index][1](),node,terminal.reset())
                    except:
                        grep_res[key] = "%s%s%s%s::"%(self.bg_colors[bg_color_index][1](),self.fg_colors[fg_color_index][1](),node,terminal.reset())
                    grep_res[key] += line

                fg_color_index,bg_color_index  = self.get_diff_bg_fg_color(fg_color_index,bg_color_index)

        return grep_res

    def grepCount(self, dir_path, search_str, grep_cluster_logs):
        files = self.log_reader.getFiles(grep_cluster_logs, dir_path)
        grepRes = {}

        for file in files:
            grepRes[file.split("/")[-2]] = self.log_reader.grepCount(search_str, file)

        return grepRes

    def grepDiff(self, dir_path, search_str, grep_cluster_logs, start_tm, duration, slice_tm, show_count):
        grep_diff_res = {}

        files = self.log_reader.getFiles(grep_cluster_logs, dir_path);
        global_start_time = ""
        union_keys = []
        for file in files:
            global_start_time,grep_diff_res[file] = self.log_reader.grepDiff(search_str, file, start_tm, duration, slice_tm, global_start_time)
            if grep_diff_res[file]["value"]:
                union_keys = list(set(union_keys) | set(grep_diff_res[file]["value"].keys()))

        index_count = 0
        for key in sorted(union_keys):
            skip = index_count%show_count
            for file in files:
                if skip:
                    if grep_diff_res[file]["value"] and key in grep_diff_res[file]["value"].keys():
                        del grep_diff_res[file]["value"][key]
                        del grep_diff_res[file]["diff"][key]
                else:
                    if not grep_diff_res[file]["value"] or key not in grep_diff_res[file]["value"].keys():
                        grep_diff_res[file]["value"][key] = []
                        grep_diff_res[file]["diff"][key] = []
            index_count += 1

        return grep_diff_res