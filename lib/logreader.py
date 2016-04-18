from lib import logutil

__author__ = 'aerospike'

import os
import glob
import re
import time
import datetime
from lib.util import shell_command
import copy

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


class LogReader(object):
    ascollectinfoExt1 = "/ascollectinfo.log"
    ascollectinfoExt2 = "/*.log"
    serverLogExt = "/aerospike.log"
    summary_pattern = '~([^~]+) Information(~+)'
    networkStartPattern = 'Network Information'
    serviceStartPattern = 'Service Configuration'
    networkEndPattern = 'Number of rows'
    section_separator = "(=+)ASCOLLECTINFO(=+)"
    section_separator_with_date = "(=+)ASCOLLECTINFO[*](=+)"
    statsPattern = "\[\'statistics\'"
    configPattern = "\[\'config\'"
    configDiffPattern = "\[\'config\',[\s]*\'diff\'"
    distributionPattern = "\[\'distribution\'"
    latencyPattern = "\[\'latency\'\]"
    cluster_log_file_identifier = ["=ASCOLLECTINFO=", "Configuration~~~", "Statistics~"]
    server_log_file_identifier = ["thr_info.c::", "heartbeat_received", "ClusterSize"]
    server_log_file_identifier_pattern = "(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{2} \d{4} \d{2}:\d{2}:\d{2} GMT: (?:INFO|WARNING|DEBUG|DETAIL) \([a-z_]+\): \([a-z_\.]+::[\d]+\)"

    @staticmethod
    def getPrefixes(path):
        nodePrefixes = []
        lines = open(path, 'r').readlines()
        line = lines.pop(0)
        while(line):
            if re.search(LogReader.serviceStartPattern, line):
                line = lines.pop(0)
                nodes = line.split()
                nodePrefixes = nodes[2:len(nodes)]
                break
            line = lines.pop(0)
        return nodePrefixes

    def get_timestamp(self, file):
        file_id = open(file, "r")
        file_id.seek(0, 0)
        line = file_id.readline()
        timestamp = line.strip().strip("\n").strip()
        if timestamp.endswith("UTC"):
            return timestamp
        elif timestamp == "===ASCOLLECTINFO===":
            return self.getTime(file)
        return ""

    def get_server_node_id(self, file):
        not_found=""
        max_attempts = 10
        match_count = 0
        server_log_node_identifier = "node id "
        server_node_id_pattern = "node id ([0-9a-fA-F]+(\s|$))"

        if not file:
            return not_found
        try:
            for line in reversed(open(file).readlines()):
                if server_log_node_identifier in line:
                    try:
                        node_id = re.search(server_node_id_pattern, line.strip()).group(1)
                        if node_id:
                            return node_id
                    except:
                        pass
                    match_count += 1
                    if match_count > max_attempts:
                        return not_found
        except:
            pass
        return not_found

    def is_cluster_log_file(self, file=""):
        if not file:
            return False
        for search_string in self.cluster_log_file_identifier:
            try:
                out, err = shell_command(["grep -m 1 %s %s"%(search_string, file)])
            except:
                return False
            if err or not out:
                return False
        return True

    def is_server_log_file(self, file=""):
        if not file:
            return False
        try:
            out, err = shell_command(["head -n 10 %s"%(file)])
        except:
            return False
        if err or not out:
            return False
        lines = out.strip().split('\n')
        matched_count = 0
        for line in lines:
            try:
                if re.search(self.server_log_file_identifier_pattern, line):
                    matched_count += 1
            except:
                pass
        if matched_count==len(lines):
            return True
        return False

    def get_time(self, path):
        try:
            filename = re.split("/", path)[-2]
        except:
            filename = path
        try:
            return time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.localtime(
                    float(
                        re.split(
                            '_',
                            filename)[2])))
        except:
            return filename

    def get_nodes(self, path):
        nodes = []
        lines = open(path, 'r').readlines()
        line = lines.pop(0)
        while(line):
            if re.search(self.serviceStartPattern, line):
                line = lines.pop(0)
                node_ids = line.split()
                nodes = node_ids[2:len(node_ids)]
                break
            if lines:
                line = lines.pop(0)
            else:
                break
        return nodes

    def read(self, path):
        logInfo = {}
        logInfo["statistics"] = {}
        logInfo["config"] = {}
        logInfo["distribution"] = {}
        logInfo["summary"] = {}
        file_id = open(path, "r")
        line = file_id.readline()
        while(line):
            config_pattern_matched = re.search(self.configPattern, line)
            distribution_pattern_matched = re.search(self.distributionPattern, line)
            latency_pattern_matched = re.search(self.latencyPattern, line)
            stats_pattern_matched = re.search(self.statsPattern, line)
            summary_pattern_matched = re.search(self.summary_pattern, line)
            if config_pattern_matched:
                try:
                    if not re.search(self.configDiffPattern, line):
                        logInfo["config"].update(self.readConfig(file_id))
                except:
                    pass
            elif distribution_pattern_matched:
                try:
                    logInfo["distribution"].update(self.readDistribution(file_id))
                except:
                    pass
            elif latency_pattern_matched:
                try:
                    logInfo["latency"] = self.readLatency(file_id)
                except:
                    pass
            elif stats_pattern_matched:
                try:
                    logInfo["statistics"].update(self.readStats(file_id))
                except:
                    pass
            elif summary_pattern_matched:
                try:
                    logInfo["summary"].update(self.readSummary(file_id, line))
                except:
                    pass
            try:
                line = file_id.readline()
            except IndexError:
                break
        return logInfo

    def htableToString(self, file_id):
        resStr = ""
        line = file_id.readline()
        while(line.strip().__len__() != 0 and not line.startswith('~')):
            resStr += line + "\n"
            line = file_id.readline()
        return resStr

    def htableToDic(self, file_id):
        currentLine = 0
        nodes = []
        resDir = {}
        line = file_id.readline()
        while(line.strip().__len__() != 0 and not line.startswith('~')):
            if currentLine == 0:
                tempNodes = line.split()
                nodes = tempNodes[2:len(tempNodes)]
            else:
                tempList = line.split()
                currentNode = 0
                dirEmpty = 0
                if len(resDir) == 0:
                    dirEmpty = 1
                beg = 2
                if tempList[1] != ":":
                    beg = 1
                    tempList[0] = tempList[0][0:len(tempList[0]) - 1]
                for tempVal in tempList[beg:len(tempList)]:
                    tempVal = tempVal.strip()
                    if tempVal.strip() == 'N/E':   #need to make same scenario as cluster mode, in cluster mode we do not get any value with 'N/E'
                        continue
                    tempDir = {}
                    if not dirEmpty:
                        tempDir = resDir[nodes[currentNode]]
                    tempDir[tempList[0]] = tempVal
                    resDir[nodes[currentNode]] = tempDir
                    currentNode += 1

            currentLine += 1
            line = file_id.readline()
        return resDir

    def vtable_to_dic(self, file_id):
        res_dic = {}
        line = file_id.readline()
        while(line.strip().__len__() != 0 and (line.split()[0].strip() != "Node" and not line.strip().startswith("Number of rows"))):
            line = file_id.readline()
        if line.strip().__len__() == 0 or line.strip().startswith("Number of rows"):
            return res_dic
        columns=[]
        while(line.strip().__len__() != 0 and not line.strip().startswith('~') and not line.strip().startswith("Number of rows")):
            if line.strip().startswith('.') or line.strip().startswith('Node'):
                temp_columns = line.split()[1:]
                if not columns:
                    columns = temp_columns
                else:
                    _columns = ["%s %s"%(c1.strip(),c2.strip()) for c1,c2 in zip(columns,temp_columns)]
                    columns = _columns
            else:
                temp_list = line.split()
                current_column = 0
                temp_dic = {}
                for temp_val in temp_list[1:len(temp_list)]:
                    temp_val = temp_val.strip()
                    try:
                        test_value = float(temp_val)  # bytewise distribution values are in K,M format... to fix this issue we need to differentiate between float and string
                    except:
                        current_column -= 1
                    column = columns[current_column]
                    if column in temp_dic:
                        temp_dic[column] += " %s"%(temp_val)
                    else:
                        temp_dic[column] = temp_val
                    current_column += 1
                res_dic[temp_list[0]] = {}
                res_dic[temp_list[0]]['values'] = temp_dic
            line = file_id.readline()

        return columns, res_dic

    def readStats(self, file_id):
        statDic = {}

        binPattern = '~([^~]+) Bin Statistics'
        setPattern = '~([^~]+) Set Statistics'
        servicePattern = 'Service Statistics'
        nsPattern = '~([^~]+) Namespace Statistics'
        xdrPattern = 'XDR Statistics'
        dcPattern = '~([^~]+) DC Statistics'
        sindexPattern = '~([^~]+) Sindex Statistics'

        line = file_id.readline()
        while(not re.search(self.section_separator, line) and not re.search(self.section_separator_with_date,line)):
            if line.strip().__len__() != 0:
                dic = {}
                key = "key"
                if re.search(binPattern, line):
                    if "bins" not in statDic:
                        statDic["bins"] = {}
                    dic = statDic["bins"]
                    key = re.search(binPattern, line).group(1)
                elif re.search(setPattern, line):
                    if "sets" not in statDic:
                        statDic["sets"] = {}
                    dic = statDic["sets"]
                    key = re.search(setPattern, line).group(1)
                elif re.search(servicePattern, line):
                    dic = statDic
                    key = "service"
                elif re.search(nsPattern, line):
                    if "namespace" not in statDic:
                        statDic["namespace"] = {}
                    dic = statDic["namespace"]
                    key = re.search(nsPattern, line).group(1)
                elif re.search(xdrPattern, line):
                    dic = statDic
                    key = "xdr"
                elif re.search(dcPattern, line):
                    if "dc" not in statDic:
                        statDic["dc"] = {}
                    dic = statDic["dc"]
                    key = re.search(dcPattern, line).group(1)
                elif re.search(sindexPattern, line):
                    if "sindex" not in statDic:
                        statDic["sindex"] = {}
                    dic = statDic["sindex"]
                    key = re.search(sindexPattern, line).group(1)

                dic[key] = self.htableToDic(file_id)
            try:
                line = file_id.readline()
            except IndexError:
                break

        return statDic

    def readConfig(self, file_id):
        configDic = {}
        servicePattern = '(~+)Service Configuration(~+)'
        netPattern = '(~+)Network Configuration(~+)'
        nsPattern = '~([^~]+)Namespace Configuration(~+)'
        xdrPattern = '(~+)XDR Configuration(~+)'
        dcPattern = '~([^~]+)DC Configuration(~+)'

        line = file_id.readline()

        while(not re.search(self.section_separator, line) and not re.search(self.section_separator_with_date,line)):
            if line.strip().__len__() != 0:
                dic = {}
                key = "key"
                if re.search(servicePattern, line):
                    dic = configDic
                    key = "service"
                elif re.search(netPattern, line):
                    dic = configDic
                    key = "network"
                elif re.search(nsPattern, line):
                    if "namespace" not in configDic:
                        configDic["namespace"] = {}
                    dic = configDic["namespace"]
                    key = re.search(nsPattern, line).group(1).strip()
                elif re.search(xdrPattern, line):
                    dic = configDic
                    key = "xdr"
                elif re.search(dcPattern, line):
                    if "dc" not in configDic:
                        configDic["dc"] = {}
                    dic = configDic["dc"]
                    key = re.search(dcPattern, line).group(1).strip()

                dic[key] = self.htableToDic(file_id)
            try:
                line = file_id.readline()
            except IndexError:
                break
        return configDic

    def readLatency(self, file_id):
        configDic = {}

        pattern = '~([^~]+) Latency(~+)'

        line = file_id.readline()

        while(not re.search(self.section_separator, line) and not re.search(self.section_separator_with_date,line)):
            if line.strip().__len__() != 0:
                m1 = re.search(pattern, line)

                if m1:
                    dic = configDic
                    key = m1.group(1).strip()
                    dic[key] = self.latencyTableToDic(file_id)

            try:
                line = file_id.readline()
            except IndexError:
                break

        return configDic

    def latencyTableToDic(self, file_id):
        result = {}
        line = file_id.readline()
        while(line.strip().__len__() == 0):
            line = file_id.readline()

        if line.strip().startswith("Number of rows"):
            return result

        header = []
        vals = line.strip().split()
        if vals[0] == "Node":
            header = vals[1:len(vals)]
        else:
            return result

        line = file_id.readline()
        while(line.strip().startswith(".")):
            vals = line.strip().split()
            for index in range(1, len(vals)):
                if vals[index] != ".":
                    header[index - 1] = header[index - 1] + " " + vals[index]
            line = file_id.readline()

        for i in range(0, len(header)):
            if header[i].endswith("Ms"):
                header[i] = header[i].replace("Ms", "ms")
            elif header[i].startswith("Ops"):
                header[i] = header[i].replace("Ops", "ops")

        while not line.strip().startswith("Number of rows"):
            try:
                vals = line.strip().split()
                for i in range(2, len(vals)):
                    vals[i] = float(vals[i])
                result[vals[0]] = (header, vals[1:len(vals)])
                line = file_id.readline()
            except:
                continue

        file_id.seek(1, 1)
        return result

    def readSummary(self, file_id, header):
        summaryInfo = {}
        summary_pattern_matched = re.search(self.summary_pattern, header)
        if not summary_pattern_matched:
            return summaryInfo

        stanza = summary_pattern_matched.group(1)
        stanza = stanza.lower()
        if stanza:
            if stanza=="secondary index":
                stanza="sindex"
            elif stanza=="set":
                stanza="sets"

            summaryInfo[stanza] = header + self.readSummaryStr(file_id)

        return summaryInfo

    def readSummaryStr(self, file_id):
        line = file_id.readline()
        summaryStr = ""
        while(not re.search(self.section_separator, line) and not re.search(self.section_separator_with_date,line)):
            if line.strip().__len__() != 0:
                summaryStr += line
            try:
                line = file_id.readline()
            except IndexError:
                break

        return summaryStr

    def readDistribution(self, file_id):
        configDic = {}

        ttlPattern = '~([^~]+) - TTL Distribution in Seconds(~+)'
        evictPattern = '~([^~]+) - Eviction Distribution in Seconds(~+)'
        objszPattern = '~([^~]+) - Object Size Distribution in Record Blocks(~+)'
        objszBytesPattern = '([^~]+) - Object Size Distribution in Bytes'

        line = file_id.readline()
        bytewise_distribution = False
        while(not re.search(self.section_separator, line) and not re.search(self.section_separator_with_date,line)):
            if line.strip().__len__() != 0 :
                m1 = re.search(ttlPattern, line)
                m2 = re.search(evictPattern, line)
                m3 = re.search(objszPattern, line)
                m4 = re.search(objszBytesPattern, line)
                dic = {}
                key = "key"
                if m1:
                    if "ttl" not in configDic:
                        configDic["ttl"] = {}
                    dic = configDic["ttl"]
                    key = m1.group(1).strip()
                elif m2:
                    if "evict" not in configDic:
                        configDic["evict"] = {}
                    dic = configDic["evict"]
                    key = m2.group(1).strip()
                elif m3:
                    if "objsz" not in configDic:
                        configDic["objsz"] = {}
                    dic = configDic["objsz"]
                    key = m3.group(1).strip()
                elif m4:
                    if "objsz-b" not in configDic:
                        configDic["objsz-b"] = {}
                    dic = configDic["objsz-b"]
                    key = m4.group(1).strip()
                    bytewise_distribution = True

                if bytewise_distribution:
                    columns, dic[key] = self.vtable_to_dic(file_id)
                    dic[key]['columns'] = columns
                else:
                    dic[key] = self.dist_table_to_dic(file_id)
            try:
                line = file_id.readline()
            except IndexError:
                break
        return configDic

    def dist_table_to_dic(self, file_id):
        result = {}
        line = file_id.readline()
        while(line.strip().__len__() != 0 and (line.split()[0].strip() != "Node" and not line.strip().startswith("Number of rows"))):
            line = file_id.readline()

        if line.strip().__len__() == 0 or line.strip().startswith("Number of rows"):
            return result

        line = file_id.readline()
        while not line.strip().startswith("Number of rows"):
            vals = line.split()
            data = {}
            data['percentiles'] = vals[1:len(vals)]
            result[vals[0]] = data
            line = file_id.readline()

        #file_id.seek(1, 1)
        return result

    def get_grep_string(self, strs, file, is_and=False, is_casesensitive=True):
        search_str = ""
        if not strs:
            return search_str
        if not isinstance(strs, list):
            return search_str

        grep_cmd = "grep "
        if not is_casesensitive:
            grep_cmd += "-i "
        g_str = strs[0]
        if is_and:
            search_str = "%s \"%s\" %s" % (grep_cmd, g_str, file)
            for str in strs[1:len(strs)]:
                search_str += "|" + "%s \"%s\"" % (grep_cmd, str)
        else:
            for str in strs[1:len(strs)]:
                g_str += "\\|" + str
            search_str = "%s \"%s\" %s" % (grep_cmd, g_str, file)
        return search_str

    def grep(self, strs, ignore_str, unique, file, is_and=False, is_casesensitive=True):
        if not strs:
            return []
        if isinstance(strs,str):
            strs = [strs]
        if not isinstance(strs, list):
            return []

        search_str = self.get_grep_string(strs, file, is_and, is_casesensitive)
        if not search_str:
            return []

        if ignore_str:
            if unique:
                out, err = shell_command(
                    [search_str, '|', 'grep -v ', ignore_str, '| sort -k 9 | uniq -f 8 | sort -k 1,4'])
                return out
            else:
                out, err = shell_command(
                    [search_str, '|', 'grep -v ', ignore_str])
                return out
        else:
            if unique:
                out, err = shell_command(
                    [search_str, '| sort -k 9 | uniq -f 8 | sort -k 1,4'])
                return out
            else:
                out, err = shell_command([search_str])
                return out

    def grepCount(self, strs, ignore_str, unique, file, is_and=False, is_casesensitive=True):
        search_str = self.get_grep_string(strs, file, is_and, is_casesensitive)
        if not search_str:
            return []

        if ignore_str:
            if unique:
                out, err = shell_command(
                    [search_str, '| grep -v', ignore_str, '| sort -k 9 | uniq -f 8 | wc -l'])
                return out
            else:
                out, err = shell_command(
                    [search_str, '| grep -v', ignore_str, '| wc -l'])
                return out
        else:
            if unique:
                out, err = shell_command(
                    [search_str, '| sort -k 9 | uniq -f 8 | wc -l'])
                return out
            else:
                out, err = shell_command([search_str, '| wc -l'])
                return out

    def parse_timedelta(self, arg):
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

    def parse_init_dt(self, arg_from, tail_dt):
        if arg_from.startswith("-"):
            # Relative start time:
            try:
                init_dt = tail_dt - self.parse_timedelta(arg_from.strip("- "))
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

    def get_dt(self, line):
        return line[0: line.find(" GMT:")]

    def parse_dt(self, line):
        prefix = line[0: line.find(" GMT:")].split(",")[0]
        return datetime.datetime(*(time.strptime(prefix, DT_FMT)[0:6]))

    def grepDiff(
            self,
            grep_str,
            file,
            start_tm="head",
            duration="",
            slice_tm="10",
            global_start_tm="",
            limit="", is_casesensitive=True):
        latencyPattern1 = '%s (\d+)'
        latencyPattern2 = '%s \(([0-9,\s]+)\)'
        latencyPattern3 = '(\d+)\((\d+)\) %s'
        latencyPattern4 = '%s \((\d+)'
        result = {"value": {}, "diff": {}}

        lines = self.grep([grep_str], None, None, file, False, is_casesensitive).strip().split('\n')
        if not lines or lines == ['']:
            return global_start_tm, result
        line = lines.pop(0)
        try:
            tail_line = lines[-1]
        except:
            tail_line = line
        tail_tm = self.parse_dt(tail_line)
        if global_start_tm:
            start_tm = global_start_tm
        else:
            if start_tm == "head":
                start_tm = self.parse_dt(line)
            else:
                start_tm = self.parse_init_dt(start_tm, tail_tm)
                if start_tm > tail_tm:
                    # print "Wrong start time"
                    return global_start_tm, result

        while(self.parse_dt(line) < start_tm):
            try:
                line = lines.pop(0)
            except:
                # print "Wrong start time"
                return global_start_tm, result

        if duration:
            duration_tm = self.parse_timedelta(duration)
            end_tm = start_tm + duration_tm
        else:
            end_tm = tail_tm + self.parse_timedelta("10")

        slice_size = self.parse_timedelta(slice_tm)

        if is_casesensitive:
            m1 = re.search(latencyPattern1 % (grep_str), line)
            m2 = re.search(latencyPattern2 % (grep_str), line)
            m3 = re.search(latencyPattern3 % (grep_str), line)
            m4 = re.search(latencyPattern4 % (grep_str), line)
        else:
            m1 = re.search(latencyPattern1 % (grep_str), line, re.IGNORECASE)
            m2 = re.search(latencyPattern2 % (grep_str), line, re.IGNORECASE)
            m3 = re.search(latencyPattern3 % (grep_str), line, re.IGNORECASE)
            m4 = re.search(latencyPattern4 % (grep_str), line, re.IGNORECASE)
        while(not m1 and not m2 and not m3 and not m4):
            try:
                line = lines.pop(0)
                if self.parse_dt(line) >= end_tm:
                    return global_start_tm, result
            except:
                return global_start_tm, result
            if is_casesensitive:
                m1 = re.search(latencyPattern1 % (grep_str), line)
                m2 = re.search(latencyPattern2 % (grep_str), line)
                m3 = re.search(latencyPattern3 % (grep_str), line)
                m4 = re.search(latencyPattern4 % (grep_str), line)
            else:
                m1 = re.search(latencyPattern1 % (grep_str), line, re.IGNORECASE)
                m2 = re.search(latencyPattern2 % (grep_str), line, re.IGNORECASE)
                m3 = re.search(latencyPattern3 % (grep_str), line, re.IGNORECASE)
                m4 = re.search(latencyPattern4 % (grep_str), line, re.IGNORECASE)

        value = {}
        diff = {}

        slice_start = start_tm
        slice_end = slice_start + slice_size
        while(self.parse_dt(line) >= slice_end):
            #value[slice_start.strftime(DT_FMT)] = []
            #diff[slice_start.strftime(DT_FMT)] = []
            slice_start = slice_end
            slice_end = slice_start + slice_size

        if slice_end > end_tm:
            slice_end = end_tm

        pattern = ""
        prev = []
        slice_val = []
        pattern_type = 0

        # print str(m1) + " : " + str(m2) + " " + str(m3) + " " +str(m4)
        if m1:
            pattern = latencyPattern1 % (grep_str)
            slice_val.append(int(m1.group(1)))
        elif m2:
            pattern = latencyPattern2 % (grep_str)
            slice_val = map(lambda x: int(x), m2.group(1).split(","))
            pattern_type = 1
        elif m3:
            pattern = latencyPattern3 % (grep_str)
            slice_val = map(lambda x: int(x), list(m3.groups()))
            pattern_type = 2
        elif m4:
            pattern = latencyPattern4 % (grep_str)
            slice_val.append(int(m4.group(1)))
            pattern_type = 3
        else:
            print "no match"
            return global_start_tm, result

        for line in lines:
            # print line
            if self.parse_dt(line) >= end_tm:
                under_limit = True
                if limit:
                    under_limit = False
                if prev:
                    if limit:
                        temp = ([b - a for b, a in zip(slice_val, prev)])
                        if any(i >= limit for i in temp):
                            diff[slice_start.strftime(DT_FMT)] = (
                                [b for b in temp])
                            under_limit = True
                        temp = []
                    else:
                        diff[slice_start.strftime(DT_FMT)] = (
                            [b - a for b, a in zip(slice_val, prev)])
                else:
                    if not limit or any(i >= limit for i in slice_val):
                        diff[slice_start.strftime(DT_FMT)] = (
                            [b for b in slice_val])
                        under_limit = True

                if under_limit:
                    value[slice_start.strftime(DT_FMT)] = (
                        [b for b in slice_val])
                slice_val = []
                break

            if self.parse_dt(line) >= slice_end:
                under_limit = True
                if limit:
                    under_limit = False
                if prev:
                    if limit:
                        temp = ([b - a for b, a in zip(slice_val, prev)])
                        if any(i >= limit for i in temp):
                            diff[slice_start.strftime(DT_FMT)] = (
                                [b for b in temp])
                            under_limit = True
                        temp = []
                    else:
                        diff[slice_start.strftime(DT_FMT)] = (
                            [b - a for b, a in zip(slice_val, prev)])
                else:
                    if not limit or any(i >= limit for i in slice_val):
                        diff[slice_start.strftime(DT_FMT)] = (
                            [b for b in slice_val])
                        under_limit = True

                if under_limit:
                    value[slice_start.strftime(DT_FMT)] = (
                        [b for b in slice_val])
                prev = slice_val
                slice_start = slice_end
                slice_end = slice_start + slice_size
                slice_val = []
                if slice_end > end_tm:
                    slice_end = end_tm

            if is_casesensitive:
                m = re.search(pattern, line)
            else:
                m = re.search(pattern, line, re.IGNORECASE)

            if m:
                tm = self.get_dt(line)
                current = None
                if pattern_type == 2:
                    current = map(lambda x: int(x), list(m.groups()))
                else:
                    current = map(lambda x: int(x), m.group(1).split(","))
                if slice_val:
                    slice_val = ([b + a for b, a in zip(current, slice_val)])
                else:
                    slice_val = ([b for b in current])

        if slice_val:
            under_limit = True
            if limit:
                under_limit = False
            if prev:
                if limit:
                    temp = ([b - a for b, a in zip(slice_val, prev)])
                    if any(i >= limit for i in temp):
                        diff[slice_start.strftime(DT_FMT)] = (
                            [b for b in temp])
                        under_limit = True
                    temp = []
                else:
                    diff[slice_start.strftime(DT_FMT)] = (
                        [b - a for b, a in zip(slice_val, prev)])
            else:
                if not limit or any(i >= limit for i in slice_val):
                    diff[slice_start.strftime(DT_FMT)] = (
                        [b for b in slice_val])
                    under_limit = True

            if under_limit:
                value[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])

        result["value"] = value
        result["diff"] = diff

        return start_tm, result
#l = LogReader("/var/log/aerospike/asla/as_log_1444289465.19")
# print
# l.getPrefixes("/var/log/aerospike/asla/as_log_1444289465.19/ascollectinfo.log")
