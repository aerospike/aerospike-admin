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

import datetime
import re
import time

from lib.utils.util import shell_command
from lib.utils.constants import *

INDEX_DT_LEN = 4
STEP = 1000


class CollectinfoReader(object):
    ascollectinfo_ext1 = "/ascollectinfo.log"
    ascollectinfo_ext2 = "/*.log"
    summary_pattern = '~([^~]+) Information(~+)'
    network_start_pattern = 'Network Information'
    service_start_pattern = 'Service Configuration'
    network_end_pattern = 'Number of rows'
    section_separator = "(=+)ASCOLLECTINFO(=+)"
    section_separator_with_date = "(=+)ASCOLLECTINFO\(([\d_]*)\)(=+)"
    stats_pattern = "\[\'statistics\'"
    config_pattern = "\[\'config\'"
    config_diff_pattern = "\[\'config\',[\s]*\'diff\'"
    distribution_pattern = "\[\'distribution\'"
    cinfo_log_file_identifier_key = "=ASCOLLECTINFO"
    cinfo_log_file_identifiers = ["Configuration~~~", "Statistics~"]
    system_log_file_identifier_key = "=ASCOLLECTINFO"
    system_log_file_identifiers = ["hostname -I", "uname -a", "ip addr",
                                   "Data collection for get_awsdata in progress", "top -n", "cat /var/log/syslog"]

    def get_node_names(self, path):
        node_names = []
        lines = open(path, 'r').readlines()
        line = lines.pop(0)
        while(line):
            if re.search(self.service_start_pattern, line):
                line = lines.pop(0)
                nodes = line.split()
                node_names = nodes[2:len(nodes)]
                break
            line = lines.pop(0)
        return node_names

    def get_timestamp(self, log_file):
        file_id = open(log_file, "r")
        file_id.seek(0, 0)
        timestamp = ""
        while not timestamp:
            line = file_id.readline()
            timestamp = line.strip().strip("\n").strip()
        if timestamp.endswith("UTC"):
            return timestamp
        elif "===ASCOLLECTINFO===" in timestamp:
            return self._extract_timestamp_from_path(log_file)
        elif re.search(self.section_separator_with_date, timestamp):
            dt_tm_str = re.search(
                self.section_separator_with_date, timestamp).group(2)
            date_object = datetime.datetime.strptime(
                dt_tm_str, '%Y%m%d_%H%M%S')
            return date_object.strftime('%Y-%m-%d %H:%M:%S UTC')
        return ""

    def is_cinfo_log_file(self, log_file=""):
        if not log_file:
            return False
        try:
            out, err = shell_command(['head -n 30 "%s"' % (log_file)])
        except Exception:
            return False
        if err or not out:
            return False
        lines = out.strip().split('\n')
        found = False
        for line in lines:
            try:
                if self.cinfo_log_file_identifier_key in line:
                    found = True
                    break
            except Exception:
                pass
        if not found:
            return False
        for search_string in self.cinfo_log_file_identifiers:
            try:
                out, err = shell_command(
                    ['grep -m 1 %s "%s"' % (search_string, log_file)])
            except Exception:
                return False
            if err or not out:
                return False
        return True

    def is_system_log_file(self, log_file=""):
        if not log_file:
            return False
        try:
            out, err = shell_command(['head -n 30 "%s"' % (log_file)])
        except Exception:
            return False
        if err or not out:
            return False
        lines = out.strip().split('\n')
        found = False
        for line in lines:
            try:
                if self.system_log_file_identifier_key in line:
                    found = True
                    break
            except Exception:
                pass
        if not found:
            return False
        for search_string in self.system_log_file_identifiers:
            try:
                out, err = shell_command(
                    ['grep -m 1 "%s" "%s"' % (search_string, log_file)])
            except Exception:
                continue
            if err or not out:
                continue
            else:
                return True
        return False

    def read(self, path):
        loginfo = {}
        loginfo["statistics"] = {}
        loginfo["config"] = {}
        loginfo["distribution"] = {}
        loginfo["summary"] = {}
        file_id = open(path, "r")
        line = file_id.readline()

        while(line):
            config_pattern_matched = re.search(self.config_pattern, line)
            distribution_pattern_matched = re.search(self.distribution_pattern, line)
            stats_pattern_matched = re.search(self.stats_pattern, line)
            summary_pattern_matched = re.search(self.summary_pattern, line)

            if config_pattern_matched:
                try:
                    if not re.search(self.config_diff_pattern, line):
                        loginfo["config"].update(self._read_config(file_id))
                except Exception:
                    pass

            elif distribution_pattern_matched:
                try:
                    loginfo["distribution"].update(
                        self._read_distribution(file_id))
                except Exception:
                    pass

            elif stats_pattern_matched:
                try:
                    loginfo["statistics"].update(self._read_stats(file_id))
                except Exception:
                    pass

            elif summary_pattern_matched:
                try:
                    loginfo["summary"].update(
                        self._read_summary(file_id, line))
                except Exception:
                    pass

            try:
                line = file_id.readline()
            except IndexError:
                break

        return loginfo

    def _extract_timestamp_from_path(self, path):
        try:
            filename = re.split("/", path)[-2]
        except Exception:
            filename = path
        try:
            return time.strftime(
                '%Y-%m-%d %H:%M:%S',
                time.localtime(
                    float(
                        re.split(
                            '_',
                            filename)[2])))
        except Exception:
            return filename

    def _htable_to_dict(self, file_id):
        current_line = 0
        nodes = []
        res_dir = {}
        line = file_id.readline()
        while(line.strip().__len__() != 0 and not line.startswith('~')):
            if current_line == 0:
                temp_nodes = line.split()
                nodes = temp_nodes[2:len(temp_nodes)]
                for node in nodes:
                    res_dir[node] = {}
            else:
                temp_list = line.split()
                current_node = 0
                beg = 2
                if len(temp_list) > 1 and temp_list[1] != ":":
                    beg = 1
                    temp_list[0] = temp_list[0][0:len(temp_list[0]) - 1]
                for temp_val in temp_list[beg:len(temp_list)]:
                    temp_val = temp_val.strip()
                    # need to make same scenario as cluster mode, in cluster
                    # mode we do not get any value with 'N/E'
                    if temp_val.strip() == 'N/E':
                        current_node += 1
                        continue
                    temp_dir = {}
                    if res_dir:
                        if nodes[current_node] not in res_dir:
                            res_dir[nodes[current_node]] = {}
                        temp_dir = res_dir[nodes[current_node]]
                    temp_dir[temp_list[0]] = temp_val
                    res_dir[nodes[current_node]] = temp_dir
                    current_node += 1

            current_line += 1
            line = file_id.readline()
        return res_dir

    def _vtable_to_dict(self, file_id):
        res_dic = {}
        line = file_id.readline()
        while (line.strip().__len__() != 0
                and (line.split()[0].strip() != "Node"
                     and not line.strip().startswith("Number of rows"))):
            line = file_id.readline()

        if line.strip().__len__() == 0 or line.strip().startswith("Number of rows"):
            return res_dic
        columns = []

        while (line.strip().__len__() != 0
                and not line.strip().startswith('~')
                and not line.strip().startswith("Number of rows")):

            if line.strip().startswith('.') or line.strip().startswith('Node'):
                temp_columns = line.split()[1:]
                if not columns:
                    columns = temp_columns
                else:
                    _columns = ["%s %s" % (c1.strip(), c2.strip())
                                for c1, c2 in zip(columns, temp_columns)]
                    columns = _columns
            else:
                temp_list = line.split()
                current_column = 0
                temp_dic = {}
                for temp_val in temp_list[1:len(temp_list)]:
                    temp_val = temp_val.strip()
                    try:
                        # bytewise distribution values are in K,M format... to
                        # fix this issue we need to differentiate between float
                        # and string
                        float(temp_val)
                    except Exception:
                        current_column -= 1
                    column = columns[current_column]
                    if column in temp_dic:
                        temp_dic[column] += " %s" % (temp_val)
                    else:
                        temp_dic[column] = temp_val
                    current_column += 1
                res_dic[temp_list[0]] = {}
                res_dic[temp_list[0]]['values'] = temp_dic
            line = file_id.readline()

        return columns, res_dic

    def _dist_table_to_dict(self, file_id):
        result = {}
        line = file_id.readline()
        while (line.strip().__len__() != 0
                and (line.split()[0].strip() != "Node"
                     and not line.strip().startswith("Number of rows"))):
            line = file_id.readline()

        if (line.strip().__len__() == 0
                or line.strip().startswith("Number of rows")):
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

    def _read_stats(self, file_id):
        stat_dic = {}

        bin_pattern = '~([^~]+) Bin Statistics'
        set_pattern = '~([^~]+) Set Statistics'
        service_pattern = 'Service Statistics'
        ns_pattern = '~([^~]+) Namespace Statistics'
        xdr_pattern = 'XDR Statistics'
        dc_pattern = '~([^~]+) DC Statistics'
        sindex_pattern = '~([^~]+) Sindex Statistics'

        line = file_id.readline()
        while (line
                and not re.search(self.section_separator, line)
                and not re.search(self.section_separator_with_date, line)):
            if line.strip().__len__() != 0:
                dic = {}
                key = "key"
                if re.search(bin_pattern, line):
                    if STAT_BINS not in stat_dic:
                        stat_dic[STAT_BINS] = {}
                    dic = stat_dic[STAT_BINS]
                    key = re.search(bin_pattern, line).group(1)
                elif re.search(set_pattern, line):
                    if STAT_SETS not in stat_dic:
                        stat_dic[STAT_SETS] = {}
                    dic = stat_dic[STAT_SETS]
                    key = re.search(set_pattern, line).group(1)
                elif re.search(service_pattern, line):
                    dic = stat_dic
                    key = STAT_SERVICE
                elif re.search(ns_pattern, line):
                    if STAT_NAMESPACE not in stat_dic:
                        stat_dic[STAT_NAMESPACE] = {}
                    dic = stat_dic[STAT_NAMESPACE]
                    key = re.search(ns_pattern, line).group(1)
                elif re.search(xdr_pattern, line):
                    dic = stat_dic
                    key = STAT_XDR
                elif re.search(dc_pattern, line):
                    if STAT_DC not in stat_dic:
                        stat_dic[STAT_DC] = {}
                    dic = stat_dic[STAT_DC]
                    key = re.search(dc_pattern, line).group(1)
                elif re.search(sindex_pattern, line):
                    if STAT_SINDEX not in stat_dic:
                        stat_dic[STAT_SINDEX] = {}
                    dic = stat_dic[STAT_SINDEX]
                    key = re.search(sindex_pattern, line).group(1)

                dic[key] = self._htable_to_dict(file_id)

            try:
                line = file_id.readline()
            except Exception:
                break

        return stat_dic

    def _read_config(self, file_id):
        config_dic = {}
        service_pattern = '(~+)Service Configuration(~+)'
        net_pattern = '(~+)Network Configuration(~+)'
        ns_pattern = '~([^~]+)Namespace Configuration(~+)'
        xdr_pattern = '(~+)XDR Configuration(~+)'
        dc_pattern = '~([^~]+)DC Configuration(~+)'
        cluster_pattern = '(~+)Cluster Configuration(~+)'

        line = file_id.readline()

        while (line
                and not re.search(self.section_separator, line)
                and not re.search(self.section_separator_with_date, line)):
            if line.strip().__len__() != 0:
                dic = {}
                key = "key"
                if re.search(service_pattern, line):
                    dic = config_dic
                    key = CONFIG_SERVICE
                elif re.search(net_pattern, line):
                    dic = config_dic
                    key = CONFIG_NETWORK
                elif re.search(ns_pattern, line):
                    if CONFIG_NAMESPACE not in config_dic:
                        config_dic[CONFIG_NAMESPACE] = {}
                    dic = config_dic[CONFIG_NAMESPACE]
                    key = re.search(ns_pattern, line).group(1).strip()
                elif re.search(xdr_pattern, line):
                    dic = config_dic
                    key = CONFIG_XDR
                elif re.search(dc_pattern, line):
                    if CONFIG_DC not in config_dic:
                        config_dic[CONFIG_DC] = {}
                    dic = config_dic[CONFIG_DC]
                    key = re.search(dc_pattern, line).group(1).strip()
                elif re.search(cluster_pattern, line):
                    dic = config_dic
                    key = CONFIG_CLUSTER

                dic[key] = self._htable_to_dict(file_id)
            try:
                line = file_id.readline()
            except IndexError:
                break
        return config_dic

    def _read_summary(self, file_id, header):
        summary_info = {}
        summary_pattern_matched = re.search(self.summary_pattern, header)
        if not summary_pattern_matched:
            return summary_info

        stanza = summary_pattern_matched.group(1)
        stanza = stanza.lower()
        if stanza:
            if stanza == "secondary index":
                stanza = SUMMARY_SINDEX
            elif stanza == "set":
                stanza = SUMMARY_SETS

            summary_info[stanza] = header + self._read_summary_str(file_id)

        return summary_info

    def _read_summary_str(self, file_id):
        line = file_id.readline()
        summary_str = ""
        while (line
                and not re.search(self.section_separator, line)
                and not re.search(self.section_separator_with_date, line)):
            if line.strip().__len__() != 0:
                summary_str += line
            try:
                line = file_id.readline()
            except IndexError:
                break

        return summary_str

    def _read_distribution(self, file_id):
        config_dic = {}

        ttl_pattern = '~([^~]+) - TTL Distribution in Seconds(~+)'
        evict_pattern = '~([^~]+) - Eviction Distribution in Seconds(~+)'
        objsz_pattern = '~([^~]+) - Object Size Distribution in Record Blocks(~+)'
        objsz_bytes_pattern = '([^~]+) - Object Size Distribution in Bytes'

        line = file_id.readline()
        bytewise_distribution = False
        while (line
                and not re.search(self.section_separator, line)
                and not re.search(self.section_separator_with_date, line)):
            if line.strip().__len__() != 0:
                m1 = re.search(ttl_pattern, line)
                m2 = re.search(evict_pattern, line)
                m3 = re.search(objsz_pattern, line)
                m4 = re.search(objsz_bytes_pattern, line)
                dic = {}
                key = "key"
                if m1:
                    if "ttl" not in config_dic:
                        config_dic["ttl"] = {}
                    dic = config_dic["ttl"]
                    key = m1.group(1).strip()
                elif m2:
                    if "evict" not in config_dic:
                        config_dic["evict"] = {}
                    dic = config_dic["evict"]
                    key = m2.group(1).strip()
                elif m3:
                    if "objsz" not in config_dic:
                        config_dic["objsz"] = {}
                    dic = config_dic["objsz"]
                    key = m3.group(1).strip()
                elif m4:
                    if "objsz-b" not in config_dic:
                        config_dic["objsz-b"] = {}
                    dic = config_dic["objsz-b"]
                    key = m4.group(1).strip()
                    bytewise_distribution = True

                if bytewise_distribution:
                    columns, dic[key] = self._vtable_to_dict(file_id)
                    dic[key]['columns'] = columns
                else:
                    dic[key] = self._dist_table_to_dict(file_id)
            try:
                line = file_id.readline()
            except IndexError:
                break
        return config_dic
