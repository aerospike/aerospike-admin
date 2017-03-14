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
import os
import logging
import shutil
import sys
import zipfile


from lib.collectinfo_parser.full_parser import parse_info_all
from lib.collectinfo.reader import CollectinfoReader
from lib.collectinfo.cinfolog import CollectinfoLog
from lib.utils.constants import CLUSTER_FILE, JSON_FILE, SYSTEM_FILE
from lib.utils.util import restructure_sys_data
from lib.utils import logutil

###### Constants ######
DATE_SEG = 0
YEAR = 0
MONTH = 1
DATE = 2

TIME_SEG = 1
HH = 0
MM = 1
SS = 2

######################


class CollectinfoLoghdlr(object):
    all_cinfo_logs = {}
    selected_cinfo_logs = {}

    # for healthchecker
    # TODO: This is temporary extra dict, all commands should fetch data from one dict.
    # TODO: Remove parsing code from asadm
    parsed_data = {}
    parsed_as_data_logs = []
    parsed_system_data_logs = []

    # for zipped files
    ADMINHOME = os.environ['HOME'] + '/.aerospike/'
    COLLECTINFO_DIR = ADMINHOME + 'collectinfo/'

    def __init__(self, cinfo_path):
        self.cinfo_path = cinfo_path
        self._validate_and_extract_zipped_files(cinfo_path)
        self.cinfo_timestamp = None
        self.logger = logging.getLogger('asadm')

        self.reader = CollectinfoReader()
        cinfo_added, err_cinfo = self._add_cinfo_log_files(cinfo_path)
        if not cinfo_added:
            cinfo_added, _ = self._add_cinfo_log_files(self.COLLECTINFO_DIR)

        if cinfo_added == 0:
            self.logger.error(err_cinfo)
            sys.exit(1)

        health_data_updated = self._add_data_to_health_dict(cinfo_path)
        if not health_data_updated:
            self.logger.info("No data added for healthcheck.")

    def __str__(self):
        status_str = ""
        if not self.all_cinfo_logs:
            return status_str

        i = 1
        for timestamp in sorted(self.all_cinfo_logs.keys()):
            nodes = self.all_cinfo_logs[timestamp].get_node_names().keys()
            if len(nodes) == 0:
                continue

            status_str += "\n " + str(i) + ": "
            status_str += ntpath.basename(self.all_cinfo_logs[timestamp].cinfo_file)
            status_str += " ("
            status_str += str(timestamp)
            status_str += ")"
            status_str += "\n\tFound %s nodes" % (len(nodes))
            status_str += "\n\tOnline:  %s" % (", ".join(nodes))
            status_str += "\n"
            i = i + 1

        return status_str

    def close(self):
        if self.all_cinfo_logs:
            for timestamp in self.all_cinfo_logs:
                try:
                    self.all_cinfo_logs[timestamp].destroy()
                except Exception:
                    pass
            self.all_cinfo_logs.clear()
            self.selected_cinfo_logs.clear()

        if os.path.exists(self.COLLECTINFO_DIR):
            shutil.rmtree(self.COLLECTINFO_DIR)

    def get_cinfo_path(self):
        return self.cinfo_path

    def get_cinfo_timestamp(self):
        return self.cinfo_timestamp

    def get_cinfo_log_at(self, timestamp=""):

        if not timestamp or timestamp not in self.all_cinfo_logs:
            return None

        return self.all_cinfo_logs[timestamp]

    def info_getconfig(self, stanza=""):
        return self._fetch_from_cinfo_log(type="config", stanza=stanza)

    def info_statistics(self, stanza=""):
        return self._fetch_from_cinfo_log(type="statistics", stanza=stanza)

    def info_histogram(self, stanza=""):
        return self._fetch_from_cinfo_log(type="distribution", stanza=stanza)

    def info_summary(self, stanza=""):
        return self._fetch_from_cinfo_log(type="summary", stanza=stanza)

    def get_asstat_data(self, stanza=""):
        return self._fetch_from_parsed_as_data(info_type="statistics",
                                               stanza=stanza)

    def get_asconfig_data(self, stanza=""):
        return self._fetch_from_parsed_as_data(info_type="config",
                                               stanza=stanza)

    def get_asmeta_data(self, stanza=""):
        return self._fetch_from_parsed_as_data(info_type="meta_data",
                                               stanza=stanza)

    def get_sys_data(self, stanza=""):
        res_dict = {}

        for sys_ts in sorted(self.parsed_data.keys()):
            res_dict[sys_ts] = {}

            for cl in self.parsed_data[sys_ts]:
                d = self.parsed_data[sys_ts][cl]
                for node in d:
                    try:
                        res_dict[sys_ts][node] = copy.deepcopy(
                            d[node]['sys_stat'][stanza])
                    except Exception:
                        pass

                try:
                    res_dict[sys_ts] = restructure_sys_data(
                        res_dict[sys_ts], stanza)
                except Exception:
                    pass

        return res_dict

    def get_asd_build(self):
        res_dic = {}
        for timestamp in sorted(self.selected_cinfo_logs.keys()):
            try:
                res_dic[timestamp] = self.selected_cinfo_logs[
                    timestamp].get_asd_build()
            except Exception:
                continue

        return res_dic

    def _get_files_by_type(self, file_type, cinfo_path=""):
        try:
            if not cinfo_path:
                cinfo_path = self.cinfo_path

            log_files = logutil.get_all_files(cinfo_path)
            if file_type == CLUSTER_FILE:
                cinfo_files = []
                for log_file in log_files:
                    try:
                        if self.reader.is_cinfo_log_file(log_file):
                            cinfo_files.append(log_file)
                    except Exception:
                        pass

                return cinfo_files

            if file_type == JSON_FILE:
                json_files = []
                for log_file in log_files:
                    try:
                        # ToDo: It should be some proper check for asadm
                        # collectinfo json file.
                        if os.path.splitext(log_file)[1] == ".json":
                            json_files.append(log_file)
                    except Exception:
                        pass

                return json_files

            if file_type == SYSTEM_FILE:
                system_files = []
                for log_file in log_files:
                    try:
                        if self.reader.is_system_log_file(log_file):
                            system_files.append(log_file)
                    except Exception:
                        pass

                return system_files

            return []
        except Exception:
            return []

    def _update_parsed_log_list(self, stanza, old_log_list):
        logs = []
        if not stanza or not self.parsed_data:
            return logs
        found_new = False
        for sn in self.parsed_data.keys():
            for cluster in self.parsed_data[sn].keys():
                for node in self.parsed_data[sn][cluster].keys():
                    try:
                        if (self.parsed_data[sn][cluster][node][stanza]
                                and sn not in old_log_list):
                            found_new = True
                            old_log_list.append(sn)
                    except Exception:
                        pass
        return found_new

    def _is_parsed_data_changed(self):
        as_logs_updated = self._update_parsed_log_list(
            stanza="as_stat", old_log_list=self.parsed_as_data_logs)
        sys_logs_updated = self._update_parsed_log_list(
            stanza="sys_stat", old_log_list=self.parsed_system_data_logs)
        if as_logs_updated or sys_logs_updated:
            return True
        return False

    def _add_data_to_health_dict(self, cinfo_path):
        if not cinfo_path or not os.path.exists(cinfo_path):
            return False

        files = []


        if os.path.isfile(cinfo_path):
            if not zipfile.is_zipfile(cinfo_path):
                files.append(cinfo_path)
            else:
                files += logutil.get_all_files(self.COLLECTINFO_DIR)

        elif os.path.isdir(cinfo_path):
            files += logutil.get_all_files(cinfo_path)

            if os.path.exists(self.COLLECTINFO_DIR):
                # ToDo: Before adding file from COLLECTINFO_DIR, we need to check file already exists in input file list or not,
                # ToDo: collectinfo_parser fails if same file exists twice in input file list. This is possible if input has zip file and
                # ToDo: user unzipped it but did not remove zipped file, in that case collectinfo-analyser creates new unzipped file,
                # ToDo: which results in two copies of same file (one unzipped by user and one unzipped by collectinfo-analyser).

                if not self._get_files_by_type(JSON_FILE, cinfo_path):
                    for collectinfo_json_file in self._get_files_by_type(JSON_FILE, self.COLLECTINFO_DIR):
                        files.append(collectinfo_json_file)

                if not self._get_files_by_type(CLUSTER_FILE, cinfo_path):
                    for old_collectinfo_file in self._get_files_by_type(CLUSTER_FILE, self.COLLECTINFO_DIR):
                        files.append(old_collectinfo_file)

                if not self._get_files_by_type(SYSTEM_FILE, cinfo_path):
                    for sysinfo_file in self._get_files_by_type(SYSTEM_FILE, self.COLLECTINFO_DIR):
                        files.append(sysinfo_file)

        if files:
            parse_info_all(files, self.parsed_data, True)
            if self._is_parsed_data_changed():
                return True

        return False

    def _add_cinfo_log_files(self, cinfo_path=""):

        logs_added = 0
        if not cinfo_path:
            return logs_added, "Collectinfo path not specified."

        if not os.path.exists(cinfo_path):
            return logs_added, "Wrong Collectinfo path."

        error = ""
        if os.path.isdir(cinfo_path):
            for log_file in self._get_files_by_type(CLUSTER_FILE, cinfo_path):
                timestamp = self.reader.get_timestamp(log_file)

                if timestamp:
                    cinfo_log = CollectinfoLog(
                        timestamp, log_file, self.reader)
                    self.selected_cinfo_logs[timestamp] = cinfo_log
                    self.all_cinfo_logs[timestamp] = cinfo_log
                    logs_added += 1
                    if not self.cinfo_timestamp:
                        self.cinfo_timestamp = timestamp
                else:
                    return logs_added, "Missing timestamp, cannot add specified collectinfo file " + str(log_file) + ". Only supports collectinfo generated by asadm (>=0.0.13)."

            if logs_added == 0:
                return 0, "No aerospike collectinfo file found at " + str(cinfo_path)

        elif (os.path.isfile(cinfo_path)
                and self.reader.is_cinfo_log_file(cinfo_path)):
            timestamp = self.reader.get_timestamp(cinfo_path)

            if timestamp:
                cinfo_log = CollectinfoLog(timestamp, cinfo_path, self.reader)
                self.selected_cinfo_logs[timestamp] = cinfo_log
                self.all_cinfo_logs[timestamp] = cinfo_log
                logs_added += 1
                if not self.cinfo_timestamp:
                    self.cinfo_timestamp = timestamp
            else:
                return 0, "Missing timestamp, cannot add specified collectinfo file " + str(cinfo_path) + ". Only supports collectinfo generated by asadm (>=0.0.13)."

        elif (os.path.isfile(cinfo_path)
                and self.reader.is_system_log_file(cinfo_path)):
            return logs_added, "Only sysinfo file path is not sufficient for collectinfo-analyzer. Please provide collectinfo directory path."

        else:
            return logs_added, "Incorrect collectinfo path " + str(cinfo_path) + " specified. Please provide correct collectinfo directory path."

        return logs_added, ""

    def _fetch_from_cinfo_log(self, type="", stanza=""):
        res_dic = {}
        if not stanza or not type:
            return res_dic

        for timestamp in sorted(self.selected_cinfo_logs.keys()):
            try:
                res_dic[timestamp] = self.selected_cinfo_logs[
                    timestamp].get_data(type=type, stanza=stanza)
            except Exception:
                continue

        return res_dic

    def _fetch_from_parsed_as_data(self, info_type="", stanza=""):
        res_dict = {}
        if not info_type or not stanza:
            return res_dict
        for ts in sorted(self.parsed_data.keys()):
            res_dict[ts] = {}

            for cl in self.parsed_data[ts]:
                data = self.parsed_data[ts][cl]

                for node in data:

                    if node not in res_dict:
                        res_dict[ts][node] = {}

                    try:
                        d = copy.deepcopy(data[node]['as_stat'][info_type])

                        if stanza in ['namespace', 'bin', 'set', 'sindex']:
                            d = d["namespace"]

                            for ns_name in d.keys():
                                if stanza == "namespace":
                                    res_dict[ts][node][ns_name] = d[
                                        ns_name]["service"]
                                elif stanza == "bin":
                                    res_dict[ts][node][ns_name] = d[
                                        ns_name][stanza]
                                elif stanza in ["set", "sindex"]:

                                    for _name in d[ns_name][stanza]:
                                        _key = "%s %s" % (ns_name, _name)
                                        res_dict[ts][node][_key] = d[
                                            ns_name][stanza][_name]
                        else:
                            res_dict[ts][node] = d[stanza]

                    except Exception:
                        pass

        return res_dict

    def _extract_to(self, cinfo_path, new_dir_path):
        if not os.path.exists(cinfo_path) or not zipfile.is_zipfile(cinfo_path):
            return False

        try:
            zip_file = zipfile.ZipFile(cinfo_path, "r")
        except zipfile.BadZipfile:
            return False

        res = True
        try:
            zip_file.extractall(new_dir_path)
        except Exception:
            res = False
        finally:
            zip_file.close()
        return res

    def _is_required_zip_file(self, file):
        if not file or not os.path.exists(file) or not os.path.isfile(file) or not zipfile.is_zipfile(file):
            return False

        required_filename_substring = ["sysinfo.log", "ascollectinfo.log", "ascinfo.json"]
        return any(s in os.path.basename(file) for s in required_filename_substring)

    def _validate_and_extract_zipped_files(self, cinfo_path):
        if not cinfo_path or not os.path.exists(cinfo_path):
            return

        if not os.path.exists(self.COLLECTINFO_DIR):
            os.makedirs(self.COLLECTINFO_DIR)

        if os.path.isfile(cinfo_path):
            if zipfile.is_zipfile(cinfo_path):
                self._extract_to(cinfo_path, self.COLLECTINFO_DIR)
            return

        files = logutil.get_all_files(cinfo_path)
        if not files:
            return

        for file in files:
            if not self._is_required_zip_file(file):
                continue

            self._extract_to(file, self.COLLECTINFO_DIR)


