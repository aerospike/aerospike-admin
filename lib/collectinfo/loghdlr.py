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

import ntpath
import os
import shutil
import tarfile
import zipfile


from lib.collectinfo.reader import CollectinfoReader
from lib.collectinfo.cinfolog import CollectinfoLog
from lib.utils.constants import ADMIN_HOME, CLUSTER_FILE, JSON_FILE, SYSTEM_FILE
from lib.utils import logutil, util

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

    # for zipped files
    COLLECTINFO_DIR = ADMIN_HOME + 'collectinfo/'
    COLLECTINFO_INTERNAL_DIR = "collectinfo_analyser_extracted_files"

    def __init__(self, cinfo_path):
        self.cinfo_path = cinfo_path
        self._validate_and_extract_compressed_files(cinfo_path, dest_dir=self.COLLECTINFO_DIR)
        self.cinfo_timestamp = None

        self.reader = CollectinfoReader()
        snapshot_added, err_cinfo = self._add_cinfo_log_files(cinfo_path)

        if snapshot_added == 0:
            raise Exception(str(err_cinfo))

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

    def get_cinfo_log_at(self, timestamp=""):

        if not timestamp or timestamp not in self.all_cinfo_logs:
            return None

        return self.all_cinfo_logs[timestamp]

    def info_getconfig(self, stanza="", flip=False):
        return self._fetch_from_cinfo_log(type="config", stanza=stanza, flip=flip)

    def info_get_originalconfig(self, stanza="", flip=False):
        return self._fetch_from_cinfo_log(type="original_config", stanza=stanza, flip=flip)

    def info_statistics(self, stanza="", flip=False):
        return self._fetch_from_cinfo_log(type="statistics", stanza=stanza, flip=flip)

    def info_histogram(self, stanza="", flip=False):
        hist_dict = self._fetch_from_cinfo_log(type="histogram", stanza=stanza, flip=flip)
        res_dict = {}

        for timestamp, hist_snapshot in hist_dict.items():
            res_dict[timestamp] = {}
            if not hist_snapshot:
                continue

            for node, node_snapshot in hist_snapshot.items():
                res_dict[timestamp][node] = {}
                if not node_snapshot:
                    continue

                for namespace, namespace_snapshot in node_snapshot.items():
                    if not namespace_snapshot:
                        continue

                    try:
                        datum = namespace_snapshot.split(',')
                        datum.pop(0)  # don't care about ns, hist_name, or length
                        width = int(datum.pop(0))
                        datum[-1] = datum[-1].split(';')[0]
                        datum = map(int, datum)

                        res_dict[timestamp][node][namespace] = {'histogram': stanza, 'width': width, 'data': datum}
                    except Exception:
                        pass
        return res_dict

    def info_latency(self):
        return self._fetch_from_cinfo_log(type="latency")

    def info_meta_data(self, stanza=""):
        return self._fetch_from_cinfo_log(type="meta_data", stanza=stanza)

    def info_pmap(self):
        return self._fetch_from_cinfo_log(type="pmap")

    def info_namespaces(self):
        return self._fetch_from_cinfo_log(type="config", stanza="namespace_list")

    def get_sys_data(self, stanza=""):
        res_dict = {}
        if not stanza:
            return res_dict

        for timestamp in sorted(self.selected_cinfo_logs.keys()):
            try:
                out = self.selected_cinfo_logs[timestamp].get_sys_data(stanza=stanza)
                res_dict[timestamp] = util.restructure_sys_data(out, stanza)
            except Exception:
                continue

        return res_dict

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

    def _get_all_file_paths(self, cinfo_path):
        files = []


        if os.path.isfile(cinfo_path):
            if not self._is_compressed_file(cinfo_path):
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

        return files

    def _add_cinfo_log_files(self, cinfo_path=""):

        snapshots_added = 0
        if not cinfo_path:
            return snapshots_added, "Collectinfo path not specified."

        if not os.path.exists(cinfo_path):
            return snapshots_added, "Wrong Collectinfo path."

        files = self._get_all_file_paths(cinfo_path)
        if files:
            cinfo_log = CollectinfoLog(cinfo_path, files, self.reader)
            self.selected_cinfo_logs = cinfo_log.snapshots
            self.all_cinfo_logs = cinfo_log.snapshots
            snapshots_added = len(self.all_cinfo_logs)
            return snapshots_added, ""
        else:
            return snapshots_added, "Incorrect collectinfo path " + str(cinfo_path) + " specified. Please provide correct collectinfo directory path."

        return snapshots_added, ""

    def _fetch_from_cinfo_log(self, type="", stanza="", flip=False):
        res_dict = {}

        if not type:
            return res_dict

        for timestamp in sorted(self.selected_cinfo_logs.keys()):
            try:
                out = self.selected_cinfo_logs[timestamp].get_data(type=type, stanza=stanza)
                if flip:
                    out = util.flip_keys(out)

                res_dict[timestamp] = out

            except Exception:
                continue

        return res_dict

    def _is_compressed_file(self, file):
        if not file or not os.path.exists(file):
            return False

        if zipfile.is_zipfile(file) or tarfile.is_tarfile(file):
            return True

        return False

    def _extract_to(self, file, dest_dir):
        if not file or not os.path.exists(file):
            return False

        try:
            if tarfile.is_tarfile(file):
                compressed_file = tarfile.open(file)

            elif zipfile.is_zipfile(file):
                compressed_file =  zipfile.ZipFile(file, "r")

            else:
                return False

        except Exception:
            return False

        file_extracted = False
        try:
            compressed_file.extractall(path=dest_dir)
            file_extracted = True
        except Exception:
            file_extracted = False
        finally:
            compressed_file.close()

        return file_extracted

    def _validate_and_extract_compressed_files(self, cinfo_path, dest_dir=None):
        if not cinfo_path or not os.path.exists(cinfo_path):
            return

        if not dest_dir:
            dest_dir = self.COLLECTINFO_DIR

        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        if os.path.isfile(cinfo_path):
            if not self._is_compressed_file(cinfo_path):
                return

            if self._extract_to(cinfo_path, dest_dir):
                self._validate_and_extract_compressed_files(dest_dir, dest_dir=os.path.join(dest_dir, self.COLLECTINFO_INTERNAL_DIR))
                return

        files = logutil.get_all_files(cinfo_path)
        if not files:
            return

        file_extracted = False
        for file in files:
            if not self._is_compressed_file(file):
                continue

            if self._extract_to(file, dest_dir):
                file_extracted = True

        if file_extracted:
            self._validate_and_extract_compressed_files(dest_dir, dest_dir=os.path.join(dest_dir, self.COLLECTINFO_INTERNAL_DIR))


