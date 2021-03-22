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

from lib.utils.util import shell_command


class CollectinfoReader:
    cinfo_log_file_identifier_key = "=ASCOLLECTINFO"
    cinfo_log_file_identifiers = [
        "Configuration~~~\|Configuration (.*)~",
        "Statistics~\|Statistics (.*)~",
    ]
    system_log_file_identifier_key = "=ASCOLLECTINFO"
    system_log_file_identifiers = [
        "hostname -I",
        "uname -a",
        "ip addr",
        "Data collection for get_awsdata in progress",
        "top -n",
        "cat /var/log/syslog",
    ]

    def is_cinfo_log_file(self, log_file=""):
        if not log_file:
            return False

        try:
            out, err = shell_command(['head -n 30 "%s"' % (log_file)])
        except Exception:
            return False

        if err or not out:
            return False

        lines = out.strip().split("\n")
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
                    ['grep -m 1 "%s" "%s"' % (search_string, log_file)]
                )
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
        lines = out.strip().split("\n")
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
                    ['grep -m 1 "%s" "%s"' % (search_string, log_file)]
                )
            except Exception:
                continue
            if err or not out:
                continue
            else:
                return True
        return False
