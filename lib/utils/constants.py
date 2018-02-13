# Copyright 2013-2018 Aerospike, Inc.
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

ADMIN_HOME = os.path.expanduser('~') + '/.aerospike/'

CONFIG_SERVICE = "service"
CONFIG_NETWORK = "network"
CONFIG_NAMESPACE = "namespace"
CONFIG_XDR = "xdr"
CONFIG_DC = "dc"
CONFIG_CLUSTER = "cluster"

STAT_SERVICE = "service"
STAT_SETS = "set"
STAT_NAMESPACE = "namespace"
STAT_XDR = "xdr"
STAT_DC = "dc"
STAT_BINS = "bin"
STAT_SINDEX = "sindex"

SUMMARY_SERVICE = "service"
SUMMARY_NETWORK = "network"
SUMMARY_NAMESPACE = "namespace"
SUMMARY_SETS = "sets"
SUMMARY_XDR = "xdr"
SUMMARY_DC = "dc"
SUMMARY_SINDEX = "sindex"


SHOW_RESULT_KEY = "show_result"
COUNT_RESULT_KEY = "count_result"
TOTAL_ROW_HEADER = "total"
END_ROW_KEY = "End"

DT_FMT = "%b %d %Y %H:%M:%S"

CLUSTER_FILE = 0
SERVER_FILE = 1
SYSTEM_FILE = 2
JSON_FILE = 3

COLLECTINFO_SEPRATOR = "\n====ASCOLLECTINFO====\n"
COLLECTINFO_PROGRESS_MSG = "Data collection for %s%s  in progress.."
