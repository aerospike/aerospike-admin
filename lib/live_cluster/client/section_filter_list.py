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

CMD_PREFIX = "running shell command: "
# Section filter list.
# Param 'enable': Enable or disable dumping of section in parsed file.
# Param 'raw_section_name': Section name in section.json.
# Param 'final_section_name': Section name in parsed.json
# Param 'parent_section_name': Section would be inside parent section in parsed.json
# Map_format: 'parent_section_name': {
#               'final_section_name': {}
#             }
# Param 'regex_new': regex for collectinfos having delimiter.
# Param 'regex_old': regex for collectinfos, not having delimiter.
# Param 'collision_allowed': True if multiple sections allowed for same final_section_name
FILTER_LIST = {
    "ID_1": {
        "enable": True,
        "raw_section_name": "Node",
        "regex_new": r"^Node\n",
        "regex_old": r"^Node\n"
        # 'parser_func'
    },
    "ID_2": {
        "enable": True,
        "raw_section_name": "Namespace",
        "regex_new": r"^Namespace\n|\['namespace'\]",
        "regex_old": r"^Namespace\n"
        # 'parser_func'
    },
    "ID_3": {
        "enable": True,
        "raw_section_name": "XDR",
        "final_section_name": "xdr_info",
        "regex_new": r"\['xdr'\]|^XDR\n",
        "regex_old": r"^XDR\n",
        "collision_allowed": True
        # 'parser_func'
    },
    "ID_4": {
        "enable": True,
        "raw_section_name": "SETS",
        "regex_new": r"^SETS\n|\['set'\]",
        "regex_old": r"^SETS\n"
        # 'parser_func'
    },
    "ID_5": {
        "enable": True,
        "raw_section_name": "printconfig",
        "final_section_name": "config",
        "regex_new": r"printconfig|\['config'\]",
        "regex_old": r"^printconfig\n"
        # 'parser_func'
    },
    "ID_6": {
        "enable": True,
        "raw_section_name": "config_xdr",
        "final_section_name": "xdr",
        "parent_section_name": "config",
        "regex_new": r"\['config', 'xdr'\]"
        # 'parser_func'
    },
    "ID_7": {
        "enable": True,
        "raw_section_name": "config_dc",
        "final_section_name": "dc",
        "parent_section_name": "config",
        "regex_new": r"\['config', 'dc'\]",
    },
    "ID_8": {
        "enable": True,
        "raw_section_name": "compareconfig",
        "regex_new": "compareconfig",
        "regex_old": r"^compareconfig\n"
        # 'parser_func'
    },
    "ID_9": {
        "enable": True,
        "raw_section_name": "config_diff",
        "regex_new": r"\['config', 'diff'\]",
        # 'parser_func'
    },
    "ID_10": {
        "enable": True,
        "raw_section_name": "latency",
        "final_section_name": "latency",
        "regex_new": "latency",
        "regex_old": r"^latency\n"
        # 'parser_func'
    },
    "ID_11": {
        # TODO:-----------
        "enable": True,
        "raw_section_name": "statistics",
        "final_section_name": "statistics",
        "regex_new": r"^stat\n|\['statistics'\]|\"stat\"",
        "regex_old": r"^stat\n"
        # 'parser_func'
    },
    "ID_12": {
        "enable": True,
        "raw_section_name": "statistics_xdr",
        "final_section_name": "xdr",
        "parent_section_name": "statistics",
        "regex_new": r"\['statistics', 'xdr'\]",
        # 'parser_func'
    },
    "ID_13": {
        "enable": True,
        "raw_section_name": "statistics_dc",
        "final_section_name": "dc",
        "parent_section_name": "statistics",
        "regex_new": r"\['statistics', 'dc'\]",
        # 'parser_func'
    },
    # Section was inside statistics earlier, check final_section_name.
    # Both should be same. This section would be parsed by default.
    # 'final_section_name' would be 'stat_sindex' in statistics parent section
    "ID_14": {
        "enable": True,
        "raw_section_name": "statistics_sindex",
        "final_section_name": "sindex",
        "parent_section_name": "statistics",
        "regex_new": r"\['statistics', 'sindex'\]",
        # 'parser_func'
    },
    "ID_15": {
        "enable": True,
        "raw_section_name": "objsz",
        "regex_new": r"^objsz\n|-v objsz",
        "regex_old": r"^objsz\n"
        # 'parser_func'
    },
    "ID_16": {
        # TODO:--------
        "enable": True,
        "raw_section_name": "ttl-distribution_1",
        #'regex_new': 'ttl',
        #'regex_new': "[INFO] Data collection for ['distribution'] in progress..",
        "regex_new": r"^ttl\n|-v ttl",
        "regex_old": r"^ttl\n"
        # 'parser_func'
    },
    "ID_17": {
        "enable": True,
        "raw_section_name": "evict",
        "regex_new": r"^evict\n|-v evict",
        "regex_old": r"^evict\n"
        # 'parser_func'
    },
    "ID_18": {
        "enable": True,
        "raw_section_name": "NAMESPACE STATS",
        "regex_new": "^NAMESPACE STATS\n",
        "regex_old": "^NAMESPACE STATS\n"
        # 'parser_func'
    },
    "ID_19": {
        "enable": True,
        "raw_section_name": "XDR STATS",
        "regex_new": "^XDR STATS\n",
        "regex_old": "^XDR STATS\n"
        # 'parser_func'
    },
    "ID_20": {
        # TODO:----------
        "enable": False,
        "raw_section_name": "sudo lsof|grep `sudo ps aux|grep -v grep|grep -E 'asd|cld'|awk '{print $2}'`",
        "regex_new": "sudo lsof[|]grep `sudo ps aux[|]grep -v grep[|]grep -E 'asd[|]cld'[|]awk '[{]print [$]2[}]'`",
        "regex_old": CMD_PREFIX
        + "sudo lsof[|]grep `sudo ps aux[|]grep -v grep[|]grep -E 'asd[|]cld'[|]awk '[{]print [$]2[}]'`"
        # 'parser_func'
    },
    "ID_21": {
        "enable": True,
        "raw_section_name": "date",
        "regex_new": "date",
        "regex_old": CMD_PREFIX + "date"
        # 'parser_func'
    },
    "ID_22": {
        "enable": True,
        "raw_section_name": "hostname",
        "final_section_name": "hostname",
        "regex_new": "hostname",
        "regex_old": CMD_PREFIX + "hostname"
        # 'parser_func'
    },
    "ID_23": {
        "enable": True,
        "raw_section_name": "ifconfig",
        "regex_new": "ifconfig",
        "regex_old": CMD_PREFIX + "ifconfig"
        # 'parser_func'
    },
    "ID_24": {
        "enable": True,
        "raw_section_name": "uname -a",
        "final_section_name": "uname",
        "regex_new": "uname -a",
        "regex_old": CMD_PREFIX + "uname -a"
        # 'parser_func'
    },
    "ID_25": {
        "enable": True,
        "raw_section_name": "lsb_release_1",
        "final_section_name": "lsb",
        "regex_new": "lsb_release -a",
        "regex_old": CMD_PREFIX + "lsb_release -a"
        # 'parser_func'
    },
    # Two sections having lsb, they both could occure in file.
    "ID_26": {
        "enable": True,
        "raw_section_name": "lsb_release_2",
        "final_section_name": "lsb",
        "regex_new": "ls /etc[|]grep release[|]xargs -I f cat /etc/f",
        "regex_old": CMD_PREFIX + "ls /etc[|]grep release[|]xargs -I f cat /etc/f"
        # 'parser_func'
    },
    "ID_27": {
        "enable": True,
        "raw_section_name": "build rpm",
        "final_section_name": "build",
        "regex_new": 'rpm -qa[|]grep -E "citrus[|]aero"',
        "regex_old": CMD_PREFIX + 'rpm -qa[|]grep -E "citrus[|]aero"'
        # 'parser_func'
    },
    "ID_28": {
        "enable": True,
        "raw_section_name": "build dpkg",
        "final_section_name": "build",
        "regex_new": 'dpkg -l[|]grep -E "citrus[|]aero"',
        "regex_old": CMD_PREFIX + 'dpkg -l[|]grep -E "citrus[|]aero"'
        # 'parser_func'
    },
    "ID_29": {
        "enable": False,
        "raw_section_name": "aero_log",
        "regex_new": "tail -n 10* .*aerospike.log",
        "regex_old": CMD_PREFIX + "tail -n 10* .*aerospike.log"
        # 'parser_func'
    },
    "ID_30": {
        "enable": False,
        "raw_section_name": "citrus_log",
        "regex_new": "tail -n 10* .*citrusleaf.log",
        "regex_old": CMD_PREFIX + "tail -n 10* .*citrusleaf.log"
        # 'parser_func'
    },
    "ID_31": {
        "enable": False,
        "raw_section_name": "All aerospike/*.log",
        "regex_new": "tail -n 10* .*aerospike/[*].log",
        "regex_old": CMD_PREFIX + "tail -n 10* .*aerospike/[*].log",
        # 'parser_func'
    },
    "ID_32": {
        "enable": False,
        "raw_section_name": "Udf log",
        "regex_new": "tail -n 10* .*aerospike/udf.log",
        "regex_old": CMD_PREFIX + "tail -n 10* .*aerospike/*.log",
        # 'parser_func'
    },
    "ID_33": {
        "enable": False,
        "raw_section_name": "All citrusleaf/*.log",
        "regex_new": "tail -n 10* .*citrusleaf/[*].log",
        "regex_old": CMD_PREFIX + "tail -n 10* .*citrusleaf/[*].log",
        # 'parser_func'
    },
    "ID_34": {
        "enable": False,
        "raw_section_name": "xdr_log",
        "regex_new": "tail -n 10* /var/log/.*xdr.log",
        "regex_old": CMD_PREFIX + "tail -n 10* /var/log/.*xdr.log"
        # 'parser_func'
    },
    "ID_35": {
        "enable": True,
        "raw_section_name": "netstat -pant|grep 3000",
        "regex_new": "netstat -pant[|]grep 3000|^netstat\n",
        "regex_old": CMD_PREFIX + "netstat -pant[|]grep 3000"
        # 'parser_func'
    },
    "ID_36": {
        "enable": True,
        "raw_section_name": "top -n3 -b",
        "final_section_name": "top",
        "regex_new": "top -n3 -b",
        "regex_old": CMD_PREFIX + "top -n3 -b"
        # 'parser_func'
    },
    "ID_37": {
        "enable": True,
        "raw_section_name": "free -m",
        "final_section_name": "free-m",
        "regex_new": "free -m",
        "regex_old": CMD_PREFIX + "free -m"
        # 'parser_func'
    },
    "ID_38": {
        "enable": True,
        "raw_section_name": "df -h",
        "final_section_name": "df",
        "regex_new": "df -h",
        "regex_old": CMD_PREFIX + "df -h"
        # 'parser_func'
    },
    "ID_39": {
        "enable": True,
        #'raw_section_name': 'ls /sys/block/{sd*,xvd*}/queue/rotational |xargs -I f sh -c "echo f; cat f',
        "raw_section_name": "rotational_disk_info",
        "regex_new": 'ls /sys/block/{sd[*],xvd[*]}/queue/rotational [|]xargs -I f sh -c "echo f; cat f;"',
        "regex_old": CMD_PREFIX
        + 'ls /sys/block/sd[*]/queue/rotational [|]xargs -I f sh -c "echo f; cat f;"'
        # 'parser_fun'
    },
    "ID_40": {
        "enable": True,
        "raw_section_name": "ls /sys/block/{sd*,xvd*}/device/model",
        "regex_new": 'ls /sys/block/{sd[*],xvd[*]}/device/model [|]xargs -I f sh -c "echo f; cat f;"',
        "regex_old": CMD_PREFIX
        + 'ls /sys/block/{sd[*],xvd[*]}/device/model [|]xargs -I f sh -c "echo f; cat f;"',
        # 'parser_func':
    },
    "ID_41": {
        "enable": False,
        "raw_section_name": "lsof",
        "regex_new": "(?=.*lsof)(?!.*grep)",
        "regex_old": CMD_PREFIX + "(?=.*lsof)(?!.*grep)"
        # 'parser_func':
    },
    "ID_42": {
        "enable": True,
        "raw_section_name": "dmesg",
        "final_section_name": "dmesg",
        "regex_new": "dmesg",
        "regex_old": CMD_PREFIX + "dmesg"
        # 'parser_func':
    },
    "ID_43": {
        "enable": True,
        "raw_section_name": "iostat -x",
        "final_section_name": "iostat",
        "regex_new": "iostat -x 1 10",
        "regex_old": CMD_PREFIX + "iostat -x|iostat -x 1 10"
        # 'parser_func':
    },
    "ID_44": {
        "enable": True,
        "raw_section_name": "vmstat -s",
        "regex_new": "vmstat -s",
        "regex_old": CMD_PREFIX + "vmstat -s",
        # 'parser_func':
    },
    "ID_45": {
        "enable": True,
        "raw_section_name": "vmstat -m",
        "regex_new": "vmstat -m",
        "regex_old": CMD_PREFIX + "vmstat -m",
        # 'parser_func':
    },
    "ID_46": {
        "enable": True,
        "raw_section_name": "iptables -L",
        "regex_new": "iptables -L",
        "regex_old": CMD_PREFIX + "iptables -L",
        # 'parser_func':
    },
    "ID_47": {
        "enable": True,
        "raw_section_name": "aero_conf",
        "regex_new": "cat /etc/aerospike/aerospike.conf",
        "regex_old": CMD_PREFIX + "cat /etc/aerospike/aerospike.conf"
        # 'parser_func':
    },
    "ID_48": {
        "enable": True,
        "raw_section_name": "citrus_conf",
        "regex_new": "cat /etc/citrusleaf/citrusleaf.conf",
        "regex_old": CMD_PREFIX + "cat /etc/citrusleaf/citrusleaf.conf"
        # 'parser_func':
    },
    "ID_49": {
        "enable": True,
        "raw_section_name": "info_network",
        "regex_new": "'network'",
        "collision_allowed": True
        # 'parser_func':
    },
    "ID_50": {
        "enable": True,
        "raw_section_name": "info_service table",
        #'regex_new': '(?=.*service)(?!.*services)',
        "regex_new": "'service'"
        # 'parser_func':
    },
    "ID_51": {
        "enable": True,
        "raw_section_name": "info_sindex",
        "final_section_name": "sindex_info",
        "regex_new": r"\['sindex'\]",
        # 'parser_func':
    },
    # This is technically a ttl section, of different format
    "ID_52": {
        "enable": True,
        "raw_section_name": "info_ttl_distribution_2",
        "regex_new": r"\['distribution'\]",
        # 'parser_func':
    },
    "ID_53": {
        "enable": True,
        "raw_section_name": "info_eviction_distribution_2",
        "regex_new": r"\['distribution', 'eviction'\]",
        # 'parser_func':
    },
    "ID_54": {
        "enable": True,
        "raw_section_name": "info_objectsz_distribution_2",
        "regex_new": r"\['distribution', 'object_size', '-b'\]",
        # 'parser_func':
    },
    "ID_55": {
        # TODO:----------------
        "enable": True,
        "raw_section_name": "info_service list",
        "final_section_name": "endpoints",
        #'regex_new': '[INFO] Data collection for service in progress..',
        #'regex_new': "service\n|(?=.*service)(?!.*(services|'service'))"
        "regex_new": "service\n|for service in",
        # 'parser_func':
    },
    "ID_56": {
        "enable": True,
        "raw_section_name": "info_services",
        "final_section_name": "services",
        "regex_new": "services\n| for services in",
        # 'parser_func':
    },
    "ID_57": {
        "enable": True,
        "raw_section_name": "info_xdr-min-lastshipinfo",
        "regex_new": "xdr-min-lastshipinfo:",
        # 'parser_func':
    },
    "ID_58": {
        "enable": True,
        "raw_section_name": "info_dump-fabric",
        "regex_new": "dump-fabric:",
        # 'parser_func':
    },
    "ID_59": {
        "enable": True,
        "raw_section_name": "info_dump-hb:",
        "regex_new": "dump-hb:",
        # 'parser_func':
    },
    "ID_60": {
        "enable": True,
        "raw_section_name": "info_dump-migrates:",
        "regex_new": "dump-migrates:",
        # 'parser_func':
    },
    "ID_61": {
        "enable": True,
        "raw_section_name": "info_dump-msgs:",
        "regex_new": "dump-msgs:",
        # 'parser_func':
    },
    "ID_62": {
        "enable": True,
        "raw_section_name": "info_dump-paxos:",
        "regex_new": "dump-paxos:",
        # 'parser_func':
    },
    "ID_63": {
        "enable": True,
        "raw_section_name": "info_dump-smd:",
        "regex_new": "dump-smd:",
        # 'parser_func':
    },
    "ID_64": {
        "enable": True,
        "raw_section_name": "info_dump-wb:",
        "regex_new": "dump-wb:",
        # 'parser_func':
    },
    "ID_65": {
        "enable": True,
        "raw_section_name": "info_infodump-wb-summary",
        "regex_new": "dump-wb-summary:",
        # 'parser_func':
    },
    "ID_66": {
        "enable": True,
        "raw_section_name": "info_dump-wr",
        "regex_new": "dump-wr:",
        # 'parser_func':
    },
    "ID_67": {
        "enable": True,
        "raw_section_name": "info_sindex-dump:",
        "regex_new": "sindex-dump:",
        # 'parser_func':
    },
    "ID_68": {
        "enable": True,
        "raw_section_name": "info_uptime",
        "regex_new": "uptime",
        # 'parser_func':
    },
    "ID_69": {
        "enable": True,
        "raw_section_name": "info_collect_sys",
        "regex_new": "collect_sys",
        # 'parser_func':
    },
    "ID_70": {
        "enable": True,
        "raw_section_name": "info_get_awsdata",
        "final_section_name": "awsdata",
        "regex_new": "get_awsdata",
        # 'parser_func':
    },
    "ID_71": {
        "enable": True,
        "raw_section_name": "info_stderr",
        "regex_new": "tail -n 10* stderr"
        # 'parser_func':
    },
    "ID_72": {
        "enable": True,
        "raw_section_name": "info_ip addr",
        "final_section_name": "ip_addr",
        "regex_new": "ip addr"
        # 'parser_func':
    },
    "ID_73": {
        "enable": True,
        "raw_section_name": "info_ip_link",
        "regex_new": "ip -s link",
        # 'parser_func'
    },
    "ID_74": {
        "enable": True,
        "raw_section_name": "ss -pant",
        "regex_new": r"\['ss -pant'\]",
        # 'parser_func'
    },
    "ID_75": {
        "enable": True,
        "raw_section_name": "ss -pant | grep .* | grep TIME-WAIT | wc -l",
        "regex_new": "ss -pant [|] grep .* [|] grep TIME-WAIT [|] wc -l",
        # 'parser_func'
    },
    "ID_76": {
        "enable": True,
        "raw_section_name": "ss -pant | grep .* | grep CLOSE-WAIT | wc -l",
        "regex_new": "ss -pant [|] grep .* [|] grep CLOSE-WAIT [|] wc -l",
        # 'parser_func'
    },
    "ID_77": {
        "enable": True,
        "raw_section_name": "ss -pant | grep .* | grep ESTAB | wc -l",
        "regex_new": "ss -pant [|] grep .* [|] grep ESTAB [|] wc -l",
        # 'parser_func'
    },
    "ID_78": {
        "enable": True,
        "raw_section_name": "sar -n EDEV",
        "regex_new": "sar -n EDEV",
        # 'parser_func'
    },
    "ID_79": {
        "enable": True,
        "raw_section_name": "sar -n DEV",
        "regex_new": "sar -n DEV",
    },
    "ID_80": {
        "enable": False,
        "raw_section_name": "obfuscated",
        "regex_new": "obfuscated",
        # 'parser_func'
    },
    "ID_81": {
        "enable": False,
        "raw_section_name": "aerospike_critical.log",
        "regex_new": "tail -n 10* .*aerospike/aerospike_critical.log",
        # 'parser_func'
    },
    "ID_82": {
        "enable": False,
        "raw_section_name": "log messages",
        "regex_new": "cat /var/log/messages",
        # 'parser_func'
    },
    "ID_83": {
        "enable": True,
        "raw_section_name": "Running with Force on Offline Aerospike Server",
        "regex_new": "Running with Force on Offline Aerospike Server",
        "regex_old": "Running with Force on Offline Aerospike Server",
        # 'parser_func'
    },
    "ID_84": {
        "enable": True,
        "raw_section_name": "sysctl",
        "regex_new": 'sudo sysctl -a [|] grep -E "shmmax[|]file-max[|]maxfiles"',
        # 'parser_func'
    },
    "ID_85": {
        # Its aws info
        "enable": True,
        "raw_section_name": "Request metadata",
        "final_section_name": "awsdata",
        "regex_new": "Requesting... http://",
        # 'parser_func'
    },
    "ID_86": {
        "enable": True,
        "raw_section_name": "DC info",
        "regex_new": r"\['dc'\]",
        # 'parser_func'
    },
    "ID_87": {
        "enable": True,
        "raw_section_name": "features",
        "final_section_name": "features",
        "regex_new": "'features'",
        # 'parser_func'
    },
    "ID_88": {
        "enable": True,
        "raw_section_name": "mpstat -P ALL 2 3",
        "regex_new": "mpstat -P ALL 2 3",
        # 'parser_func'
    },
    "ID_89": {
        "enable": True,
        "raw_section_name": "cpuinfo",
        "regex_new": r"\['cpuinfo'\]|^cat /proc/cpuinfo\n"
        # 'parser_func'
    },
    "ID_90": {
        "enable": True,
        "raw_section_name": "ASD stats",
        "regex_new": r"^ASD STATS\n"
        # 'parser_func'
    },
    "ID_91": {
        "enable": True,
        "raw_section_name": "aerospike profiling conf",
        "regex_new": "cat /etc/aerospike/aerospike_profiling.conf"
        # 'parser_func'
    },
    "ID_92": {
        "enable": True,
        "raw_section_name": "meminfo_kb",
        "final_section_name": "meminfo",
        "regex_new": "cat /proc/meminfo"
        # 'parser_func'
    },
    "ID_93": {
        "enable": True,
        "raw_section_name": "interrupts",
        "final_section_name": "interrupts",
        "regex_new": "cat /proc/interrupts",
        # 'parser_func'
    },
    "ID_94": {
        "enable": True,
        "raw_section_name": "asadm version",
        "regex_new": "asadm version"
        # 'parser_func'
    },
    "ID_95": {
        "enable": True,
        "raw_section_name": "pmap",
        "regex_new": r"\['pmap'\]"
        # 'parser_func'
    },
    "ID_96": {
        "enable": True,
        "raw_section_name": "syslog",
        "regex_new": "cat /var/log/syslog"
        # 'parser_func'
    },
    "ID_97": {
        "enable": True,
        "raw_section_name": "partition-info",
        "regex_new": "partition-info"
        # 'parser_func'
    },
    "ID_98": {
        "enable": True,
        "raw_section_name": "hist-dump:ttl",
        "final_section_name": "ttl",
        "regex_new": "hist-dump:ns=.*;hist=ttl",
        "parent_section_name": "histogram",
        "collision_allowed": True
        # 'parser_func'
    },
    "ID_99": {
        "enable": True,
        "raw_section_name": "hist-dump:objsz",
        "final_section_name": "objsz",
        "regex_new": "hist-dump:ns=.*;hist=objsz",
        "parent_section_name": "histogram",
        "collision_allowed": True
        # 'parser_func'
    },
    # SUD: need to be added in dev code
    "ID_100": {
        "enable": True,
        "raw_section_name": "scheduler_info",
        "final_section_name": "scheduler",
        "regex_new": 'ls /sys/block/{.*}/queue/scheduler [|]xargs -I f sh -c "echo f; cat f;"'
        # 'parser_func'
    },
    "ID_101": {
        "enable": True,
        "raw_section_name": "config_cluster",
        "final_section_name": "cluster",
        "parent_section_name": "config",
        "regex_new": r"\['config', 'cluster'\]"
        # 'parser_func'
    },
    # Leave 102 for merge from pensive
    "ID_103": {
        "enable": True,
        "raw_section_name": "ss -ant state time-wait sport = :%d or dport = :%d | wc -l",
        "regex_new": "ss -ant state time-wait sport = :%d or dport = :%d [|] wc -l",
        # 'parser_func'
    },
    "ID_104": {
        "enable": True,
        "raw_section_name": "ss -ant state close-wait sport = :%d or dport = :%d | wc -l",
        "regex_new": "ss -ant state close-wait sport = :%d or dport = :%d [|] wc -l",
        # 'parser_func'
    },
    "ID_105": {
        "enable": True,
        "raw_section_name": "ss -ant state established sport = :%d or dport = :%d | wc -l",
        "regex_new": "ss -ant state established sport = :%d or dport = :%d [|] wc -l",
        # 'parser_func'
    },
    "ID_106": {
        "enable": True,
        "raw_section_name": "netstat -ant|grep 3000",
        "regex_new": r"netstat -ant[|]grep 3000|^netstat\n",
        "regex_old": CMD_PREFIX + "netstat -ant[|]grep 3000"
        # 'parser_func'
    },
    "ID_107": {
        "enable": True,
        "raw_section_name": "lscpu",
        "final_section_name": "lscpu",
        "regex_new": r"[cpu] lscpu\n"
        # 'parser_func'
    },
    "ID_108": {
        "enable": True,
        "raw_section_name": "iptables -S",
        "final_section_name": "iptables",
        "regex_new": "iptables",
        # 'parser_func':
    },
    "ID_109": {
        "enable": True,
        "raw_section_name": "sysctl vm sys",
        "final_section_name": "sysctlall",
        "regex_new": "sysctlall",
        # 'parser_func':
    },
    "ID_110": {
        "enable": True,
        "raw_section_name": 'sudo fdisk -l |grep Disk |grep dev | cut -d " " -f 2 | cut -d ":" -f 1 | xargs sudo hdparm -I 2>/dev/null',
        "final_section_name": "hdparm",
        "regex_new": "hdparm",
        # 'parser_func':
    },
    "ID_111": {
        "enable": True,
        "raw_section_name": 'sudo pgrep asd | xargs -I f sh -c "cat /proc/f/limits"',
        "final_section_name": "limits",
        "regex_new": "limits",
        # 'parser_func':
    },
    "ID_112": {
        "enable": True,
        "raw_section_name": "curl -m 1 http://169.254.169.254/1.0/ || true",
        "final_section_name": "environment",
        "regex_new": "environment",
        # 'parser_func':
    },
    "ID_113": {
        "enable": True,
        "raw_section_name": "roster:",
        "final_section_name": "roster",
        "regex_new": "roster",
        "regex_old": r"^roster\n"
        # 'parser_func'
    },
    "ID_114": {
        "enable": True,
        "raw_section_name": "ethtool",
        "final_section_name": "ethtool",
        # 'parser_func'
    },
}


SKIP_LIST = ["dump-wb-summary", "hist-dump"]
# xdr, dc are different component, so pass them separately to parse.
# Namespace, sindex, set, bin are basic part so they will be parsed
# automatically.
AS_SECTION_NAME_LIST = [
    "statistics",
    "statistics.dc",
    "statistics.xdr",
    "config",
    "config.dc",
    "config.xdr",
    "config.cluster",
]
# Other Available sections  ['latency', 'sindex_info', 'features']

SYS_SECTION_NAME_LIST = [
    "top",
    "lsb",
    "uname",
    "meminfo",
    "scheduler",
    "hostname",
    "df",
    "free-m",
    "iostat",
    "interrupts",
    "ip_addr",
    "dmesg",
]
# Meta data have all meta info (asd_build, cluster_name)
DERIVED_SECTION_LIST = ["features"]

# List of histogram dumps (raw)
HISTOGRAM_SECTION_NAME_LIST = ["histogram.ttl", "histogram.objsz"]

# List of latency dumps
LATENCY_SECTION_NAME_LIST = ["latency"]
