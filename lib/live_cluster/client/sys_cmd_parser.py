# Copyright 2022-2025 Aerospike, Inc.
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

import logging
import re
import math
import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


def _get_mem_in_byte_from_str(memstr, mem_unit_len, shift=0):
    # Some files have float in (a,b) format rather than (a.b)
    if "," in memstr:
        memstr = memstr.replace(",", ".")

    if "k" in memstr or "K" in memstr:
        return _get_bytes_from_float(memstr, 10, mem_unit_len)
    elif "m" in memstr or "M" in memstr:
        return _get_bytes_from_float(memstr, 20, mem_unit_len)
    elif "g" in memstr or "G" in memstr:
        return _get_bytes_from_float(memstr, 30, mem_unit_len)
    elif "t" in memstr or "T" in memstr:
        return _get_bytes_from_float(memstr, 40, mem_unit_len)
    elif "p" in memstr or "P" in memstr:
        return _get_bytes_from_float(memstr, 50, mem_unit_len)
    elif "e" in memstr or "E" in memstr:
        return _get_bytes_from_float(memstr, 60, mem_unit_len)
    elif "z" in memstr or "Z" in memstr:
        return _get_bytes_from_float(memstr, 70, mem_unit_len)
    elif "y" in memstr or "Y" in memstr:
        return _get_bytes_from_float(memstr, 80, mem_unit_len)

    else:
        return _get_bytes_from_float(memstr, shift, 0)


def _get_bytes_from_float(memstr, shift, mem_unit_len):
    try:
        if mem_unit_len == 0:
            memnum = float(memstr)
        else:
            memnum = float(memstr[:-mem_unit_len])
    except ValueError:
        return memstr

    if memstr == "0":
        return int(0)
    f, i = math.modf(memnum)
    num = 1 << shift
    totalmem = (i * num) + (f * num)
    return int(totalmem)


# Used in top command output


def _replace_comma_from_map_value_field(datamap):
    if isinstance(datamap, dict):
        for key in datamap:
            if isinstance(datamap[key], dict) or isinstance(datamap[key], list):
                _replace_comma_from_map_value_field(datamap[key])
            else:
                if isinstance(datamap[key], str):
                    datamap[key] = (
                        datamap[key].replace(",", ".")
                        if datamap[key].replace(",", "").isdigit()
                        else datamap[key]
                    )

    elif isinstance(datamap, list):
        for index, item in datamap:
            if isinstance(item, dict) or isinstance(item, list):
                _replace_comma_from_map_value_field(item)
            else:
                if isinstance(item, str):
                    datamap[index] = (
                        datamap[index].replace(",", ".")
                        if datamap[index].replace(",", "").isdigit()
                        else datamap[index]
                    )


def _parse_top_section_line(
    line, tok_separater, keyval_separater_list
) -> dict[str, Any] | None:
    dataobj = {}
    lineobj = line.rstrip().split(":")
    if len(lineobj) != 2:
        return None
    line = lineobj[1]
    kv_obj_list = line.strip().split(tok_separater)
    for obj in kv_obj_list:
        keyval = []
        for d in keyval_separater_list:
            keyval = obj.strip().split(d)
            if len(keyval) == 2:
                break
        if len(keyval) == 2:
            dataobj[keyval[1]] = keyval[0]
    return dataobj


def parse_top_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: top")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    topdata: dict[str, Any] = {
        "uptime": {},
        "tasks": {},
        "cpu_utilization": {},
        "ram": {},
        "swap": {},
        "asd_process": {},
        "xdr_process": {},
    }
    # top_section = cmd_raw_output[raw_section_name][0]
    asd_flag = False
    xdr_flag = False

    for index, line in enumerate(output_lines):
        line = line.strip()
        if re.search("top -n3 -b", line):
            continue

        # Match object to get uptime in days.
        # "top - 18:56:45 up 103 days, 13:00,  2 users,  load average: 1.29, 1.34, 1.35\n"
        matchobj_1 = re.match(r".*up (.*?) days.*", line)
        # Match object to get total task running.
        # "Tasks: 149 total,   1 running, 148 sleeping,   0 stopped,   0 zombie\n"
        # Match object to get cpu utilization info.
        # "%Cpu(s): 11.3 us,  1.0 sy,  0.0 ni, 85.0 id,  1.7 wa,  0.0 hi,  0.7 si,  0.3 st\n"
        # Match object to get RAM info.
        # "Ki_b Mem:  62916356 total, 54829756 used,  8086600 free,   194440 buffers\n"
        # Match object to get Swap Mem info.
        # "Ki_b Swap:        0 total,        0 used,        0 free. 52694652 cached Mem\n"
        matchobj_2 = re.match(
            r".*Swap:.* (.*?).total.* (.*?).used.* (.*?).free.* (.*?).ca.*", line
        )
        matchobj_3 = re.match(
            r".*Swap:.* (.*?).total.* (.*?).free.* (.*?).used.* (.*?).av.*", line
        )
        obj = None

        if "up" in line and "load" in line:
            obj1 = re.match(r".*up.* (.*?):(.*?),.* load .*", line)
            obj2 = re.match(r".* (.*?) min", line)
            hr = 0
            mn = 0
            days = 0
            if matchobj_1:
                days = int(matchobj_1.group(1))
            if obj1:
                hr = int(obj1.group(1))
                mn = int(obj1.group(2))
            if obj2:
                mn = int(obj2.group(1))

            topdata["uptime"]["seconds"] = (
                (days * 24 * 60 * 60) + (hr * 60 * 60) + (mn * 60)
            )
            # topdata['uptime']['days'] = matchobj_1.group(1)

        if re.search(r"Tasks.*total", line):
            obj = _parse_top_section_line(line, ",", [" "])
            topdata["tasks"] = obj

        elif re.search(r"Cpu.*us", line):
            obj = _parse_top_section_line(line, ",", [" ", "%"])
            topdata["cpu_utilization"] = obj

        elif re.search(r"Mem.*total", line):
            shift = 1
            if "Ki_b" in line or "KiB" in line:
                shift = 10
            if "Mi_b" in line or "MiB" in line:
                shift = 20

            obj = _parse_top_section_line(line, ",", [" ", "+"])
            topdata["ram"] = obj

            if topdata["ram"] is not None:
                for mem in topdata["ram"]:
                    topdata["ram"][mem] = _get_mem_in_byte_from_str(
                        topdata["ram"][mem], 1, shift=shift
                    )

        elif matchobj_2 or matchobj_3:
            shift = 1
            if "Ki_b" in line or "KiB" in line:
                shift = 10
            if "Mi_b" in line or "MiB" in line:
                shift = 20

            if matchobj_2:
                topdata["swap"]["total"] = matchobj_2.group(1)
                topdata["swap"]["used"] = matchobj_2.group(2)
                topdata["swap"]["free"] = matchobj_2.group(3)
                topdata["swap"]["cached"] = matchobj_2.group(4)
            elif matchobj_3:
                topdata["swap"]["total"] = matchobj_3.group(1)
                topdata["swap"]["free"] = matchobj_3.group(2)
                topdata["swap"]["used"] = matchobj_3.group(3)
                topdata["swap"]["avail"] = matchobj_3.group(4)

            for mem in topdata["swap"]:
                topdata["swap"][mem] = _get_mem_in_byte_from_str(
                    topdata["swap"][mem], 1, shift=shift
                )

        else:
            # Break, If we found data for both process.
            # Also break if it chacked more the top 15 process.
            if (asd_flag and xdr_flag) or index > 25:
                break
            # "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU %MEM     TIME+ COMMAND\n"
            # "26937 root      20   0 59.975g 0.049t 0.048t S 117.6 83.9 164251:27 asd\n"
            if not asd_flag and re.search("asd", line):
                asd_flag = True
                l = re.split(r"\ +", line)
                topdata["asd_process"]["virtual_memory"] = l[4]
                topdata["asd_process"]["resident_memory"] = l[5]
                topdata["asd_process"]["shared_memory"] = l[6]
                topdata["asd_process"]["%cpu"] = l[8]
                topdata["asd_process"]["%mem"] = l[9]
                for field in topdata["asd_process"]:
                    if field == "%cpu" or field == "%mem":
                        continue
                    topdata["asd_process"][field] = _get_mem_in_byte_from_str(
                        topdata["asd_process"][field], 1
                    )
            elif not xdr_flag and re.search("xdr", line):
                xdr_flag = True
                l = re.split(r"\ +", line)
                topdata["xdr_process"]["virtual_memory"] = l[4]
                topdata["xdr_process"]["resident_memory"] = l[5]
                topdata["xdr_process"]["shared_memory"] = l[6]
                topdata["xdr_process"]["%cpu"] = l[8]
                topdata["xdr_process"]["%mem"] = l[9]
                for field in topdata["xdr_process"]:
                    if field == "%cpu" or field == "%mem":
                        continue
                    topdata["xdr_process"][field] = _get_mem_in_byte_from_str(
                        topdata["xdr_process"][field], 1
                    )

    _replace_comma_from_map_value_field(topdata)

    datalist = ["tasks", "cpu_utilization", "ram", "swap"]
    for sec in datalist:
        if not topdata[sec] or len(topdata[sec]) == 0:
            logger.error(
                "Top format changed. data could be missing. section: " + str(sec)
            )

    return topdata


# output: {kernel_name: AAA, nodename: AAA, kernel_release: AAA}


def parse_uname_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: uname")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    unamedata = {}

    for line in output_lines:
        if re.search("uname -a", line) or line.strip() == "":
            continue
        # "Linux e-asmem-01.ame.admarketplace.net 2.6.32-279.el6.x86_64 #1 SMP Fri Jun 22 12:19:21 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux\n"
        l = re.split(r"\ +", (line.split("#")[0]))
        unamedata["kernel_name"] = l[0]
        unamedata["nodename"] = l[1]
        unamedata["kernel_release"] = l[2]
        break

    return unamedata


# output: {key: val..........}
def parse_meminfo_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: meminfo")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    meminfo_data = {}
    meminfo_section = output_lines

    # If this section is not empty then there would be more than 5-6 lines,
    # defensive check.
    if len(meminfo_section) < 3:
        logger.info("meminfo section seems empty.")
        return {}

    for line in meminfo_section:
        # If line is a newline char, skip it. line size 4 (defensive check)
        if len(line) < 4 or line.strip() == "":
            continue

        # "Mem_total:       32653368 k_b\n",
        if ":" not in line:
            continue

        keyval = line.split(":")
        key = keyval[0].replace(" ", "_")
        meminfo_data[key] = int(keyval[1].split()[0]) * 1024

    return meminfo_data


def _get_age_month(y, m):
    n = datetime.now()
    return (n.year - y) * 12 + n.month - m


def parse_lsb_release_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: lsb_release")

    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        logger.warning("Null section json")
        return {}

    lsb_data = {}

    for line in output_lines:
        # "LSB Version:\t:base-4.0-amd64:base-4.0-noarch:core-4.0-amd64:
        # "Description:\t_cent_oS release 6.4 (Final)\n"
        matchobj = re.match(r"Description:\t(.*)", line)
        if matchobj:
            lsb_data["description"] = matchobj.group(1).strip()
            break
        # "Red Hat Enterprise Linux Server release 6.7 (Santiago)\n"
        # "Cent_oS release 6.7 (Final)\n"
        if re.search(".* release [0-9]+", line):
            lsb_data["description"] = line.strip()
            break
        # Few formats have only PRETTY_NAME, so need to add this condition.
        # "PRETTY_NAME=\"Ubuntu 14.04.2 LTS\"\n"
        matchobj = re.match(r"PRETTY_NAME=\"(.*)\"", line)
        if matchobj:
            lsb_data["description"] = matchobj.group(1)
            break

        if "description" in lsb_data and (
            "amazon" in lsb_data["description"].lower()
            and "ami" in lsb_data["description"].lower()
        ):
            # For amazon linux ami
            for index, line in enumerate(output_lines):
                matchobj = re.match(r"version=(.*)", line.lower())
                if matchobj:
                    v = matchobj.group(1).strip()
                    try:
                        v = v.split(".")
                        y, m = v[0], v[1]
                        if y.startswith("'") or y.startswith('"'):
                            y = y[1:]
                        if m.endswith("'") or m.endswith('"'):
                            m = m[:-1]
                        y = int(y)
                        m = int(m)
                        lsb_data["os_age_months"] = _get_age_month(y, m)
                    except Exception:
                        # Error while parsing version
                        pass

    return lsb_data


# "hostname\n",
# "rs-as01\n",
#
# output: {hostname: {'hosts': [...................]}}


def parse_hostname_section(cmd_raw_output: str):
    logger.info("Parsing section: hostname")

    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    hnamedata = {}

    for line in output_lines:
        if line == "\n" or line == "." or "hostname" in line:
            continue
        else:
            hnamedata["hosts"] = line.rstrip().split()
            break

    return hnamedata


### "Filesystem             Size  Used Avail Use% Mounted on\n",
### "/dev/xvda1             7.8_g  1.6_g  5.9_g  21% /\n",
### "none                   4.0_k     0  4.0_k   0% /sys/fs/cgroup\n",
#
# output: [{name: AAA, size: AAA, used: AAA, avail: AAA, %use: AAA,
# mount_point: AAA}, ....]


def parse_df_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: df")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    df_data = []
    tok_count = 6
    found_sec_start = False
    size_in_kb = False

    for index, line in enumerate(output_lines):
        if re.search(r"id.*enabled", line):
            break
        if line.strip() == "":
            continue
        if "Filesystem" in line:
            found_sec_start = True
            continue
        if "1_k-block" in line:
            size_in_kb = True
            continue

        if found_sec_start:
            tok_list = line.strip().split()

            if len(tok_list) != tok_count:
                if index > len(output_lines) - 1:
                    continue
                if len(tok_list) == 1 and (
                    len(output_lines[index + 1].rstrip().split()) == tok_count - 1
                ):
                    tok_list = tok_list + output_lines[index + 1].rstrip().split()
                    output_lines[index + 1] = ""
                else:
                    continue

            file_system = {}
            file_system["name"] = tok_list[0]
            file_system["size"] = _get_mem_in_byte_from_str(tok_list[1], 1)
            file_system["used"] = _get_mem_in_byte_from_str(tok_list[2], 1)
            file_system["avail"] = _get_mem_in_byte_from_str(tok_list[3], 1)
            file_system["%use"] = tok_list[4].replace("%", "")
            file_system["mount_point"] = tok_list[5]

            if size_in_kb:
                file_system["size"] = file_system["size"] * 1024
            df_data.append(file_system)

    return {"Filesystems": df_data}


### "             total       used       free     shared    buffers     cached\n",
### "Mem:         32068      31709        358          0         17      13427\n",
### "-/+ buffers/cache:      18264      13803\n",
### "Swap:         1023        120        903\n",
#
# output: {mem: {}, buffers/cache: {}, swap: {}}


def parse_free_m_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: free_m")

    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    free_m_data = {}
    tok_list = []
    alltok_list = [
        "total",
        "used",
        "free",
        "shared",
        "buffers",
        "cached",
        "buff/cache",
        "available",
    ]
    found_sec_start = False

    for line in output_lines:
        if "total" in line and "used" in line and "free" in line:
            sectok_list = line.rstrip().split()
            if set(sectok_list).intersection(set(alltok_list)) != set(sectok_list):
                logger.error(
                    "Free-m section format changed. union list: "
                    + str(alltok_list)
                    + " new sec list: "
                    + str(sectok_list)
                )
                return {}
            tok_list = sectok_list
            found_sec_start = True

        if found_sec_start and "Mem:" in line:
            data_list = line.rstrip().split()

            mem_obj = {}
            for idx, val in enumerate(tok_list):
                try:
                    mem_obj[val] = int(data_list[idx + 1])
                except Exception:
                    mem_obj[val] = data_list[idx + 1]

            free_m_data["mem"] = mem_obj
            continue

        if found_sec_start and "-/+ buffers/cache:" in line:
            data_list = line.rstrip().split()

            buffer_obj = {}
            try:
                buffer_obj[tok_list[1]] = int(data_list[2])
            except Exception:
                buffer_obj[tok_list[1]] = data_list[2]

            try:
                buffer_obj[tok_list[2]] = int(data_list[3])
            except Exception:
                buffer_obj[tok_list[2]] = data_list[3]

            free_m_data["buffers/cache"] = buffer_obj
            continue

        if found_sec_start and "Swap:" in line:
            data_list = line.rstrip().split()

            swap_obj = {}
            try:
                swap_obj[tok_list[0]] = int(data_list[1])
            except Exception:
                swap_obj[tok_list[0]] = data_list[1]

            try:
                swap_obj[tok_list[1]] = int(data_list[2])
            except Exception:
                swap_obj[tok_list[1]] = data_list[2]

            try:
                swap_obj[tok_list[2]] = int(data_list[3])
            except Exception:
                swap_obj[tok_list[2]] = data_list[3]

            free_m_data["swap"] = swap_obj
            continue

    return free_m_data


def _modify_keys_in_iostat_section(iostatobj_list):
    for obj in iostatobj_list:
        change_key_name_in_map(obj, ["rkB/s"], "rk_b/s")
        change_key_name_in_map(obj, ["wkB/s"], "wk_b/s")


def parse_dmesg_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: dmesg")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    dmesg_section = output_lines
    dmesg_data: dict[str, Any] = {"OOM": False, "Blocked": False, "ENA_enable": False}

    for line in dmesg_section:
        if "OOM" in line:
            dmesg_data["OOM"] |= True

        if "blocked for more than 120 seconds" in line:
            dmesg_data["Blocked"] |= True

        if "Linux version" in line:
            dmesg_data["OS"] = line

        if " ena " in line or " ena:" in line:
            dmesg_data["ENA_enabled"] = True

    return dmesg_data


def parse_lscpu_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: lscpu")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    lscpu_data = {}

    for line in output_lines:
        if line == "":
            continue

        lineobj = line.rstrip().split(":")

        if len(lineobj) < 2:
            continue

        key = str(lineobj[0])
        val = str(lineobj[1])
        lscpu_data[key.strip()] = val.strip()

    return lscpu_data


def parse_iptables_section(cmd_raw_section) -> dict[str, Any]:
    logger.info("Parsing section: iptables")

    output_lines = cmd_raw_section.split("\n")

    if not output_lines:
        return {}

    iptables_data = {"has_firewall": False}

    for line in output_lines:
        if "DROP" in line:
            iptables_data["has_firewall"] = True
            break

    return iptables_data


def parse_sysctlall_section(cmd_raw_output) -> dict[str, Any]:
    logger.info("Parsing section: sysctlall")

    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    sysctlall_data = {}

    for line in output_lines:
        if line == "":
            continue

        lineobj = line.rstrip().split("=")

        if len(lineobj) < 2:
            continue

        key = str(lineobj[0])
        val = str(lineobj[1])
        sysctlall_data[key.strip()] = val.strip()

    return sysctlall_data


def parse_hdparm_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: hdparm")

    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    device_data = {}

    device = ""

    for line in output_lines:
        if re.search("/dev.*:", line, re.IGNORECASE):
            device = line
            continue

        if not device:
            continue

        if (
            "Sector size" in line
            or "device size" in line
            or "Model Number" in line
            or "Serial Number" in line
            or "Firmware Revision" in line
            or "Transport" in line
            or "Queue Depth" in line
        ):
            lineobj = line.rstrip().split(":")
            if len(lineobj) < 2:
                continue

            key = str(device) + str(lineobj[0]).strip()
            val = str(lineobj[1]).strip()

            device_data[key] = val

    return device_data


def parse_limits_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: limits")

    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    limits = {}

    for line in output_lines:
        if "Max" not in line:
            continue

        lineobj = [_f for _f in line.rstrip().split("  ") if _f]
        key = str(lineobj[0]).strip()
        limits["Soft " + key] = str(lineobj[1]).strip()
        limits["Hard " + key] = str(lineobj[2]).strip()

    return limits


def parse_environment_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: environment")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    env_data = {}

    platform = "baremetal"

    for line in output_lines:
        if line.strip() == "meta-data":
            platform = "aws"
            break

    env_data["platform"] = platform

    return env_data


def parse_scheduler_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: scheduler")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    scheduler_data = {}

    schedulers = []
    scheduler = ""
    device = ""
    for line in output_lines:
        line = line.strip()
        if not line or "cannot access" in line:
            continue

        if "scheduler" in line:
            l = line.split("/sys/block/")
            if not l:
                continue

            l = l[1].split("/queue/scheduler")
            if not l:
                continue

            device = l[0].strip()
            continue

        if not device:
            # device not found yet, no need to proceed with this line
            continue

        # find scheduler
        for s in line.split():
            if not s:
                continue
            if s.startswith("[") and s.endswith("]"):
                scheduler = s[1 : len(s) - 1].lower()

        # if scheduler found, set details
        if scheduler:
            schedulers.append({"device": device, "scheduler": scheduler})
            scheduler = ""
            device = ""

    scheduler_data["scheduler_stat"] = schedulers
    return scheduler_data


def parse_ethtool_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: ethtool")

    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        logger.warning("Null section json")
        return {}

    ethtool_data = {}
    current_device = None

    for line in output_lines:
        line = line.lower()

        if "ethtool" in line:
            current_device = line.split()[-1]
            ethtool_data[current_device] = {}
            continue

        if "nic statistics" in line:
            continue

        if current_device is None:
            continue

        line = line.replace(" ", "")
        line = line.split(":")

        if len(line) != 2:
            continue

        key, val = line

        try:
            ethtool_data[current_device][key] = int(val)
        except:
            ethtool_data[current_device][key] = val

    return ethtool_data


### "iostat -x 1 10\n",
### "Linux 2.6.32-279.el6.x86_64 (bfs-dl360g8-02) \t02/02/15 \t_x86_64_\t(24 CPU)\n",
### "avg-cpu:  %user   %nice %system %iowait  %steal   %idle\n",
### "           0.78    0.00    1.44    0.26    0.00   97.51\n",
# "\n",
### "Device:         rrqm/s   wrqm/s     r/s     w/s   rsec/s   wsec/s avgrq-sz avgqu-sz   await  svctm  %util\n",
### "sdb               0.00     4.00    0.00    4.00     0.00    64.00    16.00     0.02    5.75   4.00   1.60\n",
#
# output: [{avg-cpu: {}, device_stat: {}}, .........]


def parse_iostat_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: iostat")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    # Create a List of all instances of iostat data.
    section_list = []
    start = False
    section = []
    for line in output_lines:
        if "avg-cpu" in line and "user" in line:
            if start:
                section_list.append(section)
                section = []
            start = True
        section.append(line)
    section_list.append(section)

    iostat_data = []

    avgcpu_line = False
    # tok_cpuline = []
    tok_cpuline = [
        "avg-cpu:",
        "%user",
        "%nice",
        "%system",
        "%iowait",
        "%steal",
        "%idle",
    ]
    device_line = False
    tok_deviceline = []
    tok_devicelist = [
        "Device:",
        "rrqm/s",
        "wrqm/s",
        "r/s",
        "w/s",
        "rk_b/s",
        "rkB/s",
        "wk_b/s",
        "wkB/s",
        "avgrq-sz",
        "avgqu-sz",
        "await",
        "r_await",
        "w_await",
        "svctm",
        "%util",
        "rsec/s",
        "wsec/s",
    ]

    # Iterate over all instances and create list of maps
    for iostat_section in section_list:
        section_data = {}
        cpuobj = {}
        deviceobj_list = []
        for line in iostat_section:
            deviceobj = {}
            if "avg-cpu" in line and "user" in line:
                avgcpu_line = True
                sectok_cpuline = line.rstrip().split()
                if tok_cpuline != sectok_cpuline:
                    logger.error(
                        "iostat section format changed. old sec list: "
                        + str(tok_cpuline)
                        + " new sec list: "
                        + str(sectok_cpuline)
                    )
                    return {}
                continue

            if "Device:" in line and "rrqm/s" in line:
                avgcpu_line = False
                device_line = True
                sectok_deviceline = line.rstrip().split()
                if set(sectok_deviceline).intersection(set(tok_devicelist)) == set(
                    sectok_deviceline
                ):
                    tok_deviceline = sectok_deviceline
                else:
                    logger.error(
                        "iostat section format changed. old sec union list: "
                        + str(tok_devicelist)
                        + " new sec list: "
                        + str(sectok_deviceline)
                    )
                    return {}
                continue

            if avgcpu_line:
                data_list = line.rstrip().split()
                if len(data_list) + 1 != len(tok_cpuline):
                    continue

                for idx, val in enumerate(data_list):
                    cpuobj[tok_cpuline[idx + 1]] = val
                continue

            if device_line:
                data_list = line.rstrip().split()
                if len(data_list) != len(tok_deviceline):
                    continue

                deviceobj[tok_deviceline[0].replace(":", "")] = data_list[0]
                for idx, val in enumerate(data_list):
                    if idx == 0:
                        continue
                    deviceobj[tok_deviceline[idx]] = val
                deviceobj_list.append(deviceobj)

        section_data["avg-cpu"] = cpuobj
        section_data["device_stat"] = deviceobj_list
        # Change rkB/s -> rk_b/s and wkB/S -> wk_b/s
        _modify_keys_in_iostat_section(deviceobj_list)
        iostat_data.append(section_data)

    return {"iostats": iostat_data}


def parse_interrupts_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: interrupts")
    output_lines = cmd_raw_output.split("\n")

    if not output_lines:
        return {}

    tok_list = []
    int_list = []
    cpu_tok = []

    for line in output_lines:
        if "cat /proc" in line or line == "\n":
            continue
        if "CPU" in line:
            cpu_tok = line.rstrip().split()
            continue
        if "Tx_rx" in line:
            tok_list = line.rstrip().split()
            device_name = tok_list[-1]
            int_type = tok_list[-2]
            int_id = tok_list[0]
            cpu_list = tok_list[1:-2]

            dev_obj = {}
            dev_obj["device_name"] = device_name
            dev_obj["interrupt_id"] = int_id.replace(":", "")
            dev_obj["interrupt_type"] = int_type

            dev_obj["interrupts"] = {}
            for idx, cpu in enumerate(cpu_tok):
                dev_obj["interrupts"][cpu] = cpu_list[idx]
            int_list.append(dev_obj)

    return {"device_interrupts": int_list}


def parse_ipaddr_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: ipaddr")
    output_lines = cmd_raw_output.split("\n")

    if not cmd_raw_output:
        return {}

    ip_data = {}
    ip_list = []

    for line in output_lines:
        # inet 127.0.0.1/8 scope host lo
        if "inet" in line and "inet6" not in line:
            tok_list = line.rstrip().split()
            ip_list.append(tok_list[1].split("/")[0])
            continue

        # inet6 fe80::a236:9fff:fe82:7fde/64 scope link
        if "inet6" in line:
            tok_list = line.rstrip().split()
            ip = "[" + tok_list[1].split("/")[0] + "]"
            ip_list.append(ip)
            continue

    ip_data["hosts"] = ip_list
    return ip_data


def parse_awsdata_section(cmd_raw_output: str) -> dict[str, Any]:
    logger.info("Parsing section: awsdata")
    output_lines = cmd_raw_output.split("\n")

    if not cmd_raw_output:
        logger.warning("Null section json")
        return {}

    awsdata = {}
    field_count = 0
    total_fields = 2

    for index, line in enumerate(output_lines):
        if field_count >= total_fields:
            break
        if "in_aWS" not in awsdata and re.search("This .* in AWS", line, re.IGNORECASE):
            awsdata["in_aws"] = True
            field_count += 1
            continue
        if "in_aWS" not in awsdata and re.search("not .* in aws", line, re.IGNORECASE):
            awsdata["in_aws"] = False
            field_count += 1
            continue
        if "instance_type" not in awsdata and re.search("instance-type", line):
            awsdata["instance_type"] = (output_lines[index + 1]).split("\n")[0]
            field_count += 1
            if "in_aWS" not in awsdata:
                awsdata["in_aws"] = True
                field_count += 1
            continue

    # parsed_map[final_section_name_1] = awsdata
    return awsdata


##########
# Utils
##########


def change_key_name_in_map(datamap, old_keys, new_key):
    for key in old_keys:
        if key in datamap:
            datamap[new_key] = datamap[key]
            datamap.pop(key, None)


# This should check only raw values.
# Aerospike doesn't send float values
# pretty print and other cpu stats can send float
# This will skip list if its first item is not a dict.


def type_check_basic_values(section: dict[str, Any]):
    malformedkeys = []
    # ip_regex = "[0-9]{1,2,3}(\.[0-9]{1,2,3})*"
    for key in section:
        if isinstance(section[key], dict):
            type_check_basic_values(section[key])

        elif (
            isinstance(section[key], list)
            and len(section[key]) > 0
            and isinstance(section[key][0], dict)
        ):
            for item in section[key]:
                type_check_basic_values(item)

        else:
            if "." in key or " " in key:
                malformedkeys.append(key)

            if (
                isinstance(section[key], list)
                or isinstance(section[key], int)
                or isinstance(section[key], bool)
                or isinstance(section[key], float)
            ):
                continue
            elif section[key] is None:
                logger.debug("Value for key " + key + " is Null")
                continue
            elif section[key] == "N/E" or section[key] == "n/e":
                logger.debug("'N/E' for the field.")
                section[key] = None
                continue

            # Handle float of format (a.b), only 1 dot would be there.
            if section[key].replace(".", "", 1).isdigit():
                section[key] = _str_to_number(section[key])

            # Handle bool
            elif is_bool(section[key]):
                section[key] = _str_to_boolean(section[key])

            elif section[key].lstrip("-").replace(".", "", 1).isdigit():
                num = section[key].lstrip("-")
                number = _str_to_number(num)
                section[key] = -1 * number
            # Handle negative format (-ab,c,f)

    for key in malformedkeys:
        newkey = key.replace(".", "_").replace(" ", "_")
        val = section[key]
        section.pop(key, None)
        section[newkey] = val


def is_bool(val):
    return val.lower() in ["true", "false", "yes", "no"]


def _str_to_number(number):
    try:
        return int(number)
    except ValueError:
        try:
            return float(number)
        except ValueError:
            return number


# Bool is represented as 'true' or 'false'
def _str_to_boolean(val):
    if not is_bool(val):
        logger.warning(
            "string passed for boolean conversion must be a boolean string true/false/yes/no"
        )
        return
    if val.lower() in ["true", "yes"]:
        return True
    elif val.lower() in ["false", "no"]:
        return False
