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

import re
import threading
import subprocess
import pipes
import sys
import StringIO


class Future(object):

    """
    Very basic implementation of a async future.
    """

    def __init__(self, func, *args, **kwargs):
        self._result = None

        args = list(args)
        args.insert(0, func)
        self.exc = None

        def wrapper(func, *args, **kwargs):
            self.exc = None
            try:
                self._result = func(*args, **kwargs)
            except Exception as e:
                self.exc = e

        self._worker = threading.Thread(target=wrapper,
                                        args=args, kwargs=kwargs)

    def start(self):
        self._worker.start()
        return self

    def result(self):
        if self.exc:
            raise self.exc
        self._worker.join()
        return self._result


def shell_command(command):
    """
    command is a list of ['cmd','arg1','arg2',...]
    """

    command = pipes.quote(" ".join(command))
    command = ['sh', '-c', "'%s'" % (command)]
    try:
        p = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = p.communicate()
    except Exception:
        return '', 'error'
    else:
        return out, err

    # Redirecting the stdout to use the output elsewhere


def capture_stdout(func, line=''):
    """
    Redirecting the stdout to use the output elsewhere
    """

    sys.stdout.flush()
    old = sys.stdout
    capturer = StringIO.StringIO()
    sys.stdout = capturer

    func(line)

    output = capturer.getvalue()
    sys.stdout = old
    return output


def compile_likes(likes):
    likes = map(re.escape, likes)
    likes = "|".join(likes)
    likes = re.compile(likes)
    return likes


def filter_list(ilist, pattern_list):
    if not ilist or not pattern_list:
        return ilist
    likes = compile_likes(pattern_list)
    return filter(likes.search, ilist)


def clear_val_from_dict(keys, d, val):
    for key in keys:
        if key in d and val in d[key]:
            d[key].remove(val)


def fetch_argument(line, arg, default):
    success = True
    try:
        if arg in line:
            i = line.index(arg)
            val = line[i + 1]
            return success, val
    except Exception:
        pass
    return not success, default


def fetch_line_clear_dict(line, arg, return_type, default, keys, d):
    if not line:
        return default
    try:
        success, _val = fetch_argument(line, arg, default)
        if _val is not None:
            val = return_type(_val)
        else:
            val = None

        if success and keys and d:
            clear_val_from_dict(keys, d, arg)
            clear_val_from_dict(keys, d, _val)

    except Exception:
        val = default
    return val


def get_arg_and_delete_from_mods(line, arg, return_type, default, modifiers, mods):
    try:
        val = fetch_line_clear_dict(
            line=line, arg=arg, return_type=return_type, default=default, keys=modifiers, d=mods)
        line.remove(arg)
        if val:
            line.remove(str(val))
    except Exception:
        val = default
    return val


def check_arg_and_delete_from_mods(line, arg, default, modifiers, mods):
    try:
        if arg in line:
            val = True
            clear_val_from_dict(modifiers, mods, arg)
            line.remove(arg)
        else:
            val = False
    except Exception:
        val = default
    return val

CMD_FILE_SINGLE_LINE_COMMENT_START = "//"
CMD_FILE_MULTI_LINE_COMMENT_START = "/*"
CMD_FILE_MULTI_LINE_COMMENT_END = "*/"


def parse_commands(file_or_queries, command_end_char=";", is_file=True):
    commands = ""
    try:
        commented = False
        if is_file:
            lines = open(file_or_queries, 'r').readlines()
        else:
            lines = file_or_queries.split("\n")

        for line in lines:
            if not line or not line.strip():
                continue
            line = line.strip()
            if commented:
                if line.endswith(CMD_FILE_MULTI_LINE_COMMENT_END):
                    commented = False
                continue
            if line.startswith(CMD_FILE_SINGLE_LINE_COMMENT_START):
                continue
            if line.startswith(CMD_FILE_MULTI_LINE_COMMENT_START):
                if not line.endswith(CMD_FILE_MULTI_LINE_COMMENT_END):
                    commented = True
                continue
            try:
                if line.endswith(command_end_char):
                    line = line.replace('\n', '')
                else:
                    line = line.replace('\n', ' ')
                commands = commands + line
            except Exception:
                commands = line
    except Exception:
        pass
    return commands


def parse_queries(file, delimiter=";", is_file=True):
    queries_str = parse_commands(file, is_file=is_file)
    if queries_str:
        return queries_str.split(delimiter)
    else:
        return []


def set_value_in_dict(d, key, value):
    if (not d or not key or (not value and value != 0 and value != False)
            or isinstance(value, Exception)):
        return
    d[key] = value


def get_value_from_dict(d, keys, default_value=None, return_type=None):
    if not isinstance(keys, tuple):
        keys = (keys,)
    for key in keys:
        if key in d:
            val = d[key]
            if return_type and val:
                try:
                    return return_type(val)
                except:
                    pass
            return val
    return default_value


def strip_string(search_str):
    search_str = search_str.strip()
    if search_str[0] == "\"" or search_str[0] == "\'":
        return search_str[1:len(search_str) - 1]
    else:
        return search_str


def system_command_output_parser(cmd, output):
    if "top" in cmd:
        return {
            "topcmd": {
                "xdr_process": {},
                "RAM_KiB": {
                    "used": 2782300,
                    "free": 60137088,
                    "buffers": 56296,
                    "total": 62919388
                },
                "Uptime": {
                    "days": 2
                },
                "Cpu_utilization": {},
                "Tasks": {
                    "total": 116,
                    "sleeping": 115,
                    "running": 1
                },
                "asd_process": {
                    "resident_memory": "2.0gB",
                    "shared_memory": "1.7gB",
                    "virtual_memory": "3870mB"
                },
                "Swap_KiB": {
                    "used": 0,
                    "free": 0,
                    "total": 0,
                    "cached": 2130832
                }
            }
        }
    elif "lsb_release" in cmd or "ls /etc|grep release" in cmd:
        return {
            "lsb_release": {
                "Description": "Amazon Linux AMI 2016.09"
            }
        }
    elif "hostname" in cmd:
        return {
            "hostname": {
                "ips": ["10.242.96.35", "10.242.96.36", "10.5.214.188", "10.0.2.15"]
            }
        }


def flip_keys(orig_data):
    new_data = {}
    for key1, data1 in orig_data.iteritems():
        if isinstance(data1, Exception):
            continue
        for key2, data2 in data1.iteritems():
            if key2 not in new_data:
                new_data[key2] = {}
            new_data[key2][key1] = data2

    return new_data


def first_key_to_upper(data):
    if not data or not isinstance(data, dict):
        return data
    updated_dict = {}
    for k, v in data.iteritems():
        updated_dict[k.upper()] = v
    return updated_dict


def restructure_sys_data(content, cmd):
    if not content:
        return {}
    if cmd == "meminfo":
        pass
    elif cmd in ["free-m", "top"]:
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "iostat":
        try:
            for n in content.keys():
                c = content[n]
                c = c["iostats"][-1]
                if "device_stat" in c:
                    d_s = {}
                    for d in c["device_stat"]:
                        d_s[d["Device"]] = d
                    c["device_stat"] = d_s
                content[n] = c
        except Exception as e:
            print e
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "interrupts":
        try:
            for n in content.keys():
                try:
                    interrupt_list = content[n]["device_interrupts"]
                except Exception:
                    continue
                new_interrrupt_dict = {}
                for i in interrupt_list:
                    new_interrrupt = {}
                    itype = i["interrupt_type"]
                    iid = i["interrupt_id"]
                    idev = i["device_name"]
                    new_interrrupt[idev] = i["interrupts"]
                    if itype not in new_interrrupt_dict:
                        new_interrrupt_dict[itype] = {}
                    if iid not in new_interrrupt_dict[itype]:
                        new_interrrupt_dict[itype][iid] = {}
                    new_interrrupt_dict[itype][iid].update(
                        copy.deepcopy(new_interrrupt))
                content[n]["device_interrupts"] = new_interrrupt_dict
        except Exception as e:
            print e
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "df":
        try:
            for n in content.keys():
                try:
                    file_system_list = content[n]["Filesystems"]
                except Exception:
                    continue
                new_df_dict = {}
                for fs in file_system_list:
                    name = fs["name"]
                    if name not in new_df_dict:
                        new_df_dict[name] = {}
                    new_df_dict[name].update(copy.deepcopy(fs))

                content[n] = new_df_dict
        except Exception:
            pass

    return content
