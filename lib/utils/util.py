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

import copy
import pipes
import re
import socket
import StringIO
import subprocess
import sys
import threading


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
            except Exception:
                # Store original stack trace/exception to be re-thrown later.
                self.exc = sys.exc_info()

        self._worker = threading.Thread(target=wrapper,
                                        args=args, kwargs=kwargs)

    def start(self):
        self._worker.start()
        return self

    def result(self):
        if self.exc:
            raise self.exc[0], self.exc[1], self.exc[2]

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
    likes = ["(" + like.translate(None, '\'"') + ")" for like in likes]
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
            if val is not None:
                if not return_type:
                    return val

                try:
                    if return_type == bool:
                        if val.lower() == "false":
                            return False
                        if val.lower() == "true":
                            return True
                except Exception:
                    pass

                try:
                    return return_type(val)
                except Exception:
                    pass

            return default_value
    return default_value


def strip_string(search_str):
    search_str = search_str.strip()
    if search_str[0] == "\"" or search_str[0] == "\'":
        return search_str[1:len(search_str) - 1]
    else:
        return search_str


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


def get_value_from_second_level_of_dict(data, keys, default_value=None, return_type=None):
    """
    Function takes dictionary and keys to find values inside all subkeys of dictionary.
    Returns dictionary containing subkey and value of input keys
    """

    res_dict = {}
    if not data or isinstance(data, Exception):
        return res_dict

    for _k in data:
        if not data[_k] or isinstance(data[_k], Exception):
            continue

        res_dict[_k] = get_value_from_dict(data[_k], keys, default_value=default_value, return_type=return_type)

    return res_dict


def add_dicts(d1, d2):
    """
    Function takes two dictionaries and merges those to one dictionary by adding values for same key.
    """

    if not d2:
        return d1

    for _k in d2:
        if _k in d1:
            d1[_k] += d2[_k]
        else:
            d1[_k] = d2[_k]

    return d1


def pct_to_value(data, d_pct):
    """
    Function takes dictionary with base value, and dictionary with percentage and converts percentage to value.
    """

    if not data or not d_pct:
        return data

    out_map = {}
    for _k in data:
        if _k not in d_pct:
            continue

        out_map[_k] = (float(data[_k])/100.0) * float(d_pct[_k])

    return out_map


def mbytes_to_bytes(data):
    if not data:
        return data

    if isinstance(data, int) or isinstance(data, float):
        return data * 1048576

    if isinstance(data, dict):
        for _k in data.keys():
            data[_k] = copy.deepcopy(mbytes_to_bytes(data[_k]))
        return data

    return data


def find_delimiter_in(value):
    """Find a good delimiter to split the value by"""

    for d in [';', ':', ',']:
        if d in value:
            return d

    return ';'


def convert_edition_to_shortform(edition):
    """Convert edition to shortform Enterprise or Community or N/E"""

    if edition.lower() in ['enterprise', 'true', 'ee'] or 'enterprise' in edition.lower():
        return "Enterprise"

    if edition.lower() in ['community', 'false', 'ce'] or 'community' in edition.lower():
        return "Community"

    return "N/E"


def write_to_file(file, data):
    f = open(str(file), 'a')
    f.write(str(data))
    return f.close()


def is_valid_ip_port(key):
    """
    It returns True if key matches with either "IP:port" or "[ipv6]:port" format.
    """

    if not key or ":" not in key:
        return False

    key = key.strip()
    l = key.split(":")
    if "]:" in key:
        # IPv6 address
        l = key.split("]:")

    if len(l) < 2:
        return False

    address, port = l[0], l[1]

    try:
        p = int(port)
    except Exception:
        return False

    address = address.strip()

    if address.startswith("["):
        address = address[1:]

    if _is_valid_ipv4_address(address) or _is_valid_ipv6_address(address):
        return True

    return False

def _is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def _is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True
