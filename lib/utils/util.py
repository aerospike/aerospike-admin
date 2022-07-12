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

import asyncio
import copy
import inspect
import io
import pipes
import re
import socket
import subprocess
import sys
import logging
from time import time
from typing import (
    Any,
    Awaitable,
    Callable,
    Generator,
    Generic,
    Iterable,
    Literal,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

from lib.utils import logger_debug

logger = logger_debug.get_debug_logger(__name__, logging.CRITICAL)


def callable(func, *args, **kwargs):
    """
    Save a function call for later. Useful for saving functions that print output.
    """
    return lambda: func(*args, **kwargs)


def shell_command(command) -> tuple[str, str]:
    """
    command is a list of ['cmd','arg1','arg2',...]
    """
    command = pipes.quote(" ".join(command))
    command = ["bash", "-c", "'%s'" % (command)]
    try:
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = p.communicate()
    except Exception:
        return "", "error"
    else:
        return bytes_to_str(out), bytes_to_str(err)


async def capture_stdout(func, *args, **kwargs):
    """
    Redirecting the stdout to use the output elsewhere
    """

    sys.stdout.flush()
    old = sys.stdout

    try:
        capturer = io.StringIO()
        sys.stdout = capturer

        if inspect.iscoroutinefunction(func):
            await func(*args, **kwargs)
        else:
            tmp_output = func(*args, **kwargs)

            if inspect.iscoroutine(tmp_output):
                tmp_output = await tmp_output

        output = capturer.getvalue()
    finally:
        sys.stdout = old

    return output


def capture_stderr(func, *args, **kwargs):
    """
    Redirecting the stderr to use the output elsewhere
    """

    sys.stderr.flush()
    old = sys.stderr
    capturer = io.StringIO()
    sys.stderr = capturer

    func(*args, **kwargs)

    output = capturer.getvalue()
    sys.stderr = old
    return output


def capture_stdout_and_stderr(func, *args, **kwargs):
    sys.stdout.flush()
    stdout_old = sys.stdout
    stdout_capturer = io.StringIO()
    sys.stdout = stdout_capturer

    sys.stderr.flush()
    stderr_old = sys.stderr
    stderr_capturer = io.StringIO()
    sys.stderr = stderr_capturer

    func(*args, **kwargs)

    stdout_output = stdout_capturer.getvalue()
    sys.stdout = stdout_old

    stderr_output = stderr_capturer.getvalue()
    sys.stderr = stderr_old

    return stdout_output, stderr_output


async def capture_stdout_and_stderr_async(func, *args, **kwargs):
    sys.stdout.flush()
    stdout_old = sys.stdout
    stdout_capturer = io.StringIO()
    sys.stdout = stdout_capturer

    sys.stderr.flush()
    stderr_old = sys.stderr
    stderr_capturer = io.StringIO()
    sys.stderr = stderr_capturer

    await func(*args, **kwargs)

    stdout_output = stdout_capturer.getvalue()
    sys.stdout = stdout_old

    stderr_output = stderr_capturer.getvalue()
    sys.stderr = stderr_old

    return stdout_output, stderr_output


def compile_likes(likes):
    if likes is None:
        likes = []

    likes = ["(" + like.translate(str.maketrans("", "", "'\"")) + ")" for like in likes]
    likes = "|".join(likes)
    likes = re.compile(likes)
    return likes


def filter_list(ilist, pattern_list):
    if not ilist or not pattern_list:
        return ilist
    likes = compile_likes(pattern_list)
    return filter(likes.search, ilist)


def clear_val_from_list_in_dict(keys, d, val):
    for key in keys:
        if key in d and val in d[key]:
            d[key].remove(val)


ReturnType = TypeVar("ReturnType")
DefaultType = TypeVar("DefaultType")


def fetch_argument(
    line, arg, default: DefaultType
) -> Union[tuple[Literal[True], str], tuple[Literal[False], DefaultType]]:
    success = True
    try:
        if arg in line:
            i = line.index(arg)
            val = line[i + 1]
            return success, val
    except Exception:
        pass
    return not success, default


def _fetch_line_clear_dict(
    line, arg, return_type: Type[ReturnType], default: DefaultType, keys, d
) -> Union[DefaultType, ReturnType]:
    if not line:
        return default
    try:
        success, _val = fetch_argument(line, arg, default)
        if _val is not None:
            val = return_type(_val)
        else:
            val = None

        if success and keys and d:
            clear_val_from_list_in_dict(keys, d, arg)
            clear_val_from_list_in_dict(keys, d, _val)

    except Exception:
        val = default
    return val


def get_arg_and_delete_from_mods(
    line, arg, return_type: Type[ReturnType], default: DefaultType, modifiers, mods
) -> Union[DefaultType, ReturnType]:
    try:
        val = _fetch_line_clear_dict(
            line=line,
            arg=arg,
            return_type=return_type,
            default=default,
            keys=modifiers,
            d=mods,
        )

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
            clear_val_from_list_in_dict(modifiers, mods, arg)
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
            lines = open(file_or_queries, "r").readlines()
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
                    line = line.replace("\n", "")
                else:
                    line = line.replace("\n", " ")
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
    if (
        d is None
        or not isinstance(d, dict)
        or not key
        or (not value and value != 0 and value is not False)
        or isinstance(value, Exception)
    ):
        return

    d[key] = value


@overload
def _cast(value: str, return_type: None) -> Tuple[str, Literal[True]]:
    pass


@overload
def _cast(value: str, return_type: Type[bool]) -> Tuple[bool, bool]:
    pass


@overload
def _cast(
    value: str, return_type: Type[ReturnType]
) -> Tuple[Union[ReturnType, None], bool]:
    pass


def _cast(
    value: str, return_type: Union[Type[ReturnType], None, Type[bool]] = str
) -> Union[
    Tuple[Union[ReturnType, None], bool], Tuple[str, Literal[True]], Tuple[bool, bool]
]:
    """
    Function takes value and data type to cast.
    Returns result of casting and success status
    """

    if not return_type or value is None:
        return value, True

    try:
        if return_type == bool and isinstance(value, str):
            if value.lower() == "false":
                return False, True
            if value.lower() == "true":
                return True, True
    except Exception:
        pass

    try:
        return return_type(value), True
    except Exception:
        pass

    return None, False


def get_value_from_dict(
    d, keys, default_value: DefaultType = None, return_type: Type[ReturnType] = None
) -> Union[DefaultType, ReturnType]:
    """
    Function takes dictionary and keys to find values inside dictionary.
    Returns value of first matching key from keys which is available in d else returns default_value
    """

    if not isinstance(keys, tuple) and not isinstance(keys, list):
        keys = (keys,)

    for key in keys:
        if key in d:
            val, success = _cast(d[key], return_type=return_type)
            if success:
                return val

            return default_value
    return default_value


def get_values_from_dict(
    d, re_keys, return_type: Type[ReturnType] = str
) -> list[ReturnType]:
    """
    Function takes dictionary and regular expressions for keys to find values inside dictionary.
    Returns list of values for all matching keys with any of regular expression keys else returns empty list
    """

    values = []
    if not re_keys or not d or not isinstance(d, dict):
        return values

    if not isinstance(re_keys, tuple) and not isinstance(re_keys, list):
        re_keys = (re_keys,)

    keys = filter_list(d.keys(), re_keys)

    for key in keys:
        val, success = _cast(d[key], return_type=return_type)
        if success:
            values.append(val)
            continue

        values.append(d[key])

    return values


def strip_string(search_str):
    return search_str.strip().strip("'\"")


def flip_keys(orig_data):
    """
    Flips a two level nested dictionary.
    Example:
    {key1: {key2: value, key3: value}} => {key2: {key1: value}, {key3: value}}
    """
    new_data = {}
    for key1, data1 in orig_data.items():
        if isinstance(data1, Exception):
            continue

        for key2, data2 in data1.items():
            if key2 not in new_data:
                new_data[key2] = {}

            new_data[key2][key1] = data2

    return new_data


def first_key_to_upper(data):
    if not data or not isinstance(data, dict):
        return data
    updated_dict = {}
    for k, v in data.items():
        updated_dict[k.upper()] = v
    return updated_dict


# TODO: Remove duplications or extra steps
# TODO: Organize parse flow
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
            print(e)
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
                        copy.deepcopy(new_interrrupt)
                    )
                content[n]["device_interrupts"] = new_interrrupt_dict
        except Exception as e:
            print(e)
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

    elif cmd == "scheduler":
        try:
            for n in content.keys():
                c = content[n]
                c = c["scheduler_stat"]
                sch = {}
                for d_info in c:
                    sch[d_info["device"]] = {}
                    sch[d_info["device"]]["scheduler"] = d_info["scheduler"]

                content[n] = sch
        except Exception:
            pass

    return content


def get_value_from_second_level_of_dict(
    data: dict[Any, str],
    keys: list[str],
    default_value: DefaultType = None,
    return_type: Type[ReturnType] = str,
) -> dict[str, Union[ReturnType, DefaultType]]:
    """
    Function takes dictionary and subkeys to find values inside all keys of dictionary.
    Returns dictionary containing key and value of input keys
    """

    res_dict = {}
    if not data or isinstance(data, Exception):
        return res_dict

    for _k in data:
        if not data[_k] or isinstance(data[_k], Exception):
            continue

        res_dict[_k] = get_value_from_dict(
            data[_k], keys, default_value=default_value, return_type=return_type
        )

    return res_dict


def get_values_from_second_level_of_dict(
    data, re_keys, return_type: Type[ReturnType] = str
) -> dict[str, ReturnType]:
    """
    Function takes dictionary and regular expression subkeys to find values inside all keys of dictionary.
    Returns dictionary containing key and all values for matching input keys
    """

    res_dict = {}
    if not data or isinstance(data, Exception):
        return res_dict

    for _k in data:
        if not data[_k] or isinstance(data[_k], Exception):
            continue

        res_dict[_k] = get_values_from_dict(data[_k], re_keys, return_type=return_type)

    return res_dict


def get_nested_value_from_dict(
    data: dict[str, Any],
    keys: list[str],
    default_value=None,
    return_type: Type[ReturnType] = str,
) -> Union[ReturnType, None]:
    """
    Given a list of keys, returns the nested value in a dict.
    """
    ref = data
    for key in keys:
        temp_ref = get_value_from_dict(ref, key)

        if not temp_ref:
            return default_value

        ref = temp_ref

    val, success = _cast(ref, return_type)

    if success:
        return val

    return default_value


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

        out_map[_k] = (float(data[_k]) / 100.0) * float(d_pct[_k])

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

    for d in [";", ":", ","]:
        if d in value:
            return d

    return ";"


def convert_edition_to_shortform(edition):
    """Convert edition to shortform Enterprise or Community or N/E"""

    if (
        edition.lower() in ["enterprise", "true", "ee"]
        or "enterprise" in edition.lower()
    ):
        return "Enterprise"

    if (
        edition.lower() in ["community", "false", "ce"]
        or "community" in edition.lower()
    ):
        return "Community"

    return "N/E"


def write_to_file(file, data):
    f = open(str(file), "a")
    f.write(str(data))
    return f.close()


def is_valid_ip_port(key):
    """
    It returns True if key matches with either "IP:port" or "[ipv6]:port" format.
    """

    if not key or ":" not in key:
        return False

    key = key.strip()
    split = key.split(":")
    if "]:" in key:
        # IPv6 address
        split = key.split("]:")

    if len(split) < 2 or ("]" not in key and len(split) != 2):
        return False

    address, port = split[0], split[1]

    try:
        int(port)
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
        return address.count(".") == 3
    except socket.error:  # not a valid address
        return False

    return True


def _is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def is_str(data):

    return isinstance(data, str)


def bytes_to_str(data: Union[bytes, str]) -> str:
    if isinstance(data, str):
        return data

    return data.decode("utf-8")


def str_to_bytes(data: Union[bytes, str]) -> bytes:
    if isinstance(data, bytes):
        return data

    return str.encode(data, "utf-8")


ItemsType = TypeVar("ItemsType")


def find_most_frequent(
    list_: Iterable[ItemsType],
) -> Union[None, ItemsType]:
    count = {}
    most_freq = None

    for size in list_:
        if size not in count:
            count[size] = 1
        else:
            count[size] += 1

    max_count = 0

    for val, count in count.items():
        if count > max_count:
            max_count = count
            most_freq = val

    return most_freq


AwaitableType = TypeVar("AwaitableType")
AwaitableReturnType = TypeVar("AwaitableReturnType")


class async_cached(Generic[AwaitableType]):
    """
    Doesn't support lists, dicts and other unhashables
    Also doesn't support kwargs for reasons above.
    """

    class _CacheableCoroutine(Generic[AwaitableReturnType]):
        """
        Allow a coroutine to be awaited multipul times. The lock makes sure multiple
        methods do not call await on the coroutine.
        """

        result: AwaitableReturnType

        def __init__(self, co: Awaitable[AwaitableReturnType]):
            self._co = co
            self._done = False
            self._lock = asyncio.Lock()
            self._raised = False

        def __await__(self) -> Generator[Any, None, AwaitableReturnType]:
            yield from self._lock.acquire().__await__()
            try:
                if not self._done:
                    self.result = yield from self._co.__await__()
                    self._done = True
                    return self.result
                elif isinstance(self.result, Exception):
                    raise self.result
                else:
                    return self.result
            except Exception as e:
                self.result = e  # redundant in the case of re-raising the exception
                self._done = True
                self._raised = True
                raise
            finally:
                self._lock.release()

        def raised(self) -> bool:
            return self._raised

    def __init__(self, func: Callable[..., Awaitable[AwaitableType]], ttl=0.5):
        self.func = func
        self.ttl = ttl
        self.cache = {}

    def __setitem__(self, key, value: _CacheableCoroutine):
        self.cache[key] = (value, time() + self.ttl)

    def __getitem__(self, key) -> Awaitable[AwaitableType]:
        if key in self.cache:
            # This effectively clear the key if the coroutine raises an exception.
            if not self.cache[key][0].raised():
                value, eol = self.cache[key]
                if eol > time():
                    logger.debug("return cached %s: %s", key[1:], value)
                    return value

        self[key] = self._CacheableCoroutine(self.func(*key))
        return self.cache[key][0]

    def __call__(self, *args, **kwargs):
        if "disable_cache" in kwargs and kwargs["disable_cache"]:
            return self.func(*args)
        return self[args]
