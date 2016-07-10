# Copyright 2013-2016 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re
import itertools
import threading
from time import time
import subprocess
import pipes
import sys, StringIO

def info_to_dict(value, delimiter = ';'):
    """
    Simple function to convert string to dict
    """

    stat_dict = {}
    stat_param = itertools.imap(lambda sp: info_to_tuple(sp, "="),
                                info_to_list(value, delimiter))
    for g in itertools.groupby(stat_param, lambda x: x[0]):
        try:
            value = map(lambda v: v[1], g[1])
            value = ",".join(sorted(value)) if len(value) > 1 else value[0]
            stat_dict[g[0]] = value
        except Exception:
            # NOTE: 3.0 had a bug in stats at least prior to 3.0.44. This will
            # ignore that bug.

            # Not sure if this bug is fixed or not.. removing this try/catch
            # results in things not working. TODO: investigate.
            pass
    return stat_dict

def info_to_dict_multi_level(value, keyname, delimiter1 = ';', delimiter2 = ':'):
    """
    Simple function to convert string to dict where string is format like
    field1_section1=value1<delimiter2>field2_section1=value2<delimiter2>... <delimiter1> field1_section2=value3<delimiter2>field2_section2=value4<delimiter2>...
    """
    value_list = info_to_list(value, delimiter1)
    value_dict = {}
    for v in value_list:
        values = info_to_dict(v, delimiter2)
        if not values or isinstance(values,Exception) or keyname not in values.keys():
            continue
        value_dict[values[keyname]] = values
    return value_dict

def info_colon_to_dict(value):
    """
    Simple function to convert colon separated string to dict
    """
    return info_to_dict(value, ':')

def info_to_list(value, delimiter = ";"):
    return re.split(delimiter, value)

def info_to_tuple(value, delimiter = ":"):
    return tuple(info_to_list(value, delimiter))

def concurrent_map(func, data):
    """
    Similar to the builtin function map(). But spawn a thread for each argument
    and apply 'func' concurrently.

    Note: unlie map(), we cannot take an iterable argument. 'data' should be an
    indexable sequence.
    """

    N = len(data)
    result = [None] * N

    # Uncomment following line to run single threaded.
    #return [func(datum) for datum in data]

    #wrapper to dispose the result in the right slot
    def task_wrapper(i):
        result[i] = func(data[i])

    threads = [threading.Thread(target=task_wrapper, args=(i,)) for i in xrange(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return result

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

class cached(object):
    # Doesn't support lists, dicts and other unhashables
    # Also doesn't support kwargs for reason above.

    def __init__(self, func, ttl=0.5):
        self.func = func
        self.ttl = ttl
        self.cache = {}

    def __setitem__(self, key, value):
        self.cache[key] = (value, time() + self.ttl)

    def __getitem__(self, key):
        if key in self.cache:
            value, eol = self.cache[key]
            if eol > time():
                return value

        self[key] = self.func(*key)
        return self.cache[key][0]

    def __call__(self, *args):
        return self[args]

def shell_command(command):
    """
    command is a list of ['cmd','arg1','arg2',...]
    """

    command = pipes.quote(" ".join(command))
    command = ['sh', '-c', "'%s'"%(command)]
    try:
        p = subprocess.Popen(command
                             , stdout=subprocess.PIPE
                             , stderr=subprocess.PIPE)

        out, err = p.communicate()
    except Exception as e:
        return '', 'error'
    else:
        return out, err

    # Redirecting the stdout to use the output elsewhere

def capture_stdout(func,line=''):
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

def compileLikes(likes):
    likes = map(re.escape, likes)
    likes = "|".join(likes)
    likes = re.compile(likes)
    return likes

def filter_list(ilist, pattern_list):
    if not ilist or not pattern_list:
        return ilist
    likes = compileLikes(pattern_list)
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
            val = line[i+1]
            return success, val
    except Exception:
        pass
    return not success, default

def fetch_line_clear_dict(line, arg, return_type, default, keys, d):
    if not line:
        return default
    try:
        success, _val = fetch_argument(line, arg, default)
        if success and keys and d:
            clear_val_from_dict(keys, d, arg)
            clear_val_from_dict(keys, d, _val)
        val = return_type(_val)
    except Exception:
        val = default
    return val

def get_arg_and_delete_from_mods(line, arg, return_type, default, modifiers, mods):
    try:
        val = fetch_line_clear_dict(line=line, arg=arg, return_type=return_type, default=default, keys=modifiers, d=mods)
    except Exception:
        val = default
    return val

def check_arg_and_delete_from_mods(line, arg, default, modifiers, mods):
    try:
        if arg in line:
            val = True
            clear_val_from_dict(modifiers, mods, arg)
        else:
            val = False
    except Exception:
        val = default
    return val

def remove_suffix(input_string, suffix):
    try:
        input_string = input_string.strip()
        if not input_string.endswith(suffix):
            return input_string
        return input_string[0: input_string.rfind(suffix)]
    except Exception:
        return input_string

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

def set_value_in_dict(d, key, value):
    if not d or not key or (not value and value!=0 and value!=False) or isinstance(value,Exception):
        return
    d[key] = value