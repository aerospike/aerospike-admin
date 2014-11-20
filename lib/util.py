# Copyright 2013-2014 Aerospike, Inc.
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
        except:
            # NOTE: 3.0 had a bug in stats at least prior to 3.0.44. This will
            # ignore that bug.

            # Not sure if this bug is fixed or not.. removing this try/catch
            # results in things not working. TODO: investigate.
            pass
    return stat_dict

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

