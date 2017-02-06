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

class PrefixDict(object):
    def __init__(self):
        self._kv = {}

    def add(self, key, data):
        self._kv[key] = data

    def __setitem__(self, key, value):
        return self.add(key, value)

    def getPrefix(self, key):
        # There should only be one key found
        keys = self.getKey(key)
        if len(keys) > 1:
            raise KeyError("Unable to get prefix for an ambiguous key: '%s'"%(key))

        # Filter these keys
        keys = self._kv.keys()
        key = list(key)
        prefix = ""
        while len(keys) > 1:
            prefix += key.pop(0)
            keys = self._prefixFilter(prefix, keys)

        return prefix

    def _prefixFilter(self, prefix, keys):
        return filter(lambda key: key.startswith(prefix), keys)

    def getKey(self, prefix):
        keys = self._prefixFilter(prefix, self._kv.keys())
        if len(keys) == 0:
            raise KeyError("Unable to find keys with prefix '%s'"%(prefix))
        return keys

    def keys(self):
        return self._kv.keys()

    def get(self, prefix):
        keys = self.getKey(prefix)
        return map(lambda key: self._kv[key], keys)

    def __contains__(self, prefix):
        try:
            self.getKey(prefix)
            return True
        except Exception:
            return False

    def remove(self, prefix):
        keys = self.getKey(prefix)

        if len(keys) > 1:
            raise KeyError("Prefix may not be ambiguous for removal: %s"%(prefix))

        value = self._kv[keys[0]]
        del self._kv[keys[0]]
        
        return value

    def __getitem__(self, prefix):
        return self.get(prefix)

    def __delitem__(self, prefix):
        self.remove(prefix)
        
    def __str__(self):
        return str(self._kv)

    def __len__(self):
        return len(self._kv)

class SuffixDict(PrefixDict):

    def getPrefix(self, key):
        # There should only be one key found
        keys = self.getKey(key)
        if len(keys) > 1:
            raise KeyError("Unable to get prefix for an ambiguous key: '%s'"%(key))

        # Filter these keys
        keys = self._kv.keys()
        key = list(key)
        prefix = ""
        while len(keys) > 1:
            prefix = key.pop() + prefix
            keys = self._prefixFilter(prefix, keys)

        return prefix

    def _prefixFilter(self, prefix, keys):
        return filter(lambda key: key.endswith(prefix), keys)            

