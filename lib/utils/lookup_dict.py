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


class LookupDict:

    LOOKUP_MODE = 0
    PREFIX_MODE = 1
    SUFFIX_MODE = 2

    def __init__(self, mode=None):
        self._kv = {}

        if mode is None:
            mode = self.LOOKUP_MODE

        self.mode = mode

    def __setitem__(self, key, value):
        return self.add(key, value)

    def __getitem__(self, key):
        return self.get(key)

    def __delitem__(self, key):
        self.remove(key)

    def __str__(self):
        return str(self._kv)

    def __len__(self):
        return len(self._kv)

    def __contains__(self, k):
        try:
            self.get_key(k)
            return True
        except Exception:
            return False

    def _filter(self, k, keys):
        return [key for key in keys if k in key]

    def _get_prefix(self, key, min_prefix_len=1):
        # There should only be one key found
        keys = self._get_key_by_filter(key, self._prefix_filter)
        if len(keys) > 1:
            raise KeyError("Unable to get prefix for an ambiguous key: '%s'" % (key))

        if min_prefix_len == 0:
            return ""

        # Filter these keys
        keys = self._kv.keys()
        key = list(key)
        prefix = ""
        while len(keys) > 1:
            prefix += key.pop(0)
            keys = self._prefix_filter(prefix, keys)

        if len(prefix) >= min_prefix_len:
            return prefix

        try:
            k = keys[0]
            if len(k) <= min_prefix_len:
                return k
            return k[:min_prefix_len]

        except Exception:
            return prefix

    def _prefix_filter(self, prefix, keys):
        return [key for key in keys if key.startswith(prefix)]

    def _get_suffix(self, key, min_suffix_len=1):
        # There should only be one key found
        keys = self._get_key_by_filter(key, self._suffix_filter)
        if len(keys) > 1:
            raise KeyError("Unable to get suffix for an ambiguous key: '%s'" % (key))

        if min_suffix_len == 0:
            return ""

        # Filter these keys
        keys = self._kv.keys()
        key = list(key)
        suffix = ""
        while len(keys) > 1:
            suffix = key.pop() + suffix
            keys = self._suffix_filter(suffix, keys)

        if len(suffix) >= min_suffix_len:
            return suffix

        try:
            k = keys[0]
            if len(k) <= min_suffix_len:
                return k
            return k[len(k) - min_suffix_len :]

        except Exception:
            return suffix

    def _suffix_filter(self, suffix, keys):
        return [key for key in keys if key.endswith(suffix)]

    def _get_key_by_filter(self, k, f):
        keys = f(k, self.keys())
        if len(keys) == 0:
            raise KeyError("Unable to find keys with '%s'" % (k))
        return keys

    def add(self, key, data):
        self._kv[key] = data

    def get_key(self, k):
        if self.mode == self.PREFIX_MODE:
            return self._get_key_by_filter(k, self._prefix_filter)

        if self.mode == self.SUFFIX_MODE:
            return self._get_key_by_filter(k, self._suffix_filter)

        return self._get_key_by_filter(k, self._filter)

    def keys(self):
        return list(self._kv.keys())

    def get(self, k):
        keys = self.get_key(k)
        return [self._kv[key] for key in keys]

    def remove(self, k):
        keys = self.get_key(k)

        if len(keys) > 1:
            raise KeyError("Prefix may not be ambiguous for removal: %s" % (k))

        value = self._kv[keys[0]]
        del self._kv[keys[0]]

        return value

    def get_shortname(self, key, min_prefix_len=1, min_suffix_len=1):
        if self.mode == self.PREFIX_MODE:
            return self._get_prefix(key, min_prefix_len=min_prefix_len)

        if self.mode == self.SUFFIX_MODE:
            return self._get_suffix(key, min_suffix_len=min_suffix_len)

        # There should only be one key found
        keys = self.get_key(key)
        if len(keys) > 1:
            raise KeyError("Unable to get shortname for an ambiguous key: '%s'" % (key))

        if min_prefix_len + min_suffix_len >= len(key):
            return key

        short_format = "%s...%s"

        p = self._get_prefix(key, min_prefix_len=min_prefix_len)
        s = self._get_suffix(key, min_suffix_len=min_suffix_len)
        shortname = short_format % (p, s)

        if len(shortname) >= len(key):
            return key

        return shortname


class PrefixDict(LookupDict):
    def __init__(self):
        super(PrefixDict, self).__init__(self.PREFIX_MODE)

    def get_prefix(self, key):
        return self.get_shortname(key)
