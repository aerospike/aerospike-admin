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

from lib.health.exceptions import HealthException
from lib.utils.util import get_value_from_dict


def deep_merge_dicts(dict_to, dict_from):
    """
    Function takes dictionaries to merge

    Merge dict_from to dict_to and returns dict_to
    """

    if (not dict_to and not dict_from):
        return dict_to

    if not dict_to:
        return dict_from

    if not isinstance(dict_to, dict):
        return dict_to

    if not dict_from or not isinstance(dict_from, dict):
        # either dict_from is None/empty or is last value whose key matched
        # already, so no need to add
        return dict_to

    for _key in dict_from.keys():
        if _key not in dict_to:
            dict_to[_key] = dict_from[_key]
        else:
            dict_to[_key] = deep_merge_dicts(dict_to[_key], dict_from[_key])

    return dict_to


def fetch_keys_from_dict(data={}, keys=[], from_keys=[]):
    """
    Function takes dictionary, list of keys to fetch, list of from_keys to filter scope

    Returns dictionary of selected keys and values
    """

    if not data or not isinstance(data, dict):
        raise HealthException("Wrong Input Data for select operation.")

    result_dict = {}
    if not keys:
        raise HealthException("No key provided for select operation.")

    for _key in data:
        if from_keys:
            f_key = from_keys[0]
            if isinstance(_key, tuple):
                # from_keys work with static component keys only, if we get
                                # tuple keys means we have done with checking of all component
                                # keys and not found any from key match so no need to check
                                # further in this direction
                break

            if (f_key == "ALL") or (_key == f_key):
                # from_key is ALL or matching with _key
                child_res = fetch_keys_from_dict(data[_key], keys=keys,
                                                 from_keys=from_keys[1:] if len(from_keys) > 1 else [])

            else:
                # no key match, need to check further
                child_res = fetch_keys_from_dict(data[_key], keys=keys,
                                                 from_keys=from_keys)

            if child_res:
                if f_key == "ALL":
                    # It assumes ALL is only for top snapshot level
                    result_dict[(_key, "SNAPSHOT")] = copy.deepcopy(child_res)
                else:
                    result_dict = deep_merge_dicts(
                        result_dict, copy.deepcopy(child_res))

        else:
            if (False, "*", None) in keys and isinstance(_key, tuple):
                result_dict[_key] = copy.deepcopy(data[_key])
            elif isinstance(_key, tuple) and _key[1] == "KEY":
                for check_substring, s_key, new_name in keys:
                    if ((check_substring and re.search(s_key, _key[0]))
                            or (not check_substring and _key[0] == s_key)):
                        if new_name:
                            result_dict[(new_name, "KEY")] = data[_key]
                        else:
                            result_dict[_key] = data[_key]
                        break

            elif data[_key] and isinstance(data[_key], dict):
                child_res = fetch_keys_from_dict(data[_key], keys=keys)
                if child_res:
                    if isinstance(_key, tuple):
                        result_dict[_key] = copy.deepcopy(child_res)
                    else:
                        result_dict = deep_merge_dicts(result_dict,
                                                       copy.deepcopy(child_res))

    return result_dict


def add_component_keys(data, component_key_list):
    if not component_key_list:
        return data

    if data is None:
        data = {}

    if not isinstance(data, dict):
        return data

    temp_dict = data

    for _key in component_key_list:
        if _key not in temp_dict:
            temp_dict[_key] = {}
        temp_dict = temp_dict[_key]

    return temp_dict


def pop_tuple_keys_for_next_level(tuple_key_list):
    """
    Function takes list of tuple keys (TYPE, NAME)

    Returns list of selected tuple keys

    """

    poped_nks = []
    key_level_separator_found = False

    if not tuple_key_list:
        return poped_nks, key_level_separator_found

    while True:
        # Finding tuple keys till (None, None) is found.
        # Multiple tuple keys can be possible for same level, Ex. for set we
        # need to add namespace and set
        try:
            key = tuple_key_list.pop(0)
            if key[0] is None:
                # No component info means this is just separator between
                # different level keys
                key_level_separator_found = True
                break

            poped_nks.append(key)
        except Exception:
            break

    return poped_nks, key_level_separator_found


def merge_dicts_with_new_tuple_keys(dict_from, main_dict, new_tuple_keys,
                                    forced_all_new_keys=True):
    if not dict_from and dict_from != 0:
        return

    if main_dict is None:
        main_dict = {}

    if not isinstance(main_dict, dict):
        return

    if not isinstance(dict_from, dict):
        if isinstance(main_dict, dict) and not main_dict:
            main_dict = copy.deepcopy(dict_from)
        return

    poped_nks, key_level_separator_found = pop_tuple_keys_for_next_level(
        new_tuple_keys)

    for _key in dict_from.keys():
        temp_dict = main_dict
        last_level = False

        if isinstance(dict_from[_key], dict):
            _k = _key
        else:
            # last _key:value, need to create tuple (_key, "KEY")
            _k = (_key, "KEY")
            last_level = True

        if poped_nks and (not last_level or forced_all_new_keys):
            for i, k in enumerate(poped_nks):
                type = k[0]
                name = k[1]

                if type:
                    # This is valid tuple key requirement, as type is
                    # available.

                    if (not name or isinstance(name, list)
                            or isinstance(name, dict)):
                        # _key is the name for type
                        _k = (_key, type)

                    elif isinstance(name, tuple):
                        # name of key to fetch is present
                        _k = (get_value_from_dict(dict_from[_key], name, _key),
                              type)

                    else:
                        # static name provided
                        _k = (name, type)

                if _k not in temp_dict:
                    temp_dict[_k] = {}

                if i < len(poped_nks) - 1:
                    # added all keys till this path
                    temp_dict = temp_dict[_k]
        else:
            if _k not in temp_dict:
                temp_dict[_k] = {}

        if last_level:
            temp_dict[_k] = copy.deepcopy(dict_from[_key])
        else:
            merge_dicts_with_new_tuple_keys(dict_from[_key], temp_dict[_k],
                                            new_tuple_keys, forced_all_new_keys=forced_all_new_keys)

    # Need to push back all poped tuple keys, as same should go to other
    # siblings
    if key_level_separator_found:
        new_tuple_keys.insert(0, (None, None))

    while poped_nks:
        new_tuple_keys.insert(0, poped_nks.pop())

    return


def create_health_input_dict(dict_from, main_dict, new_tuple_keys,
                             new_component_keys=None, forced_all_new_keys=True):
    """
    Function takes dictionary of new values, main dictionary, new tuple keys to create, extra components keys to add

    Merge dict_from to main_dict with extra component keys and new tuple keys and returns main_dict
    """

    if main_dict is None:
        main_dict = {}

    if not dict_from:
        return main_dict

    main_dict_ptr = add_component_keys(main_dict, new_component_keys)
    merge_dicts_with_new_tuple_keys(dict_from, main_dict_ptr, new_tuple_keys,
                                    forced_all_new_keys)

    return main_dict


def h_eval(data):
    """
    Function takes dictionary

    Evaluate values and convert string to correct type (boolean/int/float/long/string)
    """
    if isinstance(data, dict):
        for _k in data.keys():
            data[_k] = h_eval(data[_k])
            if data[_k] is None or (isinstance(data[_k], dict) and not data[_k]):
                data.pop(_k)
        return data
    else:
        try:
            if isinstance(data, unicode):
                data = str(data)

            if isinstance(data, str):
                if data.endswith("%"):
                    data = data[:-1]

                if data.lower() == "false":
                    return False

                if data.lower() == "true":
                    return True

                if data.lower() == "n/e":
                    return None

                try:
                    return int(data)
                except Exception:
                    pass

                try:
                    return long(data)
                except Exception:
                    pass

                try:
                    return float(data)
                except Exception:
                    pass

            return data
        except:
            return data


def print_dict(data, padding=" "):
    if data is None:
        return

    if isinstance(data, dict):
        if not data:
            return

        for _k in data:
            s = "%s%s" % (padding, str(_k))
            if isinstance(data[_k], dict):
                print s
                print_dict(data[_k], padding + "  ")
            else:
                print "%s : %s" % (s, str(data[_k]))
    else:
        print "%s%s" % (padding, str(data))


def merge_key(key, _key, recurse=False):
    """
    Return key as is if not to be merged

    Merge only the non tag part [0]
    """

    if not recurse:
        return _key

    if len(key) > 0:
        return str(key) + "/" + str(_key[0])

    return _key[0]


def make_map(key, value):
    return {(key, "KEY"): value}


def get_kv(data):
    v = list(data.values())[0]
    k = list(data)[0][0]
    return k, v


def make_key(key):
    return (key, "KEY")


def create_snapshot_key(id, snapshot_prefix="SNAPSHOT"):
    id = str(id)
    if len(id) > 2:
        return snapshot_prefix + id

    if len(id) == 2:
        return snapshot_prefix + "0" + id

    if len(id) == 1:
        return snapshot_prefix + "00" + id

    return None
