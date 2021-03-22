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

import copy

from lib.utils import util

from . import constants


def deep_merge_dicts(dict_to, dict_from):
    """
    Function takes dictionaries to merge

    Merge dict_from to dict_to and returns dict_to
    """

    if not dict_to and not dict_from:
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


def merge_dicts_with_new_tuple_keys(
    dict_from, main_dict, new_tuple_keys, forced_all_new_keys=True
):
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

    poped_nks, key_level_separator_found = pop_tuple_keys_for_next_level(new_tuple_keys)

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

                    if not name or isinstance(name, list) or isinstance(name, dict):
                        # _key is the name for type
                        _k = (_key, type)

                    elif isinstance(name, tuple):
                        # name of key to fetch is present
                        _k = (
                            util.get_value_from_dict(dict_from[_key], name, _key),
                            type,
                        )

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
            merge_dicts_with_new_tuple_keys(
                dict_from[_key],
                temp_dict[_k],
                new_tuple_keys,
                forced_all_new_keys=forced_all_new_keys,
            )

    # Need to push back all poped tuple keys, as same should go to other
    # siblings
    if key_level_separator_found:
        new_tuple_keys.insert(0, (None, None))

    while poped_nks:
        new_tuple_keys.insert(0, poped_nks.pop())

    return


def create_health_input_dict(
    dict_from,
    main_dict,
    new_tuple_keys,
    new_component_keys=None,
    forced_all_new_keys=True,
):
    """
    Function takes dictionary of new values, main dictionary, new tuple keys to create, extra components keys to add

    Merge dict_from to main_dict with extra component keys and new tuple keys and returns main_dict
    """

    if main_dict is None:
        main_dict = {}

    if not dict_from:
        return main_dict

    main_dict_ptr = add_component_keys(main_dict, new_component_keys)
    merge_dicts_with_new_tuple_keys(
        dict_from, main_dict_ptr, new_tuple_keys, forced_all_new_keys
    )

    return main_dict


def h_eval(data):
    """
    Function takes dictionary

    Evaluate values and convert string to correct type (boolean/int/float/long/string)
    """
    if isinstance(data, dict):
        for _k in list(data.keys()):
            data[_k] = h_eval(data[_k])
            if data[_k] is None or (isinstance(data[_k], dict) and not data[_k]):
                data.pop(_k)
        return data

    if isinstance(data, list) or isinstance(data, tuple) or isinstance(data, set):
        res = []
        for _k in data:
            res.append(h_eval(_k))

        if isinstance(data, tuple):
            return tuple(res)

        if isinstance(data, set):
            return set(res)

        return res

    try:
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
                return float(data)
            except Exception:
                pass

        return data
    except Exception:
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
                print(s)
                print_dict(data[_k], padding + "  ")
            else:
                print("%s : %s" % (s, str(data[_k])))
    else:
        print("%s%s" % (padding, str(data)))


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


def _remove_duplicates_from_saved_value_list(v_list):
    """
    Remove items with duplicate keys and create single tuple entry with last possible value for key in list.

    """

    if not v_list:
        return v_list

    tmp_dict = {}
    for i in v_list:
        tmp_dict[i[0]] = (i[1], i[2])

    res_list = []
    for i in v_list:
        t = (i[0], tmp_dict[i[0]][0], tmp_dict[i[0]][1])
        if t not in res_list:
            res_list.append(t)

    return res_list


def _extract_saved_value_list_from_value_vector(v):
    val_to_save = []

    for i in v:
        try:
            _k, _v = get_kv(i)

            if _v[1]:
                val_to_save += _v[1]

        except Exception:
            # Not expected Input format (list of kv map)
            pass

    return val_to_save


def create_value_list_to_save(
    save_param=None, key=" ", value=None, op1=None, op2=None, formatting=True
):
    """
    Merge saved value lists of operand/s.

    """

    value_list = []

    if op1:
        if isinstance(op1, list):
            value_list += _extract_saved_value_list_from_value_vector(op1)
        else:
            value_list += op1[1]

    if op2:
        if isinstance(op2, list):
            value_list += _extract_saved_value_list_from_value_vector(op2)
        else:
            value_list += op2[1]

    if save_param is None:
        # Not saving value (result)
        return _remove_duplicates_from_saved_value_list(value_list)

    if save_param == "":
        # Saving value (result) with key
        value_list.append((key, value, formatting))

    else:
        # Saving value (result) with save_param as key
        value_list.append((save_param, value, formatting))

    return _remove_duplicates_from_saved_value_list(value_list)


def create_snapshot_key(id, snapshot_prefix="SNAPSHOT"):
    id = str(id)
    if len(id) > 2:
        return snapshot_prefix + id

    if len(id) == 2:
        return snapshot_prefix + "0" + id

    if len(id) == 1:
        return snapshot_prefix + "00" + id

    return None


def create_health_internal_tuple(val, saved_value_list=[]):
    return (val, saved_value_list)


def get_value_from_health_internal_tuple(t):
    if not t or not isinstance(t, tuple):
        return t

    return t[0]


def is_health_parser_variable(var):
    """

    :param var: variable to check
    :return: True/False

    """
    if not var:
        return False

    if isinstance(var, tuple) and var[0] == constants.HEALTH_PARSER_VAR:
        return True

    return False


def find_majority_element(value_list):
    if not value_list:
        return None

    m_value = value_list[0]
    tmp_dict = {}
    tmp_dict[m_value] = 1

    for i in range(1, len(value_list)):
        v = value_list[i]
        if v in tmp_dict:
            tmp_dict[v] += 1
        else:
            tmp_dict[v] = 1

        if v != m_value and tmp_dict[v] > tmp_dict[m_value]:
            m_value = v

    return m_value
