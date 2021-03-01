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

import json
import re


def parse_record(parent_field, record):
    field_names = []
    field_values = []
    for name in record:
        if isinstance(record[name], dict):
            new_parent_field = parent_field.copy()
            new_parent_field.append(name)
            names = " ".join(new_parent_field)
            if "converted" in record[name]:
                field_names.append(names)
                field_values.append(record[name]["converted"])
            elif "raw" in record[name]:
                field_names.append(names)
                field_values.append(record[name]["raw"])
            else:
                # Must have subgroups:
                sub_names, sub_values = parse_record(new_parent_field, record[name])
                field_names.extend(sub_names)
                field_values.extend(sub_values)
        else:
            raise Exception("Unhandled parsing")

    return field_names, field_values


def parse_output(actual_out={}, horizontal=False, header_len=2, merge_header=True):
    """
        commmon parser for all show commands will return tuple of following
        @param heading : first line of output
        @param header: Second line of output
        @param params: list of parameters 
    
    """
    title = actual_out["title"]
    description = actual_out.get("description", "")
    data_names = {}
    data_values = []
    num_records = 0

    for group in actual_out["groups"]:
        for record in group["records"]:
            temp_names, temp_values = parse_record([], record)

            # We assume every record has the same set of names
            if len(data_names) == 0:
                data_names = temp_names

            data_values.append(temp_values)
            num_records += 1

    return title, description, data_names, data_values, num_records


def get_separate_output(in_str=""):
    _regex = re.compile(r"((?<=^{).*?(?=^}))", re.MULTILINE | re.DOTALL)
    out = re.findall(_regex, in_str)
    ls = []
    for item in out:
        item = remove_escape_sequence(item)
        item = "{" + item + "}"
        ls.append(json.loads(item))

    return ls


def get_merged_header(*lines):
    h = [[_f for _f in _h.split(" ") if _f] for _h in lines]
    header = []
    if len(h) == 0 or any(len(h[i]) != len(h[i + 1]) for i in range(len(h) - 1)):
        return header
    for idx in range(len(h[0])):
        header_i = h[0][idx]
        for jdx in range(len(h) - 1):
            if h[jdx + 1][idx] == ".":
                break
            header_i += " " + h[jdx + 1][idx]
        header.append(header_i)
    return header


def check_for_subset(actual_list, expected_sub_list):
    if not expected_sub_list:
        return True
    if not actual_list:
        return False
    for i in expected_sub_list:
        if isinstance(i, tuple):
            found = False
            for s_i in i:
                if s_i is None:
                    found = True
                    break
                if s_i in actual_list:
                    found = True
                    break
            if not found:
                print(i, actual_list)
                return False
        else:
            if i not in actual_list:
                print(i)
                return False
    return True


# Checks that a single expected list has a subset equal to actual_list.
def check_for_subset_in_list_of_lists(actual_list, list_of_expected_sub_lists):
    for expected_list in list_of_expected_sub_lists:
        if check_for_subset(actual_list, expected_list):
            return True
    return False


def remove_escape_sequence(line):
    ansi_escape = re.compile(r"(\x9b|\x1b\[)[0-?]*[ -\/]*[@-~]")
    return ansi_escape.sub("", line)


def check_for_types(actual_lists, expected_types):
    def is_float(x):
        try:
            val = float(x)
            if "." in x:
                return True
            return False
        except ValueError:
            return False

    def is_int(x):
        try:
            val = int(x)
            if "." in x:
                return False
            return True
        except ValueError:
            return False

    def is_bool(x):
        if x in ("True", "true", "False", "false"):
            return True
        return False

    def check_list_against_types(a_list):
        if a_list is None or expected_types is None:
            return False
        if len(a_list) == len(expected_types):
            for idx in range(len(a_list)):
                typ = expected_types[idx]
                val = a_list[idx]
                if typ == int:
                    if not is_int(val):
                        return False
                elif typ == float:
                    if not is_float(val):
                        return False
                elif typ == bool:
                    if not is_bool(val):
                        return False
                elif typ == str:
                    if any([is_bool(val), is_int(val), is_float(val)]):
                        return False
                else:
                    raise Exception("Type is not yet handles in test_util.py", typ)

            return True
        return False

    for actual_list in actual_lists:
        if check_list_against_types(actual_list) == False:
            return False
    return True
