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

import os

DATE_SEG = 0
DATE_SEPARATOR = "-"
TIME_SEG = 1
TIME_SEPARATOR = ":"


def check_time(val, date_string, segment, index=""):
    try:
        if segment == DATE_SEG:
            if val.__contains__("-"):
                for v in range(int(val.split("-")[0]), int(val.split("-")[1]) + 1):
                    if (
                        int(
                            date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[
                                index
                            ]
                        )
                        == v
                    ):
                        return True

            elif val.__contains__(","):
                for v in val.split(","):
                    if int(
                        date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[index]
                    ) == int(v):
                        return True

            else:
                if int(
                    date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[index]
                ) == int(val):
                    return True
        elif segment == TIME_SEG:
            if val.__contains__("-"):
                for v in range(int(val.split("-")[0]), int(val.split("-")[1]) + 1):
                    if (
                        int(
                            date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[
                                index
                            ]
                        )
                        == v
                    ):
                        return True

            elif val.__contains__(","):
                for v in val.split(","):
                    if int(
                        date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[index]
                    ) == int(v):
                        return True

            else:
                if int(
                    date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[index]
                ) == int(val):
                    return True
    except Exception:
        pass

    return False


def get_dirs(path=""):
    try:
        return [
            name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))
        ]
    except Exception:
        return []


def get_all_files(dir_path=""):
    fname_list = []
    if not dir_path:
        return fname_list
    try:
        for root, sub_dir, files in os.walk(dir_path):
            for fname in files:
                fname_list.append(os.path.join(root, fname))
    except Exception:
        pass

    return fname_list


def intersect_list(a, b):
    return list(set(a) & set(b))


def fetch_value_from_dic(hash, keys):
    if not hash or not keys:
        return "N/E"
    temp_hash = hash
    for key in keys:
        if key in temp_hash:
            temp_hash = temp_hash[key]
        else:
            return "N/E"
    return temp_hash
