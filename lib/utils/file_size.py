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

byte = [
    (1024.0 ** 5, " PB"),
    (1024.0 ** 4, " TB"),
    (1024.0 ** 3, " GB"),
    (1024.0 ** 2, " MB"),
    (1024.0 ** 1, " KB"),
    (1024.0 ** 0, " B "),
]

byte_verbose = [
    (1024 ** 5, (" petabyte ", " petabytes")),
    (1024 ** 4, (" terabyte ", " terabytes")),
    (1024 ** 3, (" gigabyte ", " gigabytes")),
    (1024 ** 2, (" megabyte ", " megabytes")),
    (1024 ** 1, (" kilobyte ", " kilobytes")),
    (1024 ** 0, (" byte     ", " bytes    ")),
]

si = [
    (1000 ** 5, " P"),
    (1000 ** 4, " T"),
    (1000 ** 3, " G"),
    (1000 ** 2, " M"),
    (1000 ** 1, " K"),
    (1000 ** 0, "  "),
]

si_float = [
    (1000.0 ** 5, " P"),
    (1000.0 ** 4, " T"),
    (1000.0 ** 3, " G"),
    (1000.0 ** 2, " M"),
    (1000.0 ** 1, " K"),
    (1000.0 ** 0, "  "),
]

time = [
    ((60.0 ** 2) * 24, " days"),
    (60.0 ** 2, " hrs "),
    (60.0 ** 1, " mins"),
    (60.0 ** 0, " secs"),
]

systems = (byte, byte_verbose, si, si_float, time)


def size(bytes, system=byte):
    """
    Human-readable file size.
    """
    for factor, suffix in system:
        if bytes >= factor:
            break
    amount = bytes / factor
    if isinstance(suffix, tuple):
        singular, multiple = suffix
        if amount == 1:
            suffix = singular
        else:
            suffix = multiple
    if type(amount) == float:
        return "%0.3f%s" % (amount, suffix)
    else:
        return str(amount) + suffix


def is_file_size(value):
    global systems
    try:
        float(str(value))
        return True
    except ValueError:
        pass  # continue

    def isnumeric_helper(suffix):
        tmp_value = value.replace(suffix, "")
        tmp_value.strip()
        try:
            float(tmp_value)
            return True
        except ValueError:
            return False

    for system in systems:
        for factor, suffix in system:
            if type(suffix) is str:
                if isnumeric_helper(suffix):
                    return True
            else:
                for name in suffix:
                    if isnumeric_helper(name):
                        return True
    return False
