# Copyright 2013-2025 Aerospike, Inc.
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
    (1024.0**5, " PiB"),
    (1024.0**4, " TiB"),
    (1024.0**3, " GiB"),
    (1024.0**2, " MiB"),
    (1024.0**1, " KiB"),
    (1024.0**0, " B  "),
]

si = [
    (1000**5, " P"),
    (1000**4, " T"),
    (1000**3, " G"),
    (1000**2, " M"),
    (1000**1, " K"),
    (1000**0, "  "),
]

si_float = [
    (1000.0**5, " P"),
    (1000.0**4, " T"),
    (1000.0**3, " G"),
    (1000.0**2, " M"),
    (1000.0**1, " K"),
    (1000.0**0, "  "),
]

time = [
    ((60.0**2) * 24, " days"),
    (60.0**2, " hrs "),
    (60.0**1, " mins"),
    (60.0**0, " secs"),
]

legacy_byte_suffixes = (" PB", " TB", " GB", " MB", " KB", " B ")

systems = (byte, si, si_float, time)


def size(bytes, system=byte):
    """
    Human-readable file size.
    """
    for factor, suffix in system:
        if bytes >= factor:
            break
    amount = bytes / factor
    if type(amount) == float:
        return "%0.3f%s" % (amount, suffix)
    else:
        return str(amount) + suffix


def is_file_size(value):
    try:
        float(str(value))
        return True
    except ValueError:
        pass  # continue

    suffixes = [suffix for system in systems for _, suffix in system]
    suffixes.extend(legacy_byte_suffixes)

    for suffix in suffixes:
        try:
            float(str(value).replace(suffix, ""))
            return True
        except ValueError:
            continue

    return False
