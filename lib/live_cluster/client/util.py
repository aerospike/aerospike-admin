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

import re
import sys
import logging

from . import section_filter_list

# Assumption - Always a valid number is passed to convert to integer/float

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)

FILTER_LIST = section_filter_list.FILTER_LIST
DERIVED_SECTION_LIST = section_filter_list.DERIVED_SECTION_LIST


def change_key_name_in_map(datamap, old_keys, new_key):
    for key in old_keys:
        if key in datamap:
            datamap[new_key] = datamap[key]
            datamap.pop(key, None)


def type_check_raw_all(nodes, section_name, parsed_map):
    for node in nodes:
        if section_name in parsed_map[node]:
            _type_check_field_and_raw_values(parsed_map[node][section_name])


# This should check only raw values.
# Aerospike doesn't send float values
# pretty print and other cpu stats can send float
# This will skip list if its first item is not a dict.


def type_check_basic_values(section):
    malformedkeys = []
    # ip_regex = "[0-9]{1,2,3}(\.[0-9]{1,2,3})*"
    for key in section:
        if isinstance(section[key], dict):
            type_check_basic_values(section[key])

        elif (
            isinstance(section[key], list)
            and len(section[key]) > 0
            and isinstance(section[key][0], dict)
        ):
            for item in section[key]:
                type_check_basic_values(item)

        else:
            if "." in key or " " in key:
                malformedkeys.append(key)
            if (
                isinstance(section[key], list)
                or isinstance(section[key], int)
                or isinstance(section[key], bool)
                or isinstance(section[key], float)
            ):
                continue
            elif section[key] is None:
                logger.debug("Value for key " + key + " is Null")
                continue
            elif section[key] == "N/E" or section[key] == "n/e":
                logger.debug("'N/E' for the field.")
                section[key] = None
                continue

            # Handle float of format (a.b), only 1 dot would be there.
            if section[key].replace(".", "", 1).isdigit():
                section[key] = _str_to_number(section[key])

            # Handle bool
            elif is_bool(section[key]):
                section[key] = _str_to_boolean(section[key])

            # Handle negative format (-ab,c,f)
            elif section[key].lstrip("-").isdigit():
                num = section[key].lstrip("-")
                if num.isdigit():
                    number = _str_to_number(num)
                    section[key] = -1 * number

    for key in malformedkeys:
        newkey = key.replace(".", "_").replace(" ", "_")
        val = section[key]
        section.pop(key, None)
        section[newkey] = val


def get_section_name_from_id(sec_id):
    raw_section_name = FILTER_LIST[sec_id]["raw_section_name"]
    final_section_name = (
        FILTER_LIST[sec_id]["final_section_name"]
        if "final_section_name" in FILTER_LIST[sec_id]
        else ""
    )
    parent_section_name = (
        FILTER_LIST[sec_id]["parent_section_name"]
        if "parent_section_name" in FILTER_LIST[sec_id]
        else ""
    )
    return raw_section_name, final_section_name, parent_section_name


def is_collision_allowed_for_section(sec_id):
    if "collision_allowed" not in FILTER_LIST[sec_id]:
        return False

    if FILTER_LIST[sec_id]["collision_allowed"] == True:
        return True

    return False


def is_valid_section(
    imap, raw_section_name, final_section_name, collision_allowed=False
):
    if not imap:
        logger.warning("Null section json")
        return False

    if raw_section_name not in imap:
        logger.warning(raw_section_name + " section not present.")
        return False

    if len(imap[raw_section_name]) > 1 and not collision_allowed:
        logger.warning(
            "More than one entries detected, There is a collision for this section: "
            + final_section_name
        )
        return False
    return True


def is_bool(val):
    return val.lower() in ["true", "false", "yes", "no"]


def _str_to_number(number):
    try:
        return int(number)
    except ValueError:
        try:
            return float(number)
        except ValueError:
            return number


# Bool is represented as 'true' or 'false'
def _str_to_boolean(val):
    if not is_bool(val):
        logger.warning(
            "string passed for boolean conversion must be a boolean string true/false/yes/no"
        )
        return
    if val.lower() in ["true", "yes"]:
        return True
    elif val.lower() in ["false", "no"]:
        return False


# Aerospike doesn't send float values
# pretty print and other cpu stats can send float


def _type_check_field_and_raw_values(section):
    keys = []
    # ip_regex = "[0-9]{1,2,3}(\.[0-9]{1,2,3})*"
    for key in section:
        if isinstance(section[key], dict):
            _type_check_field_and_raw_values(section[key])
        elif (
            isinstance(section[key], list)
            and len(section[key]) > 0
            and isinstance(section[key][0], dict)
        ):
            for item in section[key]:
                _type_check_field_and_raw_values(item)

        else:
            if (
                isinstance(section[key], list)
                or isinstance(section[key], int)
                or isinstance(section[key], bool)
                or isinstance(section[key], float)
            ):
                continue

            if section[key] is None:
                logger.debug("Value for key " + key + " is Null")
                continue
            # Some numbers have a.b.c.d* format, which matches with IP address
            # So do a defensive check at starting.
            # All type of address stats and config should be string so continue
            # mesh-adderss, service-address.
            if "addr" in key:
                continue

            # 3.9 config have ns name in some of the field names. {ns_name}-field_name
            # Thease fields are already under ns section, so no need to put ns_name again.
            # Remove ns name and put only filed name.
            if re.match(r"\{.*\}-.*", key):
                section[key.split("}-")[1]] = section.pop(key)

            # Handle format like (a,b,c) this is a valid number
            elif section[key].replace(",", "").isdigit():
                number = _str_to_number(section[key].replace(",", ""))
                if number < sys.maxsize:
                    section[key] = number
                else:
                    keys.append(key)

            # Handle format (a.b.cd.s), its valid number.
            elif section[key].replace(".", "").isdigit():
                number = _str_to_number(section[key].replace(".", ""))
                if number < sys.maxsize:
                    section[key] = number
                else:
                    keys.append(key)

            # Handle bool
            elif is_bool(section[key]):
                section[key] = _str_to_boolean(section[key])

            # Handle format (-ab,c,f)
            elif section[key].lstrip("-").replace(",", "").isdigit():
                num = section[key].lstrip("-").replace(",", "")
                if num.isdigit():
                    number = _str_to_number(num)
                    section[key] = -1 * number

    for key in keys:
        section.pop(key, None)
