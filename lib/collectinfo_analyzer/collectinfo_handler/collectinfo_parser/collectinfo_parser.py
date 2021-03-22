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
import json
import re
import logging

from . import section_filter_list

SECTION_DELIMITER = "ASCOLLECTINFO"
MIN_MATCH_COUNT = 2
COLLECTINFO_START_LINE_MAX = 4
SECTION_DETECTION_LINE_MAX = 2
MIN_LINES_IN_SECTION_JSON = 3

FILTER_LIST = section_filter_list.FILTER_LIST
SKIP_LIST = section_filter_list.SKIP_LIST

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


def extract_validate_filter_section_from_file(cinfo_path, imap, ignore_exception):
    """
    Parse the collectinfo and convert it into intermediate map form for
    further processing

    cinfo_path is location for collecinfo file
    imap is result intermediate map form.
    """
    logger.info("Creating section json. parse, validate, filter sections.")

    imap_old_keys = list(imap.keys())

    if "cinfo_paths" not in imap:
        imap["cinfo_paths"] = []

    imap["cinfo_paths"].append(cinfo_path)

    n_section = _parse_collectinfo_to_imap(cinfo_path, imap, ignore_exception)

    _imap_verify_section_count(imap, imap_old_keys, n_section, ignore_exception)

    _imap_remove_disabled_filter_sections(imap)


def extract_section_from_live_cmd(command, command_raw_output, imap):
    """
    Parse output of live command and convert it into intermediate map form for
    further processing

    command is system command name string to be used as key for imap
    command_raw_output is raw string form output of command. To be passed by
    the caller of the functions.
    imap is result intermediate map form.
    """

    sectionName = ""
    sectionId = "0"
    for key in FILTER_LIST:
        section = FILTER_LIST[key]
        if "final_section_name" in section and section["final_section_name"] == command:
            sectionName = section["raw_section_name"]
            sectionId = key
    if sectionName == "":
        logger.warning("Cannot find section_name for command: " + command)
        return

    imap[sectionName] = []
    outList = command_raw_output.split("\n")
    imap[sectionName].append(outList)
    imap["section_ids"] = [sectionId]


def _parse_collectinfo_to_imap(cinfo_path, imap, ignore_exception):

    logger.info("Extract sections from collectinfo file.")

    delimit = SECTION_DELIMITER
    section_list = FILTER_LIST
    skip_list = SKIP_LIST
    n_section = 0

    if not os.path.exists(cinfo_path):
        logger.warning("collectinfo doesn't exist at path: " + cinfo_path)
        return 0

    if _collectinfo_has_delimiter(cinfo_path, delimit):

        n_section = _get_collectinfo_num_sections(cinfo_path, delimit)

        _parse_new_collectinfo_to_imap(
            cinfo_path, section_list, skip_list, delimit, imap, ignore_exception
        )

    else:

        _parse_old_collectinfo_to_imap(cinfo_path, section_list, imap, ignore_exception)

    return n_section


def _imap_verify_section_count(imap, imap_old_keys, n_section, ignore_exception):
    # Validate no of section in imap
    if n_section == 0:
        return

    imap_n_section = 0
    for key in imap:
        if key == "section_ids" or key == "cinfo_paths" or key in imap_old_keys:
            continue
        imap_n_section += len(imap[key])

    logger.debug("imap_sec: " + str(imap_n_section) + "n_section: " + str(n_section))

    if imap_n_section != n_section and not ignore_exception:
        logger.error(
            "Something wrong, no of section in file and no of extracted are not matching"
        )
        logger.error(
            "imap_sec: " + str(imap_n_section) + "n_section: " + str(n_section)
        )
        if not ignore_exception:
            raise Exception(
                "Extracted section count is not matching with section count in file."
            )


# Extract sections from old collectinfo files


def _parse_old_collectinfo_to_imap(cinfo_path, section_list, imap, ignore_exception):

    logger.info("Processing old collectinfo: " + cinfo_path)

    if "section_ids" not in imap:
        imap["section_ids"] = []

    # Check if cinfo file doesn't exist in given path
    if not os.path.exists(cinfo_path):
        logger.warning("collectinfo doesn't exist at Path: " + cinfo_path)
        return

    with open(cinfo_path, "r") as cinfo:

        current_section_data = []
        current_section_name = None
        current_section_id = None

        fileline = ""

        while True:

            try:
                fileline = cinfo.readline()
            except UnicodeDecodeError as e:
                if not ignore_exception:
                    logger.warning("Error at: " + fileline)
                    logger.warning(e)
                continue

            if fileline == "":
                break

            # Look for Start New Section
            found_new_section = False
            new_section_name = None
            new_section_id = None

            for section_id in section_list:

                section = section_list[section_id]

                if "regex_old" not in section.keys():
                    continue

                if re.search(section["regex_old"], fileline):
                    found_new_section = True
                    new_section_id = section_id
                    new_section_name = section["raw_section_name"]
                    break

            # If new section is found, add current section to imap if
            # it exists. And set current = new
            #
            # If new section is not found add content to current data
            if found_new_section:
                if current_section_name:
                    _update_imap_for_old_cinfo(
                        imap,
                        current_section_name,
                        current_section_data,
                        ignore_exception,
                    )
                    imap["section_ids"].append(current_section_id)
                    current_section_data = []

                current_section_name = new_section_name
                current_section_id = new_section_id
            else:
                current_section_data.append(fileline)

        # At the end, if current section exists update imap
        if current_section_name:
            _update_imap_for_old_cinfo(
                imap, current_section_name, current_section_data, ignore_exception
            )
            imap["section_ids"].append(current_section_id)
            current_section_data = []


# Correct the logic that if next section starts before 2 lines and section not detected. it should throw error,
# Update section name everytime a delimiter line hits, or something else whatever could be done. fix logic
# Extract sections from new collectinfo files, having delimiter.


def _parse_new_collectinfo_to_imap(
    cinfo_path, section_list, section_skip_list, delimiter, imap, ignore_exception
):
    logger.info("Processing new collectinfo: " + cinfo_path)

    if "section_ids" not in imap:
        imap["section_ids"] = []

    # Check if cinfo file doesn't exist in given path
    if not os.path.exists(cinfo_path):
        logger.warning("collectinfo doesn't exist at path: " + cinfo_path)
        return

    with open(cinfo_path, "r") as cinfo:

        current_section_name = None
        current_section_data = []
        current_section_id = 0

        while True:

            try:
                fileline = cinfo.readline()
            except UnicodeDecodeError as e:
                if not ignore_exception:
                    logger.warning("Error at: " + fileline)
                    logger.warning(e)
                continue

            if fileline == "":
                break
            regex = "regex_new"

            # Identify 'ASCOLLECTINFO' section
            if re.search(delimiter, fileline):

                # Update imap at delimiter if current section exists
                if current_section_name:
                    _update_imap_for_new_cinfo(
                        imap,
                        current_section_name,
                        current_section_data,
                        section_skip_list,
                        ignore_exception,
                    )
                    imap["section_ids"].append(current_section_id)
                    current_section_data = []
                    current_section_name = None
                    found_new_section = False

                # Search for next section name
                index = 1
                section_line = ""
                while index <= SECTION_DETECTION_LINE_MAX:

                    try:
                        section_line = cinfo.readline()
                    except UnicodeDecodeError as e:
                        if not ignore_exception:
                            logger.warning("Error at: " + section_line)
                            logger.warning(e)
                        continue

                    if section_line == "":
                        break

                    index = index + 1

                    # if line is > 300 ignore
                    if len(section_line) > 300:
                        continue

                    # Check for only two lines after delimiter for filter line
                    for section_id in section_list:
                        section = section_list[section_id]

                        # Check if this filter doesn't have regex of same
                        # version as collectinfo.
                        if regex not in section.keys():
                            continue

                        if re.search(section[regex], section_line):
                            found_new_section = True
                            new_section_name = section["raw_section_name"]
                            new_section_id = section_id
                            break
                    if found_new_section:
                        break

                if section_line == "":
                    break

                if not found_new_section:
                    if not ignore_exception:
                        logger.warning(
                            "Unknown section detected, printing first few lines:"
                            + str(current_section_data[:3])
                        )
                        raise Exception(
                            "Unknown section detected" + str(current_section_data[:3])
                        )
                    continue

                current_section_id = new_section_id
                current_section_name = new_section_name

            else:
                if current_section_name:
                    current_section_data.append(fileline)

        if current_section_name:
            _update_imap_for_new_cinfo(
                imap,
                current_section_name,
                current_section_data,
                section_skip_list,
                ignore_exception,
            )
            imap["section_ids"].append(current_section_id)
            current_section_data = []
            current_section_name = None


def get_timestamp_from_file(cinfo_path):
    timestamp = ""
    fileline = ""
    if not os.path.exists(cinfo_path):
        logger.warning("collectinfo doesn't exist at Path: " + cinfo_path)
        return
    with open(cinfo_path, "r") as cinfo:
        try:
            fileline = cinfo.readline()
        except UnicodeDecodeError as e:
            logger.warning("Error at: " + fileline)
            logger.warning(e)
        if "UTC" in fileline:
            timestamp = fileline.strip()
    return timestamp


def _imap_remove_disabled_filter_sections(imap):
    section_list = FILTER_LIST
    logger.info("Removing disabled filter section...")
    for key in section_list:
        filter_obj = section_list[key]
        if filter_obj["enable"] is False:
            # Remove that key from map
            try:
                logger.debug(
                    "Removing filter section from imap: "
                    + str(filter_obj["raw_section_name"])
                )
                del imap[filter_obj["raw_section_name"]]
            except KeyError:
                pass


def _collectinfo_has_delimiter(cinfo_path, delimiter):
    with open(cinfo_path, "r") as cinfo:
        index = 0
        fileline = ""
        while True:
            try:
                fileline = cinfo.readline()
                if fileline == "":
                    break
            except UnicodeDecodeError as e:
                logger.warning("Error at: " + fileline)
                logger.warning(e)
                continue
            # Check only till "COLLECTINFO_START_LINE_MAX" number of lines.
            if index >= COLLECTINFO_START_LINE_MAX:
                break
            if re.search(delimiter, fileline):
                return True
            index += 1
        return False


# Count no of sections in new cinfo file


def _get_collectinfo_num_sections(cinfo_path, delimiter):
    n_section = 0
    if not os.path.exists(cinfo_path):
        logger.warning("collectinfo doesn't exist at path: " + cinfo_path)
        return

    infile = cinfo_path
    with open(infile, "r") as cinfo:
        while True:
            fileline = ""
            try:
                fileline = cinfo.readline()
                if fileline == "":
                    break
            except UnicodeDecodeError as e:
                logger.warning("Error at: " + fileline)
                logger.warning(e)
                continue

            if re.search(delimiter, fileline):
                n_section += 1

    return n_section


def _update_imap_for_old_cinfo(imap, key, value, ignore_exception):
    vallist = []
    if key in imap.keys():
        preval = imap[key]

        # Report in case of collision
        logger.warning("There is a collision for section: " + key)

        vallist.extend(preval)

    # This would append all colliding section in a list
    vallist.append(value)
    imap[key] = vallist


def _update_imap_for_new_cinfo(imap, key, value, section_skip_list, ignore_exception):

    vallist = []

    same_section = False

    if key in imap.keys():
        preval = imap[key]

        # TODO - MOVE comment to souce of skip
        # listhist-dump:ns=<ns_name>;hist-name=<ttl|objsz>
        for sec in section_skip_list:
            if sec in key:
                same_section = True

        if not same_section:
            logger.warning("There is a collision for section: " + key)
            for section in preval:
                if (
                    section[0].strip() == value[0].strip()
                    or "log" in str(section[:2])
                    and "log" in str(value[:2])
                ):
                    same_section = True

        if not same_section:
            if not ignore_exception:
                logger.error(
                    "collision between two different sections, There could be new section added. Please check logs"
                )
                logger.info("old_sections: " + str(preval[:2]))
                logger.info("new_section: " + str(value[:2]))
                raise Exception(
                    "collision between two different sections, There could be new section added. Please check logs"
                )

        vallist.extend(preval)

    # This would append all colliding section in a list
    vallist.append(value)
    imap[key] = vallist


# Cross_validate printconfig section in extracted section json from raw cinfo


def _collectinfo_has_printconfig(imap_file_path):
    logger.info("Cross-validating printconfig")

    match_strings = [
        "microbenchmarks",
        "memory-accounting",
        "paxos-max-cluster-size",
        "auto-dun",
        "fb-health-bad-pct",
        "paxos-protocol",
    ]

    if not _validate_collectinfo_section(
        imap_file_path, "printconfig", match_strings, MIN_MATCH_COUNT
    ):
        logger.warning("print config cross-validator failed. " + imap_file_path)
        raise Exception("print config cross-validator failed.")


# Cross_validate stats section in extracted section json from raw cinfo
def _collectinfo_has_statistics(imap_file_path):
    logger.info("Cross-validating statistics")

    match_strings = [
        "batch_errors",
        "batch_initiate",
        "err_write_fail_bin_exists",
        "err_write_fail_generation",
        "fabric_msgs_rcvd",
        "partition_desync",
        "proxy_initiate",
    ]

    if not _validate_collectinfo_section(
        imap_file_path, "statistic", match_strings, MIN_MATCH_COUNT
    ):
        logger.warning("statistics cross-validator failed. " + imap_file_path)
        raise Exception("statistics cross-validator failed.")


# Cross_validate section in extracted section json from raw cinfo


def _validate_collectinfo_section(
    imap_file_path, section_name, match_strings, min_match_count
):

    if not os.path.exists(imap_file_path):
        logger.warning("cinfo doesn't exist at path for validation: " + imap_file_path)
        return False
    if not imap_file_path.endswith(".json"):
        logger.warning("Not a cinfo file: " + imap_file_path)
        return False

    # Count is across all the files to match min_match_count.
    count = 0

    with open(imap_file_path) as imap_file:

        exist = False

        imap = json.load(imap_file)

        # Skip files which are not valid section json for cinfo
        if len(imap) < MIN_LINES_IN_SECTION_JSON:
            return True

        if "cinfo_paths" not in imap.keys() or len(imap["cinfo_paths"]) == 0:
            logger.warning("cinfo doesn't have cinfo_paths.")
            return False

        logger.info(str(imap["cinfo_paths"]))

        for cinfo_path in imap["cinfo_paths"]:

            with open(cinfo_path, "rb") as cinfo:

                # Set iterator to start of the file
                cinfo.seek(0, 0)

                for fileline in cinfo:

                    for match_str in match_strings:
                        line = str(fileline)
                        if re.search(match_str, line):
                            count += 1

                    if count >= min_match_count:
                        exist = True
                        break

                if exist:
                    break

            if exist:
                break

        if exist:
            if section_name not in imap.keys():
                return False
            else:
                return True

    return False
