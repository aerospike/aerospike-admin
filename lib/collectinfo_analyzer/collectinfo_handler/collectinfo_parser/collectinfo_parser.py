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
from datetime import datetime
import json
import logging
import os

from lib.utils import conf_parser

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


def parse_collectinfo_files(
    file_paths, parsed_map, license_usage_map, ignore_exception=False
):
    """
    Parses on files in the collectinfo.tgz to run in collectinfo (-cf) mode.
    """
    UNKNOWN_NODE = "UNKNOWN_NODE"

    # Get imap
    # imap = {}
    # timestamp = ""

    json_parsed_timestamps = []

    # IF a valid cinfo json is present in cinfo_paths then append
    # its data in parsed_map.
    for cinfo_path_name in file_paths:
        if cinfo_path_name.endswith("ascinfo.json"):
            cinfo_map = {}
            try:
                with open(cinfo_path_name) as cinfo_json:
                    cinfo_map = json.load(cinfo_json, object_hook=_stringify)
            except IOError as e:
                if not ignore_exception:
                    logger.error(str(e))
                    raise

            if not _is_valid_collectinfo_json(cinfo_map):
                return
            else:
                logger.info("File is already pasred_json: " + cinfo_path_name)
                parsed_map.update(cinfo_map)
                json_parsed_timestamps = list(cinfo_map.keys())

        if cinfo_path_name.endswith("aslicenseusage.json"):
            license_map = {}

            try:
                with open(cinfo_path_name) as unique_json:
                    license_map = json.load(unique_json, object_hook=_stringify)
            except IOError as e:
                if not ignore_exception:
                    logger.error(str(e))
                    raise

            license_usage_map.update(license_map)

    parsed_conf_map = {}
    for cinfo_path in file_paths:
        if os.path.splitext(cinfo_path)[1] == ".json":
            continue

        if os.path.splitext(cinfo_path)[1] == ".conf":
            parsed_conf_map = conf_parser.parse_file(cinfo_path)

    if not json_parsed_timestamps and not parsed_conf_map:
        return

    return _add_missing_config_data(
        parsed_map,
        parsed_conf_map,
        json_parsed_timestamps,
        ignore_exception,
    )


def _match_nodeip(sys_map, known_ips):
    if "uname" in sys_map:
        uname_host = sys_map["uname"]["nodename"]

        for nodeid in known_ips:
            if uname_host in known_ips[nodeid] or uname_host in nodeid:
                return nodeid

    if "hostname" in sys_map and "hosts" in sys_map["hostname"]:
        sys_hosts = sys_map["hostname"]["hosts"]

        for sys_host in sys_hosts:
            for nodeid in known_ips:
                if sys_host in known_ips[nodeid] or sys_host in nodeid:
                    return nodeid


def _is_valid_collectinfo_json(cinfo_map):
    timestamp_format = "%Y-%m-%d %H:%M:%S UTC"
    if len(cinfo_map) == 0:
        return False
    for timestamp in cinfo_map:
        try:
            datetime.strptime(timestamp, timestamp_format)
        except ValueError:
            return False

        if len(cinfo_map[timestamp]) == 0:
            return False
    return True


def _create_node_ip_map(parsed_map):
    node_to_ip_map = {}

    for timestamp, pm_timestamp in parsed_map.items():  # normally length = 1
        pmt_cluster_name = list(pm_timestamp.values())[0]  # length always = 1
        for ip, pmtc_ip in pmt_cluster_name.items():
            meta_map = pmtc_ip["as_stat"]["meta_data"]
            node_id = meta_map.get("node_id", "")

            if node_id == "":
                continue

            node_to_ip_map[node_id] = ip

    return node_to_ip_map


def _stringify(data):
    """
    Convert unicode to string.

    """

    if isinstance(data, dict):
        data_str = {}
        for _k, v in data.items():
            data_str[_stringify(_k)] = _stringify(v)

        return data_str

    elif isinstance(data, list):
        return [_stringify(element) for element in data]

    else:
        return data


def _merge_samelevel_maps(main_map, from_map):
    """
    :param main_map: main dictionary to update
    :param from_map: dictionary to merge into main_map
    :return: updated main_map
    """

    if not main_map:
        return copy.deepcopy(from_map)

    if not isinstance(from_map, dict):
        return main_map

    for _k in from_map:

        if _k not in main_map:
            main_map[_k] = copy.deepcopy(from_map[_k])

        elif (
            _k in main_map
            and isinstance(main_map[_k], dict)
            and isinstance(from_map[_k], dict)
        ):
            main_map[_k] = _merge_samelevel_maps(main_map[_k], from_map[_k])

    return main_map


def _merge_nodelevel_map_to_mainmap(
    main_map,
    nodes_data_map,
    timestamps,
    node_ip_mapping={},
    keys_after_node_id=[],
    create_new_node=False,
):
    """
    :param main_map: main dictionary which is output of this function. Format should be {timestamp: { cluster: {nodeid: {....}}}}
    :param nodes_data_map: dictionary to merge into main_map. Format should be {nodeid: {...}}
    :param timestamps: list of timestamps to consider while merging
    :param node_ip_mapping: NodeId to IP or IP to NodeId mapping
    :param keys_after_node_id: List of extra keys to add after nodeid
    :param create_new_node: True if want to force to create new nodeid which is available in nodes_data_map but not available in main_map
    :return: updated main_map
    """

    if not nodes_data_map:
        return

    for timestamp in timestamps:
        if timestamp not in main_map:
            main_map[timestamp] = {}
            main_map[timestamp]["null"] = {}

        for cl in main_map[timestamp]:
            for node in nodes_data_map:
                node_key = None

                if node in main_map[timestamp][cl]:
                    node_key = node

                elif (
                    node in node_ip_mapping
                    and node_ip_mapping[node] in main_map[timestamp][cl]
                ):
                    node_key = node_ip_mapping[node]

                elif create_new_node:
                    node_key = node
                    main_map[timestamp][cl][node_key] = {}

                if not node_key:
                    continue

                if not keys_after_node_id or len(keys_after_node_id) == 0:
                    _dict_ptr = main_map[timestamp][cl]
                    _key = node_key

                elif len(keys_after_node_id) == 1:
                    _dict_ptr = main_map[timestamp][cl][node_key]
                    _key = keys_after_node_id[0]
                    if _key not in _dict_ptr:
                        _dict_ptr[_key] = {}

                else:
                    _dict_ptr = main_map[timestamp][cl][node_key]
                    for _k in keys_after_node_id[:-1]:
                        if _k not in _dict_ptr:
                            _dict_ptr[_k] = {}
                        _dict_ptr = _dict_ptr[_k]
                    _key = keys_after_node_id[-1]
                    if _key not in _dict_ptr:
                        _dict_ptr[_key] = {}

                _dict_ptr[_key] = _merge_samelevel_maps(
                    _dict_ptr[_key], nodes_data_map[node]
                )


def _get_sys_map(parsed_map, ignore_exception):
    """
    Extract System information from imap

    """

    sys_map = {}

    try:
        for timestamp, pm_timestamp in parsed_map.items():  # normally length = 1
            pmt_cluster_name = list(pm_timestamp.values())[0]  # length always = 1
            for ip, pmtc_ip in pmt_cluster_name.items():
                sys_map = pmtc_ip.get("sys_stat", {})
                if sys_map != {}:
                    return sys_map

    except Exception as e:

        if not ignore_exception:
            logger.error(
                "sys_section_parser cannot parse intermediate json. Err: " + str(e)
            )
            raise

    return sys_map


def _add_missing_config_data(
    parsed_map,
    parsed_conf_map={},
    timestamps=[],
    ignore_exception=False,
):
    """
    Add missing Aerospike original config data (from conf file) into parsed_map.

    """
    try:
        node_to_ip_mapping = _create_node_ip_map(parsed_map)
        sys_map = _get_sys_map(parsed_map, ignore_exception)
        node = _match_nodeip(sys_map, node_to_ip_mapping)

        conf_map = {}
        conf_map[node] = parsed_conf_map

        _merge_nodelevel_map_to_mainmap(
            parsed_map,
            conf_map,
            timestamps,
            node_to_ip_mapping,
            ["as_stat", "original_config"],
        )
    except Exception:
        return

    return
