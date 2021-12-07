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

from . import as_section_parser
from . import collectinfo_parser
from . import conf_parser
from . import section_filter_list
from . import sys_section_parser

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)

AS_SECTION_NAME_LIST = section_filter_list.AS_SECTION_NAME_LIST
HISTOGRAM_SECTION_NAME_LIST = section_filter_list.HISTOGRAM_SECTION_NAME_LIST
LATENCY_SECTION_NAME_LIST = section_filter_list.LATENCY_SECTION_NAME_LIST
SYS_SECTION_NAME_LIST = section_filter_list.SYS_SECTION_NAME_LIST
SECTION_FILTER_LIST = section_filter_list.FILTER_LIST
DERIVED_SECTION_LIST = section_filter_list.DERIVED_SECTION_LIST


def parse_collectinfo_files(
    file_paths, parsed_map, license_usage_map, ignore_exception=False
):
    UNKNOWN_NODE = "UNKNOWN_NODE"

    # Get imap
    imap = {}
    timestamp = ""

    json_parsed_timestamps = []
    _missing_version = 0

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
                _missing_version = _find_missing_data_version(cinfo_map)
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

        else:
            if timestamp == "":
                timestamp = collectinfo_parser.get_timestamp_from_file(cinfo_path)
            try:
                collectinfo_parser.extract_validate_filter_section_from_file(
                    cinfo_path, imap, ignore_exception
                )
            except Exception as e:
                if not ignore_exception:
                    logger.error(
                        "Cinfo parser cannot create intermediate json. Err: " + str(e)
                    )
                    raise

    if json_parsed_timestamps:

        if not _missing_version and not parsed_conf_map:
            return

        return _add_missing_data(
            imap,
            parsed_map,
            parsed_conf_map,
            json_parsed_timestamps,
            _missing_version,
            ignore_exception,
        )

    # get as_map using imap
    as_map = _get_as_map(imap, AS_SECTION_NAME_LIST, ignore_exception)

    # get histogram_map using imap
    histogram_map = _get_as_map(imap, HISTOGRAM_SECTION_NAME_LIST, ignore_exception)

    # get latency_map using imap
    latency_map = _convert_parsed_latency_map_to_collectinfo_format(
        _get_as_map(imap, LATENCY_SECTION_NAME_LIST, ignore_exception)
    )

    # get sys_map using imap
    sys_map = _get_sys_map(imap, ignore_exception)

    # get meta_map using imap
    meta_map = _get_meta_map(imap, ignore_exception)
    # ip_to_node mapping required for correct arrangement of histogram map
    ip_to_node_map = _create_ip_to_node_map(meta_map)

    # Get valid cluster name
    # Valid Cluster name could be stored in parsed_map, check that too.
    cluster_name = as_section_parser.get_cluster_name(as_map)
    if cluster_name is None:
        cluster_name = "null"

    if timestamp not in parsed_map:
        parsed_map[timestamp] = {}
        parsed_map[timestamp][cluster_name] = {}
    else:
        if "null" in parsed_map[timestamp] and cluster_name != "null":
            parsed_map[timestamp][cluster_name] = copy.deepcopy(
                parsed_map[timestamp]["null"]
            )
            (parsed_map[timestamp]).pop("null", None)
        elif "null" not in parsed_map[timestamp] and cluster_name == "null":
            cluster_name = list(parsed_map[timestamp].keys())[0]

    # Insert as_stat
    _merge_nodelevel_map_to_mainmap(
        parsed_map,
        as_map,
        [timestamp],
        keys_after_node_id=["as_stat"],
        create_new_node=True,
    )

    # Insert histogram stat
    _merge_nodelevel_map_to_mainmap(
        parsed_map,
        histogram_map,
        [timestamp],
        keys_after_node_id=["as_stat"],
        node_ip_mapping=ip_to_node_map,
    )

    # Insert latency stat
    _merge_nodelevel_map_to_mainmap(
        parsed_map,
        latency_map,
        [timestamp],
        keys_after_node_id=["as_stat"],
        node_ip_mapping=ip_to_node_map,
    )

    # insert meta_stat
    _merge_nodelevel_map_to_mainmap(
        parsed_map,
        meta_map,
        [timestamp],
        keys_after_node_id=["as_stat", "meta_data"],
        node_ip_mapping=ip_to_node_map,
    )

    # insert endpoints
    _add_missing_endpoints_data(
        imap, parsed_map, [timestamp], ip_to_node_map, ignore_exception
    )

    nodemap = parsed_map[timestamp][cluster_name]
    node_ip_map = _create_node_ip_map(meta_map)

    # Insert sys_stat
    if (
        len(sys_map) == 0
        and UNKNOWN_NODE in nodemap
        and "sys_stat" in nodemap[UNKNOWN_NODE]
    ):
        sys_map = nodemap[UNKNOWN_NODE]["sys_stat"]

    node = _match_nodeip(sys_map, node_ip_map)
    if node is None:
        node = UNKNOWN_NODE

    if len(sys_map) != 0:
        if node not in nodemap:
            nodemap[node] = {}
        _update_map(nodemap[node], "sys_stat", sys_map)

    try:
        nodemap[node]["as_stat"]["original_config"] = parsed_conf_map
    except Exception:
        pass

    # Assume all provided sys_stat belong to same node.
    # if any node has sys_stat and there is 'UNKNOWN' node then put that unknown data
    # in known sys_stat.
    for node in nodemap:
        if node == UNKNOWN_NODE:
            continue
        if "sys_stat" in nodemap[node] and UNKNOWN_NODE in nodemap:
            nodemap[node]["sys_stat"].update(nodemap[UNKNOWN_NODE]["sys_stat"])
            break
    if UNKNOWN_NODE in nodemap:
        nodemap.pop(UNKNOWN_NODE, None)


def parse_aerospike_info_all(cinfo_path, parsed_map, ignore_exception=False):
    # Parse collectinfo and create intermediate section_map
    imap = {}
    collectinfo_parser.extract_validate_filter_section_from_file(
        cinfo_path, imap, ignore_exception
    )

    section_filter_list = _get_section_list_for_parsing(imap, AS_SECTION_NAME_LIST)

    logger.info("Parsing sections: " + str(section_filter_list))

    as_section_parser.parse_as_section(section_filter_list, imap, parsed_map)


def parse_system_info_all(cinfo_path, parsed_map, ignore_exception=False):
    # Parse collectinfo and create intermediate section_map
    imap = {}
    collectinfo_parser.extract_validate_filter_section_from_file(
        cinfo_path, imap, ignore_exception
    )
    section_filter_list = _get_section_list_for_parsing(imap, SYS_SECTION_NAME_LIST)

    logger.info("Parsing sections: " + str(section_filter_list))
    sys_section_parser.parse_sys_section(section_filter_list, imap, parsed_map)


def parse_aerospike_info_section(
    cinfo_path, parsed_map, sectionlist, ignore_exception=False
):
    # Parse collectinfo and create intermediate section_map
    imap = {}
    collectinfo_parser.extract_validate_filter_section_from_file(
        cinfo_path, imap, ignore_exception
    )

    as_section_parser.parse_as_section(sectionlist, imap, parsed_map)


def parse_system_info_section(
    cinfo_path, parsed_map, sectionlist, ignore_exception=False
):
    # Parse collectinfo and create intermediate section_map
    imap = {}
    collectinfo_parser.extract_validate_filter_section_from_file(
        cinfo_path, imap, ignore_exception
    )

    sys_section_parser.parse_sys_section(sectionlist, imap, parsed_map)


def parse_system_live_command(command, command_raw_output, parsed_map):
    # Parse live cmd output and create imap
    imap = {}
    collectinfo_parser.extract_section_from_live_cmd(command, command_raw_output, imap)
    sectionlist = []
    sectionlist.append(command)
    sys_section_parser.parse_sys_section(sectionlist, imap, parsed_map)


def _get_section_list_for_parsing(imap, available_section):
    final_section_list = []
    imap_section_list = []
    imap_section_list.extend(DERIVED_SECTION_LIST)

    if "section_ids" not in imap:
        logger.warning("`section_ids` section missing in section_json.")
        return final_section_list

    for section_id in imap["section_ids"]:
        section = SECTION_FILTER_LIST[section_id]
        if "final_section_name" in section:
            sec_name = ""
            if "parent_section_name" in section:
                sec_name = (
                    section["parent_section_name"] + "." + section["final_section_name"]
                )
            else:
                sec_name = section["final_section_name"]
            imap_section_list.append(sec_name)

    final_section_list = list(set(imap_section_list).intersection(available_section))
    return final_section_list


def _update_map(datamap, key, valuemap):
    if key not in datamap:
        datamap[key] = valuemap
        return
    datamap[key].update(valuemap)


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


def _create_node_ip_map(nodemap):
    if not nodemap:
        return {}

    node_ip_map = {}
    for nodeid in nodemap:
        try:
            node_ip_map[nodeid] = nodemap[nodeid]["ip"]
        except Exception:
            pass

    return node_ip_map


def _create_ip_to_node_map(meta_map):
    """
    Create IP to NodeId mapping from meta_map

    """

    ip_to_node = {}
    if not meta_map or not isinstance(meta_map, dict):
        return ip_to_node

    for node in meta_map:
        if not meta_map[node] or "ip" not in meta_map[node]:
            continue

        ip_to_node[meta_map[node]["ip"]] = node

    return ip_to_node


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


def _get_meta_map(imap, ignore_exception):
    """
    Extract Metadata information from imap

    """

    meta_map = {}

    try:
        as_section_parser.get_meta_info(imap, meta_map)

    except Exception as e:

        if not ignore_exception:
            logger.error(
                "as_section_parser cannot parse intermediate json to get meta info. Err: "
                + str(e)
            )
            raise

    return meta_map


def _get_as_map(imap, as_section_name_list, ignore_exception):
    """
    Extract Aerospike information (config, stats, histogram dump) from imap

    """

    as_map = {}
    as_section_list = _get_section_list_for_parsing(imap, as_section_name_list)

    try:
        as_section_parser.parse_as_section(as_section_list, imap, as_map)
    except Exception as e:

        if not ignore_exception:
            logger.error(
                "as_section_parser cannot parse intermediate json. Err: " + str(e)
            )
            raise

    return as_map


def _get_sys_map(imap, ignore_exception):
    """
    Extract System information from imap

    """

    sys_map = {}
    sys_section_list = _get_section_list_for_parsing(imap, SYS_SECTION_NAME_LIST)

    try:
        sys_section_parser.parse_sys_section(sys_section_list, imap, sys_map)

    except Exception as e:

        if not ignore_exception:
            logger.error(
                "sys_section_parser cannot parse intermediate json. Err: " + str(e)
            )
            raise

    return sys_map


def _add_missing_as_data(
    imap, parsed_map, timestamps, node_ip_mapping, ignore_exception
):
    """
    Add missing Aerospike data (config and stats) into parsed_map which is loaded from old format json file

    """

    as_section_name_list = ["config.cluster"]
    as_map = _get_as_map(imap, as_section_name_list, ignore_exception)
    _merge_nodelevel_map_to_mainmap(
        parsed_map, as_map, timestamps, node_ip_mapping, ["as_stat"]
    )


def _add_missing_endpoints_data(
    imap, parsed_map, timestamps, node_ip_mapping, ignore_exception
):
    """
    Add missing Aerospike data (config and stats) into parsed_map which is loaded from old format json file

    """
    as_section_name_list = ["endpoints", "services"]
    as_map = _get_as_map(imap, as_section_name_list, ignore_exception)
    _merge_nodelevel_map_to_mainmap(
        parsed_map, as_map, timestamps, node_ip_mapping, ["as_stat", "meta_data"]
    )


def _add_missing_histogram_data(
    imap, parsed_map, timestamps, node_ip_mapping, ignore_exception
):
    """
    Add missing Aerospike histogram data into parsed_map which is loaded from old format json file

    """

    histogram_map = _get_as_map(imap, HISTOGRAM_SECTION_NAME_LIST, ignore_exception)
    _merge_nodelevel_map_to_mainmap(
        parsed_map, histogram_map, timestamps, node_ip_mapping, ["as_stat"]
    )


def _convert_parsed_latency_map_to_collectinfo_format(parsed_map):
    latency_map = {}

    for node, node_data in parsed_map.items():
        if (
            not node_data
            or isinstance(node_data, Exception)
            or "latency" not in node_data
        ):
            continue

        latency_data = node_data["latency"]

        for hist, hist_data in latency_data.items():
            if not hist_data or isinstance(hist_data, Exception):
                continue

            if node not in latency_map:
                latency_map[node] = {}
                latency_map[node]["latency"] = {}

            if hist not in latency_map[node]["latency"]:
                latency_map[node]["latency"][hist] = {}
                latency_map[node]["latency"][hist]["total"] = {}
                latency_map[node]["latency"][hist]["total"]["columns"] = []
                latency_map[node]["latency"][hist]["total"]["values"] = []

            _vl = []
            for _k, _v in hist_data.items():
                latency_map[node]["latency"][hist]["total"]["columns"].append(_k)
                _vl.append(_v)
            latency_map[node]["latency"][hist]["total"]["values"].append(_vl)

    return latency_map


def _add_missing_latency_data(
    imap, parsed_map, timestamps, node_ip_mapping, ignore_exception
):
    """
    Add missing Aerospike latency data into parsed_map which is loaded from old format json file

    """

    latency_map = {}
    parsed_latency_map = _get_as_map(imap, LATENCY_SECTION_NAME_LIST, ignore_exception)

    latency_map = _convert_parsed_latency_map_to_collectinfo_format(parsed_latency_map)

    _merge_nodelevel_map_to_mainmap(
        parsed_map, latency_map, timestamps, node_ip_mapping, ["as_stat"]
    )


def _to_map(value, delimiter1=":", delimiter2="="):
    """
    Converts raw string to map
    Ex. 'ns=bar:roster=null:pending_roster=A,B,C:observed_nodes=null'
    Returns {'ns': 'bar', 'roster': 'null', 'pending_roster': 'A,B,C', 'observed_nodes': 'null'}
    """
    vmap = {}
    if not value:
        return vmap

    try:
        data_list = value.split(delimiter1)
    except Exception:
        return vmap

    for kv in data_list:
        try:
            k, v = kv.split(delimiter2)
            vmap[k] = v
        except Exception:
            continue

    return vmap


def _to_roster_map(parsed_map):
    """
    Converts raw roster output to collectinfo format
    Ex. {'172.17.0.3:3000': {'roster': 'ns=bar:roster=null:pending_roster=null:observed_nodes=null'}, ...}
    Returns {'172.17.0.3:3000': {'roster':{'bar': {'ns': 'bar', 'roster': ['null'], ...}, ...}, ...}}
    """
    roster_map = {}
    if not parsed_map:
        return roster_map

    list_fields = ["roster", "pending_roster", "observed_nodes"]

    for node, node_data in parsed_map.items():
        if (
            not node_data
            or isinstance(node_data, Exception)
            or "roster" not in node_data
        ):
            continue

        roster_data = node_data["roster"]

        try:
            ns_data_list = roster_data.split(";")
        except Exception:
            continue

        if not ns_data_list:
            continue

        ns_map = {}
        for ns_data in ns_data_list:
            m = _to_map(ns_data)
            if not m or "ns" not in m:
                continue
            for k, v in m.items():
                if k not in list_fields:
                    continue
                try:
                    m[k] = v.split(",")
                except Exception:
                    pass

            ns_map[m["ns"]] = m

        roster_map[node] = {}
        roster_map[node]["roster"] = ns_map

    return roster_map


def _add_missing_roster_data(
    imap, parsed_map, timestamps, node_ip_mapping, ignore_exception
):
    """
    Add missing Aerospike roster data into parsed_map which is loaded from old format file

    """

    roster_map = {}
    parsed_roster_map = _get_as_map(imap, ["roster"], ignore_exception)
    roster_map = _to_roster_map(parsed_roster_map)
    _merge_nodelevel_map_to_mainmap(
        parsed_map, roster_map, timestamps, node_ip_mapping, ["as_stat", "config"]
    )


def _add_missing_original_config_data(
    parsed_conf_map, parsed_map, timestamps, node_ip_mapping, ignore_exception
):
    """
    Add missing Aerospike original config data (from conf file) into parsed_map.

    """

    _merge_nodelevel_map_to_mainmap(
        parsed_map,
        parsed_conf_map,
        timestamps,
        node_ip_mapping,
        ["as_stat", "original_config"],
    )


def _add_missing_dmesg_data(
    sys_map, parsed_map, timestamps, node, node_ip_mapping, ignore_exception
):
    """
    Add missing system dmesg data into parsed_map.

    """
    if not sys_map or "dmesg" not in sys_map:
        return

    dmesg_map = {}
    dmesg_map[node] = {}
    dmesg_map[node]["dmesg"] = sys_map["dmesg"]
    _merge_nodelevel_map_to_mainmap(
        parsed_map, dmesg_map, timestamps, node_ip_mapping, ["sys_stat"]
    )


def _add_missing_scheduler_data(
    sys_map, parsed_map, timestamps, node, node_ip_mapping, ignore_exception
):
    """
    Add missing IO scheduler details into parsed_map.

    """

    if not sys_map or "scheduler" not in sys_map:
        return

    scheduler_map = {}
    scheduler_map[node] = {}
    scheduler_map[node]["scheduler"] = sys_map["scheduler"]
    _merge_nodelevel_map_to_mainmap(
        parsed_map, scheduler_map, timestamps, node_ip_mapping, ["sys_stat"]
    )


# Format: [version, key to identify version changes, parent keys of key till node]
new_additional_field_pointers = [
    [1, "node_id", ["as_stat", "meta_data"]],
    [2, "dmesg", ["sys_stat"]],
    [3, "endpoints", ["as_stat", "meta_data"]],
    [4, "latency", ["as_stat"]],
]


def _find_missing_data_version(cinfo_map):
    """
    Check cinfo_map parsed from json file is having all necessary data or not.
    Old json file does not have some data sections Ex. node_id, histogram, cluster config etc.
    Further version does not have latency data only.

    """

    if not cinfo_map:
        return new_additional_field_pointers[0][0]

    found_version = 0
    for i in new_additional_field_pointers:
        _version = i[0]
        _key = i[1]
        _parent_keys = i[2]

        for timestamp in cinfo_map:
            if found_version >= _version:
                break

            if cinfo_map[timestamp]:

                for cl in cinfo_map[timestamp]:
                    if found_version >= _version:
                        break

                    if cinfo_map[timestamp][cl]:

                        for node in cinfo_map[timestamp][cl]:
                            try:
                                _ptr = cinfo_map[timestamp][cl][node]
                                for _pk in _parent_keys:
                                    _ptr = _ptr[_pk]
                                if _key in _ptr:
                                    found_version = _version
                                    break

                            except Exception:
                                return _version

        if found_version < _version:
            return _version

    return 0


def _add_missing_data(
    imap,
    parsed_map,
    parsed_conf_map={},
    timestamps=[],
    missing_version=0,
    ignore_exception=False,
):
    """
    Add missing data (Aerospike stats, config, metadata and histogram dump) into parsed_map which is loaded from old format json file

    """

    # To maintain some backward compatability.
    # Not sure if adding missing data is still needed.
    # Code seems to support backwards compatibility and is quite dated.
    try:
        meta_map = _get_meta_map(imap, ignore_exception)
        node_to_ip_mapping = _create_node_ip_map(meta_map)
        sys_map = _get_sys_map(imap, ignore_exception)
        node = _match_nodeip(sys_map, node_to_ip_mapping)
        conf_map = {}
        conf_map[node] = parsed_conf_map
        _add_missing_original_config_data(
            conf_map, parsed_map, timestamps, node_to_ip_mapping, ignore_exception
        )
    except Exception:
        return

    if missing_version == 0:
        return

    if missing_version == 1:
        _merge_nodelevel_map_to_mainmap(
            parsed_map,
            meta_map,
            timestamps,
            node_to_ip_mapping,
            ["as_stat", "meta_data"],
        )
        _add_missing_as_data(
            imap, parsed_map, timestamps, node_to_ip_mapping, ignore_exception
        )
        _add_missing_histogram_data(
            imap, parsed_map, timestamps, node_to_ip_mapping, ignore_exception
        )

    if missing_version <= 2:
        _add_missing_dmesg_data(
            sys_map, parsed_map, timestamps, node, node_to_ip_mapping, ignore_exception
        )

    if missing_version <= 3:
        _add_missing_scheduler_data(
            sys_map, parsed_map, timestamps, node, node_to_ip_mapping, ignore_exception
        )
        _add_missing_endpoints_data(
            imap, parsed_map, timestamps, node_to_ip_mapping, ignore_exception
        )

    if missing_version <= 4:
        _add_missing_latency_data(
            imap, parsed_map, timestamps, node_to_ip_mapping, ignore_exception
        )
        _add_missing_roster_data(
            imap, parsed_map, timestamps, node_to_ip_mapping, ignore_exception
        )
