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
from datetime import datetime
import json
import logging
import os

from as_section_parser import parse_as_section, get_meta_info, get_cluster_name
import cinfo_parser
import section_filter_list
from sys_section_parser import parse_sys_section

logger = logging.getLogger(__name__)

AS_SECTION_NAME_LIST = section_filter_list.AS_SECTION_NAME_LIST
HISTOGRAM_SECTION_NAME_LIST = section_filter_list.HISTOGRAM_SECTION_NAME_LIST
SYS_SECTION_NAME_LIST = section_filter_list.SYS_SECTION_NAME_LIST
SECTION_FILTER_LIST = section_filter_list.FILTER_LIST
DERIVED_SECTION_LIST = section_filter_list.DERIVED_SECTION_LIST


def parse_info_all(cinfo_paths, parsed_map, ignore_exception=False):
    UNKNOWN_NODE = 'UNKNOWN_NODE'

    # Get imap
    imap = {}
    timestamp = ''

    json_parsed_timestamps = []
    # IF a valid cinfo json is present in cinfo_paths then append
    # its data in parsed_map.
    for cinfo_path_name in cinfo_paths:
        if os.path.splitext(cinfo_path_name)[1] == ".json":
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
                if _is_complete_json_data(cinfo_map):
                    return
                json_parsed_timestamps = cinfo_map.keys()
                break

    for cinfo_path in cinfo_paths:
        if os.path.splitext(cinfo_path)[1] == ".json":
            continue

        if timestamp == '':
            timestamp = cinfo_parser.get_timestamp_from_file(cinfo_path)
        try:
            cinfo_parser.extract_validate_filter_section_from_file(cinfo_path, imap, ignore_exception)
        except Exception as e:
            if not ignore_exception:
                logger.error("Cinfo parser can not create intermediate json. Err: " + str(e))
                raise

    if json_parsed_timestamps:
        return _add_missing_data(imap, parsed_map, json_parsed_timestamps, ignore_exception)

    # get as_map using imap
    as_map = _get_as_map(imap, AS_SECTION_NAME_LIST, ignore_exception)

    # get histogram_map using imap
    histogram_map = _get_as_map(imap, HISTOGRAM_SECTION_NAME_LIST, ignore_exception)

    # get sys_map using imap
    sys_map = _get_sys_map(imap, ignore_exception)

    # get meta_map using imap
    meta_map = _get_meta_map(imap, ignore_exception)
    # ip_to_node mapping required for correct arrangement of histogram map
    ip_to_node_map = _create_ip_to_node_map(meta_map)

    # Get valid cluster name
    # Valid Cluster name could be stored in parsed_map, check that too.
    cluster_name = get_cluster_name(as_map)
    if cluster_name is None:
        cluster_name = 'null'

    if timestamp not in parsed_map:
        parsed_map[timestamp] = {}
        parsed_map[timestamp][cluster_name] = {}
    else:
        if 'null' in parsed_map[timestamp] and cluster_name != 'null':
            parsed_map[timestamp][cluster_name] = copy.deepcopy(parsed_map[timestamp]['null'])
            (parsed_map[timestamp]).pop('null', None)
        elif 'null' not in parsed_map[timestamp] and cluster_name == 'null':
            cluster_name = parsed_map[timestamp].keys()[0]

    # Insert as_stat
    _merge_nodelevel_map_to_mainmap(parsed_map, as_map, [timestamp], keys_after_node_id=["as_stat"], create_new_node=True)

    # Insert histogram stat
    _merge_nodelevel_map_to_mainmap(parsed_map, histogram_map, [timestamp], keys_after_node_id=["as_stat"], node_ip_mapping=ip_to_node_map)

    # insert meta_stat
    _merge_nodelevel_map_to_mainmap(parsed_map, meta_map, [timestamp], keys_after_node_id=["as_stat", "meta_data"], node_ip_mapping=ip_to_node_map)

    # insert endpoints
    _add_missing_endpoints_data(imap, parsed_map, [timestamp], ip_to_node_map, ignore_exception)

    nodemap = parsed_map[timestamp][cluster_name]
    node_ip_map = _create_node_ip_map(meta_map)

    # Insert sys_stat
    nodes = nodemap.keys()
    if len(sys_map) == 0 and UNKNOWN_NODE in nodemap \
            and 'sys_stat' in nodemap[UNKNOWN_NODE]:
        sys_map = nodemap[UNKNOWN_NODE]['sys_stat']

    node = _match_nodeip(sys_map, node_ip_map)
    if node is None:
        node = UNKNOWN_NODE

    if len(sys_map) != 0:
        if node not in nodemap:
            nodemap[node] = {}
        _update_map(nodemap[node], 'sys_stat', sys_map)

    # Assume all provided sys_stat belong to same node.
    # if any node has sys_stat and there is 'UNKNOWN' node then put that unknown data
    # in known sys_stat.
    found_sys_node = False
    for node in nodemap:
        if node == UNKNOWN_NODE:
            continue
        if 'sys_stat' in nodemap[node] and UNKNOWN_NODE in nodemap:
            nodemap[node]['sys_stat'].update(nodemap[UNKNOWN_NODE]['sys_stat'])
            found_sys_node = True
            break
    if UNKNOWN_NODE in nodemap:
        nodemap.pop(UNKNOWN_NODE, None)

def parse_aerospike_info_all(cinfo_path, parsed_map, ignore_exception=False):
    # Parse collectinfo and create intermediate section_map
    imap = {}
    cinfo_parser.extract_validate_filter_section_from_file(
        cinfo_path, imap, ignore_exception)

    section_filter_list = _get_section_list_for_parsing(
        imap, AS_SECTION_NAME_LIST)

    logger.info("Parsing sections: " + str(section_filter_list))

    parse_as_section(section_filter_list, imap, parsed_map)


def parse_system_info_all(cinfo_path, parsed_map, ignore_exception=False):
    # Parse collectinfo and create intermediate section_map
    imap = {}
    cinfo_parser.extract_validate_filter_section_from_file(cinfo_path, imap, ignore_exception)
    section_filter_list = _get_section_list_for_parsing(imap, SYS_SECTION_NAME_LIST)

    logger.info("Parsing sections: " + str(section_filter_list))
    parse_sys_section(section_filter_list, imap, parsed_map)


def parse_aerospike_info_section(cinfo_path, parsed_map, sectionlist, ignore_exception=False):
    # Parse collectinfo and create intermediate section_map
    imap = {}
    cinfo_parser.extract_validate_filter_section_from_file(cinfo_path, imap, ignore_exception)

    parse_as_section(sectionlist, imap, parsed_map)


def parse_system_info_section(cinfo_path, parsed_map, sectionlist, ignore_exception=False):
    # Parse collectinfo and create intermediate section_map
    imap = {}
    cinfo_parser.extract_validate_filter_section_from_file(cinfo_path, imap, ignore_exception)

    parse_sys_section(sectionlist, imap, parsed_map)


def parse_system_live_command(command, command_raw_output, parsed_map):
    # Parse live cmd output and create imap
    imap = {}
    cinfo_parser.extract_section_from_live_cmd(command, command_raw_output, imap)
    sectionlist = []
    sectionlist.append(command)
    parse_sys_section(sectionlist, imap, parsed_map)


def _get_section_list_for_parsing(imap, available_section):
    final_section_list = []
    imap_section_list = []
    imap_section_list.extend(DERIVED_SECTION_LIST)
    if 'section_ids' not in imap:
        logger.warning("`section_ids` section missing in section_json.")
        return final_section_list
    for section_id in imap['section_ids']:
        section = SECTION_FILTER_LIST[section_id]
        if 'final_section_name' in section:
            sec_name = ''
            if 'parent_section_name' in section:
                sec_name = section['parent_section_name'] + '.' + section['final_section_name']
            else:
                sec_name = section['final_section_name']
            imap_section_list.append(sec_name)
    final_section_list = list(set(imap_section_list).intersection(available_section))
    return final_section_list


def _update_map(datamap, key, valuemap):
    if key not in datamap:
        datamap[key] = valuemap
        return
    datamap[key].update(valuemap)


def _match_nodeip(sys_map, known_ips):
    if 'uname' in sys_map:
        uname_host = sys_map['uname']['nodename']

        for nodeid in known_ips:
            if uname_host in known_ips[nodeid] or uname_host in nodeid:
                return nodeid

    if 'hostname' in sys_map:
        sys_hosts = sys_map['hostname']['hosts']

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
            node_ip_map[nodeid] = nodemap[nodeid]['ip']
        except Exception:
            pass

    return node_ip_map

def _is_complete_json_data(cinfo_map):
    """
    Check cinfo_map parsed from json file is having all necessary data or not.
    Old json file does not have some data sections Ex. node_id, histogram, cluster config etc.

    """

    if not cinfo_map:
        return True

    for timestamp in cinfo_map:
        if cinfo_map[timestamp]:

            for cl in cinfo_map[timestamp]:
                if cinfo_map[timestamp][cl]:

                    for node in cinfo_map[timestamp][cl]:
                        try:
                            if "node_id" in cinfo_map[timestamp][cl][node]["as_stat"]["meta_data"]:
                                return True

                        except Exception:
                            return False

    return False

def _create_ip_to_node_map(meta_map):
    """
    Create IP to NodeId mapping from meta_map

    """

    ip_to_node = {}
    if not meta_map or not isinstance(meta_map, dict):
        return ip_to_node

    for node in meta_map:
        if not meta_map[node] or not 'ip' in meta_map[node]:
            continue

        ip_to_node[meta_map[node]['ip']] = node

    return ip_to_node

def _stringify(input):
    """
    Convert unicode to string.

    """

    if isinstance(input, dict):
        data = {}
        for _k,v in input.iteritems():
            data[_stringify(_k)] = _stringify(v)

        return data

    elif isinstance(input, list):
        return [_stringify(element) for element in input]

    elif isinstance(input, unicode):
        return str(input)

    else:
        return input

def _merge_samelevel_maps(main_map, from_map):
    '''
    :param main_map: main dictionary to update
    :param from_map: dictionary to merge into main_map
    :return: updated main_map
    '''

    if not main_map:
        return copy.deepcopy(from_map)

    if not isinstance(from_map, dict):
        return main_map

    for _k in from_map:

        if _k not in main_map:
            main_map[_k] = copy.deepcopy(from_map[_k])

        elif _k in main_map and isinstance(main_map[_k], dict) and isinstance(from_map[_k], dict):
            main_map[_k] = _merge_samelevel_maps(main_map[_k], from_map[_k])

    return main_map

def _merge_nodelevel_map_to_mainmap(main_map, nodes_data_map, timestamps, node_ip_mapping={}, keys_after_node_id=[], create_new_node=False):
    '''
    :param main_map: main dictionary which is output of this function. Format should be {timestamp: { cluster: {nodeid: {....}}}}
    :param nodes_data_map: dictionary to merge into main_map. Format should be {nodeid: {...}}
    :param timestamps: list of timestamps to consider while merging
    :param node_ip_mapping: NodeId to IP or IP to NodeId mapping
    :param keys_after_node_id: List of extra keys to add after nodeid
    :param create_new_node: True if want to force to create new nodeid which is available in nodes_data_map but not available in main_map
    :return: updated main_map
    '''

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

                elif node in node_ip_mapping and node_ip_mapping[node] in main_map[timestamp][cl]:
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

                _dict_ptr[_key] = _merge_samelevel_maps(_dict_ptr[_key], nodes_data_map[node])


def _get_meta_map(imap, ignore_exception):
    """
    Extract Metadata information from imap

    """

    meta_map = {}

    try:
        get_meta_info(imap, meta_map)

    except Exception as e:

        if not ignore_exception:
            logger.error("as_section_parser can not parse intermediate json to get meta info. Err: " + str(e))
            raise

    return meta_map

def _get_as_map(imap, as_section_name_list, ignore_exception):
    """
    Extract Aerospike information (config, stats, histogram dump) from imap

    """

    as_map = {}
    as_section_list = _get_section_list_for_parsing(imap, as_section_name_list)

    try:
        parse_as_section(as_section_list, imap, as_map)
    except Exception as e:

        if not ignore_exception:
            logger.error("as_section_parser can not parse intermediate json. Err: " + str(e))
            raise

    return as_map

def _get_sys_map(imap, ignore_exception):
    """
    Extract System information from imap

    """

    sys_map = {}
    sys_section_list = _get_section_list_for_parsing(imap, SYS_SECTION_NAME_LIST)

    try:
        parse_sys_section(sys_section_list, imap, sys_map)

    except Exception as e:

        if not ignore_exception:
            logger.error("sys_section_parser can not parse intermediate json. Err: " + str(e))
            raise

    return sys_map

def _add_missing_as_data(imap, parsed_map, timestamps, node_ip_mapping, ignore_exception):
    """
    Add missing Aerospike data (config and stats) into parsed_map which is loaded from old format json file

    """

    as_section_name_list = ["config.cluster"]
    as_map = _get_as_map(imap, as_section_name_list, ignore_exception)
    _merge_nodelevel_map_to_mainmap(parsed_map, as_map, timestamps, node_ip_mapping, ["as_stat"])

def _add_missing_endpoints_data(imap, parsed_map, timestamps, node_ip_mapping, ignore_exception):
    """
    Add missing Aerospike data (config and stats) into parsed_map which is loaded from old format json file

    """
    as_section_name_list = ["endpoints", "services"]
    as_map = _get_as_map(imap, as_section_name_list, ignore_exception)
    _merge_nodelevel_map_to_mainmap(parsed_map, as_map, timestamps, node_ip_mapping, ["as_stat", "meta_data"])

def _add_missing_histogram_data(imap, parsed_map, timestamps, node_ip_mapping, ignore_exception):
    """
    Add missing Aerospike histogram data into parsed_map which is loaded from old format json file

    """

    histogram_map = _get_as_map(imap, HISTOGRAM_SECTION_NAME_LIST, ignore_exception)
    _merge_nodelevel_map_to_mainmap(parsed_map, histogram_map, timestamps, node_ip_mapping, ["as_stat"])

def _add_missing_data(imap, parsed_map, timestamps, ignore_exception):
    """
    Add missing data (Aerospike stats, config, metadata and histogram dump) into parsed_map which is loaded from old format json file

    """

    meta_map = _get_meta_map(imap, ignore_exception)
    node_to_ip_mapping = _create_node_ip_map(meta_map)
    _merge_nodelevel_map_to_mainmap(parsed_map, meta_map, timestamps, node_to_ip_mapping, ["as_stat", "meta_data"])
    _add_missing_as_data(imap, parsed_map, timestamps, node_to_ip_mapping, ignore_exception)
    _add_missing_histogram_data(imap, parsed_map, timestamps, node_to_ip_mapping, ignore_exception)
    _add_missing_endpoints_data(imap, parsed_map, timestamps, node_to_ip_mapping, ignore_exception)
