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

from as_section_parser import parse_as_section, get_meta_info, get_cluster_name
from sys_section_parser import parse_sys_section 

import section_filter_list
import logging
import cinfo_parser
import json
import copy
from datetime import datetime

logger = logging.getLogger(__name__)

AS_SECTION_NAME_LIST = section_filter_list.AS_SECTION_NAME_LIST
SYS_SECTION_NAME_LIST = section_filter_list.SYS_SECTION_NAME_LIST
SECTION_FILTER_LIST = section_filter_list.FILTER_LIST
DERIVED_SECTION_LIST = section_filter_list.DERIVED_SECTION_LIST

def parse_info_all(cinfo_paths, parsed_map, ignore_exception=False):
    UNKNOWN_NODE = 'UNKNOWN_NODE'

    # Get imap
    imap = {}
    timestamp = ''

    # IF a valid cinfo json is present in cinfo_paths then append
    # its data in parsed_map.
    for cinfo_path_name in cinfo_paths:
        if 'json' in cinfo_path_name:
            cinfo_map = {}
            try:
                with open(cinfo_path_name) as cinfo_json:
                    cinfo_map = json.load(cinfo_json)
            except IOError as e:
                if not ignore_exception:
                    logger.error(str(e))
                    raise

            if not _is_valid_collectinfo_json(cinfo_map):
                return
            else:
                logger.info("File is already pasred_json: " + cinfo_path_name)
                parsed_map.update(cinfo_map)
                return

    for cinfo_path in cinfo_paths:
        if timestamp == '':
            timestamp = cinfo_parser.get_timestamp_from_file(cinfo_path)
        try:
            cinfo_parser.extract_validate_filter_section_from_file(
                cinfo_path, imap, ignore_exception)
        except Exception as e:
            if not ignore_exception:
                logger.error("Cinfo parser can not create intermediate json. Err: " + str(e))
                raise

    # get as_map using imap
    as_map = {}
    as_section_list = _get_section_list_for_parsing(imap, AS_SECTION_NAME_LIST)
    try:
        parse_as_section(as_section_list, imap, as_map)
    except Exception as e:
        if not ignore_exception:
            logger.error("as_section_parser can not parse intermediate json. Err: " + str(e))
            raise

    # get sys_map using imap
    sys_map = {}
    sys_section_list = _get_section_list_for_parsing(
        imap, SYS_SECTION_NAME_LIST)
    try:
        parse_sys_section(sys_section_list, imap, sys_map)
    except Exception as e:
        if not ignore_exception:
            logger.error("sys_section_parser can not parse intermediate json. Err: " + str(e))
            raise

    # get meta_map using imap
    meta_map = {}
    try:
        get_meta_info(imap, meta_map)
    except Exception as e:
        if not ignore_exception:
            logger.error("as_section_parser can not parse intermediate json to get meta info. Err: " + str(e))
            raise

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

    nodemap = parsed_map[timestamp][cluster_name]
    # Insert as_stat
    for nodeid in as_map:
        if nodeid not in nodemap:
            nodemap[nodeid] = {}
        # TODO can we get better name?
        _update_map(nodemap[nodeid], 'as_stat', as_map[nodeid])

    # insert meta_stat
    for nodeid in meta_map:
        if nodeid not in nodemap:
            nodemap[nodeid] = {}
        if 'as_stat' not in nodemap[nodeid]:
            nodemap[nodeid]['as_stat'] = {}
        _update_map(nodemap[nodeid]['as_stat'], 'meta_data', meta_map[nodeid])
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
            return True
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
