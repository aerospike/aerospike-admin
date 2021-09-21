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
import copy
import logging

from . import section_filter_list
from . import util

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)

FILTER_LIST = section_filter_list.FILTER_LIST
DERIVED_SECTION_LIST = section_filter_list.DERIVED_SECTION_LIST


def parse_as_section(section_list, imap, parsed_map):
    # Parse As stat
    logger.info("Parse As stats.")

    nodes = _identify_nodes(imap)

    if not nodes:
        logger.warning("Node can't be identified. Cannot parse")
        return

    for section in section_list:
        if section == "statistics":
            _parse_stat_section(nodes, imap, parsed_map)

        elif section == "statistics.dc":
            _parse_dc_stat_section(nodes, imap, parsed_map)

        elif section == "statistics.xdr":
            _parse_xdr_stat_section(nodes, imap, parsed_map)

        elif section == "config":
            _parse_config_section(nodes, imap, parsed_map)

        elif section == "config.dc":
            _parse_dc_config_section(nodes, imap, parsed_map)

        elif section == "config.xdr":
            _parse_xdr_config_section(nodes, imap, parsed_map)

        elif section == "config.cluster":
            _parse_cluster_config_section(nodes, imap, parsed_map)

        elif section == "latency":
            _parse_latency_section(nodes, imap, parsed_map)

        elif section == "sindex_info":
            _parse_sindex_info_section(nodes, imap, parsed_map)

        elif section == "features":
            _parse_features(nodes, imap, parsed_map)

        elif section == "histogram.ttl":
            _parse_hist_dump_ttl(nodes, imap, parsed_map)

        elif section == "histogram.objsz":
            _parse_hist_dump_objsz(nodes, imap, parsed_map)

        elif section == "endpoints":
            _parse_endpoints(nodes, imap, parsed_map)

        elif section == "services":
            _parse_services(nodes, imap, parsed_map)

        elif section == "roster":
            _parse_roster_section(nodes, imap, parsed_map)

        else:
            logger.warning(
                "Section unknown, cannot be parsed. Check AS_SECTION_NAME_LIST. Section: "
                + section
            )

    # Change raw value after parsing all sections. A section can be a child
    # section of other like 'stat_dc'. Note that parsed_map[node][section]
    # is not be there for child section. Cannot parse all sections blindly,
    # otherwise it could run over, sections, which are been already converted.
    logger.info(
        "Converting basic raw string vals to original vals. sections: "
        + str(section_list)
    )
    for section in section_list:
        for node in nodes:
            if section in parsed_map[node]:
                # Need to create separate dict so that it only convert desired
                # func
                param_map = {section: parsed_map[node][section]}
                # type_check_basic_values(param_map)
                parsed_map[node][section] = copy.deepcopy(param_map[section])


# output: {in_aws: AAA, instance_type: AAA}
def get_cluster_name(parsed_map):
    for node in parsed_map:
        if (
            "config" in parsed_map[node]
            and "service" in parsed_map[node]["config"]
            and "cluster-name" in parsed_map[node]["config"]["service"]
        ):
            # Return cluster name when get a valid one.
            if parsed_map[node]["config"]["service"]["cluster-name"] != "null":
                return parsed_map[node]["config"]["service"]["cluster-name"]
    return "null"


def get_meta_info(imap, meta_map):
    # get nodes
    nodes = _identify_nodes(imap)
    if len(nodes) == 0:
        return
    asd_meta = _get_meta_from_network_info(imap, nodes)
    ip_meta = _get_ip_from_network_info(imap, nodes)

    for node in nodes:
        meta_map[node] = {}
        if node in asd_meta:
            meta_map[node].update(asd_meta[node])

        if node in ip_meta:
            meta_map[node].update(ip_meta[node])


def _compare_version(ver2, ver1):
    m1 = re.match(r"(.+)\.(.+)\.(.+)", ver1)
    m2 = re.match(r"(.+)\.(.+)\.(.+)", ver2)

    if m1 and m2:
        if int(m2.group(1)) > int(m1.group(1)):
            return True
        elif (int(m2.group(1)) == int(m1.group(1))) and (
            int(m2.group(2)) > int(m1.group(2))
        ):
            return True
        elif (
            (int(m2.group(1)) == int(m1.group(1)))
            and (int(m2.group(2)) == int(m1.group(2)))
            and (int(m2.group(3)) > int(m1.group(3)))
        ):
            return True
    return False


def _update_version_field(build_data, version_key, version_value):
    update = False
    if version_key not in build_data:
        update = True
    else:
        # True if version > build_data['server-version']
        update = _compare_version(version_value, build_data[version_key])

    if update:
        build_data[version_key] = version_value
    return update


def _parse_build_version(imap, parsed_map):

    # RPM
    raw_section_name_1, final_section_name_1, _ = util.get_section_name_from_id("ID_27")

    # DPKG
    raw_section_name_2, final_section_name_2, _ = util.get_section_name_from_id("ID_28")

    logger.info("Parsing section: " + final_section_name_1)

    if not (
        util.is_valid_section(imap, raw_section_name_1, final_section_name_1)
        and util.is_valid_section(imap, raw_section_name_2, final_section_name_2)
    ):
        return

    distro = {}
    asd_found = False
    build_data = {}
    build_data["edition"] = "EE"
    ver_regex = r"[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}"

    for dist in [raw_section_name_1, raw_section_name_2]:

        if dist not in imap:
            continue

        # Use 0, others are ignored for repeated values.
        distro = imap[dist][0]

        for i in range(len(distro)):

            match = re.search(ver_regex, distro[i])
            if not match:
                continue

            version = distro[i][match.start() : match.end()]

            if re.search("tool", distro[i]):
                _update_version_field(build_data, "tool-version", version)

            elif re.search("amc", distro[i]) or re.search("management", distro[i]):
                _update_version_field(build_data, "amc-version", version)

            elif re.search("server", distro[i]):
                update = _update_version_field(build_data, "server-version", version)

                if update:
                    if re.search("community", distro[i]):
                        build_data["edition"] = "CE"
                    build_data["package"] = dist
                    asd_found = True

            # In some of the cases the server version has format
            # aerospike-3.5.14-27.x86_64. so grep for aerospike,
            # if any of the previous conditions were not met.
            elif not asd_found and (
                (
                    re.search("aerospike", distro[i])
                    or re.search("citrusleaf", distro[i])
                )
                and "x86_64" in distro[i]
                and "client" not in distro[i]
            ):
                build_data["server-version"] = version
                build_data["package"] = dist
                asd_found = True

            else:
                logger.debug(
                    "The line matches the regex but doesn't contain any valid versions "
                    + distro[i]
                )

    if not asd_found:
        logger.warning("Asd Version string not present in JSON.")

    parsed_map[final_section_name_1] = build_data


def _get_cluster_size(imap):
    # statistics section
    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_11")

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    stats = imap[raw_section_name][0]

    for stat in stats:

        if "cluster_size" not in stat:
            continue

        cluster_size_list = stat.split()
        for cluster_size in cluster_size_list:
            if cluster_size.isdigit():
                return int(cluster_size)
        return int(0)


def _get_unique_namespaces(imap):

    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_2")

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    ns_section_lines = imap[raw_section_name][0]

    type1_section_found = False

    type2_section_found = False

    ns_name_set = {}
    ns_name_index = 0

    skip_header_lines = 3

    for section_line in ns_section_lines:

        if "Node" in section_line and "Namespace" in section_line:
            token_list = section_line.split()
            if "Node" in token_list[0]:
                ns_name_index = 1

        # End of Section
        if "Number of" in section_line or "No." in section_line:
            break

        if "~~~~Name" in section_line:
            type1_section_found = True
            continue

        elif "=== NAME" in section_line:
            type2_section_found = True
            continue

        # Leave 3 lines and get unique list of ns
        if type1_section_found or type2_section_found:
            if skip_header_lines != 0:
                skip_header_lines = skip_header_lines - 1
                continue

        if type1_section_found:
            ns_name = section_line.split()[ns_name_index]
            ns_name_set.add(ns_name)

        if type2_section_found:
            ns_name = section_line.split()[0].split("/")[1]
            ns_name_set.add(ns_name)

    return list(ns_name_set)


def _identify_nodes(imap):
    nodes1 = _get_nodes_from_latency_info(imap)
    logger.debug("Nodes from latency_info: " + str(nodes1))

    nodes2 = _get_nodes_from_network_info(imap)
    logger.debug("Nodes from network_info: " + str(nodes2))

    if nodes1 and nodes2:
        return nodes1 if len(nodes1) >= len(nodes2) else nodes2
    elif nodes1:
        return nodes1
    elif nodes2:
        return nodes2
    else:
        logger.warning(
            "couldn't find nodes from latency section and info_network section."
        )
        return []


def _get_nodes_from_latency_info(imap):

    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_10")

    logger.info("Parsing section: " + raw_section_name)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    latency_section_lines = imap[raw_section_name][0]
    delimiter_count = 0
    nodes = []
    for latency_line in latency_section_lines:
        # Node data is between two delimiters. So fetch nodeid from data between
        # those two delimiter lines. Exit after encountering 2nd delimiter.
        if len(latency_line) < 2:
            # Empty line or last line
            continue

        if "~~~~~~~" in latency_line or "====" in latency_line:
            delimiter_count += 1

        elif delimiter_count == 1:
            node_id = _get_node_id_from_latency_line(latency_line)
            if node_id is None:
                logger.debug("Node_id absent in latency section line" + latency_line)
            else:
                nodes.append(node_id)

        elif delimiter_count == 2:
            logger.debug("Parsed all the nodes in latency, signing off" + str(nodes))
            return nodes

        else:
            # for the lines appearing before any delimiter
            continue
    return nodes


def _get_nodes_from_network_info(imap):

    sec_id = "ID_49"
    raw_section_name, final_section_name, _ = util.get_section_name_from_id(sec_id)

    logger.info("Parsing section: " + raw_section_name)

    if not util.is_valid_section(
        imap,
        raw_section_name,
        final_section_name,
        util.is_collision_allowed_for_section(sec_id),
    ):
        return

    info_section_lines = "".join(imap[raw_section_name][0])
    nodes = []

    info_network_dict = json.loads(info_section_lines)

    try:
        for group in info_network_dict["groups"]:
            for record in group["records"]:
                nodes.append(record["Node ID"]["raw"])
    except KeyError:
        raise KeyError("New format of Network info detected. Cannot get nodeids.")

    logger.debug("Parsed all the nodes in info_network, signing off" + str(nodes))

    return nodes


def _is_single_column_format(section):
    length = len(section)
    for i in range(length):
        if "==" in section[i]:
            return True
        elif "~~" in section[i]:
            return False


def _get_section_array_from_multicolumn_section(section_lines):
    # Header line could contain any of the given delimiter.
    delimiter_list = ["~", " Statistics", " Configuration"]
    section_list = []
    section = []
    section_found = False

    # If column length is smaller than header than there will be no
    # padding with (~~). There will be no (:) in the header line.
    for line in section_lines:
        if ": " in line:
            if section_found:
                section.append(line)
        else:
            for match_str in delimiter_list:
                if match_str not in line:
                    continue
                if section_found:
                    section_list.append(section)
                    section = []
                section_found = True
                break
            if section_found:
                section.append(line)
    if section_found:
        section_list.append(section)
    return section_list


def _get_node_section_from_parsed_map(node, parsed_map, section_name):
    if node in parsed_map:
        return parsed_map[node][section_name]
    else:
        for nodeid in parsed_map:
            # nodeip = a..basfdfdf:3000 so remove 3000 and than check
            if nodeid.split(":")[0] in node or node.split(":")[0] in nodeid:
                return parsed_map[nodeid][section_name]
    return None


def _update_set_and_bin_counts(parsed_map, section_name):
    ns_section = "namespace"
    set_section = "set"
    bin_section = "bin"
    service_section = "service"

    for node in parsed_map:
        parsed_section = parsed_map[node][section_name]
        if service_section not in parsed_section:
            continue

        if ns_section in parsed_section:
            parsed_section[service_section]["ns_count"] = len(
                parsed_section[ns_section]
            )

            for ns in parsed_section[ns_section]:
                if service_section not in parsed_section[ns_section][ns]:
                    continue

                objmap = parsed_section[ns_section][ns]

                if set_section in objmap:
                    logger.debug("Set count: " + str(len(objmap[set_section])))
                    objmap[service_section]["set_count"] = len(objmap[set_section])
                if bin_section in objmap:
                    bin_count = 0
                    found = False
                    if "num-bin-names" in objmap[bin_section]:
                        bin_count = objmap[bin_section]["num-bin-names"]
                        found = True
                    elif "bin_names" in objmap[bin_section]:
                        bin_count = objmap[bin_section]["bin_names"]
                        found = True
                    if found:
                        logger.debug("Bin count: " + bin_count)
                        objmap[service_section]["bin_count"] = bin_count


def _parse_multi_column_format(section):
    # Ordering of respective nodeid and data will be same in 'nodeids[]'
    # and 'section_array[]'
    nodeids = []
    section_obj = {}
    for line in section:
        if ":" not in line:
            continue
        keyval = line.split(":", 1)
        key = keyval[0].strip()
        vals = keyval[1].strip().split()
        if key == "NODE":
            nodeids.extend(vals)
            for node in nodeids:
                section_obj[node] = {}
            continue

        elif len(nodeids) != 0:
            if len(vals) != len(nodeids):
                continue
            for index, node in enumerate(nodeids):
                if vals[index] != "N/E":
                    section_obj[node][key] = vals[index]
    return section_obj


def _parse_multi_column_stat_sub_section(raw_section, parsed_map, section_name):
    sec_line = raw_section[0]
    section = raw_section[1:]
    if "~" in sec_line:
        split_names = re.split("~+", sec_line)
        sub_section_name = split_names[1]
        if not sub_section_name.strip() and split_names[0]:
            # Lengthy section names might have single ~ at the end, for which we get section name at index 0.
            sub_section_name = split_names[0]
    else:
        sub_section_name = sec_line

    SEC_MAP = {
        "ns_section": "namespace",
        "set_section": "set",
        "bin_section": "bin",
        "service_section": "service",
        "sindex_section": "sindex",
    }
    sec_map = SEC_MAP
    ns_section = sec_map["ns_section"]
    set_section = sec_map["set_section"]
    bin_section = sec_map["bin_section"]
    service_section = sec_map["service_section"]
    sindex_section = sec_map["sindex_section"]

    ns_name = ""
    set_name = ""
    sindex_name = ""
    cursec = ""

    toks = sub_section_name.split()
    if " Namespace " in sub_section_name:
        # ~~~~~~~~~~<ns_name> Namespace Statistics~~~~~~~~~~~
        cursec = ns_section
        ns_name = toks[0]

    elif " Bin " in sub_section_name:
        # ~~~~~<ns_name> Bin Statistics~~~~~~~~~~~~~~~~~~~~~~
        cursec = bin_section
        ns_name = toks[0]

    elif " Set " in sub_section_name:
        # ~~~~~~<ns_name> <set_name> Set Statistics~~~~~~~~~~
        cursec = set_section
        ns_name = toks[0]
        set_name = toks[1]

    elif " Sindex " in sub_section_name:
        # ~~~~~~~<ns_name> <set_name> <sindexname> Statistics~~
        cursec = sindex_section
        ns_name = toks[0]
        set_name = toks[1]
        sindex_name = toks[2]

    elif "Service " in sub_section_name:
        # ~~~~~~~Service Statistics~~~~~~~~~~~~~~
        cursec = service_section

    else:
        logger.info("Unknown header line : " + sub_section_name)
        return
    logger.debug("current_section: " + cursec)

    section_obj = _parse_multi_column_format(section)

    # Put multicolumn parsed data in proper format for statistics section.
    for node in section_obj:
        parsed_sec = _get_node_section_from_parsed_map(node, parsed_map, section_name)
        if parsed_sec is None:
            logger.warning("Nodeid is not in info_network or latency: " + node)
            continue
        # Update Service and Network information.
        if cursec == service_section:
            parsed_sec[service_section] = section_obj[node]

        else:
            # Initialize namespace sections.
            if ns_section not in parsed_sec:
                parsed_sec[ns_section] = {}
            parsed_ns_sec = parsed_sec[ns_section]

            if ns_name not in parsed_ns_sec:
                parsed_ns_sec[ns_name] = {
                    set_section: {},
                    bin_section: {},
                    sindex_section: {},
                    service_section: {},
                }

            # Update Bin, Set, Sindex and Service data in namespace section.
            if cursec == bin_section:
                parsed_ns_sec[ns_name][bin_section] = section_obj[node]

            elif cursec == set_section:
                if set_section not in parsed_ns_sec[ns_name]:
                    parsed_ns_sec[ns_name][set_section] = {}
                parsed_ns_sec[ns_name][set_section][set_name] = section_obj[node]

            elif cursec == sindex_section:
                if sindex_section not in parsed_ns_sec[ns_name]:
                    parsed_ns_sec[ns_name][sindex_section] = {}
                parsed_ns_sec[ns_name][sindex_section][sindex_name] = section_obj[node]

            else:
                parsed_ns_sec[ns_name][service_section] = section_obj[node]
    _update_set_and_bin_counts(parsed_map, section_name)


def _parse_multi_column_config_sub_section(raw_section, parsed_map, section_name):
    sec_line = raw_section[0]
    section = raw_section[1:]

    if "~" in sec_line:
        sub_section_name = re.split("~+", sec_line)[1]
    else:
        sub_section_name = sec_line
    SEC_MAP = {
        "ns_section": "namespace",
        "service_section": "service",
        "network_section": "network",
    }
    sec_map = SEC_MAP
    ns_section = sec_map["ns_section"]
    service_section = sec_map["service_section"]
    network_section = sec_map["network_section"]

    ns_name = ""
    cursec = ""

    toks = sub_section_name.split()
    if " Namespace " in sub_section_name:
        # ~~~~~~~~~~<ns_name> Namespace Configuration~~~~~~~~~~~
        cursec = ns_section
        ns_name = toks[0]

    elif "Network " in sub_section_name:
        # ~~~~~~~Network Configuration~~~~~~~~~~~~~~~~~~~~~~~~~
        cursec = network_section

    elif "Service " in sub_section_name:
        # ~~~~~~~Service Configuration~~~~~~~~~~~~~~
        cursec = service_section

    else:
        logger.info("Unknown header line: " + sub_section_name)
        return
    logger.debug("current_section: " + cursec)

    section_obj = _parse_multi_column_format(section)
    # Put multicolumn parsed data in proper format for config section.
    for node in section_obj:
        parsed_sec = _get_node_section_from_parsed_map(node, parsed_map, section_name)
        if parsed_sec is None:
            logger.warning("Nodeid is not in info_network or latency: " + node)
            continue
        # Update Service and Network information.
        if cursec == service_section:
            parsed_sec[service_section] = section_obj[node]

        elif cursec == network_section:
            parsed_sec[network_section] = section_obj[node]

        else:
            # Initialize namespace sections.
            if ns_section not in parsed_sec:
                parsed_sec[ns_section] = {}
            parsed_ns_sec = parsed_sec[ns_section]

            if ns_name not in parsed_ns_sec:
                parsed_ns_sec[ns_name] = {service_section: {}}

            parsed_ns_sec[ns_name][service_section] = section_obj[node]


def _parse_multi_column_stat_section(stat_section, parsed_map, section_name):
    section_list = _get_section_array_from_multicolumn_section(stat_section)
    for raw_section in section_list:
        _parse_multi_column_stat_sub_section(raw_section, parsed_map, section_name)


def _parse_multi_column_config_section(config_section, parsed_map, section_name):
    section_list = _get_section_array_from_multicolumn_section(config_section)
    for raw_section in section_list:
        _parse_multi_column_config_sub_section(raw_section, parsed_map, section_name)


def _parse_multi_column_sub_section(
    raw_section, parsed_map, final_section_name, parent_section_name
):
    sec_line = raw_section[0]
    section = raw_section[1:]

    if "~" in sec_line:
        sub_section_name = re.split("~+", sec_line)[1]
    else:
        sub_section_name = sec_line
    xdr_section = "xdr"
    dc_section = "dc"
    cluster_section = "cluster"
    cur_sec = ""
    dc_name = ""

    tok = sub_section_name.strip().split()
    if "XDR " in sub_section_name:
        # ~~~~~XDR Statistics/Config~~~~
        cur_sec = xdr_section

    elif "DC" in sub_section_name:
        # ~~~~~DC Statistics/Config~~~~~
        dc_name = tok[0]
        cur_sec = dc_section

    elif "Cluster " in sub_section_name:
        # ~~~~~Cluster Config~~~~
        cur_sec = cluster_section

    else:
        logger.info("Unknown header line: " + sub_section_name)
        return

    logger.debug("current_section: " + cur_sec)

    section_obj = _parse_multi_column_format(section)
    for node in section_obj:
        parsed_sec = _get_node_section_from_parsed_map(
            node, parsed_map, parent_section_name
        )
        if parsed_sec is None:
            logger.warning("Nodeid is not in info_network or latency: " + node)
            continue

        # Update XDR/DC/Cluster information.
        if cur_sec == xdr_section or cur_sec == cluster_section:
            parsed_sec[final_section_name] = section_obj[node]

        elif cur_sec == dc_section:
            if final_section_name not in parsed_sec:
                parsed_sec[final_section_name] = {}
            parsed_sec[final_section_name][dc_name] = section_obj[node]


def _parse_multi_column_section(
    info_section, parsed_map, final_section_name, parent_section_name
):
    section_list = _get_section_array_from_multicolumn_section(info_section)
    for raw_section in section_list:
        _parse_multi_column_sub_section(
            raw_section, parsed_map, final_section_name, parent_section_name
        )


def _init_nodes_for_parsed_json(nodes, parsed_map, section_name):
    for node in nodes:
        if node not in parsed_map:
            parsed_map[node] = {}
        if section_name not in parsed_map[node]:
            parsed_map[node][section_name] = {}


def _parse_single_column_format(info_section, parsed_map, section_name):
    nodes = list(parsed_map.keys())
    json_to_fill = None
    for i in range(len(info_section)):
        if "====" in info_section[i]:
            for node in nodes:
                if node not in info_section[i]:
                    continue

                if section_name not in parsed_map[node]:
                    parsed_map[node][section_name] = {}

                parsed_map[node][section_name]["service"] = {}

                json_to_fill = parsed_map[node][section_name]["service"]
                break
        elif json_to_fill is not None:
            key_val = info_section[i].split()
            json_to_fill[key_val[0]] = key_val[-1].strip()


def _get_histogram_name(latency_line):
    if "====" in latency_line or "~~~~" in latency_line:
        # Assumptions : Histogram name consists of characters from a-z (cases ignored).
        # Name may contain "_" (underscore).
        name = re.findall("[a-z_]+", latency_line, flags=re.IGNORECASE)[0]
        # the latency_line could have '[1m' in it. ignore this 'm' character
        if "[1m" in latency_line:
            return name[1:]
        else:
            return name
    else:
        logger.debug(
            "histogram name validator not present in the argument " + str(latency_line)
        )


# Given a line from latency Section, identifies all the keys and returns it as an array.
# Eg- [ ops/sec, >1ms, >8ms, >16ms]
# Assumption - This line must contain time word in it.
# TODO - Can there be a way to identify without hardcoding anything.
#      - Negation of time regex and absence of "===="/"~~~~" signifies this as a line containing
#      - histogram keys. But this logic is inference from something else. May not hold always.


def _get_histogram_keys(latency_line):
    if "time" not in latency_line:
        logger.debug(
            "histogram keys validator not present in the argument " + str(latency_line)
        )

    latency_line = latency_line.lower()
    keys = latency_line.split()
    key_start_index = 0
    for i in range(len(keys)):
        if keys[i] == "time":
            key_start_index = i
    if len(keys) > 4:
        key_list = ["Time Span" if i == "time" else i for i in keys[key_start_index:]]
        return key_list
    else:
        logger.warning("Number of keys in histogram is less than four " + str(keys))


time_regex = r"\d{2}:\d{2}:\d{2}.*->\d{2}:\d{2}:\d{2}"


def _get_histogram_values(latency_line):
    global time_regex
    if re.findall(time_regex, latency_line):
        values = re.split(time_regex, latency_line, maxsplit=1)[1].split()
        values.insert(0, re.findall(time_regex, latency_line)[0])
        return values


# To identify if a line has node_id, time isprinted in the format
# 15:56:24-GMT->15:56:34", Do a regular expression search on the line.


def _get_node_id_from_latency_line(data_string):
    global time_regex
    if re.search(time_regex, data_string):
        node_id = data_string.split()[0]
        return node_id
    else:
        logger.debug(
            "The argument doesn't contain node_id validator " + str(data_string)
        )
        return None


def _parse_nondefault_section(sec_id, nodes, imap, parsed_map):
    (
        raw_section_name,
        final_section_name,
        parent_section_name,
    ) = util.get_section_name_from_id(sec_id)

    logger.info("Parsing section: " + final_section_name)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    if parent_section_name == "":
        logger.warning("Parent section name not present. Cannot parse section")
        return

    info_section = imap[raw_section_name][0]

    # initialize only if parent section is not present, do not overwrite.
    _init_nodes_for_parsed_json(nodes, parsed_map, parent_section_name)

    _parse_multi_column_section(
        info_section, parsed_map, final_section_name, parent_section_name
    )


def _parse_config_section(nodes, imap, parsed_map):
    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_5")

    logger.info("Parsing section: " + final_section_name)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    config_section = imap[raw_section_name][0]

    logger.debug("invoking format identifier")
    single_column = _is_single_column_format(config_section)

    _init_nodes_for_parsed_json(nodes, parsed_map, final_section_name)

    if single_column:
        _parse_single_column_format(config_section, parsed_map, final_section_name)
    else:
        _parse_multi_column_config_section(
            config_section, parsed_map, final_section_name
        )


def _parse_dc_config_section(nodes, imap, parsed_map):
    sec_id = "ID_7"
    _parse_nondefault_section(sec_id, nodes, imap, parsed_map)


def _parse_xdr_config_section(nodes, imap, parsed_map):
    sec_id = "ID_6"
    _parse_nondefault_section(sec_id, nodes, imap, parsed_map)


def _parse_cluster_config_section(nodes, imap, parsed_map):
    sec_id = "ID_101"
    _parse_nondefault_section(sec_id, nodes, imap, parsed_map)


def _get_stat_sindex_section(imap):
    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_14")

    logger.info("Parsing section: " + final_section_name)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    stat_section = imap[raw_section_name][0]

    del1 = "~~"
    del2 = "Sindex Statistics"
    sec_index = 0
    found = False
    for index, line in enumerate(stat_section):
        if del1 in line or del2 in line:
            sec_index = index
            found = True
            break
    if found:
        return stat_section[sec_index:]


def _parse_stat_section(nodes, imap, parsed_map):
    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_11")

    logger.info("Parsing section: " + final_section_name)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    stat_section = imap[raw_section_name][0]

    logger.debug("invoking format identifier")
    single_column = _is_single_column_format(stat_section)

    _init_nodes_for_parsed_json(nodes, parsed_map, final_section_name)

    if single_column:
        _parse_single_column_format(stat_section, parsed_map, final_section_name)
    else:
        sindex_stat = _get_stat_sindex_section(imap)
        if sindex_stat:
            stat_section.extend(sindex_stat)
        _parse_multi_column_stat_section(stat_section, parsed_map, final_section_name)


def _parse_dc_stat_section(nodes, imap, parsed_map):
    sec_id = "ID_13"
    _parse_nondefault_section(sec_id, nodes, imap, parsed_map)


def _parse_xdr_stat_section(nodes, imap, parsed_map):
    sec_id = "ID_12"
    _parse_nondefault_section(sec_id, nodes, imap, parsed_map)


def _parse_latency_section(nodes, imap, parsed_map):
    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_10")

    logger.info("Parsing section: " + final_section_name)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    latency_section = imap[raw_section_name][0]
    histogram = ""

    _init_nodes_for_parsed_json(nodes, parsed_map, final_section_name)

    section_length = len(latency_section)
    for i in range(section_length):
        # ~~~~~~~~~~~read Latency~~~~~~~~~~~~~~~
        if "====" in latency_section[i] or "~~~~" in latency_section[i]:
            histogram = _get_histogram_name(latency_section[i])
            logger.info("Histogram name: " + histogram)
            for key in parsed_map:
                parsed_map[key][final_section_name][histogram] = {}

        # Node                 Time   Ops/Sec   >1Ms   >8Ms   >64Ms
        elif "time" in latency_section[i].lower():
            keys = _get_histogram_keys(latency_section[i])

        # Actual data line contain time_regex eg(07:58:13->07:58:23)
        elif not re.search(time_regex, latency_section[i]):
            continue

        else:
            node_id = _get_node_id_from_latency_line(latency_section[i])
            logger.debug("Got node_id: " + str(node_id))

            if node_id is None and len(latency_section[i]) > 2:
                logger.warning("Node_id is None " + str(latency_section[i]))
                continue
            else:
                values = _get_histogram_values(latency_section[i])
                if values is None:
                    if len(latency_section[i]) > 2:
                        logger.warning(
                            "get_histogram keys returned a NULL set for keys "
                            + str(latency_section[i])
                        )
                    else:
                        logger.debug("latency section contains an empty string")

                if len(keys) != len(values):
                    logger.warning(
                        "Histogram: number of keys and values do not match "
                        + str(keys)
                        + " "
                        + str(values)
                    )
                    continue
                else:
                    for i in range(len(values)):
                        if node_id in parsed_map:
                            parsed_map[node_id][final_section_name][histogram][
                                keys[i]
                            ] = values[i]


def _parse_sindex_info_section(nodes, imap, parsed_map):
    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_51")

    logger.info("Parsing section: " + final_section_name)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    sindexdata = {}
    sindex_section = imap[raw_section_name][0]

    _init_nodes_for_parsed_json(nodes, parsed_map, final_section_name)

    # Get the starting of data
    # "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Secondary Index Information~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
    # "               Node          Index       Namespace         Set       Bin   State     Sync     Keys     Objects   si_accounted_memory     q           w          d       s   \n"
    # "                  .           Name               .           .      Type       .    State        .           .                     .     .           .          .       .   \n"
    # "10.103.208.193:3000   bid_creative   dsp_event_log   video_bid   NUMERIC      RW   synced   510      7616730                   18432     0     7635733      18967       0   \n"
    start_index = 0
    for index in range(len(sindex_section)):
        if re.search("~~", sindex_section[index]):
            start_index = index + 3
            break
    # Update sindex info for respective nodeid
    for index in range(len(sindex_section)):
        if index < start_index:
            continue

        l = re.split(r"\ +", sindex_section[index])

        # End of section
        if len(l) < 5:
            break
        node_id = l[0]
        if node_id not in sindexdata:
            sindexdata[node_id] = {}
            sindexdata[node_id][final_section_name] = {}
            sindexdata[node_id][final_section_name]["index"] = []
        index_obj = {}
        index_obj["index_name"] = l[1]
        index_obj["namespace"] = l[2]
        index_obj["set"] = l[3]
        index_obj["bin_type"] = l[4]
        index_obj["state"] = l[5]
        index_obj["sync_state"] = l[6]
        # Extra added info, previously not there.
        if len(l) > 8:
            index_obj["keys"] = l[7]
            index_obj["objects"] = l[8]
            index_obj["si_accounted_memory"] = l[9]
        sindexdata[node_id][final_section_name]["index"].append(index_obj)

    # Update sindex count for respective nodes.
    for node_id in sindexdata:
        sindexdata[node_id][final_section_name]["index_count"] = len(
            sindexdata[node_id][final_section_name]["index"]
        )
        if node_id in parsed_map:
            parsed_map[node_id][final_section_name] = sindexdata[node_id][
                final_section_name
            ]
        else:
            logger.info("Node id not in nodes section: " + node_id)
    # type_check_raw_all(nodes, final_section_name, parsed_map)


# "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Features~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n",
##  "NODE           :   192.168.16.174:3000   192.168.16.175:3000   192.168.16.176:3000   \n",
##  "AGGREGATION    :   NO                    NO                    NO                    \n",
##  "BATCH          :   NO                    NO                    NO                    \n",


def _parse_features(nodes, imap, parsed_map):
    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_87")

    logger.info("Parsing section: " + final_section_name)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        _init_nodes_for_parsed_json(nodes, parsed_map, final_section_name)
        _identify_features_from_stats(nodes, imap, parsed_map, final_section_name)
        return

    featurelist = [
        "KVS",
        "UDF",
        "BATCH",
        "SCAN",
        "SINDEX",
        "QUERY",
        "AGGREGATION",
        "LDT",
        "XDR ENABLED",
        "XDR DESTINATION",
    ]
    feature_section = imap[raw_section_name][0]
    featureobj = _parse_multi_column_format(feature_section)

    # Test all features are valid in featureobj.
    for node in featureobj:
        badkeys = []
        for feature in featureobj[node]:
            if feature in featurelist:
                continue
            if util.is_bool(featureobj[node][feature]):
                raise Exception(
                    "Feature list changed. Please check feature list section. feature_name: "
                    + feature
                    + " featurelist: "
                    + str(featurelist)
                )
            else:
                # "invalid literal for int() with base 10: 'partition'\n"
                badkeys.append(feature)

        for feature in badkeys:
            featureobj[node].pop(feature, None)

    for node in parsed_map:
        if node not in featureobj:
            continue
        parsed_map[node][final_section_name] = featureobj[node]


def _parse_hist_dump(section):
    namespace = None
    parsed_section = {}
    if not section or len(section) <= 0:
        return namespace, parsed_section

    parsed_section = eval(section[0])

    if not parsed_section:
        return namespace, parsed_section

    for node, hist_dump in parsed_section.items():
        if (
            not node
            or not hist_dump
            or isinstance(hist_dump, Exception)
            or ":" not in hist_dump
        ):
            continue

        namespace = hist_dump.split(":")[0].strip()
        break

    return namespace, parsed_section


def _parse_hist_dump_section(sec_id, nodes, imap, parsed_map):
    (
        raw_section_name,
        final_section_name,
        parent_section_name,
    ) = util.get_section_name_from_id(sec_id)
    logger.info("Parsing section: " + final_section_name)

    if not util.is_valid_section(
        imap,
        raw_section_name,
        final_section_name,
        collision_allowed=util.is_collision_allowed_for_section(sec_id),
    ):
        return

    hist_dump_sections = imap[raw_section_name]

    for hist_dump_section in hist_dump_sections:
        namespace, hist_dump_section = _parse_hist_dump(hist_dump_section)
        if not namespace:
            continue

        for node, hist_dump in hist_dump_section.items():
            map_ptr = None
            if node not in parsed_map:
                parsed_map[node] = {}
            map_ptr = parsed_map[node]

            if parent_section_name:
                if parent_section_name not in map_ptr:
                    map_ptr[parent_section_name] = {}
                map_ptr = map_ptr[parent_section_name]

            if final_section_name not in map_ptr:
                map_ptr[final_section_name] = {}
            map_ptr = map_ptr[final_section_name]

            map_ptr[namespace] = copy.deepcopy(hist_dump)


def _parse_hist_dump_ttl(nodes, imap, parsed_map):
    sec_id = "ID_98"
    _parse_hist_dump_section(sec_id, nodes, imap, parsed_map)


def _parse_hist_dump_objsz(nodes, imap, parsed_map):
    sec_id = "ID_99"
    _parse_hist_dump_section(sec_id, nodes, imap, parsed_map)


def _parse_asinfo_node_value_section(sec_id, imap, parsed_map):
    (
        raw_section_name,
        final_section_name,
        parent_section_name,
    ) = util.get_section_name_from_id(sec_id)

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    for raw_dump in imap[raw_section_name]:
        try:
            for node, val in eval(raw_dump[0]).items():
                map_ptr = None
                if node not in parsed_map:
                    parsed_map[node] = {}
                map_ptr = parsed_map[node]

                if parent_section_name:
                    if parent_section_name not in map_ptr:
                        map_ptr[parent_section_name] = {}
                    map_ptr = map_ptr[parent_section_name]

                map_ptr[final_section_name] = val

        except Exception:
            pass


def _parse_endpoints(nodes, imap, parsed_map):
    sec_id = "ID_55"
    _parse_asinfo_node_value_section(sec_id, imap, parsed_map)


def _parse_services(nodes, imap, parsed_map):
    sec_id = "ID_56"
    _parse_asinfo_node_value_section(sec_id, imap, parsed_map)


def _parse_roster_section(nodes, imap, parsed_map):
    sec_id = "ID_113"
    _parse_asinfo_node_value_section(sec_id, imap, parsed_map)


def _stat_exist_in_statistics(statmap, statlist):
    if not statmap:
        return False
    if not statlist or len(statlist) == 0:
        return True
    for stat in statlist:
        # Stat value should be greater than zero, so it should be integer too?
        if (
            stat in statmap
            and statmap[stat]
            and not isinstance(statmap[stat], str)
            and statmap[stat] > 0
        ):
            return True
    return False


def _is_statistics_parsed(nodes, parsed_map):
    sec_id = "ID_11"
    raw_section_name, final_section_name, _ = util.get_section_name_from_id(sec_id)
    for node in parsed_map:
        if final_section_name in parsed_map[node]:
            return True
    return False


def _identify_features_from_stats(nodes, imap, parsed_map, section_name):

    # check for 'statistics' section.
    raw_section_name, final_section_name, _ = util.get_section_name_from_id("ID_11")

    if not util.is_valid_section(imap, raw_section_name, final_section_name):
        return

    if not _is_statistics_parsed(nodes, parsed_map):
        _parse_stat_section(nodes, imap, parsed_map)

    if not _is_statistics_parsed(nodes, parsed_map):
        logger.warning("Statistics not present. Cannot get feature.")
        return

    for node in parsed_map:
        service_map = None
        ns_map = None
        service_sec = "service"
        ns_sec = "namespace"

        featureobj = {
            "KVS": "NO",
            "UDF": "NO",
            "BATCH": "NO",
            "SCAN": "NO",
            "SINDEX": "NO",
            "QUERY": "NO",
            "AGGREGATION": "NO",
            "LDT": "NO",
            "XDR ENABLED": "NO",
            "XDR DESTINATION": "NO",
        }
        if (
            final_section_name in parsed_map[node]
            and service_sec in parsed_map[node][final_section_name]
        ):
            service_map = parsed_map[node][final_section_name][service_sec]

        if (
            final_section_name in parsed_map[node]
            and ns_sec in parsed_map[node][final_section_name]
        ):
            ns_map = parsed_map[node][final_section_name][ns_sec]

        if _stat_exist_in_statistics(
            service_map, ["stat_read_reqs", "stat_write_reqs"]
        ):
            featureobj["KVS"] = "YES"

        elif ns_map:
            for namespace in ns_map:
                if service_sec in ns_map[namespace]:
                    ns_service_map = ns_map[namespace][service_sec]
                    if _stat_exist_in_statistics(
                        ns_service_map,
                        [
                            "client_read_error",
                            "client_read_success",
                            "client_write_error",
                            "client_write_success",
                        ],
                    ):
                        featureobj["KVS"] = "YES"
                        break

        if _stat_exist_in_statistics(service_map, ["udf_read_reqs", "udf_write_reqs"]):
            featureobj["UDF"] = "YES"

        elif ns_map:
            for namespace in ns_map:
                if service_sec in ns_map[namespace]:
                    ns_service_map = ns_map[namespace][service_sec]
                    if _stat_exist_in_statistics(
                        ns_service_map, ["client_udf_complete", "client_udf_error"]
                    ):
                        featureobj["UDF"] = "YES"
                        break

        if _stat_exist_in_statistics(
            service_map, ["batch_initiate", "batch_index_initiate"]
        ):
            featureobj["BATCH"] = "YES"

        if _stat_exist_in_statistics(
            service_map,
            [
                "tscan_initiate",
                "basic_scans_succeeded",
                "basic_scans_failed",
                "aggr_scans_succeeded" "aggr_scans_failed",
                "udf_bg_scans_succeeded",
                "udf_bg_scans_failed",
            ],
        ):
            featureobj["SCAN"] = "YES"
        elif ns_map:
            for namespace in ns_map:
                if service_sec in ns_map[namespace]:
                    ns_service_map = ns_map[namespace][service_sec]
                    if _stat_exist_in_statistics(
                        ns_service_map,
                        [
                            "scan_basic_complete",
                            "scan_basic_error",
                            "scan_aggr_complete",
                            "scan_aggr_error",
                            "scan_udf_bg_complete",
                            "scan_udf_bg_error",
                        ],
                    ):
                        featureobj["SCAN"] = "YES"
                        break

        if _stat_exist_in_statistics(service_map, ["sindex-used-bytes-memory"]):
            featureobj["SINDEX"] = "YES"
        elif ns_map:
            for namespace in ns_map:
                if service_sec in ns_map[namespace]:
                    ns_service_map = ns_map[namespace][service_sec]
                    if _stat_exist_in_statistics(
                        ns_service_map, ["memory_used_sindex_bytes"]
                    ):
                        featureobj["SINDEX"] = "YES"
                        break

        if _stat_exist_in_statistics(service_map, ["query_reqs", "query_success"]):
            featureobj["QUERY"] = "YES"
        elif ns_map:
            for namespace in ns_map:
                if service_sec in ns_map[namespace]:
                    ns_service_map = ns_map[namespace][service_sec]
                    if _stat_exist_in_statistics(
                        ns_service_map, ["query_reqs", "query_success"]
                    ):
                        featureobj["QUERY"] = "YES"
                        break

        if _stat_exist_in_statistics(
            service_map,
            [
                "query_aggr_complete",
                "query_aggr_error",
                "query_aggr_abort",
                # renamed/removed on 5.7
                "query_agg_success",
                "query_agg_error",
                "query_agg_abort",
                "query_agg",
            ],
        ):
            featureobj["AGGREGATION"] = "YES"
        elif ns_map:
            for namespace in ns_map:
                if service_sec in ns_map[namespace]:
                    ns_service_map = ns_map[namespace][service_sec]
                    if _stat_exist_in_statistics(
                        ns_service_map,
                        [
                            "query_aggr_complete",
                            "query_aggr_error",
                            "query_aggr_abort",
                            # renamed/removed on 5.7
                            "query_agg_success",
                            "query_agg_error",
                            "query_agg_abort",
                            "query_agg",
                        ],
                    ):
                        featureobj["AGGREGATION"] = "YES"
                        break

        if _stat_exist_in_statistics(
            service_map,
            [
                "sub-records",
                "ldt-writes",
                "ldt-reads",
                "ldt-deletes",
                "ldt_writes",
                "ldt_reads",
                "ldt_deletes",
                "sub_objects",
            ],
        ):
            featureobj["LDT"] = "YES"
        elif ns_map:
            for namespace in ns_map:
                if service_sec in ns_map[namespace]:
                    ns_service_map = ns_map[namespace][service_sec]
                    if _stat_exist_in_statistics(
                        ns_service_map,
                        [
                            "ldt-writes",
                            "ldt-reads",
                            "ldt-deletes",
                            "ldt_writes",
                            "ldt_reads",
                            "ldt_deletes",
                        ],
                    ):
                        featureobj["LDT"] = "YES"
                        break

        if _stat_exist_in_statistics(
            service_map, ["stat_read_reqs_xdr", "xdr_read_success", "xdr_read_error"]
        ):
            featureobj["XDR ENABLED"] = "YES"

        if _stat_exist_in_statistics(service_map, ["stat_write_reqs_xdr"]):
            featureobj["XDR DESTINATION"] = "YES"
        elif ns_map:
            for namespace in ns_map:
                if service_sec in ns_map[namespace]:
                    ns_service_map = ns_map[namespace][service_sec]
                    if _stat_exist_in_statistics(
                        ns_service_map,
                        ["xdr_write_success", "xdr_client_write_success"],
                    ):
                        featureobj["XDR DESTINATION"] = "YES"
                        break
        parsed_map[node][section_name] = featureobj


def _get_meta_from_network_info(imap, nodes):
    sec_id = "ID_49"
    raw_section_name, final_section_name, _ = util.get_section_name_from_id(sec_id)

    logger.info("Parsing section: " + raw_section_name)

    if not util.is_valid_section(
        imap,
        raw_section_name,
        final_section_name,
        util.is_collision_allowed_for_section(sec_id),
    ):
        return {}

    info_section_lines = "".join(imap[raw_section_name][0])
    info_network_dict = json.loads(info_section_lines)
    meta_map = {}

    try:
        for group in info_network_dict["groups"]:
            for record in group["records"]:
                node = record["Node ID"]["converted"]
                build = record["Build"]["converted"]
                node_id = record["Node ID"]["converted"]
                edition = "EE"

                if "C-" in build:
                    edition = "CE"

                meta_map[node] = {}
                meta_map[node]["asd_build"] = build
                meta_map[node]["edition"] = edition
                meta_map[node]["node_id"] = node_id

    except KeyError:
        raise KeyError(
            "New format of Network info detected. Cannot get network metadata."
        )

    return meta_map


def _get_ip_from_network_info(imap, nodes):
    sec_id = "ID_49"
    raw_section_name, final_section_name, _ = util.get_section_name_from_id(sec_id)
    logger.info("Parsing section: " + raw_section_name)

    if not util.is_valid_section(
        imap,
        raw_section_name,
        final_section_name,
        util.is_collision_allowed_for_section(sec_id),
    ):
        return {}

    info_section_lines = "".join(imap[raw_section_name][0])
    ip_map = {}

    info_network_dict = json.loads(info_section_lines)

    try:
        for group in info_network_dict["groups"]:
            for record in group["records"]:
                node = record["Node ID"]["raw"]
                ip = record["IP"]["converted"]

                ip_map[node] = {}
                ip_map[node]["ip"] = ip

    except KeyError:
        raise KeyError(
            "New format of Network info detected. Cannot get network metadata."
        )

    return ip_map
