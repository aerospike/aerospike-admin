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

from lib.utils import common, util
from lib.utils.lookup_dict import LookupDict

from .collectinfo_parser import full_parser


class _CollectinfoNode(object):
    def __init__(self, timestamp, node_name, node_id="N/E"):
        self.timestamp = timestamp
        self.node_name = node_name
        self.node_id = node_id
        self.asd_build = "N/E"
        self.asd_version = "N/E"
        self.cluster_name = "null"
        self.ip = "N/E"

    def sock_name(self, use_fqdn):
        return self.ip

    def set_ip(self, ip):
        self.ip = ip

    def set_node_id(self, node_id):
        try:
            if node_id.startswith("*"):
                node_id = node_id[1:]
        except Exception:
            pass
        self.node_id = node_id

    def set_asd_build(self, asd_build):
        self.asd_build = asd_build

    def set_cluster_name(self, cluster_name):
        self.cluster_name = cluster_name

    def set_asd_version(self, asd_version):
        self.asd_version = util.convert_edition_to_shortform(asd_version)


class _CollectinfoSnapshot:
    def __init__(self, cluster_name, timestamp, cinfo_data, cinfo_file):
        self.cluster_name = cluster_name
        self.timestamp = timestamp
        self.nodes = {}
        self.node_names = {}
        self.node_ids = {}
        self.cinfo_data = self.ns_name_fault_check(cinfo_data)
        self.cinfo_file = cinfo_file
        self.node_lookup = LookupDict()
        self._initialize_nodes()

    def _initialize_nodes(self):
        try:
            self._set_nodes(self.get_node_names())
            self._set_node_id()
            self._set_ip()
            self._set_asd_build()
            self._set_asd_version()
            self._set_cluster_name()
        except Exception:
            pass

    def destroy(self):
        try:
            del self.timestamp
            del self.cinfo_data
            del self.cinfo_file
            del self.nodes
            del self.node_names
        except Exception:
            pass

    def ns_name_fault_check(self, value):
        try:
            for node, node_data in value.items():
                if not node or not node_data:
                    continue
                if "as_stat" not in node_data:
                    continue

                if "config" in node_data["as_stat"]:
                    if "namespace" in node_data["as_stat"]["config"]:
                        for ns in value[node]["as_stat"]["config"]["namespace"].keys():
                            if " " in ns:
                                del value[node]["as_stat"]["config"]["namespace"][ns]

                if "statistics" in node_data["as_stat"]:
                    if "namespace" in node_data["as_stat"]["statistics"]:
                        for ns in value[node]["as_stat"]["statistics"][
                            "namespace"
                        ].keys():
                            if " " in ns:
                                del value[node]["as_stat"]["statistics"]["namespace"][
                                    ns
                                ]
                                continue
                            if (
                                "set"
                                in value[node]["as_stat"]["statistics"]["namespace"][ns]
                            ):
                                for sets in list(
                                    value[node]["as_stat"]["statistics"]["namespace"][
                                        ns
                                    ]["set"].keys()
                                ):
                                    if " " in sets:
                                        del value[node]["as_stat"]["statistics"][
                                            "namespace"
                                        ][ns]["set"][sets]

        except Exception:
            pass
        return value

    def get_node_displaynames(self):
        node_names = {}

        for key in self.get_node_names():
            if util.is_valid_ip_port(key):
                node_names[key] = key
            else:
                node_names[key] = self.node_lookup.get_shortname(
                    key, min_prefix_len=20, min_suffix_len=5
                )

        return node_names

    def get_node_names(self, nodes=None):
        if not self.node_names:
            if self.cinfo_data:
                node_names = self.cinfo_data.keys()
            else:
                return {}

            for node_name in node_names:
                self.node_names[node_name] = node_name
        return copy.deepcopy(self.node_names)

    def get_node_ids(self, nodes=None):
        if not self.node_ids:
            if not self.nodes:
                return {}

            for key, node in self.nodes.items():
                self.node_ids[key] = node.node_id

        return copy.deepcopy(self.node_ids)

    def get_data(self, type="", stanza=""):
        data = {}

        if not type or not self.cinfo_data:
            return data

        try:
            # return copy.deepcopy(self.cinfo_data[type][stanza])
            for node, node_data in self.cinfo_data.items():
                try:
                    if not node or not node_data:
                        continue

                    if "as_stat" not in node_data or type not in node_data["as_stat"]:
                        continue

                    if node not in data:
                        data[node] = {}

                    d = node_data["as_stat"][type]

                    if not stanza:
                        data[node] = copy.deepcopy(d)
                        continue

                    if stanza in [
                        "namespace",
                        "bin",
                        "bins",
                        "set",
                        "sindex",
                        "namespace_list",
                    ]:
                        d = d["namespace"]

                        if stanza == "namespace_list":
                            data[node] = list(d.keys())
                            continue

                        for ns_name in d.keys():
                            try:
                                if stanza == "namespace":
                                    data[node][ns_name] = copy.deepcopy(
                                        d[ns_name]["service"]
                                    )

                                elif stanza == "bin" or stanza == "bins":
                                    data[node][ns_name] = copy.deepcopy(
                                        d[ns_name][stanza]
                                    )

                                elif stanza == "set":
                                    for _name in d[ns_name][stanza]:
                                        _key = "%s %s" % (ns_name, _name)
                                        data[node][_key] = copy.deepcopy(
                                            d[ns_name][stanza][_name]
                                        )

                                elif stanza == "sindex":
                                    for _name in d[ns_name][stanza]:
                                        try:
                                            set = d[ns_name][stanza][_name]["set"]
                                            _key = "%s %s %s" % (ns_name, set, _name)
                                        except Exception:
                                            continue

                                        data[node][_key] = copy.deepcopy(
                                            d[ns_name][stanza][_name]
                                        )

                            except Exception:
                                pass

                    elif type == "meta_data" and stanza in ["endpoints", "services"]:
                        try:
                            data[node] = copy.deepcopy(d[stanza]).split(";")
                        except Exception:
                            data[node] = copy.deepcopy(d[stanza])

                    elif type == "meta_data" and stanza == "edition":
                        edition = copy.deepcopy(d[stanza])
                        data[node] = util.convert_edition_to_shortform(edition)

                    elif type == "histogram" and stanza == "object-size":
                        if stanza in d:
                            data[node] = copy.deepcopy(d[stanza])

                        else:
                            # old collectinfo does not have object-size-logarithmic
                            # it should return objsz if server version is old
                            as_version = node_data["as_stat"]["meta_data"]["asd_build"]
                            if (
                                not common.is_new_histogram_version(as_version)
                                and "objsz" in d
                            ):
                                data[node] = copy.deepcopy(d["objsz"])

                            else:
                                data[node] = {}

                    else:
                        data[node] = copy.deepcopy(d[stanza])

                except Exception:
                    data[node] = {}

        except Exception:
            pass

        return data

    def get_sys_data(self, stanza=""):
        data = {}

        if not type or not stanza or not self.cinfo_data:
            return data

        try:
            for node, node_data in self.cinfo_data.items():
                try:
                    if not node or not node_data:
                        continue

                    if (
                        "sys_stat" not in node_data
                        or stanza not in node_data["sys_stat"]
                    ):
                        continue

                    data[node] = node_data["sys_stat"][stanza]

                except Exception:
                    data[node] = {}

        except Exception:
            pass

        return data

    def get_node(self, node_key):
        if node_key in self.nodes:
            return [self.nodes[node_key]]
        else:
            return [_CollectinfoNode(self.timestamp, node_key, node_key)]

    def get_configs(self, stanza=""):
        return self.get_data(type="config", stanza=stanza)

    def get_statistics(self, stanza=""):
        return self.get_data(type="statistics", stanza=stanza)

    def get_histograms(self, stanza=""):
        return self.get_data(type="histogram", stanza=stanza)

    def get_summary(self, stanza=""):
        return self.get_data(type="summary", stanza=stanza)

    def get_expected_principal(self):
        try:
            principal = "0"
            for n in self.nodes.values():
                if n.node_id == "N/E":
                    if self._get_node_count() == 1:
                        return n.node_id
                    return "UNKNOWN_PRINCIPAL"
                if n.node_id.zfill(16) > principal.zfill(16):
                    principal = n.node_id
            return principal
        except Exception:
            return "UNKNOWN_PRINCIPAL"

    def get_asd_build(self):
        asd_build = {}
        try:
            for node in self.nodes:
                asd_build[node] = self.nodes[node].asd_build
        except Exception:
            pass
        return asd_build

    def get_asd_version(self):
        asd_version = {}
        try:
            for node in self.nodes:
                asd_version[node] = self.nodes[node].asd_version
        except Exception:
            pass
        return asd_version

    def get_cluster_name(self):
        cluster_name = {}
        try:
            for node in self.nodes:
                cluster_name[node] = self.nodes[node].cluster_name
        except Exception:
            pass
        return cluster_name

    def _set_nodes(self, nodes):
        for node in nodes:
            self.node_names[node] = node
            self.nodes[node] = _CollectinfoNode(self.timestamp, node)
            self.node_lookup[node] = node

    def _get_node_count(self):
        return len(self.nodes.keys())

    def _set_node_id(self):
        for node in self.nodes:
            try:
                self.nodes[node].set_node_id(
                    self.cinfo_data[node]["as_stat"]["meta_data"]["node_id"]
                )
            except Exception:
                pass

    def _set_ip(self):

        for node in self.nodes:
            try:
                self.nodes[node].set_ip(
                    self.cinfo_data[node]["as_stat"]["meta_data"]["ip"]
                )
            except Exception:
                pass

    def _set_asd_build(self):

        for node in self.nodes:
            try:
                self.nodes[node].set_asd_build(
                    self.cinfo_data[node]["as_stat"]["meta_data"]["asd_build"]
                )
            except Exception:
                pass

    def _set_asd_version(self):

        for node in self.nodes:
            try:
                self.nodes[node].set_asd_version(
                    self.cinfo_data[node]["as_stat"]["meta_data"]["edition"]
                )
            except Exception:
                pass

    def _set_cluster_name(self):

        for node in self.nodes:
            try:
                self.nodes[node].set_cluster_name(self.cluster_name)
            except Exception:
                pass


class CollectinfoLog(object):
    def __init__(self, cinfo_path, files, reader):
        self.files = files
        self.reader = reader
        self.snapshots = {}
        self.data = {}
        self.license_data_usage = {}
        full_parser.parse_collectinfo_files(
            files, self.data, self.license_data_usage, True
        )

        if self.data:
            for ts in sorted(self.data.keys(), reverse=True):
                if self.data[ts]:
                    for cl in self.data[ts]:
                        cinfo_data = self.data[ts][cl]
                        if cinfo_data and not isinstance(cinfo_data, Exception):
                            self.snapshots[ts] = _CollectinfoSnapshot(
                                cl, ts, cinfo_data, cinfo_path
                            )

                    # Since we are not dealing with timeseries we should fetch only one snapshot
                    break

    def destroy(self):
        try:
            del self.files
            del self.reader
            for sn in self.snapshots:
                self.snapshots[sn].destroy()
            del self.snapshots
            del self.data
        except Exception:
            pass

    def get_snapshots(self):
        return self.snapshots
