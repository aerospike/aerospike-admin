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

from lib.collectinfo_parser.full_parser import parse_info_all
from lib.utils import util

class CollectinfoNode(object):

    def __init__(self, timestamp, node_name, node_id="N/E"):
        self.timestamp = timestamp
        self.node_name = node_name
        self.node_id = node_id
        self.xdr_build = "N/E"
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

    def set_xdr_build(self, xdr_build):
        self.xdr_build = xdr_build

    def set_asd_build(self, asd_build):
        self.asd_build = asd_build

    def set_cluster_name(self, cluster_name):
        self.cluster_name = cluster_name

    def set_asd_version(self, asd_version):
        self.asd_version = util.convert_edition_to_shortform(asd_version)


class CollectinfoSnapshot(object):

    def __init__(self, cluster_name, timestamp, cinfo_data, cinfo_file):
        self.cluster_name = cluster_name
        self.timestamp = timestamp
        self.nodes = {}
        self.node_names = {}
        self.cinfo_data = cinfo_data
        self.cinfo_file = cinfo_file
        self._initialize_nodes()

    def _initialize_nodes(self):
        try:
            self._set_nodes(self.get_node_names())
            self._set_node_id()
            self._set_ip()
            self._set_xdr_build()
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

    def get_node_names(self):
        if not self.node_names:
            if self.cinfo_data:
                node_names = self.cinfo_data.keys()
            else:
                return {}

            for node_name in node_names:
                self.node_names[node_name] = node_name
        return copy.deepcopy(self.node_names)

    def get_data(self, type="", stanza=""):
        data = {}

        if not type or not self.cinfo_data:
            return data

        try:
            # return copy.deepcopy(self.cinfo_data[type][stanza])
            for node, node_data in self.cinfo_data.iteritems():
                try:
                    if not node or not node_data:
                        continue

                    if not 'as_stat' in node_data or type not in node_data['as_stat']:
                        continue

                    if node not in data:
                        data[node] = {}

                    d = node_data['as_stat'][type]

                    if not stanza:
                        data[node] = copy.deepcopy(d)
                        continue

                    if stanza in ['namespace', 'bin', 'bins', 'set', 'sindex']:
                        d = d["namespace"]

                        for ns_name in d.keys():
                            try:
                                if stanza == "namespace":
                                    data[node][ns_name] = copy.deepcopy(d[ns_name]["service"])

                                elif stanza == "bin" or stanza == "bins":
                                    data[node][ns_name] = copy.deepcopy(d[ns_name][stanza])

                                elif stanza in ["set", "sindex"]:

                                    for _name in d[ns_name][stanza]:
                                        _key = "%s %s" % (ns_name, _name)
                                        data[node][_key] = copy.deepcopy(d[ns_name][stanza][_name])

                            except Exception:
                                pass

                    elif type == "meta_data" and stanza in ["endpoints", "services"]:
                        try:
                            data[node] = copy.deepcopy(d[stanza]).split(';')
                        except Exception:
                            data[node] = copy.deepcopy(d[stanza])

                    elif type == "meta_data" and stanza == "edition":
                        edition = copy.deepcopy(d[stanza])
                        data[node] = util.convert_edition_to_shortform(edition)

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
            for node, node_data in self.cinfo_data.iteritems():
                try:
                    if not node or not node_data:
                        continue

                    if not 'sys_stat' in node_data or stanza not in node_data['sys_stat']:
                        continue

                    data[node] = node_data['sys_stat'][stanza]

                except Exception:
                    data[node] = {}

        except Exception:
            pass

        return data

    def get_node(self, node_key):
        if node_key in self.nodes:
            return [self.nodes[node_key]]
        else:
            return [CollectinfoNode(self.timestamp, node_key, node_key)]

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
            principal="0"
            for n in self.nodes.itervalues():
                if n.node_id == 'N/E':
                    if self._get_node_count() == 1:
                        return n.node_id
                    return "UNKNOWN_PRINCIPAL"
                if n.node_id.zfill(16) > principal.zfill(16):
                    principal=n.node_id
            return principal
        except Exception:
            return "UNKNOWN_PRINCIPAL"

    def get_xdr_build(self):
        xdr_build={}
        try:
            for node in self.nodes:
                xdr_build[node]=self.nodes[node].xdr_build
        except Exception:
            pass
        return xdr_build

    def get_asd_build(self):
        asd_build={}
        try:
            for node in self.nodes:
                asd_build[node]=self.nodes[node].asd_build
        except Exception:
            pass
        return asd_build

    def get_asd_version(self):
        asd_version={}
        try:
            for node in self.nodes:
                asd_version[node]=self.nodes[node].asd_version
        except Exception:
            pass
        return asd_version

    def get_cluster_name(self):
        cluster_name={}
        try:
            for node in self.nodes:
                cluster_name[node]=self.nodes[node].cluster_name
        except Exception:
            pass
        return cluster_name

    def _set_nodes(self, nodes):
        for node in nodes:
            self.node_names[node] = node
            self.nodes[node] = CollectinfoNode(self.timestamp, node)

    def _get_node_count(self):
        return len(self.nodes.keys())

    def _set_node_id(self):
        for node in self.nodes:
            try:
                self.nodes[node].set_node_id(self.cinfo_data[node]['as_stat']['meta_data']['node_id'])
            except Exception:
                pass

    def _set_ip(self):

        for node in self.nodes:
            try:
                self.nodes[node].set_ip(self.cinfo_data[node]['as_stat']['meta_data']['ip'])
            except Exception:
                pass

    def _set_xdr_build(self):

        for node in self.nodes:
            try:
                self.nodes[node].set_xdr_build(self.cinfo_data[node]['as_stat']['meta_data']['xdr_build'])
            except Exception:
                pass

    def _set_asd_build(self):

        for node in self.nodes:
            try:
                self.nodes[node].set_asd_build(self.cinfo_data[node]['as_stat']['meta_data']['asd_build'])
            except Exception:
                pass

    def _set_asd_version(self):

        for node in self.nodes:
            try:
                self.nodes[node].set_asd_version(self.cinfo_data[node]['as_stat']['meta_data']['edition'])
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
        parse_info_all(files, self.data, True)
        if self.data:
            for ts in self.data:
                if self.data[ts]:
                    for cl in self.data[ts]:
                        self.snapshots[ts] = CollectinfoSnapshot(cl, ts, self.data[ts][cl], cinfo_path)

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