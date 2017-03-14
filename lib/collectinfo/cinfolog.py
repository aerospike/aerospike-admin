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
from lib.utils import logutil
from lib.utils.constants import *
from lib.collectinfo.reader import CollectinfoReader


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
        if asd_version.lower() in ['enterprise', 'true']:
            self.asd_version = "Enterprise"
        elif asd_version.lower() in ['community', 'false']:
            self.asd_version = "Community"
        else:
            self.asd_version = "N/E"


class CollectinfoLog(object):

    def __init__(self, timestamp, cinfo_file, reader):
        self.timestamp = timestamp
        self.cinfo_file = cinfo_file
        self.reader = reader
        self.nodes = {}
        self.node_names = {}
        self.cinfo_data = {}

    def destroy(self):
        try:
            del self.timestamp
            del self.cinfo_file
            del self.reader
            del self.cinfo_data
            del self.nodes
            del self.node_names
        except Exception:
            pass

    def get_node_names(self):
        if not self.node_names:
            if (self.cinfo_data
                    and "config" in self.cinfo_data
                    and CONFIG_SERVICE in self.cinfo_data["config"]):
                node_names = self.cinfo_data["config"][CONFIG_SERVICE].keys()
            else:
                node_names = self.reader.get_node_names(self.cinfo_file)

            for node_name in node_names:
                self.node_names[node_name] = node_name
        return copy.deepcopy(self.node_names)

    def get_data(self, type="", stanza=""):
        if not type or not stanza:
            return {}
        try:
            if not self.cinfo_data:
                self.cinfo_data = self.reader.read(self.cinfo_file)
                if (self.cinfo_data
                        and "config" in self.cinfo_data
                        and CONFIG_SERVICE in self.cinfo_data["config"]):
                    self._set_nodes(
                        self.cinfo_data["config"][CONFIG_SERVICE].keys())
                elif (self.cinfo_data
                        and "statistics" in self.cinfo_data
                        and STAT_SERVICE in self.cinfo_data["statistics"]):
                    self._set_nodes(
                        self.cinfo_data["statistics"][STAT_SERVICE].keys())
                self._set_node_id()
                self._set_ip()
                self._set_xdr_build()
                self._set_asd_build()
                self._set_asd_version()
                self._set_cluster_name()

            elif type not in self.cinfo_data:
                self.cinfo_data.update(self.reader.read(self.cinfo_file))

            return copy.deepcopy(self.cinfo_data[type][stanza])
        except Exception:
            pass
        return {}

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
        return self.get_data(type="distribution", stanza=stanza)

    def get_summary(self, stanza=""):
        return self.get_data(type="summary", stanza=stanza)

    def get_expected_principal(self):
        if not self.cinfo_data:
            self._set_node_id()
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
            if not self.cinfo_data:
                self._set_xdr_build()

            for node in self.nodes:
                xdr_build[node]=self.nodes[node].xdr_build
        except Exception:
            pass
        return xdr_build

    def get_asd_build(self):
        asd_build={}
        try:
            if not self.cinfo_data:
                self._set_asd_build()

            for node in self.nodes:
                asd_build[node]=self.nodes[node].asd_build
        except Exception:
            pass
        return asd_build

    def get_asd_version(self):
        asd_version={}
        try:
            if not self.cinfo_data:
                self._set_asd_version()

            for node in self.nodes:
                asd_version[node]=self.nodes[node].asd_version
        except Exception:
            pass
        return asd_version

    def get_cluster_name(self):
        cluster_name={}
        try:
            if not self.cinfo_data:
                self._set_cluster_name()

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

        node_ids=self._fetch_columns_for_nodes(type="summary",
                stanza=SUMMARY_SERVICE, header_columns=['Node'],
                column_to_find=['Node', 'Id'], symbol_to_neglct='.')

        if not node_ids:
            node_ids=self._fetch_columns_for_nodes(type="summary",
                    stanza=SUMMARY_NETWORK, header_columns=['Node'],
                    column_to_find=['Node', 'Id'], symbol_to_neglct='.')

        if not node_ids and self._get_node_count() == 1:
            service_stats=self.get_data(type="statistics",
                    stanza=STAT_SERVICE)

            for node in self.nodes:
                self.nodes[node].set_node_id(
                    logutil.fetch_value_from_dic(service_stats,
                        [node, 'paxos_principal']))

        elif node_ids:
            for node in node_ids:
                if node in self.nodes:
                    self.nodes[node].set_node_id(node_ids[node])

    def _set_ip(self):

        ips=self._fetch_columns_for_nodes(type="summary",
                stanza=SUMMARY_SERVICE, header_columns=['Node', 'Ip'],
                column_to_find=['Ip'], symbol_to_neglct='.')

        if not ips:
            ips=self._fetch_columns_for_nodes(type="summary",
                    stanza=SUMMARY_NETWORK, header_columns=['Node', 'Ip'],
                    column_to_find=['Ip'], symbol_to_neglct='.')

        if ips:
            for node in ips:
                if node in self.nodes:
                    self.nodes[node].set_ip(ips[node])

    def _set_xdr_build(self):

        xdr_builds=self._fetch_columns_for_nodes(type="summary",
                stanza=SUMMARY_XDR, header_columns=['Node', 'Build'],
                column_to_find=['Build'], symbol_to_neglct='.')

        if xdr_builds:
            for node in xdr_builds:
                if node in self.nodes:
                    self.nodes[node].set_xdr_build(xdr_builds[node])

    def _set_asd_build(self):

        asd_builds=self._fetch_columns_for_nodes(type="summary",
                stanza=SUMMARY_SERVICE, header_columns=['Node', 'Build'],
                column_to_find=['Build'], symbol_to_neglct='.')

        if not asd_builds:
            asd_builds=self._fetch_columns_for_nodes(type="summary",
                    stanza=SUMMARY_NETWORK, header_columns=['Node', 'Build'],
                    column_to_find=['Build'], symbol_to_neglct='.')

        if asd_builds:
            for node in asd_builds:
                if node in self.nodes and asd_builds[node]:
                    if asd_builds[node].startswith("E-"):
                        self.nodes[node].set_asd_build(asd_builds[node][2:])
                        self.nodes[node].set_asd_version("Enterprise")
                    elif asd_builds[node].startswith("C-"):
                        self.nodes[node].set_asd_build(asd_builds[node][2:])
                        self.nodes[node].set_asd_version("Community")
                    else:
                        self.nodes[node].set_asd_build(asd_builds[node])

    def _set_asd_version(self):

        asd_versions=self._fetch_columns_for_nodes(type="summary",
                stanza=SUMMARY_NETWORK, header_columns=['Node', 'Enterprise'],
                column_to_find=['Enterprise'], symbol_to_neglct='.')

        if asd_versions:
            for node in asd_versions:
                if node in self.nodes and asd_versions[node]:
                    self.nodes[node].set_asd_version(asd_versions[node])

    def _set_cluster_name(self):

        cluster_names=self._fetch_columns_for_nodes(type="summary",
                stanza=SUMMARY_NETWORK, header_columns=['Cluster', 'Node'],
                column_to_find=['Cluster', 'Name'], symbol_to_neglct='.')

        if cluster_names:
            for node in cluster_names:
                if node in self.nodes:
                    self.nodes[node].set_cluster_name(cluster_names[node])

    def _find_column_num(self, lines, column_to_find, header_columns):

        if not lines:
            return lines, None
        column_found=False
        column_to_find_index=0
        header_search_incomplete=False
        indices=[]

        while not column_found and lines:
            line=lines.pop(0)

            if (all(column in line for column in header_columns)
                    or header_search_incomplete):
                line_list=line.split()

                temp_indices=[i for i, x in enumerate(
                    line_list) if x == column_to_find[column_to_find_index]]

                if not indices:
                    indices=temp_indices
                else:
                    indices=logutil.intersect_list(indices, temp_indices)

                column_to_find_index += 1

                if column_to_find_index == len(column_to_find):
                    column_found=True
                    header_search_incomplete=False
                else:
                    header_search_incomplete=True
        return lines, indices

    def _fetch_columns_for_nodes(self, type, stanza, header_columns,
            column_to_find, symbol_to_neglct):

        summary=self.get_data(type=type, stanza=stanza)
        node_value={}
        if summary and isinstance(summary, str):
            lines=summary.split('\n')
            lines, node_col=self._find_column_num(
                lines, ['Node', '.'], header_columns)

            lines=summary.split('\n')
            lines, indices=self._find_column_num(
                lines, column_to_find, header_columns)
            for line in lines:
                try:

                    if(line.split()[node_col[0]].strip() == symbol_to_neglct):
                        continue
                    else:
                        line_list=line.split()
                        node=line_list[node_col[0]].strip()
                        col_val=line_list[indices[0]].strip()
                        if node in self.nodes:
                            node_value[node]=col_val
                except Exception:
                    pass
        return node_value
