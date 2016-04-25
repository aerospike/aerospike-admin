import copy
from lib import logutil
from lib.logreader import LogReader

__author__ = 'aerospike'

class LogNode(object):
    def __init__(self, timestamp, node_name, node_id="N/E"):
        self.timestamp = timestamp
        self.node_name = node_name
        self.node_id = node_id
        self.xdr_build = "N/E"
        self.asd_build = "N/E"
        self.asd_version = "N/E"
        self.ip = "N/E"

    def sockName(self, use_fqdn):
        return self.ip

    def set_ip(self, ip):
        self.ip = ip

    def set_node_id(self, node_id):
        try:
            if node_id.startswith("*"):
                node_id = node_id[1:]
        except:
            pass
        self.node_id = node_id

    def set_xdr_build(self, xdr_build):
        self.xdr_build = xdr_build

    def set_asd_build(self, asd_build):
        self.asd_build = asd_build

    def set_asd_version(self, asd_version):
        if asd_version.lower() in ['enterprise', 'true']:
            self.asd_version = "Enterprise"
        elif asd_version.lower() in ['community', 'false']:
            self.asd_version = "Community"
        else:
            self.asd_version = "N/E"

class LogSnapshot(object):

    def __init__(self, timestamp, cluster_file, log_reader):
        self.timestamp = timestamp
        self.cluster_file = cluster_file
        self.log_reader = log_reader
        self.nodes = {}
        self.prefixes = {}
        self.cluster_data = {}

    def destroy(self):
        try:
            del self.timestamp
            del self.cluster_file
            del self.log_reader
            del self.cluster_data
            del self.nodes
            del self.prefixes
        except:
            pass

    def get_prefixes(self):
        if not self.prefixes:
            if self.cluster_data and "config" in self.cluster_data and "service" in self.cluster_data["config"]:
                prefixes = self.cluster_data["config"]["service"].keys()
            else:
                prefixes = LogReader.getPrefixes(self.cluster_file)
            for prefix in prefixes:
                self.prefixes[prefix] = prefix

        return copy.deepcopy(self.prefixes)

    def set_nodes(self, nodes):
        for node in nodes:
            self.prefixes[node] = node
            self.nodes[node] = LogNode(self.timestamp, node)

    def getNodeNames(self):
        return self.get_prefixes()

    def get_data(self, type="", stanza=""):
        if not type or not stanza:
            return {}
        try:
            if not self.cluster_data:
                self.cluster_data = self.log_reader.read(self.cluster_file)
                if self.cluster_data and "config" in self.cluster_data and "service" in self.cluster_data["config"]:
                    self.set_nodes(self.cluster_data["config"]["service"].keys())
                elif self.cluster_data and "statistics" in self.cluster_data and "service" in self.cluster_data["statistics"]:
                    self.set_nodes(self.cluster_data["statistics"]["service"].keys())
                self.set_node_id()
                self.set_ip()
                self.set_xdr_build()
                self.set_asd_build()
                self.set_asd_version()
            elif type not in self.cluster_data:
                self.cluster_data.update(self.log_reader.read(self.cluster_file))

            return copy.deepcopy(self.cluster_data[type][stanza])
        except:
            pass
        return {}

    def getNode(self, node_key):
        if node_key in self.nodes:
            return [self.nodes[node_key]]
        else:
            return [LogNode(self.timestamp, node_key, node_key)]

    def get_configs(self, stanza=""):
        return self.get_data(type="config", stanza=stanza)

    def get_statistics(self, stanza=""):
        return self.get_data(type="statistics", stanza=stanza)

    def get_histograms(self, stanza=""):
        return self.get_data(type="distribution", stanza=stanza)

    def get_summary(self, stanza=""):
        return self.get_data(type="summary", stanza=stanza)

    def getExpectedPrincipal(self):
        if not self.cluster_data:
            self.set_node_id()
        try:
            principal = "0"
            for n in self.nodes.itervalues():
                if n.node_id=='N/E':
                    if self.get_node_count()==1:
                        return n.node_id
                    return "UNKNOWN_PRINCIPAL"
                if n.node_id.zfill(16) > principal.zfill(16):
                    principal = n.node_id
            return principal
        except Exception as e:
            return "UNKNOWN_PRINCIPAL"

    def get_node_count(self):
        return len(self.nodes.keys())

    def set_node_id(self):
        node_ids = self.fetch_columns_for_nodes(type="summary", stanza="service", header_columns=['Node'],column_to_find=['Node','Id'],symbol_to_neglct='.')
        if not node_ids:
            node_ids = self.fetch_columns_for_nodes(type="summary", stanza="network", header_columns=['Node'],column_to_find=['Node','Id'],symbol_to_neglct='.')
        if not node_ids and self.get_node_count()==1:
            service_stats = self.get_data(type="statistics", stanza="service")
            for node in self.nodes:
                self.nodes[node].set_node_id(logutil.fetch_value_from_dic(service_stats, [node, 'paxos_principal']))
        elif node_ids:
            for node in node_ids:
                if node in self.nodes:
                    self.nodes[node].set_node_id(node_ids[node])

    def set_ip(self):
        ips = self.fetch_columns_for_nodes(type="summary", stanza="service", header_columns=['Node','Ip'],column_to_find=['Ip'],symbol_to_neglct='.')
        if not ips:
            ips = self.fetch_columns_for_nodes(type="summary", stanza="network", header_columns=['Node','Ip'],column_to_find=['Ip'],symbol_to_neglct='.')
        if ips:
            for node in ips:
                if node in self.nodes:
                    self.nodes[node].set_ip(ips[node])

    def set_xdr_build(self):
        xdr_builds = self.fetch_columns_for_nodes(type="summary", stanza="xdr", header_columns=['Node','Build'],column_to_find=['Build'],symbol_to_neglct='.')
        if xdr_builds:
            for node in xdr_builds:
                if node in self.nodes:
                    self.nodes[node].set_xdr_build(xdr_builds[node])

    def set_asd_build(self):
        asd_builds = self.fetch_columns_for_nodes(type="summary", stanza="service", header_columns=['Node','Build'],column_to_find=['Build'],symbol_to_neglct='.')
        if not asd_builds:
            asd_builds = self.fetch_columns_for_nodes(type="summary", stanza="network", header_columns=['Node','Build'],column_to_find=['Build'],symbol_to_neglct='.')
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

    def set_asd_version(self):
        asd_versions = self.fetch_columns_for_nodes(type="summary", stanza="network", header_columns=['Node','Enterprise'],column_to_find=['Enterprise'],symbol_to_neglct='.')
        if asd_versions:
            for node in asd_versions:
                if node in self.nodes and asd_versions[node]:
                    self.nodes[node].set_asd_version(asd_versions[node])

    def fetch_columns_for_nodes(self, type, stanza, header_columns, column_to_find, symbol_to_neglct):
        summary = self.get_data(type=type, stanza=stanza)
        node_value = {}
        if summary and isinstance(summary, str):
            lines = summary.split('\n')
            column_found = False
            header_search_incomplete = False
            column_to_find_index = 0
            indices = []
            for line in lines:
                if column_found:
                    try:
                       if(line.split()[0].strip()==symbol_to_neglct):
                           continue
                       else:
                           line_list = line.split()
                           node = line_list[0].strip()
                           xdr_build = line_list[indices[0]].strip()
                           if node in self.nodes:
                               node_value[node] = xdr_build
                    except:
                        pass
                elif all(column in line for column in header_columns) or header_search_incomplete:
                    line_list = line.split()
                    temp_indices = [i for i, x in enumerate(line_list) if x == column_to_find[column_to_find_index]]
                    if not indices:
                        indices = temp_indices
                    else:
                        indices = logutil.intersect_list(indices, temp_indices)
                    column_to_find_index += 1
                    if column_to_find_index == len(column_to_find):
                        column_found = True
                        header_search_incomplete = False
                    else:
                        header_search_incomplete = True
        return node_value

    def get_xdr_build(self):
        xdr_build = {}
        try:
            if not self.cluster_data:
                self.set_xdr_build()

            for node in self.nodes:
                xdr_build[node] = self.nodes[node].xdr_build
        except:
            pass
        return xdr_build

    def get_asd_build(self):
        asd_build = {}
        try:
            if not self.cluster_data:
                self.set_asd_build()

            for node in self.nodes:
                asd_build[node] = self.nodes[node].asd_build
        except:
            pass
        return asd_build

    def get_asd_version(self):
        asd_version = {}
        try:
            if not self.cluster_data:
                self.set_asd_version()

            for node in self.nodes:
                asd_version[node] = self.nodes[node].asd_version
        except:
            pass
        return asd_version