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

from lib.utils import util


def get_sindex_stats(cluster, nodes='all', for_mods=[]):
    stats = cluster.info_sindex(nodes=nodes)

    sindex_stats = {}
    if stats:
        for host, stat_list in stats.iteritems():
            if not stat_list or isinstance(stat_list, Exception):
                continue
            namespace_list = [stat['ns'] for stat in stat_list]
            namespace_list = util.filter_list(namespace_list, for_mods)
            for stat in stat_list:
                if not stat or stat['ns'] not in namespace_list:
                    continue
                ns = stat['ns']
                set = stat['set']
                indexname = stat['indexname']

                if not indexname or not ns:
                    continue

                sindex_key = "%s %s %s" % (ns, set, indexname)

                if sindex_key not in sindex_stats:
                    sindex_stats[sindex_key] = {}
                sindex_stats[sindex_key] = cluster.info_sindex_statistics(
                    ns, indexname, nodes=nodes)
                for node in sindex_stats[sindex_key].keys():
                    if (not sindex_stats[sindex_key][node]
                            or isinstance(sindex_stats[sindex_key][node], Exception)):
                        continue
                    for key, value in stat.iteritems():
                        sindex_stats[sindex_key][node][key] = value
    return sindex_stats

class GetDistributionController():

    def __init__(self, cluster):
        self.modifiers = set(['with', 'for'])
        self.cluster = cluster

    def do_distribution(self, histogram_name, nodes='all'):
        histogram = self.cluster.info_histogram(histogram_name, nodes=nodes)
        return util.create_histogram_output(histogram_name, histogram)

    def do_object_size(self, byte_distribution=False, bucket_count=5, nodes='all'):

        histogram_name = 'objsz'

        if not byte_distribution:
            return self.do_distribution(histogram_name)

        histogram = util.Future(self.cluster.info_histogram, histogram_name, nodes=nodes).start()
        builds = util.Future(self.cluster.info, 'build', nodes=nodes).start()
        histogram = histogram.result()
        builds = builds.result()

        return util.create_histogram_output(histogram_name, histogram, byte_distribution=True, bucket_count=bucket_count, builds=builds)

class GetLatencyController():

    def __init__(self, cluster):
        self.cluster = cluster

    def get_all(self, nodes='all'):
        latency_map = {'latency': self.get_latency(nodes=nodes)}
        return latency_map

    def get_latency(self, nodes='all'):
        latency = self.cluster.info_latency(
            nodes=nodes, back=None, duration=None, slice=None, ns_set=None)
        hist_latency = {}

        for node_id, hist_data in latency.iteritems():
            if isinstance(hist_data, Exception):
                continue
            for hist_name, data in hist_data.iteritems():
                if hist_name not in hist_latency:
                    hist_latency[hist_name] = {node_id: data}
                else:
                    hist_latency[hist_name][node_id] = data
        return hist_latency


class GetConfigController():

    def __init__(self, cluster):
        self.cluster = cluster

    def get_all(self, nodes='all'):
        config_map = {'service': (util.Future(self.get_service, nodes=nodes).start()).result(),
                      'namespace': (util.Future(self.get_namespace, nodes=nodes).start()).result(),
                      'network': (util.Future(self.get_network, nodes=nodes).start()).result(),
                      'xdr': (util.Future(self.get_xdr, nodes=nodes).start()).result(),
                      'dc': (util.Future(self.get_dc, nodes=nodes).start()).result(),
                      'cluster': (util.Future(self.get_cluster, nodes=nodes).start()).result()
                      }
        return config_map

    def get_service(self, nodes='all'):
        service_configs = self.cluster.info_get_config(
            nodes=nodes, stanza='service')
        for node in service_configs:
            if isinstance(service_configs[node], Exception):
                service_configs[node] = {}
            else:
                service_configs[node] = service_configs[node]['service']

        return service_configs

    def get_network(self, nodes='all'):
        hb_configs = util.Future(
            self.cluster.info_get_config, nodes=nodes, stanza='network.heartbeat').start()
        info_configs = util.Future(
            self.cluster.info_get_config, nodes=nodes, stanza='network.info').start()
        nw_configs = util.Future(
            self.cluster.info_get_config, nodes=nodes, stanza='network').start()

        network_configs = {}
        hb_configs = hb_configs.result()
        for node in hb_configs:
            if isinstance(hb_configs[node], Exception):
                network_configs[node] = {}
            else:
                network_configs[node] = hb_configs[node]['network.heartbeat']

        info_configs = info_configs.result()
        for node in info_configs:
            if isinstance(info_configs[node], Exception):
                continue
            else:
                network_configs[node].update(
                    info_configs[node]['network.info'])

        nw_configs = nw_configs.result()
        for node in nw_configs:
            if isinstance(nw_configs[node], Exception):
                continue
            else:
                network_configs[node].update(nw_configs[node]['network'])

        return network_configs

    def get_namespace(self, nodes='all'):
        namespace_configs = self.cluster.info_get_config(
            nodes=nodes, stanza='namespace')
        for node in namespace_configs:
            if isinstance(namespace_configs[node], Exception):
                namespace_configs[node] = {}
            else:
                namespace_configs[node] = namespace_configs[node]['namespace']

        ns_configs = {}
        for host, configs in namespace_configs.iteritems():
            for ns, config in configs.iteritems():
                if ns not in ns_configs:
                    ns_configs[ns] = {}

                try:
                    ns_configs[ns][host].update(config)
                except KeyError:
                    ns_configs[ns][host] = config
        return ns_configs

    def get_xdr(self, nodes='all'):
        configs = self.cluster.info_XDR_get_config(nodes=nodes)

        xdr_configs = {}
        for node, config in configs.iteritems():
            if isinstance(config, Exception):
                continue

            xdr_configs[node] = config['xdr']
        return xdr_configs

    def get_dc(self, nodes='all'):
        all_dc_configs = self.cluster.info_dc_get_config(nodes=nodes)
        dc_configs = {}
        for host, configs in all_dc_configs.iteritems():
            if not configs or isinstance(configs, Exception):
                continue
            for dc, config in configs.iteritems():
                if dc not in dc_configs:
                    dc_configs[dc] = {}

                try:
                    dc_configs[dc][host].update(config)
                except KeyError:
                    dc_configs[dc][host] = config
        return dc_configs

    def get_cluster(self, nodes='all'):

        configs = util.Future(self.cluster.info_get_config, nodes=nodes,
                stanza='cluster').start()

        configs = configs.result()
        cl_configs = {}
        for node, config in configs.iteritems():
            if isinstance(config, Exception):
                continue
            cl_configs[node] = config['cluster']

        return cl_configs

class GetStatisticsController():

    def __init__(self, cluster):
        self.cluster = cluster

    def get_all(self, nodes='all'):
        stat_map = {'service': (util.Future(self.get_service, nodes=nodes).start()).result(),
                    'namespace': (util.Future(self.get_namespace, nodes=nodes).start()).result(),
                    'set': (util.Future(self.get_sets, nodes=nodes).start()).result(),
                    'bin': (util.Future(self.get_bins, nodes=nodes).start()).result(),
                    'sindex': (util.Future(self.get_sindex, nodes=nodes).start()).result(),
                    'xdr': (util.Future(self.get_xdr, nodes=nodes).start()).result(),
                    'dc': (util.Future(self.get_dc, nodes=nodes).start()).result()
                    }
        return stat_map

    def get_service(self, nodes='all'):
        service_stats = self.cluster.info_statistics(nodes=nodes)
        return service_stats

    def get_namespace(self, nodes='all', for_mods=[]):
        namespaces = self.cluster.info_namespaces(nodes=nodes)

        namespaces = namespaces.values()
        namespace_set = set()
        for namespace in namespaces:
            if isinstance(namespace, Exception):
                continue
            namespace_set.update(namespace)
        namespace_list = util.filter_list(list(namespace_set), for_mods)

        ns_stats = {}
        for namespace in namespace_list:
            ns_stats[namespace] = util.Future(
                self.cluster.info_namespace_statistics, namespace,
                nodes=nodes).start().result()
            for _k in ns_stats[namespace].keys():
                if not ns_stats[namespace][_k]:
                    ns_stats[namespace].pop(_k)

        return ns_stats

    def get_sindex(self, nodes='all', for_mods=[]):
        sindex_stats = get_sindex_stats(self.cluster, nodes, for_mods)
        return sindex_stats

    def get_sets(self, nodes='all', for_mods=[]):
        sets = self.cluster.info_set_statistics(nodes=nodes)

        set_stats = {}
        for host_id, key_values in sets.iteritems():
            if isinstance(key_values, Exception) or not key_values:
                continue
            namespace_list = [ns_set[0] for ns_set in key_values.keys()]
            namespace_list = util.filter_list(namespace_list, for_mods)
            for key, values in key_values.iteritems():
                if key[0] not in namespace_list:
                    continue
                if key not in set_stats:
                    set_stats[key] = {}
                host_vals = set_stats[key]

                if host_id not in host_vals:
                    host_vals[host_id] = {}
                hv = host_vals[host_id]
                hv.update(values)

        return set_stats

    def get_bins(self, nodes='all', for_mods=[]):
        bin_stats = self.cluster.info_bin_statistics(nodes=nodes)
        new_bin_stats = {}

        for node_id, bin_stat in bin_stats.iteritems():
            if not bin_stat or isinstance(bin_stat, Exception):
                continue

            namespace_list = util.filter_list(bin_stat.keys(), for_mods)

            for namespace, stats in bin_stat.iteritems():
                if namespace not in namespace_list:
                    continue
                if namespace not in new_bin_stats:
                    new_bin_stats[namespace] = {}
                ns_stats = new_bin_stats[namespace]

                if node_id not in ns_stats:
                    ns_stats[node_id] = {}
                node_stats = ns_stats[node_id]

                node_stats.update(stats)

        return new_bin_stats

    def get_xdr(self, nodes='all'):
        xdr_stats = self.cluster.info_XDR_statistics(nodes=nodes)
        return xdr_stats

    def get_dc(self, nodes='all'):
        all_dc_stats = self.cluster.info_all_dc_statistics(nodes=nodes)
        dc_stats = {}
        for host, stats in all_dc_stats.iteritems():
            if not stats or isinstance(stats, Exception):
                continue
            for dc, stat in stats.iteritems():
                if dc not in dc_stats:
                    dc_stats[dc] = {}

                try:
                    dc_stats[dc][host].update(stat)
                except KeyError:
                    dc_stats[dc][host] = stat
        return dc_stats

    def _check_key_for_gt(self, d={}, keys=(), v=0, is_and=False, type_check=int):
        if not keys:
            return True
        if not d:
            return False
        if not isinstance(keys, tuple):
            keys = (keys,)
        if is_and:
            if all(util.get_value_from_dict(d, k, v, type_check) > v for k in keys):
                return True
        else:
            if any(util.get_value_from_dict(d, k, v, type_check) > v for k in keys):
                return True
        return False

    def get_features(self, nodes='all'):
        service_stats = self.cluster.info_statistics(nodes=nodes)
        ns_stats = self.cluster.info_all_namespace_statistics(nodes=nodes)

        features = {}
        for feature, keys in util.FEATURE_KEYS.iteritems():
            for node, s_stats in service_stats.iteritems():

                if node not in features:
                    features[node] = {}

                features[node][feature.upper()] = "NO"
                n_stats = None

                if node in ns_stats and not isinstance(ns_stats[node], Exception):
                    n_stats = ns_stats[node]

                if util.check_feature_by_keys(s_stats, keys[0], n_stats, keys[1]):
                    features[node][feature.upper()] = "YES"

        return features

class GetPmapController():

    def __init__(self, cluster):
        self.cluster = cluster

    def _get_namespace_data(self, namespace_stats, cluster_keys):
        ns_info = {}

        for ns, nodes in namespace_stats.items():
            repl_factor = {}

            for node, params in nodes.items():
                if isinstance(params, Exception):
                    continue
                if cluster_keys[node] not in repl_factor:
                    repl_factor[cluster_keys[node]] = 0

                repl_factor[cluster_keys[node]] = max(repl_factor[cluster_keys[node]], int(params['repl-factor']))

            for ck in repl_factor:
                if ck not in ns_info:
                    ns_info[ck] = {}
                if ns not in ns_info[ck]:
                    ns_info[ck][ns] = {}

                ns_info[ck][ns]['repl_factor'] = repl_factor[ck]

        return ns_info

    def _get_pmap_data(self, pmap_info, ns_info, versions, cluster_keys):
        pid_range = 4096        # each namespace is divided into 4096 partition
        pmap_data = {}
        ns_available_part = {}

        # required fields
        # format : (index_ptr, field_name, default_index)
        required_fields = [("namespace_index","namespace",0),("partition_index","partition",1),("state_index","state",2),
                           ("replica_index","replica",3),("origin_index","origin",4),("target_index","target",5)]

        for _node, partitions in pmap_info.items():
            node_pmap = dict()
            ck = cluster_keys[_node]

            if isinstance(partitions, Exception):
                continue

            f_indices = {}

            # default index in partition fields for server < 3.6.1
            for t in required_fields:
                f_indices[t[0]] = t[2]

            index_set = False

            for item in partitions.split(';'):
                fields = item.split(':')

                if not index_set:
                    index_set = True

                    if all(i[1] in fields for i in required_fields):
                        # pmap format contains headers from server 3.9 onwards
                        for t in required_fields:
                            f_indices[t[0]] = fields.index(t[1])

                        continue

                ns, pid, state, replica, origin, target = fields[f_indices["namespace_index"]], int(fields[f_indices["partition_index"]]),\
                                         fields[f_indices["state_index"]], int(fields[f_indices["replica_index"]]),\
                                         fields[f_indices["origin_index"]], fields[f_indices["target_index"]]

                if pid not in range(pid_range):
                    print "For {0} found partition-ID {1} which is beyond legal partitions(0...4096)".format(ns, pid)
                    continue

                if ns not in node_pmap:
                    node_pmap[ns] = { 'master_partition_count' : 0,
                                      'prole_partition_count' : 0,
                                    }

                if ck not in ns_available_part:
                    ns_available_part[ck] = {}

                if ns not in ns_available_part[ck]:
                    ns_available_part[ck][ns] = {}
                    ns_available_part[ck][ns]['available_partition_count'] = 0

                if replica == 0:
                    if origin == '0':
                        node_pmap[ns]['master_partition_count'] += 1
                    else:
                        node_pmap[ns]['prole_partition_count'] += 1
                else:
                    if target == '0':
                        if state == 'S' or state == 'D':
                            node_pmap[ns]['prole_partition_count'] += 1
                    else:
                        node_pmap[ns]['master_partition_count'] += 1

                if state == 'S' or state == 'D':
                    ns_available_part[ck][ns]['available_partition_count'] += 1



            pmap_data[_node] = node_pmap

        for _node, _ns_data in pmap_data.items():
            ck = cluster_keys[_node]
            for ns, params in _ns_data.items():
                params['missing_partition_count'] = (pid_range * ns_info[ck][ns]['repl_factor']) - ns_available_part[ck][ns]['available_partition_count']
                params['cluster_key'] = ck

        return pmap_data

    def get_pmap(self, nodes='all'):
        getter = GetStatisticsController(self.cluster)
        versions = util.Future(self.cluster.info, 'version', nodes=nodes).start()
        pmap_info = util.Future(self.cluster.info, 'partition-info', nodes=nodes).start()
        service_stats = getter.get_service(nodes=nodes)
        namespace_stats = getter.get_namespace(nodes=nodes)

        versions = versions.result()
        pmap_info = pmap_info.result()

        cluster_keys = {}
        for node in service_stats.keys():
            if not service_stats[node] or isinstance(service_stats[node], Exception):
                cluster_keys[node] = "N/E"
            else:
                cluster_keys[node] = util.get_value_from_dict(service_stats[node], ('cluster_key'), default_value="N/E")

        ns_info = self._get_namespace_data(namespace_stats, cluster_keys)

        pmap_data = self._get_pmap_data(pmap_info, ns_info, versions, cluster_keys)

        return pmap_data