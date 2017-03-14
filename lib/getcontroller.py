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

from distutils.version import LooseVersion

from lib.utils import util
from lib.utils import filesize


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
        histogram = util.flip_keys(histogram)

        for namespace, host_data in histogram.iteritems():
            for host_id, data in host_data.iteritems():
                hist = data['data']
                width = data['width']

                cum_total = 0
                total = sum(hist)
                percentile = 0.1
                result = []

                for i, v in enumerate(hist):
                    cum_total += float(v)
                    if total > 0:
                        portion = cum_total / total
                    else:
                        portion = 0.0

                    while portion >= percentile:
                        percentile += 0.1
                        result.append(i + 1)

                    if percentile > 1.0:
                        break

                if result == []:
                    result = [0] * 10

                if histogram_name is "objsz":
                    data['percentiles'] = [
                        (r * width) - 1 if r > 0 else r for r in result]
                else:
                    data['percentiles'] = [r * width for r in result]

        return histogram

    def do_object_size(self, byte_distribution=False, show_bucket_count=5, nodes='all'):

        histogram_name = 'objsz'

        if not byte_distribution:
            return self.do_distribution(histogram_name)

        histogram = util.Future(
            self.cluster.info_histogram, histogram_name, nodes=nodes).start()
        builds = util.Future(
            self.cluster.info, 'build', nodes=nodes).start()
        histogram = util.flip_keys(histogram.result())
        builds = builds.result()

        for namespace, host_data in histogram.iteritems():
            result = []
            rblock_size_bytes = 128
            width = 1
            for host_id, data in host_data.iteritems():
                try:
                    as_version = builds[host_id]
                    if (LooseVersion(as_version) < LooseVersion("2.7.0")
                            or (LooseVersion(as_version) >= LooseVersion("3.0.0")
                                and LooseVersion(as_version) < LooseVersion("3.1.3"))):
                        rblock_size_bytes = 512
                except Exception:
                    pass

                hist = data['data']
                width = data['width']

                for i, v in enumerate(hist):
                    if v and v > 0:
                        result.append(i)

            result = list(set(result))
            result.sort()
            start_buckets = []
            if len(result) <= show_bucket_count:
                # if asinfo buckets with values>0 are less than
                # show_bucket_count then we can show all single buckets as it
                # is, no need to merge to show big range
                for res in result:
                    start_buckets.append(res)
                    start_buckets.append(res + 1)
            else:
                # dividing volume buckets (from min possible bucket with
                # value>0 to max possible bucket with value>0) into same range
                start_bucket = result[0]
                size = result[len(result) - 1] - result[0] + 1

                bucket_width = size / show_bucket_count
                additional_bucket_index = show_bucket_count - \
                    (size % show_bucket_count)

                bucket_index = 0

                while bucket_index < show_bucket_count:
                    start_buckets.append(start_bucket)
                    if bucket_index == additional_bucket_index:
                        bucket_width += 1
                    start_bucket += bucket_width
                    bucket_index += 1
                start_buckets.append(start_bucket)

            columns = []
            need_to_show = {}
            for i, bucket in enumerate(start_buckets):
                if i == len(start_buckets) - 1:
                    break
                key = self.get_bucket_range(
                    bucket, start_buckets[i + 1], width, rblock_size_bytes)
                need_to_show[key] = False
                columns.append(key)
            for host_id, data in host_data.iteritems():
                rblock_size_bytes = 128
                try:
                    as_version = builds[host_id]

                    if (LooseVersion(as_version) < LooseVersion("2.7.0")
                            or (LooseVersion(as_version) >= LooseVersion("3.0.0")
                                and LooseVersion(as_version) < LooseVersion("3.1.3"))):
                        rblock_size_bytes = 512
                except Exception:
                    pass
                hist = data['data']
                width = data['width']
                data['values'] = {}
                for i, s in enumerate(start_buckets):
                    if i == len(start_buckets) - 1:
                        break
                    b_index = s
                    key = self.get_bucket_range(
                        s, start_buckets[i + 1], width, rblock_size_bytes)
                    if key not in columns:
                        columns.append(key)
                    if key not in data["values"]:
                        data["values"][key] = 0
                    while b_index < start_buckets[i + 1]:
                        data["values"][key] += hist[b_index]
                        b_index += 1

                    if data["values"][key] > 0:
                        need_to_show[key] = True
                    else:
                        if key not in need_to_show:
                            need_to_show[key] = False
            host_data["columns"] = []
            for column in columns:
                if need_to_show[column]:
                    host_data["columns"].append(column)

        return histogram

    def get_bucket_range(self, current_bucket, next_bucket, width, rblock_size_bytes):
        s_b = "0 B"
        if current_bucket > 0:
            last_bucket_last_rblock_end = (
                (current_bucket * width) - 1) * rblock_size_bytes
            if last_bucket_last_rblock_end < 1:
                last_bucket_last_rblock_end = 0
            else:
                last_bucket_last_rblock_end += 1
            s_b = filesize.size(last_bucket_last_rblock_end, filesize.byte)
            if current_bucket == 99 or next_bucket > 99:
                return ">%s" % (s_b.replace(" ", ""))

        bucket_last_rblock_end = (
            (next_bucket * width) - 1) * rblock_size_bytes
        e_b = filesize.size(bucket_last_rblock_end, filesize.byte)
        return "%s to %s" % (s_b.replace(" ", ""), e_b.replace(" ", ""))


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
                      'dc': (util.Future(self.get_dc, nodes=nodes).start()).result()
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
        for node, stats in service_stats.iteritems():
            features[node] = {}
            features[node]["KVS"] = "NO"
            if self._check_key_for_gt(stats, ('stat_read_reqs', 'stat_write_reqs')):
                features[node]["KVS"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self._check_key_for_gt(nsval, ('client_read_error', 'client_read_success', 'client_write_error', 'client_write_success')):
                        features[node]["KVS"] = "YES"
                        break

            features[node]["UDF"] = "NO"
            if self._check_key_for_gt(stats, ('udf_read_reqs', 'udf_write_reqs')):
                features[node]["UDF"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self._check_key_for_gt(nsval, ('client_udf_complete', 'client_udf_error')):
                        features[node]["UDF"] = "YES"
                        break

            features[node]["BATCH"] = "NO"
            if self._check_key_for_gt(stats, ('batch_initiate', 'batch_index_initiate')):
                features[node]["BATCH"] = "YES"

            features[node]["SCAN"] = "NO"
            if self._check_key_for_gt(stats, ('tscan_initiate', 'basic_scans_succeeded', 'basic_scans_failed', 'aggr_scans_succeeded'
                                             'aggr_scans_failed', 'udf_bg_scans_succeeded', 'udf_bg_scans_failed')):
                features[node]["SCAN"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self._check_key_for_gt(nsval, ('scan_basic_complete', 'scan_basic_error', 'scan_aggr_complete',
                                                     'scan_aggr_error', 'scan_udf_bg_complete', 'scan_udf_bg_error')):
                        features[node]["SCAN"] = "YES"
                        break

            features[node]["SINDEX"] = "NO"
            if self._check_key_for_gt(stats, ('sindex-used-bytes-memory')):
                features[node]["SINDEX"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self._check_key_for_gt(nsval, ('memory_used_sindex_bytes')):
                        features[node]["SINDEX"] = "YES"
                        break

            features[node]["QUERY"] = "NO"
            if self._check_key_for_gt(stats, ('query_reqs', 'query_success')):
                features[node]["QUERY"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self._check_key_for_gt(nsval, ('query_reqs', 'query_success')):
                        features[node]["QUERY"] = "YES"
                        break

            features[node]["AGGREGATION"] = "NO"
            if self._check_key_for_gt(stats, ('query_agg', 'query_agg_success')):
                features[node]["AGGREGATION"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self._check_key_for_gt(nsval, ('query_agg', 'query_agg_success')):
                        features[node]["AGGREGATION"] = "YES"
                        break

            features[node]["LDT"] = "NO"
            if self._check_key_for_gt(stats, ('sub-records', 'ldt-writes', 'ldt-reads', 'ldt-deletes', 'ldt_writes', 'ldt_reads', 'ldt_deletes', 'sub_objects')):
                features[node]["LDT"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self._check_key_for_gt(nsval, ('ldt-writes', 'ldt-reads', 'ldt-deletes', 'ldt_writes', 'ldt_reads', 'ldt_deletes')):
                        features[node]["LDT"] = "YES"
                        break

            features[node]["XDR ENABLED"] = "NO"
            if self._check_key_for_gt(stats, ('stat_read_reqs_xdr', 'xdr_read_success', 'xdr_read_error')):
                features[node]["XDR ENABLED"] = "YES"

            features[node]["XDR DESTINATION"] = "NO"
            if self._check_key_for_gt(stats, ('stat_write_reqs_xdr')):
                features[node]["XDR DESTINATION"] = "YES"
            elif node in ns_stats:
                for ns, nsval in ns_stats[node].iteritems():
                    if self._check_key_for_gt(nsval, ('xdr_write_success')):
                        features[node]["XDR DESTINATION"] = "YES"
                        break
        return features

