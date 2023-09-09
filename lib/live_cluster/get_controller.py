# Copyright 2013-2023 Aerospike, Inc.
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

import asyncio
import copy
from typing import Iterable, Optional
from lib.base_get_controller import BaseGetConfigController

from lib.utils import common, util, constants
from lib.utils.types import NodeDict, DatacenterDict, NamespaceDict
from .client import Cluster


# Helpers
def _union_iterable(vals: Iterable[Iterable[str]]) -> set[str]:
    val_set = set()

    for val in vals:
        if not isinstance(val, Exception):
            val_set = val_set.union(val)

    return val_set


async def _get_all_dcs(cluster, nodes) -> set[str]:
    dcs_dict = await cluster.info_dcs(nodes=nodes)
    return _union_iterable(dcs_dict.values())


async def _get_all_namespaces(cluster, nodes) -> set[str]:
    namespaces_per_node = await cluster.info_namespaces(nodes=nodes)
    return _union_iterable(namespaces_per_node.values())


class GetDistributionController:
    def __init__(self, cluster):
        self.modifiers = set(["with", "for"])
        self.cluster = cluster

    async def do_distribution(self, histogram_name, nodes="all"):
        histogram = await self.cluster.info_histogram(histogram_name, nodes=nodes)
        return common.create_histogram_output(histogram_name, histogram)

    async def do_object_size(
        self, byte_distribution=False, bucket_count=5, nodes="all"
    ):
        histogram_name = "objsz"

        if not byte_distribution:
            return await self.do_distribution(histogram_name, nodes=nodes)

        histogram, builds = await asyncio.gather(
            self.cluster.info_histogram(histogram_name, logarithmic=True, nodes=nodes),
            self.cluster.info("build", nodes=nodes),
        )

        return common.create_histogram_output(
            histogram_name,
            histogram,
            byte_distribution=True,
            bucket_count=bucket_count,
            builds=builds,
        )


class GetLatenciesController:
    def __init__(self, cluster):
        self.cluster = cluster

    async def get_latencies_and_latency_nodes(
        self, nodes="all"
    ) -> tuple[list[str], list[str]]:
        """
        Returns a tuple (latencies, latency) of lists that contain nodes that support
        latencies cmd and nodes that do not.
        """
        latencies_nodes = []
        latency_nodes = []
        builds = await self.cluster.info_build(nodes=nodes)

        for node, build in builds.items():
            if isinstance(build, Exception):
                continue
            if common.is_new_latencies_version(build):
                latencies_nodes.append(node)
            else:
                latency_nodes.append(node)
        return latencies_nodes, latency_nodes

    def _copy_latency_data_to_latencies_table(
        self, latencies_table, latency_table, context
    ):
        latencies_data = util.get_nested_value_from_dict(
            latencies_table, context, None, dict
        )
        latency_data = util.get_nested_value_from_dict(
            latency_table, context, None, dict
        )

        if latencies_data is None:
            return latency_data

        # Make every new entry start out with 'N/A' for all values
        for idx in range(len(latencies_data["values"])):
            for jdx in range(len(latencies_data["values"][idx])):
                latencies_data["values"][idx][jdx] = "N/A"

        if latency_data is None:
            return

        # See if any columns in latencies_data match latency_data and copy them
        # over.
        for col_idx, col in enumerate(latencies_data["columns"]):
            if col in latency_data["columns"]:
                val_idx = latency_data["columns"].index(col)
                for vals_idx in range(len(latencies_data["values"])):
                    latencies_data["values"][vals_idx][col_idx] = latency_data[
                        "values"
                    ][vals_idx][val_idx]

    # Merges latency tables into latencies table.  This is needed because a
    # latencies table can have different columns.
    def merge_latencies_and_latency_tables(self, latencies_table, latency_table):
        if not latencies_table:
            return latency_table
        if not latency_table:
            return latencies_table

        # Make an entry in latencies_table for every entry in latency_table
        for latencies_address in latencies_table:
            for latency_address in latency_table:
                # Create entry with same schema as latencies_table
                latencies_table[latency_address] = copy.deepcopy(
                    latencies_table[latencies_address]
                )
            break

        # Go through latency data and copy appropriate values over
        for latency_address in latency_table:
            latencies_entry = latencies_table[latency_address]
            for histogram_name in latencies_entry:
                histogram_data = latencies_entry[histogram_name]
                if "total" in histogram_data:
                    self._copy_latency_data_to_latencies_table(
                        latencies_table,
                        latency_table,
                        [latency_address, histogram_name, "total"],
                    )
                if "namespace" in histogram_data:
                    namespaces = histogram_data["namespace"]
                    for namespace in namespaces:
                        self._copy_latency_data_to_latencies_table(
                            latencies_table,
                            latency_table,
                            [latency_address, histogram_name, "namespace", namespace],
                        )

        return latencies_table

    async def get_namespace_set(self, nodes) -> set[str]:
        return set(await _get_all_namespaces(self.cluster, nodes))

    async def get_all(self, nodes, buckets, exponent_increment, verbose, ns_set=None):
        latencies_nodes, latency_nodes = await self.get_latencies_and_latency_nodes()
        latencies = None

        # all nodes support "show latencies"
        if len(latency_nodes) == 0:
            latencies = await self.cluster.info_latencies(
                nodes=nodes,
                buckets=buckets,
                exponent_increment=exponent_increment,
                verbose=verbose,
                ns_set=ns_set,
            )
        # No nodes support "show latencies"
        elif len(latencies_nodes) == 0:
            latencies = await self.cluster.info_latency(nodes=nodes, ns_set=ns_set)
        # Some nodes support latencies and some do not
        else:
            latency, latencies = await asyncio.gather(
                self.cluster.info_latency(nodes=latency_nodes, ns_set=ns_set),
                self.cluster.info_latencies(
                    nodes=latencies_nodes,
                    buckets=buckets,
                    exponent_increment=exponent_increment,
                    verbose=verbose,
                    ns_set=ns_set,
                ),
            )
            latencies = self.merge_latencies_and_latency_tables(latencies, latency)

        return util.filter_exceptions(latencies)


async def get_sets(cluster, flip, nodes, for_mods: list[str] | None):
    sets = await cluster.info_all_set_statistics(nodes=nodes)

    ns_filter = None
    set_filter = None

    if for_mods:
        try:
            ns_filter = [for_mods[0]]
            set_filter = [for_mods[1]]
        except IndexError:
            pass

    set_stats = {}
    for host_id, key_values in sets.items():
        if isinstance(key_values, Exception) or not key_values:
            continue

        namespace_set = {ns_set[0] for ns_set in key_values.keys()}
        namespace_set = set(util.filter_list(namespace_set, ns_filter))

        sets = {ns_set[1] for ns_set in key_values.keys()}
        sets = set(util.filter_list(sets, set_filter))

        for key, values in key_values.items():
            if key[0] not in namespace_set or key[1] not in sets:
                continue

            if key not in set_stats:
                set_stats[key] = {}
            host_vals = set_stats[key]

            if host_id not in host_vals:
                host_vals[host_id] = {}
            hv = host_vals[host_id]
            hv.update(values)

    # Inverted match common structure of other getters, i.e. host is top level key
    if not flip:
        return util.flip_keys(set_stats)

    return set_stats


class GetConfigController(BaseGetConfigController):
    def __init__(self, cluster):
        self.cluster = cluster

    async def get_all(self, nodes="all"):
        futures = [
            (
                constants.CONFIG_SECURITY,
                asyncio.create_task(self.get_security(nodes=nodes)),
            ),
            (
                constants.CONFIG_SERVICE,
                asyncio.create_task(self.get_service(nodes=nodes)),
            ),
            (
                constants.CONFIG_NAMESPACE,
                asyncio.create_task(self.get_namespace(nodes=nodes)),
            ),
            (
                constants.CONFIG_SET,
                asyncio.create_task(self.get_sets(nodes=nodes)),
            ),
            (
                constants.CONFIG_NETWORK,
                asyncio.create_task(self.get_network(nodes=nodes)),
            ),
            (constants.CONFIG_XDR, asyncio.create_task(self.get_xdr(nodes=nodes))),
            (constants.CONFIG_DC, asyncio.create_task(self.get_xdr_dcs(nodes=nodes))),
            (
                constants.CONFIG_XDR_NS,
                asyncio.create_task(self.get_xdr_namespaces(nodes=nodes)),
            ),
            (
                constants.CONFIG_XDR_FILTER,
                asyncio.create_task(self.get_xdr_filters(nodes=nodes)),
            ),
            (
                constants.CONFIG_ROSTER,
                asyncio.create_task(self.get_roster(nodes=nodes)),
            ),
            (constants.CONFIG_RACKS, asyncio.create_task(self.get_racks(nodes=nodes))),
            (
                constants.CONFIG_RACK_IDS,
                asyncio.create_task(self.get_rack_ids(nodes=nodes)),
            ),
            (
                constants.CONFIG_LOGGING,
                asyncio.create_task(self.get_logging(nodes=nodes)),
            ),
        ]
        config_map = dict([(k, await f) for k, f in futures])

        return config_map

    async def get_logging(self, nodes="all"):
        logging_configs = await self.cluster.info_logging_config(nodes=nodes)
        for node in logging_configs:
            if isinstance(logging_configs[node], Exception):
                logging_configs[node] = {}

        return logging_configs

    async def get_security(self, nodes="all"):
        security_configs = await self.cluster.info_get_config(
            nodes=nodes, stanza="security"
        )
        for node in security_configs:
            if isinstance(security_configs[node], Exception):
                security_configs[node] = {}

        return security_configs

    async def get_service(self, nodes="all"):
        service_configs = await self.cluster.info_get_config(
            nodes=nodes, stanza="service"
        )
        for node in service_configs:
            if isinstance(service_configs[node], Exception):
                service_configs[node] = {}

        return service_configs

    async def get_network(self, nodes="all"):
        network_configs = {}
        nw_configs = await self.cluster.info_get_config(nodes=nodes, stanza="network")

        for node in nw_configs:
            if isinstance(nw_configs[node], Exception):
                continue
            else:
                network_configs[node] = nw_configs[node]

        return network_configs

    async def get_namespace(
        self, flip=False, nodes="all", for_mods: list[str] | None = None
    ):
        namespace_set = set(await _get_all_namespaces(self.cluster, nodes))
        namespace_list = list(util.filter_list(namespace_set, for_mods))
        ns_configs = {}
        ns_node_configs = []

        ns_node_configs = [
            asyncio.create_task(
                self.cluster.info_get_config(
                    stanza="namespace", namespace=namespace, nodes=nodes
                )
            )
            for namespace in namespace_list
        ]

        for namespace, node_configs in zip(namespace_list, ns_node_configs):
            node_configs = await node_configs

            for node, node_config in list(node_configs.items()):
                if (
                    not node_config
                    or isinstance(node_config, Exception)
                    or namespace not in node_config
                    or isinstance(node_config[namespace], Exception)
                ):
                    continue

                if node not in ns_configs:
                    ns_configs[node] = {}

                ns_configs[node][namespace] = node_config[namespace]

        if flip:
            ns_configs = util.flip_keys(ns_configs)

        return ns_configs

    async def get_sets(
        self, flip=False, nodes="all", for_mods: list[str] | None = None
    ):
        """
        set stats and config are currently returned together in a single response. That means
        that there are sections of asadm that expect stats and config to be in a single
        struct. When the separation does occur code will need to be audited to make sure this
        expectation no longer exists. This method will help that effort.
        """
        return await get_sets(self.cluster, flip, nodes, for_mods)

    async def get_xdr(self, nodes="all"):
        xdr_configs: NodeDict[dict[str, str]] = await self.cluster.info_xdr_config(
            nodes=nodes
        )

        for node, node_configs in xdr_configs.items():
            if isinstance(node_configs, Exception) or not node_configs:
                xdr_configs[node] = {}

        return xdr_configs

    async def get_xdr_dcs(
        self, flip=False, nodes="all", for_mods: list[str] | None = None
    ):
        all_dcs = await _get_all_dcs(self.cluster, nodes)
        filtered_dcs = list(util.filter_list(all_dcs, for_mods))

        result: NodeDict[
            DatacenterDict[dict[str, str]] | Exception
        ] = await self.cluster.info_xdr_dcs_config(nodes=nodes, dcs=filtered_dcs)

        for node, node_config in result.items():
            if isinstance(node_config, Exception) or not node_config:
                result[node] = {}
                continue

            for dc, dc_config in node_config.items():
                if not dc_config or isinstance(dc_config, Exception):
                    result[node][dc] = {}  # type: ignore

        if flip:
            result = util.flip_keys(result)

        return result

    async def get_xdr_namespaces(self, nodes="all", for_mods: list[str] | None = None):
        dcs_filter: list[str] | None = None
        namespaces_filter: list[str] | None = None

        if for_mods is not None:
            try:
                namespaces_filter = [for_mods[0]]
                dcs_filter = [for_mods[1]]
            except IndexError:
                pass

        all_dcs = await _get_all_dcs(self.cluster, nodes)
        all_namespaces = await _get_all_namespaces(self.cluster, nodes)

        filtered_dcs = list(util.filter_list(list(all_dcs), dcs_filter))
        filtered_namespaces = list(
            util.filter_list(list(all_namespaces), namespaces_filter)
        )

        # Not all dcs have all namespaces but that is OK. This function checks that
        # a particular namespace is apart of a dc before making a request.
        result: NodeDict[
            DatacenterDict[NamespaceDict[dict[str, str]] | Exception] | Exception
        ] = await self.cluster.info_xdr_namespaces_config(
            nodes=nodes, namespaces=filtered_namespaces, dcs=filtered_dcs
        )

        for node, node_config in result.items():
            if not node_config or isinstance(node_config, Exception):
                result[node] = {}
                continue

            for dc, dc_config in node_config.items():
                if not dc_config or isinstance(dc_config, Exception):
                    result[node][dc] = {}  # type: ignore
                    continue

                for ns, ns_config in dc_config.items():
                    if not ns_config or isinstance(ns_config, Exception):
                        result[node][dc][ns] = {}  # type: ignore

        return result

    async def get_xdr_filters(self, nodes="all", for_mods: list[str] | None = None):
        dcs_filter: list[str] | None = None
        namespaces_filter: list[str] | None = None
        filtered_dcs = None

        if for_mods:
            try:
                dcs_filter = [for_mods[0]]
                namespaces_filter = [for_mods[1]]
            except IndexError:
                pass

        if dcs_filter:
            all_dcs = await _get_all_dcs(self.cluster, nodes)
            filtered_dcs = list(util.filter_list(list(all_dcs), dcs_filter))

        result: NodeDict[
            DatacenterDict[NamespaceDict[dict[str, str]]]
        ] = await self.cluster.info_get_xdr_filter(dcs=filtered_dcs, nodes=nodes)

        for host, host_filters in result.items():
            if isinstance(host_filters, Exception) or host_filters is None:
                result[host] = {}
                continue

            for dc, dc_filters in host_filters.items():
                if isinstance(dc_filters, Exception) or dc_filters is None:
                    result[host][dc] = {}
                    continue

                filtered_namespaces = util.filter_list(
                    list(dc_filters.keys()), namespaces_filter
                )

                for ns in list(dc_filters.keys()):
                    # No need to check for exception here because all namespaces are
                    # returned by a single dc info request unlike xdr ns configs.
                    if ns not in filtered_namespaces:
                        del result[host][dc][ns]

        return result

    async def get_roster(self, flip=False, nodes="all"):
        configs = await self.cluster.info_roster(nodes=nodes)
        roster_configs = {}

        if configs:
            for node, config in configs.items():
                if not config or isinstance(config, Exception):
                    continue

                roster_configs[node] = config

        if flip:
            roster_configs = util.flip_keys(roster_configs)

        return roster_configs

    async def get_racks(self, flip=False, nodes="all"):
        configs = await self.cluster.info_racks(nodes=nodes)
        rack_configs = {}

        if configs:
            for node, config in configs.items():
                if isinstance(config, Exception):
                    continue

                rack_configs[node] = config

        if flip:
            rack_configs = util.flip_keys(rack_configs)

        return rack_configs

    async def get_rack_ids(self, flip=False, nodes="all"):
        configs = await self.cluster.info_rack_ids(nodes=nodes)
        rack_ids = {}

        if configs:
            for node, config in configs.items():
                if not config or isinstance(config, Exception):
                    continue

                rack_ids[node] = config

        if flip:
            rack_ids = util.flip_keys(rack_ids)

        return rack_ids


class GetStatisticsController:
    def __init__(self, cluster):
        self.cluster: Cluster = cluster

    async def get_all(self, nodes="all"):
        futures = [
            (
                constants.STAT_SERVICE,
                asyncio.create_task(self.get_service(nodes=nodes)),
            ),
            (
                constants.STAT_NAMESPACE,
                asyncio.create_task(self.get_namespace(nodes=nodes)),
            ),
            (constants.STAT_SETS, asyncio.create_task(self.get_sets(nodes=nodes))),
            (constants.STAT_BINS, asyncio.create_task(self.get_bins(nodes=nodes))),
            (constants.STAT_SINDEX, asyncio.create_task(self.get_sindex(nodes=nodes))),
            (constants.STAT_XDR, asyncio.create_task(self.get_xdr(nodes=nodes))),
            (constants.STAT_DC, asyncio.create_task(self.get_xdr_dcs(nodes=nodes))),
            (
                constants.STAT_XDR_NS,
                asyncio.create_task(self.get_xdr_namespaces(nodes=nodes)),
            ),
        ]

        stat_map = dict([(k, await f) for k, f in futures])

        return stat_map

    async def get_service(self, nodes="all"):
        service_stats = await self.cluster.info_statistics(nodes=nodes)
        return util.filter_exceptions(service_stats)

    async def get_namespace(self, flip=False, nodes="all", for_mods=[]):
        namespace_set = set(await _get_all_namespaces(self.cluster, nodes))
        namespace_list = list(util.filter_list(namespace_set, for_mods))
        tasks = [
            asyncio.create_task(
                self.cluster.info_namespace_statistics(namespace, nodes=nodes)
            )
            for namespace in namespace_list
        ]
        ns_stats = {}

        for namespace, stat_task in zip(namespace_list, tasks):
            ns_stats[namespace] = await stat_task

            if isinstance(ns_stats[namespace], Exception):
                continue

            for node in list(ns_stats[namespace].keys()):
                if not ns_stats[namespace][node] or isinstance(
                    ns_stats[namespace][node], Exception
                ):
                    ns_stats[namespace].pop(node)

        # Inverted match common structure of other getters, i.e. host is top level key
        if not flip:
            return util.flip_keys(ns_stats)

        return ns_stats

    async def get_sindex(
        self, flip=False, nodes="all", for_mods: list[str] | None = None
    ):
        stats = await self.cluster.info_sindex(nodes=nodes)
        stats = util.filter_exceptions(stats)

        result = {}
        if stats:
            for host, stat_list in stats.items():
                if not stat_list or isinstance(stat_list, Exception):
                    continue

                ns_filter = None
                sindex_filter = None

                if for_mods is not None:
                    try:
                        ns_filter = [for_mods[0]]
                        sindex_filter = [for_mods[1]]
                    except IndexError:
                        pass

                namespace_set = {stat["ns"] for stat in stat_list}
                namespace_set = set(util.filter_list(namespace_set, ns_filter))

                sindex_set = {stat["indexname"] for stat in stat_list}
                sindex_set = set(util.filter_list(sindex_set, sindex_filter))

                for stat in stat_list:
                    if not stat or stat["ns"] not in namespace_set:
                        continue

                    ns = stat["ns"]
                    set_ = stat["set"]
                    indexname = stat["indexname"]

                    if not indexname or not ns or indexname not in sindex_set:
                        continue

                    sindex_key = "%s %s %s" % (ns, set_, indexname)

                    if sindex_key not in result:
                        # Only call this once per sindex
                        result[sindex_key] = await self.cluster.info_sindex_statistics(
                            ns, indexname, nodes=nodes
                        )

                    for node in list(result[sindex_key]):
                        if not result[sindex_key][node] or isinstance(
                            result[sindex_key][node], Exception
                        ):
                            del result[sindex_key][node]
                            continue

                        for key, value in stat.items():
                            result[sindex_key][node][key] = value

        # Inverted match common structure of other getters, i.e. host is top level key
        if not flip:
            return util.flip_keys(result)

        return result

    async def get_sets(
        self, flip=False, nodes="all", for_mods: list[str] | None = None
    ):
        return await get_sets(self.cluster, flip, nodes, for_mods)

    async def get_bins(
        self, flip=False, nodes="all", for_mods: list[str] | None = None
    ):
        for_mods = [] if for_mods is None else for_mods
        bin_stats = await self.cluster.info_bin_statistics(nodes=nodes)
        new_bin_stats = {}

        for node_id, bin_stat in bin_stats.items():
            if not bin_stat or isinstance(bin_stat, Exception):
                continue

            namespace_set = set(util.filter_list(bin_stat.keys(), for_mods))

            for namespace, stats in bin_stat.items():
                if namespace not in namespace_set:
                    continue
                if namespace not in new_bin_stats:
                    new_bin_stats[namespace] = {}
                ns_stats = new_bin_stats[namespace]

                if node_id not in ns_stats:
                    ns_stats[node_id] = {}
                node_stats = ns_stats[node_id]

                node_stats.update(stats)

        # Inverted match common structure of other getters, i.e. host is top level key
        if not flip:
            return util.flip_keys(new_bin_stats)

        return new_bin_stats

    async def get_xdr(self, nodes="all"):
        xdr_stats = await self.cluster.info_XDR_statistics(nodes=nodes)

        for host, host_stats in xdr_stats.items():
            if not host_stats or isinstance(host_stats, Exception):
                xdr_stats[host] = {}
                continue

        return xdr_stats

    async def get_xdr_dcs(
        self, flip=False, nodes="all", for_mods: list[str] | None = None
    ):
        all_dcs = await _get_all_dcs(self.cluster, nodes)
        filter_dcs = list(util.filter_list(list(all_dcs), for_mods))

        result = await self.cluster.info_all_dc_statistics(nodes=nodes, dcs=filter_dcs)

        for host, host_stats in result.items():
            if not host_stats or isinstance(host_stats, Exception):
                result[host] = {}
                continue

            for dc, dc_stats in host_stats.items():
                if not dc_stats or isinstance(dc_stats, Exception):
                    result[host][dc] = {}

        if flip:
            return util.flip_keys(result)

        return result

    async def get_xdr_namespaces(
        self,
        nodes="all",
        for_mods: Optional[list[str]] = None,
    ):
        dcs_filter: list[str] | None = None
        namespaces_filter: list[str] | None = None

        if for_mods:
            try:
                namespaces_filter = [for_mods[0]]
                dcs_filter = [for_mods[1]]
            except IndexError:
                pass

        all_dcs = await _get_all_dcs(self.cluster, nodes)
        all_namespaces = await _get_all_namespaces(self.cluster, nodes)

        filtered_dcs = list(util.filter_list(list(all_dcs), dcs_filter))
        filtered_namespaces = list(
            util.filter_list(list(all_namespaces), namespaces_filter)
        )

        # Not all dcs have all namespaces but that is OK. This function checks that
        # a particular namespace is apart of a dc before making a request.
        result: NodeDict[
            DatacenterDict[NamespaceDict[dict[str, str]]]
        ] = await self.cluster.info_all_xdr_namespaces_statistics(
            namespaces=filtered_namespaces, dcs=filtered_dcs, nodes=nodes
        )

        for host, host_stats in result.items():
            if isinstance(host_stats, Exception) or host_stats is None:
                result[host] = {}
                continue

            for dc, dc_stats in host_stats.items():
                if isinstance(dc_stats, Exception) or dc_stats is None:
                    result[host][dc] = {}
                    continue

                for ns, ns_dict in dc_stats.items():
                    if isinstance(ns_dict, Exception) or ns_dict is None:
                        result[host][dc][ns] = {}

        return result


class GetFeaturesController:
    def __init__(self, cluster):
        self.cluster = cluster

    async def get_features(self, nodes="all"):
        (
            service_stats,
            ns_stats,
            xdr_dc_stats,
            service_configs,
            ns_configs,
            security_configs,
        ) = await asyncio.gather(
            self.cluster.info_statistics(nodes=nodes),
            self.cluster.info_all_namespace_statistics(nodes=nodes),
            self.cluster.info_all_dc_statistics(nodes=nodes),
            self.cluster.info_get_config(stanza="service", nodes=nodes),
            self.cluster.info_get_config(stanza="namespace", nodes=nodes),
            self.cluster.info_get_config(stanza="security", nodes=nodes),
        )

        return common.find_nodewise_features(
            service_stats=service_stats,
            ns_stats=ns_stats,
            xdr_dc_stats=xdr_dc_stats,
            service_configs=service_configs,
            ns_configs=ns_configs,
            security_configs=security_configs,
        )


class GetClusterMetadataController:
    # TODO: do we need this? Technically asadm only really ever deals with metadata. I
    # want this to handle things that arn't configs or stats . . .

    def __init__(self, cluster):
        self.cluster = cluster

    async def get_builds(self, nodes="all"):
        builds = await self.cluster.info_build(nodes=nodes)
        return util.filter_exceptions(builds)


class GetPmapController:
    def __init__(self, cluster):
        self.cluster = cluster

    def _get_namespace_data(self, namespace_stats, cluster_keys):
        ns_info = {}

        # stats to fetch
        stats = ["dead_partitions", "unavailable_partitions"]

        for ns, nodes in namespace_stats.items():
            for node, params in nodes.items():
                if isinstance(params, Exception):
                    continue

                if cluster_keys[node] not in ns_info:
                    ns_info[cluster_keys[node]] = {}

                d = ns_info[cluster_keys[node]]
                if ns not in d:
                    d[ns] = {}

                d = d[ns]
                if node not in d:
                    d[node] = {}

                for s in stats:
                    util.set_value_in_dict(
                        d[node], s, util.get_value_from_dict(params, (s,))
                    )

        return ns_info

    def _get_pmap_data(self, pmap_info, ns_info, cluster_keys, node_ids):
        pid_range = 4096  # each namespace is divided into 4096 partition
        pmap_data = {}
        ns_available_part = {}

        # format : (index_ptr, field_name, default_index)
        # required fields present in all versions
        required_fields = [
            ("namespace_index", "namespace", 0),
            ("partition_index", "partition", 1),
            ("state_index", "state", 2),
            ("replica_index", "replica", 3),
        ]

        # fields present in version < 3.15.0
        optional_old_fields = [
            ("origin_index", "origin", 4),
            ("target_index", "target", 5),
        ]

        # fields present in version >= 3.15.0
        optional_new_fields = [("working_master_index", "working_master", None)]

        for _node, partitions in pmap_info.items():
            node_pmap = dict()

            if _node not in cluster_keys or _node not in node_ids:
                continue

            ck = cluster_keys[_node]
            node_id = node_ids[_node]

            if isinstance(partitions, Exception):
                continue

            f_indices = {}

            # Setting default indices in partition fields for server < 3.8.4
            for t in required_fields + optional_old_fields + optional_new_fields:
                f_indices[t[0]] = t[2]

            # First row might be header, we need to check and set indices if its header row
            index_set = False

            for item in partitions.split(";"):
                fields = item.split(":")

                if not index_set:
                    # pmap format contains headers from server 3.8.4 onwards
                    index_set = True

                    if all(i[1] in fields for i in required_fields):
                        for t in required_fields:
                            f_indices[t[0]] = fields.index(t[1])

                        if all(i[1] in fields for i in optional_old_fields):
                            for t in optional_old_fields:
                                f_indices[t[0]] = fields.index(t[1])
                        elif all(i[1] in fields for i in optional_new_fields):
                            for t in optional_new_fields:
                                f_indices[t[0]] = fields.index(t[1])

                        continue

                ns, pid, state, replica = (
                    fields[f_indices["namespace_index"]],
                    int(fields[f_indices["partition_index"]]),
                    fields[f_indices["state_index"]],
                    int(fields[f_indices["replica_index"]]),
                )

                if f_indices["working_master_index"]:
                    working_master = fields[f_indices["working_master_index"]]
                    origin = target = None
                else:
                    origin, target = (
                        fields[f_indices["origin_index"]],
                        fields[f_indices["target_index"]],
                    )
                    working_master = None

                if pid not in range(pid_range):
                    print(
                        "For {0} found partition-ID {1} which is beyond legal partitions(0...4096)".format(
                            ns, pid
                        )
                    )
                    continue

                if ns not in node_pmap:
                    node_pmap[ns] = {
                        "master_partition_count": 0,
                        "prole_partition_count": 0,
                    }

                if ck not in ns_available_part:
                    ns_available_part[ck] = {}

                if ns not in ns_available_part[ck]:
                    ns_available_part[ck][ns] = {}
                    ns_available_part[ck][ns]["available_partition_count"] = 0

                if working_master:
                    if node_id == working_master:
                        # Working master
                        node_pmap[ns]["master_partition_count"] += 1

                    elif replica == 0 or state == "S" or state == "D":
                        # Eventual master or replicas
                        node_pmap[ns]["prole_partition_count"] += 1

                elif replica == 0:
                    if origin == "0":
                        # Working master (Final and proper master)
                        node_pmap[ns]["master_partition_count"] += 1

                    else:
                        # Eventual master
                        node_pmap[ns]["prole_partition_count"] += 1

                else:
                    if target == "0":
                        if state == "S" or state == "D":
                            node_pmap[ns]["prole_partition_count"] += 1

                    else:
                        # Working master (Acting master)
                        node_pmap[ns]["master_partition_count"] += 1

            pmap_data[_node] = node_pmap

        for _node, _ns_data in pmap_data.items():
            ck = cluster_keys[_node]

            for ns, params in _ns_data.items():
                params["cluster_key"] = ck

                try:
                    params.update(ns_info[ck][ns][_node])
                except Exception:
                    pass

        return pmap_data

    async def get_pmap(self, nodes="all"):
        getter = GetStatisticsController(self.cluster)
        service_stats = asyncio.create_task(getter.get_service(nodes=nodes))
        namespace_stats = asyncio.create_task(
            getter.get_namespace(flip=True, nodes=nodes)
        )
        node_ids = asyncio.create_task(self.cluster.info("node", nodes=nodes))
        pmap_info = asyncio.create_task(
            self.cluster.info("partition-info", nodes=nodes)
        )
        service_stats = await service_stats

        cluster_keys = {}
        for node in service_stats.keys():
            if not service_stats[node] or isinstance(service_stats[node], Exception):
                cluster_keys[node] = "N/E"
            else:
                cluster_keys[node] = util.get_value_from_dict(
                    service_stats[node], ("cluster_key"), default_value="N/E"
                )

        ns_info = self._get_namespace_data(await namespace_stats, cluster_keys)
        pmap_data = self._get_pmap_data(
            await pmap_info, ns_info, cluster_keys, await node_ids
        )

        return pmap_data


class GetAclController:
    def __init__(self, cluster):
        self.cluster = cluster

    async def get_all(self, nodes="all", flip=False):
        futures = [
            (
                constants.ADMIN_USERS,
                asyncio.create_task(self.get_users(nodes=nodes)),
            ),
            (
                constants.ADMIN_ROLES,
                asyncio.create_task(self.get_roles(nodes=nodes)),
            ),
        ]
        stat_map = dict([(k, await f) for k, f in futures])

        if flip:
            return util.flip_keys(stat_map)

        return stat_map

    async def get_users(self, nodes="all"):
        return await self.cluster.admin_query_users(nodes=nodes)

    async def get_user(self, username, nodes="all"):
        return await self.cluster.admin_query_user(username, nodes=nodes)

    async def get_roles(self, nodes="all"):
        return await self.cluster.admin_query_roles(nodes=nodes)

    async def get_role(self, role_name, nodes="all"):
        return await self.cluster.admin_query_role(role_name, nodes=nodes)


class GetUdfController:
    def __init__(self, cluster):
        self.cluster = cluster

    async def get_udfs(self, nodes="all"):
        return await self.cluster.info_udf_list(nodes=nodes)


class GetSIndexController:
    def __init__(self, cluster):
        self.cluster = cluster

    async def get_sindexs(self, nodes="all"):
        return await self.cluster.info_sindex(nodes=nodes)


class GetJobsController:
    def __init__(self, cluster):
        self.cluster = cluster

    async def get_all(self, flip=False, nodes="all"):
        futures = [
            (constants.JobType.SCAN, asyncio.create_task(self.get_scans(nodes=nodes))),
            (constants.JobType.QUERY, asyncio.create_task(self.get_query(nodes=nodes))),
            (
                constants.JobType.SINDEX_BUILDER,
                asyncio.create_task(self.get_sindex_builder(nodes=nodes)),
            ),
        ]
        job_map = dict([(k, await f) for k, f in futures])

        if flip:
            job_map = util.flip_keys(job_map)

        return job_map

    async def get_scans(self, nodes="all"):
        scan_data = await self.cluster.info_scan_show(nodes=nodes)

        for host, data in list(scan_data.items()):
            if isinstance(data, Exception):
                del scan_data[host]

        return scan_data

    async def get_query(self, nodes="all"):
        query_data = await self.cluster.info_query_show(nodes=nodes)

        for host, data in list(query_data.items()):
            if isinstance(data, Exception):
                del query_data[host]

        return query_data

    async def get_sindex_builder(self, nodes="all"):
        sindex_builder_data = await self.cluster.info_jobs(
            module="sindex-builder", nodes=nodes
        )

        for host, data in list(sindex_builder_data.items()):
            if isinstance(data, Exception):
                del sindex_builder_data[host]

        return sindex_builder_data
