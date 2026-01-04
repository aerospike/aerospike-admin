# Copyright 2021-2025 Aerospike, Inc.
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
import logging
from lib.live_cluster.get_controller import (
    GetConfigController,
    GetStatisticsController,
)
from lib.utils import util, version, constants
from lib.base_controller import CommandHelp, ModifierHelp
from .live_cluster_command_controller import LiveClusterCommandController
from lib.base_controller import ShellException

logger = logging.getLogger(__name__)

Modifiers = constants.Modifiers
ModifierUsageHelp = constants.ModifierUsage

with_modifier_help = ModifierHelp(
    Modifiers.WITH,
    "Show results from specified nodes. Acceptable values are ip:port, node-id, or FQDN",
    default="all",
)


@CommandHelp(
    "A collection of commands that display summary tables for various aspects of Aerospike namespaces",
    short_msg="Provides summary tables for various aspects of Aerospike functionality",
    usage=f"[{ModifierUsageHelp.WITH}]",
    modifiers=(with_modifier_help,),
)
class InfoController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "for"])
        self.controller_map = dict(
            namespace=InfoNamespaceController, transactions=InfoTransactionsController
        )
        self.config_getter = GetConfigController(self.cluster)
        self.stat_getter = GetStatisticsController(self.cluster)

    @CommandHelp("Displays network, namespace, and xdr summary information")
    async def _do_default(self, line):
        # If no subcommand is provided, show the default info summary with network, namespace, and xdr information
        # For unknown subcommands (e.g., 'info random'), we explicitly reject them rather than falling back to
        # the default info summary because:
        #  1. It's confusing for users - they expect either a valid result or a clear error
        #  2. It can mislead users into thinking their command was valid when it wasn't
        #  3. It produces inconsistent output - sometimes partial info would be shown
        #  4. It makes debugging harder - typos wouldn't be caught and reported
        if line:
            raise ShellException(
                f"info: '{line[0]}' is not a valid subcommand. See 'help info' for available subcommands."
            )

        results = await asyncio.gather(
            self.do_network(line),
            self.controller_map["namespace"](get_futures=True)([]),
            self.do_xdr(line),
        )

        results[1] = results[1]["futures"]

        return results

    @CommandHelp(
        "Displays network information for the cluster",
        usage=f"[{ModifierUsageHelp.WITH}]",
        modifiers=(with_modifier_help,),
    )
    async def do_network(self, line):
        stats, cluster_names, builds, versions = await asyncio.gather(
            self.cluster.info_statistics(nodes=self.nodes),
            self.cluster.info("cluster-name", nodes=self.nodes),
            self.cluster.info_build(nodes=self.nodes),
            self.cluster.info_version(nodes=self.nodes),
        )

        return util.callable(
            self.view.info_network,
            stats,
            cluster_names,
            versions,
            builds,
            self.cluster,
            **self.mods,
        )

    @CommandHelp("Displays summary information for each set")
    async def do_set(self, line):
        stats = await self.cluster.info_all_set_statistics(nodes=self.nodes)
        return util.callable(self.view.info_set, stats, self.cluster, **self.mods)

    # pre 5.0
    @CommandHelp(
        'Displays summary information for each datacenter. Replaced by "info xdr" for server >= 5.0.',
        usage=f"[{ModifierUsageHelp.WITH}]",
        modifiers=(with_modifier_help,),
        hide=True,
    )
    async def do_dc(self, line):
        stats, configs = await asyncio.gather(
            self.cluster.info_all_dc_statistics(nodes=self.nodes),
            self.config_getter.get_xdr_dcs(nodes=self.nodes),
        )
        builds = asyncio.create_task(self.cluster.info_build(nodes=self.nodes))

        for node in stats.keys():
            if (
                stats[node]
                and not isinstance(stats[node], Exception)
                and node in configs
                and configs[node]
                and not isinstance(configs[node], Exception)
            ):
                for dc in stats[node].keys():
                    try:
                        stats[node][dc].update(configs[node][dc])
                    except Exception:
                        pass

            elif (
                (not stats[node] or isinstance(stats[node], Exception))
                and node in configs
                and configs[node]
                and not isinstance(configs[node], Exception)
            ):
                try:
                    stats[node] = configs[node]
                except Exception:
                    pass

        nodes_running_v5_or_higher = False
        nodes_running_v49_or_lower = False
        node_xdr_build_major_version = 4
        builds = await builds

        for node in stats:
            try:
                node_xdr_build_major_version = int(builds[node][0])
            except Exception:
                continue

            if node_xdr_build_major_version >= 5:
                nodes_running_v5_or_higher = True
            else:
                nodes_running_v49_or_lower = True

        futures = []

        if nodes_running_v49_or_lower:
            futures.append(
                util.callable(self.view.info_dc, stats, self.cluster, **self.mods)
            )

        if nodes_running_v5_or_higher:
            futures.append(
                util.callable(
                    logger.warning,
                    "'info dc' is deprecated on aerospike versions >= 5.0. "
                    + "Use 'info xdr' instead.",
                )
            )

        return futures

    @CommandHelp(
        "Displays summary information for each datacenter",
        usage=f"[for <dc-substring>] [{ModifierUsageHelp.WITH}]",
        modifiers=(
            ModifierHelp(Modifiers.FOR, "Filter datacenters using a substring match"),
            with_modifier_help,
        ),
    )
    async def do_xdr(self, line):
        new_stats, old_stats, xdr_enabled, builds = await asyncio.gather(
            self.stat_getter.get_xdr_dcs(for_mods=self.mods["for"], nodes=self.nodes),
            self.stat_getter.get_xdr(nodes=self.nodes),
            self.cluster.is_XDR_enabled(nodes=self.nodes),
            self.cluster.info_build(nodes=self.nodes),
        )
        xdr5_stats = {}
        old_xdr_stats = {}

        for node in new_stats:
            if not isinstance(builds[node], Exception) and version.LooseVersion(
                builds[node]
            ) < version.LooseVersion(constants.SERVER_NEW_XDR5_VERSION):
                old_xdr_stats[node] = old_stats[node]
            else:
                xdr5_stats[node] = new_stats[node]

        futures = []

        if xdr5_stats:
            futures.append(
                util.callable(
                    self.view.info_XDR,
                    xdr5_stats,
                    xdr_enabled,
                    self.cluster,
                    **self.mods,
                )
            )

        if old_xdr_stats:
            futures.append(
                util.callable(
                    self.view.info_old_XDR,
                    old_xdr_stats,
                    builds,
                    xdr_enabled,
                    self.cluster,
                    **self.mods,
                )
            )

        return futures

    @CommandHelp(
        "Displays summary information for Secondary Indexes",
        usage=f"[{ModifierUsageHelp.WITH}]",
        modifiers=(with_modifier_help,),
    )
    async def do_sindex(self, line):
        sindex_stats, ns_configs = await asyncio.gather(
            self.stat_getter.get_sindex(), self.config_getter.get_namespace()
        )
        return util.callable(
            self.view.info_sindex, sindex_stats, ns_configs, self.cluster, **self.mods
        )

    @CommandHelp(
        "Displays detailed release information for the cluster (8.1.1 or later)",
        usage=f"[{ModifierUsageHelp.WITH}]",
        modifiers=(with_modifier_help,),
    )
    async def do_release(self, line):
        # Check if release info is supported on all nodes
        versions = await self.cluster.info_build(nodes=self.nodes)
        versions = util.filter_exceptions(versions)

        fully_supported = all(
            [
                (
                    True
                    if version.LooseVersion(v)
                    >= version.LooseVersion(constants.SERVER_RELEASE_INFO_FIRST_VERSION)
                    else False
                )
                for v in versions.values()
            ]
        )

        if not fully_supported:
            logger.warning(
                "'info release' is not supported on aerospike versions < %s",
                constants.SERVER_RELEASE_INFO_FIRST_VERSION,
            )
            return

        release_data = await self.cluster.info_release(nodes=self.nodes)
        return util.callable(
            self.view.info_release, release_data, self.cluster, **self.mods
        )


@CommandHelp(
    "A collection of commands that display summary tables for various aspects of Aerospike namespaces",
    usage=f"[{ModifierUsageHelp.WITH}]",
    modifiers=(with_modifier_help,),
)
class InfoNamespaceController(LiveClusterCommandController):
    def __init__(self, get_futures=False):
        self.modifiers = set(["with"])
        self.get_futures = get_futures
        self.stats_getter = GetStatisticsController(self.cluster)

    @CommandHelp(
        "Displays usage and objects information for each namespace",
    )
    async def _do_default(self, line):
        tasks = await asyncio.gather(
            self.do_usage(line),
            self.do_object(line),
        )
        if self.get_futures:
            # Wrapped to prevent base class from calling result.
            return dict(futures=tasks)

        return tasks

    @CommandHelp(
        "Displays usage information for each namespace.",
        usage=f"[{ModifierUsageHelp.WITH}]",
        modifiers=(with_modifier_help,),
    )
    async def do_usage(self, line):
        service_stats, ns_stats = await asyncio.gather(
            self.stats_getter.get_service(nodes=self.nodes),
            self.stats_getter.get_namespace(nodes=self.nodes),
        )  # Includes stats and configs
        return util.callable(
            self.view.info_namespace_usage,
            ns_stats,
            service_stats,
            self.cluster,
            **self.mods,
        )

    @CommandHelp(
        "Displays object information for each namespace.",
        usage=f"[{ModifierUsageHelp.WITH}]",
        modifiers=(with_modifier_help,),
    )
    async def do_object(self, line):
        # In SC mode effective rack-id is different from that in namespace config.
        config_getter = GetConfigController(self.cluster)
        stat_getter = GetStatisticsController(self.cluster)
        stats, rack_ids = await asyncio.gather(
            stat_getter.get_namespace(nodes=self.nodes),
            config_getter.get_rack_ids(nodes=self.nodes),
        )

        return util.callable(
            self.view.info_namespace_object, stats, rack_ids, self.cluster, **self.mods
        )


@CommandHelp(
    "Displays transaction metrics for each 'strong-consistency' enabled namespace.",
    usage=f"[{ModifierUsageHelp.WITH}]",
    modifiers=(with_modifier_help,),
)
class InfoTransactionsController(LiveClusterCommandController):
    def __init__(self, get_futures=False):
        self.modifiers = set(["with"])
        self.get_futures = get_futures
        self.stats_getter = GetStatisticsController(self.cluster)

    @CommandHelp(
        "Displays monitors and provisionals information for transactions in each 'strong-consistency' enabled namespace.",
    )
    async def _do_default(self, line):
        tasks = await asyncio.gather(
            self.do_monitors(line),
            self.do_provisionals(line),
        )
        if self.get_futures:
            # Wrapped to prevent base class from calling result.
            return dict(futures=tasks)

        return tasks

    @CommandHelp(
        "Displays monitor-related transaction metrics for each 'strong-consistency' enabled namespace.",
        usage=f"[{ModifierUsageHelp.WITH}]",
        modifiers=(with_modifier_help,),
    )
    async def do_monitors(self, line):
        # Get namespace statistics which contain MRT metrics
        ns_stats = await self.stats_getter.get_strong_consistency_namespace(
            nodes=self.nodes
        )

        # Collect all namespaces from all nodes
        namespaces = set()
        for node_id, node_stats in ns_stats.items():
            namespaces.update(node_stats.keys())

        # If no namespaces with strong consistency enabled were found, return
        if not namespaces:
            logger.debug(
                "No namespaces with strong consistency enabled were found for do_monitors"
            )
            return

        # Get <ERO~MRT set statistics for all namespaces from all nodes concurrently
        set_stats_futures = [
            asyncio.create_task(
                self.cluster.info_set_statistics(
                    namespace, constants.MRT_SET, nodes=self.nodes
                )
            )
            for namespace in namespaces
        ]
        all_set_data = await asyncio.gather(*set_stats_futures)

        # Map the results back to their namespaces and merge into ns_stats
        for namespace, set_data in zip(namespaces, all_set_data):
            for node_id, set_stats in set_data.items():
                if (
                    isinstance(set_stats, Exception)
                    or node_id not in ns_stats
                    or namespace not in ns_stats[node_id]
                ):
                    continue

                # Add set metrics to namespace stats with prefixed names
                ns_stats[node_id][namespace]["pseudo_mrt_monitor_used_bytes"] = int(
                    set_stats.get("data_used_bytes", 0) if set_stats else 0
                )
                ns_stats[node_id][namespace]["stop-writes-count"] = int(
                    set_stats.get("stop-writes-count", 0) if set_stats else 0
                )
                ns_stats[node_id][namespace]["stop-writes-size"] = int(
                    set_stats.get("stop-writes-size", 0) if set_stats else 0
                )

        return util.callable(
            self.view.info_transactions_monitors,
            ns_stats,
            self.cluster,
            **self.mods,
        )

    @CommandHelp(
        "Displays provisional-related transaction metrics for each 'strong-consistency' enabled namespace.",
        usage=f"[{ModifierUsageHelp.WITH}]",
        modifiers=(with_modifier_help,),
    )
    async def do_provisionals(self, line):
        # Get namespace statistics which contain MRT metrics
        ns_stats = await self.stats_getter.get_strong_consistency_namespace(
            nodes=self.nodes
        )

        # Check if any strong consistency namespaces were found
        namespaces = set()
        for _, node_stats in ns_stats.items():
            namespaces.update(node_stats.keys())

        if not namespaces:
            logger.debug(
                "No namespaces with strong consistency enabled were found for do_provisionals"
            )
            return

        return util.callable(
            self.view.info_transactions_provisionals,
            ns_stats,
            self.cluster,
            **self.mods,
        )
