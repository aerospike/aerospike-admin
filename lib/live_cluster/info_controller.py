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
        self.controller_map = dict(namespace=InfoNamespaceController)
        self.config_getter = GetConfigController(self.cluster)
        self.stat_getter = GetStatisticsController(self.cluster)

    @CommandHelp("Displays network, namespace, and xdr summary information")
    async def _do_default(self, line):
        # We are not using line for any of subcommand, but if user enters 'info object' or 'info usage' then it will
        # give error for unexpected format. We can catch this inside InfoNamespaceController but in that case
        # it will show incomplete output, for ex. 'info object' will print output of 'info network', 'info xdr' and
        # 'info namespace object', but since it is not correct command it should print output for partial correct
        # command, in this case it should print data for 'info'. To keep consistent output format, we are passing empty
        # list as line.
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
            self.cluster.info("version", nodes=self.nodes),
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
