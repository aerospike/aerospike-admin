import asyncio
from lib.get_controller import (
    GetConfigController,
    GetStatisticsController,
    get_sindex_stats,
)
from lib.utils import util
from lib.base_controller import CommandHelp

from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp(
    'The "info" command provides summary tables for various aspects',
    "of Aerospike functionality.",
)
class InfoController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "for"])
        self.controller_map = dict(namespace=InfoNamespaceController)
        self.config_getter = GetConfigController(self.cluster)

    @CommandHelp("Displays network, namespace, and XDR summary information.")
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_network(line),
            self.controller_map["namespace"]()(line),
            self.do_xdr(line),
        )

    @CommandHelp('"info network" displays network information for Aerospike.')
    async def do_network(self, line):
        stats, cluster_names, builds, versions = await asyncio.gather(
            self.cluster.info_statistics(nodes=self.nodes),
            self.cluster.info("cluster-name", nodes=self.nodes),
            self.cluster.info("build", nodes=self.nodes),
            self.cluster.info("version", nodes=self.nodes),
        )

        return util.Future(
            self.view.info_network,
            stats,
            cluster_names,
            versions,
            builds,
            self.cluster,
            **self.mods
        )

    @CommandHelp('"info set" displays summary information for each set.')
    async def do_set(self, line):
        stats = await self.cluster.info_all_set_statistics(nodes=self.nodes)
        return util.Future(self.view.info_set, stats, self.cluster, **self.mods)

    # pre 5.0
    @CommandHelp(
        '"info dc" displays summary information for each datacenter.',
        'Replaced by "info xdr" for server >= 5.0.',
    )
    async def do_dc(self, line):
        stats = self.cluster.info_all_dc_statistics(nodes=self.nodes)
        configs = self.config_getter.get_dc(nodes=self.nodes)
        builds = self.cluster.info_build(nodes=self.nodes)
        configs = await configs
        stats = await stats

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
                util.Future(self.view.info_dc, stats, self.cluster, **self.mods)
            )

        if nodes_running_v5_or_higher:
            futures.append(
                util.Future(
                    self.logger.warning,
                    "'info dc' is deprecated on aerospike versions >= 5.0. "
                    + "Use 'info xdr' instead.",
                )
            )

        return futures

    @CommandHelp('"info xdr" displays summary information for each datacenter.')
    async def do_xdr(self, line):
        stats = self.cluster.info_XDR_statistics(nodes=self.nodes)
        builds = self.cluster.info_build(nodes=self.nodes)
        xdr_enable = self.cluster.is_XDR_enabled(nodes=self.nodes)

        old_xdr_stats = {}
        xdr5_stats = {}
        node_xdr_build_major_version = 4

        stats = await stats
        builds = await builds

        for node in stats:
            try:
                node_xdr_build_major_version = int(builds[node][0])
            except Exception:
                continue

            if node_xdr_build_major_version < 5:
                old_xdr_stats[node] = stats[node]
            else:
                xdr5_stats[node] = stats[node]

        xdr_enable = await xdr_enable
        futures = []

        if xdr5_stats:
            temp = {}
            for node in xdr5_stats:
                for dc in xdr5_stats[node]:
                    if dc not in temp:
                        temp[dc] = {}
                    temp[dc][node] = xdr5_stats[node][dc]

            xdr5_stats = temp
            matches = None

            if self.mods["for"]:
                matches = set(util.filter_list(xdr5_stats.keys(), self.mods["for"]))

            # futures = [
            #     util.Future(
            #         self.view.info_XDR,
            #         xdr5_stats[dc],
            #         xdr_enable,
            #         self.cluster,
            #         title="XDR Information %s" % dc,
            #         **self.mods
            #     )
            #     for dc in xdr5_stats
            #     if not self.mods["for"] or dc in matches
            # ]

        # if old_xdr_stats:
        #     futures.append(
        #         util.Future(
        #             self.view.info_old_XDR,
        #             old_xdr_stats,
        #             builds,
        #             xdr_enable,
        #             self.cluster,
        #             **self.mods
        #         )
        #     )

        return futures

    @CommandHelp(
        '"info sindex" displays summary information for Secondary Indexes (SIndex).'
    )
    async def do_sindex(self, line):
        sindex_stats = await get_sindex_stats(self.cluster, self.nodes)
        return util.Future(
            self.view.info_sindex, sindex_stats, self.cluster, **self.mods
        )


@CommandHelp(
    '"info namespace" command provides summary tables for various aspects',
    "of Aerospike namespaces.",
)
class InfoNamespaceController(LiveClusterCommandController):
    def __init__(self, get_futures=False):
        self.modifiers = set(["with"])
        self.get_futures = get_futures

    @CommandHelp("Displays usage and objects information for namespaces")
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_usage(line),
            self.do_object(line),
        )

    @CommandHelp("Displays usage information for each namespace.")
    async def do_usage(self, line):
        stats = await self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        return util.Future(
            self.view.info_namespace_usage, stats, self.cluster, **self.mods
        )

    @CommandHelp("Displays object information for each namespace.")
    async def do_object(self, line):
        # In SC mode effective rack-id is different from that in namespace config.
        config_getter = GetConfigController(self.cluster)
        stat_getter = GetStatisticsController(self.cluster)
        stats = stat_getter.get_namespace(nodes=self.nodes)
        rack_ids = config_getter.get_rack_ids(nodes=self.nodes)

        return util.Future(
            self.view.info_namespace_object,
            await stats,
            await rack_ids,
            self.cluster,
            **self.mods
        )
