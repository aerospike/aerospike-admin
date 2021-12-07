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
    def _do_default(self, line):
        actions = [util.Future(self.do_network, line).start()]
        # We are not using line for any of subcommand, but if user enters 'info object' or 'info usage' then it will
        # give error for unexpected format. We can catch this inside InfoNamespaceController but in that case
        # it will show incomplete output, for ex. 'info object' will print output of 'info network', 'info xdr' and
        # 'info namespace object', but since it is not correct command it should print output for partial correct
        # command, in this case it should print data for 'info'. To keep consistent output format, we are passing empty
        # list as line.
        res = self.controller_map["namespace"](get_futures=True)(line)
        if isinstance(res, dict):
            if "futures" in res:
                actions.extend(res["futures"])
        else:
            for action in res:
                if action:
                    actions.append(action)
        actions.append(util.Future(self.do_xdr, line).start())

        return [action.result() for action in actions]

    @CommandHelp('"info network" displays network information for Aerospike.')
    def do_network(self, line):
        stats = util.Future(self.cluster.info_statistics, nodes=self.nodes).start()
        cluster_configs = util.Future(
            self.config_getter.get_cluster, nodes=self.nodes
        ).start()
        cluster_names = util.Future(
            self.cluster.info, "cluster-name", nodes=self.nodes
        ).start()
        builds = util.Future(self.cluster.info, "build", nodes=self.nodes).start()
        versions = util.Future(self.cluster.info, "version", nodes=self.nodes).start()

        cluster_names = cluster_names.result()
        builds = builds.result()
        versions = versions.result()
        cluster_configs.result()
        stats = stats.result()

        for node in stats:
            try:
                if not isinstance(cluster_configs[node]["mode"], Exception):
                    stats[node]["rackaware_mode"] = cluster_configs[node]["mode"]
            except Exception:
                pass
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
    def do_set(self, line):
        stats = self.cluster.info_all_set_statistics(nodes=self.nodes)
        return util.Future(self.view.info_set, stats, self.cluster, **self.mods)

    # pre 5.0
    @CommandHelp(
        '"info dc" displays summary information for each datacenter.',
        'Replaced by "info xdr" for server >= 5.0.',
    )
    def do_dc(self, line):
        stats = util.Future(
            self.cluster.info_all_dc_statistics, nodes=self.nodes
        ).start()
        builds = util.Future(self.cluster.info_build, nodes=self.nodes).start()

        configs = self.config_getter.get_dc(nodes=self.nodes)

        stats = stats.result()

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

        builds = builds.result()
        nodes_running_v5_or_higher = False
        nodes_running_v49_or_lower = False
        node_xdr_build_major_version = 4

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
    def do_xdr(self, line):
        stats = util.Future(self.cluster.info_XDR_statistics, nodes=self.nodes).start()
        xdr_enable = util.Future(self.cluster.is_XDR_enabled, nodes=self.nodes).start()
        builds = util.Future(self.cluster.info_build, nodes=self.nodes).start()
        stats = stats.result()
        builds = builds.result()

        old_xdr_stats = {}
        xdr5_stats = {}
        node_xdr_build_major_version = 4

        for node in stats:
            try:
                node_xdr_build_major_version = int(builds[node][0])
            except Exception:
                continue

            if node_xdr_build_major_version < 5:
                old_xdr_stats[node] = stats[node]
            else:
                xdr5_stats[node] = stats[node]

        xdr_enable = xdr_enable.result()
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

            futures = [
                util.Future(
                    self.view.info_XDR,
                    xdr5_stats[dc],
                    xdr_enable,
                    self.cluster,
                    title="XDR Information %s" % dc,
                    **self.mods
                )
                for dc in xdr5_stats
                if not self.mods["for"] or dc in matches
            ]

        if old_xdr_stats:
            futures.append(
                util.Future(
                    self.view.info_old_XDR,
                    old_xdr_stats,
                    builds,
                    xdr_enable,
                    self.cluster,
                    **self.mods
                )
            )

        return futures

    @CommandHelp(
        '"info sindex" displays summary information for Secondary Indexes (SIndex).'
    )
    def do_sindex(self, line):
        sindex_stats = get_sindex_stats(self.cluster, self.nodes)
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
    def _do_default(self, line):
        actions = [
            util.Future(self.do_usage, line).start(),
            util.Future(self.do_object, line).start(),
        ]

        if self.get_futures:
            # Wrapped to prevent base class from calling result.
            return dict(futures=actions)

        return [action.result() for action in actions]

    @CommandHelp("Displays usage information for each namespace.")
    def do_usage(self, line):
        stats = self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        return util.Future(
            self.view.info_namespace_usage, stats, self.cluster, **self.mods
        )

    @CommandHelp("Displays object information for each namespace.")
    def do_object(self, line):
        # In SC mode effective rack-id is different from that in namespace config.
        config_getter = GetConfigController(self.cluster)
        stat_getter = GetStatisticsController(self.cluster)
        stats = util.Future(stat_getter.get_namespace, nodes=self.nodes).start()
        rack_ids = util.Future(config_getter.get_rack_ids, nodes=self.nodes).start()
        stats = stats.result()
        rack_ids = rack_ids.result()

        return util.Future(
            self.view.info_namespace_object, stats, rack_ids, self.cluster, **self.mods
        )
