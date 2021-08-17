from lib.base_controller import CommandHelp
from lib.utils import common, util
from lib.get_controller import (
    GetConfigController,
    GetDistributionController,
    GetPmapController,
    GetRolesController,
    GetSIndexController,
    GetStatisticsController,
    GetUdfController,
    GetUsersController,
    GetLatenciesController,
)

from .client.info import ASProtocolError
from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp('"show" is used to display Aerospike Statistics configuration.')
class ShowController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "config": ShowConfigController,
            "statistics": ShowStatisticsController,
            "latencies": ShowLatenciesController,
            "distribution": ShowDistributionController,
            "mapping": ShowMappingController,
            "pmap": ShowPmapController,
            "users": ShowUsersController,
            "roles": ShowRolesController,
            "udfs": ShowUdfsController,
            "sindex": ShowSIndexController,
            # TODO
            # 'rosters': ShowRosterController,
            # 'racks': ShowRacksController,
            # 'jobs': ShowJobsController,
        }

        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    '"show distribution" is used to show the distribution of object sizes',
    "and time to live for node and a namespace.",
)
class ShowDistributionController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "for"])
        self.getter = GetDistributionController(self.cluster)

    @CommandHelp("Shows the distributions of Time to Live and Object Size")
    def _do_default(self, line):
        actions = (
            util.Future(self.do_time_to_live, line[:]).start(),
            util.Future(self.do_object_size, line[:]).start(),
        )

        return [action.result() for action in actions]

    @CommandHelp("Shows the distribution of TTLs for namespaces")
    def do_time_to_live(self, line):

        histogram = self.getter.do_distribution("ttl", nodes=self.nodes)

        return util.Future(
            self.view.show_distribution,
            "TTL Distribution",
            histogram,
            "Seconds",
            "ttl",
            self.cluster,
            like=self.mods["for"],
        )

    @CommandHelp(
        "Shows the distribution of namespace Eviction TTLs for server version 3.7.5 and below"
    )
    def do_eviction(self, line):

        histogram = self.getter.do_distribution("evict", nodes=self.nodes)

        return util.Future(
            self.view.show_distribution,
            "Eviction Distribution",
            histogram,
            "Seconds",
            "evict",
            self.cluster,
            like=self.mods["for"],
        )

    @CommandHelp(
        "Shows the distribution of Object sizes for namespaces",
        "  Options:",
        "    -b               - Force to show byte wise distribution of Object Sizes.",
        "                       Default is rblock wise distribution in percentage",
        "    -k <buckets>     - Maximum number of buckets to show if -b is set.",
        "                       It distributes objects in same size k buckets and ",
        "                       displays only buckets that have objects in them. ",
        "                       [default is 5].",
    )
    def do_object_size(self, line):

        byte_distribution = util.check_arg_and_delete_from_mods(
            line=line, arg="-b", default=False, modifiers=self.modifiers, mods=self.mods
        )

        bucket_count = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-k",
            return_type=int,
            default=5,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        if not byte_distribution:
            histogram = self.getter.do_object_size(nodes=self.nodes)
            units = None

            try:
                units = common.get_histogram_units(histogram)

                if units is None:
                    units = "Record Blocks"
            except Exception as e:
                self.logger.error(e)
                return

            return util.Future(
                self.view.show_distribution,
                "Object Size Distribution",
                histogram,
                units,
                "objsz",
                self.cluster,
                like=self.mods["for"],
            )

        histogram = self.getter.do_object_size(
            byte_distribution=True, bucket_count=bucket_count, nodes=self.nodes
        )

        histogram_name = "objsz"
        title = "Object Size Distribution"
        unit = "Bytes"
        set_bucket_count = True

        return util.Future(
            self.view.show_object_distribution,
            title,
            histogram,
            unit,
            histogram_name,
            bucket_count,
            set_bucket_count,
            self.cluster,
            like=self.mods["for"],
        )


@CommandHelp('"show latencies" is used to show the server latency histograms')
class ShowLatenciesController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like", "for"])
        self.latency_getter = GetLatenciesController(self.cluster)

    def get_namespace_set(self):
        namespace_set = set()

        if self.mods["for"]:
            namespace_set = self.latency_getter.get_namespace_set(self.nodes)
            namespace_set = set(util.filter_list(namespace_set, self.mods["for"]))

        return namespace_set

    def sort_data_by_histogram_name(self, latency_data):
        hist_latency = {}
        for node_id, hist_data in list(latency_data.items()):
            if isinstance(hist_data, Exception):
                continue
            for hist_name, data in list(hist_data.items()):
                if hist_name not in hist_latency:
                    hist_latency[hist_name] = {node_id: data}
                else:
                    hist_latency[hist_name][node_id] = data
        return hist_latency

    # It would be nice if the  'show latencies' help section could be completely removed for servers prior to 5.1
    @CommandHelp(
        "Displays latency information for the Aerospike cluster.",
        "  Options:",
        "    -e           - Exponential increment of latency buckets, i.e. 2^0 2^(e) ... 2^(e * i)",
        "                   [default: 3]",
        "    -b           - Number of latency buckets to display.",
        "                   [default: 3]",
        "    -v           - Set to display verbose output of optionally configured histograms.",
    )
    def _do_default(self, line):
        increment = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-e",
            return_type=int,
            default=3,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        buckets = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-b",
            return_type=int,
            default=3,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        verbose = util.check_arg_and_delete_from_mods(
            line=line, arg="-v", default=False, modifiers=self.modifiers, mods=self.mods
        )

        namespace_set = self.get_namespace_set()
        (
            latencies_nodes,
            latency_nodes,
        ) = self.latency_getter.get_latencies_and_latency_nodes(self.nodes)
        latencies = self.latency_getter.get_all(
            self.nodes, buckets, increment, verbose, namespace_set
        )

        # No nodes support "show latencies"
        if len(latencies_nodes) == 0:
            self.logger.warning(
                "'show latencies' is not fully supported on aerospike versions <= 5.0"
            )
        # Some nodes support latencies and some do not
        elif len(latency_nodes) != 0:
            self.logger.warning(
                "'show latencies' is not fully supported on aerospike versions <= 5.0"
            )

        # TODO: This format should probably be returned from get controller
        latencies = self.sort_data_by_histogram_name(latencies)

        self.view.show_latency(
            latencies,
            self.cluster,
            show_ns_details=True if namespace_set else False,
            **self.mods
        )


@CommandHelp('"show config" is used to display Aerospike configuration settings')
class ShowConfigController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like", "diff", "for"])
        self.getter = GetConfigController(self.cluster)

    @CommandHelp(
        "Displays service, network, and namespace configuration",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    -flip        - Flip output table to show Nodes on Y axis and config on X axis.",
    )
    def _do_default(self, line):
        actions = (
            util.Future(self.do_service, line[:]).start(),
            util.Future(self.do_network, line[:]).start(),
            util.Future(self.do_namespace, line[:]).start(),
        )

        return [action.result() for action in actions]

    @CommandHelp("Displays service configuration")
    def do_service(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        service_configs = self.getter.get_service(nodes=self.nodes)

        return util.Future(
            self.view.show_config,
            "Service Configuration",
            service_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods
        )

    @CommandHelp("Displays network configuration")
    def do_network(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        network_configs = self.getter.get_network(nodes=self.nodes)

        return util.Future(
            self.view.show_config,
            "Network Configuration",
            network_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods
        )

    @CommandHelp("Displays namespace configuration")
    def do_namespace(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ns_configs = self.getter.get_namespace(
            nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.Future(
                self.view.show_config,
                "%s Namespace Configuration" % (ns),
                configs,
                self.cluster,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods
            )
            for ns, configs in list(ns_configs.items())
        ]

    @CommandHelp("Displays XDR configuration")
    def do_xdr(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr5_configs = self.getter.get_xdr5(nodes=self.nodes)
        old_xdr_configs = self.getter.get_old_xdr(nodes=self.nodes)

        futures = []

        if xdr5_configs:
            formatted_configs = common.format_xdr5_configs(
                xdr5_configs, self.mods.get("for", [])
            )
            futures.append(
                util.Future(
                    self.view.show_xdr5_config,
                    "XDR Configuration",
                    formatted_configs,
                    self.cluster,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods
                )
            )
        if old_xdr_configs:
            futures.append(
                util.Future(
                    self.view.show_config,
                    "XDR Configuration",
                    old_xdr_configs,
                    self.cluster,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods
                )
            )

        return futures

    # pre 5.0
    @CommandHelp(
        "Displays datacenter configuration.",
        'Replaced by "show config xdr" for server >= 5.0.',
    )
    def do_dc(self, line):

        xdr_builds = util.Future(
            self.cluster.info_build_version, nodes=self.nodes
        ).start()

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        dc_configs = self.getter.get_dc(nodes=self.nodes)
        nodes_running_v5_or_higher = False
        nodes_running_v49_or_lower = False
        xdr_builds = xdr_builds.result()
        node_xdr_build_major_version = 4

        for xdr_build in xdr_builds.values():
            try:
                node_xdr_build_major_version = int(xdr_build[0])
            except Exception:
                continue

            if node_xdr_build_major_version >= 5:
                nodes_running_v5_or_higher = True
            else:
                nodes_running_v49_or_lower = True

        futures = []
        if nodes_running_v49_or_lower:
            futures = [
                util.Future(
                    self.view.show_config,
                    "%s DC Configuration" % (dc),
                    configs,
                    self.cluster,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods
                )
                for dc, configs in dc_configs.items()
            ]

        if nodes_running_v5_or_higher:
            futures.append(
                util.Future(
                    self.logger.warning,
                    "Detected nodes running aerospike version >= 5.0. "
                    + "Please use 'asadm -e \"show config xdr\"' for versions 5.0 and up.",
                )
            )

        return futures

    @CommandHelp("Displays Cluster configuration")
    def do_cluster(self, line):

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        cl_configs = self.getter.get_cluster(nodes=self.nodes)

        return util.Future(
            self.view.show_config,
            "Cluster Configuration",
            cl_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods
        )


@CommandHelp(
    '"show mapping" is used to display Aerospike mapping from IP to Node_id and Node_id to IPs'
)
class ShowMappingController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["like"])

    @CommandHelp("Displays mapping IPs to Node_id and Node_id to IPs")
    def _do_default(self, line):
        actions = (
            util.Future(self.do_ip, line).start(),
            util.Future(self.do_node, line).start(),
        )
        return [action.result() for action in actions]

    @CommandHelp("Displays IP to Node_id mapping")
    def do_ip(self, line):
        ip_to_node_map = self.cluster.get_IP_to_node_map()
        return util.Future(
            self.view.show_mapping, "IP", "NODE-ID", ip_to_node_map, **self.mods
        )

    @CommandHelp("Displays Node_id to IPs mapping")
    def do_node(self, line):
        node_to_ip_map = self.cluster.get_node_to_IP_map()
        return util.Future(
            self.view.show_mapping, "NODE-ID", "IPs", node_to_ip_map, **self.mods
        )


@CommandHelp(
    '"show statistics" is used to display statistics for Aerospike components.'
)
class ShowStatisticsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like", "for"])
        self.getter = GetStatisticsController(self.cluster)

    @CommandHelp(
        "Displays bin, set, service, and namespace statistics",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    -flip        - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
    def _do_default(self, line):

        actions = (
            util.Future(self.do_bins, line[:]).start(),
            util.Future(self.do_sets, line[:]).start(),
            util.Future(self.do_service, line[:]).start(),
            util.Future(self.do_namespace, line[:]).start(),
        )

        return [action.result() for action in actions]

    @CommandHelp("Displays service statistics")
    def do_service(self, line):

        show_total = util.check_arg_and_delete_from_mods(
            line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods
        )

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        service_stats = self.getter.get_service(nodes=self.nodes)

        return util.Future(
            self.view.show_stats,
            "Service Statistics",
            service_stats,
            self.cluster,
            show_total=show_total,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods
        )

    @CommandHelp("Displays namespace statistics")
    def do_namespace(self, line):

        show_total = util.check_arg_and_delete_from_mods(
            line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods
        )

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ns_stats = self.getter.get_namespace(
            nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.Future(
                self.view.show_stats,
                "%s Namespace Statistics" % (namespace),
                ns_stats[namespace],
                self.cluster,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods
            )
            for namespace in sorted(ns_stats.keys())
        ]

    @CommandHelp("Displays sindex statistics")
    def do_sindex(self, line):

        show_total = util.check_arg_and_delete_from_mods(
            line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods
        )

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        sindex_stats = self.getter.get_sindex(
            nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.Future(
                self.view.show_stats,
                "%s Sindex Statistics" % (ns_set_sindex),
                sindex_stats[ns_set_sindex],
                self.cluster,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods
            )
            for ns_set_sindex in sorted(sindex_stats.keys())
        ]

    @CommandHelp("Displays set statistics")
    def do_sets(self, line):

        show_total = util.check_arg_and_delete_from_mods(
            line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods
        )

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        set_stats = self.getter.get_sets(nodes=self.nodes, for_mods=self.mods["for"])

        return [
            util.Future(
                self.view.show_stats,
                "%s %s Set Statistics" % (namespace, set_name),
                stats,
                self.cluster,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods
            )
            for (namespace, set_name), stats in list(set_stats.items())
        ]

    @CommandHelp("Displays bin statistics")
    def do_bins(self, line):

        show_total = util.check_arg_and_delete_from_mods(
            line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods
        )

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        new_bin_stats = self.getter.get_bins(
            nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.Future(
                self.view.show_stats,
                "%s Bin Statistics" % (namespace),
                new_bin_stat,
                self.cluster,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods
            )
            for namespace, new_bin_stat in list(new_bin_stats.items())
        ]

    @CommandHelp("Displays XDR statistics")
    def do_xdr(self, line):
        show_total = util.check_arg_and_delete_from_mods(
            line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods
        )

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_builds = util.Future(
            self.cluster.info_build_version, nodes=self.nodes
        ).start()

        xdr_stats = util.Future(self.getter.get_xdr, nodes=self.nodes).start()

        xdr_builds = xdr_builds.result()
        xdr_stats = xdr_stats.result()
        old_xdr_stats = {}
        xdr5_stats = {}
        node_xdr_build_major_version = 4

        for node in xdr_stats:
            try:
                node_xdr_build_major_version = int(xdr_builds[node][0])
            except Exception:
                continue

            if node_xdr_build_major_version < 5:
                old_xdr_stats[node] = xdr_stats[node]
            else:
                xdr5_stats[node] = xdr_stats[node]

        futures = []

        if xdr5_stats:
            temp = {}
            for node in xdr5_stats:
                for dc in xdr5_stats[node]:
                    if dc not in temp:
                        temp[dc] = {}
                    temp[dc][node] = xdr5_stats[node][dc]

            xdr5_stats = temp

            if self.mods["for"]:
                matches = set(util.filter_list(xdr5_stats.keys(), self.mods["for"]))

            futures = [
                util.Future(
                    self.view.show_stats,
                    "XDR Statistics %s" % dc,
                    xdr5_stats[dc],
                    self.cluster,
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods
                )
                for dc in xdr5_stats
                if not self.mods["for"] or dc in matches
            ]

        if old_xdr_stats:
            futures.append(
                util.Future(
                    self.view.show_stats,
                    "XDR Statistics",
                    old_xdr_stats,
                    self.cluster,
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods
                )
            )

        return futures

    # pre 5.0
    @CommandHelp(
        "Displays datacenter statistics.",
        'Replaced by "show statistics xdr" for server >= 5.0.',
    )
    def do_dc(self, line):

        show_total = util.check_arg_and_delete_from_mods(
            line=line, arg="-t", default=False, modifiers=self.modifiers, mods=self.mods
        )

        title_every_nth = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-r",
            return_type=int,
            default=0,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        dc_stats = util.Future(self.getter.get_dc, nodes=self.nodes).start()

        xdr_builds = util.Future(
            self.cluster.info_build_version, nodes=self.nodes
        ).start()

        dc_stats = dc_stats.result()
        xdr_builds = xdr_builds.result()
        nodes_running_v5_or_higher = False
        nodes_running_v49_or_lower = False
        node_xdr_build_major_version = 4

        for dc in dc_stats.values():

            for node in dc:
                try:
                    node_xdr_build_major_version = int(xdr_builds[node][0])
                except Exception:
                    continue

                if node_xdr_build_major_version >= 5:
                    nodes_running_v5_or_higher = True
                else:
                    nodes_running_v49_or_lower = True

        futures = []

        if nodes_running_v49_or_lower:
            futures = [
                util.Future(
                    self.view.show_config,
                    "%s DC Statistics" % (dc),
                    stats,
                    self.cluster,
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods
                )
                for dc, stats in list(dc_stats.items())
            ]

        if nodes_running_v5_or_higher:
            futures.append(
                util.Future(
                    self.logger.warning,
                    "'show statistics dc' is deprecated on aerospike versions >= 5.0. \n"
                    + "Use 'show statistics xdr' instead.",
                )
            )

        return futures


@CommandHelp('"show pmap" displays partition map analysis of the Aerospike cluster.')
class ShowPmapController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set()
        self.getter = GetPmapController(self.cluster)

    def _do_default(self, line):
        pmap_data = self.getter.get_pmap(nodes=self.nodes)

        return util.Future(self.view.show_pmap, pmap_data, self.cluster)


@CommandHelp(
    '"show users" displays users and their assigned roles, connections, and quota metrics',
    "for the Aerospike cluster.",
)
class ShowUsersController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["like"])
        self.getter = GetUsersController(self.cluster)

    def _do_default(self, line):
        principal_node = self.cluster.get_expected_principal()
        users_data = self.getter.get_users(nodes=[principal_node])
        resp = list(users_data.values())[0]

        if isinstance(resp, ASProtocolError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        return util.Future(self.view.show_users, resp, **self.mods)


@CommandHelp(
    '"show roles" displays roles and their assigned privileges, allowlist, and quotas',
    "for the Aerospike cluster.",
)
class ShowRolesController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["like"])
        self.getter = GetRolesController(self.cluster)

    def _do_default(self, line):
        principal_node = self.cluster.get_expected_principal()
        roles_data = self.getter.get_roles(nodes=[principal_node])
        resp = list(roles_data.values())[0]

        if isinstance(resp, ASProtocolError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        return util.Future(self.view.show_roles, resp, **self.mods)


@CommandHelp('"show udfs" displays UDF modules along with metadata.')
class ShowUdfsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["like"])
        self.getter = GetUdfController(self.cluster)

    def _do_default(self, line):
        principal_node = self.cluster.get_expected_principal()
        udfs_data = self.getter.get_udfs(nodes=[principal_node])
        resp = list(udfs_data.values())[0]

        return util.Future(self.view.show_udfs, resp, **self.mods)


@CommandHelp('"show sindex" displays secondary indexes and static metadata.')
class ShowSIndexController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["like"])
        self.getter = GetSIndexController(self.cluster)

    def _do_default(self, line):
        principal_node = self.cluster.get_expected_principal()
        sindexes_data = self.getter.get_sindexs(nodes=[principal_node])
        resp = list(sindexes_data.values())[0]

        return util.Future(self.view.show_sindex, resp, **self.mods)
