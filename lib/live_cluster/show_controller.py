import asyncio
from lib.base_controller import CommandHelp, CommandName
from lib.utils import common, util, version, constants
from lib.get_controller import (
    GetConfigController,
    GetDistributionController,
    GetJobsController,
    GetPmapController,
    GetRolesController,
    GetSIndexController,
    GetStatisticsController,
    GetUdfController,
    GetUsersController,
    GetLatenciesController,
)

from .client import ASProtocolError
from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp('"show" is used to display Aerospike Statistics configuration.')
class ShowController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "distribution": ShowDistributionController,
            "mapping": ShowMappingController,
            "pmap": ShowPmapController,
            "best-practices": ShowBestPracticesController,
            "jobs": ShowJobsController,
            "racks": ShowRacksController,
            "roster": ShowRosterController,
            "roles": ShowRolesController,
            "users": ShowUsersController,
            "udfs": ShowUdfsController,
            "sindex": ShowSIndexController,
            "config": ShowConfigController,
            "latencies": ShowLatenciesController,
            "statistics": ShowStatisticsController,
        }

        self.modifiers = set()

    async def _do_default(self, line):
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
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_time_to_live(line[:]),
            self.do_object_size(line[:]),
        )

    @CommandHelp("Shows the distribution of TTLs for namespaces")
    async def do_time_to_live(self, line):

        histogram = await self.getter.do_distribution("ttl", nodes=self.nodes)

        return util.callable(
            self.view.show_distribution,
            "TTL Distribution",
            histogram,
            "Seconds",
            "ttl",
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
    async def do_object_size(self, line):

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
            histogram = await self.getter.do_object_size(nodes=self.nodes)
            units = None

            try:
                units = common.get_histogram_units(histogram)

                if units is None:
                    units = "Record Blocks"
            except Exception as e:
                self.logger.error(e)
                return

            return util.callable(
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

        return util.callable(
            self.view.show_object_distribution,
            title,
            await histogram,
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

    async def get_namespace_set(self):
        namespace_set = set()

        if self.mods["for"]:
            namespace_set = await self.latency_getter.get_namespace_set(self.nodes)
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
    async def _do_default(self, line):
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

        namespace_set = await self.get_namespace_set()
        latencies, (latencies_nodes, latency_nodes) = await asyncio.gather(
            self.latency_getter.get_all(
                self.nodes, buckets, increment, verbose, namespace_set
            ),
            self.latency_getter.get_latencies_and_latency_nodes(self.nodes),
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
            **self.mods,
        )


@CommandHelp('"show config" is used to display Aerospike configuration settings')
class ShowConfigController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like", "diff", "for"])
        self.getter = GetConfigController(self.cluster)

    @CommandHelp(
        "Displays security, service, network, and namespace configuration",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    -flip        - Flip output table to show Nodes on Y axis and config on X axis.",
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_security(line[:]),
            self.do_service(line[:]),
            self.do_network(line[:]),
            self.do_namespace(line[:]),
        )

    @CommandHelp("Displays security configuration")
    async def do_security(self, line):

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

        security_configs = await self.getter.get_security(nodes=self.nodes)

        return util.callable(
            self.view.show_config,
            "Security Configuration",
            security_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods,
        )

    @CommandHelp("Displays service configuration")
    async def do_service(self, line):

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

        service_configs = await self.getter.get_service(nodes=self.nodes)

        return util.callable(
            self.view.show_config,
            "Service Configuration",
            service_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods,
        )

    @CommandHelp("Displays network configuration")
    async def do_network(self, line):

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

        network_configs = await self.getter.get_network(nodes=self.nodes)

        return util.callable(
            self.view.show_config,
            "Network Configuration",
            network_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods,
        )

    @CommandHelp("Displays namespace configuration")
    async def do_namespace(self, line):

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

        ns_configs = await self.getter.get_namespace(
            flip=True, nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.callable(
                self.view.show_config,
                "%s Namespace Configuration" % (ns),
                configs,
                self.cluster,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods,
            )
            for ns, configs in list(ns_configs.items())
        ]

    @CommandHelp("Displays XDR configuration")
    async def do_xdr(self, line):

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

        xdr5_configs, old_xdr_configs = asyncio.gather(
            self.getter.get_xdr5(nodes=self.nodes),
            self.getter.get_old_xdr(nodes=self.nodes),
        )
        futures = []

        if xdr5_configs:
            formatted_configs = common.format_xdr5_configs(
                xdr5_configs, self.mods.get("for", [])
            )
            futures.append(
                util.callable(
                    self.view.show_xdr5_config,
                    "XDR Configuration",
                    formatted_configs,
                    self.cluster,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods,
                )
            )
        if old_xdr_configs:
            futures.append(
                util.callable(
                    self.view.show_config,
                    "XDR Configuration",
                    old_xdr_configs,
                    self.cluster,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods,
                )
            )

        return futures

    # pre 5.0
    @CommandHelp(
        "Displays datacenter configuration.",
        'Replaced by "show config xdr" for server >= 5.0.',
    )
    async def do_dc(self, line):
        builds = asyncio.create_task(self.cluster.info_build(nodes=self.nodes))
        dc_configs = asyncio.create_task(
            self.getter.get_dc(flip=True, nodes=self.nodes)
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

        nodes_running_v5_or_higher = False
        nodes_running_v49_or_lower = False
        node_xdr_build_major_version = 4
        builds = await builds

        for build in builds.values():
            try:
                node_xdr_build_major_version = int(build[0])
            except Exception:
                continue

            if node_xdr_build_major_version >= 5:
                nodes_running_v5_or_higher = True
            else:
                nodes_running_v49_or_lower = True

        futures = []
        dc_configs = await dc_configs

        if nodes_running_v49_or_lower:
            futures = [
                util.callable(
                    self.view.show_config,
                    "%s DC Configuration" % (dc),
                    configs,
                    self.cluster,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods,
                )
                for dc, configs in dc_configs.items()
            ]

        if nodes_running_v5_or_higher:
            futures.append(
                util.callable(
                    self.logger.warning,
                    "Detected nodes running aerospike version >= 5.0. "
                    + "Please use 'asadm -e \"show config xdr\"' for versions 5.0 and up.",
                )
            )

        return futures


@CommandHelp(
    '"show mapping" is used to display Aerospike mapping from IP to Node_id and Node_id to IPs'
)
class ShowMappingController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["like"])

    @CommandHelp("Displays mapping IPs to Node_id and Node_id to IPs")
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_ip(line),
            self.do_node(line),
        )

    @CommandHelp("Displays IP to Node_id mapping")
    async def do_ip(self, line):
        ip_to_node_map = await self.cluster.get_IP_to_node_map()
        return util.callable(
            self.view.show_mapping, "IP", "NODE-ID", ip_to_node_map, **self.mods
        )

    @CommandHelp("Displays Node_id to IPs mapping")
    async def do_node(self, line):
        node_to_ip_map = await self.cluster.get_node_to_IP_map()
        return util.callable(
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
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_bins(line[:]),
            self.do_sets(line[:]),
            self.do_service(line[:]),
            self.do_namespace(line[:]),
        )

    @CommandHelp("Displays service statistics")
    async def do_service(self, line):

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

        service_stats = await self.getter.get_service(nodes=self.nodes)

        return util.callable(
            self.view.show_stats,
            "Service Statistics",
            service_stats,
            self.cluster,
            show_total=show_total,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods,
        )

    @CommandHelp("Displays namespace statistics")
    async def do_namespace(self, line):
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

        ns_stats = await self.getter.get_namespace(
            flip=True, nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.callable(
                self.view.show_stats,
                "%s Namespace Statistics" % (namespace),
                ns_stats[namespace],
                self.cluster,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods,
            )
            for namespace in sorted(ns_stats.keys())
        ]

    @CommandHelp("Displays sindex statistics")
    async def do_sindex(self, line):
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

        sindex_stats = await self.getter.get_sindex(
            flip=True, nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.callable(
                self.view.show_stats,
                "%s Sindex Statistics" % (ns_set_sindex),
                sindex_stats[ns_set_sindex],
                self.cluster,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods,
            )
            for ns_set_sindex in sorted(sindex_stats.keys())
        ]

    @CommandHelp("Displays set statistics")
    async def do_sets(self, line):
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

        set_stats = await self.getter.get_sets(
            flip=True, nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.callable(
                self.view.show_stats,
                "%s %s Set Statistics" % (namespace, set_name),
                stats,
                self.cluster,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods,
            )
            for (namespace, set_name), stats in list(set_stats.items())
        ]

    @CommandHelp("Displays bin statistics")
    async def do_bins(self, line):
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

        new_bin_stats = await self.getter.get_bins(
            flip=True, nodes=self.nodes, for_mods=self.mods["for"]
        )

        return [
            util.callable(
                self.view.show_stats,
                "%s Bin Statistics" % (namespace),
                new_bin_stat,
                self.cluster,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods,
            )
            for namespace, new_bin_stat in list(new_bin_stats.items())
        ]

    @CommandHelp("Displays XDR statistics")
    async def do_xdr(self, line):
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

        builds, xdr_stats = await asyncio.gather(
            self.cluster.info_build(nodes=self.nodes),
            self.getter.get_xdr(nodes=self.nodes),
        )

        old_xdr_stats = {}
        xdr5_stats = {}
        node_xdr_build_major_version = 4

        for node in xdr_stats:
            try:
                node_xdr_build_major_version = int(builds[node][0])
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
                util.callable(
                    self.view.show_stats,
                    "XDR Statistics %s" % dc,
                    xdr5_stats[dc],
                    self.cluster,
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods,
                )
                for dc in xdr5_stats
                if not self.mods["for"] or dc in matches
            ]

        if old_xdr_stats:
            futures.append(
                util.callable(
                    self.view.show_stats,
                    "XDR Statistics",
                    old_xdr_stats,
                    self.cluster,
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods,
                )
            )

        return futures

    # pre 5.0
    @CommandHelp(
        "Displays datacenter statistics.",
        'Replaced by "show statistics xdr" for server >= 5.0.',
    )
    async def do_dc(self, line):

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

        dc_stats, builds = await asyncio.gather(
            self.getter.get_dc(flip=True, nodes=self.nodes),
            self.cluster.info_build(nodes=self.nodes),
        )

        nodes_running_v5_or_higher = False
        nodes_running_v49_or_lower = False
        node_xdr_build_major_version = 4

        for dc in dc_stats.values():

            for node in dc:
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
            futures = [
                util.callable(
                    self.view.show_config,
                    "%s DC Statistics" % (dc),
                    stats,
                    self.cluster,
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    **self.mods,
                )
                for dc, stats in list(dc_stats.items())
            ]

        if nodes_running_v5_or_higher:
            futures.append(
                util.callable(
                    self.logger.warning,
                    "'show statistics dc' is deprecated on aerospike versions >= 5.0. \n"
                    + "Use 'show statistics xdr' instead.",
                )
            )

        return futures


@CommandHelp("Displays partition map analysis of the Aerospike cluster.")
class ShowPmapController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set()
        self.getter = GetPmapController(self.cluster)

    async def _do_default(self, line):
        pmap_data = await self.getter.get_pmap(nodes=self.nodes)

        return self.view.show_pmap(pmap_data, self.cluster)


@CommandHelp(
    "Displays users and their assigned roles, connections, and quota metrics",
    "for the Aerospike cluster.",
    "Usage: users [user]",
    "  user          - Display output for a single user.",
)
class ShowUsersController(LiveClusterCommandController):
    def __init__(self):
        self.getter = GetUsersController(self.cluster)

    async def _do_default(self, line):
        user = None

        if line:
            user = line.pop(0)

        users_data = None

        if user is None:
            users_data = await self.getter.get_users(nodes="principal")
        else:
            users_data = await self.getter.get_user(user, nodes="principal")

        resp = list(users_data.values())[0]

        if isinstance(resp, ASProtocolError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        return self.view.show_users(resp, **self.mods)


@CommandHelp(
    "Displays roles and their assigned privileges, allowlist, and quotas",
    "for the Aerospike cluster.",
    "Usage: roles [role]",
    "  role          - Display output for a single role.",
)
class ShowRolesController(LiveClusterCommandController):
    def __init__(self):
        self.getter = GetRolesController(self.cluster)

    async def _do_default(self, line):
        role = None

        if line:
            role = line.pop(0)

        if role is None:
            roles_data = await self.getter.get_roles(nodes="principal")
        else:
            roles_data = await self.getter.get_role(role, nodes="principal")

        resp = list(roles_data.values())[0]

        if isinstance(resp, ASProtocolError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        return self.view.show_roles(resp, **self.mods)


@CommandHelp("Displays UDF modules along with metadata.")
class ShowUdfsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["like", "for"])
        self.getter = GetUdfController(self.cluster)

    async def _do_default(self, line):
        udfs_data = await self.getter.get_udfs(nodes="principal")
        resp = list(udfs_data.values())[0]

        return self.view.show_udfs(resp, **self.mods)


@CommandHelp("Displays secondary indexes and static metadata.")
class ShowSIndexController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["like"])
        self.getter = GetSIndexController(self.cluster)

    async def _do_default(self, line):
        sindexes_data = await self.getter.get_sindexs(nodes="principal")
        resp = list(sindexes_data.values())[0]

        self.view.show_sindex(resp, **self.mods)


@CommandHelp(
    'Displays roster information per node. Use the "diff" modifier to',
    'to show differences between node rosters. For easier viewing run "page on" first.',
    "  Options:",
    "    -flip        - Flip output table to show nodes on X axis and roster on Y axis.",
)
class ShowRosterController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["for", "with", "diff"])
        self.getter = GetConfigController(self.cluster)

    async def _do_default(self, line):
        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        roster_data = await self.getter.get_roster(flip=False, nodes=self.nodes)

        return self.view.show_roster(
            roster_data,
            self.cluster,
            flip=flip_output,
            **self.mods,
        )


@CommandHelp('Displays any of Aerospike\'s violated "best-practices".')
class ShowBestPracticesController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with"])

    async def _do_default(self, line):
        versions = asyncio.create_task(self.cluster.info_build())
        best_practices = asyncio.create_task(
            self.cluster.info_best_practices(nodes=self.nodes)
        )
        versions = await versions

        fully_supported = all(
            [
                True
                if version.LooseVersion(v)
                >= version.LooseVersion(
                    constants.SERVER_SHOW_BEST_PRACTICES_FIRST_VERSION
                )
                else False
                for v in versions.values()
            ]
        )

        if not fully_supported:
            self.logger.warning(
                "'show best-practices' is not supported on aerospike versions < {}",
                constants.SERVER_SHOW_BEST_PRACTICES_FIRST_VERSION,
            )

        best_practices = await best_practices

        return self.view.show_best_practices(self.cluster, best_practices, **self.mods)


@CommandHelp(
    "Displays jobs and associated metadata.",
)
class ShowJobsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like", "trid"])
        self.getter = GetJobsController(self.cluster)

    @CommandHelp(
        '"show jobs" displays scans, queries, and sindex-builder jobs.',
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_scans(line[:]),
            self.do_queries(line[:]),
            self.do_sindex_builder(line[:]),
        )

    @CommandHelp(
        'Displays scan jobs. For easier viewing run "page on" first.',
        "Usage: scans [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    async def do_scans(self, line):
        jobs = await self.getter.get_scans(nodes=self.nodes)
        return util.callable(
            self.view.show_jobs, "Scan Jobs", self.cluster, jobs, **self.mods
        )

    @CommandHelp(
        "Displays query jobs.",
        "Usage: queries [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    async def do_queries(self, line):
        jobs = await self.getter.get_query(nodes=self.nodes)
        return util.callable(
            self.view.show_jobs, "Query Jobs", self.cluster, jobs, **self.mods
        )

    # TODO: Should be removed eventually. "sindex-builder" was removed in server 5.7.
    # So should probably be removed when server 7.0 is supported.
    @CommandHelp(
        "Displays sindex-builder jobs. Removed in server v. 5.7 and later.",
        "Usage: sindex-builder [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    @CommandName("sindex-builder")
    async def do_sindex_builder(self, line):
        jobs = await self.getter.get_sindex_builder(nodes=self.nodes)
        return util.callable(
            self.view.show_jobs, "SIndex Builder Jobs", self.cluster, jobs, **self.mods
        )


@CommandHelp("Displays rack information for a rack-aware cluster.")
class ShowRacksController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with"])
        self.getter = GetConfigController(self.cluster)

    async def _do_default(self, line):
        racks_data = await self.getter.get_racks(nodes="principal", flip=False)
        return self.view.show_racks(racks_data, **self.mods)
