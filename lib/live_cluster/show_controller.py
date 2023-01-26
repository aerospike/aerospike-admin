import asyncio
from lib.base_controller import CommandHelp, CommandName
from lib.utils import common, util, version, constants
from lib.live_cluster.get_controller import (
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
        self.controller_map = {"xdr": ShowConfigXDRController}

    @CommandHelp(
        "Displays security, service, network, and namespace configuration",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_security(line[:]),
            self.do_service(line[:]),
            self.do_network(line[:]),
            self.do_namespace(line[:]),
        )

    @CommandHelp(
        "Displays security configuration",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    @CommandHelp(
        "Displays service configuration",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    @CommandHelp(
        "Displays network configuration",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    @CommandHelp(
        "Displays namespace configuration",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    # pre 5.0 but will still work
    @CommandHelp(
        "DEPRECATED: Replaced by 'show config xdr'",
        "Displays datacenter configuration.",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
    async def do_dc(self, line):
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        futures = []
        dc_configs = await self.getter.get_xdr_dcs(flip=True, nodes=self.nodes)

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

        futures.append(
            util.callable(
                self.logger.warning,
                "'show config dc' is deprecated. Please use 'show config xdr dc' instead.",
            )
        )

        return futures


@CommandHelp(
    "'show config xdr' is used to display Aerospike XDR configuration settings."
)
class ShowConfigXDRController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like", "diff", "for"])
        self.getter = GetConfigController(self.cluster)

    @CommandHelp(
        "Displays xdr, xdr datacenter, and xdr namespace configuration.",
        "Use the available subcommands for more granularity.",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self._do_xdr(line[:]),
            self.do_dc(line[:]),
            self.do_namespace(line[:]),
        )

    async def _do_xdr(self, line):
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_configs = await self.getter.get_xdr(nodes=self.nodes)
        return util.callable(
            self.view.show_config,
            "XDR Configuration",
            xdr_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods,
        )

    @CommandHelp(
        "Displays xdr datacenter configuration.",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
    async def do_dc(self, line):
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_ns_configs = await self.getter.get_xdr_dcs(
            nodes=self.nodes, for_mods=self.mods["for"]
        )
        return util.callable(
            self.view.show_xdr_dc_config,
            xdr_ns_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods,
        )

    @CommandHelp(
        "Displays xdr namespace configuration.",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_ns_configs = await self.getter.get_xdr_namespaces(
            nodes=self.nodes, for_mods=self.mods["for"]
        )
        return util.callable(
            self.view.show_xdr_ns_config,
            xdr_ns_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods,
        )

    @CommandHelp(
        "Displays xdr filters.",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip      - Flip output table to show Nodes on Y axis and config on X axis.",
    )
    async def do_filter(self, line):
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        builds = asyncio.create_task(self.cluster.info_build(nodes="principal"))
        xdr_filters = asyncio.create_task(
            self.getter.get_xdr_filters(nodes="principal", for_mods=self.mods["for"])
        )
        builds = await builds

        fully_supported = all(
            [
                True
                if version.LooseVersion(v)
                >= version.LooseVersion(constants.SERVER_XDR_FILTER_FIRST_VERSION)
                else False
                for v in builds.values()
            ]
        )

        self.view.show_xdr_filters(
            await xdr_filters,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            **self.mods,
        )

        if not fully_supported:
            self.logger.warning(
                "Server version 5.3 or newer is required to run 'show config xdr filter'"
            )


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


@CommandHelp('"show statistics" is used to display statistics.')
class ShowStatisticsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like", "for"])
        self.getter = GetStatisticsController(self.cluster)
        self.controller_map = {"xdr": ShowStatisticsXDRController}

    @CommandHelp(
        "Displays bin, set, service, and namespace statistics",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_bins(line[:]),
            self.do_sets(line[:]),
            self.do_service(line[:]),
            self.do_namespace(line[:]),
        )

    @CommandHelp(
        "Displays service statistics",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    @CommandHelp(
        "Displays namespace statistics",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    @CommandHelp(
        "Displays sindex statistics",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    @CommandHelp(
        "Displays set statistics",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    @CommandHelp(
        "Displays bin statistics",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    # pre 5.0 but still works
    @CommandHelp(
        "DEPRECATED: Replaced by 'show statistics xdr dc.'",
        "Displays datacenter statistics.",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        dc_stats = await self.getter.get_xdr_dcs(nodes=self.nodes)

        futures = [
            util.callable(
                self.view.show_xdr_dc_stats,
                dc_stats,
                self.cluster,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                show_total=show_total,
                **self.mods,
            )
        ]

        futures.append(
            util.callable(
                self.logger.warning,
                "'show statistics dc' is deprecated. Please use 'show statistics xdr dc' instead.",
            )
        )

        return futures


@CommandHelp(
    '"show statistics xdr" is used to display xdr statistics for Aerospike components.'
)
class ShowStatisticsXDRController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with", "like", "diff", "for"])
        self.getter = GetStatisticsController(self.cluster)

    @CommandHelp(
        "Displays xdr, xdr datacenter, and xdr namespace statistics.",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self._do_xdr(line[:]),
            self.do_dc(line[:]),
            self.do_namespace(line[:]),
        )

    async def _do_xdr(self, line):
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_stats = await self.getter.get_xdr(nodes=self.nodes)

        return util.callable(
            self.view.show_stats,
            "XDR Statistics",
            xdr_stats,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            show_total=show_total,
            **self.mods,
        )

    @CommandHelp(
        "Displays xdr datacenter statistics.",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_ns_configs = await self.getter.get_xdr_dcs(
            nodes=self.nodes, for_mods=self.mods["for"]
        )
        self.view.show_xdr_dc_stats(
            xdr_ns_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            show_total=show_total,
            **self.mods,
        )

    @CommandHelp(
        "Displays xdr namespace statistics.",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   [default: False, no repetition]",
        "    --flip       - Flip output table to show Nodes on Y axis and stats on X axis.",
        "    --by-dc      - Display each datacenter as a new table rather than each namespace. Makes it easier",
        "                   to identify issues belonging to a particular namespace",
        "                   [default: False, by namespace]",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        by_dc = util.check_arg_and_delete_from_mods(
            line=line,
            arg="--by-dc",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_ns_configs = await self.getter.get_xdr_namespaces(
            nodes=self.nodes, for_mods=self.mods["for"]
        )
        self.view.show_xdr_ns_stats(
            xdr_ns_configs,
            self.cluster,
            title_every_nth=title_every_nth,
            flip_output=flip_output,
            show_total=show_total,
            by_dc=by_dc,
            **self.mods,
        )


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
    "    --flip       - Flip output table to show nodes on X axis and roster on Y axis.",
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
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

    # TODO: This should be a utility
    async def _supported(self, v):
        builds = await self.cluster.info_build(nodes=self.nodes)

        for build in builds.values():
            if not isinstance(build, Exception) and version.LooseVersion(
                build
            ) < version.LooseVersion(v):
                return True

        return False

    async def _scans_supported(self):
        return await self._supported(constants.SERVER_QUERIES_ABORT_ALL_FIRST_VERSION)

    async def _sindex_supported(self):
        return await self._supported(constants.SERVER_SINDEX_BUILDER_REMOVED_VERSION)

    @CommandHelp(
        '"show jobs" displays jobs from all available modules.',
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_queries(line[:]),
            self.do_scans(line[:], default=True),
            self.do_sindex_builder(line[:], default=True),
        )

    @CommandHelp(
        'Displays query jobs. For easier viewing run "page on" first.',
        "Usage: queries [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    async def do_queries(self, line):
        jobs = await self.getter.get_query(nodes=self.nodes)
        return util.callable(
            self.view.show_jobs, "Query Jobs", self.cluster, jobs, **self.mods
        )

    # TODO: Should be removed eventually. "scan-show" was removed in server 6.0.
    # So should probably be removed when server 7.0 is supported.
    @CommandHelp(
        'Displays scan jobs. For easier viewing run "page on" first.',
        "Removed in server v. {} and later.".format(
            constants.SERVER_QUERIES_ABORT_ALL_FIRST_VERSION
        ),
        "Usage: scans [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    async def do_scans(self, line, default=False):
        # default indicates calling function is _do_default
        if not await self._scans_supported():
            if not default:
                self.logger.error(
                    "Scans were unified into queries in server v. {} and later. User 'show queries' instead.".format(
                        constants.SERVER_QUERIES_ABORT_ALL_FIRST_VERSION
                    )
                )
            return

        jobs = await self.getter.get_scans(nodes=self.nodes)
        return util.callable(
            self.view.show_jobs, "Scan Jobs", self.cluster, jobs, **self.mods
        )

    # TODO: Should be removed eventually. "sindex-builder" was removed in server 5.7.
    # So should probably be removed when server 7.0 is supported.
    @CommandHelp(
        "Displays sindex-builder jobs. Removed in server v. {} and later.".format(
            constants.SERVER_SINDEX_BUILDER_REMOVED_VERSION
        ),
        "Usage: sindex-builder [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    @CommandName("sindex-builder")
    async def do_sindex_builder(self, line, default=False):
        # default indicates calling function is _do_default
        if not await self._sindex_supported():
            if not default:
                self.logger.error(
                    "SIndex builder jobs were removed in server v. {} and later.".format(
                        constants.SERVER_SINDEX_BUILDER_REMOVED_VERSION
                    )
                )
            return

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
