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
from lib.base_controller import CommandHelp, CommandName, ModifierHelp
from lib.utils import common, util, version, constants
from lib.utils.constants import ModifierUsage, Modifiers
from lib.live_cluster.get_controller import (
    GetClusterMetadataController,
    GetConfigController,
    GetDistributionController,
    GetJobsController,
    GetPmapController,
    GetSIndexController,
    GetStatisticsController,
    GetUdfController,
    GetAclController,
    GetLatenciesController,
)

from .client import ASProtocolError
from .live_cluster_command_controller import LiveClusterCommandController

logger = logging.getLogger(__name__)

with_modifier_help = ModifierHelp(
    Modifiers.WITH,
    "Show results from specified nodes. Acceptable values are ip:port, node-id, or FQDN",
    default="all",
)

for_ns_modifier_help = ModifierHelp(
    Modifiers.FOR,
    "Filter by namespace using a substring match",
)

diff_row_modifier_help = ModifierHelp(
    Modifiers.DIFF,
    "Only display rows and values that differ between nodes.",
)
diff_col_modifier_help = ModifierHelp(
    Modifiers.DIFF,
    "Only display columns and values that differ between nodes.",
)

like_stat_modifier_help = ModifierHelp(
    Modifiers.LIKE, "Filter by statistic substring match"
)
like_config_modifier_help = ModifierHelp(
    Modifiers.LIKE, "Filter by configuration parameter substring match"
)
like_stat_usage = f"{Modifiers.LIKE} <stat-substring>"
like_config_usage = f"{Modifiers.LIKE} <config-substring>"


@CommandHelp(
    "A collection of commands used to display information about the Aerospike cluster"
)
class ShowController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "distribution": ShowDistributionController,
            "mapping": ShowMappingController,
            "pmap": ShowPmapController,
            "best-practices": ShowBestPracticesController,
            "jobs": ShowJobsController,
            "udfs": ShowUdfsController,
            "stop-writes": ShowStopWritesController,
            "racks": ShowRacksController,
            "roster": ShowRosterController,
            "roles": ShowRolesController,
            "users": ShowUsersController,
            "sindex": ShowSIndexController,
            "config": ShowConfigController,
            "latencies": ShowLatenciesController,
            "statistics": ShowStatisticsController,
        }

        self.modifiers = set()


@CommandHelp(
    "A collection of commands that display the distribution of object sizes",
    "and time to live for node and a namespace.",
    short_msg="A collection of commands that display the distribution of object sizes and time to live",
    usage=f"[{Modifiers.FOR} <ns-substring>] [{ModifierUsage.WITH}]",
    modifiers=(
        for_ns_modifier_help,
        with_modifier_help,
    ),
)
class ShowDistributionController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.WITH, Modifiers.FOR])
        self.getter = GetDistributionController(self.cluster)

    @CommandHelp("Shows the distributions of Time to Live and Object Size")
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_time_to_live(line[:]),
            self.do_object_size(line[:]),
        )

    @CommandHelp(
        "Shows the distribution of TTLs for namespaces",
        modifiers=(
            for_ns_modifier_help,
            with_modifier_help,
        ),
        short_msg="Displays the distribution of Object sizes for namespace",
        usage=f"[{Modifiers.FOR} <ns-substring>] [{ModifierUsage.WITH}]",
    )
    async def do_time_to_live(self, line):
        histogram = await self.getter.do_distribution("ttl", nodes=self.nodes)

        return util.callable(
            self.view.show_distribution,
            "TTL Distribution",
            histogram,
            "Seconds",
            "ttl",
            self.cluster,
            like=self.mods[Modifiers.FOR],
        )

    @CommandHelp(
        "Displays the distribution of Object sizes for namespaces",
        modifiers=(
            ModifierHelp(
                "-b",
                "Force to show byte-wise distribution of Object Sizes.",
                default="Record block wise distribution in percentage",
            ),
            ModifierHelp(
                "-k",
                "Maximum number of buckets to show if -b is set. It distributes objects in the same size k buckets and displays only buckets that have objects in them.",
                default="5",
            ),
            for_ns_modifier_help,
            with_modifier_help,
        ),
        short_msg="Displays the distribution of Object sizes for namespace",
        usage=f"[-b] [-k <num-buckets>] [{Modifiers.FOR} <ns-substring>] [{ModifierUsage.WITH}]",
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
                logger.error(e)
                return

            return util.callable(
                self.view.show_distribution,
                "Object Size Distribution",
                histogram,
                units,
                "objsz",
                self.cluster,
                like=self.mods[Modifiers.FOR],
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
            like=self.mods[Modifiers.FOR],
        )


@CommandHelp(
    "Displays latency information for the Aerospike cluster.",
    modifiers=(
        ModifierHelp(
            "-e",
            "Exponential increment of latency buckets, i.e. 2^0 2^(e) ... 2^(e * i)",
            default="3",
        ),
        ModifierHelp("-b", "Number of latency buckets to display.", default="3"),
        ModifierHelp(
            "-v", "Set to display verbose output of optionally configured histograms."
        ),
        for_ns_modifier_help,
        ModifierHelp(
            Modifiers.LIKE, "Filter by histogram name substring match", default="test"
        ),
        with_modifier_help,
    ),
    short_msg="Displays the server latency histograms",
    usage=f"[-e <increment>] [-b <num-buckets>] [-v] [{Modifiers.FOR} <ns-substring>] [like <histogram-substring>] [{ModifierUsage.WITH}",
)
class ShowLatenciesController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.WITH, Modifiers.LIKE, Modifiers.FOR])
        self.latency_getter = GetLatenciesController(self.cluster)

    async def _get_namespace_set(self):
        namespace_set = None

        if self.mods[Modifiers.FOR]:
            namespace_set = await self.latency_getter.get_namespace_set(self.nodes)
            namespace_set = set(
                util.filter_list(namespace_set, self.mods[Modifiers.FOR])
            )

        return namespace_set

    # It would be nice if the  'show latencies' help section could be completely removed for servers prior to 5.1
    # TODO: If it is a controller but it has only the default command then use its help
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

        namespace_set = await self._get_namespace_set()
        latencies, (latencies_nodes, latency_nodes) = await asyncio.gather(
            self.latency_getter.get_all(
                self.nodes, buckets, increment, verbose, namespace_set
            ),
            self.latency_getter.get_latencies_and_latency_nodes(self.nodes),
        )

        # No nodes support "show latencies"
        if len(latencies_nodes) == 0:
            logger.warning(
                "'show latencies' is not fully supported on aerospike versions <= 5.0"
            )
        # Some nodes support latencies and some do not
        elif len(latency_nodes) != 0:
            logger.warning(
                "'show latencies' is not fully supported on aerospike versions <= 5.0"
            )

        self.view.show_latency(
            latencies,
            self.cluster,
            show_ns_details=True if namespace_set else False,
            **self.mods,
        )


repeat_modifier_help = ModifierHelp(
    "-r",
    "Repeat output table title and row header after every <terminal width> columns.",
    default="False",
)
flip_config_modifier = ModifierHelp(
    "--flip",
    "Flip output table to show Nodes on Y axis and config on X axis.",
)


@CommandHelp(
    "A collection of commands that display configuration settings",
    usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}] [{ModifierUsage.WITH}]",
    modifiers=(
        repeat_modifier_help,
        flip_config_modifier,
        diff_row_modifier_help,
        like_config_modifier_help,
        with_modifier_help,
    ),
)
class ShowConfigController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(
            [Modifiers.WITH, Modifiers.LIKE, Modifiers.DIFF, Modifiers.FOR]
        )
        self.getter = GetConfigController(self.cluster)
        self.controller_map = {"xdr": ShowConfigXDRController}

    @CommandHelp(
        "Displays security, service, network, and namespace configuration",
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
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}] [{ModifierUsage.WITH}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            like_config_modifier_help,
            with_modifier_help,
        ),
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
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}] [{ModifierUsage.WITH}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            like_config_modifier_help,
            with_modifier_help,
        ),
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
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}] [{ModifierUsage.WITH}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            like_config_modifier_help,
            with_modifier_help,
        ),
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
        "Displays namespace configuration.",
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <ns-substring>] [{like_config_usage}] [{ModifierUsage.WITH}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            for_ns_modifier_help,
            like_config_modifier_help,
            with_modifier_help,
        ),
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
            flip=True, nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
        )

        return [
            util.callable(
                self.view.show_config,
                "%s Namespace Configuration" % (ns),
                ns_configs[ns],
                self.cluster,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods,
            )
            for ns in sorted(ns_configs.keys())
        ]

    # pre 5.0 but will still work
    @CommandHelp(
        "DEPRECATED: Replaced by 'show config xdr' Displays datacenter configuration.",
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}] [{ModifierUsage.WITH}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            like_config_modifier_help,
            with_modifier_help,
        ),
        hide=True,
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
        dc_configs = await self.getter.get_xdr_dcs(nodes=self.nodes)
        futures = [
            util.callable(
                self.view.show_xdr_dc_config,
                dc_configs,
                self.cluster,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods,
            )
        ]

        futures.append(
            util.callable(
                logger.warning,
                "'show config dc' is deprecated. Please use 'show config xdr dc' instead.",
            )
        )

        return futures


@CommandHelp(
    "A collection of commands that display xdr configuration",
    modifiers=(
        repeat_modifier_help,
        flip_config_modifier,
        diff_row_modifier_help,
        ModifierHelp(
            Modifiers.FOR,
            "Filter by datacenter or namespace substring match",
        ),
        like_config_modifier_help,
        with_modifier_help,
    ),
    usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring>|<ns-substring>] [{like_config_usage}] [{ModifierUsage.WITH}]",
)
class ShowConfigXDRController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(
            [Modifiers.WITH, Modifiers.LIKE, Modifiers.DIFF, Modifiers.FOR]
        )
        self.getter = GetConfigController(self.cluster)

    @CommandHelp(
        "Displays xdr, xdr datacenter, and xdr namespace configuration",
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self._do_xdr(line[:]),
            self.do_dcs(line[:]),
            self.do_namespaces(line[:]),
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
        "Displays xdr datacenter configuration",
        short_msg="Displays xdr datacenter configuration",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            ModifierHelp(Modifiers.FOR, "Filter by datacenter substring match"),
            like_config_modifier_help,
            with_modifier_help,
        ),
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring>] [{like_config_usage}] {ModifierUsage.WITH}",
    )
    async def do_dcs(self, line):
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
            nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
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
        "Displays xdr namespace configuration",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            ModifierHelp(
                Modifiers.FOR,
                "Filter by namespace substring match then by datacenter substring match",
            ),
            like_config_modifier_help,
            with_modifier_help,
        ),
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <ns-substring> [<dc-substring>]] [{like_config_usage}] {ModifierUsage.WITH}",
    )
    async def do_namespaces(self, line):
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
            nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
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
        "Displays configured xdr filters",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_col_modifier_help,
            ModifierHelp(
                Modifiers.FOR,
                "Filter by datacenter substring match then by namespace substring match",
            ),
            with_modifier_help,
        ),
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring> [<ns-substring>]] {ModifierUsage.WITH}",
    )
    async def do_filters(self, line):
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
            self.getter.get_xdr_filters(
                nodes="principal", for_mods=self.mods[Modifiers.FOR]
            )
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
            logger.warning(
                "Server version 5.3 or newer is required to run 'show config xdr filter'"
            )


@CommandHelp(
    "A collection of commands to display mapping from IP to Node_id and Node_id to IPs",
    modifiers=(ModifierHelp(Modifiers.LIKE, "Filter by IP or Node_id substring"),),
    usage="[like <ip or node_id substring>]",
)
class ShowMappingController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.LIKE])

    @CommandHelp("Displays mapping IPs to Node_id and Node_id to IPs")
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_ip(line),
            self.do_node(line),
        )

    @CommandHelp(
        "Displays IP to Node_id mapping",
        modifiers=(ModifierHelp(Modifiers.LIKE, "Filter by IP substring"),),
        usage="[like <ip substring>]",
    )
    async def do_ip(self, line):
        ip_to_node_map = await self.cluster.get_IP_to_node_map()
        return util.callable(
            self.view.show_mapping, "IP", "NODE-ID", ip_to_node_map, **self.mods
        )

    @CommandHelp(
        "Displays Node_id to IPs mapping",
        modifiers=(ModifierHelp(Modifiers.LIKE, "Filter by Node_id substring"),),
        usage="[like <node_id substring>]",
    )
    async def do_node(self, line):
        node_to_ip_map = await self.cluster.get_node_to_IP_map()
        return util.callable(
            self.view.show_mapping, "NODE-ID", "IPs", node_to_ip_map, **self.mods
        )


total_modifier_help = ModifierHelp(
    "-t",
    "Set to show total column at the end. It contains node wise sum for statistics.",
)

flip_stats_modifier_help = flip_config_modifier
flip_stats_modifier_help.msg = (
    "Flip output table to show Nodes on Y axis and config on X axis."
)


@CommandHelp(
    "A collection of commands that displays runtime statistics",
    usage=f"[-rt] [--flip] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
    modifiers=(
        total_modifier_help,
        repeat_modifier_help,
        flip_stats_modifier_help,
        like_stat_modifier_help,
        with_modifier_help,
    ),
)
class ShowStatisticsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.WITH, Modifiers.LIKE, Modifiers.FOR])
        self.stat_getter = GetStatisticsController(self.cluster)
        self.meta_getter = GetClusterMetadataController(self.cluster)
        self.controller_map = {"xdr": ShowStatisticsXDRController}

    @CommandHelp(
        "Displays bin, set, service, and namespace statistics",
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_sets(line[:]),
            self.do_service(line[:]),
            self.do_namespace(line[:]),
        )

    @CommandHelp(
        "Displays service statistics",
        usage=f"[-rt] [--flip] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            like_stat_modifier_help,
            with_modifier_help,
        ),
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

        service_stats = await self.stat_getter.get_service(nodes=self.nodes)

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
        usage=f"[-rt] [--flip] [{Modifiers.FOR} <ns-substring>] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            for_ns_modifier_help,
            like_stat_modifier_help,
            with_modifier_help,
        ),
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

        ns_stats = await self.stat_getter.get_namespace(
            flip=True, nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
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
        usage=f"[-rt] [--flip] [{Modifiers.FOR} <ns-substring> [<sindex-substring>]] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            ModifierHelp(
                Modifiers.FOR,
                "Filter first by namespace substring and then by sindex substring",
            ),
            like_stat_modifier_help,
            with_modifier_help,
        ),
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

        sindex_stats = await self.stat_getter.get_sindex(
            flip=True, nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
        )

        return [
            util.callable(
                self.view.show_stats,
                "%s SIndex Statistics" % (ns_set_sindex),
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
        usage=f"[-rt] [--flip] [{Modifiers.FOR} <ns-substring> [<set-substring>]] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            ModifierHelp(
                Modifiers.FOR,
                "Filter first by namespace substring match and then by set substring match",
            ),
            like_stat_modifier_help,
            with_modifier_help,
        ),
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

        set_stats = await self.stat_getter.get_sets(
            flip=True, nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
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
        usage=f"[-rt] [--flip] [{Modifiers.FOR} <ns-substring>] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            for_ns_modifier_help,
            like_stat_modifier_help,
            with_modifier_help,
        ),
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

        new_bin_stats, builds = await asyncio.gather(
            self.stat_getter.get_bins(
                flip=True, nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
            ),
            self.meta_getter.get_builds(nodes=self.nodes),
        )

        if any(
            [
                version.LooseVersion(build)
                >= version.LooseVersion(constants.SERVER_INFO_BINS_REMOVAL_VERSION)
                for build in builds.values()
            ]
        ):
            logger.error(
                f"Server version {constants.SERVER_INFO_BINS_REMOVAL_VERSION} removed namespace bin-name limits and statistics."
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
        "DEPRECATED: Replaced by 'show statistics xdr dc.' Displays datacenter statistics.",
        usage=f"[-rt] [--flip] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            like_stat_modifier_help,
            with_modifier_help,
        ),
        hide=True,
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

        dc_stats = await self.stat_getter.get_xdr_dcs(nodes=self.nodes)

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
                logger.warning,
                "'show statistics dc' is deprecated. Please use 'show statistics xdr dc' instead.",
            )
        )

        return futures


@CommandHelp(
    "A collection of commands that display xdr statistics for different contexts",
    usage=f"[-rt] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc>|<ns>]] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
    modifiers=(
        total_modifier_help,
        repeat_modifier_help,
        flip_stats_modifier_help,
        diff_row_modifier_help,
        like_stat_modifier_help,
        ModifierHelp(
            Modifiers.FOR, "Filter by datacenter or namespace substring match"
        ),
        with_modifier_help,
    ),
)
class ShowStatisticsXDRController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(
            [Modifiers.WITH, Modifiers.LIKE, Modifiers.DIFF, Modifiers.FOR]
        )
        self.getter = GetStatisticsController(self.cluster)

    @CommandHelp(
        "Displays xdr, xdr datacenter, and xdr namespace statistics",
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
        "Displays xdr datacenter statistics",
        usage=f"[-rt] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring>]] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            diff_row_modifier_help,
            like_stat_modifier_help,
            ModifierHelp(Modifiers.FOR, "Filter by datacenter substring match"),
            with_modifier_help,
        ),
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
            nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
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
        "Displays xdr namespace statistics",
        usage=f"[-rt] [--flip] [--by-dc] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring> <ns-substring>]] [{ModifierUsage.LIKE}] [{ModifierUsage.WITH}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            ModifierHelp(
                "--by-dc",
                "Display each datacenter as a new table rather than each namespace. This makes it easier to identify issues belonging to a particular namespace.",
                default="False",
            ),
            diff_row_modifier_help,
            like_stat_modifier_help,
            ModifierHelp(
                Modifiers.FOR,
                "Filter first by datacenter and then by namespace substring match",
            ),
            with_modifier_help,
        ),
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
            nodes=self.nodes, for_mods=self.mods[Modifiers.FOR]
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
    "A collection of commands that display user configuration and statistics",
    usage=f"[<username>]",
    modifiers=(ModifierHelp("user", "Display output for a single user."),),
)
class ShowUsersController(LiveClusterCommandController):
    def __init__(self):
        self.getter = GetAclController(self.cluster)
        self.controller_map = {"statistics": ShowUsersStatsController}

    @CommandHelp(
        "Displays users and their assigned roles and quotas",
    )
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
            logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        return self.view.show_users(resp, **self.mods)


@CommandHelp(
    "Displays users, open connections, and quota usage for the Aerospike cluster.",
    modifiers=(ModifierHelp("user", "Display output for a single user."),),
    short_msg="Displays users, open connections, and quota usage",
    usage=f"[<username>]",
)
class ShowUsersStatsController(LiveClusterCommandController):
    def __init__(self):
        self.getter = GetAclController(self.cluster)

    async def _do_default(self, line):
        user = None

        if line:
            user = line.pop(0)

        users_data = None

        if user is None:
            users_data = await self.getter.get_users(nodes=self.nodes)
        else:
            users_data = await self.getter.get_user(user, nodes=self.nodes)

        if all([isinstance(data, Exception) for data in users_data.values()]):
            raise list(users_data.values())[0]

        return self.view.show_users_stats(self.cluster, users_data, **self.mods)


@CommandHelp(
    "Displays roles and their assigned privileges, allowlist, and quotas for the Aerospike cluster.",
    modifiers=(ModifierHelp("role", "Display output for a single role"),),
    short_msg="Displays roles and their assigned privileges, allowlist, and quotas",
    usage="[role]",
)
class ShowRolesController(LiveClusterCommandController):
    def __init__(self):
        self.getter = GetAclController(self.cluster)

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
            logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        return self.view.show_roles(resp, **self.mods)


@CommandHelp(
    "Displays UDF modules along with metadata.",
    modifiers=(
        ModifierHelp(Modifiers.LIKE, "Filter UDFs by name using a substring match"),
    ),
    usage=f"[{ModifierUsage.LIKE}]",
)
class ShowUdfsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.LIKE])
        self.getter = GetUdfController(self.cluster)

    async def _do_default(self, line):
        udfs_data = await self.getter.get_udfs(nodes="principal")
        resp = list(udfs_data.values())[0]

        return self.view.show_udfs(resp, **self.mods)


@CommandHelp(
    "Displays secondary indexes and static metadata.",
    modifiers=(
        ModifierHelp(Modifiers.LIKE, "Filter indexes by name using a substring match"),
    ),
    usage=f"[{ModifierUsage.LIKE}]",
)
class ShowSIndexController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.LIKE])
        self.getter = GetSIndexController(self.cluster)

    async def _do_default(self, line):
        sindexes_data = await self.getter.get_sindexs(nodes="principal")
        resp = list(sindexes_data.values())[0]

        self.view.show_sindex(resp, **self.mods)


@CommandHelp(
    'Displays roster information per node. For easier viewing run "page on" first.',
    modifiers=(
        ModifierHelp(
            "--flip", "Flip output table to show nodes on X axis and roster on Y axis."
        ),
        diff_col_modifier_help,
        for_ns_modifier_help,
        with_modifier_help,
    ),
    usage=f"[--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <ns-substring>] [{ModifierUsage.WITH}]",
    short_msg="Displays roster information per node",
)
class ShowRosterController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.FOR, Modifiers.WITH, Modifiers.DIFF])
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


@CommandHelp(
    'Displays any of Aerospike\'s violated "best-practices".',
    modifiers=(with_modifier_help,),
    usage=f"[{ModifierUsage.WITH}]",
)
class ShowBestPracticesController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.WITH])

    async def _do_default(self, line):
        versions = asyncio.create_task(self.cluster.info_build())
        best_practices = asyncio.create_task(
            self.cluster.info_best_practices(nodes=self.nodes)
        )
        versions = util.filter_exceptions(await versions)

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
            logger.warning(
                "'show best-practices' is not supported on aerospike versions < {}",
                constants.SERVER_SHOW_BEST_PRACTICES_FIRST_VERSION,
            )

        best_practices = await best_practices

        return self.view.show_best_practices(self.cluster, best_practices, **self.mods)


@CommandHelp(
    "A collection of commands that display jobs and associated metadata",
)
class ShowJobsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.WITH, "trid"])
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
        "Displays jobs from all available modules",
    )
    async def _do_default(self, line):
        return await asyncio.gather(
            self.do_queries(line[:]),
            self.do_scans(line[:], default=True),
            self.do_sindex_builder(line[:], default=True),
        )

    @CommandHelp(
        'Displays query jobs. For easier viewing run "page on" first.',
        modifiers=(
            ModifierHelp("trid", "List of transaction IDs to filter for."),
            with_modifier_help,
        ),
        usage=f"[trid <trid1> [<trid2>]] [{ModifierUsage.WITH}]",
        short_msg="Displays query jobs",
    )
    async def do_queries(self, line):
        jobs = await self.getter.get_query(nodes=self.nodes)
        return util.callable(
            self.view.show_jobs, "Query Jobs", self.cluster, jobs, **self.mods
        )

    # TODO: Should be removed eventually. "scan-show" was removed in server 6.0.
    # So should probably be removed when server 7.0 is supported.
    @CommandHelp(
        f'Displays scan jobs. For easier viewing run "page on" first. Removed in server v. {constants.SERVER_QUERIES_ABORT_ALL_FIRST_VERSION} and later.',
        modifiers=(
            ModifierHelp("trid", "List of transaction IDs to filter for."),
            with_modifier_help,
        ),
        usage=f"[trid <trid1> [<trid2>]] [{ModifierUsage.WITH}]",
        short_msg=f"Displays scan jobs. Removed in server v. {constants.SERVER_QUERIES_ABORT_ALL_FIRST_VERSION} and later",
    )
    async def do_scans(self, line, default=False):
        # default indicates calling function is _do_default
        if not await self._scans_supported():
            if not default:
                logger.error(
                    "Scans were unified into queries in server v. {} and later. Use 'show jobs queries' instead.".format(
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
        modifiers=(
            ModifierHelp("trid", "List of transaction IDs to filter for."),
            with_modifier_help,
        ),
        usage=f"[trid <trid1> [<trid2>]] [{ModifierUsage.WITH}]",
        short_msg="Displays sindex-builder jobs. Removed in server v. {} and later".format(
            constants.SERVER_SINDEX_BUILDER_REMOVED_VERSION
        ),
    )
    @CommandName("sindex-builder")
    async def do_sindex_builder(self, line, default=False):
        # default indicates calling function is _do_default
        if not await self._sindex_supported():
            if not default:
                logger.error(
                    "SIndex builder jobs were removed in server v. {} and later.".format(
                        constants.SERVER_SINDEX_BUILDER_REMOVED_VERSION
                    )
                )
            return

        jobs = await self.getter.get_sindex_builder(nodes=self.nodes)
        return util.callable(
            self.view.show_jobs, "SIndex Builder Jobs", self.cluster, jobs, **self.mods
        )


@CommandHelp(
    "Displays rack information for a rack-aware cluster",
    modifiers=(with_modifier_help,),
    usage=f"[{ModifierUsage.WITH}]",
)
class ShowRacksController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.WITH])
        self.getter = GetConfigController(self.cluster)

    async def _do_default(self, line):
        racks_data = await self.getter.get_racks(nodes="principal", flip=False)
        return self.view.show_racks(racks_data, **self.mods)


@CommandHelp(
    "Displays all metrics that could trigger stop-writes",
    modifiers=(
        for_ns_modifier_help,
        with_modifier_help,
    ),
    usage=f"[{Modifiers.FOR} <ns-substring>] [{ModifierUsage.WITH}]",
)
class ShowStopWritesController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.WITH, Modifiers.FOR])
        self.config_getter = GetConfigController(self.cluster)
        self.stat_getter = GetStatisticsController(self.cluster)

    async def _do_default(self, line):
        if len(self.mods[Modifiers.FOR]) < 2:
            (
                service_stats,
                ns_stats,
                ns_configs,
                set_stats,
                set_configs,
            ) = await asyncio.gather(
                self.stat_getter.get_service(),
                self.stat_getter.get_namespace(for_mods=self.mods[Modifiers.FOR]),
                self.config_getter.get_namespace(for_mods=self.mods[Modifiers.FOR]),
                self.stat_getter.get_sets(for_mods=self.mods[Modifiers.FOR]),
                self.config_getter.get_sets(for_mods=self.mods[Modifiers.FOR]),
            )
        else:
            ns_stats = {}
            ns_configs = {}
            (
                service_stats,
                set_stats,
                set_configs,
            ) = await asyncio.gather(
                self.stat_getter.get_service(),
                self.stat_getter.get_sets(for_mods=self.mods[Modifiers.FOR]),
                self.config_getter.get_sets(for_mods=self.mods[Modifiers.FOR]),
            )

        return self.view.show_stop_writes(
            common.create_stop_writes_summary(
                service_stats, ns_stats, ns_configs, set_stats, set_configs
            ),
            self.cluster,
            **self.mods,
        )
