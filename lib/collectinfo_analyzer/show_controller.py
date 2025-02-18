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

import logging
from lib.collectinfo_analyzer.get_controller import (
    GetAclController,
    GetClusterMetadataController,
    GetConfigController,
    GetStatisticsController,
)
from lib.utils import common, constants, util, version
from lib.base_controller import CommandHelp, CommandName, ModifierHelp
from .collectinfo_command_controller import CollectinfoCommandController

logger = logging.getLogger(__name__)

Modifiers = constants.Modifiers
ModifierUsage = constants.ModifierUsage

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
class ShowController(CollectinfoCommandController):
    def __init__(self):
        self.controller_map = {
            "distribution": ShowDistributionController,
            "pmap": ShowPmapController,
            "best-practices": ShowBestPracticesController,
            "jobs": ShowJobsController,
            "racks": ShowRacksController,
            "roster": ShowRosterController,
            "roles": ShowRolesController,
            "users": ShowUsersController,
            "udfs": ShowUdfsController,
            "stop-writes": ShowStopWritesController,
            "sindex": ShowSIndexController,
            "config": ShowConfigController,
            "latencies": ShowLatenciesController,
            "statistics": ShowStatisticsController,
        }
        self.modifiers = set()


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
    usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}]",
    modifiers=(
        repeat_modifier_help,
        flip_config_modifier,
        diff_row_modifier_help,
        like_config_modifier_help,
    ),
)
class ShowConfigController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set([Modifiers.LIKE, Modifiers.DIFF, Modifiers.FOR])
        self.controller_map = {"xdr": ShowConfigXDRController}
        self.getter = GetConfigController(self.log_handler)

    @CommandHelp(
        "Displays security, service, network, and namespace configuration",
    )
    def _do_default(self, line):
        self.do_security(line[:])
        self.do_service(line[:])
        self.do_network(line[:])
        self.do_namespace(line[:])

    @CommandHelp(
        "Displays security configuration",
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            like_config_modifier_help,
        ),
    )
    def do_security(self, line):
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

        security_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_SECURITY
        )

        for timestamp in sorted(security_configs.keys()):
            self.view.show_config(
                "Security Configuration",
                security_configs[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp(
        "Displays service configuration",
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            like_config_modifier_help,
        ),
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        service_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_SERVICE
        )

        for timestamp in sorted(service_configs.keys()):
            self.view.show_config(
                "Service Configuration",
                service_configs[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp(
        "Displays network configuration",
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            like_config_modifier_help,
        ),
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        network_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_NETWORK
        )

        for timestamp in sorted(network_configs.keys()):
            self.view.show_config(
                "Network Configuration",
                network_configs[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp(
        "Displays namespace configuration.",
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <ns-substring>] [{like_config_usage}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            for_ns_modifier_help,
            like_config_modifier_help,
        ),
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ns_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_NAMESPACE, flip=True
        )

        for timestamp in sorted(ns_configs.keys()):
            for ns, configs in ns_configs[timestamp].items():
                self.view.show_config(
                    "%s Namespace Configuration" % (ns),
                    configs,
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods,
                )

    # pre 5.0
    @CommandHelp(
        "DEPRECATED: Replaced by 'show config xdr' Displays datacenter configuration.",
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{like_config_usage}]",
        modifiers=(
            repeat_modifier_help,
            flip_config_modifier,
            diff_row_modifier_help,
            like_config_modifier_help,
        ),
        hide=True,
    )
    def do_dc(self, line):
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

        xdr_dc_configs = self.getter.get_xdr_dcs(for_mods=self.mods["for"])

        for timestamp in xdr_dc_configs.keys():
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            self.view.show_xdr_dc_config(
                xdr_dc_configs[timestamp],
                cinfo_log,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                **self.mods,
            )

        logger.warning(
            "The 'show config dc' command is deprecated. Please use 'show config xdr dc' instead."
        )


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
    ),
    usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring>|<ns-substring>] [{like_config_usage}]",
)
class ShowConfigXDRController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "diff", "for"])
        self.getter = GetConfigController(self.log_handler)

    def _check_ns_stats_and_warn(self, xdr_ns_stats):
        for ts_stats in xdr_ns_stats.values():
            for node_stats in ts_stats.values():
                if not node_stats:
                    logger.warning(
                        "XDR namespace subcontexts were introduced in server 5.0. Try 'show config namespace'"
                    )
                    return

    @CommandHelp(
        "Displays xdr, xdr datacenter, and xdr namespace configuration",
    )
    def _do_default(self, line):
        self._do_xdr(line[:])
        self.do_dc(line[:])
        self.do_namespace(line[:])

    def _do_xdr(self, line):
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

        xdr_configs = self.getter.get_xdr()

        for timestamp in xdr_configs.keys():
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            self.view.show_config(
                "XDR Configuration",
                xdr_configs[timestamp],
                cinfo_log,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
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
        ),
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring>] [{like_config_usage}]",
    )
    def do_dc(self, line):
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

        xdr_dc_configs = self.getter.get_xdr_dcs(for_mods=self.mods["for"])

        for timestamp in xdr_dc_configs.keys():
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            self.view.show_xdr_dc_config(
                xdr_dc_configs[timestamp],
                cinfo_log,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
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
        ),
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <ns-substring> [<dc-substring>]] [{like_config_usage}]",
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_ns_configs = self.getter.get_xdr_namespaces(for_mods=self.mods["for"])

        for timestamp in xdr_ns_configs.keys():
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            self.view.show_xdr_ns_config(
                xdr_ns_configs[timestamp],
                cinfo_log,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
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
        ),
        usage=f"[-r] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring> [<ns-substring>]]",
    )
    def do_filter(self, line):
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

        xdr_filters = self.getter.get_xdr_filters(for_mods=self.mods["for"])

        for timestamp in xdr_filters.keys():
            self.view.show_xdr_filters(
                xdr_filters[timestamp],
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
                **self.mods,
            )


@CommandHelp(
    "A collection of commands that display the distribution of object sizes",
    "and time to live for node and a namespace.",
    short_msg="A collection of commands that display the distribution of object sizes and time to live",
    usage=f"[{Modifiers.FOR} <ns-substring>]",
    modifiers=(for_ns_modifier_help,),
)
class ShowDistributionController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["for"])

    @CommandHelp("Shows the distributions of Time to Live and Object Size")
    def _do_default(self, line):
        self.do_time_to_live(line)
        self.do_object_size(line)

    def _do_distribution(self, histogram_name, title, unit):
        histogram = self.log_handler.info_histogram(histogram_name)
        for timestamp in sorted(histogram.keys()):
            if not histogram[timestamp]:
                continue
            hist_output = common.create_histogram_output(
                histogram_name, histogram[timestamp]
            )
            self.view.show_distribution(
                title,
                hist_output,
                unit,
                histogram_name,
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                like=self.mods["for"],
            )

    @CommandHelp(
        "Shows the distribution of TTLs for namespaces",
        modifiers=(for_ns_modifier_help,),
        short_msg="Displays the distribution of Object sizes for namespace",
        usage=f"[{Modifiers.FOR} <ns-substring>]",
    )
    def do_time_to_live(self, line):
        return self._do_distribution("ttl", "TTL Distribution", "Seconds")

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
        ),
        short_msg="Displays the distribution of Object sizes for namespace",
        usage=f"[-b] [-k <num-buckets>] [{Modifiers.FOR} <ns-substring>]",
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

        histogram_name = "objsz"
        if not byte_distribution:
            return self._do_distribution(
                histogram_name, "Object Size Distribution", "Record Blocks"
            )

        histogram = self.log_handler.info_histogram(
            histogram_name, byte_distribution=True
        )
        builds = self.log_handler.info_meta_data(stanza="asd_build")

        for timestamp in histogram:
            self.view.show_object_distribution(
                "Object Size Distribution",
                common.create_histogram_output(
                    histogram_name,
                    histogram[timestamp],
                    byte_distribution=True,
                    bucket_count=bucket_count,
                    builds=builds,
                ),
                "Bytes",
                "objsz",
                bucket_count,
                True,
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                loganalyser_mode=True,
                like=self.mods["for"],
            )


@CommandHelp(
    "Displays latency information for the Aerospike cluster.",
    modifiers=(
        for_ns_modifier_help,
        ModifierHelp(Modifiers.LIKE, "Filter by histogram name substring match"),
    ),
    short_msg="Displays the server latency histograms",
    usage=f"[{Modifiers.FOR} <ns-substring>] [like <histogram-substring>]",
)
class ShowLatenciesController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "for"])

    @CommandHelp(
        "Displays latency information for Aerospike cluster.",
    )
    def _do_default(self, line):
        namespaces = {}
        if self.mods["for"]:
            namespaces = self.log_handler.info_namespaces()

        latency = self.log_handler.info_latency()

        for timestamp in sorted(latency.keys()):
            namespace_set = set()
            _latency = {}
            if timestamp in namespaces:
                for _namespace in namespaces[timestamp].values():
                    if isinstance(_namespace, Exception):
                        continue
                    namespace_set.update(_namespace)
                namespace_set = set(util.filter_list(namespace_set, self.mods["for"]))

                for node_id, node_data in latency[timestamp].items():
                    if not node_data or isinstance(node_data, Exception):
                        continue
                    if node_id not in _latency:
                        _latency[node_id] = {}
                    for hist_name, hist_data in node_data.items():
                        if not hist_data or isinstance(hist_data, Exception):
                            continue

                        if hist_name not in _latency[node_id]:
                            _latency[node_id][hist_name] = {}

                        for _type, _type_data in hist_data.items():
                            _latency[node_id][hist_name][_type] = {}
                            if _type != "namespace":
                                _latency[node_id][hist_name][_type] = _type_data
                                continue

                            for _ns, _ns_data in _type_data.items():
                                if _ns in namespace_set:
                                    _latency[node_id][hist_name][_type][_ns] = _ns_data

            else:
                _latency = latency[timestamp]

            self.view.show_latency(
                _latency,
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                show_ns_details=True if namespace_set else False,
                timestamp=timestamp,
                **self.mods,
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
    usage=f"[-rt] [--flip] [{ModifierUsage.LIKE}]",
    modifiers=(
        total_modifier_help,
        repeat_modifier_help,
        flip_stats_modifier_help,
        like_stat_modifier_help,
    ),
)
class ShowStatisticsController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "for"])
        self.controller_map = {"xdr": ShowStatisticsXDRController}
        self.getter = GetStatisticsController(
            self.log_handler
        )  # TODO: Use this getter for more than just xdr
        self.meta_getter = GetClusterMetadataController(self.log_handler)

    @CommandHelp(
        "Displays bin, set, service, and namespace statistics",
    )
    def _do_default(self, line):
        self.do_sets(line[:])
        self.do_service(line[:])
        self.do_namespace(line[:])

    @CommandHelp(
        "Displays service statistics",
        usage=f"[-rt] [--flip] [{ModifierUsage.LIKE}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            like_stat_modifier_help,
        ),
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        service_stats = self.log_handler.info_statistics(stanza=constants.STAT_SERVICE)

        for timestamp in sorted(service_stats.keys()):
            self.view.show_config(
                "Service Statistics",
                service_stats[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp(
        "Displays namespace statistics",
        usage=f"[-rt] [--flip] [{Modifiers.FOR} <ns-substring>] [{ModifierUsage.LIKE}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            for_ns_modifier_help,
            like_stat_modifier_help,
        ),
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ns_stats = self.log_handler.info_statistics(
            stanza=constants.STAT_NAMESPACE, flip=True
        )

        for timestamp in sorted(ns_stats.keys()):
            namespace_list = util.filter_list(
                ns_stats[timestamp].keys(), self.mods["for"]
            )
            for ns in sorted(namespace_list):
                stats = ns_stats[timestamp][ns]
                self.view.show_stats(
                    "%s Namespace Statistics" % (ns),
                    stats,
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods,
                )

    @CommandHelp(
        "Displays set statistics",
        usage=f"[-rt] [--flip] [{Modifiers.FOR} <ns-substring> [<set-substring>]] [{ModifierUsage.LIKE}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            ModifierHelp(
                Modifiers.FOR,
                "Filter first by namespace substring match and then by set substring match",
            ),
            like_stat_modifier_help,
        ),
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        set_stats = self.getter.get_sets(for_mods=self.mods["for"], flip=True)

        for timestamp in sorted(set_stats.keys()):
            for key, stats in set_stats[timestamp].items():
                ns, set_ = key
                self.view.show_stats(
                    "%s %s Set Statistics" % (ns, set_),
                    stats,
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods,
                )

    @CommandHelp(
        "Displays bin statistics",
        usage=f"[-rt] [--flip] [{Modifiers.FOR} <ns-substring>] [{ModifierUsage.LIKE}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            for_ns_modifier_help,
            like_stat_modifier_help,
        ),
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        builds = self.meta_getter.get_builds()

        for timestamp in sorted(builds.keys()):
            nodes_builds = builds[timestamp]
            if any(
                [
                    version.LooseVersion(build)
                    >= version.LooseVersion(constants.SERVER_INFO_BINS_REMOVAL_VERSION)
                    for build in nodes_builds.values()
                ]
            ):
                logger.error(
                    f"Server version {constants.SERVER_INFO_BINS_REMOVAL_VERSION} removed namespace bin-name limits and statistics."
                )

        new_bin_stats = self.log_handler.info_statistics(
            stanza=constants.STAT_BINS, flip=True
        )

        for timestamp in sorted(new_bin_stats.keys()):
            if not new_bin_stats[timestamp] or isinstance(
                new_bin_stats[timestamp], Exception
            ):
                continue

            namespace_set = set(
                util.filter_list(new_bin_stats[timestamp].keys(), self.mods["for"])
            )

            for ns, stats in new_bin_stats[timestamp].items():
                if ns not in namespace_set:
                    continue

                self.view.show_stats(
                    "%s Bin Statistics" % (ns),
                    stats,
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods,
                )

    # pre 5.0
    @CommandHelp(
        "DEPRECATED: Replaced by 'show statistics xdr dc.' Displays datacenter statistics.",
        usage=f"[-rt] [--flip] [{ModifierUsage.LIKE}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            like_stat_modifier_help,
        ),
        hide=True,
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_dc_stats = self.getter.get_xdr_dcs()

        for timestamp in xdr_dc_stats.keys():
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            self.view.show_xdr_dc_stats(
                xdr_dc_stats[timestamp],
                cinfo_log,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                show_total=show_total,
                timestamp=timestamp,
                **self.mods,
            )

        logger.warning(
            "'show statistics dc' is deprecated. Please use 'show statistics xdr dc' instead."
        )

    @CommandHelp(
        "Displays sindex statistics",
        usage=f"[-rt] [--flip] [{Modifiers.FOR} <ns-substring> [<sindex-substring>]] [{ModifierUsage.LIKE}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            ModifierHelp(
                Modifiers.FOR,
                "Filter first by namespace substring and then by sindex substring",
            ),
            like_stat_modifier_help,
        ),
    )
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        sindex_stats = self.log_handler.info_statistics(
            stanza=constants.STAT_SINDEX, flip=True
        )

        for timestamp in sorted(sindex_stats.keys()):
            if not sindex_stats[timestamp] or isinstance(
                sindex_stats[timestamp], Exception
            ):
                continue

            namespace_set = {
                ns_set_sindex.split()[0]
                for ns_set_sindex in sindex_stats[timestamp].keys()
            }
            try:
                namespace_set = set(
                    util.filter_list(namespace_set, self.mods["for"][:1])
                )
            except Exception:
                pass

            sindex_set = {
                ns_set_sindex.split()[2]
                for ns_set_sindex in sindex_stats[timestamp].keys()
            }
            try:
                sindex_set = set(util.filter_list(sindex_set, self.mods["for"][1:2]))
            except Exception:
                pass

            for sindex, stats in sindex_stats[timestamp].items():
                ns, set_, si = sindex.split()
                if ns not in namespace_set or si not in sindex_set:
                    continue

                self.view.show_stats(
                    "%s SIndex Statistics" % (sindex),
                    stats,
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods,
                )


@CommandHelp(
    "A collection of commands that display xdr statistics for different contexts",
    usage=f"[-rt] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc>|<ns>]] [{ModifierUsage.LIKE}]",
    modifiers=(
        total_modifier_help,
        repeat_modifier_help,
        flip_stats_modifier_help,
        diff_row_modifier_help,
        like_stat_modifier_help,
        ModifierHelp(
            Modifiers.FOR, "Filter by datacenter or namespace substring match"
        ),
    ),
)
class ShowStatisticsXDRController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "for"])
        self.getter = GetStatisticsController(self.log_handler)

    def _check_ns_stats_and_warn(self, xdr_ns_stats):
        for ts_stats in xdr_ns_stats.values():
            for node_stats in ts_stats.values():
                if not node_stats:
                    logger.warning(
                        "XDR namespace statistics were introduced in server 5.0 and not added to the collectinfo file until asadm 2.13.0"
                    )
                    return

    @CommandHelp(
        "Displays xdr, xdr datacenter, and xdr namespace statistics",
    )
    def _do_default(self, line):
        self._do_xdr(line[:])
        self.do_dc(line[:])
        self.do_namespace(line[:])

    def _do_xdr(self, line):
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

        xdr_stats = self.getter.get_xdr()

        for timestamp in xdr_stats.keys():
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            # There are no XDR level stats for XDR 5. This will not print anything
            # if it is empty
            self.view.show_stats(
                "XDR Statistics",
                xdr_stats[timestamp],
                cinfo_log,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                show_total=show_total,
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp(
        "Displays xdr datacenter statistics",
        usage=f"[-rt] [--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring>]] [{ModifierUsage.LIKE}]",
        modifiers=(
            total_modifier_help,
            repeat_modifier_help,
            flip_stats_modifier_help,
            diff_row_modifier_help,
            like_stat_modifier_help,
            ModifierHelp(Modifiers.FOR, "Filter by datacenter substring match"),
        ),
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
        ) or util.check_arg_and_delete_from_mods(
            line=line,
            arg="--flip",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        xdr_dc_stats = self.getter.get_xdr_dcs(for_mods=self.mods["for"])

        for timestamp in xdr_dc_stats.keys():
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            self.view.show_xdr_dc_stats(
                xdr_dc_stats[timestamp],
                cinfo_log,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                show_total=show_total,
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp(
        "Displays xdr namespace statistics",
        usage=f"[-rt] [--flip] [--by-dc] [{Modifiers.DIFF}] [{Modifiers.FOR} <dc-substring> [<ns-substring>]] [{ModifierUsage.LIKE}]",
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
        ),
    )
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

        xdr_ns_stats = self.getter.get_xdr_namespaces(for_mods=self.mods["for"])

        for timestamp in xdr_ns_stats.keys():
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            self.view.show_xdr_ns_stats(
                xdr_ns_stats[timestamp],
                cinfo_log,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                show_total=show_total,
                by_dc=by_dc,
                timestamp=timestamp,
                **self.mods,
            )

        self._check_ns_stats_and_warn(xdr_ns_stats)


@CommandHelp("Displays partition map analysis of Aerospike cluster.")
class ShowPmapController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        pmap_data = self.log_handler.info_pmap()

        for timestamp in sorted(pmap_data.keys()):
            if not pmap_data[timestamp]:
                continue

            self.view.show_pmap(
                pmap_data[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
            )


@CommandHelp(
    "A collection of commands that display user configuration and statistics",
    usage=f"[<username>]",
    modifiers=(ModifierHelp("user", "Display output for a single user."),),
)
class ShowUsersController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like"])
        self.controller_map = {"statistics": ShowUsersStatsController}
        self.getter = GetAclController(self.log_handler)

    @CommandHelp(
        "Displays users and their assigned roles and quotas",
    )
    def _do_default(self, line):
        user = None

        if line:
            user = line.pop(0)

        users_data = None

        if user is None:
            users_data = self.getter.get_users(nodes="principal")
        else:
            users_data = self.getter.get_user(user, nodes="principal")

        for timestamp in sorted(users_data.keys()):
            if not users_data[timestamp]:
                continue

            data = list(users_data[timestamp].values())[0]
            self.view.show_users(data, timestamp=timestamp, **self.mods)


@CommandHelp(
    "Displays users, open connections, and quota usage for the Aerospike cluster.",
    modifiers=(ModifierHelp("user", "Display output for a single user."),),
    short_msg="Displays users, open connections, and quota usage",
    usage=f"[<username>]",
)
class ShowUsersStatsController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like"])
        self.getter = GetAclController(self.log_handler)

    async def _do_default(self, line):
        user = None

        if line:
            user = line.pop(0)

        users_data = None

        if user is None:
            users_data = self.getter.get_users()
        else:
            users_data = self.getter.get_user(user)

        for timestamp in sorted(users_data.keys()):
            if not users_data[timestamp]:
                continue

            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            self.view.show_users_stats(
                cinfo_log, users_data[timestamp], timestamp=timestamp, **self.mods
            )


@CommandHelp(
    "Displays roles and their assigned privileges, allowlist, and quotas for the Aerospike cluster.",
    modifiers=(ModifierHelp("role", "Display output for a single role"),),
    short_msg="Displays roles and their assigned privileges, allowlist, and quotas",
    usage="[role]",
)
class ShowRolesController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like"])

    def _do_default(self, line):
        roles_data = self.log_handler.admin_acl(stanza=constants.ADMIN_ROLES)

        for timestamp in sorted(roles_data.keys()):
            if not roles_data[timestamp]:
                continue

            data = list(roles_data[timestamp].values())[0]
            self.view.show_roles(data, timestamp=timestamp, **self.mods)


@CommandHelp(
    "Displays UDF modules along with metadata.",
    modifiers=(
        ModifierHelp(Modifiers.LIKE, "Filter UDFs by name using a substring match"),
    ),
    usage=f"[{ModifierUsage.LIKE}]",
)
class ShowUdfsController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like"])

    def _do_default(self, line):
        udf_data = self.log_handler.info_meta_data(stanza=constants.METADATA_UDF)

        for timestamp in sorted(udf_data.keys()):
            if not udf_data[timestamp]:
                continue

            node_id_to_ip = self.log_handler.get_node_id_to_ip_mapping(timestamp)
            principal_id = self.log_handler.get_principal(timestamp)

            try:
                principal_ip = node_id_to_ip[principal_id]
                data = udf_data[timestamp][principal_ip]
                self.view.show_udfs(data, timestamp=timestamp, **self.mods)
            except KeyError:
                data = list(udf_data[timestamp].values())[0]
                self.view.show_udfs(data, timestamp=timestamp, **self.mods)
                logger.warning(
                    f"No UDF data found for principal node {principal_id}. Using a random node instead."
                )


@CommandHelp(
    "Displays secondary indexes and static metadata.",
    modifiers=(
        ModifierHelp(Modifiers.LIKE, "Filter indexes by name using a substring match"),
    ),
    usage=f"[{ModifierUsage.LIKE}]",
)
class ShowSIndexController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like"])

    def _do_default(self, line):
        sindexes_data = self.log_handler.info_statistics(stanza=constants.STAT_SINDEX)

        for timestamp in sorted(sindexes_data.keys()):
            if not sindexes_data[timestamp]:
                continue

            node_id_to_ip = self.log_handler.get_node_id_to_ip_mapping(timestamp)
            principal_id = self.log_handler.get_principal(timestamp)

            try:
                principal_ip = node_id_to_ip[principal_id]
                data = sindexes_data[timestamp][principal_ip]
                formatted_data = list(data.values())
                self.view.show_sindex(formatted_data, timestamp=timestamp, **self.mods)
            except KeyError:
                data = list(sindexes_data[timestamp].values())[0]
                formatted_data = list(data.values())
                self.view.show_sindex(formatted_data, timestamp=timestamp, **self.mods)
                logger.warning(
                    f"No sindex data found for principal node {principal_id}. Using a random node instead."
                )


@CommandHelp(
    'Displays roster information per node. For easier viewing run "page on" first.',
    modifiers=(
        ModifierHelp(
            "--flip", "Flip output table to show nodes on X axis and roster on Y axis."
        ),
        diff_col_modifier_help,
        for_ns_modifier_help,
    ),
    usage=f"[--flip] [{Modifiers.DIFF}] [{Modifiers.FOR} <ns-substring>]",
    short_msg="Displays roster information per node",
)
class ShowRosterController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "diff", "for"])

    def _do_default(self, line):
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

        roster_configs = self.log_handler.info_getconfig(stanza=constants.CONFIG_ROSTER)

        for timestamp in roster_configs:
            self.view.show_roster(
                roster_configs[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                flip=flip_output,
                **self.mods,
            )


@CommandHelp(
    'Displays any of Aerospike\'s violated "best-practices".',
)
class ShowBestPracticesController(CollectinfoCommandController):
    def __init__(self):
        pass

    def _do_default(self, line):
        best_practices = self.log_handler.info_meta_data(
            stanza=constants.METADATA_PRACTICES
        )

        for timestamp in sorted(best_practices.keys()):
            if not best_practices[timestamp]:
                continue

            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            self.view.show_best_practices(
                cinfo_log, best_practices[timestamp], timestamp=timestamp, **self.mods
            )


@CommandHelp(
    "A collection of commands that display jobs and associated metadata",
)
class ShowJobsController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["trid"])

    @CommandHelp(
        "Displays scans, queries, and sindex-builder jobs.",
    )
    def _do_default(self, line):
        self.do_scans(line[:])
        self.do_queries(line[:])
        self.do_sindex_builder(line[:])

    def _job_helper(self, module, title):
        jobs_data = self.log_handler.info_meta_data(stanza=constants.METADATA_JOBS)

        for timestamp in sorted(jobs_data.keys()):
            if not jobs_data[timestamp]:
                continue

            jobs_data = util.flip_keys(jobs_data[timestamp])
            scan_data = jobs_data.get(module)
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            self.view.show_jobs(title, cinfo_log, scan_data, **self.mods)

    @CommandHelp(
        f'Displays scan jobs. For easier viewing run "page on" first. Removed in server v. {constants.SERVER_QUERIES_ABORT_ALL_FIRST_VERSION} and later.',
        modifiers=(ModifierHelp("trid", "List of transaction IDs to filter for."),),
        usage=f"[trid <trid1> [<trid2>]]",
        short_msg=f"Displays scan jobs. Removed in server v. {constants.SERVER_QUERIES_ABORT_ALL_FIRST_VERSION} and later",
    )
    def do_scans(self, line):
        self._job_helper(constants.JobType.SCAN, "Scan Jobs")

    @CommandHelp(
        'Displays query jobs. For easier viewing run "page on" first.',
        modifiers=(ModifierHelp("trid", "List of transaction IDs to filter for."),),
        usage=f"[trid <trid1> [<trid2>]]",
        short_msg="Displays query jobs",
    )
    def do_queries(self, line):
        self._job_helper(constants.JobType.QUERY, "Query Jobs")

    # TODO: Should be removed eventually. "sindex-builder" was removed in server 5.7.
    # So should probably be removed when server 7.0 is supported.
    @CommandHelp(
        "Displays sindex-builder jobs. Removed in server v. {} and later.".format(
            constants.SERVER_SINDEX_BUILDER_REMOVED_VERSION
        ),
        modifiers=(ModifierHelp("trid", "List of transaction IDs to filter for."),),
        usage=f"[trid <trid1> [<trid2>]]",
        short_msg="Displays sindex-builder jobs. Removed in server v. {} and later".format(
            constants.SERVER_SINDEX_BUILDER_REMOVED_VERSION
        ),
    )
    @CommandName("sindex-builder")
    def do_sindex_builder(self, line):
        self._job_helper(constants.JobType.SINDEX_BUILDER, "SIndex Builder Jobs")


@CommandHelp(
    "Displays rack information for a rack-aware cluster",
)
class ShowRacksController(CollectinfoCommandController):
    def __init__(self):
        pass

    def _do_default(self, line):
        racks_data = self.log_handler.info_getconfig(stanza=constants.CONFIG_RACKS)

        for timestamp, data in racks_data.items():
            node_id_to_ip = self.log_handler.get_node_id_to_ip_mapping(timestamp)
            principal_id = self.log_handler.get_principal(timestamp)

            try:
                principal_ip = node_id_to_ip[principal_id]
                data = {principal_ip: data[principal_ip]}
                self.view.show_racks(data, timestamp=timestamp, **self.mods)
            except KeyError:
                data = {1: list(data.values())[0]}
                self.view.show_racks(data, timestamp=timestamp, **self.mods)
                logger.warning(
                    f"No racks data found for principal node {principal_id}. Using a random node instead."
                )


@CommandHelp(
    "Displays all metrics that could trigger stop-writes",
    modifiers=(for_ns_modifier_help,),
    usage=f"[{Modifiers.FOR} <ns-substring>]",
)
class ShowStopWritesController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["for"])
        self.config_getter = GetConfigController(self.log_handler)
        self.stat_getter = GetStatisticsController(self.log_handler)

    async def _do_default(self, line):
        service_stats = self.stat_getter.get_service()
        ns_stats = self.stat_getter.get_namespace()
        ns_configs = self.config_getter.get_namespace()

        if len(self.mods["for"]) < 2:
            ns_stats = self.stat_getter.get_namespace(for_mods=self.mods["for"])
            ns_configs = self.config_getter.get_namespace(for_mods=self.mods["for"])
        else:
            ns_stats = {}
            ns_configs = {}

        set_stats = self.stat_getter.get_sets(for_mods=self.mods["for"])
        set_configs = self.config_getter.get_sets(for_mods=self.mods["for"])

        for timestamp in sorted(service_stats.keys()):
            if not service_stats[timestamp]:
                continue

            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)

            return self.view.show_stop_writes(
                common.create_stop_writes_summary(
                    service_stats[timestamp],
                    ns_stats[timestamp] if ns_stats else {},
                    ns_configs[timestamp] if ns_configs else {},
                    set_stats[timestamp] if set_stats else {},
                    set_configs[timestamp] if set_configs else {},
                ),
                cinfo_log,
                **self.mods,
            )
