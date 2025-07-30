# Copyright 2022-2025 Aerospike, Inc.
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

from lib.base_controller import CommandHelp, ModifierHelp
from lib.collectinfo_analyzer.get_controller import (
    GetConfigController,
    GetStatisticsController,
)
from lib.utils import constants, util, version
import logging

logger = logging.getLogger(__name__)

from .collectinfo_command_controller import CollectinfoCommandController
from lib.base_controller import ShellException

Modifiers = constants.Modifiers
ModifierUsageHelp = constants.ModifierUsage


@CommandHelp(
    "Commands that display summary tables for various aspects of Aerospike functionality.",
    short_msg="Provides summary tables for various aspects of Aerospike functionality",
)
class InfoController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["for"])
        self.stats_getter = GetStatisticsController(self.log_handler)
        self.config_getter = GetConfigController(self.log_handler)
        self.controller_map = dict(
            namespace=InfoNamespaceController, transactions=InfoTransactionsController
        )

    @CommandHelp("Displays network, namespace, and xdr summary information.")
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

        self.do_network(line)
        # needs to be awaited since the base class is async
        await self.controller_map["namespace"]()(line[:])
        self.do_xdr(line)

    @CommandHelp(
        "Displays network information for the cluster",
    )
    def do_network(self, line):
        service_stats = self.log_handler.info_statistics(stanza=constants.STAT_SERVICE)
        for timestamp in sorted(service_stats.keys()):
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()
            versions = cinfo_log.get_asd_version()
            cluster_names = cinfo_log.get_cluster_name()

            # Note how cinfo_log mapped to cluster. Both implement interfaces
            # required by view object
            self.view.info_network(
                service_stats[timestamp],
                cluster_names,
                versions,
                builds,
                cluster=cinfo_log,
                timestamp=timestamp,
                **self.mods,
            )

    def _convert_key_to_tuple(self, stats):
        for key in list(stats.keys()):
            key_tuple = tuple(key.split())
            stats[key_tuple] = stats[key]
            del stats[key]

    @CommandHelp("Displays summary information for each set")
    def do_set(self, line):
        set_stats = self.stats_getter.get_sets()

        for timestamp in sorted(set_stats.keys()):
            if not set_stats[timestamp]:
                continue

            self.view.info_set(
                set_stats[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp(
        "Displays summary information for each datacenter",
        usage=f"[for <dc-substring>]",
        modifiers=(
            ModifierHelp(Modifiers.FOR, "Filter datacenters using a substring match"),
        ),
    )
    def do_xdr(self, line):
        old_stats = self.stats_getter.get_xdr()
        new_stats = self.stats_getter.get_xdr_dcs(for_mods=self.mods["for"])
        for timestamp in sorted(old_stats.keys()):
            if not old_stats[timestamp]:
                continue

            xdr_enable = {}
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()
            old_xdr_stats = {}
            xdr5_stats = {}

            for xdr_node in old_stats[timestamp].keys():
                xdr_enable[xdr_node] = True
                build = builds.get(xdr_node)

                if not build:
                    continue

                if version.LooseVersion(builds[xdr_node]) < version.LooseVersion(
                    constants.SERVER_NEW_XDR5_VERSION
                ):
                    old_xdr_stats[xdr_node] = old_stats[timestamp][xdr_node]
                else:
                    xdr5_stats[xdr_node] = new_stats[timestamp][xdr_node]

            if xdr5_stats:
                self.view.info_XDR(
                    xdr5_stats,
                    xdr_enable,
                    cluster=cinfo_log,
                    timestamp=timestamp,
                    **self.mods,
                )

            if old_xdr_stats:
                self.view.info_old_XDR(
                    old_xdr_stats,
                    builds,
                    xdr_enable,
                    cluster=cinfo_log,
                    timestamp=timestamp,
                    **self.mods,
                )

    # pre 5.0
    @CommandHelp(
        'Displays summary information for each datacenter. Replaced by "info xdr" for server >= 5.0.',
        hide=True,
    )
    def do_dc(self, line):
        dc_stats = self.log_handler.info_statistics(stanza=constants.STAT_DC, flip=True)
        dc_config = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_DC, flip=True
        )
        for timestamp in sorted(dc_stats.keys()):
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()
            nodes_running_v5_or_higher = False
            nodes_running_v49_or_lower = False
            node_xdr_build_major_version = 5

            if not dc_stats[timestamp]:
                continue

            for dc in dc_stats[timestamp].keys():
                try:
                    if (
                        dc_stats[timestamp][dc]
                        and not isinstance(dc_stats[timestamp][dc], Exception)
                        and dc_config[timestamp]
                        and dc_config[timestamp][dc]
                        and not isinstance(dc_config[timestamp][dc], Exception)
                    ):
                        for node in dc_stats[timestamp][dc].keys():
                            if node in dc_config[timestamp][dc]:
                                dc_stats[timestamp][dc][node].update(
                                    dc_config[timestamp][dc][node]
                                )

                    elif (
                        (
                            not dc_stats[timestamp][dc]
                            or isinstance(dc_stats[timestamp][dc], Exception)
                        )
                        and dc_config[timestamp]
                        and dc_config[timestamp][dc]
                        and not isinstance(dc_config[timestamp][dc], Exception)
                    ):
                        dc_stats[timestamp][dc] = dc_config[timestamp][dc]

                except Exception:
                    pass

            for version in builds.values():
                try:
                    node_xdr_build_major_version = int(version[0])
                except Exception:
                    continue

                if node_xdr_build_major_version >= 5:
                    nodes_running_v5_or_higher = True
                else:
                    nodes_running_v49_or_lower = True

            if nodes_running_v49_or_lower:
                self.view.info_dc(
                    util.flip_keys(dc_stats[timestamp]),
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    timestamp=timestamp,
                    **self.mods,
                )

            if nodes_running_v5_or_higher:
                self.view.print_result(
                    "WARNING: 'info dc' is deprecated "
                    + "on aerospike versions >= 5.0.\n"
                    + "Use 'info xdr' instead."
                )

    @CommandHelp(
        "Displays summary information for Secondary Indexes",
    )
    def do_sindex(self, line):
        sindex_stats = self.stats_getter.get_sindex()
        ns_configs = self.config_getter.get_namespace()

        for timestamp in sorted(sindex_stats.keys()):
            if not sindex_stats[timestamp] or not ns_configs[timestamp]:
                continue

            self.view.info_sindex(
                sindex_stats[timestamp],
                ns_configs[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods,
            )


@CommandHelp(
    "A collection of commands that display summary tables for various aspects of Aerospike namespaces",
    short_msg="Provides summary tables for various aspects of Aerospike functionality",
)
class InfoNamespaceController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set()
        self.config_getter = GetConfigController(self.log_handler)
        self.stat_getter = GetStatisticsController(self.log_handler)

    @CommandHelp("Displays usage and objects information for each namespace")
    def _do_default(self, line):
        self.do_usage(line)
        self.do_object(line)

    @CommandHelp("Displays usage information for each namespace")
    def do_usage(self, line):
        ns_stats = self.stat_getter.get_namespace()
        service_stats = self.stat_getter.get_service()

        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                continue

            self.view.info_namespace_usage(
                ns_stats[timestamp],
                service_stats[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp("Displays object information for each namespace.")
    def do_object(self, line):
        # In SC mode effective rack-id is different from that in namespace config.
        ns_stats = self.stat_getter.get_namespace()
        rack_ids = self.config_getter.get_rack_ids()

        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                continue

            self.view.info_namespace_object(
                ns_stats[timestamp],
                rack_ids.get(timestamp, {}),
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods,
            )


@CommandHelp(
    "Displays transaction metrics for each 'strong-consistency' enabled namespace.",
)
class InfoTransactionsController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set()
        self.stats_getter = GetStatisticsController(self.log_handler)

    @CommandHelp(
        "Displays monitors and provisionals information for transactions in each 'strong-consistency' enabled namespace.",
    )
    def _do_default(self, line):
        self.do_monitors(line)
        self.do_provisionals(line)

    @CommandHelp(
        "Displays monitor-related transaction metrics for each 'strong-consistency' enabled namespace.",
    )
    def do_monitors(self, line):
        # Get namespace statistics which contain MRT metrics
        ns_stats = self.stats_getter.get_strong_consistency_namespace()

        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                continue

            namespaces = set()
            for _, node_stats in ns_stats[timestamp].items():
                namespaces.update(node_stats.keys())

            # Check if any strong consistency namespaces were found
            if not namespaces:
                logger.debug(
                    "No namespaces with strong consistency enabled were found at %s",
                    timestamp,
                )
                continue

            for namespace in namespaces:
                set_data = self.stats_getter.get_sets(
                    for_mods=[namespace, constants.MRT_SET]
                )

                if timestamp in set_data:
                    for node_id, sets_dict in set_data[timestamp].items():
                        if (
                            node_id not in ns_stats[timestamp]
                            or namespace not in ns_stats[timestamp][node_id]
                        ):
                            continue
                        set_stats = sets_dict.get((namespace, constants.MRT_SET))
                        # Always add set metrics to namespace stats, defaulting to 0 if not present
                        ns_stats[timestamp][node_id][namespace][
                            "pseudo_mrt_monitor_used_bytes"
                        ] = int(set_stats.get("data_used_bytes", 0) if set_stats else 0)
                        ns_stats[timestamp][node_id][namespace]["stop-writes-count"] = (
                            int(
                                set_stats.get("stop-writes-count", 0)
                                if set_stats
                                else 0
                            )
                        )
                        ns_stats[timestamp][node_id][namespace]["stop-writes-size"] = (
                            int(
                                set_stats.get("stop-writes-size", 0) if set_stats else 0
                            )
                        )

            self.view.info_transactions_monitors(
                ns_stats[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods,
            )

    @CommandHelp(
        "Displays provisional-related transaction metrics for each 'strong-consistency' enabled namespace.",
    )
    def do_provisionals(self, line):
        # Get namespace statistics which contain MRT metrics
        ns_stats = self.stats_getter.get_strong_consistency_namespace()

        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                continue

            namespaces = set()
            for _, node_stats in ns_stats[timestamp].items():
                namespaces.update(node_stats.keys())

            if not namespaces:
                logger.debug(
                    "No namespaces with strong consistency enabled were found at %s",
                    timestamp,
                )
                continue

            self.view.info_transactions_provisionals(
                ns_stats[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods,
            )
