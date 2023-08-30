# Copyright 2021-2023 Aerospike, Inc.
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
import copy
import logging
import os
import pprint
import time

from lib.health import util as health_util
from lib.live_cluster.constants import SSH_MODIFIER_HELP, SSH_MODIFIER_USAGE
from lib.live_cluster.get_controller import (
    GetConfigController,
    GetStatisticsController,
)
from lib.utils import util
from lib.base_controller import CommandHelp, ModifierHelp

from .live_cluster_command_controller import LiveClusterCommandController

logger = logging.getLogger(__name__)


@CommandHelp(
    "Displays health summary. If remote server System credentials provided, then it will collect remote system stats and analyse that also. If credentials are not available then it will collect only localhost system statistics. This command is still in beta and its output should not be directly acted upon without further analysis.",
    short_msg="Displays health summary",
    usage=f"[-dv] [-f <query_file>] [-o <output_file>] [-n <num_snapshots>] [-s <sleep_seconds>] [-oc <output_filter_category>] [-wl <output_filter_warn_level>] [{SSH_MODIFIER_USAGE}]",
    modifiers=(
        ModifierHelp("-f", "Query file path", default="inbuilt health queries."),
        ModifierHelp(
            "-o",
            "Output file path. This parameter works if Query file path provided, otherwise health command will work in interactive mode.",
        ),
        ModifierHelp("-v", "Enable to display extra details of assert errors."),
        ModifierHelp("-d", "Enable to display extra details of exceptions."),
        ModifierHelp("-n", "Number of snapshots", default="1"),
        ModifierHelp(
            "-s",
            "Sleep time in seconds between each snapshot",
            default="1 sec",
        ),
        ModifierHelp(
            "-oc",
            "Output filter Category. This parameter works if Query file path provided, otherwise health command will work in interactive mode. Format: string of dot (.) separated category levels",
        ),
        ModifierHelp(
            "-wl",
            "Output filter Warning level. Expected value CRITICAL or WARNING or INFO. This parameter works if Query file path provided, otherwise health command will work in interactive mode.",
        ),
        *SSH_MODIFIER_HELP,
    ),
    hide=True,
)
class HealthCheckController(LiveClusterCommandController):
    last_snapshot_collection_time = 0
    last_snapshot_count = 0

    def __init__(self):
        self.modifiers = set()

    async def _get_asstat_data(self, stanza):
        if stanza == "service":
            return await self.cluster.info_statistics(nodes=self.nodes)
        elif stanza == "namespace":
            return await self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        elif stanza == "sets":
            return await self.cluster.info_all_set_statistics(nodes=self.nodes)
        elif stanza == "bins":
            return await self.cluster.info_bin_statistics(nodes=self.nodes)
        elif stanza == "xdr":
            return await self.cluster.info_XDR_statistics(nodes=self.nodes)
        elif stanza == "dc":
            return await self.cluster.info_all_dc_statistics(nodes=self.nodes)
        elif stanza == "sindex":
            getter = GetStatisticsController(self.cluster)  # TODO: Use getter for all?
            return await getter.get_sindex(nodes=self.nodes)
        elif stanza == "udf":
            return await self.cluster.info_udf_list(nodes=self.nodes)
        elif stanza == "endpoints":
            return await self.cluster.info_service_list(nodes=self.nodes)
        elif stanza == "services":
            return await self.cluster.info_peers_flat_list(nodes=self.nodes)

    async def _get_asconfig_data(self, stanza):
        if stanza == "xdr":
            return await self.cluster.info_xdr_config(nodes=self.nodes)
        elif stanza == "dc":
            return await self.cluster.info_xdr_dcs_config(nodes=self.nodes)
        elif stanza == "roster":
            getter = GetConfigController(self.cluster)  # TODO: Use getter for all?
            return await getter.get_roster(nodes=self.nodes)
        elif stanza == "racks":
            return await self.cluster.info_racks(nodes=self.nodes)
        else:
            return await self.cluster.info_get_config(nodes=self.nodes, stanza=stanza)

    async def _get_as_meta_data(self, stanza):
        if stanza == "build":
            return await self.cluster.info("build", nodes=self.nodes)
        if stanza == "node_id":
            return await self.cluster.info("node", nodes=self.nodes)
        elif stanza == "edition":
            editions = await self.cluster.info("edition", nodes=self.nodes)
            if not editions:
                return editions

            editions_in_shortform = {}
            for node, edition in editions.items():
                if not edition or isinstance(edition, Exception):
                    continue

                editions_in_shortform[node] = util.convert_edition_to_shortform(edition)

            return editions_in_shortform
        elif stanza == "health":
            return await self.cluster.info_health_outliers(nodes=self.nodes)

    async def _do_default(self, line):
        output_file = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-o",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        snap_count = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-n",
            return_type=int,
            default=1,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        sleep_tm = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-s",
            return_type=int,
            default=1,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        verbose = util.check_arg_and_delete_from_mods(
            line=line, arg="-v", default=False, modifiers=self.modifiers, mods=self.mods
        )

        debug = util.check_arg_and_delete_from_mods(
            line=line, arg="-d", default=False, modifiers=self.modifiers, mods=self.mods
        )

        output_filter_category = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-oc",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        output_filter_warning_level = util.get_arg_and_delete_from_mods(
            line,
            arg="-wl",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        enable_ssh = util.check_arg_and_delete_from_mods(
            line=line,
            arg="--enable-ssh",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_user = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-user",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_pwd = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-pwd",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_port = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-port",
            return_type=int,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_key = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-key",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_key_pwd = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-key",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        # Query file can be specified without -f
        # hence always parsed in the end
        query_file = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-f",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        if not query_file and line:
            query_file = line[0]

        if query_file:
            query_file = util.strip_string(query_file)

        if output_file:
            output_file = util.strip_string(output_file)

        if output_filter_category:
            output_filter_category = [
                util.strip_string(c).upper()
                for c in util.strip_string(output_filter_category).split(".")
            ]
        else:
            output_filter_category = []

        if output_filter_warning_level:
            output_filter_warning_level = util.strip_string(
                output_filter_warning_level
            ).upper()

        if (
            time.time() - HealthCheckController.last_snapshot_collection_time > 60
        ) or HealthCheckController.last_snapshot_count != snap_count:
            # There is possibility of different cluster-names in old
            # heartbeat protocol. As asadm works with single cluster,
            # so we are setting one static cluster-name.
            cluster_name = "C1"

            stanza_dict = {
                "statistics": (
                    self._get_asstat_data,
                    [
                        (
                            "service",
                            "SERVICE",
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "namespace",
                            "NAMESPACE",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("NAMESPACE", None),
                            ],
                        ),
                        (
                            "sets",
                            "SET",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                (
                                    "NAMESPACE",
                                    (
                                        "ns_name",
                                        "ns",
                                    ),
                                ),
                                (
                                    "SET",
                                    (
                                        "set_name",
                                        "set",
                                    ),
                                ),
                            ],
                        ),
                        (
                            "bins",
                            "BIN",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("NAMESPACE", None),
                            ],
                        ),
                        (
                            "xdr",
                            "XDR",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("DC", None),
                                # (None, None),
                                # (None, None),
                                # ("NAMESPACE", None),
                            ],
                        ),
                        (
                            "dc",
                            "DC",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("DC", None),
                            ],
                        ),
                        (
                            "sindex",
                            "SINDEX",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("NAMESPACE", ("ns",)),
                                ("SET", ("set",)),
                                ("SINDEX", ("indexname",)),
                            ],
                        ),
                    ],
                ),
                "config": (
                    self._get_asconfig_data,
                    [
                        (
                            "service",
                            "SERVICE",
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "security",
                            "SECURITY",
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        ("xdr", "XDR", [("CLUSTER", cluster_name), ("NODE", None)]),
                        # (
                        #     "xdr",
                        #     "XDR_DC",
                        #     [
                        #         ("CLUSTER", cluster_name),
                        #         ("NODE", None),
                        #         (None, None),
                        #         (None, None),
                        #         ("DC", None),
                        #     ],
                        # ),
                        (
                            "network",
                            "NETWORK",
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "dc",
                            "DC",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("DC", None),
                            ],
                        ),
                        (
                            "namespace",
                            "NAMESPACE",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("NAMESPACE", None),
                            ],
                        ),
                        (
                            "roster",
                            "ROSTER",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("NAMESPACE", None),
                            ],
                        ),
                        (
                            "racks",
                            "RACKS",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("NAMESPACE", None),
                                (None, None),
                                ("RACKS", None),
                            ],
                        ),
                    ],
                ),
                "original_config": (
                    self.cluster.info_get_originalconfig,
                    [
                        (
                            "service",
                            "SERVICE",
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        ("xdr", "XDR", [("CLUSTER", cluster_name), ("NODE", None)]),
                        (
                            "network",
                            "NETWORK",
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "dc",
                            "DC",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("DC", None),
                            ],
                        ),
                        (
                            "namespace",
                            "NAMESPACE",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("NAMESPACE", None),
                            ],
                        ),
                    ],
                ),
                "cluster": (
                    self._get_as_meta_data,
                    [
                        (
                            "build",
                            "METADATA",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "version"),
                            ],
                        ),
                        (
                            "edition",
                            "METADATA",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "edition"),
                            ],
                        ),
                        (
                            "node_id",
                            "METADATA",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "node-id"),
                            ],
                        ),
                    ],
                ),
                "endpoints": (
                    self._get_asstat_data,
                    [
                        (
                            "endpoints",
                            "METADATA",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "endpoints"),
                            ],
                        ),
                    ],
                ),
                "services": (
                    self._get_asstat_data,
                    [
                        (
                            "services",
                            "METADATA",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "services"),
                            ],
                        ),
                    ],
                ),
                "metadata": (
                    self._get_asstat_data,
                    [
                        (
                            "udf",
                            "UDF",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("FILENAME", None),
                            ],
                        ),
                    ],
                ),
                "health": (
                    self._get_as_meta_data,
                    [
                        (
                            "health",
                            "METADATA",
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("OUTLIER", None),
                            ],
                        ),
                    ],
                ),
            }
            sys_cmd_dict = {
                "sys_stats": (
                    util.restructure_sys_data,
                    [
                        (
                            "free-m",
                            "SYSTEM",
                            "FREE",
                            True,
                            [(None, None), ("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "top",
                            "SYSTEM",
                            "TOP",
                            True,
                            [(None, None), ("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "iostat",
                            "SYSTEM",
                            "IOSTAT",
                            False,
                            [
                                (None, None),
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("DEVICE", None),
                            ],
                        ),
                        (
                            "meminfo",
                            "SYSTEM",
                            "MEMINFO",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "dmesg",
                            "SYSTEM",
                            "DMESG",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "lscpu",
                            "SYSTEM",
                            "LSCPU",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("LSCPU", None),
                            ],
                        ),
                        (
                            "iptables",
                            "SYSTEM",
                            "IPTABLES",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "sysctlall",
                            "SYSTEM",
                            "SYSCTLALL",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("SYSCTL", None),
                            ],
                        ),
                        (
                            "hdparm",
                            "SYSTEM",
                            "HDPARM",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("HDPARM", None),
                            ],
                        ),
                        (
                            "limits",
                            "SYSTEM",
                            "LIMITS",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("LIMITS", None),
                            ],
                        ),
                        (
                            "interrupts",
                            "SYSTEM",
                            "INTERRUPTS",
                            False,
                            [
                                (None, None),
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("INTERRUPT_TYPE", None),
                                (None, None),
                                ("INTERRUPT_ID", None),
                                (None, None),
                                ("INTERRUPT_DEVICE", None),
                            ],
                        ),
                        (
                            "df",
                            "SYSTEM",
                            "DF",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("FILE_SYSTEM", None),
                            ],
                        ),
                        (
                            "lsb",
                            "SYSTEM",
                            "LSB",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None), ("LSB", None)],
                        ),
                        (
                            "environment",
                            "SYSTEM",
                            "ENVIRONMENT",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("ENVIRONMENT", None),
                            ],
                        ),
                        (
                            "scheduler",
                            "SYSTEM",
                            "SCHEDULER",
                            False,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("DEVICE", None),
                            ],
                        ),
                    ],
                ),
            }
            health_input = {}

            sn_ct = 0
            sleep = sleep_tm * 1.0

            logger.info(
                "Collecting "
                + str(snap_count)
                + " collectinfo snapshot. Use -n to set number of snapshots."
            )
            while sn_ct < snap_count:
                fetched_as_val = {}

                for _key, (info_function, stanza_list) in stanza_dict.items():
                    for stanza_item in stanza_list:
                        stanza = stanza_item[0]
                        fetched_as_val[(_key, stanza)] = asyncio.create_task(
                            info_function(stanza)
                        )

                # Collecting data
                sys_stats = asyncio.create_task(
                    self.cluster.info_system_statistics(
                        nodes=self.nodes,
                        enable_ssh=enable_ssh,
                        ssh_user=ssh_user,
                        ssh_pwd=ssh_pwd,
                        ssh_key=ssh_key,
                        ssh_key_pwd=ssh_key_pwd,
                        ssh_port=ssh_port,
                    )
                )

                # Creating health input model
                for _key, (info_function, stanza_list) in stanza_dict.items():
                    for stanza_item in stanza_list:
                        stanza = stanza_item[0]
                        component_name = stanza_item[1]

                        try:
                            d = await fetched_as_val[(_key, stanza)]
                        except Exception:
                            continue

                        try:
                            new_tuple_keys = copy.deepcopy(stanza_item[2])
                        except Exception:
                            new_tuple_keys = []

                        new_component_keys = [
                            health_util.create_snapshot_key(sn_ct),
                            component_name,
                            _key.upper(),
                        ]

                        health_input = health_util.create_health_input_dict(
                            d, health_input, new_tuple_keys, new_component_keys
                        )

                sys_stats = util.flip_keys(await sys_stats)

                for cmd_key, (sys_function, sys_cmd_list) in sys_cmd_dict.items():
                    for cmd_item in sys_cmd_list:
                        cmd_section = cmd_item[0]
                        component_name = cmd_item[1]
                        sub_component_name = cmd_item[2]
                        forced_all_new_keys = cmd_item[3]

                        try:
                            d = sys_function(sys_stats[cmd_section], cmd_section)
                        except Exception:
                            continue

                        if cmd_section == "free-m":
                            d = util.mbytes_to_bytes(d)

                        try:
                            new_tuple_keys = copy.deepcopy(cmd_item[4])
                        except Exception:
                            new_tuple_keys = []

                        new_component_keys = [
                            health_util.create_snapshot_key(sn_ct),
                            component_name,
                            sub_component_name,
                        ]

                        health_input = health_util.create_health_input_dict(
                            d,
                            health_input,
                            new_tuple_keys,
                            new_component_keys,
                            forced_all_new_keys,
                        )

                sn_ct += 1
                logger.info("Snapshot " + str(sn_ct))
                time.sleep(sleep)

            if os.environ.get("FEATKEY"):
                with open("live_health_input.txt", "w") as f:
                    f.write(pprint.pformat(health_input))

            health_input = health_util.h_eval(health_input)

            self.health_checker.set_health_input_data(health_input)
            HealthCheckController.last_snapshot_collection_time = time.time()
            HealthCheckController.last_snapshot_count = snap_count

        else:
            logger.info(
                "Using previous collected snapshot data since it is not older than 1 minute."
            )

        health_summary = self.health_checker.execute(query_file=query_file)

        if health_summary:
            self.view.print_health_output(
                health_summary,
                verbose,
                debug,
                output_file,
                output_filter_category,
                output_filter_warning_level,
            )
            if not verbose:
                logger.info("Please use -v option for more details on failure. \n")
