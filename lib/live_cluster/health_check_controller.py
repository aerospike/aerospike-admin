import asyncio
import copy
import time

from lib.health import util as health_util
from lib.live_cluster.client.get_controller import (
    GetConfigController,
    GetStatisticsController,
)
from lib.utils import util
from lib.base_controller import CommandHelp

from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp(
    "Checks for common inconsistencies and print if there is any.",
    "This command is still in beta and its output should not be directly acted upon without further analysis.",
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
            return await getter.get_sindex(flip=True, nodes=self.nodes)
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

    @CommandHelp(
        "Displays health summary. If remote server System credentials provided, then it will collect remote system stats",
        "and analyse that also. If credentials are not available then it will collect only localhost system statistics.",
        "  Options:",
        "    -f           <string>     - Query file path. Default: inbuilt health queries.",
        "    -o           <string>     - Output file path. ",
        "                                This parameter works if Query file path provided, otherwise health command will work in interactive mode.",
        "    -v                        - Enable to display extra details of assert errors.",
        "    -d                        - Enable to display extra details of exceptions.",
        "    -n           <int>        - Number of snapshots. Default: 1",
        "    -s           <int>        - Sleep time in seconds between each snapshot. Default: 1 sec",
        "    -oc          <string>     - Output filter Category. ",
        "                                This parameter works if Query file path provided, otherwise health command will work in interactive mode.",
        "                                Format : string of dot (.) separated category levels",
        "    -wl          <string>     - Output filter Warning level. Expected value CRITICAL or WARNING or INFO ",
        "                                This parameter works if Query file path provided, otherwise health command will work in interactive mode.",
        "    --enable-ssh              - Enables the collection of system statistics from a remote server.",
        "    --ssh-user   <string>     - Default user ID for remote servers. This is the ID of a user of the system, not the ID of an Aerospike user.",
        "    --ssh-pwd    <string>     - Default password or passphrase for key for remote servers. This is the user's password for logging into",
        "                                the system, not a password for logging into Aerospike.",
        "    --ssh-port   <int>        - Default SSH port for remote servers. Default: 22",
        "    --ssh-key    <string>     - Default SSH key (file path) for remote servers.",
        "    --ssh-cf     <string>     - Remote System Credentials file path.",
        "                                If the server credentials are not in the credentials file, then authentication is attempted with the default",
        "                                credentials.",
        "                                File format : each line should contain <IP[:PORT]>,<USER_ID>,<PASSWORD or PASSPHRASE>,<SSH_KEY>",
        "                                Example:  1.2.3.4,uid,pwd",
        "                                          1.2.3.4:3232,uid,pwd",
        "                                          1.2.3.4:3232,uid,,key_path",
        "                                          1.2.3.4:3232,uid,passphrase,key_path",
        "                                          [2001::1234:10],uid,pwd",
        "                                          [2001::1234:10]:3232,uid,,key_path",
    )
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

        default_user = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-user",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        default_pwd = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-pwd",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        default_ssh_port = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-port",
            return_type=int,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        default_ssh_key = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-key",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        credential_file = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-cf",
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

            self.logger.info(
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
                        default_user=default_user,
                        default_pwd=default_pwd,
                        default_ssh_key=default_ssh_key,
                        default_ssh_port=default_ssh_port,
                        credential_file=credential_file,
                        collect_remote_data=enable_ssh,
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
                self.logger.info("Snapshot " + str(sn_ct))
                time.sleep(sleep)
            health_util.print_dict(health_input)
            health_input = health_util.h_eval(health_input)

            self.health_checker.set_health_input_data(health_input)
            HealthCheckController.last_snapshot_collection_time = time.time()
            HealthCheckController.last_snapshot_count = snap_count

        else:
            self.logger.info(
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
                self.logger.info("Please use -v option for more details on failure. \n")
