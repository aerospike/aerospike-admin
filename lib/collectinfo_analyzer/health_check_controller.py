# Copyright 2022-2023 Aerospike, Inc.
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

import copy
import logging
import os
import pprint

from lib.base_controller import CommandHelp, ModifierHelp
import lib.health as health
from lib.utils import util

from .collectinfo_command_controller import CollectinfoCommandController

logger = logging.getLogger(__name__)


@CommandHelp(
    "Displays all lines from cluster logs (collectinfos) matched with input strings.",
    short_msg="Displays health summary",
    usage="[-dv] [-f <query_file>] [-o <output_file>] [-oc <output_filter_category>] [-wl <output_filter_warn_level>]",
    modifiers=(
        ModifierHelp(
            "-f <string>", "Query file path. Default: inbuilt health queries."
        ),
        ModifierHelp(
            "-o <string>",
            "Output file path. This parameter works if Query file path provided, otherwise health command will work in interactive mode.",
        ),
        ModifierHelp("-v", "Enable to display extra details of assert errors."),
        ModifierHelp("-d", "Enable to display extra details of exceptions."),
        ModifierHelp(
            "-oc <string>",
            "Output filter Category. This parameter works if Query file path provided, otherwise health command will work in interactive mode. Format: string of dot (.) separated category levels",
        ),
        ModifierHelp(
            "-wl <string>",
            "Output filter Warning level. Expected value CRITICAL or WARNING or INFO. This parameter works if Query file path provided, otherwise health command will work in interactive mode.",
        ),
    ),
)
class HealthCheckController(CollectinfoCommandController):
    health_check_input_created = False

    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        output_file = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-o",
            return_type=str,
            default=None,
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
            line=line,
            arg="-wl",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        # Query file name last to be parsed as health
        # command can be run without -f and directly
        # with file name
        query_file = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-f",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

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

        if not HealthCheckController.health_check_input_created:
            # There is possibility of different cluster-names in old heartbeat protocol.
            # As asadm works with single cluster, so we are setting one static
            # cluster-name.
            cluster_name = "C1"
            stanza_dict = {
                "statistics": (
                    self.log_handler.info_statistics,
                    [
                        (
                            "service",
                            "SERVICE",
                            "STATISTICS",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "namespace",
                            "NAMESPACE",
                            "STATISTICS",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("NAMESPACE", None),
                            ],
                        ),
                        (
                            "set",
                            "SET",
                            "STATISTICS",
                            True,
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
                            "bin",
                            "BIN",
                            "STATISTICS",
                            True,
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
                            "STATISTICS",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "dc",
                            "DC",
                            "STATISTICS",
                            True,
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
                            "STATISTICS",
                            True,
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
                    self.log_handler.info_getconfig,
                    [
                        (
                            "service",
                            "SERVICE",
                            "CONFIG",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "xdr",
                            "XDR",
                            "CONFIG",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "network",
                            "NETWORK",
                            "CONFIG",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "dc",
                            "DC",
                            "CONFIG",
                            True,
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
                            "CONFIG",
                            True,
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
                            "CONFIG",
                            True,
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
                            "CONFIG",
                            True,
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
                    self.log_handler.info_get_originalconfig,
                    [
                        (
                            "service",
                            "SERVICE",
                            "ORIGINAL_CONFIG",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "xdr",
                            "XDR",
                            "ORIGINAL_CONFIG",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "network",
                            "NETWORK",
                            "ORIGINAL_CONFIG",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
                        ),
                        (
                            "dc",
                            "DC",
                            "ORIGINAL_CONFIG",
                            True,
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
                            "ORIGINAL_CONFIG",
                            True,
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
                    self.log_handler.info_meta_data,
                    [
                        (
                            "asd_build",
                            "METADATA",
                            "CLUSTER",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "version"),
                            ],
                        ),
                        (
                            "edition",
                            "METADATA",
                            "CLUSTER",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "edition"),
                            ],
                        ),
                        (
                            "node_id",
                            "METADATA",
                            "CLUSTER",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "node-id"),
                            ],
                        ),
                    ],
                ),
                "endpoints": (
                    self.log_handler.info_meta_data,
                    [
                        (
                            "endpoints",
                            "METADATA",
                            "ENDPOINTS",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "endpoints"),
                            ],
                        ),
                    ],
                ),
                "services": (
                    self.log_handler.info_meta_data,
                    [
                        (
                            "services",
                            "METADATA",
                            "SERVICES",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                ("KEY", "services"),
                            ],
                        ),
                    ],
                ),
                "udf": (
                    self.log_handler.info_meta_data,
                    [
                        (
                            "udf",
                            "UDF",
                            "METADATA",
                            True,
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
                    self.log_handler.info_meta_data,
                    [
                        (
                            "health",
                            "METADATA",
                            "HEALTH",
                            True,
                            [
                                ("CLUSTER", cluster_name),
                                ("NODE", None),
                                (None, None),
                                ("OUTLIER", None),
                            ],
                        ),
                    ],
                ),
                "sys_stats": (
                    self.log_handler.get_sys_data,
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
                            "iptables",
                            "SYSTEM",
                            "IPTABLES",
                            True,
                            [("CLUSTER", cluster_name), ("NODE", None)],
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
            for _key, (info_function, stanza_list) in stanza_dict.items():
                for stanza_item in stanza_list:
                    stanza = stanza_item[0]
                    component_name = stanza_item[1]
                    sub_component_name = stanza_item[2]
                    forced_all_new_keys = stanza_item[3]

                    d = info_function(stanza=stanza)

                    if not d:
                        continue

                    if stanza == "free-m":
                        d = util.mbytes_to_bytes(d)

                    sn_ct = 0
                    new_tuple_keys = []

                    try:
                        new_tuple_keys = copy.deepcopy(stanza_item[4])
                    except Exception:
                        pass

                    for _k in sorted(d.keys()):
                        health_input = health.util.create_health_input_dict(
                            d[_k],
                            health_input,
                            new_tuple_keys=new_tuple_keys,
                            new_component_keys=[
                                health.util.create_snapshot_key(sn_ct),
                                component_name,
                                sub_component_name,
                            ],
                            forced_all_new_keys=forced_all_new_keys,
                        )
                        sn_ct += 1

            # FEATKEY is defined during tests. This is to help debugging github actions failures.
            if os.environ.get("FEATKEY"):
                with open("cf_health_input.txt", "w") as f:
                    f.write(pprint.pformat(health_input))

            health_input = health.util.h_eval(health_input)
            self.health_checker.set_health_input_data(health_input)
            HealthCheckController.health_check_input_created = True

        health_summary = self.health_checker.execute(query_file=query_file)

        if health_summary:
            self.view.print_health_output(
                health_summary,
                debug=debug,
                verbose=verbose,
                output_file=output_file,
                output_filter_category=output_filter_category,
                output_filter_warning_level=output_filter_warning_level,
            )
            if not verbose:
                logger.info("Please use -v option for more details on failure. \n")
