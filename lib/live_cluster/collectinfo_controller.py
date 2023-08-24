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
import json
import logging
from os import path
import os
import pprint
import shutil
import time
import sys
import traceback
from typing import Any, Callable, Coroutine, Optional
from lib.live_cluster.client import node
from lib.live_cluster.client.node import Node
from lib.live_cluster.generate_config_controller import GenerateConfigController
from lib.live_cluster.logfile_downloader import LogFileDownloader
from lib.live_cluster import ssh
from lib.utils.types import NodeDict

from lib.view.sheet.render import get_style_json, set_style_json
from lib.view.terminal import terminal
from lib.utils import common, constants, util, version
from lib.utils.logger import LogFormatter, stderr_log_handler, logger as g_logger
from lib.base_controller import CommandHelp, ModifierHelp
from lib.collectinfo_analyzer.collectinfo_root_controller import (
    CollectinfoRootController,
)
from lib.live_cluster.get_controller import (
    GetStatisticsController,
    GetConfigController,
    GetAclController,
    GetLatenciesController,
    GetPmapController,
    GetJobsController,
)

from .live_cluster_command_controller import LiveClusterCommandController
from .features_controller import FeaturesController
from .info_controller import InfoController
from .show_controller import ShowController

logger = logging.getLogger(__name__)


@CommandHelp(
    "Collects cluster info, aerospike conf file for local node and system stats from all nodes if remote server credentials provided. If credentials are not available then it will collect system stats from local node only.",
    usage="[-n <num-snapshots>] [-s <sleep>] [--enable-ssh --ssh-user <user> --ssh-pwd <pwd> [--ssh-port <port>] [--ssh-key <key>] [--ssh-cf <credentials-file>]] [--agent-host <host> --agent-port <port> [--agent-store]] [--output-prefix <prefix>] [--asconfig-file <path>]",
    modifiers=(
        ModifierHelp("-n", "Number of snapshots.", default="1"),
        ModifierHelp(
            "-s", "Sleep time in seconds between each snapshot.", default="5 sec"
        ),
        ModifierHelp(
            "--enable-ssh",
            "Enables the collection of system statistics from the remote server.",
        ),
        ModifierHelp(
            "--ssh-user",
            "Default user ID for remote servers. This is the ID of a user of the system, not the ID of an Aerospike user.",
        ),
        ModifierHelp(
            "--ssh-pwd",
            "Default password or passphrase for key for remote servers. This is the user's password for logging into the system, not a password for logging into Aerospike.",
        ),
        ModifierHelp(
            "--ssh-port", "Default SSH port for remote servers.", default="22"
        ),
        ModifierHelp("--ssh-key", "Default SSH key (file path) for remote servers."),
        ModifierHelp(
            "--ssh-cf",
            "Remote System Credentials file path. If the server credentials are not in the credentials file, then authentication is attempted with the default credentials. File format: each line must contain <IP[:PORT]>,<USER_ID>,<PASSWORD-or-PASSPHRASE>,<SSH_KEY>",
        ),
        ModifierHelp(
            "--agent-host",
            "Host IP of the Unique Data Agent to collect license data usage.",
        ),
        ModifierHelp("--agent-port", "Port of the UDA.", default="8080"),
        ModifierHelp("--agent-store", "Collect the raw datastore of the UDA."),
        ModifierHelp("--output-prefix", "Output directory name prefix."),
        ModifierHelp(
            "--asconfig-file",
            "Aerospike config file path to collect.",
            default="/etc/aerospike/aerospike.conf",
        ),
    ),
    short_msg="Collects cluster info, system stats, and aerospike conf file for local node",
)
class CollectinfoController(LiveClusterCommandController):
    get_pmap = False

    def __init__(self):
        self.modifiers = set(["with"])
        self.collectinfo_root_controller = None

    def _collect_local_file(self, src, dest_dir):
        logger.info("Copying file %s to %s" % (src, dest_dir))
        try:
            shutil.copy2(src, dest_dir)
        except Exception as e:
            raise e

    async def _collectinfo_capture_and_write_to_file(
        self, filename: str, func: Callable, param: list[str] = []
    ):
        if self.nodes and isinstance(self.nodes, list):
            param += ["with"] + self.nodes

        o = await util.capture_stdout(func, param[:])

        self._write_func_output_to_file(filename, func, param, o)

    def _write_func_output_to_file(
        self, filename: str, func: Callable, param: list[str], content: str
    ):
        name = ""
        sep = constants.COLLECTINFO_SEPERATOR

        old_style_json = get_style_json()
        set_style_json(False)

        try:
            name = func.__name__
        except Exception as e:
            pass

        if param:
            sep += " ".join(param) + "\n"

        util.write_to_file(filename, sep + str(content))

        set_style_json(old_style_json)

    def _write_version(self, line):
        print("asadm version " + str(self.asadm_version))

    def _parse_namespace(self, namespace_data):
        """
        This method will return set of namespaces present given namespace data
        @param namespace_data: should be a form of dict returned by info protocol for namespace.
        """
        namespaces = set()

        for _value in namespace_data.values():
            for ns in _value.split(";"):
                namespaces.add(ns)
        return namespaces

    ###########################################################################
    # Functions for dumping json

    def _restructure_set_section(self, stats):
        for node, node_data in stats.items():
            if constants.STAT_SETS not in node_data.keys():
                continue

            for key, val in node_data[constants.STAT_SETS].items():
                ns_name = key[0]
                setname = key[1]

                if ns_name not in node_data[constants.STAT_NAMESPACE]:
                    continue

                ns = node_data[constants.STAT_NAMESPACE][ns_name]

                if constants.STAT_SETS not in ns.keys():
                    ns[constants.STAT_SETS] = {}

                ns[constants.STAT_SETS][setname] = copy.deepcopy(val)

            del node_data[constants.STAT_SETS]

    def _restructure_sindex_section(self, stats):
        # Due to new server feature namespace add/remove with rolling restart,
        # there is possibility that different nodes will have different namespaces and
        # old sindex info available for node which does not have namespace for that sindex.

        for node, node_data in stats.items():
            if "sindex" not in node_data.keys():
                continue

            for key, val in node_data["sindex"].items():
                key_list = key.split()
                ns_name = key_list[0]
                sindex_name = key_list[2]

                if ns_name not in node_data["namespace"]:
                    continue

                ns = node_data["namespace"][ns_name]

                if "sindex" not in ns.keys():
                    ns["sindex"] = {}

                ns["sindex"][sindex_name] = copy.deepcopy(val)

            del node_data["sindex"]

    def _restructure_bin_section(self, stats):
        for node, node_data in stats.items():
            if "bin" not in node_data.keys():
                continue
            for ns_name, val in node_data["bin"].items():
                if ns_name not in node_data["namespace"]:
                    continue

                ns = node_data["namespace"][ns_name]
                ns["bin"] = copy.deepcopy(val)

            del node_data["bin"]

    def _init_stat_ns_subsection(self, data):
        for node, node_data in data.items():
            if "namespace" not in node_data.keys():
                continue
            ns_map = node_data["namespace"]
            for ns, data in ns_map.items():
                ns_map[ns]["set"] = {}
                ns_map[ns]["bin"] = {}
                ns_map[ns]["sindex"] = {}

    def _restructure_ns_section(self, data):
        for node, node_data in data.items():
            if "namespace" not in node_data.keys():
                continue
            ns_map = node_data["namespace"]
            for ns, data in ns_map.items():
                stat = {}
                stat[ns] = {}
                stat[ns]["service"] = data
                ns_map[ns] = stat[ns]

    def _remove_exception_from_section_output(self, data):
        for section in data:
            for node in data[section]:
                if isinstance(data[section][node], Exception):
                    data[section][node] = {}

    async def _get_as_cluster_name(self) -> str:
        cluster_names = await self.cluster.info("cluster-name")

        # Get the cluster name and add one more level in map
        cluster_name = "null"

        # Cluster name.
        for node in cluster_names:
            if (
                not isinstance(cluster_names[node], Exception)
                and cluster_names[node] != "null"
            ):
                cluster_name = cluster_names[node]
                break

        return cluster_name

    async def _get_as_data_json(self):
        as_map = {}
        stat_getter = GetStatisticsController(self.cluster)
        config_getter = GetConfigController(self.cluster)

        stats, config = await asyncio.gather(
            stat_getter.get_all(nodes=self.nodes),
            config_getter.get_all(nodes=self.nodes),
        )

        self._remove_exception_from_section_output(stats)
        self._remove_exception_from_section_output(config)

        # flip key to get node ids in upper level and sections inside them.
        # {'namespace': {'ip1': {'test': {}}, 'ip2': {'test': {}}}} -->
        # {'ip1':{'namespace': {'test': {}}}, 'ip2': {'namespace': {'test': {}}}}
        new_stats = util.flip_keys(stats)
        new_config = util.flip_keys(config)

        # Create a new service level for all ns stats.
        # {'namespace': 'test': {<stats>}} -->
        # {'namespace': 'test': {'service': {<stats>}}}
        self._restructure_ns_section(new_stats)
        # ns stats would have set and bin data too, service level will
        # consolidate its service stats and put sets, sindex, bin stats
        # in namespace section
        self._init_stat_ns_subsection(new_stats)
        self._restructure_set_section(new_stats)
        self._restructure_sindex_section(new_stats)
        self._restructure_bin_section(new_stats)
        # No config for sindex, bin
        self._restructure_ns_section(new_config)
        self._restructure_set_section(new_config)

        as_map["statistics"] = new_stats
        as_map["config"] = new_config

        new_as_map = util.flip_keys(as_map)

        return new_as_map

    def _check_for_exception_and_set(self, data, section_name, nodeid, result_map):
        if nodeid in data:
            if not isinstance(data[nodeid], Exception):
                result_map[nodeid][section_name] = data[nodeid]
            else:
                result_map[nodeid][section_name] = ""

    async def _get_as_metadata(self):
        metamap = {}
        (
            builds,
            editions,
            node_ids,
            ips,
            endpoints,
            services,
            udf_data,
            health_outliers,
            best_practices,
            jobs,
        ) = await asyncio.gather(
            self.cluster.info_build(nodes=self.nodes),
            self.cluster.info_version(nodes=self.nodes),
            self.cluster.info_node(nodes=self.nodes),
            self.cluster.info_ip_port(nodes=self.nodes),
            self.cluster.info_service_list(nodes=self.nodes),
            self.cluster.info_peers_flat_list(nodes=self.nodes),
            self.cluster.info_udf_list(nodes=self.nodes),
            self.cluster.info_health_outliers(nodes=self.nodes),
            self.cluster.info_best_practices(nodes=self.nodes),
            GetJobsController(self.cluster).get_all(flip=True, nodes=self.nodes),
        )
        node_names = self.cluster.get_node_names()

        for nodeid in builds:
            metamap[nodeid] = {}
            self._check_for_exception_and_set(builds, "asd_build", nodeid, metamap)
            self._check_for_exception_and_set(editions, "edition", nodeid, metamap)
            self._check_for_exception_and_set(node_ids, "node_id", nodeid, metamap)
            self._check_for_exception_and_set(ips, "ip", nodeid, metamap)
            self._check_for_exception_and_set(endpoints, "endpoints", nodeid, metamap)
            self._check_for_exception_and_set(services, "services", nodeid, metamap)
            self._check_for_exception_and_set(udf_data, "udf", nodeid, metamap)
            self._check_for_exception_and_set(
                health_outliers, "health", nodeid, metamap
            )
            self._check_for_exception_and_set(
                best_practices, "best_practices", nodeid, metamap
            )
            self._check_for_exception_and_set(node_names, "node_names", nodeid, metamap)
            self._check_for_exception_and_set(jobs, "jobs", nodeid, metamap)
        return metamap

    async def _get_as_histograms(self):
        histogram_map = {}
        hist_list = [
            ("ttl", "ttl", False),
            ("objsz", "objsz", False),
            ("objsz", "object-size", True),
        ]
        hist_dumps = await asyncio.gather(
            *[
                self.cluster.info_histogram(
                    hist[0],
                    logarithmic=hist[2],
                    raw_output=True,
                    nodes=self.nodes,
                )
                for hist in hist_list
            ]
        )

        for hist, hist_dump in zip(hist_list, hist_dumps):
            for node in hist_dump:
                if node not in histogram_map:
                    histogram_map[node] = {}

                if not hist_dump[node] or isinstance(hist_dump[node], Exception):
                    continue

                histogram_map[node][hist[1]] = hist_dump[node]

        return histogram_map

    async def _get_as_latency(self):
        latency_getter = GetLatenciesController(self.cluster)
        latencies_data = await latency_getter.get_all(
            self.nodes, buckets=17, exponent_increment=1, verbose=1
        )
        latency_map = {}

        for node in latencies_data:
            if node not in latency_map:
                latency_map[node] = {}

            if not latencies_data[node] or isinstance(latencies_data[node], Exception):
                continue

            latency_map[node] = latencies_data[node]

        return latency_map

    async def _get_as_pmap(self):
        getter = GetPmapController(self.cluster)
        return await getter.get_pmap(nodes=self.nodes)

    async def _get_as_access_control_list(self) -> NodeDict[dict[str, dict[str, Any]]]:
        users_getter = GetAclController(self.cluster)
        users_map = await users_getter.get_all()
        self._remove_exception_from_section_output(users_map)
        users_map = util.flip_keys(users_map)
        return users_map

    async def _get_collectinfo_data_json(
        self,
        default_user,
        default_pwd_key,
        default_ssh_port,
        default_ssh_key,
        enable_ssh,
    ):
        logger.debug("Collectinfo data to store in collectinfo_*.json")

        dump_map = {}

        (
            cluster_name,
            as_map,
            meta_map,
            histogram_map,
            latency_map,
            acl_map,
            sys_map,
        ) = await asyncio.gather(
            self._get_as_cluster_name(),
            self._get_as_data_json(),
            self._get_as_metadata(),
            self._get_as_histograms(),
            self._get_as_latency(),
            self._get_as_access_control_list(),
            self.cluster.info_system_statistics(
                default_user=default_user,
                default_pwd=default_pwd_key,
                default_ssh_key=default_ssh_key,
                default_ssh_port=default_ssh_port,
                nodes=self.nodes,
                collect_remote_data=enable_ssh,
            ),
        )

        pmap_map = None

        if CollectinfoController.get_pmap:
            pmap_map = await self._get_as_pmap()

        for node in as_map:
            dump_map[node] = {}
            dump_map[node]["as_stat"] = as_map[node]
            if node in sys_map:
                dump_map[node]["sys_stat"] = sys_map[node]
            if node in meta_map:
                dump_map[node]["as_stat"]["meta_data"] = meta_map[node]

            if node in histogram_map:
                dump_map[node]["as_stat"]["histogram"] = histogram_map[node]

            if node in latency_map:
                dump_map[node]["as_stat"]["latency"] = latency_map[node]

            if pmap_map and node in pmap_map:
                dump_map[node]["as_stat"]["pmap"] = pmap_map[node]

            # ACL requests only go to principal therefor we are storing it only
            # for the principal
            if node in acl_map:
                dump_map[node]["as_stat"]["acl"] = acl_map[node]

        snp_map = {}
        snp_map[cluster_name] = dump_map
        return snp_map

    def _dump_in_json_file(self, complete_name, dump):
        try:
            json_dump = json.dumps(dump, indent=2, separators=(",", ":"))
            util.filter_exceptions(json_dump)
            self._dump_collectinfo_file(complete_name, json_dump)
        except Exception:
            pretty_json = pprint.pformat(dump, indent=1)
            logger.debug(pretty_json)
            raise

    async def _dump_collectinfo_json(
        self,
        as_logfile_prefix,
        default_user,
        default_pwd_key,
        default_ssh_port,
        default_ssh_key,
        enable_ssh,
        snp_count,
        wait_time,
    ):
        snpshots = {}

        for i in range(snp_count):
            snp_timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            logger.info(
                "Data collection for Snapshot: " + str(i + 1) + " in progress..."
            )

            snpshots[snp_timestamp] = await self._get_collectinfo_data_json(
                default_user,
                default_pwd_key,
                default_ssh_port,
                default_ssh_key,
                enable_ssh,
            )

            logger.info("Data collection for Snapshot " + str(i + 1) + " finished.")

            time.sleep(wait_time)

        self._dump_in_json_file(as_logfile_prefix + "ascinfo.json", snpshots)

    def _dump_collectinfo_file(self, filename: str, dump: str):
        logger.info("Dumping collectinfo %s.", filename)

        try:
            util.write_to_file(filename, dump)
        except Exception as e:
            logger.warning("Failed to write file {}: {}", filename, str(e))
            raise

    async def _dump_collectinfo_license_data(
        self,
        as_logfile_prefix: str,
        agent_host: str,
        agent_port: str,
        get_store: bool,
    ) -> None:
        logger.info("Data collection license usage in progress...")
        logger.info("Requesting data usage for past 365 days...")
        error = None
        resp = {}

        try:
            resp = await common.request_license_usage(agent_host, agent_port, get_store)
        except Exception as e:
            msg = "Failed to retrieve license usage information : {}".format(e)
            resp["error"] = msg
            logger.error(msg)

            complete_filename = as_logfile_prefix + "aslicenseusage.json"
            self._dump_in_json_file(complete_filename, resp)

            raise Exception(msg)

        if "raw_store" in resp:
            filename = "aslicenseraw.store"
            complete_filename = as_logfile_prefix + filename
            raw_store = resp["raw_store"]
            self._dump_collectinfo_file(complete_filename, raw_store)
            del resp["raw_store"]

        complete_filename = as_logfile_prefix + "aslicenseusage.json"
        self._dump_in_json_file(complete_filename, resp)

    ###########################################################################
    # Functions for dumping pretty print files

    async def _dump_collectinfo_ascollectinfo(
        self, as_logfile_prefix, file_header
    ) -> None:
        ####### Dignostic info ########
        file = "ascollectinfo.log"
        complete_filename = as_logfile_prefix + file
        logger.info(f"Capturing pretty print output for {file} . . .")

        try:
            dignostic_info_params = [
                "network",
                "namespace",
                "set",
                "xdr",
                "dc",
                "sindex",
            ]

            dignostic_features_params = ["features"]

            dignostic_show_params = [
                "config",
                "config xdr",
                "config dc",
                "config cluster",
                "distribution",
                "distribution eviction",
                "distribution object_size -b",
                "latencies -v -e 1 -b 17",
                "statistics",
                "statistics xdr",
                "statistics dc",
                "statistics sindex",
            ]

            if CollectinfoController.get_pmap:
                dignostic_show_params.append("pmap")

            dignostic_aerospike_info_commands = [
                "service",
                "services",
                "peers-clear-std",
                "peers-clear-alt",
                "peers-tls-std",
                "peers-tls-alt",
                "alumni-clear-std",
                "alumni-tls-std",
                "peers-generation",
                "roster:",
            ]

            as_version = asyncio.create_task(self.cluster.info("build"))
            namespaces = asyncio.create_task(self.cluster.info("namespaces"))

            # find version
            try:
                as_version = await as_version
                as_version = as_version.popitem()[1]
            except Exception:
                as_version = None

            if isinstance(as_version, Exception):
                as_version = None

            # find all namespaces
            try:
                namespaces = self._parse_namespace(await namespaces)
            except Exception:
                namespaces = []

            # add hist-dump or histogram command to collect list

            hist_list = ["ttl", "object-size", "object-size-linear"]
            hist_dump_info_str = "histogram:namespace=%s;type=%s"

            try:
                if version.LooseVersion(as_version) < version.LooseVersion("4.2.0"):
                    # histogram command introduced in 4.2.0
                    # use hist-dump command for older versions
                    hist_list = ["ttl", "objsz"]
                    hist_dump_info_str = "hist-dump:ns=%s;hist=%s"
            except Exception:  # probably failed to get build version, node may be down
                pass

            for ns in namespaces:
                for hist in hist_list:
                    dignostic_aerospike_info_commands.append(
                        hist_dump_info_str % (ns, hist)
                    )

            util.write_to_file(complete_filename, file_header)

            # All these calls to collectinfo_content must happen synchronously because they
            # capture std output.
            try:
                await self._collectinfo_capture_and_write_to_file(
                    complete_filename, self._write_version
                )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                info_controller = InfoController()
                for info_param in dignostic_info_params:
                    logger.info(
                        f"Capturing output of command 'info {info_param}' and writing to {file}"
                    )
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename, info_controller, info_param.split()
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                show_controller = ShowController()
                for show_param in dignostic_show_params:
                    logger.info(
                        f"Capturing output of command 'show {show_param}' for {file}"
                    )
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename, show_controller, show_param.split()
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                features_controller = FeaturesController()
                for cmd in dignostic_features_params:
                    logger.info(
                        f"Capturing output of command '{cmd}' and writing to {file}"
                    )
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename, features_controller, cmd.split()
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                for cmd in dignostic_aerospike_info_commands:
                    logger.info(
                        f"Capturing output of asinfo command '{cmd}' and writing to {file}"
                    )
                    result = await self.cluster.info(cmd)
                    self._write_func_output_to_file(
                        complete_filename, self.cluster.info, [cmd], result
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))
        except Exception as e:
            util.write_to_file(complete_filename, str(e))
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.debug(traceback.format_exc())
            raise

        logger.info(f"Finished capturing pretty print output for {file}.")

    async def _dump_collectinfo_summary(self, as_logfile_prefix: str, fileHeader: str):
        complete_filename = as_logfile_prefix + "summary.log"

        try:
            util.write_to_file(complete_filename, fileHeader)

            summary_params = ["summary"]
            summary_info_params = ["network", "namespace", "set", "xdr", "dc", "sindex"]

            try:
                await self._collectinfo_capture_and_write_to_file(
                    complete_filename, self._write_version
                )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            if self.collectinfo_root_controller is None:
                logger.critical("Collectinfo root controller is not initialized.")
                return

            try:
                for summary_param in summary_params:
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename,
                        self.collectinfo_root_controller.execute,
                        summary_param.split(),
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

            try:
                info_controller = InfoController()
                for info_param in summary_info_params:
                    await self._collectinfo_capture_and_write_to_file(
                        complete_filename, info_controller, info_param.split()
                    )
            except Exception as e:
                util.write_to_file(complete_filename, str(e))

        except Exception as e:
            util.write_to_file(complete_filename, str(e))
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.debug(traceback.format_exc())
            raise

    async def _dump_collectinfo_health(self, as_logfile_prefix: str, fileHeader: str):
        if self.collectinfo_root_controller is None:
            logger.critical("Collectinfo root controller is not initialized.")
            return

        complete_filename = as_logfile_prefix + "health.log"

        health_params = ["health -v"]

        try:
            util.write_to_file(complete_filename, fileHeader)

            for health_param in health_params:
                await self._collectinfo_capture_and_write_to_file(
                    complete_filename,
                    self.collectinfo_root_controller.execute,
                    health_param.split(),
                )
        except Exception as e:
            util.write_to_file(complete_filename, str(e))
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.debug(traceback.format_exc())
            raise

    async def _dump_collectinfo_sysinfo(self, as_logfile_prefix: str, fileHeader: str):
        complete_filename = as_logfile_prefix + "sysinfo.log"

        # getting service port to use in ss/netstat command
        port = 3000
        try:
            _, port, _ = self.cluster.get_seed_nodes()[0]
        except Exception:
            port = 3000

        try:
            self.failed_cmds = common.collect_sys_info(
                port=port, file_header=fileHeader, outfile=complete_filename
            )
        except Exception as e:
            util.write_to_file(complete_filename, str(e))
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.debug(traceback.format_exc())
            raise

    async def _dump_collectinfo_aerospike_conf(
        self, as_logfile_prefix: str, conf_path: str | None = None
    ):
        """
        Gets the static aerospike.conf if available.
        """
        complete_filename = as_logfile_prefix + "aerospike.conf"

        if not conf_path:
            conf_path = "/etc/aerospike/aerospike.conf"

        try:
            self._collect_local_file(conf_path, complete_filename)
        except Exception as e:
            logger.debug(traceback.format_exc())
            logger.warning("Failed to generate %s file.", complete_filename)
            logger.warning(str(e))
            util.write_to_file(complete_filename, str(e))

    async def _gather_logs(
        self,
        logfile_prefix: str,
        enable_ssh: bool,
        default_user: str | None,
        default_pwd_key: str | None,
        default_ssh_port: int | None,
        default_ssh_key: str | None,
    ):
        logger.info("Collecting logs from nodes...")
        ssh_config = None

        if enable_ssh:
            ssh_config = ssh.SSHConnectionConfig(
                username=default_user,
                port=default_ssh_port,
                private_key=default_ssh_key,
                private_key_pwd=default_pwd_key,
            )

        def local_path_generator(node: Node, filename: str) -> str:
            if filename == "stderr":
                filename = "stderr.log"

            return logfile_prefix + node.node_id + "_" + path.basename(filename)

        # Stores errors that occur after the connection is established
        download_errors = []
        connect_errors = []

        def error_handler(error: Exception, node: Node):
            if isinstance(error, ssh.SSHConnectionError):
                connect_errors.append(error)
            else:
                download_errors.append(error)

        """
        Returned errors are for connection issues. error_handler handles errors after
        authentication.
        """
        await LogFileDownloader(
            self.cluster, enable_ssh, ssh_config, exception_handler=error_handler
        ).download(local_path_generator)

        if not connect_errors and not download_errors:
            logger.info("Successfully downloaded logs from all nodes.")
        elif len(connect_errors) == self.cluster.get_nodes():
            logger.error("Failed to download logs from all nodes.")
            raise Exception("Failed to download logs from all nodes.")
        elif connect_errors or download_errors:
            logger.error("Failed to download logs from some nodes.")

    def setup_loggers(self, individual_file_prefix: str):
        debug_file = individual_file_prefix + "collectinfo_debug.log"
        self.debug_output_handler = logging.FileHandler(debug_file)
        self.debug_output_handler.setLevel(logging.DEBUG)
        self.debug_output_handler.setFormatter(LogFormatter())
        self.loggers: list[logging.Logger | logging.Handler] = [
            g_logger,
            stderr_log_handler,
            logging.getLogger(Node.__name__),
            logging.getLogger(common.__name__),
            logging.getLogger(LogFileDownloader.__module__),
        ]
        self.old_levels = [logger.level for logger in self.loggers]

        g_logger.setLevel(logging.DEBUG)

        for logger in self.loggers[1:]:
            # Only set the level to INFO if it is not already set to DEBUG or INFO.
            if logger.level > logging.INFO:
                logger.setLevel(logging.INFO)

        g_logger.addHandler(self.debug_output_handler)

    def teardown_loggers(self):
        g_logger.removeHandler(self.debug_output_handler)
        for logger, level in zip(self.loggers, self.old_levels):
            logger.setLevel(level)

        # TODO: clean up log levels

    ###########################################################################
    # Collectinfo caller functions

    async def _run_collectinfo(
        self,
        default_user: str | None,
        default_pwd_key: str | None,
        default_ssh_port: int | None,
        default_ssh_key: str | None,
        snp_count: int,
        wait_time: int,
        ignore_errors: bool,
        include_logs: bool = False,
        agent_host: str | None = None,
        agent_port: str | None = None,
        agent_store: bool = False,
        enable_ssh: bool = False,
        output_prefix: str = "",
        config_path: str = "",
    ):
        # JSON collectinfo snapshot count check
        if snp_count < 1:
            logger.error("Wrong collectinfo snapshot count")
            return

        timestamp = time.gmtime()
        cf_path_info = common.get_collectinfo_path(
            timestamp,
            output_prefix=output_prefix,
        )
        individual_file_prefix = path.join(
            cf_path_info.cf_dir,
            cf_path_info.files_prefix,
        )
        ignore_errors_msg = "Aborting collectinfo. To bypass use --ignore-errors."

        try:
            # Coloring might writes extra characters to file, to avoid it we need to disable terminal coloring
            self.setup_loggers(individual_file_prefix)
            terminal.enable_color(False)

            try:
                if agent_host is not None and agent_port is not None:
                    await self._dump_collectinfo_license_data(
                        individual_file_prefix,
                        agent_host,
                        agent_port,
                        agent_store,
                    )

            except Exception as e:
                logger.error(e)
                if not ignore_errors:
                    logger.error(ignore_errors_msg)
                    return

            file_header = time.strftime("%Y-%m-%d %H:%M:%S UTC\n", timestamp)
            self.failed_cmds = []

            try:
                tasks = [
                    self._dump_collectinfo_json(
                        individual_file_prefix,
                        default_user,
                        default_pwd_key,
                        default_ssh_port,
                        default_ssh_key,
                        enable_ssh,
                        snp_count,
                        wait_time,
                    )
                ]

                if include_logs:
                    logfile_prefix = path.join(
                        cf_path_info.log_dir,
                        cf_path_info.files_prefix,
                    )
                    tasks.append(
                        self._gather_logs(
                            logfile_prefix,
                            enable_ssh,
                            default_user,
                            default_pwd_key,
                            default_ssh_port,
                            default_ssh_key,
                        )
                    )
                    cf_json, logs = await asyncio.gather(*tasks, return_exceptions=True)
                else:
                    logs = None
                    cf_json = await asyncio.gather(*tasks, return_exceptions=True)

                if any(isinstance(resp, Exception) for resp in [cf_json, logs]):
                    raise
            except Exception as e:
                logger.error(e)
                if not ignore_errors:
                    logger.error(ignore_errors_msg)
                    return

            # Must happen after json dump and before summary and health. The json data is used
            # to generate the summary and health output.
            self.collectinfo_root_controller = CollectinfoRootController(
                asadm_version=self.asadm_version,
                clinfo_path=cf_path_info.cf_dir,
            )

            coroutines = [
                self._dump_collectinfo_ascollectinfo(
                    individual_file_prefix, file_header
                ),
                self._dump_collectinfo_summary(individual_file_prefix, file_header),
                self._dump_collectinfo_health(individual_file_prefix, file_header),
            ]

            if self.cluster.is_localhost_a_node():
                coroutines.append(
                    self._dump_collectinfo_sysinfo(individual_file_prefix, file_header)
                )
                coroutines.append(
                    self._dump_collectinfo_aerospike_conf(
                        individual_file_prefix, config_path
                    )
                )
            else:
                logger.info(
                    "SSH is enabled. Skipping sysinfo.log and aerospike.conf collection."
                )

            for c in coroutines:
                try:
                    await c
                except:
                    # close remaining coroutines.  An error will be raised if they are not
                    # awaited.
                    for c in coroutines:
                        c.close()

                    if not ignore_errors:
                        logger.error(ignore_errors_msg)
                        return

            common.print_collectinfo_failed_cmds(self.failed_cmds)

            # Archive collectinfo directory
            cf_archive_path, _ = common.archive_log(cf_path_info.cf_dir)
            log_archive_path = None
            log_archive_success = True

            if include_logs:
                log_archive_path, log_archive_success = common.archive_log(
                    cf_path_info.log_dir
                )

            common.print_collectinfo_summary(
                cf_archive_path,
                log_archive=log_archive_path,
                log_archive_success=log_archive_success,
            )
        finally:
            # printing collectinfo summary
            self.teardown_loggers()
            terminal.enable_color(True)

    async def _do_default(self, line):
        snp_count = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-n",
            return_type=int,
            default=1,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        wait_time = util.get_arg_and_delete_from_mods(
            line=line,
            arg="-t",
            return_type=int,
            default=5,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        agent_host = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--agent-host",
            default=None,
            return_type=str,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        agent_port = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--agent-port",
            default="8080",
            return_type=str,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        agent_store = util.check_arg_and_delete_from_mods(
            line=line,
            arg="--agent-store",
            default=False,
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

        default_pwd_key = util.get_arg_and_delete_from_mods(
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

        include_logs = util.check_arg_and_delete_from_mods(
            line=line,
            arg="--include-logs",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        output_prefix = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--output-prefix",
            return_type=str,
            default="",
            modifiers=self.modifiers,
            mods=self.mods,
        )
        output_prefix = util.strip_string(output_prefix)

        config_path = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--asconfig-file",
            return_type=str,
            default="",
            modifiers=self.modifiers,
            mods=self.mods,
        )
        config_path = util.strip_string(config_path)

        ignore_errors = util.check_arg_and_delete_from_mods(
            line=line,
            arg="--ignore-errors",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        if line:
            logger.error("Unrecognized option(s): {}".format(", ".join(line)))

        await self._run_collectinfo(
            default_user,
            default_pwd_key,
            default_ssh_port,
            default_ssh_key,
            snp_count,
            wait_time,
            ignore_errors,
            include_logs=include_logs,
            agent_host=agent_host,
            agent_port=agent_port,
            agent_store=agent_store,
            enable_ssh=enable_ssh,
            output_prefix=output_prefix,
            config_path=config_path,
        )
