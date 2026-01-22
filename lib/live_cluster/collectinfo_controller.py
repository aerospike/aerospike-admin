# Copyright 2023-2025 Aerospike, Inc.
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
from typing import Any, Callable
from lib.live_cluster.client.node import Node
from lib.live_cluster.logfile_downloader import LogFileDownloader
from lib.live_cluster import ssh
from lib.utils.types import NodeDict

from lib.view.sheet.render import get_style_json, set_style_json
from lib.view.terminal import terminal
from lib.utils import common, constants, util, version
from lib.live_cluster.constants import SSH_MODIFIER_HELP, SSH_MODIFIER_USAGE
from lib.utils.logger import LogFormatter, stderr_log_handler, logger as g_logger
from lib.base_controller import CommandHelp, ModifierHelp, ShellException
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
    GetUserAgentsController,
    GetMaskingRulesController,
)

from .live_cluster_command_controller import LiveClusterCommandController
from .features_controller import FeaturesController
from .info_controller import InfoController
from .show_controller import ShowController

logger = logging.getLogger(__name__)


@CommandHelp(
    "Collects cluster info, aerospike conf file for local node and system stats from all nodes if remote server credentials provided. If credentials are not available then it will collect system stats from local node only.",
    usage=f"[-n <num-snapshots>] [-s <sleep>] [{SSH_MODIFIER_USAGE}] [--output-prefix <prefix>] [--asconfig-file <path>]",
    modifiers=(
        ModifierHelp("-n", "Number of snapshots.", default="1"),
        ModifierHelp(
            "-s", "Sleep time in seconds between each snapshot.", default="5 sec"
        ),
        *SSH_MODIFIER_HELP,
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
            feature_keys,
            release_info,
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
            self.cluster.info_feature_key(nodes=self.nodes),
            self.cluster.info_release(nodes=self.nodes),
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
            self._check_for_exception_and_set(
                feature_keys, "feature-key", nodeid, metamap
            )
            self._check_for_exception_and_set(release_info, "release", nodeid, metamap)
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

    async def _get_as_user_agents(self) -> NodeDict[list[dict[str, str]]]:
        """Collect user agents data from all nodes"""
        user_agents_getter = GetUserAgentsController(self.cluster)
        user_agents_data = await user_agents_getter.get_user_agents(nodes=self.nodes)
        user_agents_map = {}

        for node in user_agents_data:
            if node not in user_agents_map:
                user_agents_map[node] = []

            if not user_agents_data[node] or isinstance(
                user_agents_data[node], Exception
            ):
                continue

            user_agents_map[node] = user_agents_data[node]

        return user_agents_map

    async def _get_as_masking_rules(self) -> NodeDict[list[dict[str, str]]]:
        """Collect masking rules data from principal node"""
        masking_getter = GetMaskingRulesController(self.cluster)
        masking_data = await masking_getter.get_masking_rules(nodes="principal")
        masking_map = {}

        for node in masking_data:
            if not masking_data[node] or isinstance(masking_data[node], Exception):
                continue

            masking_map[node] = masking_data[node]

        return masking_map

    async def _get_collectinfo_data_json(
        self,
        enable_ssh: bool,
        ssh_user: str | None = None,
        ssh_pwd: str | None = None,
        ssh_key: str | None = None,
        ssh_key_pwd: str | None = None,
        ssh_port: int | None = None,
    ):
        logger.debug("Collectinfo data to store in collectinfo_*.json")

        dump_map = {}

        # Split operations into batches to reduce socket contention and timeouts
        # Batch 1: Core data collection (most resource intensive)
        (
            cluster_name,
            as_map,
            meta_map,
            sys_map,
        ) = await asyncio.gather(
            self._get_as_cluster_name(),
            self._get_as_data_json(),
            self._get_as_metadata(),
            self.cluster.info_system_statistics(
                enable_ssh=enable_ssh,
                ssh_user=ssh_user,
                ssh_pwd=ssh_pwd,
                ssh_key=ssh_key,
                ssh_key_pwd=ssh_key_pwd,
                ssh_port=ssh_port,
                nodes=self.nodes,
            ),
        )

        # Batch 2: Histograms and latency data
        (
            histogram_map,
            latency_map,
        ) = await asyncio.gather(
            self._get_as_histograms(),
            self._get_as_latency(),
        )

        # Batch 3: Security and auxiliary data (lighter operations)
        (
            acl_map,
            user_agents_map,
            masking_map,
        ) = await asyncio.gather(
            self._get_as_access_control_list(),
            self._get_as_user_agents(),
            self._get_as_masking_rules(),
        )

        for val in sys_map.values():
            # TODO: remove this when we no longer return all exceptions by default
            if isinstance(val, Exception):
                raise val

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

            if node in user_agents_map:
                dump_map[node]["as_stat"]["user_agents"] = user_agents_map[node]

            if node in masking_map:
                dump_map[node]["as_stat"]["masking"] = masking_map[node]

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
        enable_ssh,
        ssh_user,
        ssh_pwd,
        ssh_key,
        ssh_key_pwd,
        ssh_port,
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
                enable_ssh,
                ssh_user,
                ssh_pwd,
                ssh_key,
                ssh_key_pwd,
                ssh_port,
            )

            logger.info("Data collection for Snapshot " + str(i + 1) + " finished.")

            await asyncio.sleep(wait_time)

        self._dump_in_json_file(as_logfile_prefix + "ascinfo.json", snpshots)

    def _dump_collectinfo_file(self, filename: str, dump: str):
        logger.info("Dumping collectinfo %s.", filename)

        try:
            util.write_to_file(filename, dump)
        except Exception as e:
            logger.warning("Failed to write file {}: {}", filename, str(e))
            raise

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
                "release",
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
                "connection",
                "service-clear-std",
                "service-clear-alt",
                "service-tls-std",
                "service-tls-alt",
                "peers-clear-std",
                "peers-clear-alt",
                "peers-tls-std",
                "peers-tls-alt",
                "alumni-clear-std",
                "alumni-tls-std",
                "alumni-clear-alt",
                "alumni-tls-alt",
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

    def setup_loggers(self, individual_file_prefix: str):
        debug_file = individual_file_prefix + "collectinfo_debug.log"
        self.debug_output_handler = logging.FileHandler(debug_file)
        self.debug_output_handler.setLevel(logging.DEBUG)
        self.debug_output_handler.setFormatter(LogFormatter())
        self.loggers: list[logging.Logger | logging.Handler] = [
            g_logger,
            stderr_log_handler,
            logging.getLogger(Node.__module__),
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
        ssh_user: str | None,
        ssh_pwd: str | None,
        ssh_port: int | None,
        ssh_key: str | None,
        ssh_key_pwd: str | None,
        snp_count: int,
        wait_time: int,
        ignore_errors: bool,
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

            file_header = time.strftime("%Y-%m-%d %H:%M:%S UTC\n", timestamp)
            self.failed_cmds = []

            try:
                await self._dump_collectinfo_json(
                    individual_file_prefix,
                    enable_ssh,
                    ssh_user,
                    ssh_pwd,
                    ssh_key,
                    ssh_key_pwd,
                    ssh_port,
                    snp_count,
                    wait_time,
                )
            except (ssh.SSHError, FileNotFoundError) as e:
                logger.error(ShellException(e))
                logger.error(
                    "Failed to login to node using ssh. Stopping creation of the collectinfo."
                )
                return
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
                    "Localhost is not an Aerospike node. Skipping sysinfo.log and aerospike.conf collection."
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
            cf_archive_path, success = common.archive_dir(cf_path_info.cf_dir)

            if success:
                common.print_collect_summary(
                    cf_archive_path,
                )
            else:
                logger.error(
                    "Failed to archive collectinfo logs. See earlier errors for more details."
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
            arg="--ssh-key-pwd",
            return_type=str,
            default=None,
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
            ssh_user,
            ssh_pwd,
            ssh_port,
            ssh_key,
            ssh_key_pwd,
            snp_count,
            wait_time,
            ignore_errors,
            enable_ssh=enable_ssh,
            output_prefix=output_prefix,
            config_path=config_path,
        )
