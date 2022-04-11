import asyncio
import copy
import json
import logging
import pprint
import shutil
import time
from os import sys
import traceback

from lib.view.sheet.render import get_style_json, set_style_json
from lib.view.terminal import terminal
from lib.utils import common, constants, util, version, logger
from lib.base_controller import CommandHelp
from lib.collectinfo_analyzer.collectinfo_root_controller import (
    CollectinfoRootController,
)
from lib.get_controller import (
    GetStatisticsController,
    GetConfigController,
    GetUsersController,
    GetRolesController,
    GetLatenciesController,
    GetPmapController,
    GetJobsController,
)

from .live_cluster_command_controller import LiveClusterCommandController
from .features_controller import FeaturesController
from .info_controller import InfoController
from .show_controller import ShowController


@CommandHelp(
    '"collectinfo" is used to collect cluster info, aerospike conf file and system stats.'
)
class CollectinfoController(LiveClusterCommandController):
    get_pmap = False

    def __init__(self):
        self.modifiers = set(["with"])
        self.aslogfile = ""
        self.aslogdir = ""

    def _collect_local_file(self, src, dest_dir):
        self.logger.info("Copying file %s to %s" % (src, dest_dir))
        try:
            shutil.copy2(src, dest_dir)
        except Exception as e:
            raise e

    async def _collectinfo_content(self, func, parm="", alt_parms=""):
        name = ""
        capture_stdout = util.capture_stdout
        sep = constants.COLLECTINFO_SEPERATOR

        old_style_json = get_style_json()
        set_style_json()

        try:
            name = func.__name__
        except Exception:
            pass

        info_line = constants.COLLECTINFO_PROGRESS_MSG % (
            name,
            "%s" % (" %s" % (str(parm)) if parm else ""),
        )
        self.logger.info(info_line)
        if parm:
            sep += str(parm) + "\n"

        if func == "cluster":
            o = await self.cluster.info(parm)
        else:
            if self.nodes and isinstance(self.nodes, list):
                parm += ["with"] + self.nodes
            o = await capture_stdout(func, parm)
        util.write_to_file(self.aslogfile, sep + str(o))

        set_style_json(old_style_json)

        return ""

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
            if "set" not in node_data.keys():
                continue

            for key, val in node_data["set"].items():
                ns_name = key[0]
                setname = key[1]

                if ns_name not in node_data["namespace"]:
                    continue

                ns = node_data["namespace"][ns_name]

                if "set" not in ns.keys():
                    ns["set"] = {}

                ns["set"][setname] = copy.deepcopy(val)

            del node_data["set"]

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
        # No config for set, sindex, bin
        self._restructure_ns_section(new_config)

        # check this 'XDR': {'STATISTICS': {'192.168.112.194:3000':
        # Type_error('expected str
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
            self.cluster.info("build", nodes=self.nodes),
            self.cluster.info("version", nodes=self.nodes),
            self.cluster.info_node(nodes=self.nodes),
            self.cluster.info_ip_port(nodes=self.nodes),
            self.cluster.info_service_list(nodes=self.nodes),
            self.cluster.info_peers_flat_list(nodes=self.nodes),
            self.cluster.info_udf_list(nodes=self.nodes),
            self.cluster.info_health_outliers(nodes=self.nodes),
            self.cluster.info_best_practices(nodes=self.nodes),
            GetJobsController(self.cluster).get_all(flip=True, nodes=self.nodes),
        )

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

    async def _get_as_access_control_list(self):
        acl_map = {}
        users_getter = GetUsersController(self.cluster)
        roles_getter = GetRolesController(self.cluster)
        users_map, roles_map = await asyncio.gather(
            users_getter.get_users(nodes="principal"),
            roles_getter.get_roles(nodes="principal"),
        )

        for node in users_map:
            acl_map[node] = {}
            self._check_for_exception_and_set(users_map, "users", node, acl_map)
            self._check_for_exception_and_set(roles_map, "roles", node, acl_map)

        return acl_map

    def _dump_in_json_file(self, as_logfile_prefix, filename, dump, ignore_errors):
        self.logger.info("Dumping collectinfo {}.", filename)
        self.aslogfile = as_logfile_prefix + filename

        try:
            json_dump = json.dumps(dump, indent=2, separators=(",", ":"))
            with open(self.aslogfile, "w") as f:
                f.write(json_dump)
        except Exception as e:
            self.logger.warning("Failed to write JSON file: " + str(e))
            pretty_json = pprint.pformat(dump, indent=1)
            self.logger.debug(pretty_json)
            raise

    async def _get_collectinfo_data_json(
        self,
        default_user,
        default_pwd,
        default_ssh_port,
        default_ssh_key,
        credential_file,
        enable_ssh,
    ):
        self.logger.debug("Collectinfo data to store in collectinfo_*.json")

        dump_map = {}

        (
            as_map,
            meta_map,
            histogram_map,
            latency_map,
            acl_map,
            sys_map,
        ) = await asyncio.gather(
            self._get_as_data_json(),
            self._get_as_metadata(),
            self._get_as_histograms(),
            self._get_as_latency(),
            self._get_as_access_control_list(),
            self.cluster.info_system_statistics(
                default_user=default_user,
                default_pwd=default_pwd,
                default_ssh_key=default_ssh_key,
                default_ssh_port=default_ssh_port,
                credential_file=credential_file,
                nodes=self.nodes,
                collect_remote_data=enable_ssh,
            ),
        )

        cluster_names = asyncio.create_task(self.cluster.info("cluster-name"))

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

            if CollectinfoController.get_pmap and node in pmap_map:
                dump_map[node]["as_stat"]["pmap"] = pmap_map[node]

            # ACL requests only go to principal therefor we are storing it only
            # for the principal
            if node in acl_map:
                dump_map[node]["as_stat"]["acl"] = acl_map[node]

        # Get the cluster name and add one more level in map
        cluster_name = "null"
        cluster_names = await cluster_names

        # Cluster name.
        for node in cluster_names:
            if not isinstance(cluster_names[node], Exception) and cluster_names[
                node
            ] not in ["null"]:
                cluster_name = cluster_names[node]
                break

        snp_map = {}
        snp_map[cluster_name] = dump_map
        return snp_map

    async def _dump_collectinfo_json(
        self,
        timestamp,
        as_logfile_prefix,
        default_user,
        default_pwd,
        default_ssh_port,
        default_ssh_key,
        credential_file,
        enable_ssh,
        snp_count,
        wait_time,
        ignore_errors,
    ):
        snpshots = {}

        for i in range(snp_count):

            snp_timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            self.logger.info(
                "Data collection for Snapshot: " + str(i + 1) + " in progress..."
            )

            snpshots[snp_timestamp] = await self._get_collectinfo_data_json(
                default_user,
                default_pwd,
                default_ssh_port,
                default_ssh_key,
                credential_file,
                enable_ssh,
            )

            time.sleep(wait_time)

        self._dump_in_json_file(
            as_logfile_prefix, "ascinfo.json", snpshots, ignore_errors
        )

    async def _dump_collectinfo_license_json(
        self, as_logfile_prefix, agent_host, agent_port, ignore_errors
    ):
        self.logger.info("Data collection license usage in progress...")
        self.logger.info("Requesting data usage for past 365 days...")
        self.aslogfile = as_logfile_prefix + "aslicenseusage.json"

        resp, error = await common.request_license_usage(agent_host, agent_port)

        if error is not None:
            self.logger.error(
                "Failed to retrieve license usage information : {}",
                str(error),
            )
            return False

        self._dump_in_json_file(
            as_logfile_prefix, "aslicenseusage.json", resp, ignore_errors
        )
        return True

    ###########################################################################
    # Functions for dumping pretty print files

    async def _dump_collectinfo_pretty_print(
        self, timestamp, as_logfile_prefix, config_path=""
    ):
        ####### Dignostic info ########
        self.aslogfile = as_logfile_prefix + "ascollectinfo.log"

        # getting service port to use in ss/netstat command
        port = 3000
        try:
            _, port, _ = self.cluster.get_seed_nodes()[0]
        except Exception:
            port = 3000

        collect_output = time.strftime("%Y-%m-%d %H:%M:%S UTC\n", timestamp)

        dignostic_info_params = ["network", "namespace", "set", "xdr", "dc", "sindex"]

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

        summary_params = ["summary"]
        summary_info_params = ["network", "namespace", "set", "xdr", "dc", "sindex"]
        health_params = ["health -v"]

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

        util.write_to_file(self.aslogfile, collect_output)

        # All these calls to collectinfo_content must happen synchronously because they
        # capture std output.
        try:
            await self._collectinfo_content(self._write_version)
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            info_controller = InfoController()
            for info_param in dignostic_info_params:
                await self._collectinfo_content(info_controller, [info_param])
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            show_controller = ShowController()
            for show_param in dignostic_show_params:
                await self._collectinfo_content(show_controller, show_param.split())
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            features_controller = FeaturesController()
            for cmd in dignostic_features_params:
                await self._collectinfo_content(features_controller, [cmd])
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            for cmd in dignostic_aerospike_info_commands:
                await self._collectinfo_content("cluster", cmd)
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        ####### Summary ########

        collectinfo_root_controller = CollectinfoRootController(
            asadm_version=self.asadm_version, clinfo_path=self.aslogdir
        )

        self.aslogfile = as_logfile_prefix + "summary.log"
        util.write_to_file(self.aslogfile, collect_output)

        try:
            await self._collectinfo_content(self._write_version)
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            for summary_param in summary_params:
                await self._collectinfo_content(
                    collectinfo_root_controller.execute, [summary_param]
                )
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        try:
            info_controller = InfoController()
            for info_param in summary_info_params:
                await self._collectinfo_content(info_controller, [info_param])
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        ####### Health ########

        self.aslogfile = as_logfile_prefix + "health.log"
        util.write_to_file(self.aslogfile, collect_output)

        try:
            for health_param in health_params:
                await self._collectinfo_content(
                    collectinfo_root_controller.execute, health_param.split()
                )
        except Exception as e:
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

        ####### System info ########

        self.aslogfile = as_logfile_prefix + "sysinfo.log"
        self.failed_cmds = common.collect_sys_info(
            port=port, timestamp=collect_output, outfile=self.aslogfile
        )

        ##### aerospike conf file #####

        conf_path = config_path
        self.aslogfile = as_logfile_prefix + "aerospike.conf"

        if not conf_path:
            conf_path = "/etc/aerospike/aerospike.conf"

            # Comparing with this version because prior to this it was
            # citrusleaf.conf
            try:
                if version.LooseVersion(as_version) <= version.LooseVersion("3.0.0"):
                    conf_path = "/etc/citrusleaf/citrusleaf.conf"
                    self.aslogfile = as_logfile_prefix + "citrusleaf.conf"
            except Exception:  # probably failed to get build version, node may be down
                pass

        try:
            self._collect_local_file(conf_path, self.aslogfile)
        except Exception as e:
            self.logger.warning(str(e))
            util.write_to_file(self.aslogfile, str(e))
            sys.stdout = sys.__stdout__

    ###########################################################################
    # Collectinfo caller functions

    async def _run_collectinfo(
        self,
        default_user,
        default_pwd,
        default_ssh_port,
        default_ssh_key,
        credential_file,
        snp_count,
        wait_time,
        ignore_errors,
        agent_host=None,
        agent_port=None,
        enable_ssh=False,
        output_prefix="",
        config_path="",
    ):

        # JSON collectinfo snapshot count check
        if snp_count < 1:
            self.logger.error("Wrong collectinfo snapshot count")
            return

        timestamp = time.gmtime()
        self.aslogdir, as_logfile_prefix = common.set_collectinfo_path(
            timestamp, output_prefix=output_prefix
        )

        debug_file = as_logfile_prefix + "collectinfo_debug.log"
        debug_output_handler = logging.FileHandler(debug_file)
        debug_output_handler.setLevel(logging.DEBUG)
        debug_output_handler.setFormatter(logger.LogFormatter())
        self.logger.addHandler(debug_output_handler)

        # Coloring might writes extra characters to file, to avoid it we need to disable terminal coloring
        terminal.enable_color(False)

        # list of failed system commands
        self.failed_cmds = []

        try:
            # JSON collectinfo
            await self._dump_collectinfo_json(
                timestamp,
                as_logfile_prefix,
                default_user,
                default_pwd,
                default_ssh_port,
                default_ssh_key,
                credential_file,
                enable_ssh,
                snp_count,
                wait_time,
                ignore_errors,
            )
        except Exception:
            exc = traceback.format_exc()
            self.logger.debug(exc)

            if not ignore_errors:
                self.logger.error(
                    "Aborting collectinfo. To bypass use --ignore-errors."
                )
                return

        try:
            if agent_host is not None:
                if not await self._dump_collectinfo_license_json(
                    as_logfile_prefix, agent_host, agent_port, ignore_errors
                ):
                    return
        except Exception:
            exc = traceback.format_exc()
            self.logger.debug(exc)

            if not ignore_errors:
                self.logger.error(
                    "Aborting collectinfo. To bypass use --ignore-errors."
                )
                return

        try:
            # Pretty print collectinfo
            await self._dump_collectinfo_pretty_print(
                timestamp, as_logfile_prefix, config_path=config_path
            )
        except Exception:
            exc = traceback.format_exc()
            self.logger.warning("Failed to generate {} file.", self.aslogfile)
            self.logger.debug(exc)

            if not ignore_errors:
                self.logger.error(
                    "Aborting collectinfo. To bypass use --ignore-errors."
                )
                return

        self.logger.removeHandler(debug_output_handler)

        # Archive collectinfo directory
        common.archive_log(self.aslogdir)

        # printing collectinfo summary
        common.print_collectinfo_summary(self.aslogdir, failed_cmds=self.failed_cmds)
        terminal.enable_color(True)

    @CommandHelp(
        "Collects cluster info, aerospike conf file for local node and system stats from all nodes if",
        "remote server credentials provided. If credentials are not available then it will collect system",
        "stats from local node only.",
        "  Options:",
        "    -n              <int>        - Number of snapshots. Default: 1",
        "    -s              <int>        - Sleep time in seconds between each snapshot. Default: 5 sec",
        "    --enable-ssh                 - Enables the collection of system statistics from the remote server.",
        "    --ssh-user      <string>     - Default user ID for remote servers. This is the ID of a user of the",
        "                                   system not the ID of an Aerospike user.",
        "    --ssh-pwd       <string>     - Default password or passphrase for key for remote servers. This is",
        "                                   the user's password for logging into the system, not a password for",
        "                                   logging into Aerospike.",
        "    --ssh-port      <int>        - Default SSH port for remote servers. Default: 22",
        "    --ssh-key       <string>     - Default SSH key (file path) for remote servers.",
        "    --ssh-cf        <string>     - Remote System Credentials file path.",
        "                                   If the server credentials are not in the credentials file, then",
        "                                   authentication is attempted with the default credentials.",
        "                                   File format : each line must contain <IP[:PORT]>,<USER_ID>",
        "                                   <PASSWORD or PASSPHRASE>,<SSH_KEY>",
        "                                   Example:  1.2.3.4,uid,pwd",
        "                                             1.2.3.4:3232,uid,pwd",
        "                                             1.2.3.4:3232,uid,,key_path",
        "                                             1.2.3.4:3232,uid,passphrase,key_path",
        "                                             [2001::1234:10],uid,pwd",
        "                                             [2001::1234:10]:3232,uid,,key_path",
        "    --agent-host    <host>       - Host IP of the Unique-Data-Agent to collect license data usage.",
        "    --agent-port    <int>        - Port of the Unique-Data-Agent. Default: 8080",
        "    --output-prefix <string>     - Output directory name prefix.",
        "    --asconfig-file <string>     - Aerospike config file path to collect.",
        "                                   Default: /etc/aerospike/aerospike.conf",
    )
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
            self.logger.error("Unrecognized option(s): {}".format(", ".join(line)))

        await self._run_collectinfo(
            default_user,
            default_pwd,
            default_ssh_port,
            default_ssh_key,
            credential_file,
            snp_count,
            wait_time,
            ignore_errors,
            agent_host=agent_host,
            agent_port=agent_port,
            enable_ssh=enable_ssh,
            output_prefix=output_prefix,
            config_path=config_path,
        )
