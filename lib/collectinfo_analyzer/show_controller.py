from lib.utils import common, constants, util
from lib.base_controller import CommandHelp, CommandName

from .collectinfo_command_controller import CollectinfoCommandController


@CommandHelp('"show" is used to display Aerospike Statistics and', "configuration.")
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
            "sindex": ShowSIndexController,
            "config": ShowConfigController,
            "latencies": ShowLatenciesController,
            "statistics": ShowStatisticsController,
        }
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp('"show config" is used to display Aerospike configuration settings')
class ShowConfigController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "diff", "for"])

    @CommandHelp(
        "Displays service, network, and namespace configuration",
        "  Options:",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   default: False, no repetition.",
        "    -flip        - Flip output table to show Nodes on Y axis and config on X axis.",
    )
    def _do_default(self, line):
        self.do_service(line[:])
        self.do_network(line[:])
        self.do_namespace(line[:])

    @CommandHelp("Displays service configuration")
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
                **self.mods
            )

    @CommandHelp("Displays network configuration")
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
                **self.mods
            )

    @CommandHelp("Displays namespace configuration")
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
                    **self.mods
                )

    @CommandHelp("Displays XDR configuration")
    def do_xdr(self, line):

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
        )

        xdr_configs = self.log_handler.info_getconfig(stanza=constants.CONFIG_XDR)
        old_xdr_configs = {}
        xdr5_configs = {}
        node_xdr_build_major_version = 5

        for timestamp in sorted(xdr_configs.keys()):
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()

            for xdr_node in xdr_configs[timestamp]:
                try:
                    node_xdr_build_major_version = int(builds[xdr_node][0])
                except Exception:
                    continue

                if node_xdr_build_major_version < 5:
                    old_xdr_configs[xdr_node] = xdr_configs[timestamp][xdr_node]
                else:
                    xdr5_configs[xdr_node] = xdr_configs[timestamp][xdr_node]

            if xdr5_configs:
                formatted_configs = common.format_xdr5_configs(
                    xdr5_configs, self.mods.get("for", [])
                )

                if formatted_configs:
                    self.view.show_xdr5_config(
                        "XDR Configuration",
                        formatted_configs,
                        cinfo_log,
                        title_every_nth=title_every_nth,
                        flip_output=flip_output,
                        timestamp=timestamp,
                        **self.mods
                    )
                else:
                    # ASADM versions < 1.0.2 could cause this error if ran on
                    # aerospike server >= 5.0.
                    #
                    self.logger.warning(
                        "Unable to parse XDR configuration info.  Collectinfo file may have been generated \n"
                        "         with an old version of ASADM on Aerospike server >= 5.0."
                    )

            if old_xdr_configs:
                self.view.show_config(
                    "XDR Configuration",
                    old_xdr_configs,
                    cinfo_log,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods
                )

    # pre 5.0
    @CommandHelp(
        "Displays datacenter configuration",
        'Replaced by "show config xdr" for server >= 5.0.',
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
        )

        dc_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_DC, flip=True
        )
        node_xdr_build_major_version = 5

        for timestamp in sorted(dc_configs.keys()):
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()
            nodes_running_v5_or_higher = False
            nodes_running_v49_or_lower = False

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
                for dc, configs in dc_configs[timestamp].items():
                    self.view.show_config(
                        "%s DC Configuration" % (dc),
                        configs,
                        self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                        title_every_nth=title_every_nth,
                        flip_output=flip_output,
                        timestamp=timestamp,
                        **self.mods
                    )

            if nodes_running_v5_or_higher:
                self.view.print_result(
                    "WARNING: Detected nodes running "
                    + "aerospike version >= 5.0. Please use 'asadm -cf "
                    + '/path/to/collect_info_file -e "show config xdr"\''
                    + " for versions 5.0 and up."
                )


@CommandHelp(
    "Displays distribution of object sizes",
    "and time to live for node and a namespace.",
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

    @CommandHelp("Shows the distribution of TTLs for namespaces")
    def do_time_to_live(self, line):
        return self._do_distribution("ttl", "TTL Distribution", "Seconds")

    @CommandHelp(
        "Shows the distribution of Object sizes for namespaces",
        "  Options:",
        "    -b   - Displays byte wise distribution of Object Sizes if it is collected in collectinfo.",
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
        "Shows the distribution of namespace Eviction TTLs for server version 3.7.5 and below"
    )
    def do_eviction(self, line):
        return self._do_distribution("evict", "Eviction Distribution", "Seconds")


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

            hist_latency = {}
            for node_id, node_data in _latency.items():
                if not node_data or isinstance(node_data, Exception):
                    continue
                for hist_name, hist_data in node_data.items():
                    if hist_name not in hist_latency:
                        hist_latency[hist_name] = {}

                    hist_latency[hist_name][node_id] = hist_data

            self.view.show_latency(
                hist_latency,
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                show_ns_details=True if namespace_set else False,
                timestamp=timestamp,
                **self.mods
            )


@CommandHelp("Displays statistics for Aerospike components.")
class ShowStatisticsController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "for"])

    @CommandHelp(
        "Displays bin, set, service, and namespace statistics",
        "  Options:",
        "    -t           - Set to show total column at the end. It contains node wise sum for statistics.",
        "    -r           - Repeat output table title and row header after every <terminal width> columns.",
        "                   default: False, no repetition.",
        "    -flip        - Flip output table to show Nodes on Y axis and stats on X axis.",
    )
    def _do_default(self, line):
        self.do_bins(line[:])
        self.do_sets(line[:])
        self.do_service(line[:])
        self.do_namespace(line[:])

    @CommandHelp("Displays service statistics")
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
                **self.mods
            )

    @CommandHelp("Displays namespace statistics")
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
                    **self.mods
                )

    @CommandHelp("Displays set statistics")
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
        )

        set_stats = self.log_handler.info_statistics(
            stanza=constants.STAT_SETS, flip=True
        )

        for timestamp in sorted(set_stats.keys()):
            if not set_stats[timestamp]:
                continue
            namespace_set = {
                ns_set.split()[0] for ns_set in set_stats[timestamp].keys()
            }

            try:
                namespace_set = set(
                    util.filter_list(namespace_set, self.mods["for"][:1])
                )
            except Exception:
                pass

            sets = {ns_set.split()[1] for ns_set in set_stats[timestamp].keys()}
            try:
                sets = set(util.filter_list(sets, self.mods["for"][1:2]))
            except Exception:
                pass

            for ns_set, stats in set_stats[timestamp].items():
                ns, set_ = ns_set.split()
                if ns not in namespace_set or set_ not in sets:
                    continue

                self.view.show_stats(
                    "%s Set Statistics" % (ns_set),
                    stats,
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods
                )

    @CommandHelp("Displays bin statistics")
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
                    **self.mods
                )

    @CommandHelp("Displays XDR statistics")
    def do_xdr(self, line):

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
        )

        xdr_stats = self.log_handler.info_statistics(stanza=constants.STAT_XDR)
        old_xdr_stats = {}
        xdr5_stats = {}
        node_xdr_build_major_version = 5

        for timestamp in sorted(xdr_stats.keys()):

            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()

            for xdr_node in xdr_stats[timestamp]:
                try:
                    node_xdr_build_major_version = int(builds[xdr_node][0])
                except Exception:
                    continue

                if node_xdr_build_major_version < 5:
                    old_xdr_stats[xdr_node] = xdr_stats[timestamp][xdr_node]
                else:
                    xdr5_stats[xdr_node] = xdr_stats[timestamp][xdr_node]

            if xdr5_stats:
                temp = {}
                for node in xdr5_stats:
                    for dc in xdr5_stats[node]:
                        if dc not in temp:
                            temp[dc] = {}
                        temp[dc][node] = xdr5_stats[node][dc]

                xdr5_stats = temp
                matches = set([])

                if self.mods["for"]:
                    matches = set(util.filter_list(xdr5_stats.keys(), self.mods["for"]))

                for dc in xdr5_stats:
                    if not self.mods["for"] or dc in matches:
                        self.view.show_config(
                            "XDR Statistics %s" % dc,
                            xdr5_stats[dc],
                            self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                            show_total=show_total,
                            title_every_nth=title_every_nth,
                            flip_output=flip_output,
                            timestamp=timestamp,
                            **self.mods
                        )

            if old_xdr_stats:
                self.view.show_config(
                    "XDR Statistics",
                    old_xdr_stats,
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods
                )

    # pre 5.0
    @CommandHelp(
        "Displays datacenter statistics",
        'Replaced by "show statistics xdr" for server >= 5.0.',
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
        )

        dc_stats = self.log_handler.info_statistics(stanza=constants.STAT_DC, flip=True)
        node_xdr_build_major_version = 5
        for timestamp in sorted(dc_stats.keys()):
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()
            nodes_running_v5_or_higher = False
            nodes_running_v49_or_lower = False

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
                for dc, stats in dc_stats[timestamp].items():
                    self.view.show_stats(
                        "%s DC Statistics" % (dc),
                        stats,
                        self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                        show_total=show_total,
                        title_every_nth=title_every_nth,
                        flip_output=flip_output,
                        timestamp=timestamp,
                        **self.mods
                    )

            if nodes_running_v5_or_higher:
                self.view.print_result(
                    "WARNING: 'show statistics dc' is deprecated on "
                    + "aerospike versions >= 5.0 \n"
                    + "Please use 'show statistics xdr' instead"
                )

    @CommandHelp("Displays sindex statistics")
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
                    "%s Sindex Statistics" % (sindex),
                    stats,
                    self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                    show_total=show_total,
                    title_every_nth=title_every_nth,
                    flip_output=flip_output,
                    timestamp=timestamp,
                    **self.mods
                )


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


@CommandHelp("Displays users and their assigned roles for Aerospike cluster.")
class ShowUsersController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like"])

    def _do_default(self, line):
        users_data = self.log_handler.admin_acl(stanza=constants.ADMIN_USERS)

        for timestamp in sorted(users_data.keys()):
            if not users_data[timestamp]:
                continue

            data = list(users_data[timestamp].values())[0]
            self.view.show_users(data, timestamp=timestamp, **self.mods)


@CommandHelp(
    "Displays roles and their assigned privileges and allowlist for Aerospike cluster."
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


@CommandHelp("Displays UDF modules along with metadata.")
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
            principal_ip = node_id_to_ip[principal_id]
            data = udf_data[timestamp][principal_ip]
            self.view.show_udfs(data, timestamp=timestamp, **self.mods)


@CommandHelp("Displays secondary indexes and static metadata.")
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
            principal_ip = node_id_to_ip[principal_id]
            data_to_process = sindexes_data[timestamp][principal_ip]

            # Re-format data since key = "<ns> <set> <sindex>" and it should be
            # a list of dictionaries where each dict hold meta for a singel sindex.
            formatted_data = list(data_to_process.values())
            self.view.show_sindex(formatted_data, timestamp=timestamp, **self.mods)


@CommandHelp("Displays roster information a node its namespaces.")
class ShowRosterController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "diff"])

    def _do_default(self, line):
        flip_output = util.check_arg_and_delete_from_mods(
            line=line,
            arg="-flip",
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
                **self.mods
            )


@CommandHelp('Displays any of Aerospike\'s violated "best-practices".')
class ShowBestPracticesController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["with"])

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
    "Displays jobs and associated metadata.",
)
class ShowJobsController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like", "trid"])

    @CommandHelp(
        "Displays scans, queries, and sindex-builder jobs.",
    )
    def _do_default(self, line):
        self.do_scans(line[:])
        self.do_queries(line[:]),
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
        "Displays scan jobs.",
        "Usage: scans [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    def do_scans(self, line):
        self._job_helper(constants.JobType.SCAN, "Scan Jobs")

    @CommandHelp(
        "Displays query jobs.",
        "Usage: queries [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    def do_queries(self, line):
        self._job_helper(constants.JobType.QUERY, "Query Jobs")

    # TODO: Should be removed eventually. "sindex-builder" was removed in server 5.7.
    # So should probably be removed when server 7.0 is supported.
    @CommandHelp(
        "Displays sindex-builder jobs. Removed in server v. 5.7 and later.",
        "Usage: sindex-builder [trid <trid1> [<trid2>]]",
        "  trid          - List of transaction ids to filter for.",
    )
    @CommandName("sindex-builder")
    def do_sindex_builder(self, line):
        self._job_helper(constants.JobType.SINDEX_BUILDER, "SIndex Builder Jobs")


@CommandHelp('Displays rack information for a rack-aware cluster".')
class ShowRacksController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["with"])

    def _do_default(self, line):
        racks_data = self.log_handler.info_getconfig(stanza=constants.CONFIG_RACKS)

        for timestamp, data in racks_data.items():
            node_id_to_ip = self.log_handler.get_node_id_to_ip_mapping(timestamp)
            principal_id = self.log_handler.get_principal(timestamp)
            principal_ip = node_id_to_ip[principal_id]
            data = {principal_ip: data[principal_ip]}

            self.view.show_racks(data, timestamp=timestamp, **self.mods)
