from lib.base_controller import CommandHelp
from lib.utils import constants, util

from .collectinfo_command_controller import CollectinfoCommandController


@CommandHelp(
    'The "info" command provides summary tables for various aspects',
    "of Aerospike functionality.",
)
class InfoController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["for"])

        self.controller_map = dict(namespace=InfoNamespaceController)

    @CommandHelp("Displays network, namespace, and xdr summary information.")
    def _do_default(self, line):
        self.do_network(line)
        self.controller_map["namespace"]()(line[:])
        self.do_xdr(line)

    @CommandHelp("Displays network summary information.")
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
                **self.mods
            )

    def _convert_key_to_tuple(self, stats):
        for key in list(stats.keys()):
            key_tuple = tuple(key.split())
            stats[key_tuple] = stats[key]
            del stats[key]

    @CommandHelp("Displays set summary information.")
    def do_set(self, line):
        set_stats = self.log_handler.info_statistics(
            stanza=constants.STAT_SETS, flip=True
        )

        for timestamp in sorted(set_stats.keys()):
            if not set_stats[timestamp]:
                continue

            self._convert_key_to_tuple(set_stats[timestamp])
            self.view.info_set(
                util.flip_keys(set_stats[timestamp]),
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods
            )

    @CommandHelp("Displays Cross Datacenter Replication (XDR) summary information.")
    def do_xdr(self, line):
        xdr_stats = self.log_handler.info_statistics(stanza=constants.STAT_XDR)
        node_xdr_build_major_version = 5
        for timestamp in sorted(xdr_stats.keys()):
            if not xdr_stats[timestamp]:
                continue

            xdr_enable = {}
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=timestamp)
            builds = cinfo_log.get_asd_build()
            old_xdr_stats = {}
            xdr5_stats = {}

            for xdr_node in xdr_stats[timestamp].keys():
                xdr_enable[xdr_node] = True
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
                    matches = set(
                        util.filter_list(list(xdr5_stats.keys()), self.mods["for"])
                    )

                for dc in xdr5_stats:
                    if not self.mods["for"] or dc in matches:
                        self.view.info_XDR(
                            xdr5_stats[dc],
                            xdr_enable,
                            cluster=cinfo_log,
                            timestamp=timestamp,
                            title="XDR Information %s" % dc,
                            **self.mods
                        )

            if old_xdr_stats:
                self.view.info_old_XDR(
                    old_xdr_stats,
                    builds,
                    xdr_enable,
                    cluster=cinfo_log,
                    timestamp=timestamp,
                    **self.mods
                )

    # pre 5.0
    @CommandHelp(
        "Displays datacenter summary information.",
        'Replaced by "info xdr" for server >= 5.0.',
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
                    **self.mods
                )

            if nodes_running_v5_or_higher:
                self.view.print_result(
                    "WARNING: 'info dc' is deprecated "
                    + "on aerospike versions >= 5.0.\n"
                    + "Use 'info xdr' instead."
                )

    @CommandHelp("Displays secondary index (SIndex) summary information).")
    def do_sindex(self, line):
        sindex_stats = self.log_handler.info_statistics(
            stanza=constants.STAT_SINDEX, flip=True
        )
        for timestamp in sorted(sindex_stats.keys()):
            if not sindex_stats[timestamp]:
                continue

            self.view.info_sindex(
                sindex_stats[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods
            )


@CommandHelp(
    'The "namespace" command provides summary tables for various aspects',
    "of Aerospike namespaces.",
)
class InfoNamespaceController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set()

    @CommandHelp("Displays usage and objects information for namespaces")
    def _do_default(self, line):
        self.do_usage(line)
        self.do_object(line)

    @CommandHelp("Displays usage information for each namespace.")
    def do_usage(self, line):
        ns_stats = self.log_handler.info_statistics(stanza=constants.STAT_NAMESPACE)

        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                continue

            self.view.info_namespace_usage(
                ns_stats[timestamp],
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods
            )

    @CommandHelp("Displays object information for each namespace.")
    def do_object(self, line):
        # In SC mode effective rack-id is different from that in namespace config.
        ns_stats = self.log_handler.info_statistics(stanza=constants.STAT_NAMESPACE)
        rack_ids = self.log_handler.info_getconfig(stanza=constants.CONFIG_RACK_IDS)

        for timestamp in sorted(ns_stats.keys()):
            if not ns_stats[timestamp]:
                continue

            self.view.info_namespace_object(
                ns_stats[timestamp],
                rack_ids.get(timestamp, {}),
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods
            )
