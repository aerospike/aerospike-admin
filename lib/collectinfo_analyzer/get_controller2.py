import asyncio
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)
from lib.utils import constants, util


class GetConfigController:
    """
    Here to mimic the behavior of the GetConfigController used in live cluster mode. It
    abstracts out using the log_analyzer and filtering via the for_mods. Same as in
    live cluster mode. One day maybe we could unify the two modes and abstract away the
    live vs replayed cluster.

    This is currently only being used for XDR configs with the hopes that it will be used in
    the future for all others.
    """

    def __init__(self, log_analyzer: CollectinfoLogHandler):
        self.log_analyzer = log_analyzer

    # TODO might be a good place to add support for the with modifier and filter nodes
    def get_all(self):
        futures = [
            (constants.CONFIG_XDR, self.get_xdr()),
            (constants.CONFIG_DC, self.get_xdr_dcs()),
            (
                constants.CONFIG_XDR_NS,
                self.get_xdr_namespaces(),
            ),
        ]
        config_map = dict([(k, f) for k, f in futures])

        return config_map

    def get_xdr(self):
        return self.log_analyzer.info_getconfig(stanza=constants.CONFIG_XDR)

    def get_xdr_dcs(self, flip=False, for_mods: list[str] | None = None):
        configs = self.log_analyzer.info_getconfig(stanza=constants.CONFIG_DC)

        for nodes_confgs in configs.values():
            for dc_configs in nodes_confgs.values():
                dcs = dc_configs.keys()
                filtered_dcs = set(util.filter_list(dcs, for_mods))

                for dc in list(dc_configs.keys()):
                    if dc not in filtered_dcs:
                        del dc_configs[dc]

        if flip:
            configs = util.flip_keys(configs)

        return configs

    def get_xdr_namespaces(self, for_mods=None):
        dcs_filter: list[str] | None = None
        namespaces_filter: list[str] | None = None

        if for_mods is not None:
            try:
                namespaces_filter = [for_mods[0]]
                dcs_filter = [for_mods[1]]
            except IndexError:
                pass

        configs = self.log_analyzer.info_getconfig(stanza=constants.CONFIG_XDR_NS)

        for nodes_configs in configs.values():
            for dc_configs in nodes_configs.values():
                dcs = dc_configs.keys()
                filtered_dcs = set(util.filter_list(dcs, dcs_filter))

                for dc, ns_configs in list(dc_configs.items()):
                    if dc not in filtered_dcs:
                        del dc_configs[dc]

                    namespaces = ns_configs.keys()
                    filtered_namespaces = set(
                        util.filter_list(namespaces, namespaces_filter)
                    )

                    for ns, ns_config in list(ns_configs.items()):
                        if ns not in filtered_namespaces:
                            del ns_configs[ns]

        return configs


class GetStatisticsController:
    """
    Here to mimic the behavior of the GetStatisticsController used in live cluster mode. It
    abstracts out using the log_analyzer and filtering via the for_mods. Same as in
    live cluster mode.

    This is currently only being used for XDR stats with the hopes that it will be used in
    the future for all others.
    """

    def __init__(self, log_analyzer: CollectinfoLogHandler):
        self.log_analyzer = log_analyzer

    # TODO might be a good place to add support for the with modifier to filter nodes
    def get_all(self):
        futures = [
            (constants.STAT_XDR, self.get_xdr()),
            (constants.STAT_DC, self.get_xdr_dcs()),
            (
                constants.STAT_XDR_NS,
                self.get_xdr_namespaces(),
            ),
        ]
        stat_map = dict([(k, f) for k, f in futures])

        return stat_map

    def get_xdr(self):
        return self.log_analyzer.info_statistics(stanza=constants.STAT_XDR)

    def get_xdr_dcs(self, flip=False, for_mods: list[str] | None = None):
        stats = self.log_analyzer.info_statistics(stanza=constants.STAT_DC)

        for nodes_stats in stats.values():
            for dc_stats in nodes_stats.values():
                dcs = dc_stats.keys()
                filtered_dcs = set(util.filter_list(dcs, for_mods))

                for dc in list(dc_stats.keys()):
                    if dc not in filtered_dcs:
                        del dc_stats[dc]

        if flip:
            stats = util.flip_keys(stats)

        return stats

    def get_xdr_namespaces(self, for_mods=None):
        dcs_filter: list[str] | None = None
        namespaces_filter: list[str] | None = None

        if for_mods is not None:
            try:
                dcs_filter = [for_mods[0]]
                namespaces_filter = [for_mods[1]]
            except IndexError:
                pass

        stats = self.log_analyzer.info_statistics(stanza=constants.STAT_XDR_NS)

        for nodes_stats in stats.values():
            for dc_stats in nodes_stats.values():
                dcs = dc_stats.keys()
                filtered_dcs = set(util.filter_list(dcs, for_mods))

                for dc, ns_stats in list(dc_stats.items()):
                    if dc not in filtered_dcs:
                        del dc_stats[dc]

                    namespaces = ns_stats.keys()
                    filtered_namespaces = set(
                        util.filter_list(namespaces, namespaces_filter)
                    )

                    for ns in list(ns_stats.keys()):
                        if ns not in filtered_namespaces:
                            del ns_stats[ns]

        return stats
