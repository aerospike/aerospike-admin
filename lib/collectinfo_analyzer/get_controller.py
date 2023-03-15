import asyncio
from typing import TypeVar
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)
from lib.utils import constants, util
from lib.utils.common import DatacenterDict, NamespaceDict, NodeDict

T = TypeVar("T")
TimestampDict = dict[str, T]


class GetConfigController:
    """
    Here to mimic the behavior of the GetConfigController used in live cluster mode. It
    abstracts out using the log_analyzer and filtering via the for_mods. Same as in
    live cluster mode. One day maybe we could unify the two modes and abstract away the
    live vs replayed cluster.

    This is currently only being used for XDR configs with the hopes that it will be used in
    the future for all others.
    """

    # TODO might be a good place to add support for the with modifier and filter nodes
    def __init__(self, log_analyzer: CollectinfoLogHandler):
        self.log_handler = log_analyzer

    def get_namespace(self):
        return self.log_handler.info_getconfig(stanza=constants.CONFIG_NAMESPACE)

    def get_rack_ids(self):
        return self.log_handler.info_getconfig(stanza=constants.CONFIG_RACK_IDS)

    def get_xdr(self):
        return self.log_handler.info_getconfig(stanza=constants.CONFIG_XDR)

    def get_xdr_dcs(self, flip=False, for_mods: list[str] | None = None):
        configs: TimestampDict[
            NodeDict[DatacenterDict[dict[str, str]]]
        ] = self.log_handler.info_getconfig(stanza=constants.CONFIG_DC)

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

    def _filter_ts_host_dc_ns_dict(
        self,
        d: TimestampDict[NodeDict[DatacenterDict[NamespaceDict[dict[str, str]]]]],
        dcs_filter: list[str] | None = None,
        namespaces_filter: list[str] | None = None,
        principal=False,
    ) -> TimestampDict[NodeDict[DatacenterDict[NamespaceDict[dict[str, str]]]]]:
        """
        Removes dcs and namespaces not found in dcs_filter and namespaces_filter. Edits
        d in place and returns d.
        """
        if not dcs_filter and not namespaces_filter and not principal:
            return d

        for ts, nodes_vals in d.items():
            principal_ip = None

            if principal:
                node_id_to_ip = self.log_handler.get_node_id_to_ip_mapping(ts)
                principal_id = self.log_handler.get_principal(ts)
                principal_ip = node_id_to_ip[principal_id]

            for node_ip, dc_vals in list(nodes_vals.items()):
                if principal_ip and principal_ip != node_ip:
                    del nodes_vals[node_ip]
                    continue

                dcs = dc_vals.keys()
                filtered_dcs = set(util.filter_list(dcs, dcs_filter))

                for dc, ns_vals in list(dc_vals.items()):
                    if dc not in filtered_dcs:
                        del dc_vals[dc]
                        continue

                    namespaces = ns_vals.keys()
                    filtered_namespaces = set(
                        util.filter_list(namespaces, namespaces_filter)
                    )

                    for ns in list(ns_vals.keys()):
                        if ns not in filtered_namespaces:
                            del ns_vals[ns]

        return d

    def get_xdr_namespaces(self, for_mods: list[str] | None = None):
        dcs_filter: list[str] | None = None
        namespaces_filter: list[str] | None = None

        if for_mods is not None:
            try:
                namespaces_filter = [for_mods[0]]
                dcs_filter = [for_mods[1]]
            except IndexError:
                pass

        configs: TimestampDict[
            NodeDict[DatacenterDict[NamespaceDict[dict[str, str]]]]
        ] = self.log_handler.info_getconfig(stanza=constants.CONFIG_XDR_NS)

        configs = self._filter_ts_host_dc_ns_dict(
            configs, dcs_filter, namespaces_filter
        )

        return configs

    def get_xdr_filters(self, for_mods: list[str] | None = None):
        dcs_filter: list[str] | None = None
        namespaces_filter: list[str] | None = None

        if for_mods is not None:
            try:
                dcs_filter = [for_mods[0]]
                namespaces_filter = [for_mods[1]]
            except IndexError:
                pass

        filters: TimestampDict[
            NodeDict[DatacenterDict[NamespaceDict[dict[str, str]]]]
        ] = self.log_handler.info_getconfig(stanza=constants.CONFIG_XDR_FILTER)

        filters = self._filter_ts_host_dc_ns_dict(
            filters, dcs_filter, namespaces_filter, principal=True
        )

        return filters


class GetStatisticsController:
    """
    Here to mimic the behavior of the GetStatisticsController used in live cluster mode. It
    abstracts out using the log_analyzer and filtering via the for_mods. Same as in
    live cluster mode.

    This is currently only being used for XDR stats with the hopes that it will be used in
    the future for all others.
    """

    def __init__(self, log_analyzer: CollectinfoLogHandler):
        self.log_handler = log_analyzer

    def get_namespace(self):
        return self.log_handler.info_statistics(stanza=constants.STAT_NAMESPACE)

    def get_sindex(self):
        return self.log_handler.info_statistics(stanza=constants.STAT_SINDEX)

    # TODO might be a good place to add support for the with modifier to filter nodes

    def get_xdr(
        self,
    ) -> TimestampDict[dict[str, str]]:
        return self.log_handler.info_statistics(stanza=constants.STAT_XDR)

    def get_xdr_dcs(self, flip=False, for_mods: list[str] | None = None):
        stats: TimestampDict[
            NodeDict[DatacenterDict[dict[str, str]]]
        ] = self.log_handler.info_statistics(stanza=constants.STAT_DC)

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
                namespaces_filter = [for_mods[0]]
                dcs_filter = [for_mods[1]]
            except IndexError:
                pass

        stats: TimestampDict[
            NodeDict[DatacenterDict[NamespaceDict[dict[str, str]]]]
        ] = self.log_handler.info_statistics(stanza=constants.STAT_XDR_NS)

        for nodes_stats in stats.values():
            for dc_stats in nodes_stats.values():
                dcs = dc_stats.keys()
                filtered_dcs = set(util.filter_list(dcs, dcs_filter))

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
