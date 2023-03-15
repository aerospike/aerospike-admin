# Copyright 2013-2021 Aerospike, Inc.
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

import datetime
import locale
import logging
from os import path
import sys
import time
from io import StringIO
from pydoc import pipepager
from typing import Any, Tuple

from lib.health import constants as health_constants
from lib.health.util import print_dict
from lib.live_cluster.client import Cluster
from lib.live_cluster.client.node import ASInfoError
from lib.utils import file_size, constants, util
from lib.utils.common import (
    SummaryClusterDict,
    SummaryDict,
    SummaryNamespacesDict,
)
from lib.view import sheet, terminal, templates
from lib.view.sheet import SheetStyle
from lib.view.table import Orientation, Table, TitleFormats

H1_offset = 13
H2_offset = 15
H_width = 80


# Helper that adds a '_' to the end of reserved words that are also modifiers.
# This code improves readability.
def reserved_modifiers(func):
    def wrapper(*args, **kwargs):
        if "with" in kwargs:
            kwargs["with_"] = kwargs["with"]

        if "for" in kwargs:
            kwargs["for_"] = kwargs["for"]

        func(*args, **kwargs)

    return wrapper


class CliView(object):
    NO_PAGER, LESS, MORE, SCROLL = range(4)
    pager = NO_PAGER
    logger = logging.getLogger("asadm")

    @staticmethod
    def print_result(out):
        if out is None or out == "":
            return

        if type(out) is not str:
            out = str(out)
        if CliView.pager == CliView.LESS:
            if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
                # We are running in a bundled app
                less_cmd = path.join(sys._MEIPASS, "less") + " -RSX"  # type: ignore MEIPASS is set by pyinstaller.
            else:
                less_cmd = "less -RSX"

            pipepager(out, less_cmd)
        elif CliView.pager == CliView.SCROLL:
            for i in out.split("\n"):
                print(i)
                time.sleep(0.05)
        else:
            print(out)

    @staticmethod
    def print_pager():
        if CliView.pager == CliView.LESS:
            print("LESS")
        elif CliView.pager == CliView.MORE:
            print("MORE")
        elif CliView.pager == CliView.SCROLL:
            print("SCROLL")
        else:
            print("NO PAGER")

    @staticmethod
    def _get_timestamp_suffix(timestamp):
        if not timestamp:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())

        return " (" + str(timestamp) + ")"

    @staticmethod
    @reserved_modifiers
    def info_network(
        stats,
        cluster_names,
        versions,
        builds,
        cluster: Cluster,
        timestamp="",
        with_=None,
        **ignore
    ):
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        hosts = cluster.nodes
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Network Information" + title_suffix
        sources = dict(
            cluster_names=cluster_names,
            node_names=node_names,
            node_ids=node_ids,
            hosts=dict(((k, h.sock_name(use_fqdn=False)) for k, h in hosts.items())),
            builds=builds,
            versions=versions,
            stats=stats,
        )

        common_size = None
        common_key = None
        common_principal = None

        cluster_sizes = util.get_value_from_second_level_of_dict(
            stats, "cluster_size"
        ).values()
        cluster_keys = util.get_value_from_second_level_of_dict(
            stats, "cluster_key"
        ).values()
        cluster_principals = util.get_value_from_second_level_of_dict(
            stats, "paxos_principal"
        ).values()

        common_size = util.find_most_frequent(cluster_sizes)
        common_key = util.find_most_frequent(cluster_keys)
        common_principal = util.find_most_frequent(cluster_principals)

        common = dict(
            principal=cluster.get_expected_principal(),
            common_size=common_size,
            common_key=common_key,
            common_principal=common_principal,
        )

        CliView.print_result(
            sheet.render(templates.info_network_sheet, title, sources, common=common)
        )

    @staticmethod
    @reserved_modifiers
    def info_namespace_usage(stats, cluster, timestamp="", with_=None, **ignore):
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Namespace Usage Information" + title_suffix
        sources = dict(
            node_ids=node_ids,
            node_names=node_names,
            ns_stats=stats,
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(
                templates.info_namespace_usage_sheet, title, sources, common=common
            )
        )

    @staticmethod
    @reserved_modifiers
    def info_namespace_object(
        stats, rack_ids, cluster, timestamp="", with_=None, **ignore
    ):
        if not stats:
            return

        # ns_stats contains rack-id in config file which is different than effective rack-id.
        # This overwrites rack-id with effective rack-id if avail.
        if rack_ids:
            for host, ns_stats in stats.items():
                for ns, ns_stat in ns_stats.items():
                    if host in rack_ids and ns in rack_ids[host]:
                        if "rack-id" in ns_stat:
                            ns_stat["rack-id"] = rack_ids[host][ns]

        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Namespace Object Information" + title_suffix
        sources = dict(
            node_ids=node_ids,
            node_names=node_names,
            ns_stats=stats,
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(
                templates.info_namespace_object_sheet, title, sources, common=common
            )
        )

    @staticmethod
    @reserved_modifiers
    def info_set(stats, cluster, timestamp="", with_=None, **ignore):
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Set Information%s" % title_suffix
        sources = dict(
            node_ids=node_ids,
            node_names=node_names,
            set_stats=stats,
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.info_set_sheet, title, sources, common=common)
        )

    # pre 5.0
    @staticmethod
    @reserved_modifiers
    def info_dc(stats, cluster, timestamp="", with_=None, **ignore):
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "DC Information%s" % (title_suffix)
        sources = dict(
            node_ids=node_ids,
            node_names=node_names,
            dc_stats=stats,
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.info_dc_sheet, title, sources, common=common)
        )

    # pre 5.0
    @staticmethod
    @reserved_modifiers
    def info_old_XDR(
        stats, builds, xdr_enable, cluster, timestamp="", with_=None, **ignore
    ):
        if not max(xdr_enable.values()):
            return

        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "XDR Information" + title_suffix
        sources = dict(
            xdr_enable=xdr_enable,
            node_ids=node_ids,
            node_names=node_names,
            builds=builds,
            xdr_stats=stats,
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.info_old_xdr_sheet, title, sources, common=common)
        )

    @staticmethod
    def info_XDR(stats, xdr_enable, cluster, timestamp="", **ignore):
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        node_names = cluster.get_node_names()
        node_ids = cluster.get_node_ids()
        common = dict(principal=cluster.get_expected_principal())
        stats = util.flip_keys(stats)
        dcs = list(stats.keys())
        dcs.sort()

        for dc in dcs:
            title = "XDR Information {}".format(dc) + title_suffix
            sources = dict(
                xdr_enable=xdr_enable,
                node_ids=node_ids,
                node_names=node_names,
                xdr_stats=stats[dc],
            )

            CliView.print_result(
                sheet.render(templates.info_xdr_sheet, title, sources, common=common)
            )

    @staticmethod
    @reserved_modifiers
    def info_sindex(
        sindex_stats, ns_configs, cluster, timestamp="", with_=None, **ignore
    ):
        # return if sindex stats are empty.
        if not sindex_stats:
            return

        # Insert sindex-type from ns_confgs into sindex_stats. Sheets can't handle
        # two objects with differing schemas.
        for node, node_stats in sindex_stats.items():
            for key in node_stats:
                ns = key.split()[0]

                sindex_type = (
                    ns_configs.get(node, {}).get(ns).get("sindex-type", "shmem")
                )

                sindex_stats[node][key]["sindex-type"] = sindex_type

        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Secondary Index Information" + title_suffix
        sources = dict(
            node_ids=node_ids,
            node_names=node_names,
            sindex_stats=sindex_stats,
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.info_sindex_sheet, title, sources, common=common)
        )

    @staticmethod
    @reserved_modifiers
    def show_distribution(
        title,
        histogram,
        unit,
        hist,
        cluster,
        like=None,
        with_=None,
        timestamp="",
        **ignore
    ):
        likes = util.compile_likes(like)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        description = "Percentage of records having {} less than or ".format(
            hist
        ) + "equal to value measured in {}".format(unit)
        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.items():
            if (
                namespace not in namespaces
                or not node_data
                or isinstance(node_data, Exception)
            ):
                continue

            this_title = "{} - {} in {}{}".format(namespace, title, unit, title_suffix)
            sources = dict(
                node_names=cluster.get_node_names(with_),
                histogram=dict((k, d["percentiles"]) for k, d in node_data.items()),
            )

            CliView.print_result(
                sheet.render(
                    templates.show_distribution_sheet,
                    this_title,
                    sources,
                    description=description,
                )
            )

    @staticmethod
    @reserved_modifiers
    def show_object_distribution(
        title,
        histogram,
        unit,
        hist,
        bucket_count,
        set_bucket_count,
        cluster,
        like=None,
        with_=None,
        timestamp="",
        loganalyser_mode=False,
        **ignore
    ):
        node_names = cluster.get_node_names(with_)
        likes = util.compile_likes(like)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        description = "Number of records having {} in the range ".format(
            hist
        ) + "measured in {}".format(unit)
        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.items():
            if namespace not in namespaces:
                continue

            ns_title = "{} - {} in {}{}".format(namespace, title, unit, title_suffix)
            sources = dict(
                node_names=node_names,
                histogram={
                    h: d.get("data", {}) for h, d in node_data.items() if h != "columns"
                },
            )

            CliView.print_result(
                sheet.render(
                    templates.show_object_distribution_sheet,
                    ns_title,
                    sources,
                    description=description,
                )
            )

    @staticmethod
    def format_latency(orig_latency):
        # XXX - eventually, node.py could return this format. Changing here
        #       because loganalyser also sends this format.
        latency = {}

        for hist, nodes_data in orig_latency.items():
            for node, node_data in nodes_data.items():
                node_latency = latency[node] = latency.get(node, {})

                if "namespace" in node_data:
                    for ns, ns_data in node_data["namespace"].items():
                        for slice_id, values in enumerate(ns_data["values"]):
                            node_latency[(ns, hist, slice_id)] = dict(
                                zip(ns_data["columns"], values)
                            )
                elif "total" in node_data:
                    # batch-index is not under 'namespace'
                    hist_data = node_data["total"]
                    for slice_id, values in enumerate(hist_data["values"]):
                        node_latency[
                            (templates.show_latency_sheet.no_entry, hist, slice_id)
                        ] = dict(zip(hist_data["columns"], values))

        return latency

    @staticmethod
    @reserved_modifiers
    def show_latency(latency, cluster, like=None, with_=None, timestamp="", **ignore):
        # TODO - May not need to converter now that dicts can be nested.
        likes = util.compile_likes(like)
        title = "Latency " + CliView._get_timestamp_suffix(timestamp)
        latency = util.flip_keys(latency)  # make histogram name top level key
        keys = set(filter(likes.search, latency.keys()))
        latency = {k: v for k, v in latency.items() if k in keys}
        latency = CliView.format_latency(latency)
        node_names = cluster.get_node_names(
            with_
        )  # TODO: Find out why table shows ~ instead of -- when latency metrics are missing for a given node.

        sources = dict(node_names=node_names, histogram=latency)

        CliView.print_result(sheet.render(templates.show_latency_sheet, title, sources))

    @staticmethod
    @reserved_modifiers
    def show_config(
        title,
        service_configs,
        cluster,
        like=None,
        diff=False,
        with_=None,
        show_total=False,
        title_every_nth=0,
        flip_output=False,
        timestamp="",
        **ignore
    ):
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = title + title_suffix
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        sources = dict(node_names=node_names, data=service_configs, node_ids=node_ids)
        disable_aggregations = not show_total
        style = SheetStyle.columns if flip_output else None
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(
                templates.show_config_sheet,
                title,
                sources,
                style=style,
                selectors=like,
                title_repeat=title_every_nth != 0,
                disable_aggregations=disable_aggregations,
                dynamic_diff=diff,
                common=common,
            )
        )

    @staticmethod
    def show_stats(*args, **kwargs):
        CliView.show_config(*args, **kwargs)

    @staticmethod
    def show_health(*args, **kwargs):
        CliView.show_config(*args, **kwargs)

    @staticmethod
    @reserved_modifiers
    def show_xdr_ns_config(
        ns_configs,
        cluster: Cluster,
        like=None,
        diff=False,
        with_=None,
        title_every_nth=0,
        flip_output=False,
        timestamp="",
        **ignore
    ):
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        common = dict(principal=cluster.get_expected_principal())
        style = SheetStyle.columns if flip_output else None

        # dict format starts at {node: {dc: {ns:{}}}}
        for node, dc_ns_configs in ns_configs.items():
            ns_configs[node] = util.flip_keys(dc_ns_configs)

        ns_configs = util.flip_keys(ns_configs)
        # dict format ends at {ns: {node: {dc:{}}}}

        sorted_keys = list(ns_configs.keys())
        sorted_keys.sort()

        for ns in sorted_keys:
            title = "XDR {} Namespace Configuration{}".format(ns, title_suffix)
            sources = dict(
                node_names=node_names,
                node_ids=node_ids,
                data=ns_configs[ns],
            )

            CliView.print_result(
                sheet.render(
                    templates.show_xdr_ns_sheet,
                    title,
                    sources,
                    selectors=like,
                    style=style,
                    title_repeat=title_every_nth != 0,
                    dynamic_diff=diff,
                    disable_aggregations=True,
                    common=common,
                )
            )

    @staticmethod
    @reserved_modifiers
    def show_xdr_ns_stats(
        ns_configs,
        cluster: Cluster,
        like=None,
        with_=None,
        title_every_nth=0,
        flip_output=False,
        show_total=False,
        by_dc=False,
        timestamp="",
        **ignore
    ):
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        common = dict(principal=cluster.get_expected_principal())
        style = SheetStyle.columns if flip_output else None

        # dict format starts at {node: {dc: {ns:{}}}}
        if not by_dc:
            for node, dc_ns_configs in ns_configs.items():
                ns_configs[node] = util.flip_keys(dc_ns_configs)

        ns_configs = util.flip_keys(ns_configs)
        # dict format ends at {ns: {node: {dc:{}}}} or {dc: {node: {ns:{}}}} if by_dc

        sorted_keys = list(ns_configs.keys())
        sorted_keys.sort()

        for key in sorted_keys:
            sources = dict(
                node_names=node_names,
                node_ids=node_ids,
                data=ns_configs[key],
            )

            if by_dc:
                title = "XDR {} DC Namespace Statistics{}".format(key, title_suffix)
                CliView.print_result(
                    sheet.render(
                        templates.show_xdr_ns_sheet_by_dc,
                        title,
                        sources,
                        selectors=like,
                        style=style,
                        title_repeat=title_every_nth != 0,
                        disable_aggregations=not show_total,
                        common=common,
                    )
                )
            else:
                title = "XDR {} Namespace Statistics{}".format(key, title_suffix)
                CliView.print_result(
                    sheet.render(
                        templates.show_xdr_ns_sheet,
                        title,
                        sources,
                        selectors=like,
                        style=style,
                        title_repeat=title_every_nth != 0,
                        disable_aggregations=not show_total,
                        common=common,
                    )
                )

    @staticmethod
    @reserved_modifiers
    def show_xdr_dc_config(
        dc_configs,
        cluster,
        like=None,
        diff=False,
        with_=None,
        title_every_nth=0,
        flip_output=False,
        timestamp="",
        **ignore
    ):
        dc_configs = util.flip_keys(dc_configs)
        sorted_keys = list(dc_configs.keys())
        sorted_keys.sort()

        for dc in sorted_keys:
            title = "XDR {} DC Configuration".format(dc)
            CliView.show_config(
                title,
                dc_configs[dc],
                cluster,
                like=like,
                diff=diff,
                with_=with_,
                show_total=False,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
            )

    @staticmethod
    @reserved_modifiers
    def show_xdr_dc_stats(
        dc_configs,
        cluster,
        like=None,
        diff=False,
        with_=None,
        title_every_nth=0,
        flip_output=False,
        show_total=False,
        timestamp="",
        **ignore
    ):
        dc_configs = util.flip_keys(dc_configs)
        sorted_keys = list(dc_configs.keys())
        sorted_keys.sort()

        for dc in sorted_keys:
            title = "XDR {} DC Statistics".format(dc)
            CliView.show_config(
                title,
                dc_configs[dc],
                cluster,
                like=like,
                diff=diff,
                with_=with_,
                show_total=show_total,
                title_every_nth=title_every_nth,
                flip_output=flip_output,
                timestamp=timestamp,
            )

    @staticmethod
    @reserved_modifiers
    def show_xdr_filters(
        xdr_filters,
        like=None,
        diff=False,
        title_every_nth=0,
        flip_output=False,
        timestamp="",
        **ignore
    ):
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        style = SheetStyle.rows if flip_output else None

        xdr_filters = CliView._squash_dict(xdr_filters)
        title = "XDR Filters{}".format(title_suffix)
        sources = dict(
            data=xdr_filters,
        )

        CliView.print_result(
            sheet.render(
                templates.show_xdr_filters,
                title,
                sources,
                selectors=like,
                style=style,
                title_repeat=title_every_nth != 0,
                dynamic_diff=diff,
            )
        )

    @staticmethod
    def show_grep(title, summary):
        if not summary or len(summary.strip()) == 0:
            return
        if title:
            print("************************** %s **************************") % (title)
        CliView.print_result(summary)

    @staticmethod
    def show_grep_count(title, grep_result, title_every_nth=0, **ignore):
        # TODO - get rid of total row in grep_result and add column aggregations to sheets.
        node_ids = {}

        for node, res in grep_result.items():
            # TODO - sheet should be able to use the key in data.
            node_ids[node] = dict(node=node)

        CliView.print_result(
            sheet.render(
                templates.grep_count_sheet,
                title,
                dict(data=grep_result, node_ids=node_ids),
                title_repeat=title_every_nth != 0,
            )
        )

    @staticmethod
    def show_grep_diff(
        title, grep_result, title_every_nth=0, like=None, diff=None, **ignore
    ):
        column_names = list()
        different_writer_info = False

        if grep_result and grep_result[list(grep_result.keys())[0]]:
            if "diff_end" in grep_result[list(grep_result.keys())[0]]["value"]:
                for _k in grep_result.keys():
                    try:
                        if grep_result[_k]["value"]["diff_end"]:
                            different_writer_info = True
                        grep_result[_k]["value"].pop("diff_end")
                    except Exception:
                        continue

            column_names = CliView._sort_list_with_string_and_datetime(
                list(grep_result[list(grep_result.keys())[0]]["value"].keys())
            )

        if len(column_names) == 0:
            return ""

        column_names.insert(0, ".")
        column_names.insert(0, "NODE")

        t = Table(
            title,
            column_names,
            title_format=TitleFormats.no_change,
            orientation=Orientation.VERTICAL,
        )

        for file in sorted(grep_result.keys()):
            if isinstance(grep_result[file], Exception):
                row1 = {}
                row2 = {}
                row3 = {}
            else:
                row1 = grep_result[file]["value"]
                row2 = grep_result[file]["diff"]
                row3 = {}

                for key in grep_result[file]["value"].keys():
                    row3[key] = "|"

            row1["NODE"] = file
            row1["."] = "Total"

            row2["NODE"] = "."
            row2["."] = "Diff"

            row3["NODE"] = "|"
            row3["."] = "|"

            t.insert_row(row1)
            t.insert_row(row2)
            t.insert_row(row3)

        t.ignore_sort()

        CliView.print_result(t.__str__(horizontal_title_every_nth=title_every_nth * 3))

        if different_writer_info:
            print(
                "\n"
                + terminal.fg_red()
                + "Input Key is not uniq, multiple writer instance (server_file:line_no) found."
                + terminal.fg_clear()
            )

    @staticmethod
    def _sort_list_with_string_and_datetime(keys):
        if not keys:
            return keys

        dt_list = []
        remove_list = []

        for key in keys:
            try:
                dt_list.append(datetime.datetime.strptime(key, constants.DT_FMT))
                remove_list.append(key)
            except Exception:
                pass

        for rm_key in remove_list:
            keys.remove(rm_key)

        if keys:
            keys = sorted(keys)

        if dt_list:
            dt_list = [k.strftime(constants.DT_FMT) for k in sorted(dt_list)]

        if keys and not dt_list:
            return keys

        if dt_list and not keys:
            return dt_list

        dt_list.extend(keys)
        return dt_list

    @staticmethod
    def show_log_latency(
        title, grep_result, title_every_nth=0, like=None, diff=None, **ignore
    ):
        column_names = []
        tps_key = ("ops/sec", None)
        last_unit = None
        current_unit = None
        units_have_changed = False

        if grep_result:
            # find column names
            if grep_result[list(grep_result.keys())[0]]:
                column_names = CliView._sort_list_with_string_and_datetime(
                    list(grep_result[list(grep_result.keys())[0]][tps_key].keys())
                )

        if len(column_names) == 0:
            return ""

        column_names.insert(0, ".")
        column_names.insert(0, "NODE")

        t = Table(
            title,
            column_names,
            title_format=TitleFormats.no_change,
            orientation=Orientation.VERTICAL,
        )

        row = None
        sub_columns_per_column = 0
        for file in sorted(grep_result.keys()):
            if isinstance(grep_result[file], Exception):
                continue
            else:
                is_first = True
                sub_columns_per_column = len(grep_result[file].keys())
                relative_stats_columns = []

                # Get keys and remove tps so that they can be sorted
                grep_result_keys = list(grep_result[file].keys())
                grep_result_keys.remove(tps_key)

                for key, unit in sorted(grep_result_keys, key=lambda tup: int(tup[0])):
                    if not unit:
                        # this is relative stat column
                        relative_stats_columns.append((key, unit))
                        continue

                    row = grep_result[file][(key, unit)]
                    current_unit = unit

                    if last_unit is None:
                        last_unit = unit
                    elif last_unit != unit:
                        units_have_changed = True

                    if is_first:
                        row["NODE"] = file
                        is_first = False
                    else:
                        row["NODE"] = "."

                    row["."] = "%% >%d%s" % (key, unit)
                    t.insert_row(row)

                row = grep_result[file][tps_key]
                row["NODE"] = "."
                row["."] = tps_key[0]
                t.insert_row(row)

                for stat in relative_stats_columns:
                    row = grep_result[file][stat]
                    row["NODE"] = "."
                    row["."] = stat[0]
                    t.insert_row(row)

                row = {}

                for key in grep_result[file][tps_key].keys():
                    row[key] = "|"

                row["NODE"] = "|"
                row["."] = "|"
                t.insert_row(row)

        t.ignore_sort()
        CliView.print_result(
            t.__str__(
                horizontal_title_every_nth=title_every_nth
                * (sub_columns_per_column + 1)
            )
        )

        if units_have_changed:
            CliView.print_result(
                "WARNING: asadm stopped early because latency units have changed from %s to %s."
                % (last_unit, current_unit)
            )
            CliView.print_result(
                "Use 'histogram -h <histogram> -f <datetime> to bypass this problem."
            )
            return False

        return True

    @staticmethod
    def show_mapping(col1, col2, mapping, like=None, timestamp="", **ignore):
        if not mapping:
            return

        if like:
            likes = util.compile_likes(like)
            filtered_keys = set(filter(likes.search, mapping.keys()))
        else:
            filtered_keys = set(mapping.keys())

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "{} to {} Mappings{}".format(col1, col2, title_suffix)
        sources = dict(
            mapping=dict(
                enumerate((k, v) for k, v in mapping.items() if k in filtered_keys)
            )
        )

        if col2 == "IPs":
            map_sheet = templates.show_mapping_to_ip_sheet
        else:
            map_sheet = templates.show_mapping_to_id_sheet

        CliView.print_result(sheet.render(map_sheet, title, sources))

    @staticmethod
    @reserved_modifiers
    def show_pmap(pmap_data, cluster, timestamp="", with_=None, **ignore):
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "Partition Map Analysis" + title_suffix
        sources = dict(
            node_names=node_names,
            node_ids=node_ids,
            pmap=pmap_data,
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.show_pmap_sheet, title, sources, common=common)
        )

    @staticmethod
    def show_users(users_data, like=None, timestamp="", **ignore):
        if not users_data:
            return

        if like:
            likes = util.compile_likes(like)
            filtered_keys = list(filter(likes.search, users_data.keys()))
        else:
            filtered_keys = users_data.keys()

        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "Users{}".format(title_timestamp)
        # Normally the top level of the dict is used to associate different sources.
        # Since we do not need one here we must artificially create one.

        users_data = dict(
            enumerate({k: v} for k, v in users_data.items() if k in filtered_keys)
        )

        sources = dict(data=users_data)
        CliView.print_result(sheet.render(templates.show_users, title, sources))

    @staticmethod
    def show_roles(roles_data, like=None, timestamp="", **ignore):
        if not roles_data:
            return

        if like:
            likes = util.compile_likes(like)
            filtered_keys = list(filter(likes.search, roles_data.keys()))
        else:
            filtered_keys = roles_data.keys()

        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "Roles{}".format(title_timestamp)
        roles_data = dict(
            enumerate({k: v} for k, v in roles_data.items() if k in filtered_keys)
        )
        sources = dict(data=roles_data)

        CliView.print_result(sheet.render(templates.show_roles, title, sources))

    @staticmethod
    def show_udfs(udfs_data, like, timestamp="", **ignore):
        if not udfs_data:
            return

        if like:
            likes = util.compile_likes(like)
            filtered_keys = list(filter(likes.search, udfs_data.keys()))
        else:
            filtered_keys = udfs_data.keys()

        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "UDF Modules{}".format(title_timestamp)
        udfs_data = dict(
            enumerate({k: v} for k, v in udfs_data.items() if k in filtered_keys)
        )
        sources = dict(data=udfs_data)

        CliView.print_result(sheet.render(templates.show_udfs, title, sources))

    @staticmethod
    def show_sindex(sindexes_data, like, timestamp="", **ignore):
        CliView._get_timestamp_suffix(timestamp)
        if not sindexes_data:
            return

        filtered_data = []

        if like:
            likes = util.compile_likes(like)
            for sindex in sindexes_data:
                if "indexname" in sindex and likes.search(sindex["indexname"]):
                    filtered_data.append(sindex)
        else:
            filtered_data = sindexes_data

        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "Secondary Indexes{}".format(title_timestamp)
        sources = dict(data=filtered_data)

        CliView.print_result(sheet.render(templates.show_sindex, title, sources))

    @staticmethod
    @reserved_modifiers
    def show_roster(
        roster_data,
        cluster,
        diff=False,
        for_=None,
        with_=None,
        flip=False,
        timestamp="",
        **ignore
    ):
        if not roster_data:
            return

        filtered_data = None

        if for_:
            filtered_data = dict(roster_data)
            likes = util.compile_likes(for_)
            for node_data in filtered_data.values():
                for key in list(node_data.keys()):
                    if not likes.search(key):
                        del node_data[key]
        else:
            filtered_data = roster_data

        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "Roster{}".format(title_timestamp)

        sources = dict(
            node_names=node_names,
            node_ids=node_ids,
            data=roster_data,
        )
        common = dict(principal=cluster.get_expected_principal())
        style = SheetStyle.columns

        if flip:
            style = SheetStyle.rows

        CliView.print_result(
            sheet.render(
                templates.show_roster,
                title,
                sources,
                common=common,
                style=style,
                dynamic_diff=diff,
            )
        )

    @staticmethod
    @reserved_modifiers
    def show_best_practices(
        cluster, failed_practices, timestamp="", with_=None, **ignore
    ):
        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "Best Practices{}".format(title_timestamp)
        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        common = dict(principal=cluster.get_expected_principal())
        sources = dict(data=failed_practices, node_names=node_names, node_ids=node_ids)

        CliView.print_result(
            sheet.render(templates.show_best_practices, title, sources, common=common)
        )
        CliView.print_result(
            "Following Aerospike's best-practices are required for optimal stability and performance.\n"
            + "Descriptions of each can be found @ https://docs.aerospike.com/docs/operations/install/linux/bestpractices/index.html"
        )

    @staticmethod
    @reserved_modifiers
    def show_jobs(
        title,
        cluster,
        jobs_data,
        timestamp="",
        trid=None,
        like=None,
        with_=None,
        **ignore
    ):
        if jobs_data is None:
            return

        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "{}{}".format(title, title_timestamp)

        filtered_data = dict(jobs_data)

        for host, host_data in jobs_data.items():
            if isinstance(host_data, ASInfoError):
                del filtered_data[host]
                continue
            if trid:
                for id in dict(host_data):
                    if id not in trid:
                        del filtered_data[host][id]

        if not filtered_data:
            return

        node_names = cluster.get_node_names(with_)
        node_ids = cluster.get_node_ids(with_)
        sources = dict(data=filtered_data, node_names=node_names, node_ids=node_ids)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(
                templates.show_jobs, title, sources, common=common, selectors=like
            )
        )

    @staticmethod
    def _squash_dict(data: dict[Any, dict[Any, dict[Any, Any]]]):
        """
        The sheet renderer handles {host: {ns: {...}}} formatted dicts well using the
        for_each_key flag in the sheet template. However, it does not handle {host: {dc: {ns: {...}}}}}
        without "squashing" it to {host: {(dc, ns): {...}}}}.
        """
        result = {}
        for node, ns_data in data.items():
            result[node] = {}
            for ns, rack in ns_data.items():
                for id, val in rack.items():
                    result[node][(ns, id)] = val

        return result

    @staticmethod
    def show_racks(rack_data, timestamp="", **ignore):
        if not rack_data:
            return

        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "Racks{}".format(title_timestamp)
        formatted = {}

        # Should only be one node (principal). Node key needed for sheets
        for node, ns_data in rack_data.items():
            formatted[node] = {}
            for ns, rack in ns_data.items():
                for id, val in rack.items():
                    formatted[node][(ns, id)] = val

        if not formatted:
            return

        sources = dict(data=formatted)

        CliView.print_result(sheet.render(templates.show_racks, title, sources))

    @staticmethod
    def killed_jobs(cluster, jobs_data, timestamp="", **ignore):
        if not jobs_data:
            return

        title_timestamp = CliView._get_timestamp_suffix(timestamp)
        title = "Kill Jobs{}".format(title_timestamp)
        hosts = list(jobs_data.keys())
        node_names = cluster.get_node_names(hosts)
        node_ids = cluster.get_node_ids(hosts)
        sources = dict(data=jobs_data, node_names=node_names, node_ids=node_ids)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.kill_jobs, title, sources, common=common)
        )

    @staticmethod
    def asinfo(results, line_sep, show_node_name, cluster, **mods):
        like = set([])

        if "like" in mods:
            like = set(mods["like"])

        for node_id, value in results.items():
            if show_node_name:
                prefix = cluster.get_node_names(mods.get("with", []))[node_id]
                node = cluster.get_node(node_id)[0]
                print(
                    "%s%s (%s) returned%s:"
                    % (terminal.bold(), prefix, node.ip, terminal.reset())
                )

            if isinstance(value, Exception):
                print("%s%s%s" % (terminal.fg_red(), value, terminal.reset()))
                print("\n")
            else:
                if isinstance(value, str):
                    delimiter = util.find_delimiter_in(value)
                    value = value.split(delimiter)

                    if like:
                        likes = util.compile_likes(like)
                        value = list(filter(likes.search, value))

                    if line_sep:
                        value = "\n".join(value)
                    else:
                        value = delimiter.join(value)

                    print(value)

                    if show_node_name:
                        print()
                else:
                    i = 1
                    for name, val in value.items():
                        print(i, ": ", name)
                        print("    ", val)
                        i += 1

                    if show_node_name:
                        print()

    @staticmethod
    def group_output(output):
        i = 0

        while i < len(output):
            group = output[i]

            if group == "\033":
                i += 1

                while i < len(output):
                    group = group + output[i]
                    if output[i] == "m":
                        i += 1
                        break
                    i += 1

                yield group
                continue
            else:
                yield group

                i += 1

    @staticmethod
    def peekable(peeked, remaining):
        for val in remaining:
            while peeked:
                yield peeked.pop(0)

            yield val

    @staticmethod
    async def watch(ctrl, line):
        diff_highlight = True
        sleep = 2.0
        num_iterations = False

        try:
            sleep = float(line[0])
            line.pop(0)
        except Exception:
            pass
        else:
            try:
                num_iterations = int(line[0])
                line.pop(0)
            except Exception:
                pass

        if line[0] == "--no-diff":
            diff_highlight = False
            line.pop(0)

        if not terminal.color_enabled:
            diff_highlight = False

        real_stdout = sys.stdout

        try:
            sys.stdout = mystdout = StringIO()
            previous = None
            count = 1

            while True:
                highlight = False
                await ctrl.execute(line[:])
                output = mystdout.getvalue()
                mystdout.truncate(0)
                mystdout.seek(0)

                if previous and diff_highlight:
                    result = []
                    prev_iterator = CliView.group_output(previous)
                    next_peeked = []
                    next_iterator = CliView.group_output(output)
                    next_iterator = CliView.peekable(next_peeked, next_iterator)

                    for prev_group in prev_iterator:
                        if "\033" in prev_group:
                            # skip prev escape seq
                            continue

                        for next_group in next_iterator:
                            if "\033" in next_group:
                                # add current escape seq
                                result += next_group
                                continue
                            elif next_group == "\n":
                                if prev_group != "\n":
                                    next_peeked.append(next_group)
                                    break
                                if highlight:
                                    result += terminal.uninverse()
                                    highlight = False
                            elif prev_group == next_group:
                                if highlight:
                                    result += terminal.uninverse()
                                    highlight = False
                            else:
                                if not highlight:
                                    result += terminal.inverse()
                                    highlight = True

                            result += next_group

                            if "\n" == prev_group and "\n" != next_group:
                                continue
                            break

                    for next_group in next_iterator:
                        if next_group == " " or next_group == "\n":
                            if highlight:
                                result += terminal.uninverse()
                                highlight = False
                        else:
                            if not highlight:
                                result += terminal.inverse()
                                highlight = True

                        result += next_group

                    if highlight:
                        result += terminal.reset()
                        highlight = False

                    result = "".join(result)
                    previous = output
                else:
                    result = output
                    previous = output

                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime(" %Y-%m-%d %H:%M:%S")
                command = " ".join(line)
                print(
                    "[%s '%s' sleep: %ss iteration: %s" % (st, command, sleep, count),
                    end=" ",
                    file=real_stdout,
                )
                if num_iterations:
                    print(" of %s" % (num_iterations), end=" ", file=real_stdout)
                print("]", file=real_stdout)
                print(result, file=real_stdout)

                if num_iterations and num_iterations <= count:
                    break

                count += 1
                time.sleep(sleep)

        except (KeyboardInterrupt, SystemExit):
            return
        finally:
            sys.stdout = real_stdout
            print("")

    @staticmethod
    def print_info_responses(title, responses, cluster, **mods):
        node_names = cluster.get_node_names(mods.get("with", []))
        sources = dict(data=responses, node_names=node_names)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.node_info_responses, title, sources, common=common)
        )

    # ##########################
    # ## Health Print functions
    # ##########################

    @staticmethod
    def _print_data(d):
        if d is None:
            return
        if isinstance(d, tuple):
            print(d)
        elif isinstance(d, dict):
            print_dict(d)
        else:
            print(str(d))

    @staticmethod
    def _print_counter_list(data, header=None):
        if not data:
            return
        print("\n" + ("_" * 100) + "\n")
        if header:
            print(
                terminal.fg_red()
                + terminal.bold()
                + str(header)
                + " ::\n"
                + terminal.unbold()
                + terminal.fg_clear()
            )
        for d in data:
            CliView._print_data(d)
            print("")

    @staticmethod
    def _print_status(status_counters, verbose=False):
        if not status_counters:
            return
        s = "\n" + terminal.bold() + "Summary".center(H_width, "_") + terminal.unbold()
        s += (
            "\n"
            + CliView._get_header("Total")
            + CliView._get_msg(
                [
                    str(
                        status_counters[
                            health_constants.HealthResultCounter.ASSERT_QUERY_COUNTER
                        ]
                    )
                ]
            )
        )
        s += CliView._get_header("Passed") + CliView._get_msg(
            [
                str(
                    status_counters[
                        health_constants.HealthResultCounter.ASSERT_PASSED_COUNTER
                    ]
                )
            ]
        )
        s += CliView._get_header("Failed") + CliView._get_msg(
            [
                str(
                    status_counters[
                        health_constants.HealthResultCounter.ASSERT_FAILED_COUNTER
                    ]
                )
            ]
        )
        s += CliView._get_header("Skipped") + CliView._get_msg(
            [
                str(
                    status_counters[
                        health_constants.HealthResultCounter.ASSERT_QUERY_COUNTER
                    ]
                    - status_counters[
                        health_constants.HealthResultCounter.ASSERT_FAILED_COUNTER
                    ]
                    - status_counters[
                        health_constants.HealthResultCounter.ASSERT_PASSED_COUNTER
                    ]
                )
            ]
        )
        print(s)

    @staticmethod
    def _print_debug_messages(ho):
        try:
            for d in ho[health_constants.HealthResultType.DEBUG_MESSAGES]:
                try:
                    print("Value of %s:" % (d[1]))
                    CliView._print_data(d[2])
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _print_exceptions(ho):
        try:
            for e in ho[health_constants.HealthResultType.EXCEPTIONS]:
                try:
                    CliView._print_counter_list(
                        data=ho[health_constants.HealthResultType.EXCEPTIONS][e],
                        header="%s Exceptions" % (e.upper()),
                    )
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _get_header(header):
        return (
            "\n"
            + terminal.bold()
            + ("%s:" % header).rjust(H1_offset)
            + terminal.unbold()
            + " ".rjust(H2_offset - H1_offset)
        )

    @staticmethod
    def _get_msg(msg, level=None):
        if level is not None:
            if level == health_constants.AssertLevel.WARNING:
                return (
                    terminal.fg_blue()
                    + ("\n" + " ".rjust(H2_offset)).join(msg)
                    + terminal.fg_clear()
                )
            elif level == health_constants.AssertLevel.INFO:
                return (
                    terminal.fg_green()
                    + ("\n" + " ".rjust(H2_offset)).join(msg)
                    + terminal.fg_clear()
                )
            else:
                return (
                    terminal.fg_red()
                    + ("\n" + " ".rjust(H2_offset)).join(msg)
                    + terminal.fg_clear()
                )
        else:
            return ("\n" + " ".rjust(H2_offset)).join(msg)

    @staticmethod
    def _format_value(val, formatting=True):
        if not val or not formatting:
            return val

        if isinstance(val, int):
            try:
                # For python 2.7
                return str(format(val, ",d"))
            except Exception:
                try:
                    # For python 2.6
                    locale.setlocale(locale.LC_ALL, "en_US.UTF-8")
                    return str(locale.format("%d", val, True))

                except Exception:
                    pass
        elif isinstance(val, float):
            return_val = None

            try:
                # For python 2.7
                return_val = format(val, ",f")
            except Exception:
                try:
                    # For python 2.6
                    locale.setlocale(locale.LC_ALL, "en_US.UTF-8")
                    return_val = locale.format("%f", val, True)
                except Exception:
                    pass

            if return_val is not None:
                return_val = str(return_val)

                if "." in return_val:
                    return_val = return_val.rstrip("0")
                    return_val = return_val.rstrip(".")

                return return_val
        elif isinstance(val, str) and val.isdigit():
            return CliView._format_value(int(val))
        elif isinstance(val, str):
            try:
                val = float(val)
                return CliView._format_value(val)
            except Exception:
                pass

        return val

    @staticmethod
    def _get_kv_msg_list(kv_list):
        if not kv_list:
            return []

        res_str = []

        for kv in kv_list:
            if not isinstance(kv, tuple):
                res_str.append(str(kv))
                continue

            tmp_res_str = str(kv[0])

            if kv[1] and isinstance(kv[1], list):
                _str = None
                for _kv in kv[1]:
                    if _kv:
                        try:
                            _str += (
                                ", "
                                + (
                                    "%s:" % (str(_kv[0]))
                                    if len(str(_kv[0]).strip()) > 0
                                    else ""
                                )
                                + "%s" % (CliView._format_value(_kv[1], _kv[2]))
                            )
                        except Exception:
                            _str = (
                                "%s:" % (str(_kv[0]))
                                if len(str(_kv[0]).strip()) > 0
                                else ""
                            ) + "%s" % (CliView._format_value(_kv[1], _kv[2]))

                if _str:
                    tmp_res_str += " {%s}" % (_str)

            if tmp_res_str:
                res_str.append(tmp_res_str)

        return res_str

    @staticmethod
    def _get_error_string(
        data, verbose=False, level=health_constants.AssertLevel.CRITICAL
    ) -> Tuple[str, int, str, int]:
        if not data:
            return "", 0, "", 0

        f_msg_str = ""
        f_msg_cnt = 0
        s_msg_str = ""
        s_msg_cnt = 0

        for d in data:
            s = ""

            if d[health_constants.AssertResultKey.LEVEL] == level:
                if d[health_constants.AssertResultKey.SUCCESS]:
                    if d[health_constants.AssertResultKey.SUCCESS_MSG]:
                        s_msg_str += CliView._get_header(
                            d[health_constants.AssertResultKey.CATEGORY][0]
                        ) + CliView._get_msg(
                            [d[health_constants.AssertResultKey.SUCCESS_MSG]]
                        )
                        s_msg_cnt += 1

                    continue

                s += CliView._get_header(
                    d[health_constants.AssertResultKey.CATEGORY][0]
                ) + CliView._get_msg(
                    [d[health_constants.AssertResultKey.FAIL_MSG]], level
                )

                if verbose:
                    import textwrap

                    s += "\n"
                    s += CliView._get_header("Description:")
                    s += CliView._get_msg(
                        textwrap.wrap(
                            str(d[health_constants.AssertResultKey.DESCRIPTION]),
                            H_width - H2_offset,
                            break_long_words=False,
                            break_on_hyphens=False,
                        )
                    )
                    s += "\n"
                    s += CliView._get_header("Keys:")
                    s += CliView._get_msg(
                        CliView._get_kv_msg_list(
                            d[health_constants.AssertResultKey.KEYS]
                        )
                    )

                    # Extra new line in case verbose output is printed
                    s += "\n"

                f_msg_str += s
                f_msg_cnt += 1

        res_fail_msg_str = ""

        if f_msg_cnt > 0:
            res_fail_msg_str += f_msg_str

        res_success_msg_str = ""

        if s_msg_cnt > 0:
            res_success_msg_str += s_msg_str

        return res_fail_msg_str, f_msg_cnt, res_success_msg_str, s_msg_cnt

    @staticmethod
    def _get_assert_output_string(
        assert_out,
        verbose=False,
        output_filter_category=[],
        level=health_constants.AssertLevel.CRITICAL,
    ) -> Tuple[str, int, str, int]:
        if not assert_out:
            return "", 0, "", 0

        res_fail_msg_str = ""
        total_fail_msg_cnt = 0
        res_success_msg_str = ""
        total_success_msg_cnt = 0

        if not isinstance(assert_out, dict):
            if not output_filter_category:
                return CliView._get_error_string(assert_out, verbose, level=level)
        else:
            for _k in sorted(assert_out.keys()):
                category = []

                if output_filter_category:
                    if _k == output_filter_category[0]:
                        category = (
                            output_filter_category[1:]
                            if len(output_filter_category) > 1
                            else []
                        )
                    else:
                        category = output_filter_category

                (
                    f_msg_str,
                    f_msg_cnt,
                    s_msg_str,
                    s_msg_cnt,
                ) = CliView._get_assert_output_string(
                    assert_out[_k], verbose, category, level=level
                )

                res_fail_msg_str += f_msg_str
                total_fail_msg_cnt += f_msg_cnt
                res_success_msg_str += s_msg_str
                total_success_msg_cnt += s_msg_cnt

        return (
            res_fail_msg_str,
            total_fail_msg_cnt,
            res_success_msg_str,
            total_success_msg_cnt,
        )

    @staticmethod
    def _print_assert_summary(
        assert_out,
        verbose=False,
        output_filter_category=[],
        output_filter_warning_level=None,
    ):
        if not output_filter_warning_level:
            search_levels = [
                health_constants.AssertLevel.INFO,
                health_constants.AssertLevel.WARNING,
                health_constants.AssertLevel.CRITICAL,
            ]
        elif output_filter_warning_level == "CRITICAL":
            search_levels = [health_constants.AssertLevel.CRITICAL]
        elif output_filter_warning_level == "WARNING":
            search_levels = [health_constants.AssertLevel.WARNING]
        elif output_filter_warning_level == "INFO":
            search_levels = [health_constants.AssertLevel.INFO]
        else:
            search_levels = [
                health_constants.AssertLevel.INFO,
                health_constants.AssertLevel.WARNING,
                health_constants.AssertLevel.CRITICAL,
            ]

        all_success_str = ""
        all_fail_str = ""
        all_fail_cnt = 0
        all_success_cnt = 0

        for level in search_levels:
            res_fail_msg_str = ""
            total_fail_msg_cnt = 0
            res_success_msg_str = ""
            total_success_msg_cnt = 0

            for _k in sorted(assert_out.keys()):
                if not assert_out[_k]:
                    continue

                category = []

                if output_filter_category:
                    if _k == output_filter_category[0]:
                        category = (
                            output_filter_category[1:]
                            if len(output_filter_category) > 1
                            else []
                        )
                    else:
                        category = output_filter_category

                (
                    f_msg_str,
                    f_msg_cnt,
                    s_msg_str,
                    s_msg_cnt,
                ) = CliView._get_assert_output_string(
                    assert_out[_k], verbose, category, level=level
                )

                if f_msg_str:
                    total_fail_msg_cnt += f_msg_cnt
                    res_fail_msg_str += f_msg_str

                if s_msg_str:
                    total_success_msg_cnt += s_msg_cnt
                    res_success_msg_str += s_msg_str

            if total_fail_msg_cnt > 0:
                summary_str = ""

                if level == health_constants.AssertLevel.CRITICAL:
                    summary_str = (
                        terminal.bold()
                        + terminal.fg_red()
                        + "CRITICAL".center(H_width, " ")
                        + terminal.fg_clear()
                        + terminal.unbold()
                    )
                elif level == health_constants.AssertLevel.WARNING:
                    summary_str = (
                        terminal.bold()
                        + terminal.fg_blue()
                        + "WARNING".center(H_width, " ")
                        + terminal.fg_clear()
                        + terminal.unbold()
                    )
                elif level == health_constants.AssertLevel.INFO:
                    summary_str = (
                        terminal.bold()
                        + terminal.fg_green()
                        + "INFO".center(H_width, " ")
                        + terminal.fg_clear()
                        + terminal.unbold()
                    )

                all_fail_str += "\n" + summary_str + "\n" + res_fail_msg_str + "\n"
                all_fail_cnt += total_fail_msg_cnt

            if total_success_msg_cnt > 0:
                all_success_str += res_success_msg_str
                all_success_cnt += total_success_msg_cnt

        if all_success_cnt > 0:
            print(
                "\n\n"
                + terminal.bold()
                + str(" %s: count(%d) " % ("PASS", all_success_cnt)).center(
                    H_width, "_"
                )
                + terminal.unbold()
            )
            print(all_success_str)

        if all_fail_cnt > 0:
            print(
                "\n\n"
                + terminal.bold()
                + str(" %s: count(%d) " % ("FAIL", all_fail_cnt)).center(H_width, "_")
                + terminal.unbold()
            )
            print(all_fail_str)

        print("_" * H_width + "\n")

    @staticmethod
    def print_health_output(
        ho,
        verbose=False,
        debug=False,
        output_file=None,
        output_filter_category=[],
        output_filter_warning_level=None,
    ):
        if not ho:
            return
        o_s = None

        if output_file is not None:
            try:
                o_s = open(output_file, "a")
                sys.stdout = o_s
            except Exception:
                sys.stdout = sys.__stdout__

        CliView._print_debug_messages(ho)
        if debug:
            CliView._print_exceptions(ho)

        CliView._print_status(
            ho[health_constants.HealthResultType.STATUS_COUNTERS], verbose=verbose
        )
        CliView._print_assert_summary(
            ho[health_constants.HealthResultType.ASSERT],
            verbose=verbose,
            output_filter_category=output_filter_category,
            output_filter_warning_level=output_filter_warning_level,
        )

        if o_s:
            o_s.close()
        sys.stdout = sys.__stdout__

    ###########################

    @staticmethod
    def get_summary_line_prefix(index, key):
        s = " " * 3
        s += (str(index) + ".").ljust(3)
        s += " " * 2
        s += key.ljust(19)
        s += ":" + (" " * 2)
        return s

    @staticmethod
    def _summary_cluster_table_view(stats: SummaryClusterDict, **ignore):
        title = "Cluster Summary"
        new_stats = dict(node_hack=stats)  # XXX - hack
        sources = dict(cluster_dict=new_stats)

        CliView.print_result(
            sheet.render(
                templates.summary_cluster_sheet,
                title,
                sources,
            )
        )

    @staticmethod
    def _summary_namespace_table_view(stats: SummaryNamespacesDict, **ignore):
        title = "Namespace Summary"
        new_stats = dict(node_hack=stats)  # XXX - hack
        sources = dict(ns_stats=new_stats)

        CliView.print_result(
            sheet.render(templates.summary_namespace_sheet, title, sources)
        )

    @staticmethod
    def _summary_cluster_list_view(cluster_dict: SummaryClusterDict, **ignore):
        index = 1
        print(
            "Cluster"
            + (
                "  (%s)"
                % (terminal.fg_red() + "Migrations in Progress" + terminal.fg_clear())
                if cluster_dict["migrations_in_progress"]
                else ""
            )
        )
        print(
            "======="
            + (
                "=========================="
                if cluster_dict["migrations_in_progress"]
                else ""
            )
        )
        print()

        if "cluster_name" in cluster_dict and len(cluster_dict["cluster_name"]) > 0:
            print(
                CliView.get_summary_line_prefix(index, "Cluster Name")
                + ", ".join(cluster_dict["cluster_name"])
            )
            index += 1

        print(
            CliView.get_summary_line_prefix(index, "Server Version")
            + ", ".join(cluster_dict["server_version"])
        )
        index += 1

        print(
            CliView.get_summary_line_prefix(index, "OS Version")
            + ", ".join(cluster_dict["os_version"])
        )
        index += 1

        print(
            CliView.get_summary_line_prefix(index, "Cluster Size")
            + ", ".join([str(cs) for cs in cluster_dict["cluster_size"]])
        )
        index += 1

        print(
            CliView.get_summary_line_prefix(index, "Devices")
            + "Total %d, per-node %d%s"
            % (
                cluster_dict["device_count"],
                cluster_dict["device_count_per_node"],
                " (number differs across nodes)"
                if not cluster_dict["device_count_same_across_nodes"]
                else "",
            )
        )
        index += 1

        print(
            CliView.get_summary_line_prefix(index, "Memory")
            + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"
            % (
                file_size.size(cluster_dict["memory"]["total"]).strip(),
                cluster_dict["memory"]["used_pct"],
                file_size.size(cluster_dict["memory"]["used"]).strip(),
                cluster_dict["memory"]["avail_pct"],
                file_size.size(cluster_dict["memory"]["avail"]).strip(),
            )
        )
        index += 1

        if "pmem_index" in cluster_dict:
            print(
                CliView.get_summary_line_prefix(index, "Pmem Index")
                + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"
                % (
                    file_size.size(cluster_dict["pmem_index"]["total"]).strip(),
                    cluster_dict["pmem_index"]["used_pct"],
                    file_size.size(cluster_dict["pmem_index"]["used"]).strip(),
                    cluster_dict["pmem_index"]["avail_pct"],
                    file_size.size(cluster_dict["pmem_index"]["avail"]).strip(),
                )
            )
            index += 1

        if "flash_index" in cluster_dict:
            print(
                CliView.get_summary_line_prefix(index, "Flash Index")
                + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"
                % (
                    file_size.size(cluster_dict["flash_index"]["total"]).strip(),
                    cluster_dict["flash_index"]["used_pct"],
                    file_size.size(cluster_dict["flash_index"]["used"]).strip(),
                    cluster_dict["flash_index"]["avail_pct"],
                    file_size.size(cluster_dict["flash_index"]["avail"]).strip(),
                )
            )
            index += 1

        if "device" in cluster_dict:
            print(
                CliView.get_summary_line_prefix(index, "Device")
                + "Total %s, %.2f%% used (%s), %.2f%% available contiguous space (%s)"
                % (
                    file_size.size(cluster_dict["device"]["total"]).strip(),
                    cluster_dict["device"]["used_pct"],
                    file_size.size(cluster_dict["device"]["used"]).strip(),
                    cluster_dict["device"]["avail_pct"],
                    file_size.size(cluster_dict["device"]["avail"]).strip(),
                )
            )
            index += 1

        if "pmem" in cluster_dict:
            print(
                CliView.get_summary_line_prefix(index, "Pmem")
                + "Total %s, %.2f%% used (%s), %.2f%% available contiguous space (%s)"
                % (
                    file_size.size(cluster_dict["pmem"]["total"]).strip(),
                    cluster_dict["pmem"]["used_pct"],
                    file_size.size(cluster_dict["pmem"]["used"]).strip(),
                    cluster_dict["pmem"]["avail_pct"],
                    file_size.size(cluster_dict["pmem"]["avail"]).strip(),
                )
            )
            index += 1

        data_summary = CliView.get_summary_line_prefix(index, "License Usage")

        try:
            # license_data was computed by uda
            time_ = cluster_dict["license_data"]["latest_time"]
            time_.strftime("%H:%M:%S %m/%d/%Y")

            data_summary += "Latest (%s): %s Min: %s Max: %s Avg: %s" % (
                time_,
                file_size.size(cluster_dict["license_data"]["latest"]),
                file_size.size(cluster_dict["license_data"]["min"]),
                file_size.size(cluster_dict["license_data"]["max"]),
                file_size.size(cluster_dict["license_data"]["avg"]),
            )
        except Exception:
            # license_data was manually computed by asadm
            data_summary += "Latest: %s" % (
                file_size.size(cluster_dict["license_data"]["latest"])
            )

        print(data_summary)
        index += 1

        print(
            CliView.get_summary_line_prefix(index, "Active Namespaces")
            + "%d of %d" % (cluster_dict["active_ns"], cluster_dict["ns_count"])
        )
        index += 1

        print(
            CliView.get_summary_line_prefix(index, "Active Features")
            + ", ".join(sorted(cluster_dict["active_features"]))
        )

        print("\n")

    @staticmethod
    def _summary_namespace_list_view(stats: SummaryNamespacesDict, **ignore):
        print("Namespaces")
        print("==========")
        print()
        for ns, ns_stats in stats.items():
            index = 1
            print(
                "   "
                + (
                    "%s" % (terminal.fg_red() + ns + terminal.fg_clear())
                    if ns_stats["migrations_in_progress"]
                    else ns
                )
            )
            print("   " + "=" * len(ns))

            print(
                CliView.get_summary_line_prefix(index, "Devices")
                + "Total %d, per-node %d%s"
                % (
                    ns_stats["devices_total"],
                    ns_stats["devices_per_node"],
                    " (number differs across nodes)"
                    if not ns_stats["device_count_same_across_nodes"]
                    else "",
                )
            )
            index += 1

            print(
                CliView.get_summary_line_prefix(index, "Memory")
                + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"
                % (
                    file_size.size(ns_stats["memory"]["total"]).strip(),
                    ns_stats["memory"]["used_pct"],
                    file_size.size(ns_stats["memory"]["used"]).strip(),
                    ns_stats["memory"]["avail_pct"],
                    file_size.size(ns_stats["memory"]["avail"]).strip(),
                )
            )
            index += 1

            try:
                print(
                    CliView.get_summary_line_prefix(index, "Pmem Index")
                    + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"
                    % (
                        file_size.size(ns_stats["pmem_index"]["total"]).strip(),
                        ns_stats["pmem_index"]["used_pct"],
                        file_size.size(ns_stats["pmem_index"]["used"]).strip(),
                        ns_stats["pmem_index"]["avail_pct"],
                        file_size.size(ns_stats["pmem_index"]["avail"]).strip(),
                    )
                )
                index += 1
            except:
                pass

            try:
                print(
                    CliView.get_summary_line_prefix(index, "Flash Index")
                    + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"
                    % (
                        file_size.size(ns_stats["flash_index"]["total"]).strip(),
                        ns_stats["flash_index"]["used_pct"],
                        file_size.size(ns_stats["flash_index"]["used"]).strip(),
                        ns_stats["flash_index"]["avail_pct"],
                        file_size.size(ns_stats["flash_index"]["avail"]).strip(),
                    )
                )
                index += 1
            except:
                pass

            if "device_total" in ns_stats:
                try:
                    print(
                        CliView.get_summary_line_prefix(index, "Device")
                        + "Total %s, %.2f%% used (%s), %.2f%% available contiguous space (%s)"
                        % (
                            file_size.size(ns_stats["device"]["total"]).strip(),
                            ns_stats["device"]["used_pct"],
                            file_size.size(ns_stats["device"]["used"]).strip(),
                            ns_stats["device"]["avail_pct"],
                            file_size.size(ns_stats["device"]["avail"]).strip(),
                        )
                    )
                    index += 1
                except:
                    pass
            elif "pmem_total" in ns_stats:
                try:
                    print(
                        CliView.get_summary_line_prefix(index, "Pmem")
                        + "Total %s, %.2f%% used (%s), %.2f%% available contiguous space (%s)"
                        % (
                            file_size.size(ns_stats["pmem"]["total"]).strip(),
                            ns_stats["pmem"]["used_pct"],
                            file_size.size(ns_stats["pmem"]["used"]).strip(),
                            ns_stats["pmem"]["avail_pct"],
                            file_size.size(ns_stats["pmem"]["avail"]).strip(),
                        )
                    )
                    index += 1
                except:
                    pass

            license_usage = CliView.get_summary_line_prefix(index, "License Usage")

            try:
                # license_data was computed by uda
                time_ = ns_stats["license_data"]["latest_time"]
                time = time_.strftime("%m/%d/%Y %Z %H:%M:%S")
                license_usage += "Latest (%s): %s Min: %s Max: %s Avg: %s" % (
                    time,
                    file_size.size(ns_stats["license_data"]["latest"]),
                    file_size.size(ns_stats["license_data"]["min"]),
                    file_size.size(ns_stats["license_data"]["max"]),
                    file_size.size(ns_stats["license_data"]["avg"]),
                )
            except Exception:
                # license_data was manually computed by asadm
                license_usage += "Latest: %s" % (
                    file_size.size(ns_stats["license_data"]["latest"])
                )

            print(license_usage)

            print(
                CliView.get_summary_line_prefix(index, "Replication Factor")
                + "%s" % (",".join([str(rf) for rf in ns_stats["repl_factor"]]))
            )
            index += 1

            if "cache_read_pct" in ns_stats:
                print(
                    CliView.get_summary_line_prefix(index, "Post-Write-Queue Hit-Rate")
                    + "%s"
                    % (file_size.size(ns_stats["cache_read_pct"], file_size.si_float))
                )
                index += 1

            if "rack_aware" in ns_stats:
                print(
                    CliView.get_summary_line_prefix(index, "Rack-aware")
                    + "%s" % (str(ns_stats["rack_aware"]))
                )
                index += 1

            print(
                CliView.get_summary_line_prefix(index, "Master Objects")
                + "%s"
                % (file_size.size(ns_stats["master_objects"], file_size.si_float))
            )
            index += 1

            if "compression_ratio" in ns_stats:
                print(
                    CliView.get_summary_line_prefix(index, "Compression-ratio")
                    + "%s" % (str(ns_stats["compression_ratio"]))
                )
                index += 1
            print()

    @staticmethod
    def print_summary(summary: SummaryDict, list_view=True):
        if list_view:
            CliView._summary_cluster_list_view(summary["CLUSTER"])
            CliView._summary_namespace_list_view(summary["NAMESPACES"])
        else:
            CliView._summary_cluster_table_view(summary["CLUSTER"])
            CliView._summary_namespace_table_view(summary["NAMESPACES"])
