# Copyright 2013-2020 Aerospike, Inc.
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
import sys
import time
import types
from io import StringIO
from collections import OrderedDict
from pydoc import pipepager

from lib.health.constants import (AssertLevel, AssertResultKey,
                                  HealthResultCounter, HealthResultType)
from lib.health.util import print_dict
from lib.utils import filesize
from lib.utils.constants import DT_FMT
from lib.utils.util import compile_likes, find_delimiter_in, get_value_from_dict
from lib.view import sheet, terminal, templates
from lib.view.sheet import SheetStyle
from lib.view.table import Extractors, Styles, Table, TitleFormats

H1_offset = 13
H2_offset = 15
H_width = 80


class CliView(object):
    NO_PAGER, LESS, MORE, SCROLL = range(4)
    pager = NO_PAGER

    @staticmethod
    def print_result(out):
        if out is None or out == "":
            return

        if type(out) is not str:
            out = str(out)
        if CliView.pager == CliView.LESS:
            pipepager(out, cmd='less -RSX')
        elif CliView.pager == CliView.SCROLL:
            for i in out.split('\n'):
                print(i)
                time.sleep(.05)
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

        return ' (' + str(timestamp) + ')'

    @staticmethod
    def info_network(stats, cluster_names, versions, builds, cluster,
                     timestamp='', **mods):
        prefixes = cluster.get_node_names(mods.get('with', []))
        hosts = cluster.nodes
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Network Information' + title_suffix
        sources = dict(
            cluster_names=cluster_names,
            prefixes=prefixes,
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.keys())),
            hosts=dict(((k, h.sock_name(use_fqdn=False))
                        for k, h in hosts.items())),
            builds=builds,
            versions=versions,
            stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.network_sheet, title, sources,
                         common=common))

    @staticmethod
    def info_namespace_usage(stats, cluster, timestamp='', **mods):
        prefixes = cluster.get_node_names(mods.get('with', []))
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Namespace Usage Information' + title_suffix
        sources = dict(
            # TODO - collect cluster-name.
            cluster_names=dict([(k, None) for k in stats.keys()]),
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.keys())),
            prefixes=prefixes,
            ns_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.namespace_usage_sheet, title, sources,
                         common=common))

    @staticmethod
    def info_namespace_object(stats, cluster, timestamp='', **mods):
        prefixes = cluster.get_node_names(mods.get('with', []))
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Namespace Object Information' + title_suffix
        sources = dict(
            # TODO - collect cluster-name.
            cluster_names=dict([(k, None) for k in stats.keys()]),
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.keys())),
            prefixes=prefixes,
            ns_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.namespace_object_sheet, title, sources,
                         common=common))

    @staticmethod
    def info_set(stats, cluster, timestamp='', **mods):
        prefixes = cluster.get_node_names(mods.get('with', []))
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Set Information%s' + title_suffix
        sources = dict(
            # TODO - collect cluster-name.
            cluster_names=dict([(k, None) for k in stats.keys()]),
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.keys())),
            prefixes=prefixes,
            set_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.set_sheet, title, sources, common=common))

    # pre 5.0
    @staticmethod
    def info_dc(stats, cluster, timestamp='', **mods):
        prefixes = cluster.get_node_names(mods.get('with', []))

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'DC Information%s' % (title_suffix)
        sources = dict(
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.keys())),
            prefixes=prefixes,
            dc_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.xdr_dc_sheet, title, sources,
                         common=common))

    # pre 5.0
    @staticmethod
    def info_old_XDR(stats, builds, xdr_enable, cluster, timestamp="", **mods):
        if not max(xdr_enable.values()):
            return

        prefixes = cluster.get_node_names(mods.get('with', []))

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'XDR Information' + title_suffix
        sources = dict(
            xdr_enable=xdr_enable,
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.keys())),
            prefixes=prefixes,
            builds=builds,
            xdr_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.xdr_sheet, title, sources, common=common))

    @staticmethod
    def info_XDR(stats, xdr_enable, cluster, timestamp="", title="XDR Information", **ignore):
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = title + title_suffix
        prefixes = cluster.get_node_names()
        node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                        for k in prefixes.keys()))
        sources = dict(
            xdr_enable=xdr_enable,
            node_ids=node_ids,
            prefixes=prefixes,
            xdr_stats=stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.info_xdr_sheet, title, sources, common=common))

    @staticmethod
    def info_sindex(stats, cluster, timestamp='', **mods):
        # return if sindex stats are empty.
        if not stats:
            return

        # stats comes in {index:{node:{k:v}}}, needs to be {node:{index:{k:v}}}
        sindex_stats = {}

        for iname, nodes in stats.items():
            for node, values in nodes.items():
                sindex_stats[node] = node_stats = sindex_stats.get(node, {})
                node_stats[iname] = values

        prefixes = cluster.get_node_names(mods.get('with', []))
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Secondary Index Information' + title_suffix
        sources = dict(
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.keys())),
            prefixes=prefixes,
            sindex_stats=sindex_stats)
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(
            sheet.render(templates.sindex_sheet, title, sources,
                         common=common))

    @staticmethod
    def show_distribution(title, histogram, unit, hist, cluster, like=None,
                          timestamp="", **mods):
        likes = compile_likes(like)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        description = 'Percentage of records having {} less than or '.format(
            hist) + 'equal to value measured in {}'.format(unit)
        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.items():
            if namespace not in namespaces or not node_data or \
               isinstance(node_data, Exception):
                continue

            this_title = '{} - {} in {}{}'.format(
                namespace, title, unit, title_suffix)
            sources = dict(
                prefixes=cluster.get_node_names(mods.get('with', [])),
                histogram=dict((k, d['percentiles'])
                               for k, d in node_data.items())
            )

            CliView.print_result(
                sheet.render(templates.distribution_sheet, this_title, sources,
                             description=description))

    @staticmethod
    def show_object_distribution(
            title, histogram, unit, hist, bucket_count, set_bucket_count,
            cluster, like=None, timestamp="", loganalyser_mode=False, **mods):
        prefixes = cluster.get_node_names(mods.get('with', []))
        likes = compile_likes(like)
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        description = "Number of records having {} in the range ".format(
            hist) + "measured in {}".format(unit)
        namespaces = set(filter(likes.search, histogram.keys()))

        for namespace, node_data in histogram.items():
            if namespace not in namespaces:
                continue

            ns_title = "{} - {} in {}{}".format(
                namespace, title, unit, title_suffix)
            sources = dict(
                prefixes=prefixes,
                histogram={h: d.get('data', {})
                           for h, d in node_data.items()
                           if h != 'columns'})

            CliView.print_result(sheet.render(
                templates.object_size_sheet, ns_title, sources,
                description=description))

    @staticmethod
    def _update_latency_column_list(data, all_columns):
        if not data or "columns" not in data or not data["columns"]:
            return

        for column in data["columns"]:
            if column[0] == '>':
                c = int(column[1:-2])
                all_columns.add((c, (column, "%%>%dMs" % c)))
            elif column[0:2] == "%>":
                c = int(column[2:-2])
                all_columns.add((c, column))

    @staticmethod
    def _create_latency_row(data, ns=" "):
        if not data or "columns" not in data or not data["columns"] or \
           "values" not in data or not data["values"]:
            return

        rows = []
        columns = data.pop("columns", None)

        for _values in data["values"]:
            row = dict(zip(columns, _values))
            row['namespace'] = ns
            rows.append(row)

        return rows

    @staticmethod
    def format_latency(orig_latency):
        # XXX - eventually, node.py could return this format. Changing here
        #       because loganalyser also sends this format.
        latency = {}

        for hist, nodes_data in orig_latency.items():
            for node, node_data in nodes_data.items():
                node_latency = latency[node] = latency.get(node, OrderedDict())

                for ns, ns_data in node_data['namespace'].items():
                    for slice_id, values in enumerate(ns_data['values']):
                        node_latency[(ns, hist, slice_id)] = OrderedDict(zip(
                            ns_data['columns'], values))

        return latency

    @staticmethod
    def show_latency(latency, cluster, machine_wise_display=False,
                     like=None, timestamp="", **mods):
        if machine_wise_display:
            return CliView.show_latency_machine_wise(
                latency, cluster, like=like, timestamp=timestamp, **mods)

        # TODO - May not need to converter now that dicts can be nested.

        prefixes = cluster.get_node_names(mods.get('with', []))
        likes = compile_likes(like)
        title = 'Latency ' + CliView._get_timestamp_suffix(timestamp)
        keys = set(filter(likes.search, latency.keys()))
        latency = {k: v for k, v in latency.items() if k in keys}
        latency = CliView.format_latency(latency)

        sources = dict(prefixes=prefixes, histogram=latency)

        CliView.print_result(sheet.render(
            templates.latency_sheet, title, sources))


    def format_latency_machine_wise(orig_latency):
        latency = {}

        for node, node_data in orig_latency.items():
            for hist, hist_data in node_data.items():
                node_latency = latency[node] = latency.get(node, OrderedDict())
                for ns, ns_data in hist_data['namespace'].items():
                    for slice_id, values in enumerate(ns_data['values']):
                        node_latency[(ns, hist, slice_id)] = OrderedDict(zip(
                            ns_data['columns'], values))

        return latency

    @staticmethod
    def show_latency_machine_wise(latency, cluster, like=None, timestamp="",
                                  **mods):
        prefixes = cluster.get_node_names(mods.get('with', []))
        likes = compile_likes(like)
        title = 'Latency ' + CliView._get_timestamp_suffix(timestamp)
        keys = set(filter(likes.search, latency.keys()))
        latency = {k: v for k, v in latency.items() if k in keys}
        latency = CliView.format_latency_machine_wise(latency)

        sources = dict(prefixes=prefixes, histogram=latency)

        CliView.print_result(sheet.render(
            templates.latency_machine_wise_sheet, title, sources))

    @staticmethod
    def show_config(title, service_configs, cluster, like=None, diff=False,
                    show_total=False, title_every_nth=0, flip_output=False,
                    timestamp="", **mods):
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = title + title_suffix
        sources = dict(
            prefixes=cluster.get_node_names(mods.get('with', [])),
            data=service_configs)
        disable_aggregations = not show_total
        style = SheetStyle.columns if flip_output else None

        CliView.print_result(
            sheet.render(
                templates.config_sheet, title, sources, style=style,
                selectors=like, title_repeat=title_every_nth != 0,
                disable_aggregations=disable_aggregations, dynamic_diff=diff))

    @staticmethod
    def show_stats(*args, **kwargs):
        CliView.show_config(*args, **kwargs)

    @staticmethod
    def show_health(*args, **kwargs):
        CliView.show_config(*args, **kwargs)

    @staticmethod
    def show_xdr5_config(title, service_configs, cluster, like=None, diff=None, show_total=True, title_every_nth=0, flip_output=False, timestamp="", col_header="", **mods):
        # print_dict(service_configs)
        prefixes = cluster.get_node_names(mods.get('with', []))

        title = 'XDR Configuration'
        sources = dict(prefixes=prefixes, data=service_configs['xdr_configs'])
        CliView.print_result(
            sheet.render(
                templates.config_sheet, title, sources, dynamic_diff=diff))

        # service_configs['dc_configs']['aerospike_b']["174.22.0.3:3000"]['auth-mode'] = 'external'
        # service_configs['ns_configs']['aerospike_b']["174.22.0.3:3000"]['test']['enabled'] = 'false'
        for dc in service_configs['dc_configs']:
            title = 'DC Configuration for {}'.format(dc)
            sources = dict(prefixes=prefixes, data=service_configs['dc_configs'][dc])
            CliView.print_result(
                sheet.render(
                    templates.config_sheet, title, sources, dynamic_diff=diff))

        for dc in service_configs['ns_configs']:
            title = 'Namespace Configuration for {}'.format(dc)
            sources = dict(prefixes=prefixes, data=service_configs['ns_configs'][dc])
            CliView.print_result(
                sheet.render(
                    templates.config_xdr_ns_sheet, title, sources, disable_aggregations=False, dynamic_diff=diff))

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
                templates.grep_count_sheet, title,
                dict(data=grep_result, node_ids=node_ids),
                title_repeat=title_every_nth != 0))

    @staticmethod
    def show_grep_diff(title, grep_result, title_every_nth=0, like=None, diff=None, **ignore):
        column_names = set()
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
                list(grep_result[list(grep_result.keys())[0]]["value"].keys()))

        if len(column_names) == 0:
            return ''

        column_names.insert(0, ".")
        column_names.insert(0, "NODE")

        t = Table(title, column_names,
                  title_format=TitleFormats.no_change, style=Styles.VERTICAL)

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

            row1['NODE'] = file
            row1['.'] = "Total"

            row2['NODE'] = "."
            row2['.'] = "Diff"

            row3['NODE'] = "|"
            row3['.'] = "|"

            t.insert_row(row1)
            t.insert_row(row2)
            t.insert_row(row3)

        t.ignore_sort()

        CliView.print_result(
            t.__str__(horizontal_title_every_nth=title_every_nth * 3))

        if different_writer_info:
            print("\n" + terminal.fg_red() + "Input Key is not uniq, multiple writer instance (server_file:line_no) found." + terminal.fg_clear())

    @staticmethod
    def _sort_list_with_string_and_datetime(keys):
        if not keys:
            return keys

        dt_list = []
        remove_list = []

        for key in keys:
            try:
                dt_list.append(datetime.datetime.strptime(key, DT_FMT))
                remove_list.append(key)
            except Exception:
                pass

        for rm_key in remove_list:
            keys.remove(rm_key)

        if keys:
            keys = sorted(keys)

        if dt_list:
            dt_list = [k.strftime(DT_FMT) for k in sorted(dt_list)]

        if keys and not dt_list:
            return keys

        if dt_list and not keys:
            return dt_list

        dt_list.extend(keys)
        return dt_list

    @staticmethod
    def show_log_latency(title, grep_result, title_every_nth=0, like=None, diff=None, **ignore):
        column_names = set()
        tps_key = ("ops/sec", None)
        last_unit = None
        current_unit = None
        units_have_changed = False

        if grep_result:
            # find column names
            if grep_result[list(grep_result.keys())[0]]:
                column_names = CliView._sort_list_with_string_and_datetime(
                    list(grep_result[list(grep_result.keys())[0]][tps_key].keys()))

        if len(column_names) == 0:
            return ''

        column_names.insert(0, ".")
        column_names.insert(0, "NODE")

        t = Table(title, column_names,
                  title_format=TitleFormats.no_change, style=Styles.VERTICAL)

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
                        row['NODE'] = file
                        is_first = False
                    else:
                        row['NODE'] = "."

                    row['.'] = "%% >%d%s" % (key, unit)
                    t.insert_row(row)

                row = grep_result[file][tps_key]
                row['NODE'] = "."
                row['.'] = tps_key[0]
                t.insert_row(row)

                for stat in relative_stats_columns:
                    row = grep_result[file][stat]
                    row['NODE'] = "."
                    row['.'] = stat[0]
                    t.insert_row(row)

                row = {}

                for key in grep_result[file][tps_key].keys():
                    row[key] = "|"

                row['NODE'] = "|"
                row['.'] = "|"
                t.insert_row(row)

        t.ignore_sort()
        CliView.print_result(t.__str__(
            horizontal_title_every_nth=title_every_nth * (sub_columns_per_column + 1)))

        if units_have_changed:
            CliView.print_result('WARNING: asadm stopped early because latency units have changed from %s to %s.' % (last_unit, current_unit))
            CliView.print_result("Use 'histogram -h <histogram> -f <datetime> to bypass this problem.")
            return False

        return True

    @staticmethod
    def show_mapping(col1, col2, mapping, like=None, timestamp="", **ignore):
        if not mapping:
            return

        if like:
            likes = compile_likes(like)
            filtered_keys = set(filter(likes.search, mapping.keys()))
        else:
            filtered_keys = set(mapping.keys())

        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = "{} to {} Mappings{}".format(col1, col2, title_suffix)
        sources = dict(mapping=dict(
            enumerate((k, v) for k, v in mapping.items()
                      if k in filtered_keys)))

        if col2 == 'IPs':
            map_sheet = templates.mapping_to_ip_sheet
        else:
            map_sheet = templates.mapping_to_id_sheet

        CliView.print_result(sheet.render(map_sheet, title, sources))

    @staticmethod
    def show_pmap(pmap_data, cluster, timestamp='', **mods):
        prefixes = cluster.get_node_names(mods.get('with', []))
        title_suffix = CliView._get_timestamp_suffix(timestamp)
        title = 'Partition Map Analysis' + title_suffix
        sources = dict(
            prefixes=prefixes,
            node_ids=dict(((k, cluster.get_node(k)[0].node_id)
                           for k in prefixes.keys())),
            pmap=pmap_data
        )
        common = dict(principal=cluster.get_expected_principal())

        CliView.print_result(sheet.render(templates.pmap_sheet, title, sources,
                                          common=common))

    @staticmethod
    def asinfo(results, line_sep, show_node_name, cluster, **mods):
        like = set([])

        if 'like' in mods:
            like = set(mods['like'])

        for node_id, value in results.items():
            if show_node_name:
                prefix = cluster.get_node_names(mods.get('with', []))[node_id]
                node = cluster.get_node(node_id)[0]
                print("%s%s (%s) returned%s:" % (terminal.bold(), prefix, node.ip, terminal.reset()))

            if isinstance(value, Exception):
                print("%s%s%s" % (terminal.fg_red(), value, terminal.reset()))
                print("\n")
            else:
                if isinstance(value, str):
                    delimiter = find_delimiter_in(value)
                    value = value.split(delimiter)

                    if like:
                        likes = compile_likes(like)
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

            if group == '\033':
                i += 1

                while i < len(output):
                    group = group + output[i]
                    if output[i] == 'm':
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
    def watch(ctrl, line):
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

        try:
            real_stdout = sys.stdout
            sys.stdout = mystdout = StringIO()
            previous = None
            count = 1

            while True:
                highlight = False
                ctrl.execute(line[:])
                output = mystdout.getvalue()
                mystdout.truncate(0)
                mystdout.seek(0)

                if previous and diff_highlight:
                    result = []
                    prev_iterator = CliView.group_output(previous)
                    next_peeked = []
                    next_iterator = CliView.group_output(output)
                    next_iterator = CliView.peekable(
                        next_peeked, next_iterator)

                    for prev_group in prev_iterator:
                        if '\033' in prev_group:
                            # skip prev escape seq
                            continue

                        for next_group in next_iterator:
                            if '\033' in next_group:
                                # add current escape seq
                                result += next_group
                                continue
                            elif next_group == '\n':
                                if prev_group != '\n':
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

                            if '\n' == prev_group and '\n' != next_group:
                                continue
                            break

                    for next_group in next_iterator:
                        if next_group == ' ' or next_group == '\n':
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
                st = datetime.datetime.fromtimestamp(
                    ts).strftime(' %Y-%m-%d %H:%M:%S')
                command = " ".join(line)
                print("[%s '%s' sleep: %ss iteration: %s" % (
                    st, command, sleep, count), end=' ', file=real_stdout)
                if num_iterations:
                    print(" of %s" % (num_iterations), end=' ', file=real_stdout)
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
            print('')

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
            print(terminal.fg_red() + terminal.bold() + str(header) + " ::\n" + terminal.unbold() + terminal.fg_clear())
        for d in data:
            CliView._print_data(d)
            print("")

    @staticmethod
    def _print_status(status_counters, verbose=False):
        if not status_counters:
            return
        s = "\n" + terminal.bold() + "Summary".center(H_width, "_") + terminal.unbold()
        s += "\n" + CliView._get_header("Total") + CliView._get_msg([str(status_counters[HealthResultCounter.ASSERT_QUERY_COUNTER])])
        s += CliView._get_header("Passed") + CliView._get_msg([str(status_counters[HealthResultCounter.ASSERT_PASSED_COUNTER])])
        s += CliView._get_header("Failed") + CliView._get_msg([str(status_counters[HealthResultCounter.ASSERT_FAILED_COUNTER])])
        s += CliView._get_header("Skipped") + CliView._get_msg([str(status_counters[HealthResultCounter.ASSERT_QUERY_COUNTER]
                                                        - status_counters[HealthResultCounter.ASSERT_FAILED_COUNTER]
                                                        - status_counters[HealthResultCounter.ASSERT_PASSED_COUNTER])])
        print(s)

    @staticmethod
    def _print_debug_messages(ho):
        try:
            for d in ho[HealthResultType.DEBUG_MESSAGES]:
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
            for e in ho[HealthResultType.EXCEPTIONS]:
                try:
                    CliView._print_counter_list(
                        data=ho[HealthResultType.EXCEPTIONS][e],
                        header="%s Exceptions" % (e.upper()))
                except Exception:
                    pass
        except Exception:
            pass

    @staticmethod
    def _get_header(header):
        return "\n" + terminal.bold() + ("%s:" % header).rjust(H1_offset) + \
            terminal.unbold() + " ".rjust(H2_offset - H1_offset)

    @staticmethod
    def _get_msg(msg, level=None):
        if level is not None:
            if level == AssertLevel.WARNING:
                return terminal.fg_blue() + ("\n" + " ".rjust(
                    H2_offset)).join(msg) + terminal.fg_clear()
            elif level == AssertLevel.INFO:
                return terminal.fg_green() + ("\n" + " ".rjust(
                    H2_offset)).join(msg) + terminal.fg_clear()
            else:
                return terminal.fg_red() + ("\n" + " ".rjust(
                    H2_offset)).join(msg) + terminal.fg_clear()
        else:
            return ("\n" + " ".rjust(H2_offset)).join(msg)

    @staticmethod
    def _format_value(val, formatting=True):
        if not val or not formatting:
            return val

        if isinstance(val, int):
            try:
                # For python 2.7
                return str(format(val, ',d'))
            except Exception:
                try:
                    # For python 2.6
                    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
                    return str(locale.format('%d', val, True))

                except Exception:
                    pass
        elif isinstance(val, float):
            return_val = None

            try:
                # For python 2.7
                return_val = format(val, ',f')
            except Exception:
                try:
                    # For python 2.6
                    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
                    return_val = locale.format('%f', val, True)
                except Exception:
                    pass

            if return_val is not None:
                return_val = str(return_val)

                if '.' in return_val:
                    return_val = return_val.rstrip('0')
                    return_val = return_val.rstrip('.')

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
                            _str += ", " + ("%s:" % (str(
                                _kv[0])) if len(str(
                                    _kv[0]).strip()) > 0 else "") + \
                                "%s" % (CliView._format_value(_kv[1], _kv[2]))
                        except Exception:
                            _str = ("%s:" % (str(
                                _kv[0])) if len(str(
                                    _kv[0]).strip()) > 0 else "") + \
                                "%s" % (CliView._format_value(_kv[1], _kv[2]))

                if _str:
                    tmp_res_str += " {%s}" % (_str)

            if tmp_res_str:
                res_str.append(tmp_res_str)

        return res_str

    @staticmethod
    def _get_error_string(data, verbose=False, level=AssertLevel.CRITICAL):
        if not data:
            return "", 0

        f_msg_str = ""
        f_msg_cnt = 0
        s_msg_str = ""
        s_msg_cnt = 0

        for d in data:
            s = ""

            if d[AssertResultKey.LEVEL] == level:

                if d[AssertResultKey.SUCCESS]:
                    if d[AssertResultKey.SUCCESS_MSG]:

                        s_msg_str += CliView._get_header(
                            d[AssertResultKey.CATEGORY][0]) + \
                            CliView._get_msg([d[AssertResultKey.SUCCESS_MSG]])
                        s_msg_cnt += 1

                    continue

                s += CliView._get_header(d[AssertResultKey.CATEGORY][0]) + \
                    CliView._get_msg([d[AssertResultKey.FAIL_MSG]], level)

                if verbose:
                    import textwrap

                    s += "\n"
                    s += CliView._get_header("Description:")
                    s += CliView._get_msg(textwrap.wrap(
                        str(d[AssertResultKey.DESCRIPTION]),
                        H_width - H2_offset,
                        break_long_words=False, break_on_hyphens=False))
                    s += "\n"
                    s += CliView._get_header("Keys:")
                    s += CliView._get_msg(CliView._get_kv_msg_list(
                        d[AssertResultKey.KEYS]))

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
    def _get_assert_output_string(assert_out, verbose=False,
                                  output_filter_category=[],
                                  level=AssertLevel.CRITICAL):
        if not assert_out:
            return ""

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
                        category = output_filter_category[1:] if len(
                            output_filter_category) > 1 else []
                    else:
                        category = output_filter_category

                f_msg_str, f_msg_cnt, s_msg_str, s_msg_cnt = CliView._get_assert_output_string(
                    assert_out[_k], verbose, category, level=level)

                res_fail_msg_str += f_msg_str
                total_fail_msg_cnt += f_msg_cnt
                res_success_msg_str += s_msg_str
                total_success_msg_cnt += s_msg_cnt

        return res_fail_msg_str, total_fail_msg_cnt, res_success_msg_str, total_success_msg_cnt

    @staticmethod
    def _print_assert_summary(assert_out, verbose=False,
                              output_filter_category=[],
                              output_filter_warning_level=None):
        if not output_filter_warning_level:
            search_levels = [AssertLevel.INFO, AssertLevel.WARNING,
                             AssertLevel.CRITICAL]
        elif output_filter_warning_level == "CRITICAL":
            search_levels = [AssertLevel.CRITICAL]
        elif output_filter_warning_level == "WARNING":
            search_levels = [AssertLevel.WARNING]
        elif output_filter_warning_level == "INFO":
            search_levels = [AssertLevel.INFO]
        else:
            search_levels = [AssertLevel.INFO, AssertLevel.WARNING,
                             AssertLevel.CRITICAL]

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
                        category = output_filter_category[1:] if len(
                            output_filter_category) > 1 else []
                    else:
                        category = output_filter_category

                f_msg_str, f_msg_cnt, s_msg_str, s_msg_cnt = \
                    CliView._get_assert_output_string(
                        assert_out[_k], verbose, category, level=level)

                if f_msg_str:
                    total_fail_msg_cnt += f_msg_cnt
                    res_fail_msg_str += f_msg_str

                if s_msg_str:
                    total_success_msg_cnt += s_msg_cnt
                    res_success_msg_str += s_msg_str

            if total_fail_msg_cnt > 0:
                summary_str = ""

                if level == AssertLevel.CRITICAL:
                    summary_str = terminal.bold() + terminal.fg_red() + \
                        "CRITICAL".center(H_width, " ") + \
                        terminal.fg_clear() + terminal.unbold()
                elif level == AssertLevel.WARNING:
                    summary_str = terminal.bold() + terminal.fg_blue() + \
                        "WARNING".center(H_width, " ") + \
                        terminal.fg_clear() + terminal.unbold()
                elif level == AssertLevel.INFO:
                    summary_str = terminal.bold() + terminal.fg_green() + \
                        "INFO".center(H_width, " ") + \
                        terminal.fg_clear() + terminal.unbold()

                all_fail_str += "\n" + summary_str + "\n" + res_fail_msg_str + "\n"
                all_fail_cnt += total_fail_msg_cnt

            if total_success_msg_cnt > 0:
                all_success_str += res_success_msg_str
                all_success_cnt += total_success_msg_cnt

        if all_success_cnt > 0:
            print("\n\n" + terminal.bold() + str(" %s: count(%d) " %("PASS", all_success_cnt)).center(H_width, "_") + terminal.unbold())
            print(all_success_str)

        if all_fail_cnt > 0:
            print("\n\n" + terminal.bold() + str(" %s: count(%d) " %("FAIL", all_fail_cnt)).center(H_width, "_") + terminal.unbold())
            print(all_fail_str)

        print("_" * H_width + "\n")

    @staticmethod
    def print_health_output(ho, verbose=False, debug=False, output_file=None,
                            output_filter_category=[],
                            output_filter_warning_level=None):
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
            ho[HealthResultType.STATUS_COUNTERS], verbose=verbose)
        CliView._print_assert_summary(
            ho[HealthResultType.ASSERT], verbose=verbose,
            output_filter_category=output_filter_category,
            output_filter_warning_level=output_filter_warning_level)

        if o_s:
            o_s.close()
        sys.stdout = sys.__stdout__

###########################

    @staticmethod
    def get_summary_line_prefix(index, key):
        s = " " * 3
        s += str(index)
        s += "." + (" " * 3)
        s += key.ljust(19)
        s += ":" + (" " * 2)
        return s

    @staticmethod
    def _summary_namespace_table_view(stats, **ignore):
        title = "Namespaces"
        # column_names = ('namespace', ('_devices', 'Devices (Total,Per-Node)'), ('_memory', 'Memory (Total,Used%,Avail%)'),
        #                 ('_disk', 'Disk (Total,Used%,Avail%)'), ('repl_factor', 'Replication Factor'), ('cache_read_pct','Post-Write-Queue Hit-Rate'),
        #                 'rack_aware', ('master_objects', 'Master Objects'),
        #                 'compression_ratio'
        #                 )

        # license_data_in_memory = False
        # license_data_on_disk = False

        # for _, ns_stats in stats.items():
        #     try:
        #         if not license_data_in_memory and ns_stats['license_data_in_memory']:
        #             license_data_in_memory = True
        #         elif not license_data_on_disk and ns_stats['license_data_on_disk']:
        #             license_data_on_disk = True
                
        #         if license_data_in_memory and license_data_on_disk:
        #             break
        #     except KeyError:
        #         pass

        # if license_data_in_memory:
        #     column_names = column_names + ('Usage (Unique-Data) In-Memory',)
        # if license_data_on_disk:
        #    column_names = column_names + ('Usage (Unique-Data) On-Device',)

        # t = Table(title, column_names, sort_by=0)

        # if license_data_in_memory:
        #     t.add_data_source(
        #         'Usage (Unique-Data) In-Memory',
        #         Extractors.byte_extractor('license_data_in_memory')
        #     )
        # if license_data_on_disk:
        #     t.add_data_source(
        #         'Usage (Unique-Data) On-Device',
        #         Extractors.byte_extractor('license_data_on_disk')
        #     )

        # t.add_cell_alert(
        #     'namespace',
        #     lambda data: data['migrations_in_progress'],
        #     color=terminal.fg_red
        # )

        # t.add_data_source_tuple(
        #     '_devices',
        #     lambda data:str(data['devices_total']),
        #     lambda data:str(data['devices_per_node']))

        # t.add_data_source_tuple(
        #     '_memory',
        #     Extractors.byte_extractor('memory_total'),
        #     lambda data:"%.2f"%data["memory_used_pct"],
        #     lambda data:"%.2f"%data["memory_available_pct"])

        # t.add_data_source_tuple(
        #     '_disk',
        #     Extractors.byte_extractor('disk_total'),
        #     lambda data:"%.2f"%data["disk_used_pct"],
        #     lambda data:"%.2f"%data["disk_available_pct"])

        # t.add_data_source(
        #     'repl_factor',
        #     lambda data:",".join([str(rf) for rf in data["repl_factor"]])
        # )

        # t.add_data_source(
        #     'master_objects',
        #     Extractors.sif_extractor('master_objects')
        # )

        # for ns, ns_stats in stats.items():
        #     if isinstance(ns_stats, Exception):
        #         row = {}
        #     else:
        #         row = ns_stats

        #     row['namespace'] = ns
        #     row['memory_used_pct'] = 100.00 - row['memory_available_pct']

        new_stats = dict(node_hack=stats)  # XXX - hack
        sources = dict(ns_stats=new_stats)

        CliView.print_result(
            sheet.render(templates.summary_namespace_sheet, title, sources))

    @staticmethod
    def _summary_namespace_list_view(stats, **ignore):
        print("Namespaces")
        print("==========")
        print()
        for ns in stats:
            index = 1
            print("   " + ("%s"%(terminal.fg_red() + ns + terminal.fg_clear())
                           if stats[ns]["migrations_in_progress"] else ns))
            print("   " + "=" * len(ns))

            print(CliView.get_summary_line_prefix(index, "Devices") + "Total %d, per-node %d%s"%(
                stats[ns]["devices_total"], stats[ns]["devices_per_node"],
                " (number differs across nodes)" if not stats[ns]["devices_count_same_across_nodes"] else ""))
            index += 1

            print(CliView.get_summary_line_prefix(index, "Memory") + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"%(
                filesize.size(stats[ns]["memory_total"]).strip(), 100.00 - stats[ns]["memory_available_pct"],
                filesize.size(stats[ns]["memory_total"] - stats[ns]["memory_aval"]).strip(),
                stats[ns]["memory_available_pct"], filesize.size(stats[ns]["memory_aval"]).strip()))
            index += 1

            if stats[ns]["disk_total"]:
                print(CliView.get_summary_line_prefix(index, "Disk") + "Total %s, %.2f%% used (%s), %.2f%% available contiguous space (%s)"%(
                    filesize.size(stats[ns]["disk_total"]).strip(), stats[ns]["disk_used_pct"],
                    filesize.size(stats[ns]["disk_used"]).strip(), stats[ns]["disk_available_pct"],
                    filesize.size(stats[ns]["disk_aval"]).strip()))
                index += 1

            print(CliView.get_summary_line_prefix(index, "Replication Factor") + "%s"%(",".join([str(rf) for rf in stats[ns]["repl_factor"]])))
            index += 1

            if "cache_read_pct" in stats[ns]:
                print(CliView.get_summary_line_prefix(index, "Post-Write-Queue Hit-Rate") + "%s"%(filesize.size(stats[ns]["cache_read_pct"], filesize.sif)))
                index += 1

            if "rack_aware" in stats[ns]:
                print(CliView.get_summary_line_prefix(index, "Rack-aware") + "%s"%(str(stats[ns]["rack_aware"])))
                index += 1

            print(CliView.get_summary_line_prefix(index, "Master Objects") + "%s"%(filesize.size(stats[ns]["master_objects"], filesize.sif)))
            index += 1
            s = ""

            if "license_data_in_memory" in stats[ns] and stats[ns]["license_data_in_memory"]:
                s += "%s in-memory"%(filesize.size(stats[ns]["license_data_in_memory"]))
            elif "license_data_on_disk" in stats[ns] and stats[ns]["license_data_on_disk"]:
                if s:
                    s += ", "
                s += "%s on-device"%(filesize.size(stats[ns]["license_data_on_disk"]))
            else:
                s += "None"
            print(CliView.get_summary_line_prefix(index, "Usage (Unique Data)") + s)
            index += 1

            if "compression_ratio" in stats[ns]:
                print(CliView.get_summary_line_prefix(index, "Compression-ratio") + "%s"%(str(stats[ns]["compression_ratio"])))
                index += 1
            print()

    @staticmethod
    def print_summary(summary, list_view=True):
        index = 1
        print("Cluster" + ("  (%s)"%(terminal.fg_red() + "Migrations in Progress" + terminal.fg_clear())
                           if summary["CLUSTER"]["migrations_in_progress"] else ""))
        print("=======" + ("==========================" if summary["CLUSTER"]["migrations_in_progress"] else ""))
        print()

        if "cluster_name" in summary["CLUSTER"] and len(summary["CLUSTER"]["cluster_name"]) > 0:
            print(CliView.get_summary_line_prefix(index, "Cluster Name") + ", ".join(summary["CLUSTER"]["cluster_name"]))
            index += 1

        print(CliView.get_summary_line_prefix(index, "Server Version") + ", ".join(summary["CLUSTER"]["server_version"]))
        index += 1

        print(CliView.get_summary_line_prefix(index, "OS Version") + ", ".join(summary["CLUSTER"]["os_version"]))
        index += 1

        print(CliView.get_summary_line_prefix(index, "Cluster Size") + ", ".join([str(cs) for cs in summary["CLUSTER"]["cluster_size"]]))
        index += 1

        print(CliView.get_summary_line_prefix(index, "Devices") + "Total %d, per-node %d%s"%(
            summary["CLUSTER"]["device"]["count"], summary["CLUSTER"]["device"]["count_per_node"],
            " (number differs across nodes)" if not summary["CLUSTER"]["device"]["count_same_across_nodes"] else ""))
        index += 1

        print(CliView.get_summary_line_prefix(index, "Memory") + "Total %s, %.2f%% used (%s), %.2f%% available (%s)"%(
            filesize.size(summary["CLUSTER"]["memory"]["total"]).strip(), 100.00 - summary["CLUSTER"]["memory"]["aval_pct"],
            filesize.size(summary["CLUSTER"]["memory"]["total"] - summary["CLUSTER"]["memory"]["aval"]).strip(),
            summary["CLUSTER"]["memory"]["aval_pct"], filesize.size(summary["CLUSTER"]["memory"]["aval"]).strip()))
        index += 1

        print(CliView.get_summary_line_prefix(index, "Disk") + "Total %s, %.2f%% used (%s), %.2f%% available contiguous space (%s)"%(
            filesize.size(summary["CLUSTER"]["device"]["total"]).strip(), summary["CLUSTER"]["device"]["used_pct"],
            filesize.size(summary["CLUSTER"]["device"]["used"]).strip(), summary["CLUSTER"]["device"]["aval_pct"],
            filesize.size(summary["CLUSTER"]["device"]["aval"]).strip()))
        index += 1

        data_summary = CliView.get_summary_line_prefix(index, "Usage (Unique Data)")
        uniq_mem_used = summary["CLUSTER"]["license_data"]["memory_size"]
        uniq_device_used = summary["CLUSTER"]["license_data"]["device_size"]
        
        # Sum all "Usage" data whether on disk or in memory.
        if uniq_mem_used or uniq_device_used:
            total = 0

            if uniq_mem_used:
                total += uniq_mem_used
            if uniq_device_used:
                total += uniq_device_used

            data_summary += "%s"%filesize.size(total)

        else:
            data_summary += "None"

        print(data_summary)
        index += 1

        print(CliView.get_summary_line_prefix(index, "Active Namespaces") + "%d of %d"%(summary["CLUSTER"]["active_ns"], summary["CLUSTER"]["ns_count"]))
        index += 1

        print(CliView.get_summary_line_prefix(index, "Features") + ", ".join(sorted(summary["CLUSTER"]["active_features"])))

        print("\n")

        if list_view:
            CliView._summary_namespace_list_view(
                summary["FEATURES"]["NAMESPACE"])
        else:
            CliView._summary_namespace_table_view(summary["FEATURES"]["NAMESPACE"])

