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

from enum import Enum, unique
import re

from lib.utils import file_size
from lib.view import terminal


class Extractors:
    # standard set of extractors

    @staticmethod
    def _num_extractor(columns, system):
        if not isinstance(columns, tuple):
            columns = (columns,)

        def si_extractor(data):
            found = False
            for column in columns:
                if column in data:
                    found = True
                    break
            if not found:
                return "N/E"
            if system == int:
                return int(data[column])
            elif system == float:
                return float(data[column])
            else:
                return file_size.size(int(data[column]), system)

        return si_extractor

    @staticmethod
    def float_extractor(columns):
        return Extractors._num_extractor(columns, float)

    @staticmethod
    def int_extractor(columns):
        return Extractors._num_extractor(columns, int)

    @staticmethod
    def sif_extractor(columns):
        return Extractors._num_extractor(columns, file_size.si_float)

    @staticmethod
    def si_extractor(columns):
        return Extractors._num_extractor(columns, file_size.si)

    @staticmethod
    def byte_extractor(columns):
        return Extractors._num_extractor(columns, file_size.byte)

    @staticmethod
    def time_extractor(columns):
        if not isinstance(columns, tuple):
            columns = (columns,)

        def t_extractor(data):
            for column in columns:
                if column in data:
                    break

            time_stamp = int(data[column])
            hours = time_stamp // 3600
            minutes = (time_stamp % 3600) // 60
            seconds = time_stamp % 60

            return "%02d:%02d:%02d" % (hours, minutes, seconds)

        return t_extractor


class TitleFormats:
    @staticmethod
    def var_to_title(name):
        rename = re.split("[\-_ ]", name)
        rename = " ".join([w.title() for w in rename]).strip()
        return rename.replace(" Pct", "%")

    @staticmethod
    def no_change(name):
        return name.strip()


@unique
class Orientation(Enum):
    # Styles
    HORIZONTAL = 0
    VERTICAL = 1


@unique
class ColumnNameAlign(Enum):
    LEFT = 0
    CENTER = 1
    RIGHT = 2


class Table:
    def __init__(
        self,
        title,
        column_names,
        sort_by=0,
        group_by=None,
        orientation=Orientation.HORIZONTAL,
        title_format=TitleFormats.var_to_title,
        column_align=ColumnNameAlign.RIGHT,
        description="",
        n_last_columns_ignore_sort=0,
    ):

        self._data = []
        self._need_sort = False
        self._data_source = {}
        self._no_alert_style = lambda: ""
        self._cell_alert = {}
        self._column_padding = "   "
        self._no_entry = "N/E"

        self._title = title
        self._group_by = group_by
        self._orientation = orientation
        self._description = description
        self._n_last_columns_ignore_sort = n_last_columns_ignore_sort

        self._column_names = []
        self._column_display_names = []
        self._render_column_ids = set()
        self._column_align_func = None

        if column_align == ColumnNameAlign.RIGHT:
            self._column_align_func = "rjust"
        elif column_align == ColumnNameAlign.LEFT:
            self._column_align_func = "ljust"
        else:
            self._column_align_func = "center"

        for name in column_names:
            if isinstance(name, str):
                self._column_names.append(name)
                self._column_display_names.append(title_format(name))
            elif type(name) == tuple or type(name) == list:
                self._column_names.append(name[0])
                self._column_display_names.append(name[1])

        if orientation == Orientation.HORIZONTAL:
            self._column_widths = [0 for _ in self._column_names]
        elif orientation == Orientation.VERTICAL:
            self._column_widths = []
        else:
            raise ValueError("Style must be either HORIZONTAL or VERTICAL")

        self._column_types = ["number" for _ in self._column_names]
        # column_types: 0 number, 1 string
        self._update_column_metadata(self._column_display_names, header=True)
        try:
            self._sort_by = column_names.index(sort_by)
        except ValueError:
            if sort_by < 0 or sort_by > len(column_names):
                raise ValueError("sort_by is not a legal value")
            self._sort_by = sort_by

    def _update_column_metadata(self, row, header=False):
        if self._orientation == Orientation.HORIZONTAL:
            for i in range(len(self._column_names)):
                if not header:
                    cell_format, cell = row[i]
                else:
                    cell = row[i]
                    # TODO - never used cell_format = self._no_alert_style

                if header:
                    max_length = max(map(len, cell.split(" ")))
                else:
                    max_length = len(cell)
                if self._column_widths[i] < max_length:
                    self._column_widths[i] = max_length
                if not header:
                    if not file_size.is_file_size(cell):
                        if cell != self._no_entry:
                            self._column_types[i] = "string"
        elif self._orientation == Orientation.VERTICAL:
            length = max([len(r[1]) if type(r) is tuple else len(r) for r in row])
            self._column_widths.append(length)
        else:
            raise ValueError("Style must be either HORIZONTAL or VERTICAL")

    def add_data_source(self, column, function):
        self._data_source[column] = function

    def ignore_sort(self, ignore=True):
        self._need_sort = not ignore

    def add_data_source_tuple(self, column, *functions, **kwargs):
        def tuple_extractor(data):
            args = []
            prior_trimmed = 0

            for function in functions:
                arg = function(data)
                orig_len = len(arg)
                arg = arg.rstrip()
                new_len = len(arg)
                trimmed = orig_len - new_len
                arg = arg.rjust(new_len + prior_trimmed)
                prior_trimmed = trimmed if trimmed != 0 else 1
                args.append(arg)

            return "(" + ",".join(args) + ")".ljust(prior_trimmed + 1)

        self._data_source[column] = tuple_extractor

    def add_cell_alert(self, column_name, is_alert, color=terminal.fg_red):
        self._cell_alert[column_name] = (is_alert, color)

    def insert_row(self, row_data):
        if not row_data:
            # passed an empty row
            return
        row = []
        if type(row_data) is not dict:
            raise ValueError("Data cannot be of type %s" % type(row_data))

        for i, column in enumerate(self._column_names):
            try:
                if column in self._data_source:
                    extractor = self._data_source[column]
                    cell = extractor(row_data)
                else:
                    cell = row_data[column]
                # column has actual data, let it render
                self._render_column_ids.add(i)
            except KeyError:  # extractor accessed n/e column
                cell = self._no_entry

            try:
                is_alert = False
                if column in self._cell_alert:
                    is_alert, color = self._cell_alert[column]

                if is_alert and is_alert(row_data):
                    cell = (color, cell)
                else:
                    cell = (self._no_alert_style, cell)
            except KeyError:  # is_alert accessed n/e column
                cell = (self._no_alert_style, cell)

            row.append(cell)

        for i, (cell_format, cell) in enumerate(row):
            if isinstance(cell, Exception):
                cell = "error"
            else:
                cell = str(cell)
            row[i] = (cell_format, cell)
        self._data.append(row)
        self._update_column_metadata(row)
        self._need_sort = True

    def _do_group(self, data):
        # requires data to be sorted
        if self._group_by is None:
            return data

        grouped_data = {}
        for row in data:
            group_by = row[self._group_by][1]
            if group_by not in grouped_data:
                grouped_data[group_by] = []

            grouped_data[group_by].append(row)

        data = []
        for group in sorted(grouped_data.keys()):
            data.extend(grouped_data[group])

        return data

    def _do_sort(self):
        if self._need_sort == True and self._n_last_columns_ignore_sort < len(
            self._data
        ):
            if self._n_last_columns_ignore_sort > 0:
                data_len = len(self._data)
                data_to_process = self._data[
                    0 : data_len - self._n_last_columns_ignore_sort
                ]
                fixed_data = self._data[
                    data_len - self._n_last_columns_ignore_sort : data_len
                ]
            else:
                data_to_process = self._data
                fixed_data = []

            if self._orientation == Orientation.HORIZONTAL:
                sorted_data = sorted(data_to_process, key=lambda d: d[self._sort_by][1])
                self._data = self._do_group(sorted_data)
                self._need_sort = False
            else:  # style is Vertical
                # Need to sort but messes with column widths
                transform = sorted(
                    range(len(data_to_process)),
                    key=lambda d: data_to_process[d][self._sort_by][1],
                )

                self._data = [data_to_process[i] for i in transform]
                first = self._column_widths[0]

                if self._n_last_columns_ignore_sort > 0:
                    fixed_column_widths = self._column_widths[
                        len(self._column_widths)
                        - self._n_last_columns_ignore_sort : len(self._column_widths)
                    ]
                else:
                    fixed_column_widths = []

                self._column_widths = [self._column_widths[i + 1] for i in transform]
                self._column_widths.insert(0, first)
                self._column_widths = self._column_widths + fixed_column_widths
                self._need_sort = False

            self._data = self._data + fixed_data

    def _gen_render_data(self, horizontal=True):
        self._render_column_display_names = []
        self._render_column_names = []
        self._render_column_widths = []
        self._render_column_types = []
        if self._orientation == Orientation.VERTICAL:
            self._render_column_widths = self._column_widths
        self._render_remap = {}
        for i, column in enumerate(self._column_display_names):
            if i in self._render_column_ids:
                self._render_column_display_names.append(self._column_display_names[i])
                if self._orientation == Orientation.HORIZONTAL:
                    self._render_column_widths.append(self._column_widths[i])
                self._render_column_names.append(self._column_names[i])
                self._render_column_types.append(self._column_types[i])
                self._render_remap[i] = len(self._render_column_names) - 1

    def gen_description(self, line_width, desc_width):
        if self._description == "":
            return []

        tdesc = self._description[:].split(" ")
        lines = []
        words = []
        while tdesc != []:
            words.append(tdesc.pop(0))
            line = " ".join(words)
            if len(line) >= desc_width:
                if len(words) > 1:
                    tdesc.insert(0, words.pop())
                    line = " ".join(words)
                words = []
                lines.append(line)
        else:
            if words:
                line = " ".join(words)
                lines.append(line)

        description = [
            "%s%s%s" % (terminal.dim(), l.center(line_width), terminal.reset())
            for l in lines
        ]
        description = "\n".join(description)

        return [
            description,
        ]

    def _get_title(self, title, width):
        if not title:
            return title

        t = title.center(width, "~")
        if t and len(t) > 0:
            if not t.startswith("~"):
                t = "~" + t
            if not t.endswith("~"):
                t += "~"
        return t

    def _get_horizontal_width(self, title_every_nth=0):
        width = sum(self._render_column_widths)
        total_repeat_titles = 0

        if title_every_nth:
            total_columns = (
                len(self._render_column_display_names) - 1
            )  # Ignoring first columns of Row Header
            total_repeat_titles = (total_columns - 1) // title_every_nth

        width += (
            total_repeat_titles * self._render_column_widths[0]
        )  # Width is same as first column
        width += len(self._column_padding) * (
            len(self._render_column_widths) + total_repeat_titles - 1
        )

        return width

    def _get_horizontal_header(self, title_every_nth=0):
        width = self._get_horizontal_width(title_every_nth)
        column_name_lines = [h.split(" ") for h in self._render_column_display_names]
        max_deep = max(map(len, column_name_lines))

        output = [terminal.bold()]
        output.append(self._get_title(self._title, width=width))
        output.append(terminal.reset())
        output = ["".join(output)]
        output.extend(self.gen_description(width, width - 10))

        for r in range(max_deep):
            row = []

            for i, c in enumerate(column_name_lines):
                if title_every_nth and (i - 1) > 0 and (i - 1) % title_every_nth == 0:
                    try:
                        row.append(
                            getattr(str, self._column_align_func)(
                                column_name_lines[0][r], self._render_column_widths[0]
                            )
                        )
                    except IndexError:
                        row.append(
                            getattr(str, self._column_align_func)(
                                ".", self._render_column_widths[0]
                            )
                        )
                    row.append(self._column_padding)

                try:
                    row.append(
                        getattr(str, self._column_align_func)(
                            c[r], self._render_column_widths[i]
                        )
                    )
                except IndexError:
                    row.append(
                        getattr(str, self._column_align_func)(
                            ".", self._render_column_widths[i]
                        )
                    )

                if i != len(column_name_lines) - 1:
                    row.append(self._column_padding)

            output.append(row)

        output = "\n".join(["".join(r) for r in output])
        return output

    def __str__(self, horizontal_title_every_nth=0):
        if len(self._render_column_ids) == 0:
            return ""
        if self._need_sort:
            self._do_sort()
        self._gen_render_data()

        if self._orientation == Orientation.HORIZONTAL:
            return self._str_horizontal(title_every_nth=horizontal_title_every_nth)
        elif self._orientation == Orientation.VERTICAL:
            return self._str_vertical(title_every_nth=horizontal_title_every_nth)
        else:
            raise ValueError(
                "Invalid style, must be either " + "table.HORIZONTAL or table.VERTICAL"
            )

    def _format_cell(self, cell, index):
        if self._render_column_types[index] == "number":
            cell = cell.rjust(self._render_column_widths[index])
        elif self._render_column_types[index] == "string":
            cell = cell.ljust(self._render_column_widths[index])
        else:
            raise ValueError(
                "Unknown column type: '%s'" % self._render_column_types[index]
            )
        return cell

    def _str_horizontal(self, title_every_nth=0):
        output = []
        output.append(self._get_horizontal_header(title_every_nth=title_every_nth))

        for drow in self._data:
            row = []
            title_cell_format = drow[0][0]
            title_cell = self._format_cell(drow[0][1], 0)

            for i, (cell_format, cell) in enumerate(drow):
                row.append(terminal.style(terminal.bg_clear, terminal.fg_clear))

                if i not in self._render_column_ids:
                    continue

                i = self._render_remap[i]

                if title_every_nth and i - 1 > 0 and (i - 1) % title_every_nth == 0:
                    row.append("%s%s" % (title_cell_format(), title_cell))
                    row.append(self._column_padding)

                cell = self._format_cell(cell, i)
                row.append("%s%s" % (cell_format(), cell))

                if i != len(drow) - 1:
                    row.append(self._column_padding)

            output.append("".join(row))

        output.append(
            "%sNumber of rows: %s"
            % (terminal.style(terminal.bg_clear, terminal.fg_clear), len(self._data))
        )
        return "\n".join(output) + "\n"

    def _str_vertical(self, title_every_nth=0):
        output = []
        title_width = []
        total_titles = 1
        if title_every_nth:
            total_columns = len(self._render_column_widths) - 1
            extra_header_columns = (total_columns - 1) // title_every_nth
            total_titles = extra_header_columns + 1  # 1 for default
        if total_titles > 1:
            slice_title_width = self._render_column_widths[0] + 1
            n_columns = 0
            for i, c_width in enumerate(self._render_column_widths[1:]):
                slice_title_width += c_width
                n_columns += 1
                if (i + 1) % title_every_nth == 0:
                    temp_width = slice_title_width
                    temp_width += len(self._column_padding) * (n_columns)
                    if i != len(self._render_column_widths) - 2:
                        temp_width += len(self._column_padding)
                    title_width.append(temp_width)
                    slice_title_width = self._render_column_widths[0] + 1
                    n_columns = 0
            if n_columns:
                temp_width = slice_title_width
                temp_width += len(self._column_padding) * (n_columns)
                title_width.append(temp_width)
        else:
            temp_width = sum(self._render_column_widths) + 1  # 1 for ":"
            temp_width += len(self._column_padding) * (
                len(self._render_column_widths) - 1
            )
            title_width.append(temp_width)

        output = [terminal.bold()]
        for t_width in title_width:
            output.append(self._get_title(self._title, width=t_width))
        output.append(terminal.reset())
        output = ["".join(output)]
        output.extend(self.gen_description(sum(title_width), sum(title_width) - 10))

        for i, column_name in enumerate(self._render_column_names):

            row = []
            row.append(terminal.style(terminal.bg_clear, terminal.fg_clear))

            column_title = column_name
            if column_name == "NODE":
                row.append(terminal.bold())
            row.append(column_title.ljust(self._render_column_widths[0]))
            row.append(":")
            row.append(self._column_padding)
            added_columns = 0

            for j, (cell_format, cell) in enumerate(
                (raw_data[i] for raw_data in self._data), 1
            ):

                if (
                    title_every_nth
                    and added_columns > 0
                    and added_columns % title_every_nth == 0
                ):
                    row.append(column_title.ljust(self._render_column_widths[0]))
                    row.append(":")
                    row.append(self._column_padding)
                cell = cell.ljust(self._render_column_widths[j])
                row.append("%s%s" % (cell_format(), cell))
                row.append(self._column_padding)
                added_columns += 1

            if column_name == "NODE":
                row.append(terminal.reset())
            output.append("".join(row))

        return "\n".join(output) + "\n"
