# Copyright 2013-2018 Aerospike, Inc.
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

from lib.view import terminal

from ..const import FieldAlignment
from .base_rsheet import BaseRField, BaseRSheet


class RowRSheet(BaseRSheet):
    # =========================================================================
    # Required overrides.

    def do_create_tuple_field(self, field, groups):
        raise NotImplementedError("Row styles doesn't support tuple fields")

    def do_create_field(self, field, groups, parent_key=None):
        return RFieldRow(self, field, groups, parent_key=parent_key)

    def do_render(self):
        rfields = self.visible_rfields

        if not rfields:
            return None

        n_records = self.n_records
        row_title_width = max(rfield.title_width for rfield in rfields)
        row_aggr_width = max(rfield.aggregate_widths[0] + 1
                             for rfield in rfields)
        column_widths = [max(rfield.widths[i] for rfield in rfields)
                         for i in range(n_records)]
        title_width = row_title_width + len(self.decl.separator) \
            + sum(column_widths) + (n_records - 1) * len(self.decl.separator) \
            + row_aggr_width

        render = []

        self._do_render_title(render, title_width)
        self._do_render_description(render, title_width, title_width - 10)

        # Render fields.
        n_groups = 0 if not rfields else rfields[0].n_groups

        # XXX - Add handling for more than one group.
        assert n_groups == 1

        # XXX - Add handling for Subgroups?

        has_aggregate = any(rfield.has_aggregate() for rfield in rfields)

        for rfield in rfields:
            row = [rfield.get_title(row_title_width)]

            for i in range(n_records):
                row.append(rfield.entry_cell(0, i, column_widths[i]))

            if has_aggregate:
                if rfield.has_aggregate():
                    row.append(rfield.aggregate_cell(0))
                else:
                    row.append("")

            render.append(self.decl.formatted_separator.join(row))

        self._do_render_n_rows(render, len(rfields))

        return "\n".join(render) + "\n"

    # =========================================================================
    # Other methods.

    def _get_column_width(self, column_idx):
        return max(
            rfield.widths[column_idx] for rfield in self.visible_rfields)

    def _do_render_title(self, render, width):
        filler = self.decl.title_fill

        t = self.title.center(width, filler)

        if len(t) > 0:
            if not t.startswith(filler):
                t = filler + t
            if not t.endswith(filler):
                t += filler

        t = terminal.bold() + t + terminal.unbold()

        render.append(t)

    def _do_render_description(self, render, line_width, desc_width):
        if self.description is None or self.description == '':
            return []

        tdesc = self.description[:].split(' ')
        lines = []
        words = []

        while tdesc != []:
            words.append(tdesc.pop(0))
            line = ' '.join(words)

            if len(line) >= desc_width:
                if len(words) > 1:
                    tdesc.insert(0, words.pop())
                    line = ' '.join(words)

                words = []
                lines.append(line)
        else:
            if words:
                line = ' '.join(words)
                lines.append(line)

        description = [terminal.dim() + l.center(line_width) + terminal.reset()
                       for l in lines]
        description = '\n'.join(description)

        render.append(description)

    def _do_render_row_titles(self, render):
        pass

    def _do_render_n_rows(self, render, n_rows):
        render.append(
            terminal.dim() + 'Number of rows: {}'.format(n_rows) +
            terminal.undim())


class RFieldRow(BaseRField):
    # =========================================================================
    # Optional overrides.

    def do_prepare(self):
        """prepare is called after all fields have been initialized."""
        self._do_prepare_find_widths()

    # =========================================================================
    # Other methods.

    def _do_prepare_find_widths(self):
        self.title_width = len(self.decl.title)
        self._do_prepare_find_aggregate_width()
        self.widths = []

        for group_converted in self.groups_converted:
            self.widths.extend(map(len, group_converted))

    def _do_prepare_find_aggregate_width(self):
        if not self.has_aggregate:
            self.aggregate_widths = [0]
            return

        self.aggregate_widths = map(len, self.aggregates_converted)

    def get_title(self, width):
        line = self.decl.title

        if self.is_ordered_by:
            orig_width = len(line)
            line = terminal.underline() + line + terminal.ununderline()
            extra_width = len(line) - orig_width
            width += extra_width

        return terminal.bold() + line.ljust(width) + terminal.unbold()

    def entry_cell(self, group_ix, entry_ix, width):
        cell = self._entry_cell_align(
            self.groups_converted[group_ix][entry_ix], width)
        format_name, formatter = self.entry_format(group_ix, entry_ix)

        if formatter is not None:
            cell = formatter(cell)

        return cell

    def _entry_cell_align(self, converted, width):
        if self.decl.align is FieldAlignment.right:
            return converted.rjust(width)
        elif self.decl.align is FieldAlignment.left:
            return converted.ljust(width)
        elif self.decl.align is FieldAlignment.center:
            return converted.center(width)
        elif self.decl.align is None:
            return converted.ljust(width)
        else:
            raise

    def aggregate_cell(self, group_ix):
        cell = self._entry_cell_align(
            self.aggregates_converted[group_ix],
            self.aggregate_widths[group_ix])

        if self.aggregates[group_ix] is not None:
            cell = terminal.fg_blue() + cell + terminal.fg_not_blue()

            if self.is_grouped_by:
                cell = terminal.bold() + cell + terminal.unbold()

        return cell
