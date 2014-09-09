# Copyright 2013-2014 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from lib import filesize
from lib import terminal
import re

class Extractors(object):
    # standard set of extractors
    
    @staticmethod
    def _numExtractor(column, system):
        def si_extractor(data):
            if system == int:
                return int(data[column])
            elif system == float:
                return float(data[column])
            else:
                return filesize.size(int(data[column]), system)

        return si_extractor

    @staticmethod
    def floatExtractor(column):
        return Extractors._numExtractor(column, float)

    @staticmethod
    def intExtractor(column):
        return Extractors._numExtractor(column, int)
        
    @staticmethod
    def sifExtractor(column):
        return Extractors._numExtractor(column, filesize.sif)

    @staticmethod
    def siExtractor(column):
        return Extractors._numExtractor(column, filesize.si)

    @staticmethod
    def byteExtractor(column):
        return Extractors._numExtractor(column, filesize.byte)

    @staticmethod
    def timeExtractor(column):
        return Extractors._numExtractor(column, filesize.time)

class TitleFormats(object):
    @staticmethod
    def varToTitle(name):
        rename = re.split('[\-_ ]', name)
        rename = ' '.join(map(lambda w: w.title(), rename)).strip()
        return rename.replace(' Pct', '%')

    @staticmethod
    def noChange(name):
        return name.strip()

class Styles(object):
    ### Styles
    HORIZONTAL = 0
    VERTICAL   = 1

class Table(object):
    def __init__(self
                 ,title
                 ,column_names
                 ,sort_by = 0
                 ,group_by = None
                 ,style = Styles.HORIZONTAL
                 ,title_format = TitleFormats.varToTitle
                 ,description=''):

        self._data = []
        self._need_sort = False
        self._data_source = {}
        self._no_alert_style = lambda: ''
        self._cell_alert = {}
        self._column_padding = "   "
        self._no_entry = 'N/E'

        self._title = title
        self._group_by = group_by
        self._style = style
        self._description = description

        self._column_names = []
        self._column_display_names = []
        self._render_column_ids = set()
        for name in column_names:
            if type(name) == str:
                self._column_names.append(name)
                self._column_display_names.append(title_format(name))
            elif type(name) == tuple or type(name) == list:
                self._column_names.append(name[0])
                self._column_display_names.append(name[1])

        if style == Styles.HORIZONTAL:
            self._column_widths = [0 for _ in self._column_names]
        elif style == Styles.VERTICAL:
            self._column_widths = []
        else:
            raise ValueError("Style must be either HORIZONAL or VERTICAL")

        self._column_types = ["number" for _ in self._column_names]
        # column_types: 0 number, 1 string
        self._updateColumnMetadata(self._column_display_names
                                   ,header = True)
        try:
            self._sort_by = column_names.index(sort_by)
        except ValueError:
            if sort_by < 0 or sort_by > len(column_names):
                raise ValueError("sort_by is not a legal value")
            self._sort_by = sort_by

    def _updateColumnMetadata(self, row, header = False):
        if self._style == Styles.HORIZONTAL:
            for i in range(len(self._column_names)):
                if not header:
                    cell_format, cell = row[i]
                else:
                    cell = row[i]
                    cell_format = self._no_alert_style

                if header:
                    max_length = max(map(len,cell.split(' ')))
                else:
                    max_length = len(cell)
                if self._column_widths[i] < max_length:
                    self._column_widths[i] = max_length
                if not header:
                    if not filesize.isfilesize(cell):
                        if cell != self._no_entry:
                            self._column_types[i] = "string"
        elif self._style == Styles.VERTICAL:
            length = max(
                map(lambda r:
                    len(r[1]) if type(r) is tuple else len(r)
                    , row))
            self._column_widths.append(length)
        else:
            raise ValueError("Style must be either HORIZONAL or VERTICAL")

    def addDataSource(self, column, function):
        self._data_source[column] = function

    def addCellAlert(self, column_name, is_alert, color=terminal.fg_red):
        self._cell_alert[column_name] = (is_alert, color)

    def insertRow(self, row_data):
        if not row_data:
            # passed an empty row
            return
        row = []
        if type(row_data) is not dict:
            raise ValueError("Data cannot be of type %s"%type(row_data))

        for i, column in enumerate(self._column_names):
            try:
                if column in self._data_source:
                    extractor = self._data_source[column]
                    cell = extractor(row_data)
                else:
                    cell = row_data[column]
                # column has actual data, let it render
                self._render_column_ids.add(i)
            except KeyError: # extractor accessed n/e column
                cell = self._no_entry

            try:
                is_alert = False
                if column in self._cell_alert:
                    is_alert, color = self._cell_alert[column]
                
                if is_alert and is_alert(row_data):
                    cell = (color, cell)
                else:
                    cell = (self._no_alert_style, cell)
            except KeyError: # is_alert accessed n/e column
                cell = (self._no_alert_style, cell)

            row.append(cell)

        for i, (cell_format, cell) in enumerate(row):
            if isinstance(cell, Exception):
                cell = "error"
            else:
                cell = str(cell)
            row[i] = (cell_format, cell)

        self._data.append(row)
        self._updateColumnMetadata(row)
        self._need_sort = True

    def _do_group(self, data):
        # requires data to be sorted
        if self._group_by is None:
            return data

        grouped_data = {}
        for row in data:
            group_by = row[self._group_by]
            if group_by not in grouped_data:
                grouped_data[group_by] = []
                
            grouped_data[group_by].append(row)

        data = []
        for group in sorted(grouped_data.keys()):
            data.extend(grouped_data[group])

        return data

    def _do_sort(self):
        if self._need_sort == True:
            if self._style == Styles.HORIZONTAL:
                sorted_data = sorted(self._data
                                     , key=lambda d: d[self._sort_by][1])
                self._data = self._do_group(sorted_data)
                self._need_sort = False
            else: # style is Vertical
                # Need to sort but messes with column widths
                transform = sorted(
                    range(len(self._data))
                    , key = lambda d: self._data[d][self._sort_by][1])

                self._data = map(lambda i: self._data[i], transform)
                first = self._column_widths[0]
                self._column_widths = map(lambda i:
                                          self._column_widths[i+1], transform)
                self._column_widths.insert(0, first)
                self._need_sort = False

    def _genRenderData(self, horizontal=True):
        columns = self._column_display_names

        self._render_column_display_names = []
        self._render_column_names = []
        self._render_column_widths = []
        if self._style == Styles.VERTICAL:
            self._render_column_widths = self._column_widths
        self._render_remap = {}
        for i, column in enumerate(self._column_display_names):
            if i in self._render_column_ids:
                self._render_column_display_names.append(self._column_display_names[i])
                if self._style == Styles.HORIZONTAL:
                    self._render_column_widths.append(self._column_widths[i])
                self._render_column_names.append(self._column_names[i])
                self._render_remap[i] = len(self._render_column_names) - 1

    def genDescription(self, line_width, desc_width):
        if self._description == '':
            return []

        tdesc = self._description[:].split(' ')
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
            
        description = ["%s%s%s"%(terminal.dim()
                                , l.center(line_width)
                                 , terminal.reset()) for l in lines]
        description = "\n".join(description)

        return [description,]

    def _getHorizontalHeader(self):
        width = sum(self._render_column_widths)
        width +=len(self._column_padding) * (len(self._render_column_widths) - 1)

        column_name_lines = map(lambda h: h.split(" ")
                                , self._render_column_display_names)
        max_deep = max(map(len, column_name_lines))

        output = [terminal.bold()]
        output.append(self._title.center(width, '~'))
        output.append(terminal.reset())
        output = [''.join(output)]
        output.extend(self.genDescription(width, width - 10))

        for r in range(max_deep):
            row = []
            for i, c in enumerate(column_name_lines):
                try:
                    row.append(c[r].rjust(self._render_column_widths[i]))
                except IndexError:
                    row.append(".".rjust(self._render_column_widths[i]))
                row.append(self._column_padding)
            output.append(row)

        output = "\n".join(map(lambda r: "".join(r), output))
        return output

    def __str__(self):
        if len(self._render_column_ids) == 0:
            return ''
        if self._need_sort:
            self._do_sort()
        self._genRenderData()

        if self._style == Styles.HORIZONTAL:
            return self._str_horizontal()
        elif self._style == Styles.VERTICAL:
            return self._str_vertical()
        else:
            raise ValueError("Invalid style, must be either " +
                             "table.HORIZONTAL or table.VERTICAL")

    def _str_horizontal(self):
        output = []
        output.append(self._getHorizontalHeader())
        for drow in self._data:
            row = []
            for i, (cell_format, cell) in enumerate(drow):
                row.append(terminal.style(
                    terminal.bg_clear
                    ,terminal.fg_clear))
                if i not in self._render_column_ids:
                    continue

                i = self._render_remap[i]

                column_name = self._render_column_names[i]

                if self._column_types[i] == "number":
                    cell = cell.rjust(self._render_column_widths[i])
                elif self._column_types[i] == "string":
                    cell = cell.ljust(self._render_column_widths[i])
                else:
                    raise ValueError(
                        "Unknown column type: '%s'"%self._render_column_types[i])

                row.append("%s%s"%(cell_format(),cell))
                row.append(self._column_padding)

            output.append(''.join(row))
        output.append("Number of rows: %s"%(len(self._data)))
        return "\n".join(output) + '\n'

    def _str_vertical(self):
        output = []
        
        title_width = sum(self._render_column_widths) + 1 # 1 for ":"
        title_width += len(self._column_padding) * (len(self._render_column_widths) - 1)
        output = [terminal.bold()]
        output.append(self._title.center(title_width, '~'))
        output.append(terminal.reset())
        output = [''.join(output)]
        output.extend(self.genDescription(title_width, title_width - 10))

        for i, column_name in enumerate(self._render_column_names):
            row = []
            row.append(terminal.style(
                terminal.bg_clear
                , terminal.fg_clear))

            column_title = column_name
            if column_name == "NODE":
                row.append(terminal.bold())
            row.append(column_title.ljust(self._render_column_widths[0]))
            row.append(":")
            row.append(self._column_padding)
            for j, (cell_format, cell) in enumerate((raw_data[i]
                                                     for raw_data in self._data), 1):
                cell = cell.ljust(self._render_column_widths[j])
                row.append("%s%s"%(cell_format(), cell))
                row.append(self._column_padding)

            if column_name == "NODE":
                row.append(terminal.reset())
            output.append(''.join(row))

        return '\n'.join(output) + '\n'
