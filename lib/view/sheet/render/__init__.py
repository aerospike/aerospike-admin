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

import traceback
from collections import defaultdict

from ..const import SheetStyle
from .column_rsheet import ColumnRSheet
from .json_rsheet import JSONRSheet


render_class = {
    SheetStyle.columns: ColumnRSheet,
    SheetStyle.json: JSONRSheet
}


def render(sheet, title, data_source, sheet_style=SheetStyle.columns,
           common=None, description=None):
        """
        Arguments:
        sheet       -- The decl.sheet to render.
        title       -- Title for this render.
        data_source -- Dictionary of data_sources to project fields from.

        Keyword Arguments:
        sheet_style -- 'SheetStyle.columns': Show sheet where records are
                                             represented as rows.
                       'SheetStyle.json'   : Show sheet represented as JSON.
        common      -- A dict of common information passed to each entry.
        description -- A description of the sheet.
        """
        # NOTE - Other than the title's suffix, it doesn't change.
        #        Title without suffix could move to decl and suffix be passed in
        #        here. Likewise, if the title moves to decl, the description should
        #        also move.
        tcommon = defaultdict(lambda: None)

        if common is not None:
            tcommon.update(common)

        assert set(sheet.from_sources) - set(data_source.keys()) == set()

        try:
            return render_class[sheet_style](
                sheet, title, data_source, tcommon,
                description=description).render()
        except Exception as e:
            # FIXME - Temporary debugging - should be removed before release.
            print e
            print "title:", title, "field_style:", sheet_style, \
                "description:", description
            traceback.print_exc()
            raise e
