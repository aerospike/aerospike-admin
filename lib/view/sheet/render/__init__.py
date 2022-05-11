# Copyright 2019 Aerospike, Inc.
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

from collections import defaultdict
import logging
from typing import Any

from lib.view.sheet.decleration import Sheet

from ..const import SheetStyle
from .column_rsheet import ColumnRSheet
from .row_rsheet import RowRSheet
from .json_rsheet import JSONRSheet


render_class = {
    SheetStyle.columns: ColumnRSheet,
    SheetStyle.rows: RowRSheet,
    SheetStyle.json: JSONRSheet,
}

logger = logging.getLogger(__name__)

use_json = False


def set_style_json(value=True):
    global use_json
    use_json = value


def get_style_json():
    global use_json
    return use_json


def render(
    sheet: Sheet,
    title: str,
    data_source: dict[str, Any],
    style=None,
    common=None,
    description=None,
    selectors=None,
    title_repeat=False,
    disable_aggregations=False,
    dynamic_diff=False,
):
    """
    Arguments:
    sheet       -- The decleration.sheet to render.
    title       -- Title for this render.
    data_source -- Dictionary of data_sources to project fields from.

    Keyword Arguments:
    style        -- 'SheetStyle.columns': Output fields as columns.
                    'SheetStyle.rows'   : Output fields as rows.
                    'SheetStyle.json'   : Output sheet as JSON.
    common       -- A dict of common information passed to each entry.
    description  -- A description of the sheet.
    selectors    -- List of regular expressions to select which fields from
                    dynamic fields.
    title_repeat -- Repeat title and row headers every n columns.
    disable_aggregations -- Disable sheet aggregations.
    dynamic_diff     -- Only show dynamic fields that aren't uniform.
    """
    tcommon = defaultdict(lambda: None)

    if common is not None:
        tcommon.update(common)

    assert (
        set(sheet.from_sources) - set(data_source.keys()) == set()
    ), "Mismatched sheet sources and data sources. Sheet: {}, Data: {}".format(
        set(sheet.from_sources), set(data_source.keys())
    )

    if use_json:
        style = SheetStyle.json
    elif style is None:
        style = sheet.default_style

    return render_class[style](
        sheet,
        title,
        data_source,
        tcommon,
        description=description,
        selectors=selectors,
        title_repeat=title_repeat,
        disable_aggregations=disable_aggregations,
        dynamic_diff=dynamic_diff,
    ).render()
