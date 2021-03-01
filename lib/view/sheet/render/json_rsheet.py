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

import json

from .base_rsheet import BaseRField, BaseRSheet, BaseRSubgroup, ErrorEntry, NoEntry


class JSONRSheet(BaseRSheet):
    def do_create_tuple_field(self, field, groups):
        return RSubgroupJSON(self, field, groups)

    def do_create_field(self, field, groups, parent_key=None):
        return RFieldJSON(self, field, groups, parent_key=parent_key)

    def do_render(self):
        rfields = self.visible_rfields

        groups = []
        result = dict(title=self.title, groups=groups)

        if self.description:
            result["description"] = self.description

        if len(rfields) == 0:
            return json.dumps(result, indent=2)

        n_groups = 0 if not rfields else rfields[0].n_groups

        for group_ix in range(n_groups):
            records = []
            aggregates = {}
            group = dict(records=records)

            groups.append(group)

            for entry_ix in range(rfields[0].n_entries_in_group(group_ix)):
                record = {}

                records.append(record)

                for rfield in rfields:
                    field_key = rfield.decleration.key

                    if rfield.is_tuple_field:
                        tuple_field = {}
                        record[field_key] = tuple_field

                        for rsubfield in rfield.visible:
                            self.do_render_field(
                                rsubfield, group_ix, entry_ix, tuple_field
                            )
                    else:
                        self.do_render_field(rfield, group_ix, entry_ix, record)

            for rfield in rfields:
                field_key = rfield.decleration.key

                if rfield.is_tuple_field:
                    tuple_agg = {}

                    for rsubfield in rfield.visible:
                        self.do_render_aggregate(rsubfield, group_ix, tuple_agg)

                    if tuple_agg:
                        aggregates[field_key] = tuple_agg
                else:
                    self.do_render_aggregate(rfield, group_ix, aggregates)

            if aggregates:
                group["aggregates"] = aggregates

        return json.dumps(result, indent=2)

    def do_render_field(self, rfield, group_ix, entry_ix, record):
        value = rfield.groups[group_ix][entry_ix]
        converted_value = rfield.groups_converted[group_ix][entry_ix].strip()

        if value is ErrorEntry:
            value = "error"
        elif value is NoEntry:
            value = "null"

        key = rfield.decleration.key  # use key, instead of title, for uniqueness
        record[key] = dict(raw=value, converted=converted_value)
        format_name, _ = rfield.entry_format(group_ix, entry_ix)

        if format_name is not None:
            record[key]["format"] = format_name

    def do_render_aggregate(self, rfield, group_ix, aggregates):
        aggregate = rfield.aggregates[group_ix]
        converted_aggregate = rfield.aggregates_converted[group_ix].strip()

        if aggregate is ErrorEntry:
            aggregate = "error"
        elif aggregate is NoEntry:
            aggregate = "null"

        key = rfield.decleration.key  # use key, instead of title, for uniqueness

        if aggregate is not None:
            aggregates[key] = dict(raw=aggregate, converted=converted_aggregate)


class RSubgroupJSON(BaseRSubgroup):
    pass


class RFieldJSON(BaseRField):
    pass
