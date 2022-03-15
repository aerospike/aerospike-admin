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

from collections import OrderedDict
from itertools import groupby
from operator import itemgetter

from lib.utils import util
from lib.view.terminal import get_terminal_size, terminal

from .. import decleration
from ..const import DynamicFieldOrder
from ..source import source_lookup
from .render_utils import ErrorEntry, NoEntry


class BaseRSheet(object):
    def __init__(
        self,
        sheet,
        title,
        sources,
        common,
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
        data_source -- Dictionary of data-sources to project fields from.

        Keyword Arguments:
        sheet_style  -- 'SheetStyle.columns': Output fields as columns.
                        'SheetStyle.rows'   : Output fields as rows.
                        'SheetStyle.json'   : Output sheet as JSON.
        common       -- A dict of common information passed to each entry.
        description  -- A description of the sheet.
        selectors    -- List of regular expressions to select which fields
                        from dynamic fields.
        title_repeat -- Repeat title/row headers every screen width.
                        Doesn't affect SheetStyle.json.
        disable_aggregations -- Disable sheet aggregations.
        dynamic_diff     -- Only show dynamic fields that aren't uniform.
        """
        self.decleration = sheet
        self.title = title

        self._debug_sources = sources
        self._init_sources(sources)

        self.common = common
        self.description = description
        self.selector = util.compile_likes(selectors)
        self.title_repeat = title_repeat
        self.disable_aggregations = disable_aggregations
        self.dynamic_diff = dynamic_diff
        self.terminal_size = get_terminal_size()

        self.dfields = self.get_dfields()

        if not self.dfields:
            self.rfields = None  # nothing to display
            return

        projections = self.project_fields()
        projections = self.where(projections)

        if self.has_all_required_fields(projections):
            projections_groups = self.group_by_fields(projections)
            self.group_hidden_fields = [[]] * len(projections_groups)
            projections_groups = self.diff(projections_groups)
            projections_groups = self.order_by_fields(projections_groups)
            self.rfields = self.create_rfields(projections_groups)
            self.visible_rfields = [
                rfield for rfield in self.rfields if not rfield.hidden
            ]

            for rfield in self.rfields:
                rfield.prepare()
        else:
            self.rfields = None  # nothing to display

    # =========================================================================
    # Required overrides.

    def do_render(self):
        """
        Renders the data in the style defined by the RSheet class.
        """
        raise NotImplementedError("override")

    def do_create_tuple_field(self, field, groups):
        """
        Each RSheet may define custom versions of RSubgroup.

        Arguments:
        field  -- The decleration.Subgroup describing this tuple field.
        groups -- The data sources having already been processed into groups.
        """
        raise NotImplementedError("override")

    def do_create_field(self, field, groups, parent_key=None):
        """
        Each RSheet may define custom version of RFields.
        Arguments:
        field  -- The decleration.Field describing this field.
        groups -- The data sources having already been processed into groups.

        Keyword Arguments:
        parent_key -- If this field is the child of a Subgroup, then this is
                      the key defined within that Subgroup.
        """
        raise NotImplementedError("override")

    # =========================================================================
    # Other methods.

    def _init_sources(self, sources):
        # TODO - This assertion can fire when a node is leaving/joining and
        #        some commands on a subset of the nodes. Should this event be
        #        logged?
        # n_source_records = map(len, list(sources.values()))

        # assert len(set(n_source_records)) == 1, \
        #     "sources contain different numbers of records {}".format(
        #         zip(sources.keys(), n_source_records))

        # Change sources from: {'source':{'row_key':value}}
        #                  to: [{'source':value}]

        # If source is a list convert it to a dictionary
        for key in sources.keys():
            if isinstance(sources[key], list):
                sources[key] = dict(enumerate(sources[key]))

        source_keys = {}

        # Using a dict as a set to maintain order and exclusivity
        for data in sources.values():
            if isinstance(data, dict):
                for keys in data.keys():
                    source_keys[keys] = None

        converted_sources = []

        for row_key in source_keys:
            new_source = {}

            for source, value in sources.items():
                new_source[source] = value.get(row_key)
            else:
                converted_sources.append(new_source)

        # Expand for_each
        expanded_sources = []

        for source in converted_sources:
            if not self.decleration.for_each:
                expanded_sources.append(source)
                continue

            for for_each in self.decleration.for_each:
                sub_source = source[for_each]

                try:
                    for item in sub_source.items():
                        new_source = source.copy()
                        new_source[for_each] = item
                        expanded_sources.append(new_source)
                except AttributeError:
                    # Non-iterable - probably an Exception.
                    new_source = source.copy()
                    new_source[for_each] = ErrorEntry
                    expanded_sources.append(new_source)

        self.sources = expanded_sources
        self.n_records = len(expanded_sources)

    def render(self):
        # XXX - Could be useful to pass 'group_by' and 'order_by' into the
        #       render function. Could use the decl's copy as their defaults.
        if self.rfields is None:
            return None

        return self.do_render()

    def get_dfields(self):
        dfields = []
        ignore_keys = set()

        for dfield in self.decleration.fields:
            if isinstance(dfield, decleration.DynamicFields):
                keys = {}

                for sources in self.sources:
                    try:
                        if dfield.source in self.decleration.for_each and isinstance(
                            sources[dfield.source], tuple
                        ):
                            keys.update(
                                (
                                    (k, None)
                                    for k in source_lookup(sources, dfield.source)[
                                        1
                                    ].keys()
                                )
                            )
                        else:
                            keys.update(
                                (
                                    (k, None)
                                    for k in source_lookup(
                                        sources, dfield.source
                                    ).keys()
                                )
                            )
                    except (AttributeError, TypeError):
                        pass

                if self.selector is not None:
                    keys = [
                        key for key in keys if self.selector.search(key) is not None
                    ]

                if dfield.order is DynamicFieldOrder.ascending:
                    keys.sort()
                elif dfield.order is DynamicFieldOrder.descending:
                    keys.sort(reverse=True)

                for key in keys:
                    if key in ignore_keys:
                        continue

                    if dfield.converter_selector:
                        conv_func = dfield.converter_selector(key)
                    else:
                        conv_func = None

                    if dfield.projector_selector:
                        proj_func = dfield.projector_selector(key)
                        proj = proj_func(dfield.source, key)

                    else:
                        proj = self._infer_projector(dfield, key)

                    if (
                        not self.disable_aggregations
                        and dfield.aggregator_selector is not None
                    ):
                        aggr = dfield.aggregator_selector(
                            key, self._is_projector_numeric(proj)
                        )
                    else:
                        aggr = None

                    dfields.append(
                        decleration.Field(
                            key,
                            proj,
                            aggregator=aggr,
                            dynamic_field_decl=dfield,
                            converter=conv_func,
                        )
                    )
            else:
                dfields.append(dfield)

                # To keep data displayed in a Field from being displayed in a DynamicFields
                if (
                    isinstance(dfield, decleration.Field)
                    and dfield.projector.keys is not None
                ):
                    ignore_keys.update(dfield.projector.keys)

        return dfields

    def _is_projector_numeric(self, projector):
        return isinstance(projector, decleration.Projectors.Float) or isinstance(
            projector, decleration.Projectors.Number
        )

    def _infer_projector(self, dfield, key):
        proj_args = (dfield.source, key)

        if not dfield.infer_projectors:
            return decleration.Projectors.String(*proj_args)

        entries = []

        for sources in self.sources:
            try:
                if isinstance(sources[dfield.source], tuple):
                    entries.append(source_lookup(sources, dfield.source)[1][key])

                else:
                    entries.append(source_lookup(sources, dfield.source)[key])
            except (KeyError, TypeError):
                # Missing or error retrieving, ignore for inference.
                pass

        has_string = False
        has_float = False
        has_int = False

        for entry in entries:
            try:
                int(entry)
                has_int = True
                continue
            except (ValueError, TypeError):
                pass

            try:
                float(entry)
                has_float = True
                continue
            except (ValueError, TypeError):
                pass

            has_string = True

        if has_string:
            return decleration.Projectors.String(*proj_args)
        elif has_float:
            return decleration.Projectors.Float(*proj_args)
        elif has_int:
            return decleration.Projectors.Number(*proj_args)
        else:  # no entries
            return decleration.Projectors.String(*proj_args)

    def project_fields(self):
        projections = []

        for sources in self.sources:
            projection = OrderedDict()
            projections.append(projection)

            for dfield in self.dfields:
                self._project_field(dfield, sources, projection)

        return projections

    def _project_field(self, dfield, sources, projection):
        if isinstance(dfield, decleration.Subgroup):
            child_projections = OrderedDict()
            projection[dfield.key] = child_projections

            for child_dfield in dfield.fields:
                self._project_field(child_dfield, sources, child_projections)

            return

        try:
            entry = dfield.projector(self.decleration, sources)
        except decleration.NoEntryException:
            entry = NoEntry
        except decleration.ErrorEntryException:
            entry = ErrorEntry

        projection[dfield.key] = entry

    def where(self, projections):
        if self.decleration.where:
            where_fn = self.decleration.where

            for record_ix in range(len(projections) - 1, -1, -1):
                if not where_fn(projections[record_ix]):
                    del projections[record_ix]

        return projections

    def has_all_required_fields(self, projections):
        required_dfields = set()

        for dfield in self.decleration.fields:
            if not isinstance(dfield, decleration.DynamicFields):
                continue

            if dfield.required:
                required_dfields.add(dfield)

        if not required_dfields:
            return True

        unfound_fields = required_dfields

        for dfield in self.dfields:
            if dfield.dynamic_field_decl in unfound_fields:
                unfound_fields.remove(dfield.dynamic_field_decl)

                if not unfound_fields:
                    return True

        return False

    def diff(self, projection_groups):
        if not self.dynamic_diff:
            return projection_groups

        dynamic_dfields = [
            dfield
            for dfield in self.dfields
            if isinstance(dfield.dynamic_field_decl, decleration.DynamicFields)
            or dfield.allow_diff
        ]
        drop_dfields_groups = []

        for group_idx in range(len(projection_groups)):
            drop_dfields = []

            for dfield in dynamic_dfields:
                entries = [
                    projection[dfield.key]
                    for projection in list(projection_groups.values())[group_idx]
                    if not projection[dfield.key] in (NoEntry, ErrorEntry)
                ]

                if all(entries[0] == entry for entry in entries):
                    drop_dfields.append(dfield)

            drop_dfields_groups.append(drop_dfields)

        # dfields in intersection can be dropped from all projections.
        # If it is not in interestion but needs to be "dropped" (not displayed)
        # from a specific group we will use hidden_fields
        drop_intersection = set(drop_dfields_groups[0])
        for drop_dfields in drop_dfields_groups:
            drop_intersection = drop_intersection.intersection(set(drop_dfields))

        self.group_hidden_fields = []

        for group_idx in range(len(projection_groups)):
            hidden_fields = []
            for dfield in drop_dfields_groups[group_idx]:
                for projection in list(projection_groups.values())[group_idx]:
                    if dfield.key in projection:
                        # If a field is in drop_intersection is it being dropped
                        # from all groups.
                        if dfield in drop_intersection:
                            if dfield in self.dfields:
                                self.dfields.remove(dfield)
                            del projection[dfield.key]
                        # Some groups need to drop the value and others do not.
                        # Using hidden_fields[group_idx] to indicate when a
                        # group should not display the field.
                        else:
                            projection[dfield.key] = None
                            hidden_fields.append(dfield)

            self.group_hidden_fields.append(hidden_fields)

        return projection_groups

    def group_by_fields(self, projections):
        """
        Single or composite key grouping
        """
        # XXX - Allow 'group by' on a field within a Subgroup.

        grouping = (((), projections),)
        group_bys = self.decleration.group_bys

        if group_bys is None:
            return OrderedDict(grouping)

        if isinstance(group_bys, str):
            group_bys = (group_bys,)

        for group_by in group_bys:
            next_grouping = []

            for pkey, pgroup in grouping:
                pgroup_sort = sorted(pgroup, key=itemgetter(group_by))
                cgroups = [
                    (pkey + (ckey,), list(cgroup))
                    for ckey, cgroup in groupby(pgroup_sort, key=itemgetter(group_by))
                ]

                next_grouping.extend(cgroups)

            grouping = next_grouping

        return OrderedDict(grouping)

    def order_by_fields(self, projections_groups):
        # XXX - Allow 'order by' on a field within a Subgroup.
        # XXX - Allow desc order.

        order_bys = self.decleration.order_bys

        if order_bys is None:
            return projections_groups

        for projections_group in projections_groups.values():
            for order_by in order_bys[::-1]:
                projections_group.sort(key=itemgetter(order_by))

        return projections_groups

    def create_rfields(self, projections_groups):
        groups = projections_groups.values()

        return [self.create_rfield(field, groups) for field in self.dfields]

    def create_rfield(self, field, groups, parent_key=None):
        if isinstance(field, decleration.Subgroup):
            return self.do_create_tuple_field(field, groups)

        return self.do_create_field(field, groups, parent_key=parent_key)


class BaseRSubgroup(object):
    def __init__(self, rsheet, field, groups):
        """
        Arguments:
        rsheet -- BaseRSheet being rendered.
        field  -- decleration.Subgroup.
        groups -- Sequence of sub-sequences where each sub-sequence is a group
                  determined by 'rsheet.decleration.group_bys'.
        """
        self.rsheet = rsheet
        self.decleration = field
        self.parent_key = None
        self.n_groups = len(groups)

        self._init_as_tuple_field(groups)

    # =========================================================================
    # Optional overrides.

    def do_prepare(self):
        """
        Post processing phase after all fields in the RSheet have been
        initialized.
        """
        return  # Override if as needed.

    # =========================================================================
    # Other methods.

    def _init_as_tuple_field(self, groups):
        self.is_tuple_field = True
        self.subfields = [
            self.rsheet.do_create_field(
                subdecl, groups, parent_key=self.decleration.key
            )
            for subdecl in self.decleration.fields
        ]
        self.visible = [subfield for subfield in self.subfields if not subfield.hidden]
        self.hidden = not self.visible

    def prepare(self):
        if self.hidden:
            return

        for subfield in self.subfields:
            subfield.prepare()

        self.do_prepare()

    def has_aggregate(self):
        return any(sub.has_aggregate() for sub in self.visible)

    def get_kv(self, group_ix, entry_ix):
        return (
            self.decleration.key,
            dict(sub.get_kv(group_ix, entry_ix) for sub in self.visible),
        )

    def n_entries_in_group(self, group_ix):
        return self.subfields[0].n_entries_in_group(group_ix)


class BaseRField(object):
    def __init__(self, rsheet, field, groups, parent_key=None):
        """
        Arguments:
        rsheet -- BaseRSheet being rendered.
        field  -- 'decleration.Subgroup'.
        groups -- Sequence of sub-sequences where each sub-sequence is a group
                  determined by 'rsheet.decleration.group_bys'.

        Keyword Argument:
        parent_key -- Not None: the decleration.key value for the parent 'Subgroup'.
        """
        self.rsheet = rsheet
        self.decleration = field
        self.parent_key = parent_key

        self.n_groups = len(groups)

        if self.rsheet.decleration.group_bys:
            self.is_grouped_by = (
                self.decleration.key in self.rsheet.decleration.group_bys
            )
        else:
            self.is_grouped_by = False

        if self.rsheet.decleration.order_bys:
            self.is_ordered_by = (
                self.decleration.key in self.rsheet.decleration.order_bys
            )
        else:
            self.is_ordered_by = False

        self._init_as_field(groups)

    # =========================================================================
    # Optional overrides.

    def do_prepare(self):
        """
        Post processing phase after all fields in the RSheet have been
        initialized.
        """
        return  # Override as needed.

    # =========================================================================
    # Other methods.

    def _init_as_field(self, raw_groups):
        self.is_tuple_field = False

        self.groups = []
        self.groups_converted = []

        self.aggregates = []
        self.aggregates_converted = []

        self._init_load_groups(raw_groups)

    def _init_load_groups(self, raw_groups):
        field_key = self.decleration.key

        if self.parent_key:
            self.groups = [
                list(map(lambda g: g[self.parent_key][field_key], raw_group))
                for raw_group in raw_groups
            ]
        else:
            self.groups = [
                list(map(itemgetter(field_key), raw_group)) for raw_group in raw_groups
            ]

        # Determine if hidden.
        if self.decleration.hidden is None:
            self.hidden = not any(
                v is not NoEntry for group in self.groups for v in group
            )
        else:
            self.hidden = self.decleration.hidden

    def prepare(self):
        if self.hidden:
            return

        self._prepare_entry_data()

        for entry_group in self.groups_entry_data:
            self._prepare_aggregate_group(entry_group)

        self._prepare_convert()
        self.do_prepare()

    def _prepare_entry_data(self):
        self.groups_entry_data = []

        for group_ix, group in enumerate(self.groups):
            entry_edata = []
            self.groups_entry_data.append(entry_edata)
            entries = [self.entry_value(e) for e in group]
            for entry_ix, entry in enumerate(entries):
                record = dict(
                    (
                        rfield.get_kv(group_ix, entry_ix)
                        for rfield in self.rsheet.rfields
                    )
                )

                entry_edata.append(
                    decleration.EntryData(
                        value=entry,
                        values=entries,
                        record=record,
                        common=self.rsheet.common,
                        is_error=group[entry_ix] is ErrorEntry,
                        is_no_entry=group[entry_ix] is NoEntry,
                    )
                )

    def _prepare_aggregate_group(self, group):
        if self.hidden:
            # Do not need to aggregate hidden fields.
            self.aggregates.append(None)
            self.aggregates_converted.append("")
            return

        if self.rsheet.disable_aggregations or self.decleration.aggregator is None:
            if self.is_grouped_by and self.rsheet.decleration.has_aggregates:
                # If a grouped field doesn't have an aggregator then the grouped
                # value will appear in the aggregates line.
                entry = group[0].value
                self.aggregates.append(entry)

                if group[0].is_error:
                    self.aggregates_converted.append(
                        self.rsheet.decleration.error_entry
                    )
                elif group[0].is_no_entry:
                    self.aggregates_converted.append(self.rsheet.decleration.no_entry)
                else:
                    self.aggregates_converted.append(str(entry))
            else:
                self.aggregates.append(None)
                self.aggregates_converted.append("")
            return

        if any(e.is_error for e in group):
            aggregate_value = ErrorEntry
        else:
            group_entries = [e for e in group if not e.is_no_entry]
            aggregate_value = self.decleration.aggregator.compute(group_entries)

            if aggregate_value is None:
                aggregate_value = NoEntry

        self.aggregates.append(aggregate_value)

    def _prepare_convert(self):
        self._prepare_convert_groups()
        self._prepare_convert_aggregates()

    def _prepare_convert_groups(self):
        self.groups_converted = []

        for fgroup in self.groups_entry_data:
            group_converted = []
            self.groups_converted.append(group_converted)

            for edata in fgroup:
                if edata.value is None:
                    if edata.is_error:
                        group_converted.append(self.rsheet.decleration.error_entry)
                    else:
                        group_converted.append(self.rsheet.decleration.no_entry)
                else:
                    group_converted.append(str(self.decleration.converter(edata)))

    def _prepare_convert_aggregates(self):
        if self.decleration.aggregator is None:
            return

        self.aggregates_converted = []

        if self.decleration.aggregator.converter is None:
            converter = self.decleration.converter
        else:
            converter = self.decleration.aggregator.converter

        for aggr_ix, aggregate in enumerate(self.aggregates):
            if aggregate is None:
                self.aggregates_converted.append("")
            elif aggregate is NoEntry:
                self.aggregates_converted.append(self.rsheet.decleration.no_entry)
            elif aggregate is ErrorEntry:
                self.aggregates_converted.append(self.rsheet.decleration.error_entry)
            else:
                self.aggregates_converted.append(
                    str(converter(decleration.EntryData(value=aggregate)))
                )

    def entry_value(self, entry):
        if entry is ErrorEntry or entry is NoEntry:
            return None

        return entry

    def get_kv(self, group_ix, entry_ix):
        entry = self.groups[group_ix][entry_ix]
        return self.decleration.key, self.entry_value(entry)

    def has_aggregate(self):
        return self.decleration.aggregator is not None

    def n_entries_in_group(self, group_ix):
        return len(self.groups[group_ix])

    def entry_format(self, group_ix, entry_ix):
        """
        Arguments:
        group_ix -- Index of a group in self.groups.
        entry_ix -- Index of an entry within a group.

        Return:
        Tuple of form (string_alert, format_function). The string_alert can be
        used when sheet is displayed in a plain text rendering (currently only
        for testing format).
        """
        edata = self.groups_entry_data[group_ix][entry_ix]

        if edata.is_error:
            return None, lambda v: terminal.fg_magenta() + v + terminal.fg_not_magenta()

        for name, formatter in self.decleration.formatters:
            format_fn = formatter(edata)

            if format_fn is not None:
                return name, format_fn

        return None, None


class BaseRSheetCLI(BaseRSheet):
    def _do_render_title(self, render, width):
        # XXX - Same as column.
        filler = self.decleration.title_fill
        columns = self.terminal_size.columns
        min_columns = len(self.title) + 6

        if min_columns < columns:
            min_columns = columns

        n_repeates = width // min_columns

        if width > min_columns and n_repeates != 1:
            extra_columns = (columns % min_columns) // n_repeates
            new_width = min_columns + extra_columns

            t = "".join(
                [self.title.center(new_width, filler) for _ in range(n_repeates)]
            )
            t = t.ljust(width, filler)
        else:
            t = self.title.center(width, filler)

        if len(t) > 0:
            if not t.startswith(filler):
                t = filler + t
            if not t.endswith(filler):
                t += filler

        title_width = len(t)
        t = terminal.bold() + t + terminal.unbold()
        render.append(t)

        return title_width

    def _do_render_description(self, render, line_width, desc_width):
        # XXX - Same as column.
        if self.description is None or self.description == "":
            return []

        tdesc = self.description[:].split(" ")
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
            terminal.dim() + line.center(line_width) + terminal.reset()
            for line in lines
        ]
        description = "\n".join(description)

        render.append(description)

    def _do_render_n_rows(self, render, n_records):
        # XXX - Same as column.
        render.append(
            terminal.dim() + "Number of rows: {}".format(n_records) + terminal.undim()
        )
