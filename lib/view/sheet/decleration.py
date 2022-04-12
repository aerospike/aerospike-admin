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

from collections import Counter
import logging
from typing import Callable

from lib.utils import file_size
from lib.view import terminal

from .const import DynamicFieldOrder, FieldType, SheetStyle
from .source import source_lookup, source_root

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


class Sheet(object):
    def __init__(
        self,
        fields,
        from_source=None,
        for_each=None,
        where=None,
        group_by=None,
        order_by=None,
        default_style=SheetStyle.columns,
        title_fill="~",
        subtitle_fill="~",
        subtitle_empty_line="",
        vertical_separator="|",
        horizontal_seperator="-",
        no_entry="--",
        error_entry="~~",
    ):
        """Instantiates a sheet definition.
        Arguments:
        fields -- Sequence of fields to present.

        Keyword Arguments:
        from_sources  -- (Required) A sequence of source names that are
                         required for rendering (used for sanity checks only).
        for_each      -- A field who's data-source contains multiple sets of
                         values.
        where         -- Function to determine if a record should be shown.
        group_by      -- Field or sequence of fields to group records by.
        order_by      -- Field or sequence of fields sort the records by.
        title_fill    --
        subtitle_fill --
        subtitle_empty_line --
        separator     -- String used to separate fields.
        no_entry      -- String used when a field is present but a particular
                         key is missing.
        error_entry   -- String used when a field's data-source is not a dict
                         or sequence.
        """
        self.fields = fields
        # XXX - Support TitleFields in SubGroups?
        self.title_field_keys = set(
            field.key for field in fields if isinstance(field, TitleField)
        )
        self.from_sources = self._arg_as_tuple(from_source)
        self.where = where
        self.for_each = self._arg_as_tuple(for_each)
        self.group_bys = self._arg_as_tuple(group_by)
        self.order_bys = self._arg_as_tuple(order_by)
        self.default_style = default_style

        self.vertical_separator = vertical_separator
        self.horizontal_seperator = horizontal_seperator
        self.formatted_vertical_separator_func: Callable[[], str] = lambda: (
            terminal.dim() + vertical_separator + terminal.undim()
        )
        self.formatted_horizontal_seperator_func: Callable[[], str] = lambda: (
            terminal.dim() + horizontal_seperator + terminal.undim()
        )
        self.title_fill = title_fill
        self.subtitle_fill = subtitle_fill
        self.subtitle_empty_line = subtitle_empty_line

        self.no_entry = no_entry
        self.error_entry = error_entry

        self.has_aggregates = any(f.has_aggregate for f in fields)

        self._init_sanity_check()

    def _arg_as_tuple(self, arg):
        if arg is None:
            return tuple()
        elif isinstance(arg, tuple):
            return arg
        elif isinstance(arg, list):
            return tuple(arg)
        elif isinstance(arg, str):
            return (arg,)

        raise ValueError(
            "Expected tuple, list or string - instead {}".format(type(arg))
        )

    def _init_sanity_check(self):
        # Ensure 'group_bys' and 'sort_bys' are in 'fields'.
        # NOTE - currently cannot group_by/sort_by a member of a Subgroup.
        static_fields = [
            field for field in self.fields if not isinstance(field, DynamicFields)
        ]
        field_set = set(field.key for field in static_fields)

        if len(field_set) != len(static_fields):
            field_keys = ",".join(
                (
                    "{} appears {} times".format(key, count)
                    for count, key in Counter(
                        field.key for field in static_fields
                    ).items()
                    if count > 1
                )
            )

            assert False, "Field keys are not unique: {}".format(field_keys)

        if self.group_bys:
            group_by_set = set(self.group_bys)
            assert len(group_by_set) == len(self.group_bys)
        else:
            group_by_set = set()

        if self.order_bys:
            order_by_set = set(self.order_bys)
            assert len(order_by_set) == len(self.order_bys)
        else:
            order_by_set = set()

        error_groups = group_by_set - field_set
        error_orders = order_by_set - field_set

        assert not error_groups, error_groups
        assert not error_orders, error_orders

        assert self.from_sources, "require a list of expected field sources"

        sources_set = set(source_root(s) for s in self.from_sources)

        assert len(sources_set) == len(self.from_sources)

        seen_sources_set = set()

        def populate_seen_sources(fields):
            for field in fields:
                if isinstance(field, Subgroup):
                    return populate_seen_sources(field.fields)

                assert not isinstance(
                    field, DynamicFields
                ), "DynamicFields cannot be members of Subgroups."

                try:
                    sources = field.projector.sources
                except AttributeError:
                    sources = set([field.projector.source])

                assert sources - sources_set == set(), "{} not subset of {}".format(
                    sources, sources_set
                )

                seen_sources_set.update(sources)

        populate_seen_sources(static_fields)

        for field in self.fields:
            if isinstance(field, DynamicFields):
                seen_sources_set.add(source_root(field.source))

        assert len(seen_sources_set) == len(sources_set)

        if self.for_each:
            for_each_set = set(self.for_each)
            assert len(for_each_set) == len(self.for_each)
        else:
            for_each_set = set()

        assert for_each_set - sources_set == set()


class Subgroup(object):
    def __init__(self, title, fields, key=None):
        """
        Arguments:
        title  -- Name in this Field's heading
        fields -- Sequence of sub-fields.

        Keyword Arguments:
        key -- Alternative key to access this key from the parent sheet.
        """
        self.title = title
        self.fields = fields
        self.key = title if key is None else key

        self.has_aggregate = any(f.has_aggregate for f in fields)


class Field(object):
    def __init__(
        self,
        title,
        projector,
        converter=None,
        formatters=None,
        aggregator=None,
        align=None,
        key=None,
        hidden=None,
        dynamic_field_decl=None,
        allow_diff=False,
    ):
        """
        Arguments:
        title     -- Name in this Field's heading
        projector -- How to retrieve a field entry from the fields data_source.

        Keyword Arguments:
        converter  -- Typically used to convert numbers to SI formats.
        formatters -- List of cell formatters functions, evaluated in order,
                      first format to not return None is applied - rest will be
                      ignored. These may *not* change the length of the
                      rendered value.
        aggregator -- Function that generates an aggregate value to be
                      displayed at the end of a group.
        align      -- None    : Allow sheet to choose alignment.
                      'left'  : Always align left.
                      'right' : Always align right.
                      'center': Always align center.
        key        -- Alternative key to access this key from the parent sheet.
        hidden     -- None : Visible if there are any entries.
                      True : Always visible.
                      False: Always hidden.
        dynamic_field_decl -- None if not from DynamicFields.
                              Otherwise DynamicFields instance.
        allow_diff -- A non dynamic field by default does not allow diff and is always
                      displayed. This is mutally exclusive with dynamic_field_decl.
                      True: Allow diff.
                      False: Don't diff.
                      Default: False
        """
        self.title = title
        self.projector = projector
        self.converter = Converters.standard if converter is None else converter
        self.formatters = [] if formatters is None else formatters
        self.aggregator = aggregator
        self.align = align
        self.key = title if key is None else key
        self.hidden = hidden
        self.dynamic_field_decl = dynamic_field_decl
        self.allow_diff = allow_diff

        self.has_aggregate = self.aggregator is not None

        # Pre-compute commonly accessed data.
        self.title_words = tuple(title.split(" "))
        self.min_title_width = max(map(len, self.title_words))


class TitleField(Field):
    def __init__(
        self,
        title,
        projector,
        converter=None,
        formatters=None,
        aggregator=None,
        align=None,
        key=None,
    ):
        if formatters is None:
            formatters = (Formatters.bold(lambda _: True),)

        super(TitleField, self).__init__(
            title,
            projector,
            converter=converter,
            formatters=formatters,
            aggregator=aggregator,
            align=align,
            key=key,
        )


class DynamicFields(object):
    def __init__(
        self,
        source,
        infer_projectors=True,
        required=False,
        aggregator_selector=None,
        projector_selector=None,
        converter_selector=None,
        order=DynamicFieldOrder.ascending,
    ):
        """
        Arguments:
        source -- Data source to project fields from.

        Keyword Arguments:
        infer_projectors -- True : If true, will try to infer a projector for a
                            field.
        aggregator_selector -- None: Function used to select aggregator.  Function
                               will take the form (key, is_numeric) -> Aggregator.
                               Key is the row or column header.  is_numeric is passed
                               in by the rendering function and allows the developer
                               to know if the the projected value is a numeric value,
                               i.e. you can use arithmetic aggregators. If none,
                               no aggregation is used.
        projector_selector -- None: Function used to select a projector. Function
                              will take the form (key) -> Projector.  If none and
                              infer_projector is false String projection is used.

        Note: If a preceding non-dynamic Field uses the same key it will not be rendered
              by a proceding DynamicField.
        """
        self.source = source
        self.infer_projectors = infer_projectors
        self.required = required
        self.projector_selector = projector_selector
        self.aggregator_selector = aggregator_selector
        self.converter_selector = converter_selector
        self.order = order

        self.has_aggregate = False  # XXX - hack


class Aggregator(object):
    def __init__(self, aggregate_func, converter=None):
        """
        Arguments:
        aggregate_func -- aggregate function. Type determined by subclass

        Keyword Arguments:
        converter   -- None    : Use the field's converter (if defined).
                    -- Function: Use this function to convert the result.
        """

        self.func = aggregate_func
        self.converter = converter

    def compute(self, values):
        raise NotImplementedError("override compute")


class ReduceAggregator(Aggregator):
    def __init__(self, aggregate_func, initializer=None, converter=None):
        """
        Arguments:
        aggregate_func -- function accepts 2 arguments and returns a value.
        """
        self.initializer = initializer
        super().__init__(aggregate_func, converter=converter)

    def compute(self, values):
        return self.reduce(values)

    def reduce(self, edatas):
        initialized = False
        result = None

        for edata in edatas:
            edata = edata.value

            if edata is None:
                return

            if not initialized:
                initialized = True

                if self.initializer is None:
                    result = edata
                    return

                result = self.initializer

            result = self.func(result, edata)

        return result


class ComplexAggregator(Aggregator):
    def __init__(self, aggregate_func, converter=None):
        """
        An aggregator that takes all the entires in a group for a more complex calculation.

        Arguments:
        aggregate_func -- function accepts 1 argument of type list(EntryData) and
        returns a value.
        """
        super().__init__(aggregate_func, converter=converter)

    def compute(self, edatas):
        return self.func(edatas)


class Aggregators(object):
    @staticmethod
    def sum(initializer=0, converter=None):
        return ReduceAggregator(
            lambda acc, value: acc + value,
            initializer=initializer,
            converter=converter,
        )

    @staticmethod
    def count(initializer=0, converter=None):
        return ReduceAggregator(
            lambda acc, value: acc + 1,
            initializer=initializer,
            converter=converter,
        )

    @staticmethod
    def min(initializer=None, converter=None):
        return ReduceAggregator(
            lambda acc, value: acc if acc <= value else value,
            initializer=initializer,
            converter=converter,
        )

    @staticmethod
    def max(initializer=None, converter=None):
        return ReduceAggregator(
            lambda acc, value: acc if acc >= value else value,
            initializer=initializer,
            converter=converter,
        )


class BaseProjector(object):
    field_type = None  # required override
    source = None  # optional override
    keys = None  # optional override

    def __init__(self, source, *keys, **kwargs):
        """
        Arguments:
        source -- Name of the source to project from.
        *keys  -- Sequence : Key aliases to project in order of preference
                             (typically newest term to oldest term).
                  [None]   : Use entire value of the source (typically used
                             when source contains individual value instead of
                             dict of values).
                  [number]: Use number as index into source (used when source
                            is a sequence of values).

        Keyword Arguments:
        for_each_key -- If True, return the key to the source when iterated by
                        'for_each', else use the value. NOTE - if not None and
                        source is not used in a 'for_each' then the sheet will
                        assert during render.
        """
        self.source = source
        self.keys = None if keys[0] is None else tuple(keys)
        self.for_each_key = kwargs.get("for_each_key", None)

    def __call__(self, sheet, sources):
        try:
            result = self.do_project(sheet, sources)
        except (NoEntryException, ErrorEntryException):
            raise
        except Exception as e:
            # XXX - A debug log may be useful.
            # print 'debug - ', e, self.source, self.source
            logger.debug("Problem projecting keys %s, exc: %s", self.keys, e)
            raise ErrorEntryException("unexpected error occurred: {}".format(e))

        if result is None:
            raise NoEntryException("No entry found for source {}".format(self.source))

        return result

    def do_project(self, sheet, sources):
        raise NotImplementedError("override do_project")

    def project_raw(self, sheet, sources, ignore_exception=False):
        row = source_lookup(sources, self.source)

        if self.source in sheet.for_each:
            if self.for_each_key:
                row = row[0]
            else:
                row = row[-1]
        else:
            assert (
                self.for_each_key is None
            ), 'for_each_key set where "for_each" is not applied to the source'

        if row is None:
            raise NoEntryException("No entry for this row")

        if not ignore_exception and isinstance(row, Exception):
            raise ErrorEntryException(row, "Error occurred fetching row")

        if self.keys is None:
            # Setting 'self.keys' to None indicates that the field needs the
            # entire value contained in the source.
            return row
        elif isinstance(self.keys[0], int):
            # Setting 'self.keys' to an integer indicate that the field needs
            # to access contents of row by index.
            return row[self.keys[0]]
        else:
            # Setting 'self.keys' to one or more strings indicates that the
            # field needs to be accessed by key.
            try:
                return next(row[k] for k in self.keys if k in row)
            except (KeyError, StopIteration):
                raise NoEntryException(
                    "{} does not contain any key in {}".format(self.source, self.keys)
                )


class Projectors(object):
    class Identity(BaseProjector):
        field_type = FieldType.undefined

        def do_project(self, sheet, sources):
            try:
                row = self.project_raw(sheet, sources)
            except ErrorEntryException as e:
                row = e.exc

            return row

    class String(BaseProjector):
        field_type = FieldType.string

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a string from.
            """
            return str(self.project_raw(sheet, sources))

    class Boolean(String):
        field_type = FieldType.boolean

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a boolean from.
            """
            value = super().do_project(sheet, sources)

            if isinstance(value, str):
                return value.lower().strip() != "false"

            return True if value else False

    class Float(String):
        field_type = FieldType.number

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a float from.
            """
            value = super().do_project(sheet, sources)

            try:
                return float(value)
            except ValueError:
                return value

    class Number(String):
        field_type = FieldType.number

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a number from.
            """
            value = super().do_project(sheet, sources)

            try:
                return int(value)
            except ValueError:
                try:
                    return int(float(value))
                except ValueError:
                    pass

                return value

    class Percent(Number):
        field_type = FieldType.number

        def __init__(self, source, *keys, **kwargs):
            """
            Arguments:
            See 'BaseProjector'

            Keyword Arguments:
            invert -- False by default, if True will return 100 - value.
            """

            super().__init__(source, *keys, **kwargs)
            self.invert = kwargs.get("invert", False)

        def do_project(self, sheet, sources):
            """
            Arguments:
            sheet -- The decleration.Sheet this field belongs to, needed for
                     determining if this field's source was iterated by
                     'for_each'.
            source -- A set of sources to project a number from.
            """
            value = super().do_project(sheet, sources)
            return value if not self.invert else 100 - value

    class Sum(BaseProjector):
        field_type = FieldType.number

        def __init__(self, *field_projectors):
            """
            Arguments:
            field_projectors  -- Projectors to be summed.
            """
            self.field_projectors = field_projectors
            self.sources = set((field_fn.source for field_fn in field_projectors))

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a sum of fields.
            """
            result = 0

            for field_projector in self.field_projectors:
                result += field_projector(sheet, sources)

            return result

    class Div(BaseProjector):
        field_type = FieldType.number

        def __init__(self, numerator_projector, denominator_projector):
            """
            Arguments:
            numerator_projector -- A field project of FieldType.number.
            denominator_projector -- A field projector with FieldType.number

            Computed as numbertor / denominator
            """
            self.numerator_projector = numerator_projector
            self.denominator_projector = denominator_projector
            self.sources = set(
                (
                    field_fn.source
                    for field_fn in [numerator_projector, denominator_projector]
                )
            )

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a sum of fields.
            """

            result = self.numerator_projector(
                sheet, sources
            ) / self.denominator_projector(sheet, sources)

            return result

    class PercentCompute(Div):
        field_type = FieldType.number

        def __init__(self, numerator_projector, denominator_projector, **kwargs):
            """
            Arguments:
            invert:  Return result as (100 - result) if true
            See Div for remaining args.

            Computed as ((numberator/denomanator) * 100)
            """
            super().__init__(numerator_projector, denominator_projector)
            self.invert = kwargs.get("invert", False)

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a sum of fields.
            """
            result = super().do_project(sheet, sources)
            result *= 100
            return result if not self.invert else 100 - result

    class Any(BaseProjector):
        def __init__(self, field_type, *field_projectors):
            """
            Arguments:
            field_type -- The 'FieldType' for this field.
            field_projectors -- Projectors to be used. First one to succeed will be returned.
                                which is useful because non-existent keys cause failure.
            """
            self.field_type = field_type
            self.sources = set()
            for field_fn in field_projectors:

                if field_fn.source is None:
                    source = field_fn.sources
                else:
                    source = set([field_fn.source])

                self.sources = self.sources.union(source)

            self.field_projectors = field_projectors

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a the result of a function
                      from.
            """

            for field_projector in self.field_projectors:
                try:
                    return field_projector(sheet, sources)
                except NoEntryException:
                    pass

    class Func(BaseProjector):
        def __init__(self, field_type, func, *field_projectors):
            """
            Arguments:
            field_type -- The 'FieldType' for this field.
            func       -- A function to evaluate the projected fields.
            field_projectors -- Projectors values will be used as the arguments
                                to func.
            """
            self.field_type = field_type
            self.sources = set((field_fn.source for field_fn in field_projectors))
            self.func = func
            self.field_projectors = field_projectors

        def do_project(self, sheet, sources):
            """
            Arguments:
            source -- A set of sources to project a the result of a function
                      from.
            """
            values = []

            for field_projector in self.field_projectors:
                try:
                    values.append(field_projector(sheet, sources))
                except KeyError:
                    values.append(None)

            return self.func(*values)

    class Exception(BaseProjector):
        def __init__(self, source, *keys, **kwargs):
            """
            Arguments:
            See 'BaseProjector'

            Keyword Arguments:
            filter_exc -- List of exception types to convert to strings.
            """

            super().__init__(source, *keys, **kwargs)
            self.filter_exc = kwargs.get("filter_exc", [])

        def do_project(self, sheet, sources):
            row = self.project_raw(sheet, sources, ignore_exception=True)
            for exc_type in self.filter_exc:
                if isinstance(row, exc_type):
                    return str(row)

            if isinstance(row, Exception):
                raise ErrorEntryException(row, "Error occurred fetching row")

            return row


class EntryData(object):
    def __init__(self, **kwargs):
        """
        Keyword Arguments:
        value  -- Unconverted entry of a field.
        values -- Sequence of unconverted values for the current group or a
                  field.
        record -- Cross-section of all fields at this entry's position.
        common -- A dictionary of common data supplied to all fields.
        """
        self.__dict__.update(kwargs)


class Converters(object):
    @staticmethod
    def _file_size(value, unit):
        try:
            return file_size.size(value, unit)
        except Exception:
            return value

    @staticmethod
    def byte(edata):
        """
        Arguments:
        edata -- Take an 'EntryData' and returns the value as byte units.
        """
        return Converters._file_size(edata.value, file_size.byte)

    @staticmethod
    def scientific_units(edata):
        """
        Arguments:
        edata -- Take an 'EntryData' and returns the value as floating pint
                 International System Units.
        """
        return Converters._file_size(edata.value, file_size.si_float)

    @staticmethod
    def time_seconds(edata):
        """
        Arguments:
        edata -- Take an 'EntryData' and returns the value as time with format
                 HH:MM:SS.
        """
        time_stamp = int(edata.value)
        hours = time_stamp // 3600
        minutes = (time_stamp % 3600) // 60
        seconds = time_stamp % 60

        return "{:02}:{:02}:{:02}".format(hours, minutes, seconds)

    @staticmethod
    def time_milliseconds(edata):
        """
        Arguments:
        edata -- Take an 'EntryData' and returns the value as time with format
                 HH:MM:SS.
        """
        edata.value = int(edata.value) / 1000
        return Converters.time_seconds(edata)

    @staticmethod
    def standard(edata):
        """
        Arguments:
        edata -- Take an 'EntryData' and returns the value as a string.
        """
        return str(edata.value)

    @staticmethod
    def _list_to_str(edata, separator):
        return separator.join(edata)

    @staticmethod
    def list_to_comma_sep_str(edata):
        if len(edata.value):
            return Converters._list_to_str(edata.value, ", ")

        return "--"

    @staticmethod
    def round(decimal):
        def fun(edata):
            return round(float(edata.value), decimal)

        return fun


class Formatters(object):
    @staticmethod
    def _apply_style(style, not_style):
        return lambda unformatted: style() + unformatted + not_style()

    @staticmethod
    def _should_apply(predicate_fn, style, not_style):
        def _should_apply_helper(edata):
            if edata.value is None:
                return None

            try:
                if predicate_fn(edata):
                    return Formatters._apply_style(style, not_style)
                else:
                    return None
            except Exception:
                return None

        return _should_apply_helper

    @staticmethod
    def red_alert(predicate_fn):
        """
        Arguments:
        predicate_fn -- A function that accepts an 'EntryData' and if true sets
                        the foreground color to red for the entry.

        Return:
        A tuple containing the string form of the alert and the function to
        apply to formatting to a cell.
        """
        return (
            "red-alert",
            Formatters._should_apply(
                predicate_fn, terminal.fg_red, terminal.fg_not_red
            ),
        )

    @staticmethod
    def yellow_alert(predicate_fn):
        """Similar to red_alert but yellow instead of red."""

        return (
            "yellow-alert",
            Formatters._should_apply(
                predicate_fn, terminal.fg_yellow, terminal.fg_not_yellow
            ),
        )

    @staticmethod
    def green_alert(predicate_fn):
        """Similar to red_alert but green instead of red."""
        return (
            "green-alert",
            Formatters._should_apply(
                predicate_fn, terminal.fg_green, terminal.fg_not_green
            ),
        )

    @staticmethod
    def bold(predicate_fn):
        """Applies bold formatting if predicate evaluates to True."""
        return (
            "bold",
            Formatters._should_apply(predicate_fn, terminal.bold, terminal.unbold),
        )


class NoEntryException(Exception):
    pass


class ErrorEntryException(Exception):
    def __init__(self, error, *args):
        self.exc = error
        super().__init__(*args)
