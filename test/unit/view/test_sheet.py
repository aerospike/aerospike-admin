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

import json
import unittest2 as unittest

from lib.view import sheet
from lib.view.sheet import (
    Aggregators,
    Converters,
    DynamicFields,
    Field,
    FieldType,
    Formatters,
    Projectors,
    Sheet,
    SheetStyle,
    Subgroup,
)


def do_render(*args, **kwargs):
    do_row = kwargs.pop("do_row", True)

    # Make sure column style renders without Exceptions.
    kwargs["style"] = SheetStyle.columns

    res = sheet.render(*args, **kwargs)

    # if res is not None:
    #     print(res)

    if do_row:
        # Make sure column style renders without Exceptions.
        kwargs["style"] = SheetStyle.rows

        res = sheet.render(*args, **kwargs)

        # if res is not None:
        #     print(res)

    # Return the json render for testing.
    kwargs["style"] = SheetStyle.json

    res = sheet.render(*args, **kwargs)

    if res is None:
        return res

    return json.loads(sheet.render(*args, **kwargs))


def do_render_column(*args, **kwargs):
    kwargs["do_row"] = False

    return do_render(*args, **kwargs)


class SheetTest(unittest.TestCase):
    def test_sheet_json_format(self):
        """Verify JSON sheet format."""
        test_sheet = Sheet(
            (
                Field(
                    "F",
                    Projectors.String("d", "f"),
                    converter=lambda edata: edata.value.upper(),
                ),
            ),
            from_source=("d",),
        )
        sources = dict(d=dict(n0=dict(f="v")))
        render = do_render(test_sheet, "test", sources)

        self.assertIn("groups", render)
        self.assertEqual(len(render["groups"]), 1)

        group = render["groups"][0]

        self.assertIn("records", group)
        self.assertEqual(len(group["records"]), 1)

        record = group["records"][0]

        self.assertIn("F", record)

        value = record["F"]

        self.assertIn("raw", value)
        self.assertIn("converted", value)
        self.assertEqual(value["raw"], "v")
        self.assertEqual(value["converted"], "V")

    def test_sheet_project_string(self):
        test_sheet = Sheet((Field("F", Projectors.String("d", "f")),), from_source="d")
        sources = dict(d=dict(n0=dict(f="v")))
        render = do_render(test_sheet, "test", sources)
        value = render["groups"][0]["records"][0]["F"]

        self.assertEqual(value["raw"], "v")
        self.assertEqual(value["converted"], "v")

    def test_sheet_project_boolean(self):
        test_sheet = Sheet((Field("F", Projectors.Boolean("d", "f")),), from_source="d")
        samples = [
            ("true", True, "True"),
            ("True", True, "True"),
            ("Garbage", True, "True"),
            (True, True, "True"),
            ("false", False, "False"),
            ("False", False, "False"),
            (False, False, "False"),
        ]

        def test_it(sample):
            sources = dict(d=dict(n0=dict(f=sample[0])))
            render = do_render(test_sheet, "test", sources)
            value = render["groups"][0]["records"][0]["F"]

            self.assertEqual(value["raw"], sample[1], str(sample))
            self.assertEqual(value["converted"], sample[2], str(sample))

        for sample in samples:
            test_it(sample)

    def test_sheet_project_float(self):
        test_sheet = Sheet((Field("F", Projectors.Float("d", "f")),), from_source="d")
        samples = [
            ("1.25", 1.25, "1.25"),
            (1.25, 1.25, "1.25"),
            ("42", 42.0, "42.0"),
            (42, 42.0, "42.0"),
        ]

        def test_it(sample):
            sources = dict(d=dict(n0=dict(f=sample[0])))
            render = do_render(test_sheet, "test", sources)
            value = render["groups"][0]["records"][0]["F"]

            self.assertEqual(value["raw"], sample[1], str(sample))
            self.assertEqual(value["converted"], sample[2], str(sample))

        for sample in samples:
            test_it(sample)

    def test_sheet_project_number(self):
        test_sheet = Sheet((Field("F", Projectors.Number("d", "f")),), from_source="d")
        samples = [("42", 42, "42"), (42, 42, "42"), ("1.25", 1, "1"), (1.25, 1, "1")]

        def test_it(sample):
            sources = dict(d=dict(n0=dict(f=sample[0])))
            render = do_render(test_sheet, "test", sources)
            value = render["groups"][0]["records"][0]["F"]

            self.assertEqual(value["raw"], sample[1], str(sample))
            self.assertEqual(value["converted"], sample[2], str(sample))

        for sample in samples:
            test_it(sample)

    def test_sheet_project_percent(self):
        samples = [
            ("42", False, 42, "42"),
            (42, False, 42, "42"),
            ("1.25", False, 1, "1"),
            (1.25, False, 1, "1"),
            ("42", True, 58, "58"),  # inverts
            (42, True, 58, "58"),
            ("1.25", True, 99, "99"),
            (1.25, True, 99, "99"),
        ]

        def test_it(sample):
            test_sheet = Sheet(
                (Field("F", Projectors.Percent("d", "f", invert=sample[1])),),
                from_source="d",
            )
            sources = dict(d=dict(n0=dict(f=sample[0])))
            render = do_render(test_sheet, "test", sources)
            value = render["groups"][0]["records"][0]["F"]

            self.assertEqual(value["raw"], sample[2], str(sample))
            self.assertEqual(value["converted"], sample[3], str(sample))

        for sample in samples:
            test_it(sample)

    def test_sheet_project_sum(self):
        test_sheet = Sheet(
            (
                Field(
                    "F",
                    Projectors.Sum(
                        Projectors.Number("d", "f0"), Projectors.Number("d", "f1")
                    ),
                ),
            ),
            from_source="d",
        )
        samples = [("42", "58", 100, "100"), (42, 58, 100, "100")]

        def test_it(sample):
            sources = dict(d=dict(n0=dict(f0=sample[0], f1=sample[1])))
            render = do_render(test_sheet, "test", sources)
            value = render["groups"][0]["records"][0]["F"]

            self.assertEqual(value["raw"], sample[2], str(sample))
            self.assertEqual(value["converted"], sample[3], str(sample))

        for sample in samples:
            test_it(sample)

    def test_sheet_project_func(self):
        test_sheet = Sheet(
            (
                Field(
                    "F",
                    Projectors.Func(
                        FieldType.boolean,
                        lambda *values: 42 in values,
                        Projectors.Number("d", "f0"),
                        Projectors.Number("d", "f1"),
                    ),
                ),
            ),
            from_source="d",
        )
        samples = [
            ("42", "58", True, "True"),
            (42, 58, True, "True"),
            (422, 588, False, "False"),
        ]

        def test_it(sample):
            sources = dict(d=dict(n0=dict(f0=sample[0], f1=sample[1])))
            render = do_render(test_sheet, "test", sources)
            value = render["groups"][0]["records"][0]["F"]

            self.assertEqual(value["raw"], sample[2], str(sample))
            self.assertEqual(value["converted"], sample[3], str(sample))

        for sample in samples:
            test_it(sample)

    def test_sheet_no_entry(self):
        test_sheet = Sheet(
            (Field("F", Projectors.String("d", "f"), hidden=False),), from_source=("d")
        )
        sources = dict(d=dict(n0={}))
        render = do_render(test_sheet, "test", sources)
        value = render["groups"][0]["records"][0]["F"]

        self.assertEqual(value["converted"], test_sheet.no_entry)

    def test_sheet_error_entry(self):
        test_sheet = Sheet(
            (Field("F", Projectors.String("d", "f")),), from_source=("d",)
        )
        sources = dict(d=dict(n0=Exception("error")))
        render = do_render(test_sheet, "test", sources)
        value = render["groups"][0]["records"][0]["F"]

        self.assertEqual(value["converted"], test_sheet.error_entry)

    def test_sheet_flat_value(self):
        test_sheet = Sheet(
            (Field("F", Projectors.String("d", None)),), from_source=("d",)
        )
        sources = dict(d=dict(n0="success"))
        render = do_render(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["F"]["raw"], "success")

    def test_sheet_indexed_value(self):
        test_sheet = Sheet((Field("F", Projectors.String("d", 1)),), from_source=("d",))
        sources = dict(d=dict(n0=["fail", "success", "fail"]))
        render = do_render(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["F"]["raw"], "success")

    def test_sheet_aggregation(self):
        test_sheet = Sheet(
            (Field("F", Projectors.Number("d", "f"), aggregator=Aggregators.sum()),),
            from_source=("d",),
        )
        sources = dict(d=dict(n0=dict(f="1"), n1=dict(f="1"), n2=dict(f="1")))
        render = do_render(test_sheet, "test", sources)
        group = render["groups"][0]

        self.assertIn("aggregates", group)

        value = group["aggregates"]["F"]

        self.assertEqual(value["raw"], 3)

    def test_sheet_aggregation_no_entry(self):
        test_sheet = Sheet(
            (
                Field(
                    "F",
                    Projectors.Number("d", "f"),
                    hidden=False,
                    aggregator=Aggregators.sum(),
                ),
            ),
            from_source=("d",),
        )
        sources = dict(d=dict(n0=dict(), n1=dict(), n2=dict()))
        render = do_render(test_sheet, "test", sources)
        group = render["groups"][0]

        self.assertIn("aggregates", group)

        value = group["aggregates"]["F"]

        self.assertEqual(value["raw"], "null")
        self.assertEqual(value["converted"], test_sheet.no_entry)

    def test_sheet_aggregation_error_entry(self):
        test_sheet = Sheet(
            (Field("F", Projectors.Number("d", "f"), aggregator=Aggregators.sum()),),
            from_source=("d",),
        )
        sources = dict(d=dict(n0=dict(f="1"), n1=Exception("err"), n2=dict(f="1")))
        render = do_render(test_sheet, "test", sources)
        group = render["groups"][0]

        self.assertIn("aggregates", group)

        value = group["aggregates"]["F"]

        self.assertEqual(value["raw"], "error")
        self.assertEqual(value["converted"], test_sheet.error_entry)

    def test_sheet_tuple_field(self):
        test_sheet = Sheet(
            (
                Subgroup(
                    "T",
                    (
                        Field("F0", Projectors.Number("d", "f0")),
                        Field("F1", Projectors.Number("d", "f1")),
                    ),
                ),
                Field("F2", Projectors.Number("d", "f2")),
            ),
            from_source=("d",),
        )
        sources = dict(d=dict(n0=dict(f0="0", f1="1", f2="2")))
        render = do_render_column(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertIn("F2", record)
        self.assertEqual(record["F2"]["raw"], 2)
        self.assertIn("T", record)

        t = record["T"]

        self.assertIn("F0", t)
        self.assertIn("F1", t)
        self.assertEqual(t["F0"]["raw"], 0)
        self.assertEqual(t["F1"]["raw"], 1)

    def test_sheet_tuple_field_hide_one(self):
        test_sheet = Sheet(
            (
                Subgroup(
                    "T",
                    (
                        Field("F0", Projectors.Number("d", "f0")),
                        Field("F1", Projectors.Number("d", "f1")),
                    ),
                ),
                Field("F2", Projectors.Number("d", "f2")),
            ),
            from_source=("d",),
        )
        sources = dict(d=dict(n0=dict(f1="1", f2="2")))
        render = do_render_column(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertIn("F2", record)
        self.assertEqual(record["F2"]["raw"], 2)
        self.assertIn("T", record)

        t = record["T"]

        self.assertNotIn("F0", t)
        self.assertIn("F1", t)
        self.assertEqual(t["F1"]["raw"], 1)

    def test_sheet_tuple_field_hide_all(self):
        test_sheet = Sheet(
            (
                Subgroup(
                    "T",
                    (
                        Field("F0", Projectors.Number("d", "f0")),
                        Field("F1", Projectors.Number("d", "f1")),
                    ),
                ),
                Field("F2", Projectors.Number("d", "f2")),
            ),
            from_source=("d",),
        )
        sources = dict(d=dict(n0=dict(f2="2")))
        render = do_render_column(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertIn("F2", record)
        self.assertEqual(record["F2"]["raw"], 2)
        self.assertNotIn("T", record)

    def test_sheet_converter_with_common(self):
        test_sheet = Sheet(
            (
                Field(
                    "F",
                    Projectors.String("d", "f"),
                    converter=lambda edata: "success"
                    if edata.value == edata.common["expected"]
                    else "failure",
                ),
            ),
            from_source="d",
        )
        sources = dict(d=dict(n0=dict(f="check")))
        common = dict(expected="check")
        render = do_render_column(test_sheet, "test", sources, common=common)
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["F"]["raw"], "check")
        self.assertEqual(record["F"]["converted"], "success")

    def test_sheet_group_by(self):
        test_sheet = Sheet(
            (
                Field("G", Projectors.String("d", "g")),
                Field("F", Projectors.Number("d", "f")),
            ),
            from_source="d",
            group_by="G",
        )
        sources = dict(d=dict(n0=dict(g="a", f=0), n1=dict(g="b", f=1)))
        render = do_render_column(test_sheet, "test", sources)

        self.assertEqual(len(render["groups"]), 2)

        group0 = render["groups"][0]
        group1 = render["groups"][1]

        self.assertNotIn("aggregates", group0)
        self.assertNotIn("aggregates", group1)

        record0 = group0["records"][0]
        record1 = group1["records"][0]

        self.assertEqual(record0["F"]["raw"], 0)
        self.assertEqual(record1["F"]["raw"], 1)

    def test_sheet_group_by_aggregation(self):
        test_sheet = Sheet(
            (
                Field("G", Projectors.String("d", "g")),
                Field("F", Projectors.Number("d", "f"), aggregator=Aggregators.count()),
            ),
            from_source="d",
            group_by="G",
        )
        sources = dict(
            d=dict(n0=dict(g="a", f=1), n1=dict(g="a", f=1), n2=dict(g="b", f=3))
        )
        render = do_render_column(test_sheet, "test", sources)

        self.assertEqual(len(render["groups"]), 2)

        aggr0 = render["groups"][0]["aggregates"]
        aggr1 = render["groups"][1]["aggregates"]

        self.assertEqual(aggr0["F"]["raw"], 2)
        self.assertEqual(aggr0["F"]["converted"], "2")
        self.assertEqual(aggr1["F"]["raw"], 1)

    def test_sheet_group_by_composite(self):
        test_sheet = Sheet(
            (
                Field("G0", Projectors.String("d", "g0")),
                Field("G1", Projectors.Boolean("d", "g1")),
                Field("F", Projectors.Number("d", "f"), aggregator=Aggregators.count()),
            ),
            from_source="d",
            group_by=("G0", "G1"),
        )
        sources = dict(
            d=dict(
                n0=dict(g0="a", g1="true", f=0),
                n1=dict(g0="a", g1="false", f=1),
                n2=dict(g0="b", g1="false", f=2),
                n3=dict(g0="b", g1="false", f=3),
            )
        )
        render = do_render_column(test_sheet, "test", sources)
        groups = render["groups"]

        self.assertEqual(len(groups), 3)
        self.assertEqual(len(groups[0]["records"]), 1)
        self.assertEqual(len(groups[1]["records"]), 1)
        self.assertEqual(len(groups[2]["records"]), 2)

    def test_sheet_order_by(self):
        test_sheet = Sheet(
            (Field("F", Projectors.Number("d", "f")),), from_source="d", order_by=("F")
        )
        sources = dict(d=dict(n0=dict(f=2), n1=dict(f=1), n2=dict(f=0)))
        render = do_render(test_sheet, "test", sources)
        records = render["groups"][0]["records"]
        v0 = records[0]["F"]["raw"]
        v2 = records[2]["F"]["raw"]

        self.assertEqual(v0, 0)
        self.assertEqual(v2, 2)

    def test_sheet_order_by_composite(self):
        test_sheet = Sheet(
            (
                Field("G", Projectors.String("d", "g")),
                Field("F", Projectors.Number("d", "f")),
            ),
            from_source="d",
            order_by=("G", "F"),
        )
        sources = dict(
            d=dict(
                n0=dict(g="a", f=2),
                n1=dict(g="a", f=0),
                n2=dict(g="b", f=1),
                n3=dict(g="b", f=3),
            )
        )
        render = do_render(test_sheet, "test", sources)
        records = render["groups"][0]["records"]

        self.assertEqual(records[0]["F"]["raw"], 0)
        self.assertEqual(records[1]["F"]["raw"], 2)
        self.assertEqual(records[2]["F"]["raw"], 1)
        self.assertEqual(records[3]["F"]["raw"], 3)

    def test_sheet_for_each_flat_value(self):
        test_sheet = Sheet(
            (
                Field("E", Projectors.String("ed", None, for_each_key=True)),
                Field("F", Projectors.Number("ed", None, for_each_key=False)),
            ),
            from_source="ed",
            for_each="ed",
        )
        sources = dict(ed=dict(n0=dict(a=1, b=2, c=3), n1=dict(a=11)))
        render = do_render(test_sheet, "test", sources)
        records = render["groups"][0]["records"]

        self.assertEqual(len(records), 4)

    def test_sheet_for_each_key_value(self):
        test_sheet = Sheet(
            (
                Field("E", Projectors.String("ed", None, for_each_key=True)),
                Field("F", Projectors.String("ed", "f")),
            ),
            from_source="ed",
            for_each="ed",
            group_by="E",
        )
        sources = dict(
            ed=dict(
                n0=dict(a=dict(f="success")),
                n1=dict(a=dict(f="success"), b=dict(f="success")),
            )
        )
        render = do_render_column(test_sheet, "test", sources)

        self.assertEqual(len(render["groups"]), 2)

        record0 = render["groups"][0]["records"][0]
        record1 = render["groups"][1]["records"][0]

        self.assertEqual(record0["E"]["raw"], "a")
        self.assertEqual(record0["F"]["raw"], "success")

        self.assertEqual(record1["E"]["raw"], "b")
        self.assertEqual(record1["F"]["raw"], "success")

    def test_sheet_for_each_indexed_value(self):
        test_sheet = Sheet(
            (
                Field("E0", Projectors.Number("ed", 0, for_each_key=True)),
                Field("E1", Projectors.Number("ed", 1, for_each_key=True)),
                Field("F", Projectors.Number("ed", 1, for_each_key=False)),
            ),
            from_source="ed",
            for_each="ed",
        )
        sources = dict(ed=dict(n0={(0, 0): (1, 0)}))
        render = do_render(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["E0"]["raw"], 0)
        self.assertEqual(record["E1"]["raw"], 0)
        self.assertEqual(record["F"]["raw"], 0)

    def test_sheet_for_each_error_entry(self):
        test_sheet = Sheet(
            (Field("F", Projectors.Number("ed", "f")),),
            from_source="ed",
            for_each="ed",
        )
        sources = dict(ed=dict(n0=dict(a=Exception())))
        render = do_render(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["F"]["raw"], "error")
        self.assertEqual(record["F"]["converted"], test_sheet.error_entry)

    def test_sheet_for_each_no_entry(self):
        test_sheet = Sheet(
            (Field("F", Projectors.Number("ed", "f"), hidden=False),),
            from_source="ed",
            for_each="ed",
        )
        sources = dict(ed=dict(n0=dict(a=dict()),))
        render = do_render(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["F"]["raw"], "null")
        self.assertEqual(record["F"]["converted"], test_sheet.no_entry)

    def test_sheet_converter_byte(self):
        converter = Converters.byte
        test_sheet = Sheet(
            (
                Field("U", Projectors.Number("d", "u"), converter=converter),
                Field("K", Projectors.Number("d", "k"), converter=converter),
                Field("M", Projectors.Number("d", "m"), converter=converter),
                Field("G", Projectors.Number("d", "g"), converter=converter),
                Field("T", Projectors.Number("d", "t"), converter=converter),
                Field("P", Projectors.Number("d", "p"), converter=converter),
            ),
            from_source="d",
        )
        u = 2
        k = u * 1024
        m = k * 1024
        g = m * 1024
        t = g * 1024
        p = t * 1024
        sources = dict(d=dict(n0=dict(u=u, k=k, m=m, g=g, t=t, p=p)))
        render = do_render(test_sheet, "test", sources)
        record = render["groups"][0]["records"][0]

        self.assertEqual(record["U"]["raw"], u)
        self.assertEqual(record["K"]["raw"], k)
        self.assertEqual(record["M"]["raw"], m)
        self.assertEqual(record["G"]["raw"], g)
        self.assertEqual(record["T"]["raw"], t)
        self.assertEqual(record["P"]["raw"], p)

        self.assertEqual(record["U"]["converted"], "2.000 B")
        self.assertEqual(record["K"]["converted"], "2.000 KB")
        self.assertEqual(record["M"]["converted"], "2.000 MB")
        self.assertEqual(record["G"]["converted"], "2.000 GB")
        self.assertEqual(record["T"]["converted"], "2.000 TB")
        self.assertEqual(record["P"]["converted"], "2.000 PB")

    def test_sheet_formatters(self):
        red = 1000
        yellow = 100
        green = 10
        none = 1
        test_sheet = Sheet(
            (
                Field(
                    "F",
                    Projectors.Number("d", "f"),
                    formatters=(
                        Formatters.red_alert(lambda edata: edata.value >= red),
                        Formatters.yellow_alert(lambda edata: edata.value >= yellow),
                        Formatters.green_alert(lambda edata: edata.value >= green),
                    ),
                ),
            ),
            from_source="d",
        )
        sources = dict(
            d=dict(n0=dict(f=red), n1=dict(f=yellow), n2=dict(f=green), n3=dict(f=none))
        )
        render = do_render(test_sheet, "test", sources)
        records = render["groups"][0]["records"]

        self.assertEqual(len(records), 4)

        for record in records:
            if record["F"]["raw"] == red:
                self.assertEqual(record["F"]["format"], "red-alert")
            elif record["F"]["raw"] == yellow:
                self.assertEqual(record["F"]["format"], "yellow-alert")
            elif record["F"]["raw"] == green:
                self.assertEqual(record["F"]["format"], "green-alert")
            elif record["F"]["raw"] == none:
                self.assertNotIn("format", record["F"])
            else:
                assert False, "illegal record value {}".format(record)

    def test_sheet_dynamic_field_exception(self):
        test_sheet = Sheet((DynamicFields("d"),), from_source="d")
        sources = dict(
            d=dict(n0=Exception("error"), n2=dict(f=1, g=1), n3=dict(f=1, g=1))
        )

        render = do_render(test_sheet, "test", sources)

        records = render["groups"][0]["records"]
        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["g"]["raw"], "error")

        for record in records:
            self.assertEqual(len(record), 2)

    def test_sheet_dynamic_field_exception_all(self):
        test_sheet = Sheet((DynamicFields("d"),), from_source="d")
        sources = dict(
            d=dict(n0=Exception("error"), n2=Exception("error"), n3=Exception("error"))
        )
        render = do_render(test_sheet, "test", sources)
        self.assertEqual(render, None)

    def test_sheet_dynamic_field_required(self):
        test_sheet = Sheet(
            (
                Field("F", Projectors.Number("d", "f")),
                DynamicFields("d", required=True),
            ),
            from_source="d",
        )
        sources = dict(d=dict(n0=dict(f=1, g=1), n2=dict(f=1), n3=dict(f=1)))
        render = do_render(test_sheet, "test", sources, selectors=["f"])
        records = render["groups"][0]["records"]

        self.assertEqual(len(records), 3)

        render = do_render(test_sheet, "test", sources, selectors=["nothing"])

        self.assertEqual(render, None)

    def test_sheet_dynamic_field(self):
        test_sheet = Sheet((DynamicFields("d"),), from_source="d")
        sources = dict(d=dict(n0=dict(f=1, g=1), n2=dict(f=1, g=1), n3=dict(f=1, g=1)))
        render = do_render(test_sheet, "test", sources)
        records = render["groups"][0]["records"]

        self.assertEqual(len(records), 3)

        for record in records:
            self.assertEqual(len(record), 2)

    def test_sheet_dynamic_field_selector(self):
        test_sheet = Sheet((DynamicFields("d"),), from_source="d")
        sources = dict(d=dict(n0=dict(f=1, g=1), n2=dict(f=1, g=1), n3=dict(f=1, g=1)))
        render = do_render(test_sheet, "test", sources, selectors=["f"])
        records = render["groups"][0]["records"]

        self.assertEqual(len(records), 3)

        for record in records:
            self.assertEqual(len(record), 1)
            self.assertEqual(list(record.keys())[0], "f")

    def numeric_sum_selector(self, key, is_numeric):
        if is_numeric:
            return Aggregators.sum()

    def test_sheet_dynamic_field_aggregator(self):
        test_sheet = Sheet(
            (DynamicFields("d", aggregator_selector=self.numeric_sum_selector),),
            from_source="d",
        )
        sources = dict(d=dict(n0=dict(f=1, g=1), n2=dict(f=1, g=1), n3=dict(f=1, g=1)))
        render = do_render(test_sheet, "test", sources)
        aggrs = render["groups"][0]["aggregates"]

        self.assertEqual(len(aggrs), 2)

        for aggr in aggrs.values():
            self.assertEqual(aggr["raw"], 3)

    def test_sheet_dynamic_field_aggregator_exception(self):
        test_sheet = Sheet(
            (DynamicFields("d", aggregator_selector=self.numeric_sum_selector),),
            from_source="d",
        )
        sources = dict(
            d=dict(n0=Exception("error"), n2=dict(f=1, g=1), n3=dict(f=1, g=1))
        )
        render = do_render(test_sheet, "test", sources)
        aggrs = render["groups"][0]["aggregates"]

        self.assertEqual(len(aggrs), 2)

        for aggr in aggrs.values():
            self.assertEqual(aggr["raw"], "error")

    def test_sheet_dynamic_field_aggregator_missing(self):
        test_sheet = Sheet(
            (DynamicFields("d", aggregator_selector=self.numeric_sum_selector),),
            from_source="d",
        )
        sources = dict(d=dict(n0=dict(f=1), n2=dict(f=1, g=1), n3=dict(f=1, g=1)))
        render = do_render(test_sheet, "test", sources)
        aggrs = render["groups"][0]["aggregates"]

        self.assertEqual(len(aggrs), 2)
        self.assertEqual(aggrs["g"]["raw"], 2)
        self.assertEqual(aggrs["f"]["raw"], 3)

    def test_sheet_dynamic_field_diff(self):
        test_sheet = Sheet((DynamicFields("d"),), from_source="d")
        sources = dict(
            d=dict(n0=dict(f=2, g=1), n2=dict(f=1, g=1), n3=dict(meh=1), n4=Exception())
        )
        render = do_render(test_sheet, "test", sources, dynamic_diff=True)
        records = render["groups"][0]["records"]

        for record in records:
            self.assertTrue("g" not in record)
            self.assertTrue("f" in record)

    def test_sheet_dynamic_field_diff_and_group_by(self):
        test_sheet = Sheet(
            (Field("group", Projectors.String("group", None)), DynamicFields("d"),),
            from_source=("d", "group"),
            group_by="group",
        )
        sources = dict(
            d=dict(
                n0=dict(f=1, g=2),
                n1=dict(f=1, g=2),
                n2=dict(f=3, g=4),
                n3=dict(f=4, g=3),
                n4=dict(f=5, g=6),
                n5=dict(f=5, g=7),
                n6=dict(f=8, g=9),
            ),
            group=dict(
                n0="group0",
                n1="group0",
                n2="group1",
                n3="group1",
                n4="group2",
                n5="group2",
                n6="group3",
            ),
        )

        render = do_render(test_sheet, "test", sources, dynamic_diff=True)

        groups = render["groups"]
        self.assertEqual(len(groups), 4)

        group0 = groups[0]

        for record in group0["records"]:
            self.assertTrue("group" in record)
            self.assertTrue("group0" in record["group"]["raw"])
            self.assertEqual(record["f"]["raw"], None)
            self.assertEqual(record["g"]["raw"], None)

        group1 = groups[1]
        group1record0 = group1["records"][0]
        group1record1 = group1["records"][1]

        for record in group1["records"]:
            self.assertTrue("group" in record)
            self.assertTrue("group1" in record["group"]["raw"])

        self.assertEqual(group1record0["f"]["raw"], 3)
        self.assertEqual(group1record0["g"]["raw"], 4)
        self.assertEqual(group1record1["f"]["raw"], 4)
        self.assertEqual(group1record1["g"]["raw"], 3)

        group2 = groups[2]
        group2record0 = group2["records"][0]
        group2record1 = group2["records"][1]

        for record in group2["records"]:
            self.assertTrue("group" in record)
            self.assertTrue("group2" in record["group"]["raw"])

        self.assertEqual(group2record0["f"]["raw"], None)
        self.assertEqual(group2record0["g"]["raw"], 6)
        self.assertEqual(group2record1["f"]["raw"], None)
        self.assertEqual(group2record1["g"]["raw"], 7)

        group3record0 = groups[3]["records"][0]

        self.assertTrue("group" in group3record0)
        self.assertTrue("group3" in group3record0["group"]["raw"])
        self.assertEqual(group3record0["f"]["raw"], None)
        self.assertEqual(group3record0["g"]["raw"], None)

    # def test_sheet_dynamic_field_every_nth_row(self):
    #     pass

    # def test_sheet_dynamic_field_every_nth_column(self):
    #     pass

    # def test_title_field(self):
    #     pass

    # def test_sheet_nested_dict_source(self):
    #     pass
