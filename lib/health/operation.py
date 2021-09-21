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

import copy
import itertools
from math import sqrt
import operator
import re

from lib.health.constants import AssertResultKey, MAJORITY, ParserResultType
from lib.health.exceptions import HealthException
from lib.health.util import (
    create_health_internal_tuple,
    create_value_list_to_save,
    deep_merge_dicts,
    find_majority_element,
    get_kv,
    get_value_from_health_internal_tuple,
    merge_key,
    make_map,
    make_key,
)

RESULT_TUPLE_HEADER = "RESULT"
NOKEY = ""

# Binary Operations

operators = {
    "+": operator.add,
    "-": operator.sub,
    "/": operator.truediv,
    "*": operator.mul,
    "%": operator.mod,
    ">": operator.gt,
    "<": operator.lt,
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
    "%%": lambda p, v: find_pct_value(p, v),
    "AND": operator.and_,
    "OR": operator.or_,
    "MAX": max,
    "MIN": min,
    "COUNT": len,
    "IN": lambda a, b: operator.contains(b, a),
}


def find_pct_value(pct, v):
    if (isinstance(v, int) or isinstance(v, float)) and (
        isinstance(pct, int) or isinstance(pct, float)
    ):
        return float(v) * (float(pct) / 100.0)

    return None


# Aggregation Operations


def basic_vector_to_scalar_operation(op, kv, typecast=int, initial_value=None):
    """
    Passed Vector values and type of value

    [ {(name, tag) : value}, {(name, tag) : value} ...

    Return aggregated result along with count of element processed
    """

    if not op or not kv or not isinstance(kv, list):
        raise HealthException("Insufficient input for vector operation ")

    if initial_value:
        found_first = True
        res = initial_value
    else:
        found_first = False
        res = None

    cnt = 0

    for i in kv:
        k1, v1 = get_kv(i)
        v1 = get_value_from_health_internal_tuple(v1)
        try:
            if not found_first:
                res = typecast(v1)
                found_first = True
                cnt = cnt + 1
                continue
        except Exception:
            continue

        try:
            res = op(res, v1)
            cnt = cnt + 1
        except Exception:
            continue

    return res, cnt


def int_vector_to_scalar_operation(op, v):
    r, _ = basic_vector_to_scalar_operation(op, v, typecast=int)
    return r


def float_vector_to_scalar_operation(op, v):
    r, _ = basic_vector_to_scalar_operation(op, v, typecast=float)
    return r


def bool_vector_to_scalar_operation(op, v):
    r, _ = basic_vector_to_scalar_operation(op, v, typecast=bool)
    return r


def vector_to_scalar_avg_operation(op, v):
    r, c = basic_vector_to_scalar_operation(op, v, typecast=int)
    if not r or c == 0:
        return None
    return float(r) / float(c)


def vector_to_scalar_equal_operation(op, v):
    """
    Passed Vector values

    [ {(name, tag) : value}, {(name, tag) : value} ...

    Return boolean scalar result True if all values are equal
    """

    if not op or not v or not isinstance(v, list):
        raise HealthException("Insufficient input for Equal operation ")

    i0 = v[0]
    k1, v1 = get_kv(i0)
    v1 = get_value_from_health_internal_tuple(v1)
    if v1 and isinstance(v1, list):
        v1 = sorted(v1)

    for i in v[1:]:
        k2, v2 = get_kv(i)
        v2 = get_value_from_health_internal_tuple(v2)
        if v2 and isinstance(v2, list):
            v2 = sorted(v2)

        if not op(v1, v2):
            return False

    return True


def vector_to_scalar_value_uniform_operation(op, v):
    """
    Passed Vector values

    [ {(name, tag) : value}, {(name, tag) : value} ...

    Return boolean scalar result True if all values are uniformly distributed
    """

    if not v or not isinstance(v, list):
        raise HealthException("Insufficient input for Value Uniform operation ")

    d = {}

    for i in v:
        k2, v2 = get_kv(i)
        v2 = get_value_from_health_internal_tuple(v2)
        if v2 and isinstance(v2, list):
            v2 = sorted(v2)

        if v2 not in d:
            d[v2] = 1
        else:
            d[v2] = d[v2] + 1

    minv = min(d.values())
    maxv = max(d.values())
    if (maxv - minv) > 1:
        return False

    return True


def vector_to_scalar_first_operation(op, v):
    """
    Passed Vector values

    [ {(name, tag) : value}, {(name, tag) : value} ...

    Returns first value from values
    """

    if not v or not isinstance(v, list):
        raise HealthException("Insufficient input for Random operation ")

    try:
        return get_value_from_health_internal_tuple(get_kv(v[0])[1])
    except Exception:
        return None


# Complex Operations


def vector_to_vector_diff_operation(kv, op, a, save_param):
    """
    Passed Vector values
    [ {(name, tag) : value}, {(name, tag) : value} ...

    Return boolean dictionary result

    { (name, tag) : True/False , (name, tag) : True/False, ... }
    """

    res = {}
    temp_res = {}
    if not kv or not a:
        raise HealthException("Insufficient input for Diff operation ")

    exception_found = False
    try:
        for x, y in itertools.combinations(kv, 2):
            k1, v1 = get_kv(x)
            k2, v2 = get_kv(y)

            _v1 = get_value_from_health_internal_tuple(v1)
            _v2 = get_value_from_health_internal_tuple(v2)

            if op(abs(_v1 - _v2), a):
                try:
                    temp_res[make_key(k1)] |= True

                except Exception:
                    temp_res[make_key(k1)] = True

                try:
                    temp_res[make_key(k2)] |= True
                except Exception:
                    temp_res[make_key(k2)] = True

            else:
                try:
                    temp_res[make_key(k1)] |= False
                except Exception:
                    temp_res[make_key(k1)] = False

                try:
                    temp_res[make_key(k2)] |= False
                except Exception:
                    temp_res[make_key(k2)] = False

        for i in kv:
            k, v = get_kv(i)
            val_to_save = create_value_list_to_save(
                save_param, value=temp_res[make_key(k)], op1=v
            )
            res[make_key(k)] = create_health_internal_tuple(
                temp_res[make_key(k)], val_to_save
            )

    except Exception:
        exception_found = True

    if exception_found:
        for x in kv:
            k, v = get_kv(x)
            res[make_key(k)] = create_health_internal_tuple(None, None)

    return res


def _find_match_operand_value(v, value_list):
    if not v or not value_list:
        return v

    if v == MAJORITY:
        return find_majority_element(value_list)

    return v


def vector_to_vector_no_match_operation(kv, op, a, save_param):
    """
    Passed Vector values
    [ {(name, tag) : value}, {(name, tag) : value} ...

    Return health internal tuple

    (True/False , [(key, value, formatting), (key, value, formatting), ...])
    """
    res = {}
    operand = get_value_from_health_internal_tuple(a)
    if not kv:
        raise HealthException("Insufficient input for NO_MATCH operation ")

    try:
        values = [get_value_from_health_internal_tuple(get_kv(m)[1]) for m in kv]
        match_operand = _find_match_operand_value(operand, values)

        result = False
        val_to_save = []
        for x in kv:
            k, v = get_kv(x)
            _val = get_value_from_health_internal_tuple(v)

            if not op(_val, match_operand):
                result |= True
                val_to_save += create_value_list_to_save(
                    save_param=None, value=result, op1=v
                )

        if operand and operand == MAJORITY:
            key = "Majority Value"
        else:
            key = "Expected Value"

        val_to_save += create_value_list_to_save(
            save_param=save_param, key=key, value=match_operand
        )
        res = create_health_internal_tuple(result, val_to_save)

    except Exception:
        res = create_health_internal_tuple(False, None)

    return res


def vector_to_vector_sd_anomaly_operation(kv, op, a, save_param):
    """
    Passed Vector values
    [ {(name, tag) : value}, {(name, tag) : value} ...

    Return health internal tuple

    (True/False , [(key, value, formatting), (key, value, formatting), ...])
    """
    res = {}
    sd_multiplier = get_value_from_health_internal_tuple(a)
    if not kv or not sd_multiplier:
        raise HealthException("Insufficient input for SD_ANOMALY operation ")

    try:
        n = len(kv)
        if n < 3:
            no_anomaly = True
            range_start = 0
            range_end = 0
        else:
            values = [get_value_from_health_internal_tuple(get_kv(m)[1]) for m in kv]
            no_anomaly = False

            try:
                # We should consider int and floats only
                s = sum(values)
            except Exception:
                no_anomaly = True

            if not no_anomaly:
                mean = float(s) / float(n)
                variance = 0
                for v in values:
                    variance += pow((v - mean), 2)
                variance = float(variance) / float(n)
                sd = sqrt(variance)
                range_start = mean - (sd_multiplier * sd)
                range_end = mean + (sd_multiplier * sd)

        result = False
        val_to_save = []
        for x in kv:
            k, v = get_kv(x)
            _val = get_value_from_health_internal_tuple(v)

            if not no_anomaly and (
                float(_val) < float(range_start) or float(_val) > float(range_end)
            ):
                result |= True
                val_to_save += create_value_list_to_save(
                    save_param=None, value=result, op1=v
                )

        val_to_save += create_value_list_to_save(save_param=save_param, value=result)
        res = create_health_internal_tuple(result, val_to_save)

    except Exception:
        res = create_health_internal_tuple(False, None)

    return res


###


class BinaryOperation:

    """
    Passed In Two Similar Vectors or Vector and Value

    [ {(name, tag) : value_a}, {(name, tag) : value_b2} ...
    op
    [ {(name, tag) : value_a1}, {(name, tag) : value_b1} ...

    OR

    [ {(name, tag) : value}, {(name, tag) : value} ...
    op
    value

    Returns boolean vector result of same field comparison of the both vector
    or value and value comparison.
    """

    def __init__(self, op):
        self.op = operators[op]

    def _operate_each_key(self, arg1, arg2, save_param=None):
        if isinstance(arg1, dict) and isinstance(arg2, dict):
            return None

        if not isinstance(arg1, dict) and not isinstance(arg2, dict):
            try:
                raw_arg1 = get_value_from_health_internal_tuple(arg1)
                raw_arg2 = get_value_from_health_internal_tuple(arg2)

                if self.op == operator.truediv and raw_arg2 == 0:
                    val_to_save = create_value_list_to_save(
                        save_param, value=0, op1=arg1, op2=arg2
                    )
                    return (0, val_to_save)

                # if any of the arg is type float or operation is division
                # cast all argument to float
                if (
                    self.op == operator.truediv
                    or isinstance(raw_arg1, float)
                    or isinstance(raw_arg2, float)
                ):
                    raw_arg1 = float(raw_arg1)
                    raw_arg2 = float(raw_arg2)

                result = self.op(raw_arg1, raw_arg2)
                val_to_save = create_value_list_to_save(
                    save_param, value=result, op1=arg1, op2=arg2
                )
                return create_health_internal_tuple(result, val_to_save)

            except Exception:
                return create_health_internal_tuple(None, [])

        dict_first = True
        if isinstance(arg1, dict):
            d = arg1
            v = arg2
        elif isinstance(arg2, dict):
            d = arg2
            v = arg1
            dict_first = False

        res_dict = {}
        for _k in d:
            if dict_first:
                res_dict[_k] = self._operate_each_key(d[_k], v, save_param=save_param)
            else:
                res_dict[_k] = self._operate_each_key(v, d[_k], save_param=save_param)

        return res_dict

    def _operate_dicts(self, arg1, arg2, on_common_only=False, save_param=None):
        if isinstance(arg1, dict) and isinstance(arg2, dict):
            k1_set = set(arg1.keys())
            k2_set = set(arg2.keys())
            if (
                len(k1_set - k2_set) > 0 or len(k2_set - k1_set) > 0
            ) and not on_common_only:
                raise HealthException(
                    "Wrong operands with non-matching keys for Binary operation."
                )
            res_dict = {}
            for _k in k1_set.intersection(k2_set):
                res_dict[_k] = self._operate_dicts(
                    arg1[_k],
                    arg2[_k],
                    on_common_only=on_common_only,
                    save_param=save_param,
                )
            return res_dict
        else:
            return self._operate_each_key(arg1, arg2, save_param=save_param)

    def operate(
        self,
        arg1,
        arg2,
        group_by=None,
        result_comp_op=None,
        result_comp_val=None,
        on_common_only=False,
        save_param=None,
    ):
        if arg1 is None or arg2 is None:
            raise HealthException("Wrong operands for Binary operation.")

        # No Group By So No Key Merging
        return self._operate_dicts(
            arg1, arg2, on_common_only=on_common_only, save_param=save_param
        )


class ApplyOperation:

    """
    Passed In Two Vectors or Vector and Value

    [ {(name, tag) : value_a}, {(name, tag) : value_b2} ...
    op
    [ {(name, tag) : value_a1}, {(name, tag) : value_b1} ...

    OR

    [ {(name, tag) : value}, {(name, tag) : value} ...
    op
    value

    Returns boolean vector result of comparison of the both vector
    or value and value comparison with consideration of apply operation (any or all).
    """

    apply_operators = {"ANY": any, "ALL": all}

    def __init__(self, op):
        self.op = self.apply_operators[op]

    def _operate_each_key(self, arg1, arg2, comp_op=None):
        if isinstance(arg1, dict):
            return None

        if not isinstance(arg2, dict):

            try:
                raw_arg1 = get_value_from_health_internal_tuple(arg1)
                raw_arg2 = get_value_from_health_internal_tuple(arg2)

                return comp_op(raw_arg1, raw_arg2)

            except Exception:
                return False

        res_list = []
        for _k in arg2:
            res_list.append(self._operate_each_key(arg1, arg2[_k], comp_op=comp_op))

        return self.op(res_list)

    def _operate_dicts(
        self, arg1, arg2, comp_op=None, check_common=True, save_param=None
    ):
        if isinstance(arg1, dict):
            if not isinstance(arg2, dict):
                check_common = False

            if check_common:
                k1_set = set(arg1.keys())
                k2_set = set(arg2.keys())
                if not list(k1_set.intersection(k2_set)):
                    check_common = False

            result_dict = {}
            for _k in arg1:
                if check_common:
                    if _k in arg2:
                        result_dict[_k] = self._operate_dicts(
                            arg1[_k],
                            arg2[_k],
                            comp_op=comp_op,
                            check_common=check_common,
                            save_param=save_param,
                        )

                else:
                    result_dict[_k] = self._operate_dicts(
                        arg1[_k],
                        arg2,
                        comp_op=comp_op,
                        check_common=check_common,
                        save_param=save_param,
                    )
            return result_dict

        else:
            result = self._operate_each_key(arg1, arg2, comp_op=comp_op)
            val_to_save = create_value_list_to_save(save_param, value=result, op1=arg1)
            return create_health_internal_tuple(result, val_to_save)

    def operate(
        self,
        arg1,
        arg2,
        group_by=None,
        result_comp_op=None,
        result_comp_val=None,
        on_common_only=False,
        save_param=None,
    ):
        if arg1 is None or arg2 is None:
            raise HealthException("Wrong operands for Apply operation.")

        if result_comp_op is None:
            raise HealthException("Wrong operator for Apply operation.")

        # No Group By So No Key Merging
        return self._operate_dicts(
            arg1, arg2, comp_op=operators[result_comp_op], save_param=save_param
        )


class SimpleOperation:

    """
    Passed In a Vector/Value and optional parameter

    Returns string result by applying operations like (split, trim etc.)
    """

    string_operators = {
        "SPLIT": lambda s, v: s.split(v),
        "UNIQUE": lambda s, v: len(s) == len(set(s)),
    }

    def __init__(self, op):
        self.op = self.string_operators[op]

    def _operate_each_key(self, arg1, arg2, save_param=None):
        if isinstance(arg1, dict):
            return None

        try:
            raw_arg1 = get_value_from_health_internal_tuple(arg1)
            raw_arg2 = get_value_from_health_internal_tuple(arg2)
            result = self.op(raw_arg1, raw_arg2)
            val_to_save = create_value_list_to_save(
                save_param, value=result, op1=arg1, op2=arg2
            )
            return create_health_internal_tuple(result, val_to_save)

        except Exception:
            return create_health_internal_tuple(None, [])

    def _operate_dicts(self, arg1, arg2, save_param=None):
        if isinstance(arg2, dict):
            raise HealthException(
                "Wrong parameter type (dictionary) for Simple operation."
            )

        if isinstance(arg1, dict):
            res_dict = {}
            for _k in arg1.keys():
                res_dict[_k] = self._operate_dicts(
                    arg1[_k], arg2, save_param=save_param
                )

            return res_dict
        else:
            return self._operate_each_key(arg1, arg2, save_param=save_param)

    def operate(
        self,
        arg1,
        arg2,
        group_by=None,
        result_comp_op=None,
        result_comp_val=None,
        on_common_only=False,
        save_param=None,
    ):
        if arg1 is None:
            raise HealthException("Wrong operands for Simple operation.")

        # No Group By So No Key Merging
        return self._operate_dicts(arg1, arg2, save_param=save_param)


class AggOperation:

    operator_and_function = {
        "+": lambda v: float_vector_to_scalar_operation(operators["+"], v),
        "*": lambda v: float_vector_to_scalar_operation(operators["*"], v),
        "AND": lambda v: bool_vector_to_scalar_operation(operators["AND"], v),
        "OR": lambda v: bool_vector_to_scalar_operation(operators["OR"], v),
        "AVG": lambda v: vector_to_scalar_avg_operation(operators["+"], v),
        "MAX": lambda v: float_vector_to_scalar_operation(operators["MAX"], v),
        "MIN": lambda v: float_vector_to_scalar_operation(operators["MIN"], v),
        "==": lambda v: vector_to_scalar_equal_operation(operators["=="], v),
        "FIRST": lambda v: vector_to_scalar_first_operation(operators["=="], v),
        "VALUE_UNIFORM": lambda v: vector_to_scalar_value_uniform_operation(
            operators["=="], v
        ),
        "COUNT": operators["COUNT"],
        "COUNT_ALL": operators["COUNT"],
    }

    def __init__(self, op):
        self.op = op
        self.op_fn = self.op_fn_distributor

    def op_fn_distributor(self, v, save_param):
        result = AggOperation.operator_and_function[self.op](v)

        val_to_save = create_value_list_to_save(save_param, value=result, op1=v)

        return create_health_internal_tuple(result, val_to_save)

    def operate(
        self,
        arg1,
        arg2=None,
        group_by=None,
        result_comp_op=None,
        result_comp_val=None,
        on_common_only=False,
        save_param=None,
    ):
        if not arg1:
            raise HealthException("Wrong operand for Aggregation operation.")

        if group_by:
            arg1 = do_multiple_group_by(arg1, group_by)

        if not arg1:
            # if not valid group_by ids, we will get empty arg1
            raise HealthException(
                "Invalid group ids %s for Aggregation operation." % (str(group_by))
            )

        try:
            return apply_operator(
                arg1,
                NOKEY,
                self.op_fn,
                group_by[-1] if group_by else "CLUSTER",
                on_all_keys=False if self.op == "COUNT" else True,
                save_param=save_param,
                update_saved_list=True,
            )
        except Exception as e:
            raise HealthException(str(e) + " for Aggregation Operation")


class ComplexOperation:

    operator_and_function = {
        "DIFF": lambda kv, op, a, sp: vector_to_vector_diff_operation(kv, op, a, sp),
        "SD_ANOMALY": lambda kv, op, a, sp: vector_to_vector_sd_anomaly_operation(
            kv, op, a, sp
        ),
        "NO_MATCH": lambda kv, op, a, sp: vector_to_vector_no_match_operation(
            kv, op, a, sp
        ),
    }

    def __init__(self, op):
        self.op = op
        self.op_fn = ComplexOperation.operator_and_function[op]

    def operate(
        self,
        arg1,
        arg2=None,
        group_by=None,
        result_comp_op=None,
        result_comp_val=None,
        on_common_only=False,
        save_param=None,
    ):
        if not arg1:
            # if empty opearand
            raise HealthException("Wrong operand for Complex operation.")

        if group_by:
            arg1 = do_multiple_group_by(arg1, group_by)

        if not arg1:
            # if not valid group_by ids, we will get empty arg1
            raise HealthException(
                "Invalid group ids %s for Complex operation." % (str(group_by))
            )

        try:
            return apply_operator(
                arg1,
                NOKEY,
                lambda kv, sp: self.op_fn(
                    kv, operators[result_comp_op], result_comp_val, sp
                ),
                group_by[-1] if group_by else "CLUSTER",
                save_param=save_param,
                update_saved_list=True,
            )

        except Exception as e:
            raise HealthException(str(e) + " for Complex Operation")


class AssertDetailOperation:

    """
    Takes vector as input and checks for assertion failure. In case of
    failure populates map with user passed message and vector of field
    which fail the assertions
    """

    def __init__(self, op):
        self.op = operators[op]

    def operate(
        self,
        data={},
        check_val=create_health_internal_tuple(True, []),
        error=None,
        category=None,
        level=None,
        description=None,
        success_msg=None,
    ):
        if not data:
            raise HealthException("Wrong Input Data for ASSERT operation.")

        res = {}
        res[AssertResultKey.FAIL_MSG] = str(error)
        res[AssertResultKey.DESCRIPTION] = description
        res[AssertResultKey.SUCCESS_MSG] = success_msg
        res[AssertResultKey.KEYS] = []
        try:
            res[AssertResultKey.CATEGORY] = category.upper().split(".")
        except Exception:
            res[AssertResultKey.CATEGORY] = None

        res[AssertResultKey.LEVEL] = level

        if not isinstance(data, dict):
            if not self.op(
                get_value_from_health_internal_tuple(data),
                get_value_from_health_internal_tuple(check_val),
            ):
                return (ParserResultType.ASSERT, res)
            return None

        kv = find_kv_vector(NOKEY, data, recurse=True, update_saved_list=False)

        if not kv:
            return (ParserResultType.ASSERT, res)

        fail = False

        for i in kv:
            k, v = get_kv(i)
            kv_tuple = (k, None)
            value_to_check = get_value_from_health_internal_tuple(v)
            if v[1]:
                kv_tuple = (k, v[1])

            if not self.op(
                value_to_check, get_value_from_health_internal_tuple(check_val)
            ):
                res[AssertResultKey.SUCCESS] = False
                fail = True
                res[AssertResultKey.KEYS].append(kv_tuple)

        if not fail:
            res[AssertResultKey.SUCCESS] = True

        return (ParserResultType.ASSERT, res)


# Group by operations


def do_group_by(data, group_by, keys=[]):
    if not group_by:
        raise HealthException("No Group ID for group by operation")

    if not data:
        raise HealthException("Wrong Input Data for group by operation.")

    if not isinstance(data, dict):
        raise HealthException(
            "Wrong group id %s for group by operation." % (str(group_by))
        )

    res = {}
    for k, t in data.keys():
        temp_d = res
        if t == group_by:
            if (k, t) not in temp_d:
                temp_d[(k, t)] = {}

            if keys:
                temp_d = temp_d[(k, t)]
                for _k in keys[:-1]:
                    if _k not in temp_d:
                        temp_d[_k] = {}
                    temp_d = temp_d[_k]
                temp_d[keys[-1]] = data[(k, t)]
            else:
                temp_d[(k, t)] = data[(k, t)]

        else:
            keys.append((k, t))

            try:
                res = deep_merge_dicts(res, do_group_by(data[(k, t)], group_by, keys))

            except Exception as e:
                raise e

            finally:
                keys.remove((k, t))

    return res


def do_multiple_group_by(d, group_by_list):
    if not group_by_list:
        raise HealthException("No Group ID for group by operation")
    if not d or not isinstance(d, dict):
        raise HealthException("Wrong Input Data for group by operation.")

    res = {}
    group_by = group_by_list[0]
    res = do_group_by(d, group_by)

    if res and len(group_by_list) > 1:
        for _k in res:
            res[_k] = do_multiple_group_by(res[_k], group_by_list[1:])

    return res


# Select operation


def _is_key_in_ignore_keys(key, ignore_keys):
    if not key or not ignore_keys:
        return False

    return any(re.search(ik[1], key) if ik[0] else key == ik[1] for ik in ignore_keys)


def select_keys_from_dict(
    data={}, keys=[], from_keys=[], ignore_keys=[], save_param=None, config_param=False
):
    """
    Function takes dictionary, list of keys to fetch, list of from_keys to filter scope

    Returns dictionary of selected keys and values
    """

    if not data or not isinstance(data, dict):
        raise HealthException("Wrong Input Data for select operation.")

    result_dict = {}
    if not keys:
        raise HealthException("No key provided for select operation.")

    for _key in data:
        if from_keys:
            f_key = from_keys[0]
            if isinstance(_key, tuple):
                # from_keys work with static component keys only, if we get
                # tuple keys means we have done with checking of all component
                # keys and not found any from key match so no need to check
                # further in this direction
                break

            if (f_key == "ALL") or (_key == f_key):
                # from_key is ALL or matching with _key
                child_res = select_keys_from_dict(
                    data[_key],
                    keys=keys,
                    from_keys=from_keys[1:] if len(from_keys) > 1 else [],
                    ignore_keys=ignore_keys,
                    save_param=save_param,
                    config_param=config_param,
                )

            else:
                # no key match, need to check further
                child_res = select_keys_from_dict(
                    data[_key],
                    keys=keys,
                    from_keys=from_keys,
                    ignore_keys=ignore_keys,
                    save_param=save_param,
                    config_param=config_param,
                )

            if child_res:
                if f_key == "ALL":
                    # It assumes ALL is only for top snapshot level
                    result_dict[(_key, "SNAPSHOT")] = copy.deepcopy(child_res)
                else:
                    result_dict = deep_merge_dicts(
                        result_dict, copy.deepcopy(child_res)
                    )

        else:
            # if (False, "*", None) in keys and isinstance(_key, tuple):
            #     result_dict[_key] = copy.deepcopy(data[_key])
            if isinstance(_key, tuple) and _key[1] == "KEY":
                for check_substring, s_key, new_name in keys:
                    if (
                        (
                            s_key == "*"
                            and not _is_key_in_ignore_keys(_key[0], ignore_keys)
                        )
                        or (check_substring and re.search(s_key, _key[0]))
                        or (not check_substring and _key[0] == s_key)
                    ):

                        val_to_save = create_value_list_to_save(
                            save_param=save_param,
                            key=_key[0],
                            value=data[_key],
                            formatting=not config_param,
                        )

                        if new_name:
                            result_dict[
                                (new_name, "KEY")
                            ] = create_health_internal_tuple(data[_key], val_to_save)

                        else:
                            result_dict[_key] = create_health_internal_tuple(
                                data[_key], val_to_save
                            )

                        break

            elif data[_key] and isinstance(data[_key], dict):
                child_res = select_keys_from_dict(
                    data[_key],
                    keys=keys,
                    ignore_keys=ignore_keys,
                    save_param=save_param,
                    config_param=config_param,
                )
                if child_res:
                    if isinstance(_key, tuple):
                        result_dict[_key] = copy.deepcopy(child_res)
                    else:
                        result_dict = deep_merge_dicts(
                            result_dict, copy.deepcopy(child_res)
                        )

    return result_dict


# Recursive worker functions to apply operation


def apply_operator(
    data,
    key,
    op_fn,
    group_by=None,
    arg2=None,
    recurse=False,
    on_all_keys=True,
    save_param=None,
    update_saved_list=False,
):
    res_dict = {}
    if not data or not isinstance(data, dict):
        raise HealthException("Wrong Input Data ")

    if not group_by:
        raise HealthException("No Group Id ")

    for _key in data.keys():
        k = merge_key(key, _key, recurse)
        if _key[1] == group_by:
            # User merged key for aggregation result
            if on_all_keys:
                # Apply operation on all leaf values
                res_dict[k] = op_fn(
                    find_kv_vector(
                        NOKEY,
                        data[_key],
                        recurse=True,
                        update_saved_list=update_saved_list,
                    ),
                    save_param,
                )
            else:
                # Apply operation on next level only, no further
                if isinstance(data[_key], dict):
                    # Next level is dict, so apply operation on keys
                    res_dict[k] = op_fn(list(data[_key].keys()), save_param)
                else:
                    # Next level is not dict, so apply operation on value
                    res_dict[k] = op_fn([data[_key]], save_param)
        else:
            res_dict[_key] = apply_operator(
                data[_key],
                k,
                op_fn,
                group_by,
                arg2,
                recurse,
                on_all_keys=on_all_keys,
                save_param=save_param,
                update_saved_list=update_saved_list,
            )

    return res_dict


def find_data_vector(data_dict):
    v = []
    if data_dict is None:
        return v

    if not isinstance(data_dict, dict):
        v.append(data_dict)
        return v

    for _key in sorted(data_dict.keys()):
        v.extend(find_data_vector(data_dict[_key]))

    return v


def add_prefix_to_saved_keys(prefix, data):
    if not prefix or not data or not data[1]:
        return data

    new_saved_value_list = []
    for i in data[1]:
        _k = prefix
        if i[0] and len(i[0].strip()) > 0:
            _k += "/%s" % (i[0])
        new_saved_value_list.append((_k, i[1], i[2]))

    return create_health_internal_tuple(data[0], new_saved_value_list)


def find_kv_vector(key, data, recurse=False, update_saved_list=False):
    """
    Function takes a arbitrary next dictionary and creates
    vector of based level key and value pair in form

    [ {(key, "KEY"): value1}, {(key1: "KEY") : value1} ... ]

    If recurse is tree key is entire "/" path from root

    e.g ascluster/sfo-counteraero8.alcfd.com:3000/dlog_overwritten_error
    """

    v = []
    if data is None:
        return v

    if not isinstance(data, dict):
        k = merge_key(key, " ", recurse)
        v.append(make_map(k, data))
        return v

    for _key in sorted(data.keys()):
        k = merge_key(key, _key, recurse)
        if not isinstance(data[_key], dict):

            if _key[1] == "KEY":
                _k = key

            else:
                _k = k
            v.append(
                make_map(
                    k,
                    add_prefix_to_saved_keys(_k, data[_key])
                    if update_saved_list
                    else data[_key],
                )
            )
            # v.append(make_map(k, data[_key]))
        else:
            v.extend(
                find_kv_vector(
                    k, data[_key], recurse=recurse, update_saved_list=update_saved_list
                )
            )

    return v
