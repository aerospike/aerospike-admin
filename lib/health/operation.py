# Copyright 2013-2017 Aerospike, Inc.
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

import itertools
from math import sqrt
import operator

from lib.health.constants import AssertResultKey, ParserResultType
from lib.health.exceptions import HealthException
from lib.health.util import deep_merge_dicts, get_kv, merge_key, make_map, make_key

RESULT_TUPLE_HEADER = "RESULT"
NOKEY = ""

operators = {
    "+": operator.add,
    "-": operator.sub,
    "/": operator.div,
    "*": operator.mul,
    "%": operator.mod,
    '>': operator.gt,
    '<': operator.lt,
    '>=': operator.ge,
    '<=': operator.le,
    '==': operator.eq,
    '!=': operator.ne,
    'AND': operator.and_,
    'OR': operator.or_,
    'MAX': max,
    'MIN': min,
    'COUNT': len
}


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

    for i in v[1:]:
        k2, v2 = get_kv(i)
        if not op(v1, v2):
            return False

    return True


def vector_to_vector_diff_operation(kv, op, a):
    """
    Passed Vector values
    [ {(name, tag) : value}, {(name, tag) : value} ...

    Return boolean dictionary result

    { (name, tag) : True/False , (name, tag) : True/False, ... }
    """

    res = {}
    if not kv or not a:
        raise HealthException("Insufficient input for Diff operation ")

    exception_found = False
    try:
        for x, y in itertools.combinations(kv, 2):
            k1, v1 = get_kv(x)
            k2, v2 = get_kv(y)
            if op(abs(v1 - v2), a):
                try:
                    res[make_key(k1)] |= True
                except Exception:
                    res[make_key(k1)] = True

                try:
                    res[make_key(k2)] |= True
                except Exception:
                    res[make_key(k2)] = True

            else:
                try:
                    res[make_key(k1)] |= False
                except Exception:
                    res[make_key(k1)] = False

                try:
                    res[make_key(k2)] |= False
                except Exception:
                    res[make_key(k2)] = False

    except Exception:
        exception_found = True

    if exception_found:
        for x in kv:
            k, v = get_kv(x)
            res[make_key(k)] = None

    return res


def vector_to_vector_sd_anomaly_operation(kv, op, a):
    """
    Passed Vector values
    [ {(name, tag) : value}, {(name, tag) : value} ...

    Return boolean dictionary result

    { (name, tag) : True/False , (name, tag) : True/False, ... }
    """
    res = {}
    if not kv or not a:
        raise HealthException("Insufficient input for SD_ANOMALY operation ")

    exception_found = False
    try:
        n = len(kv)
        if n < 3:
            no_analogy = True
            range_start = 0
            range_end = 0
        else:
            values = [get_kv(m)[1] for m in kv]
            no_analogy = False
            s = sum(values)
            mean = float(s) / float(n)
            variance = 0
            for v in values:
                variance += pow((v - mean), 2)
            variance = float(variance) / float(n)
            sd = sqrt(variance)
            range_start = mean - (a * sd)
            range_end = mean + (a * sd)

        for x in kv:
            k, v = get_kv(x)
            if (no_analogy or (float(v) >= float(range_start)
                and float(v) <= float(range_end))):
                res[make_key(k)] = False
            else:
                res[make_key(k)] = True

    except Exception:
        exception_found = True

    if exception_found:
        for x in kv:
            k, v = get_kv(x)
            res[make_key(k)] = None

    return res


class SimpleOperation():

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

    def _operate_each_key(self, arg1, arg2):
        if isinstance(arg1, dict) and isinstance(arg2, dict):
            return None

        dict_first = True
        if isinstance(arg1, dict):
            d = arg1
            v = arg2
        elif isinstance(arg2, dict):
            d = arg2
            v = arg1
            dict_first = False
        else:
            try:
                # if any of the arg is type float or operation is division
                # cast all argument to float
                if self.op == operator.div and arg2 == 0:
                    return 0

                if self.op == operator.div or isinstance(arg1, float) or isinstance(arg2, float):
                    arg1 = float(arg1)
                    arg2 = float(arg2)

                return self.op(arg1, arg2)
            except Exception:
                return None

        res_dict = {}
        for _k in d:
            if dict_first:
                res_dict[_k] = self._operate_each_key(d[_k], v)
            else:
                res_dict[_k] = self._operate_each_key(v, d[_k])

        return res_dict

    def _operate_dicts(self, arg1, arg2, on_common_only=False):
        if isinstance(arg1, dict) and isinstance(arg2, dict):
            k1_set = set(arg1.keys())
            k2_set = set(arg2.keys())
            if ((len(k1_set - k2_set) > 0 or len(k2_set - k1_set) > 0)
                    and not on_common_only):
                raise HealthException(
                    "Wrong operands with non-matching keys for Simple operation.")
            res_dict = {}
            for _k in k1_set.intersection(k2_set):
                res_dict[_k] = self._operate_dicts(
                    arg1[_k], arg2[_k], on_common_only=on_common_only)
            return res_dict
        else:
            return self._operate_each_key(arg1, arg2)

    def operate(self, arg1, arg2, group_by=None, result_comp_op=None,
            result_comp_val=None, on_common_only=False):
        if arg1 is None or arg2 is None:
            raise HealthException("Wrong operands for Simple operation.")

        # No Group By So No Key Merging
        return self._operate_dicts(arg1, arg2, on_common_only=on_common_only)


class AggOperation():

    operator_and_function = {
        '+': lambda v: int_vector_to_scalar_operation(operators["+"], v),
        '*': lambda v: int_vector_to_scalar_operation(operators["*"], v),
        'AND': lambda v: bool_vector_to_scalar_operation(operators["AND"], v),
        'OR': lambda v: bool_vector_to_scalar_operation(operators["OR"], v),
        'AVG': lambda v: vector_to_scalar_avg_operation(operators["+"], v),
        'MAX': lambda v: int_vector_to_scalar_operation(operators["MAX"], v),
        'MIN': lambda v: int_vector_to_scalar_operation(operators["MIN"], v),
        '==': lambda v: vector_to_scalar_equal_operation(operators["=="], v),
        'COUNT': operators["COUNT"],
        'COUNT_ALL': operators["COUNT"],
    }

    def __init__(self, op):
        self.op = op
        self.op_fn = AggOperation.operator_and_function[op]

    def operate(self, arg1, arg2=None, group_by=None, result_comp_op=None,
            result_comp_val=None, on_common_only=False):
        if not arg1:
            raise HealthException("Wrong operand for Aggregation operation.")

        if group_by:
            arg1 = do_multiple_group_by(arg1, group_by)

        if not arg1:
            # if not valid group_by ids, we will get empty arg1
            raise HealthException(
                "Invalid group ids %s for Aggregation operation." % (str(group_by)))

        try:
            return apply_operator(arg1, NOKEY, self.op_fn, group_by[-1] if group_by else "CLUSTER", on_all_keys=False if self.op=="COUNT" else True)
        except Exception as e:
            raise HealthException(str(e) + " for Aggregation Operation")


class ComplexOperation():

    operator_and_function = {
        'DIFF': lambda kv, op, a: vector_to_vector_diff_operation(kv, op, a),
        'SD_ANOMALY': lambda kv, op, a: vector_to_vector_sd_anomaly_operation(kv, op, a),
    }

    def __init__(self, op):
        self.op_fn = ComplexOperation.operator_and_function[op]

    def operate(self, arg1, arg2=None, group_by=None, result_comp_op=None, result_comp_val=None, on_common_only=False):
        if not arg1:
            # if empty opearand
            raise HealthException("Wrong operand for Complex operation.")

        if group_by:
            arg1 = do_multiple_group_by(arg1, group_by)

        if not arg1:
            # if not valid group_by ids, we will get empty arg1
            raise HealthException(
                "Invalid group ids %s for Complex operation." % (str(group_by)))

        try:
            return apply_operator(arg1, NOKEY, 
                    lambda kv: self.op_fn(kv, operators[result_comp_op],
                        result_comp_val), group_by[-1]
                    if group_by else "CLUSTER")

        except Exception as e:
            raise HealthException(str(e) + " for Complex Operation")


class AssertOperation():

    def __init__(self, op):
        self.op = operators[op]

    def operate(self, data={}, check_val=True, error=None):
        if not data:
            raise HealthException("Wrong Input Data for ASSERT operation.")

        if not isinstance(data, dict):
            if not self.op(data, check_val):
                return ("ASSERT", error)
            return None

        v = find_data_vector(data)

        if not v:
            return ("ASSERT", error)
        for i in v:
            if not self.op(i, check_val):
                return ("ASSERT", error)

        return None


class AssertDetailOperation():

    """
    Takes vector as input and checks for assertion failure. In case of
    failure populates map with user passed message and vector of field
    which fail the assertions
    """

    def __init__(self, op):
        self.op = operators[op]

    def operate(self, data={}, check_val=True, error=None, category=None,
            level=None, description=None, success_msg=None):
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
            if not self.op(data, check_val):
                return (ParserResultType.ASSERT, res)
            return None

        kv = find_kv_vector(NOKEY, data, True)

        if not kv:
            return (ParserResultType.ASSERT, res)

        fail = False

        for i in kv:
            k, v = get_kv(i)
            if not self.op(v, check_val):
                res[AssertResultKey.SUCCESS] = False
                fail = True
                res[AssertResultKey.KEYS].append(str(k))

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
            "Wrong group id %s for group by operation." % (str(group_by)))

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
            res = deep_merge_dicts(res, do_group_by(data[(k, t)], group_by, keys))
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

# Recursive worker functions to apply operation


def apply_operator(data, key, op_fn, group_by=None, arg2=None, recurse=False, on_all_keys = True):
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
                res_dict[k] = op_fn(find_kv_vector(NOKEY, data[_key], True))
            else:
                # Apply operation on next level only, no further
                if isinstance(data[_key], dict):
                    # Next level is dict, so apply operation on keys
                    res_dict[k] = op_fn(data[_key].keys())
                else:
                    # Next level is not dict, so apply operation on value
                    res_dict[k] = op_fn([data[_key]])
        else:
            res_dict[_key] = apply_operator(
                data[_key], k, op_fn, group_by, arg2, recurse, on_all_keys=on_all_keys)

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


def find_kv_vector(key, data, recurse=False):
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

    for _key in sorted(data.keys()):
        k = merge_key(key, _key, recurse)
        if not isinstance(data[_key], dict):
            v.append(make_map(k, data[_key]))
        else:
            v.extend(find_kv_vector(k, data[_key], recurse))

    return v
