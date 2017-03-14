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

import re

from lib.health.exceptions import HealthException
from lib.health.operation import SimpleOperation, AggOperation, ComplexOperation, AssertDetailOperation
from lib.health.util import fetch_keys_from_dict, create_snapshot_key

SNAPSHOT_KEY_PREFIX = "SNAPSHOT"
SNAPSHOT_KEY_PATTERN = r"SNAPSHOT(\d+)$"

# Operation entry points

op_list = {
    "+": SimpleOperation("+").operate,
    "-": SimpleOperation("-").operate,
    "/": SimpleOperation("/").operate,
    "*": SimpleOperation("*").operate,
    ">": SimpleOperation(">").operate,
    "<": SimpleOperation("<").operate,
    ">=": SimpleOperation(">=").operate,
    "<=": SimpleOperation("<=").operate,
    "==": SimpleOperation("==").operate,
    "!=": SimpleOperation("!=").operate,
    "&&": SimpleOperation("AND").operate,
    "||": SimpleOperation("OR").operate,
    "AND": AggOperation("AND").operate,
    "OR": AggOperation("OR").operate,
    "SUM": AggOperation("+").operate,
    "AVG": AggOperation("AVG").operate,
    "EQUAL": AggOperation("==").operate,
    "MAX": AggOperation("MAX").operate,
    "MIN": AggOperation("MIN").operate,
    "PRODUCT": AggOperation("*").operate,
    "COUNT": AggOperation("COUNT").operate,
    "COUNT_ALL": AggOperation("COUNT_ALL").operate,
    "DIFF": ComplexOperation("DIFF").operate,
    "SD_ANOMALY": ComplexOperation("SD_ANOMALY").operate
}

assert_op_list = {
    "ASSERT": AssertDetailOperation("==").operate
}


def do_operation(op=None, arg1=None, arg2=None, group_by=None,
                 result_comp_op=None, result_comp_val=None, on_common_only=False):

    if op in op_list:
        return op_list[op](arg1, arg2, group_by, result_comp_op,
                           result_comp_val, on_common_only=on_common_only)

    if op == "%%" and (isinstance(arg1, int) or isinstance(arg1, float)):
        return op_list["*"](arg2, float(arg1) / 100, group_by,
                            on_common_only=on_common_only)

    return None


def select_keys(data={}, select_keys=[], select_from_keys=[]):
    if not data or not isinstance(data, dict):
        raise HealthException("Wrong Input Data for select operation.")

    if not select_keys:
        raise HealthException("No key provided for select operation.")

    if not select_from_keys:
        select_from_keys = []

    if (not select_from_keys or (select_from_keys[0] != "ALL"
                                 and not select_from_keys[0].startswith(SNAPSHOT_KEY_PREFIX))):
        select_from_keys.insert(0, create_snapshot_key(len(data.keys()) - 1))
    elif select_from_keys[0].startswith(SNAPSHOT_KEY_PREFIX):
        select_from_keys[0] = create_snapshot_key(int(re.search(SNAPSHOT_KEY_PATTERN, select_from_keys[0]).group(1)))

    result = fetch_keys_from_dict(data=data, keys=select_keys,
                                  from_keys=select_from_keys)

    if not result:
        raise HealthException(
            "Wrong input for select operation, Nothing matches with input keys.")

    return result


def do_assert(op=None, data={}, check_val=True, error=None, category=None,
              level=None, description=None, success_msg=None):
    if op in assert_op_list:
        return assert_op_list[op](data, check_val, error, category, level,
                                  description, success_msg)

    return None

def do_assert_if_check(op=None, arg1=None, arg2=None):
    """
    Function takes operands and operator for assert if condition and evaluate that conditions.
    Returns boolean to indicate need to skip assert or not, and argument to OR with actual assert input to filter keys
    """

    if arg1 is None or (not arg1 and arg1 != 0 and arg1 != False):
        return False, None

    if op and arg2:
        arg1 = do_operation(op=op, arg1=arg1, arg2=arg2)

    # return filter argument should be in boolean form, True for key to skip and False for key to check
    return not is_data_true(arg1), do_operation(op="==", arg1=arg1, arg2=False)

def is_data_true(data):
    """
    Function takes dictionary and finds out, it contains any valid non-empty, no False, no zero value
    """

    if not data:
        return False

    if not isinstance(data, dict):
        return True

    for _k in data:
        if is_data_true(data[_k]):
            return True

    return False