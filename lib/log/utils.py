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

# ------------------------------------------------
# Check line contains strings from strs in given order.
#
def contains_substrings_in_order(line="", strs=[]):
    if not strs:
        return True

    if not line:
        return False

    s_str = strs[0]
    if not s_str:
        return True

    if s_str in line:
        try:
            main_str = line.split(s_str, 1)[1]

        except Exception:
            main_str = ""

        if len(strs) <= 1:
            return True

        return contains_substrings_in_order(main_str, strs[1:])

    else:
        return False
