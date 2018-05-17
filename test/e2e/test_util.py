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

import re

def parse_output(actual_out = "", horizontal = False, mearge_header = True):
    """
        commmon parser for all show commands will return touple of following
        @param heading : first line of output
        @param header: Second line of output
        @param params: list of parameters 
    
    """
    data =  actual_out.split('\n')
    if not data:
        return None, None, None
    heading = data.pop(0)
    if not data:
        return None, None, None
    if horizontal:
        header_line1 = data.pop(0)
        header_line2 = data.pop(0)
        row_data = data[-3]
        index = -4
        while not row_data:
            row_data = data[index]
            index = index - 1
        no_of_rows = row_data.split(':')[1]
        if mearge_header:
            return(heading, get_merged_header(header_line1, header_line2), no_of_rows)
        else:
            return(heading, header_line1 + header_line2, no_of_rows)
    else:
        header = data.pop(0)
        params = [item.split(':')[0].strip() for item in  data if item.split(':')[0].strip()]
        # handled beast color code
        # TODO: Create separate method for removing color code
        for i, item in enumerate(params):
            if "\x1b[0m" in item:
                params[i] = item[4:]
        if '\x1b[1m' in params:
            params.remove('\x1b[1m')
        return(heading, header, params)

def get_separate_output(in_str = '', mid_str=''):
    _regex = re.compile("~.+" + mid_str + " \(.+\)~.+")
    out_pattern, outstr = re.findall(_regex,in_str), re.split(_regex, in_str)
    output_list =[]
    for i, item in enumerate(out_pattern):
        output_list.append((item + outstr[i + 1]))
    return output_list

def get_merged_header(h1, h2):
    h1 = filter(None, h1.split(' '))
    h2 = filter(None, h2.split(' '))
    header = []
    if len(h1) == len(h2):
        for i in range(len(h1)):
            if h2[i] == '.':
                header.append(h1[i])
                continue
            header.append(h1[i] + ' ' + h2[i])
    return header

def check_for_subset(actual_list, expected_sub_list):
    if not expected_sub_list:
        return True
    if not actual_list:
        return False
    for i in expected_sub_list:
        if isinstance(i, tuple):
            found = False
            for s_i in i:
                if s_i is None:
                    found=True
                    break
                if s_i in actual_list:
                    found=True
                    break
            if not found:
                # print i
                return False
        else:
            if i not in actual_list:
                # print i
                return False
    return True