'''
Created on 13-Sep-2015

@author: Pavan Gupta
'''
import re

def parse_output(actual_out = "", horizontal = False):
    """
        commmon parser for all show commands will return touple of following
        @param heading : first line of output
        @param header: Second line of output
        @param params: list of parameters 
    
    """
    if horizontal:
        data =  actual_out.split('\n')
        heading = data.pop(0)
        header_line1 = data.pop(0)
        header_line2 = data.pop(0)
        no_of_rows = data[-3].split(':')[1]
        
        return(heading, get_merged_header(header_line1, header_line2), no_of_rows)
    else:
        data =  actual_out.split('\n')
        heading = data.pop(0)
        header = data.pop(0)
        params = [item.split(':')[0].strip() for item in  data if item.split(':')[0].strip()]
        # handled beast color code
        for i, item in enumerate(params):
            if "\x1b[0m" in item:
                params[i] = item[4:]
        if '\x1b[1m' in params:
            params.remove('\x1b[1m')
        return(heading, header, params)

def get_separate_output(in_str = '', mid_str=''):
    _regex = re.compile("~.+" + mid_str + "~.+")
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

