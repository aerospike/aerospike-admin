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
import copy

import re
import threading
import subprocess
import pipes
import sys
import StringIO

# Dictionary to contain feature and related stats to identify state of that feature
# Format : { feature1: ((service_stat1, service_stat2, ....), (namespace_stat1, namespace_stat2, ...), ...}

FEATURE_KEYS = {
        "KVS": (('stat_read_reqs', 'stat_write_reqs'), ('client_read_error', 'client_read_success', 'client_write_error', 'client_write_success')),
        "UDF": (('udf_read_reqs', 'udf_write_reqs'), ('client_udf_complete', 'client_udf_error')),
        "Batch": (('batch_initiate', 'batch_index_initiate'), None),
        "Scan": (('tscan_initiate', 'basic_scans_succeeded', 'basic_scans_failed', 'aggr_scans_succeeded', 'aggr_scans_failed', 'udf_bg_scans_succeeded', 'udf_bg_scans_failed'),
                ('scan_basic_complete', 'scan_basic_error', 'scan_aggr_complete', 'scan_aggr_error', 'scan_udf_bg_complete', 'scan_udf_bg_error')),
        "SINDEX": (('sindex-used-bytes-memory'), ('memory_used_sindex_bytes')),
        "Query": (('query_reqs', 'query_success'), ('query_reqs', 'query_success')),
        "Aggregation": (('query_agg', 'query_agg_success'), ('query_agg', 'query_agg_success')),
        "LDT": (('sub-records', 'ldt-writes', 'ldt-reads', 'ldt-deletes', 'ldt_writes', 'ldt_reads', 'ldt_deletes', 'sub_objects'),
                ('ldt-writes', 'ldt-reads', 'ldt-deletes', 'ldt_writes', 'ldt_reads', 'ldt_deletes')),
        "XDR Enabled": (('stat_read_reqs_xdr', 'xdr_read_success', 'xdr_read_error'), None),
        "XDR Destination": (('stat_write_reqs_xdr'), ('xdr_write_success')),
    }

class Future(object):

    """
    Very basic implementation of a async future.
    """

    def __init__(self, func, *args, **kwargs):
        self._result = None

        args = list(args)
        args.insert(0, func)
        self.exc = None

        def wrapper(func, *args, **kwargs):
            self.exc = None
            try:
                self._result = func(*args, **kwargs)
            except Exception as e:
                self.exc = e

        self._worker = threading.Thread(target=wrapper,
                                        args=args, kwargs=kwargs)

    def start(self):
        self._worker.start()
        return self

    def result(self):
        if self.exc:
            raise self.exc
        self._worker.join()
        return self._result


def shell_command(command):
    """
    command is a list of ['cmd','arg1','arg2',...]
    """

    command = pipes.quote(" ".join(command))
    command = ['sh', '-c', "'%s'" % (command)]
    try:
        p = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        out, err = p.communicate()
    except Exception:
        return '', 'error'
    else:
        return out, err

    # Redirecting the stdout to use the output elsewhere


def capture_stdout(func, line=''):
    """
    Redirecting the stdout to use the output elsewhere
    """

    sys.stdout.flush()
    old = sys.stdout
    capturer = StringIO.StringIO()
    sys.stdout = capturer

    func(line)

    output = capturer.getvalue()
    sys.stdout = old
    return output


def compile_likes(likes):
    likes = map(re.escape, likes)
    likes = "|".join(likes)
    likes = re.compile(likes)
    return likes


def filter_list(ilist, pattern_list):
    if not ilist or not pattern_list:
        return ilist
    likes = compile_likes(pattern_list)
    return filter(likes.search, ilist)


def clear_val_from_dict(keys, d, val):
    for key in keys:
        if key in d and val in d[key]:
            d[key].remove(val)


def fetch_argument(line, arg, default):
    success = True
    try:
        if arg in line:
            i = line.index(arg)
            val = line[i + 1]
            return success, val
    except Exception:
        pass
    return not success, default


def fetch_line_clear_dict(line, arg, return_type, default, keys, d):
    if not line:
        return default
    try:
        success, _val = fetch_argument(line, arg, default)
        if _val is not None:
            val = return_type(_val)
        else:
            val = None

        if success and keys and d:
            clear_val_from_dict(keys, d, arg)
            clear_val_from_dict(keys, d, _val)

    except Exception:
        val = default
    return val


def get_arg_and_delete_from_mods(line, arg, return_type, default, modifiers, mods):
    try:
        val = fetch_line_clear_dict(
            line=line, arg=arg, return_type=return_type, default=default, keys=modifiers, d=mods)
        line.remove(arg)
        if val:
            line.remove(str(val))
    except Exception:
        val = default
    return val


def check_arg_and_delete_from_mods(line, arg, default, modifiers, mods):
    try:
        if arg in line:
            val = True
            clear_val_from_dict(modifiers, mods, arg)
            line.remove(arg)
        else:
            val = False
    except Exception:
        val = default
    return val

CMD_FILE_SINGLE_LINE_COMMENT_START = "//"
CMD_FILE_MULTI_LINE_COMMENT_START = "/*"
CMD_FILE_MULTI_LINE_COMMENT_END = "*/"


def parse_commands(file_or_queries, command_end_char=";", is_file=True):
    commands = ""
    try:
        commented = False
        if is_file:
            lines = open(file_or_queries, 'r').readlines()
        else:
            lines = file_or_queries.split("\n")

        for line in lines:
            if not line or not line.strip():
                continue
            line = line.strip()
            if commented:
                if line.endswith(CMD_FILE_MULTI_LINE_COMMENT_END):
                    commented = False
                continue
            if line.startswith(CMD_FILE_SINGLE_LINE_COMMENT_START):
                continue
            if line.startswith(CMD_FILE_MULTI_LINE_COMMENT_START):
                if not line.endswith(CMD_FILE_MULTI_LINE_COMMENT_END):
                    commented = True
                continue
            try:
                if line.endswith(command_end_char):
                    line = line.replace('\n', '')
                else:
                    line = line.replace('\n', ' ')
                commands = commands + line
            except Exception:
                commands = line
    except Exception:
        pass
    return commands


def parse_queries(file, delimiter=";", is_file=True):
    queries_str = parse_commands(file, is_file=is_file)
    if queries_str:
        return queries_str.split(delimiter)
    else:
        return []


def set_value_in_dict(d, key, value):
    if (not d or not key or (not value and value != 0 and value != False)
            or isinstance(value, Exception)):
        return
    d[key] = value


def get_value_from_dict(d, keys, default_value=None, return_type=None):
    if not isinstance(keys, tuple):
        keys = (keys,)
    for key in keys:
        if key in d:
            val = d[key]
            if return_type and val:
                try:
                    return return_type(val)
                except:
                    pass
            return val
    return default_value


def strip_string(search_str):
    search_str = search_str.strip()
    if search_str[0] == "\"" or search_str[0] == "\'":
        return search_str[1:len(search_str) - 1]
    else:
        return search_str


def flip_keys(orig_data):
    new_data = {}
    for key1, data1 in orig_data.iteritems():
        if isinstance(data1, Exception):
            continue
        for key2, data2 in data1.iteritems():
            if key2 not in new_data:
                new_data[key2] = {}
            new_data[key2][key1] = data2

    return new_data


def first_key_to_upper(data):
    if not data or not isinstance(data, dict):
        return data
    updated_dict = {}
    for k, v in data.iteritems():
        updated_dict[k.upper()] = v
    return updated_dict


def restructure_sys_data(content, cmd):
    if not content:
        return {}
    if cmd == "meminfo":
        pass
    elif cmd in ["free-m", "top"]:
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "iostat":
        try:
            for n in content.keys():
                c = content[n]
                c = c["iostats"][-1]
                if "device_stat" in c:
                    d_s = {}
                    for d in c["device_stat"]:
                        d_s[d["Device"]] = d
                    c["device_stat"] = d_s
                content[n] = c
        except Exception as e:
            print e
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "interrupts":
        try:
            for n in content.keys():
                try:
                    interrupt_list = content[n]["device_interrupts"]
                except Exception:
                    continue
                new_interrrupt_dict = {}
                for i in interrupt_list:
                    new_interrrupt = {}
                    itype = i["interrupt_type"]
                    iid = i["interrupt_id"]
                    idev = i["device_name"]
                    new_interrrupt[idev] = i["interrupts"]
                    if itype not in new_interrrupt_dict:
                        new_interrrupt_dict[itype] = {}
                    if iid not in new_interrrupt_dict[itype]:
                        new_interrrupt_dict[itype][iid] = {}
                    new_interrrupt_dict[itype][iid].update(
                        copy.deepcopy(new_interrrupt))
                content[n]["device_interrupts"] = new_interrrupt_dict
        except Exception as e:
            print e
        content = flip_keys(content)
        content = first_key_to_upper(content)
    elif cmd == "df":
        try:
            for n in content.keys():
                try:
                    file_system_list = content[n]["Filesystems"]
                except Exception:
                    continue
                new_df_dict = {}
                for fs in file_system_list:
                    name = fs["name"]
                    if name not in new_df_dict:
                        new_df_dict[name] = {}
                    new_df_dict[name].update(copy.deepcopy(fs))

                content[n] = new_df_dict
        except Exception:
            pass

    return content

def get_value_from_second_level_of_dict(data, keys, default_value=None, return_type=None):
    """
    Function takes dictionary and keys to find values inside all subkeys of dictionary.
    Returns dictionary containing subkey and value of input keys
    """

    res_dict = {}
    if not data or isinstance(data, Exception):
        return res_dict

    for _k in data:
        if not data[_k] or isinstance(data[_k], Exception):
            continue

        res_dict[_k] = get_value_from_dict(data[_k], keys, default_value=default_value, return_type=return_type)

    return res_dict

def add_dicts(d1, d2):
    """
    Function takes two dictionaries and merges those to one dictionary by adding values for same key.
    """

    if not d2:
        return d1

    for _k in d2:
        if _k in d1:
            d1[_k] += d2[_k]
        else:
            d1[_k] = d2[_k]

    return d1

def pct_to_value(data, d_pct):
    """
    Function takes dictionary with base value, and dictionary with percentage and converts percentage to value.
    """

    if not data or not d_pct:
        return data

    out_map = {}
    for _k in data:
        if _k not in d_pct:
            continue

        out_map[_k] = (float(data[_k])/100.0) * float(d_pct[_k])

    return out_map

def is_keyval_greater_than_value(data={}, keys=(), value=0, is_and=False, type_check=int):
    """
    Function takes dictionary, keys and value to compare.
    Returns boolean to indicate value for key is greater than comparing value or not.
    """

    if not keys:
        return True

    if not data:
        return False

    if not isinstance(keys, tuple):
        keys = (keys,)

    if is_and:
        if all(get_value_from_dict(data, k, value, type_check) > value for k in keys):
            return True

    else:
        if any(get_value_from_dict(data, k, value, type_check) > value for k in keys):
            return True

    return False

def check_feature_by_keys(service_data=None, service_keys=None, ns_data=None, ns_keys=None):
    """
    Function takes dictionary of service data, service keys, dictionary of namespace data and namespace keys.
    Returns boolean to indicate service key in service data or namespace key in namespace data has non-zero value or not.
    """

    if service_data and not isinstance(service_data, Exception) and service_keys:
        if is_keyval_greater_than_value(service_data, service_keys):
            return True

    if ns_data and ns_keys:
        for ns, nsval in ns_data.iteritems():
            if not nsval or isinstance(nsval, Exception):
                continue
            if is_keyval_greater_than_value(nsval, ns_keys):
                return True

    return False

def find_features_for_cluster(service_data, ns_data):
    """
    Function takes dictionary of service data and dictionary of namespace data.
    Returns list of active (used) features identifying by comparing respective keys for non-zero value.
    """

    features = []

    for feature, keys in FEATURE_KEYS.iteritems():
        for node, d in service_data.iteritems():

            ns_d = None

            if node in ns_data and not isinstance(ns_data[node], Exception):
                ns_d = ns_data[node]

            if check_feature_by_keys(d, keys[0], ns_d, keys[1]):
                features.append(feature)
                break

    return features

def compute_set_overhead_for_ns(set_stats, ns):
    """
    Function takes set stat and namespace name.
    Returns set overhead for input namespace name.
    """

    if not ns or not set_stats or isinstance(set_stats, Exception):
        return 0

    overhead = 0
    for _k, stats in set_stats.iteritems():
        if not stats or isinstance(stats, Exception):
            continue

        ns_name = get_value_from_second_level_of_dict(stats, ("ns", "ns_name"), default_value=None, return_type=str).values()[0]
        if ns_name != ns:
            continue

        set_name = get_value_from_second_level_of_dict(stats, ("set", "set_name"), default_value="", return_type=str).values()[0]
        objects = sum(get_value_from_second_level_of_dict(stats, ("objects", "n_objects"), default_value=0, return_type=int).values())
        overhead += objects * (9 + len(set_name))

    return overhead

def compute_license_data_size(namespace_stats, set_stats, cluster_dict, ns_dict):
    """
    Function takes dictionary of  service stats, dictionary of namespace stats, cluster output dictionary and namespace output dictionary.
    Function finds license data size per namespace, and per cluster and updates output dictionaries.
    """

    if not namespace_stats:
        return

    cl_memory_data_size = 0
    cl_device_data_size = 0

    for ns, ns_stats in namespace_stats.iteritems():
        if not ns_stats or isinstance(ns_stats, Exception):
            continue

        repl_factor = get_value_from_second_level_of_dict(ns_stats, ("repl-factor",), default_value=0, return_type=int).values()[0]
        master_objects = sum(get_value_from_second_level_of_dict(ns_stats, ("master_objects", "master-objects"), default_value=0, return_type=int).values())
        devices_in_use = list(set(get_value_from_second_level_of_dict(ns_stats, ("storage-engine.device", "device", "storage-engine.file", "file"), default_value=None, return_type=str).values()))
        memory_data_size = None
        device_data_size = None

        if len(devices_in_use) == 0 or (len(devices_in_use) == 1 and devices_in_use[0] == None):
            # Data in memory only
            memory_data_size = sum(get_value_from_second_level_of_dict(ns_stats, ("memory_used_data_bytes", "data-used-bytes-memory"), default_value=0, return_type=int).values())
            memory_data_size = memory_data_size / repl_factor

            if memory_data_size > 0:
                memory_record_overhead = master_objects * 2
                memory_data_size = memory_data_size - memory_record_overhead

        else:
            # Data on disk
            device_data_size = sum(get_value_from_second_level_of_dict(ns_stats, ("device_used_bytes", "used-bytes-disk"), default_value=0, return_type=int).values())

            if device_data_size > 0:
                set_overhead = compute_set_overhead_for_ns(set_stats, ns)
                device_data_size = device_data_size - set_overhead

            if device_data_size > 0:
                tombstones = sum(get_value_from_second_level_of_dict(ns_stats, ("tombstones",), default_value=0, return_type=int).values())
                tombstone_overhead = tombstones * 128
                device_data_size = device_data_size - tombstone_overhead

            device_data_size = device_data_size / repl_factor
            if device_data_size > 0:
                device_record_overhead = master_objects * 64
                device_data_size = device_data_size - device_record_overhead

        ns_dict[ns]["license_data"] = {}
        if memory_data_size is not None:
            ns_dict[ns]["license_data"]["memory_size"] = memory_data_size
            cl_memory_data_size += memory_data_size

        if device_data_size is not None:
            ns_dict[ns]["license_data"]["device_size"] = device_data_size
            cl_device_data_size += device_data_size

    cluster_dict["license_data"] = {}
    cluster_dict["license_data"]["memory_size"] = cl_memory_data_size
    cluster_dict["license_data"]["device_size"] = cl_device_data_size

def initialize_summary_output(ns_list):
    """
    Function takes list of namespace names.
    Returns dictionary with summary fields set.
    """

    summary_dict = {}
    summary_dict["CLUSTER"] = {}

    summary_dict["CLUSTER"]["active_features"] = []

    summary_dict["CLUSTER"]["device"] = {}
    summary_dict["CLUSTER"]["device"]["count"] = 0
    summary_dict["CLUSTER"]["device"]["count_per_node"] = 0
    summary_dict["CLUSTER"]["device"]["count_same_across_nodes"] = True
    summary_dict["CLUSTER"]["device"]["total"] = 0
    summary_dict["CLUSTER"]["device"]["used_pct"] = 0
    summary_dict["CLUSTER"]["device"]["aval_pct"] = 0

    summary_dict["CLUSTER"]["memory"] = {}
    summary_dict["CLUSTER"]["memory"]["total"] = 0
    summary_dict["CLUSTER"]["memory"]["aval_pct"] = 0

    summary_dict["CLUSTER"]["active_ns"] = 0

    summary_dict["CLUSTER"]["license_data"] = {}
    summary_dict["CLUSTER"]["license_data"]["memory_size"] = 0
    summary_dict["CLUSTER"]["license_data"]["device_size"] = 0

    summary_dict["FEATURES"] = {}
    summary_dict["FEATURES"]["NAMESPACE"] = {}

    for ns in ns_list:
        summary_dict["FEATURES"]["NAMESPACE"][ns] = {}

        summary_dict["FEATURES"]["NAMESPACE"][ns]["device"] = {}
        summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["count"] = 0
        summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["count_per_node"] = 0
        summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["count_same_across_nodes"] = True
        summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["total"] = 0
        summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["used_pct"] = 0
        summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["aval_pct"] = 0


        summary_dict["FEATURES"]["NAMESPACE"][ns]["memory"] = {}
        summary_dict["FEATURES"]["NAMESPACE"][ns]["memory"]["total"] = 0
        summary_dict["FEATURES"]["NAMESPACE"][ns]["memory"]["aval_pct"] = 0

        summary_dict["FEATURES"]["NAMESPACE"][ns]["repl_factor"] = 0
        summary_dict["FEATURES"]["NAMESPACE"][ns]["master_objects"] = 0

        summary_dict["FEATURES"]["NAMESPACE"][ns]["license_data"] = {}

    return summary_dict

def create_summary(service_stats, namespace_stats, set_stats, metadata):
    """
    Function takes four dictionaries service stats, namespace stats, set stats and metadata.
    Returns dictionary with summary information.
    """

    features = find_features_for_cluster(service_stats, namespace_stats)

    namespace_stats = flip_keys(namespace_stats)
    set_stats = flip_keys(set_stats)

    summary_dict = initialize_summary_output(namespace_stats.keys())

    total_nodes = len(service_stats.keys())

    cl_nodewise_device_counts = {}

    cl_nodewise_mem_size = {}
    cl_nodewise_mem_aval = {}

    cl_nodewise_device_size = {}
    cl_nodewise_device_used = {}
    cl_nodewise_device_aval = {}

    compute_license_data_size(namespace_stats, set_stats, summary_dict["CLUSTER"], summary_dict["FEATURES"]["NAMESPACE"])
    summary_dict["CLUSTER"]["active_features"] = features

    summary_dict["CLUSTER"]["cluster_size"]= list(set(get_value_from_second_level_of_dict(service_stats, ("cluster_size",), default_value=0, return_type=int).values()))
    if metadata["server_version"]:
        summary_dict["CLUSTER"]["server_version"]= list(set(metadata["server_version"].values()))

    if metadata["os_version"]:
        summary_dict["CLUSTER"]["os_version"]= list(set(get_value_from_second_level_of_dict(metadata["os_version"], ("description",), default_value="", return_type=str).values()))

    for ns, ns_stats in namespace_stats.iteritems():
        if not ns_stats or isinstance(ns_stats, Exception):
            continue

        device_names_str = get_value_from_second_level_of_dict(ns_stats, ("storage-engine.device", "device", "storage-engine.file", "file"), default_value="", return_type=str)
        device_counts = dict([(k, len(v.split(',')) if v else 0) for k, v in device_names_str.iteritems()])
        cl_nodewise_device_counts = add_dicts(cl_nodewise_device_counts, device_counts)

        ns_total_devices = sum(device_counts.values())
        if ns_total_devices:
            summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["count"] = ns_total_devices
            summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["count_per_node"] = int((float(ns_total_devices)/float(total_nodes)) + 0.5)
            if len(set(device_counts.values())) > 1:
                summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["count_same_across_nodes"] = False

        mem_size = get_value_from_second_level_of_dict(ns_stats, ("memory-size",), default_value=0, return_type=int)
        mem_aval_pct = get_value_from_second_level_of_dict(ns_stats, ("memory_free_pct", "free-pct-memory"), default_value=0, return_type=int)
        mem_aval = pct_to_value(mem_size, mem_aval_pct)
        cl_nodewise_mem_size = add_dicts(cl_nodewise_mem_size, mem_size)
        cl_nodewise_mem_aval = add_dicts(cl_nodewise_mem_aval, mem_aval)
        summary_dict["FEATURES"]["NAMESPACE"][ns]["memory"]["total"] = sum(mem_size.values())
        summary_dict["FEATURES"]["NAMESPACE"][ns]["memory"]["aval_pct"] = (float(sum(mem_aval.values()))/float(sum(mem_size.values())))*100.0

        device_size = get_value_from_second_level_of_dict(ns_stats, ("device_total_bytes", "total-bytes-disk"), default_value=0, return_type=int)
        device_used = get_value_from_second_level_of_dict(ns_stats, ("device_used_bytes", "used-bytes-disk"), default_value=0, return_type=int)
        device_aval_pct = get_value_from_second_level_of_dict(ns_stats, ("device_available_pct", "available_pct"), default_value=0, return_type=int)
        device_aval = pct_to_value(device_size, device_aval_pct)
        cl_nodewise_device_size = add_dicts(cl_nodewise_device_size, device_size)
        cl_nodewise_device_used = add_dicts(cl_nodewise_device_used, device_used)
        cl_nodewise_device_aval = add_dicts(cl_nodewise_device_aval, device_aval)
        device_size_total = sum(device_size.values())
        if device_size_total > 0:
            summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["total"] = device_size_total
            summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["used_pct"] = (float(sum(device_used.values()))/float(device_size_total))*100.0
            summary_dict["FEATURES"]["NAMESPACE"][ns]["device"]["aval_pct"] = (float(sum(device_aval.values()))/float(device_size_total))*100.0

        summary_dict["FEATURES"]["NAMESPACE"][ns]["repl_factor"] = list(set(get_value_from_second_level_of_dict(ns_stats, ("repl-factor",), default_value=0, return_type=int).values()))
        master_objects = sum(get_value_from_second_level_of_dict(ns_stats, ("master_objects", "master-objects"), default_value=0, return_type=int).values())
        if master_objects > 0:
            summary_dict["FEATURES"]["NAMESPACE"][ns]["master_objects"] = master_objects
            summary_dict["CLUSTER"]["active_ns"] += 1

    cl_device_counts = sum(cl_nodewise_device_counts.values())
    if cl_device_counts:
        summary_dict["CLUSTER"]["device"]["count"] = cl_device_counts
        summary_dict["CLUSTER"]["device"]["count_per_node"] = int((float(cl_device_counts)/float(total_nodes)) + 0.5)
        if len(set(cl_nodewise_device_counts.values())) > 1:
            summary_dict["CLUSTER"]["device"]["count_same_across_nodes"] = False

    summary_dict["CLUSTER"]["memory"]["total"] = sum(cl_nodewise_mem_size.values())
    summary_dict["CLUSTER"]["memory"]["aval_pct"] = (float(sum(cl_nodewise_mem_aval.values()))/float(sum(cl_nodewise_mem_size.values())))*100.0

    cl_device_size_total = sum(cl_nodewise_device_size.values())
    if cl_device_size_total > 0:
        summary_dict["CLUSTER"]["device"]["total"] = cl_device_size_total
        summary_dict["CLUSTER"]["device"]["used_pct"] = (float(sum(cl_nodewise_device_used.values()))/float(cl_device_size_total))*100.0
        summary_dict["CLUSTER"]["device"]["aval_pct"] = (float(sum(cl_nodewise_device_aval.values()))/float(cl_device_size_total))*100.0

    return summary_dict