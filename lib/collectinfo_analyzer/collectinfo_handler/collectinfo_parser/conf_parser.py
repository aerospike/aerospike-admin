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

import re

SPACE = re.compile(r"\s+")

space_unit_converter = {
    # units in capital letters
    "P": 1024 * 1024 * 1024 * 1024 * 1024,
    "T": 1024 * 1024 * 1024 * 1024,
    "G": 1024 * 1024 * 1024,
    "M": 1024 * 1024,
    "K": 1024,
    # units in small letters
    "p": 1024 * 1024 * 1024 * 1024 * 1024,
    "t": 1024 * 1024 * 1024 * 1024,
    "g": 1024 * 1024 * 1024,
    "m": 1024 * 1024,
    "k": 1024,
}

time_unit_converter = {
    # units in capital letters
    "D": 24 * 60 * 60,
    "H": 60 * 60,
    "M": 60,
    "S": 1,
    # units in small letters
    "d": 24 * 60 * 60,
    "h": 60 * 60,
    "m": 60,
    "s": 1,
}

# space configs which need conversion to bytes
context_space_configs = [
    "dump-message-above-size",
    "file_size",
    "memory-size",
    "storage-engine.commit-min-size",
    "storage-engine.max-write-cache",
    "storage-engine.write-block-size",
    "xdr-max-ship-bandwidth",
]

# time configs which need conversion to seconds
context_time_configs = [
    "dc-connections-idle-ms",
    "default-ttl",
    "defrag-sleep",
    "hist-track-slice",
    "interval",
    "keepalive-time",
    "max-ttl",
    "mcast-ttl",
    "migrate-fill-delay",
    "migrate-retransmit-ms",
    "migrate-sleep",
    "nsup-hist-period",
    "nsup-period",
    "polling-period",
    "proto-fd-idle-ms",
    "query-untracked-time-ms",
    "session-ttl",
    "sindex-gc-period",
    "ticker-interval",
    "tomb-raider-eligable-age",
    "tomb-raider-period",
    "tomb-raider-sleep",
    "transaction-max-ms",
    "transaction-retry-ms",
    "xdr-digestlog-iowait-ms",
    "xdr-hotkey-time-ms",
    "xdr-info-timeout",
    "xdr-write-timeout",
]

# confings differs in configuration file and asinfo output
# Format: (Name in config file, name expected in asinfo output)
xdr_dc_config_name_changes = [
    ("dc-node-address-port", "Nodes"),
    ("dc-node-address-port", "nodes"),
    ("dc-int-ext-ipmap", "int-ext-ipmap"),
]

# static config
static_configs = [
    "access-address",
    "access-port",
    "address",
    "alternate-access-address",
    "mesh-seed-address-port",
    "multicast-group",
    "port",
    "tls-access-address",
    "tls-address",
    "tls-alternate-access-address",
    "tls-mesh-seed-address-port",
]


def _convert(d, unit_converter):
    if not d or not isinstance(d, str) or len(d) < 2:
        return d

    try:
        v = d[:-1]
        u = d[-1]
        if u in unit_converter:
            return str(int(v) * unit_converter[u])

    except Exception:
        pass

    return d


def _to_bytes(d):
    return _convert(d, space_unit_converter)


def _to_seconds(d):
    return _convert(d, time_unit_converter)


def _ignore_context(fstream):
    paranthesis_to_find = 1
    while True:
        try:
            line = fstream.readline()
            if not line:
                break

            line = line.strip()
            if not line or line[0] == "#":
                continue

            paranthesis_to_find += line.count("{")
            paranthesis_to_find -= line.count("}")

            if paranthesis_to_find < 1:
                break

        except Exception:
            break


def _get_kv_from_line(line, key_prefix="", value_separator=None):
    k = None
    v = None

    if not line:
        return k, v

    line = line.split("#")[0].strip()
    values = line.split()
    if len(values) > 1:
        _k = values[0]
        _values = []

        k = "%s%s" % ((key_prefix + ".") if key_prefix else "", _k)

        if _k in static_configs or k in static_configs:
            # ignore
            return None, None

        if _k in context_space_configs or k in context_space_configs:
            for _v in values[1:]:
                _values.append(_to_bytes(_v))

        elif _k in context_time_configs or k in context_time_configs:
            for _v in values[1:]:
                _values.append(_to_seconds(_v))

        else:
            _values = values[1:]

        if value_separator is not None:
            v = value_separator.join(_values)

        else:
            v = _values[0]

    return k, v


def _parse_context(
    parsed_map, fstream, key_prefix="", value_separator=None, value_delimiter=","
):
    while True:
        try:
            line = fstream.readline()
            if not line:
                break

            line = line.strip()
            if not line or line[0] == "#":
                continue

            if line[0] == "}":
                break

            _k, _v = _get_kv_from_line(
                line, key_prefix=key_prefix, value_separator=value_separator
            )
            if _k:
                if _k in parsed_map:
                    _v = parsed_map[_k] + value_delimiter + _v
                parsed_map[_k] = _v

        except Exception:
            break


def _parse_security_context(parsed_map, fstream, line):
    context = "security"
    if context not in parsed_map:
        parsed_map[context] = {}
    dir_ptr = parsed_map[context]
    _parse_context(parsed_map=dir_ptr, fstream=fstream)


def _parse_service_context(parsed_map, fstream, line):
    context = "service"
    if context not in parsed_map:
        parsed_map[context] = {}
    dir_ptr = parsed_map[context]
    _parse_context(parsed_map=dir_ptr, fstream=fstream)


def _parse_network_subcontext(parsed_map, fstream, subcontext):
    _parse_context(
        parsed_map=parsed_map,
        fstream=fstream,
        key_prefix=subcontext,
        value_separator=":",
    )


def _parse_network_context(parsed_output, fstream, line):
    context = "network"
    if context not in parsed_output:
        parsed_output[context] = {}
    dir_ptr = parsed_output[context]
    while True:
        try:
            line = fstream.readline()
            if not line:
                break

            line = line.strip()
            if not line or line[0] == "#":
                continue

            if line[0] == "}":
                break

            line = line.split("#")[0].strip()
            if line[-1] == "{":
                subcontext = line[:-1].strip()
                _parse_network_subcontext(dir_ptr, fstream, subcontext)

        except Exception:
            break


def _parse_xdr_dc_context(parsed_map, fstream, dc_name):
    if dc_name not in parsed_map:
        parsed_map[dc_name] = {}
    _parse_context(parsed_map=parsed_map[dc_name], fstream=fstream, value_separator="+")

    parsed_map[dc_name]["DC_Name"] = dc_name
    parsed_map[dc_name]["dc-name"] = dc_name
    config_to_remove = []

    for file_config_name, asinfo_config_name in xdr_dc_config_name_changes:
        if file_config_name in parsed_map[dc_name]:
            parsed_map[dc_name][asinfo_config_name] = parsed_map[dc_name][
                file_config_name
            ]
            config_to_remove.append(file_config_name)

    for c in set(config_to_remove):
        try:
            parsed_map[dc_name].pop(c)
        except Exception:
            pass


def _parse_xdr_context(parsed_output, fstream, line):
    if "xdr" not in parsed_output:
        parsed_output["xdr"] = {}
    xdr_dir_ptr = parsed_output["xdr"]

    if "dc" not in parsed_output:
        parsed_output["dc"] = {}
    dc_dir_ptr = parsed_output["dc"]

    while True:
        try:
            line = fstream.readline()
            if not line:
                break

            line = line.strip()
            if not line or line[0] == "#":
                continue

            if line[0] == "}":
                break

            line = line.split("#")[0].strip()

            if line[-1] == "{":
                subcontext = line[:-1].strip().split()
                if subcontext[0] != "datacenter" or len(subcontext) < 2:
                    _ignore_context(fstream)
                else:
                    _parse_xdr_dc_context(dc_dir_ptr, fstream, subcontext[1])

            else:
                _k, _v = _get_kv_from_line(line, value_separator=" ")

                if _k:

                    if _k == "xdr-digestlog-path" and len(_v.split()) > 1:
                        _v = _v.split()
                        xdr_dir_ptr[_k] = _v[0]
                        xdr_dir_ptr["xdr-digestlog-size"] = _to_bytes(_v[1])

                    else:
                        xdr_dir_ptr[_k] = _v

        except Exception:
            break


def _parse_namespace_subcontext(parsed_map, fstream, subcontext):
    _parse_context(parsed_map=parsed_map, fstream=fstream, key_prefix=subcontext)


def _parse_namespace_context(parsed_output, fstream, line):
    context = "namespace"
    if context not in parsed_output:
        parsed_output[context] = {}
    if not line:
        return

    ns_name = line[1]

    if ns_name not in parsed_output[context]:
        parsed_output[context][ns_name] = {}

    if "service" not in parsed_output[context][ns_name]:
        parsed_output[context][ns_name]["service"] = {}

    namespace_dir_ptr = parsed_output[context][ns_name]["service"]

    dc_context = "dc"
    if dc_context not in parsed_output:
        parsed_output[dc_context] = {}
    dc_dir_ptr = parsed_output[dc_context]

    while True:
        try:
            line = fstream.readline()
            if not line:
                break

            line = line.strip()
            if not line or line[0] == "#":
                continue

            if line[0] == "}":
                break

            line = line.split("#")[0].strip()

            if line[-1] == "{":
                subcontext = line[:-1].strip().split()
                if subcontext[0] != "storage-engine" or len(subcontext) < 2:
                    _ignore_context(fstream)
                else:
                    _parse_namespace_subcontext(
                        namespace_dir_ptr, fstream, subcontext[0]
                    )

            else:
                _k, _v = _get_kv_from_line(line)

                if _k:

                    if _k == "xdr-remote-datacenter":

                        if _v not in dc_dir_ptr:
                            dc_dir_ptr[_v] = {}

                        if "namespaces" in dc_dir_ptr[_v]:
                            dc_dir_ptr[_v]["namespaces"] += ",%s" % ns_name
                        else:
                            dc_dir_ptr[_v]["namespaces"] = ns_name

                    else:
                        namespace_dir_ptr[_k] = _v

        except Exception:
            break


# Main first level context in conf file
contexts = {
    "service": _parse_service_context,
    "network": _parse_network_context,
    "xdr": _parse_xdr_context,
    "namespace": _parse_namespace_context,
}


def parse_file(file_path):
    parsed_output = {}
    try:
        fstream = open(file_path, "r")
    except Exception:
        return parsed_output

    while True:
        try:
            line = fstream.readline()
            if not line:
                break

            line = line.strip()
            if not line or line[0] == "#" or not line[-1] == "{":
                # Ignore empty lines and comments
                continue

            line_values = line[:-1].strip().split()
            context_name = line_values[0]
            if context_name in contexts:
                contexts[context_name](parsed_output, fstream, line_values)

            else:
                _ignore_context(fstream)

        except Exception:
            pass

    return parsed_output
