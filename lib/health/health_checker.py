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

import re

from lib.health.constants import (
    ParserResultType,
    HealthResultType,
    HealthResultCounter,
    AssertResultKey,
)
from lib.health.exceptions import SyntaxException, HealthException
from lib.health.parser import HealthParser
from lib.health.query import QUERIES
from lib.health.util import is_health_parser_variable
from lib.utils.util import parse_queries
from lib.utils import version
from lib.view import terminal

VERSION_CONSTRAINT_PATTERN = "SET CONSTRAINT VERSION(.+)"


class HealthChecker:
    def __init__(self):
        try:
            self.health_parser = HealthParser()
            self.health_parser.build()
        except Exception:
            self.health_parser = None
            pass

        self.verbose = False
        self.no_valid_version = False
        self.filtered_data_set_to_parser = False

    def _reset_counters(self):
        self.status_counters = {}
        self.status_counters[HealthResultCounter.QUERY_COUNTER] = 0
        self.status_counters[HealthResultCounter.QUERY_SUCCESS_COUNTER] = 0
        self.status_counters[HealthResultCounter.QUERY_SKIPPED_COUNTER] = 0
        self.status_counters[HealthResultCounter.ASSERT_QUERY_COUNTER] = 0
        self.status_counters[HealthResultCounter.ASSERT_FAILED_COUNTER] = 0
        self.status_counters[HealthResultCounter.ASSERT_PASSED_COUNTER] = 0
        self.status_counters[HealthResultCounter.DEBUG_COUNTER] = 0
        self.status_counters[HealthResultCounter.SYNTAX_EXCEPTION_COUNTER] = 0
        self.status_counters[HealthResultCounter.HEALTH_EXCEPTION_COUNTER] = 0
        self.status_counters[HealthResultCounter.OTHER_EXCEPTION_COUNTER] = 0

        self.assert_outputs = {}
        self.health_exceptions = []
        self.syntax_exceptions = []
        self.other_exceptions = []
        self.debug_outputs = []

    def _increment_counter(self, counter):
        if counter and counter in self.status_counters:
            self.status_counters[counter] += 1

    def _set_parser_input(self, data):
        try:
            self.health_parser.set_health_data(data)
        except Exception:
            raise Exception(
                "No parser available. Please check ply module installed or not."
            )

    def _reset_parser(self):
        self.health_parser.clear_health_cache()
        if self.filtered_data_set_to_parser:
            # Healthchecker should work as setting input once and calling execute multiple times on same data.
            # So we need to reset parser input data if we set version filtered data.
            self._set_parser_input(self.health_input_data)

    def set_health_input_data(self, data):
        self.health_input_data = data
        if not data or not isinstance(data, dict):
            raise ValueError(
                terminal.fg_red()
                + "Wrong Input Data for HealthChecker"
                + terminal.fg_clear()
            )

        self._set_parser_input(data)

    def _create_health_result_dict(self):
        res = {}
        res[HealthResultType.STATUS_COUNTERS] = copy.deepcopy(self.status_counters)

        res[HealthResultType.EXCEPTIONS] = {}
        res[HealthResultType.EXCEPTIONS][
            HealthResultType.EXCEPTIONS_SYNTAX
        ] = copy.deepcopy(self.syntax_exceptions)
        res[HealthResultType.EXCEPTIONS][
            HealthResultType.EXCEPTIONS_PROCESSING
        ] = copy.deepcopy(self.health_exceptions)
        res[HealthResultType.EXCEPTIONS][
            HealthResultType.EXCEPTIONS_OTHER
        ] = copy.deepcopy(self.other_exceptions)

        res[HealthResultType.ASSERT] = copy.deepcopy(self.assert_outputs)
        res[HealthResultType.DEBUG_MESSAGES] = copy.deepcopy(self.debug_outputs)
        return res

    def _is_assert_query(self, query):
        if query and "ASSERT" in query:
            return True
        return False

    def _is_version_set_query(self, query):
        return re.search(VERSION_CONSTRAINT_PATTERN, query)

    def _set_version_checker_function(self, line):
        vp_l_e = "<=(.+)"
        vp_l = "<(.+)"
        vp_g_e = ">=(.+)"
        vp_g = ">(.+)"
        vp_e = "=(.+)"
        vp_in = r"IN \[(.+)\]"
        v_str = re.search(VERSION_CONSTRAINT_PATTERN, line).group(1).strip()

        if re.search(vp_l_e, v_str):
            v = re.search(vp_l_e, v_str).group(1)
            self.version_checker_fn = lambda x: version.LooseVersion(
                x.strip()
            ) <= version.LooseVersion(v.strip())

        elif re.search(vp_l, v_str):
            v = re.search(vp_l, v_str).group(1)
            self.version_checker_fn = lambda x: version.LooseVersion(
                x.strip()
            ) < version.LooseVersion(v.strip())

        elif re.search(vp_g_e, v_str):
            v = re.search(vp_g_e, v_str).group(1)
            self.version_checker_fn = lambda x: version.LooseVersion(
                x.strip()
            ) >= version.LooseVersion(v.strip())

        elif re.search(vp_g, v_str):
            v = re.search(vp_g, v_str).group(1)
            self.version_checker_fn = lambda x: version.LooseVersion(
                x.strip()
            ) > version.LooseVersion(v.strip())

        elif re.search(vp_e, v_str):
            v = re.search(vp_e, v_str).group(1).strip()
            if v.lower() == "all":
                self.version_checker_fn = None
            else:
                self.version_checker_fn = lambda x: version.LooseVersion(
                    x.strip()
                ) == version.LooseVersion(v)
        elif re.search(vp_in, v_str):
            v = re.search(vp_in, v_str).group(1).strip()
            v = [i.strip() for i in v.split(",")]
            if "ALL" in v or "all" in v:
                self.version_checker_fn = None
            else:
                self.version_checker_fn = lambda x: version.LooseVersion(x.strip()) in [
                    version.LooseVersion(i) for i in v
                ]
        else:
            v = v_str.strip()
            if v.lower() == "all":
                self.version_checker_fn = None
            else:
                self.version_checker_fn = lambda x: version.LooseVersion(
                    x.strip()
                ) == version.LooseVersion(v.strip())

    def _filter_nodes_to_remove(self, data):
        """
        Returns map as {cl1:v1, cl2:v2, ... } or 0 or 1
        where v can be 0 : means remove all nodes
                       1 : means keep all nodes
                       list of nodes : remove nodes from list
        """
        if not data or "METADATA" not in data or "CLUSTER" not in data["METADATA"]:
            # no metadata information available
            return 1

        sn_partial_count = 0
        sn_one_count = 0
        sn_zero_count = 0
        sn_node_dict = {}
        sn_total_clusters = 0

        for cl in data["METADATA"]["CLUSTER"].keys():
            sn_total_clusters += 1
            try:
                cl_one_count = 0
                cl_zero_count = 0
                cl_node_list = []
                cl_total_nodes = 0
                for n in data["METADATA"]["CLUSTER"][cl].keys():
                    cl_total_nodes += 1
                    try:
                        if not self.version_checker_fn(
                            data["METADATA"]["CLUSTER"][cl][n][("version", "KEY")]
                        ):
                            cl_zero_count += 1
                            cl_node_list.append(n)
                        else:
                            cl_one_count += 1
                    except Exception:
                        cl_one_count += 1
                        pass

                if cl_total_nodes == cl_one_count:
                    # keep all nodes for this cluster
                    sn_node_dict[cl] = 1
                    sn_one_count += 1
                elif cl_total_nodes == cl_zero_count:
                    # remove all nodes for this cluster
                    sn_node_dict[cl] = 0
                    sn_zero_count += 1
                else:
                    # some nodes need to remove
                    sn_node_dict[cl] = cl_node_list
                    sn_partial_count += 1
            except Exception:
                sn_node_dict[cl] = 1
                sn_one_count += 1

        if sn_total_clusters == sn_one_count:
            # keep all nodes for all cluster
            return 1
        elif sn_total_clusters == sn_zero_count:
            # remove all nodes for all cluster, so remove this snapshot itself
            return 0
        else:
            # some nodes need to remove
            return sn_node_dict

    def _remove_node_data(self, data, remove_nodes):
        if not data or not isinstance(data, dict):
            return
        for _key in list(data.keys()):
            if isinstance(_key, tuple) and _key[1] == "CLUSTER":
                if _key not in remove_nodes or remove_nodes[_key] == 1:
                    continue
                if remove_nodes[_key] == 0:
                    data.pop(_key)
                    continue
                for n in list(data[_key].keys()):
                    if n in remove_nodes[_key]:
                        data[_key].pop(n)
                if not data[_key]:
                    data.pop(_key)
            else:
                self._remove_node_data(data[_key], remove_nodes)
                if not data[_key]:
                    data.pop(_key)

    def _filter_health_input_data(self):
        data = copy.deepcopy(self.health_input_data)
        for sn in list(data.keys()):
            # SNAPSHOT level
            remove_nodes = self._filter_nodes_to_remove(data[sn])
            if remove_nodes == 1:
                continue
            elif remove_nodes == 0:
                data.pop(sn)
                continue
            else:
                self._remove_node_data(data[sn], remove_nodes)
                if not data[sn]:
                    data.pop(sn)
        return data

    def _filter_and_set_health_input_data(self, line):
        self._set_version_checker_function(line)
        if not self.version_checker_fn:
            self.no_valid_version = False
            self._set_parser_input(self.health_input_data)
            self.filtered_data_set_to_parser = False
        else:
            d = self._filter_health_input_data()
            if not d:
                self.no_valid_version = True
            else:
                self.no_valid_version = False
            self._set_parser_input(d)
            self.filtered_data_set_to_parser = True

    def _execute_query(self, query):
        return self.health_parser.parse(query)

    def _add_assert_output(self, assert_out):
        if not assert_out:
            return
        categories = assert_out[AssertResultKey.CATEGORY]
        assert_ptr = self.assert_outputs
        for c in categories[:-1]:
            if c not in assert_ptr:
                assert_ptr[c] = {}
            assert_ptr = assert_ptr[c]
        c = categories[-1]
        if c not in assert_ptr:
            assert_ptr[c] = []
        assert_ptr = assert_ptr[c]
        assert_ptr.append(assert_out)

    def _execute_queries(self, query_source=None, is_source_file=True):
        self._reset_counters()
        if not self.health_input_data or not isinstance(self.health_input_data, dict):
            raise Exception("No Health Input Data available")

        if not query_source:
            raise Exception("No Input Query Source.")

        if not isinstance(query_source, str):
            raise Exception("Query input source is not valid")

        queries = parse_queries(query_source, is_file=is_source_file)

        if not queries:
            raise Exception("Wrong Health query source.")

        for query in queries:
            if not query:
                continue

            self._increment_counter(HealthResultCounter.QUERY_COUNTER)

            if query.lower() == "exit":
                self._increment_counter(HealthResultCounter.QUERY_SUCCESS_COUNTER)
                break

            result = None
            if self._is_version_set_query(query):
                self._filter_and_set_health_input_data(query)
                self._increment_counter(HealthResultCounter.QUERY_SUCCESS_COUNTER)
                continue

            if self.no_valid_version:
                self._increment_counter(HealthResultCounter.QUERY_SKIPPED_COUNTER)
                continue
            if self._is_assert_query(query):
                self._increment_counter(HealthResultCounter.ASSERT_QUERY_COUNTER)

            try:
                result = self._execute_query(query)
                self._increment_counter(HealthResultCounter.QUERY_SUCCESS_COUNTER)
            except SyntaxException as se:
                self._increment_counter(HealthResultCounter.SYNTAX_EXCEPTION_COUNTER)
                self.syntax_exceptions.append(
                    {
                        "index": self.status_counters[
                            HealthResultCounter.QUERY_COUNTER
                        ],
                        "query": query,
                        "error": str(se),
                    }
                )
            except HealthException as he:
                self._increment_counter(HealthResultCounter.HEALTH_EXCEPTION_COUNTER)
                self.health_exceptions.append(
                    {
                        "index": self.status_counters[
                            HealthResultCounter.QUERY_COUNTER
                        ],
                        "query": query,
                        "error": str(he),
                    }
                )
            except Exception as oe:
                self._increment_counter(HealthResultCounter.OTHER_EXCEPTION_COUNTER)
                self.other_exceptions.append(
                    {
                        "index": self.status_counters[
                            HealthResultCounter.QUERY_COUNTER
                        ],
                        "query": query,
                        "error": str(oe),
                    }
                )

            if result:
                try:
                    if isinstance(result, tuple):
                        if result[0] == ParserResultType.ASSERT:
                            if result[1][AssertResultKey.SUCCESS]:
                                self._increment_counter(
                                    HealthResultCounter.ASSERT_PASSED_COUNTER
                                )
                            else:
                                self._increment_counter(
                                    HealthResultCounter.ASSERT_FAILED_COUNTER
                                )
                            self._add_assert_output(result[1])
                        elif is_health_parser_variable(result):
                            self._increment_counter(HealthResultCounter.DEBUG_COUNTER)
                            self.debug_outputs.append(result)
                except Exception:
                    pass

        return True

    def execute(self, query_file=None):
        health_summary = None

        if query_file is None:
            if not self._execute_queries(query_source=QUERIES, is_source_file=False):
                return {}
            health_summary = self._create_health_result_dict()

        elif query_file:
            if not self._execute_queries(query_source=query_file, is_source_file=True):
                return {}
            health_summary = self._create_health_result_dict()

        else:
            raise Exception("Wrong Query-file input for Health-Checker to execute")

        self.no_valid_version = False
        self._reset_parser()
        self._reset_counters()
        return health_summary
