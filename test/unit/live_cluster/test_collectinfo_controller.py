# Copyright 2024-2025 Aerospike, Inc.
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

import logging
import unittest
from unittest import mock

from lib.live_cluster.collectinfo_controller import CollectinfoController

LOGGER_NAME = "lib.live_cluster.collectinfo_controller"


class BuildDumpMapTest(unittest.TestCase):
    """Tests for CollectinfoController._build_dump_map (TOOLS-3596).

    The merge must iterate over the union of node keys across every section map, not just
    ``as_map``, so a node whose statistics/config calls all failed in the first burst is
    still included in the snapshot via the sections that did succeed.
    """

    def setUp(self):
        self.controller = CollectinfoController()
        self.empty = {}

    def _build(self, expected, as_map, sys_map, meta_map):
        return self.controller._build_dump_map(
            expected,
            as_map,
            sys_map,
            meta_map,
            self.empty,  # histogram_map
            self.empty,  # latency_map
            None,  # pmap_map
            self.empty,  # acl_map
            self.empty,  # user_agents_map
            self.empty,  # masking_map
        )

    def test_node_absent_from_as_map_is_still_included(self):
        # Node "A" returned full stats. Node "B" lost all stats/config (absent from as_map)
        # but its metadata and system-stat calls succeeded.
        as_map = {"A": {"statistics": {"s": 1}, "config": {"c": 1}}}
        sys_map = {"A": {"sys": 1}, "B": {"sys": 2}}
        meta_map = {"A": {"asd_build": "8.0"}, "B": {"asd_build": "8.0"}}

        dump_map = self._build({"A", "B"}, as_map, sys_map, meta_map)

        # The previously-dropped node is now present.
        self.assertIn("B", dump_map)
        self.assertEqual(dump_map["B"]["as_stat"], {"meta_data": {"asd_build": "8.0"}})
        self.assertEqual(dump_map["B"]["sys_stat"], {"sys": 2})

        # The fully-successful node is unchanged.
        self.assertEqual(dump_map["A"]["as_stat"]["statistics"], {"s": 1})
        self.assertEqual(dump_map["A"]["as_stat"]["config"], {"c": 1})
        self.assertEqual(dump_map["A"]["as_stat"]["meta_data"], {"asd_build": "8.0"})
        self.assertEqual(dump_map["A"]["sys_stat"], {"sys": 1})

    def test_node_with_no_data_anywhere_is_warned_and_absent(self):
        # "A" produced data; expected node "C" produced nothing in any section map.
        as_map = {"A": {"statistics": {"s": 1}}}

        with self.assertLogs(LOGGER_NAME, level="WARNING") as cm:
            dump_map = self._build({"A", "C"}, as_map, self.empty, self.empty)

        self.assertIn("A", dump_map)
        self.assertNotIn("C", dump_map)
        self.assertTrue(
            any("missing" in msg and "C" in msg for msg in cm.output),
            cm.output,
        )

    def test_no_warning_when_all_expected_nodes_present(self):
        as_map = {"A": {"statistics": {"s": 1}}}
        meta_map = {"B": {"asd_build": "8.0"}}

        logger = logging.getLogger(LOGGER_NAME)
        with mock.patch.object(logger, "warning") as warn_mock:
            dump_map = self._build({"A", "B"}, as_map, self.empty, meta_map)

        warn_mock.assert_not_called()
        self.assertEqual(set(dump_map), {"A", "B"})


if __name__ == "__main__":
    unittest.main()
