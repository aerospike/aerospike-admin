# Copyright 2026 Aerospike, Inc.
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

import unittest

from lib.collectinfo_analyzer.collectinfo_handler.collectinfo_parser import (
    collectinfo_parser,
)

TIMESTAMP = "2026-07-05 00:00:00 UTC"


def _parsed_map():
    """A snapshot with one healthy node and one node whose info calls all failed
    during collection (TOOLS-3596), leaving an empty as_stat."""
    return {
        TIMESTAMP: {
            "testcluster": {
                "1.1.1.1:3000": {
                    "as_stat": {"meta_data": {"node_id": "A1"}},
                    "sys_stat": {"uname": {"nodename": "1.1.1.1"}},
                },
                "2.2.2.2:3000": {"as_stat": {}},
            }
        }
    }


class CreateNodeIpMapTest(unittest.TestCase):
    def test_skips_node_without_meta_data(self):
        """A node with an empty as_stat must not break the node-id mapping for the
        healthy nodes (previously raised KeyError)."""
        node_to_ip = collectinfo_parser._create_node_ip_map(_parsed_map())

        self.assertEqual(node_to_ip, {"A1": "1.1.1.1:3000"})


class AddMissingConfigDataTest(unittest.TestCase):
    def test_conf_merge_survives_node_without_meta_data(self):
        """TOOLS-3596 regression guard: a degraded node in the snapshot must not
        silently abort the aerospike.conf original_config merge for the healthy
        nodes (the KeyError used to be swallowed by the bare except)."""
        parsed_map = _parsed_map()
        parsed_conf_map = {"service": {"proto-fd-max": "15000"}}

        collectinfo_parser._add_missing_config_data(
            parsed_map, parsed_conf_map, [TIMESTAMP], True
        )

        healthy_node = parsed_map[TIMESTAMP]["testcluster"]["1.1.1.1:3000"]
        self.assertEqual(healthy_node["as_stat"]["original_config"], parsed_conf_map)


if __name__ == "__main__":
    unittest.main()
