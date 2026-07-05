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

from lib.collectinfo_analyzer.collectinfo_handler.collectinfo_log import (
    _CollectinfoSnapshot,
)
from lib.utils.constants import NodeSelection

TIMESTAMP = "2026-07-05 00:00:00 UTC"


def _snapshot(cinfo_data):
    return _CollectinfoSnapshot("testcluster", TIMESTAMP, cinfo_data, "ascinfo.json")


class CollectinfoSnapshotNodeRegistrationTest(unittest.TestCase):
    """TOOLS-3596: a node whose info calls failed during collection lands in
    ascinfo.json with a (possibly empty) as_stat; the offline analyzer must still
    register it instead of silently hiding it from the bundle."""

    def test_node_with_empty_as_stat_is_registered(self):
        cinfo_data = {
            "1.1.1.1:3000": {
                "as_stat": {
                    "meta_data": {"node_id": "A1", "node_names": "node-a"},
                },
            },
            # Rescued node: every info call failed, only an empty as_stat remains.
            "2.2.2.2:3000": {"as_stat": {}},
        }

        snapshot = _snapshot(cinfo_data)

        self.assertEqual(
            snapshot.get_node_names(),
            {"1.1.1.1:3000": "node-a", "2.2.2.2:3000": "2.2.2.2:3000"},
        )
        self.assertEqual(set(snapshot.nodes), {"1.1.1.1:3000", "2.2.2.2:3000"})
        self.assertEqual(snapshot.nodes["1.1.1.1:3000"].node_id, "A1")
        self.assertEqual(snapshot.nodes["2.2.2.2:3000"].node_id, "N/E")

    def test_node_without_node_names_falls_back_to_its_key(self):
        cinfo_data = {
            "1.1.1.1:3000": {"as_stat": {"meta_data": {"node_id": "A1"}}},
        }

        snapshot = _snapshot(cinfo_data)

        self.assertEqual(snapshot.get_node_names(), {"1.1.1.1:3000": "1.1.1.1:3000"})


class CollectinfoSnapshotExpectedPrincipalTest(unittest.TestCase):
    """TOOLS-3596: a registered node without a known node_id must not force the whole
    snapshot's expected principal to UNKNOWN_PRINCIPAL; the principal is computed
    best-effort over the nodes whose ids are known."""

    def test_principal_is_best_effort_over_known_ids(self):
        cinfo_data = {
            "1.1.1.1:3000": {"as_stat": {"meta_data": {"node_id": "B2"}}},
            "2.2.2.2:3000": {"as_stat": {"meta_data": {"node_id": "A1"}}},
            "3.3.3.3:3000": {"as_stat": {}},  # no id known
        }

        snapshot = _snapshot(cinfo_data)

        self.assertEqual(snapshot.get_expected_principal(), "B2")

    def test_principal_unknown_when_no_ids_known_on_multiple_nodes(self):
        cinfo_data = {
            "1.1.1.1:3000": {"as_stat": {}},
            "2.2.2.2:3000": {"as_stat": {}},
        }

        snapshot = _snapshot(cinfo_data)

        self.assertEqual(snapshot.get_expected_principal(), "UNKNOWN_PRINCIPAL")

    def test_principal_single_node_without_id_returns_its_id(self):
        cinfo_data = {"1.1.1.1:3000": {"as_stat": {}}}

        snapshot = _snapshot(cinfo_data)

        self.assertEqual(snapshot.get_expected_principal(), "N/E")


class CollectinfoSnapshotPrincipalScopedDataTest(unittest.TestCase):
    """TOOLS-3596: principal-scoped data (e.g. ACL) is stored only on the node it was
    collected from. When the true principal's node_id was not collected, the computed
    principal points at another node; get_data must fall back to all nodes instead of
    returning nothing."""

    def test_principal_scoped_get_data_falls_back_to_all_nodes(self):
        acl = {"users": {"admin": {"roles": ["sys-admin"]}}}
        cinfo_data = {
            "1.1.1.1:3000": {"as_stat": {"meta_data": {"node_id": "A1"}}},
            # True principal: ACL was collected from it, but its node_id call failed.
            "2.2.2.2:3000": {"as_stat": {"acl": acl}},
        }

        snapshot = _snapshot(cinfo_data)

        # Best-effort principal resolves to 1.1.1.1, which has no acl data.
        self.assertEqual(snapshot.get_expected_principal(), "A1")
        self.assertEqual(
            snapshot.get_data(type="acl", nodes=NodeSelection.PRINCIPAL),
            {"2.2.2.2:3000": acl},
        )

    def test_principal_scoped_get_data_stays_narrow_when_principal_has_data(self):
        acl = {"users": {"admin": {"roles": ["sys-admin"]}}}
        cinfo_data = {
            "1.1.1.1:3000": {"as_stat": {"meta_data": {"node_id": "A1"}, "acl": acl}},
            "2.2.2.2:3000": {"as_stat": {"meta_data": {"node_id": "B2"}, "acl": {}}},
        }

        snapshot = _snapshot(cinfo_data)

        # Principal is B2 (higher id) but has empty acl; A1's data must not leak in
        # since the principal produced an (empty) entry.
        self.assertEqual(snapshot.get_expected_principal(), "B2")
        self.assertEqual(
            snapshot.get_data(type="acl", nodes=NodeSelection.PRINCIPAL),
            {"2.2.2.2:3000": {}},
        )


if __name__ == "__main__":
    unittest.main()
