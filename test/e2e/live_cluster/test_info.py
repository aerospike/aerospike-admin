# Copyright 2013-2025 Aerospike, Inc.
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
import pytest

from lib.view.sheet import set_style_json
import lib.live_cluster.live_cluster_root_controller as controller
import lib.utils.util as util
from test.e2e import util as test_util, lib

set_style_json()


class TestInfo(unittest.IsolatedAsyncioTestCase):
    rc = None
    output_list = list()
    service_info = ""
    network_info = ""
    namespace_usage_info = ""
    namespace_object_info = ""
    sindex_info = ""
    xdr_info = ""

    @classmethod
    def setUpClass(cls) -> None:
        lib.start()
        lib.create_sindex("info-sindex", "numeric", lib.NAMESPACE, "a")

    async def asyncSetUp(self):
        # Point the controller at the test cluster started by lib.start()
        seed = [(lib.SERVER_IP, lib.PORT, None)]
        self.rc = await controller.LiveClusterRootController(
            seed_nodes=seed, user="admin", password="admin"
        )  # type: ignore
        await util.capture_stdout(self.rc.execute, ["enable"])

    @classmethod
    def tearDownClass(cls) -> None:
        lib.stop()

    async def test_network(self):
        """
        This test will assert <b> info Network </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        TODO: test for values as well
        """
        exp_heading = "Network Information"
        exp_header = [
            "Node",
            "Node ID",
            "IP",
            "Build",
            "Migrations",
            "Cluster Size",
            "Cluster Key",
            "Cluster Integrity",
            "Cluster Principal",
            "Client Conns",
            "Uptime",
        ]
        expected_num_records = len(self.rc.cluster.nodes)

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            actual_num_records,
        ) = await test_util.capture_separate_and_parse_output(self.rc, ["info", "net"])
        self.assertTrue(exp_heading in actual_heading)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(expected_num_records, actual_num_records)

    async def test_sindex(self):
        """
        This test will assert <b> info sindex </b> output for heading, headerline1, headerline2
        and no of row displayed in output
        TODO: test for values as well
        """
        exp_heading = "Secondary Index Information"

        # Know to be up-to-date with server 5.1
        exp_header = [
            "Index Name",
            "Namespace",
            "Set",
            "Node",
            "Bins",
            "Bin Type",
            "State",
            "Entries",
            "Memory Used",
            "Queries Requests",
            "Queries Avg Num Recs",
            "Updates Writes",
            "Updates Deletes",
        ]

        if TestInfo.sindex_info == "":
            self.skipTest("No sindex information found.")

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["info", "sindex"]
        )

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)

    @pytest.mark.skip()
    async def test_namespace_usage(self):
        """
        This test will assert <b> info namespace usage </b> output for heading, headerline1, headerline2
        displayed in output
        TODO: test for values as well
        """
        exp_heading = "Namespace Usage Information"
        exp_header = [
            "Namespace",
            "Node",
            "Total Records",
            "Expirations",
            "Evictions",
            "Stop Writes",
            "Disk HWM%",
            "Memory Used",
            "Memory Used%",
            "Memory HWM%",
            "Memory Stop%",
            "Primary Index Type",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["info", "namespace", "usage"]
        )
        self.assertListEqual(actual_header, exp_header)
        self.assertTrue(exp_heading in actual_heading)

    async def test_memory(self):
        """
        This test asserts <b> info memory </b> output heading, the headline
        columns, and the allocation and capacity values. The fixture pins
        server 8.1.3+ (lib.SERVER_TAG), whose image must report the arena stats
        and host_total_mem_kbytes (SERVER-1546); the container has no tracked
        cgroup limit, so Capacity is the host total.
        """
        exp_heading = "Memory Information"
        always_present = [
            "Node",
            "Free%",
            "Build",
            "Capacity",
            "Allocated Total",
            "Allocated Shmem",
            "Allocated Heap",
        ]

        raw_output = await util.capture_stdout(self.rc.execute, ["info", "memory"])
        separated = test_util.get_separate_output(raw_output)
        self.assertTrue(separated, "info memory produced no tables")

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(separated[0])
        self.assertTrue(exp_heading in actual_heading)
        for column in always_present:
            self.assertIn(column, actual_header)

        self.assertEqual(num_records, len(self.rc.cluster.nodes))

        for group in separated[0]["groups"]:
            for record in group["records"]:
                shmem = record["Allocated"]["Shmem"]["raw"]
                total = record["Allocated"]["Total"]["raw"]
                capacity = record["Capacity"]["raw"]

                self.assertGreater(shmem, 0)
                self.assertGreaterEqual(total, shmem)
                self.assertGreater(capacity, total)

    async def test_memory_verbose(self):
        """
        This test asserts <b> info memory --verbose </b> renders the breakdown
        sheets in addition to the headline sheet. Subgroup fields are flattened
        by the parser to "<subgroup> <field>".
        TODO: test for values as well
        """
        raw_output = await util.capture_stdout(
            self.rc.execute, ["info", "memory", "--verbose"]
        )
        separated = test_util.get_separate_output(raw_output)

        self.assertTrue(separated, "info memory --verbose produced no tables")

        headers_by_heading = {}

        for sheet in separated:
            heading, _, header, _, _ = test_util.parse_output(sheet)
            headers_by_heading[heading] = header

        def header_for(heading_substr):
            for heading, header in headers_by_heading.items():
                if heading_substr in heading:
                    return header
            return None

        host = header_for("Host and CGroup Memory")
        self.assertIsNotNone(host)
        for column in [
            "Node",
            "Host Total",
            "Free System",
            "Free Sys%",
            "CGroup Tracking",
        ]:
            self.assertIn(column, host)

        allocation = header_for("Index and Data Memory")
        self.assertIsNotNone(allocation)
        for column in ["Node", "Total Alloc", "Total Used"]:
            self.assertIn(column, allocation)

        process = header_for("Process Heap")
        self.assertIsNotNone(process)
        for column in ["Node", "RSS", "Heap Alloc", "Heap Eff%"]:
            self.assertIn(column, process)

    async def test_namespace_usage_reports_index_allocation(self):
        """
        The 8.1.3 per-namespace arena stats must surface as allocation columns
        in <b> info namespace usage </b>. setUpClass creates a secondary index
        so si_alloc_bytes is present.
        """
        _, _, header, _, _ = await test_util.capture_separate_and_parse_output(
            self.rc, ["info", "namespace", "usage"]
        )
        self.assertIn("Primary Index Alloc", header)
        self.assertIn("Secondary Index Alloc", header)

    @pytest.mark.skip()
    async def test_namespace_object(self):
        """
        This test will assert <b> info namespace Object </b> output for heading, headerline1, headerline2
        displayed in output
        TODO: test for values as well
        """
        exp_heading = "Namespace Object Information"
        exp_header = [
            "Namespace",
            "Node",
            "Rack ID",
            "Repl Factor",
            "Total Records",
            "Objects Master",
            "Objects Prole",
            "Objects Non-Replica",
            "Tombstones Master",
            "Tombstones Prole",
            "Tombstones Non-Replica",
            "Pending Migrates Tx",
            "Pending Migrates Rx",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["info", "namespace", "object"]
        )
        self.assertListEqual(actual_header, exp_header)
        self.assertTrue(exp_heading in actual_heading)

    # @unittest.skip("Will enable only when xdr is configured")
    async def test_xdr(self):
        """
        This test will assert info XDR output.
        and no of row displayed in output
        TODO: test for values as well
        """
        exp_heading = "XDR Information"

        # Left incase older server versions need testing

        exp_header = [
            "Node",
            "Success",
            "Retry Connection Reset",
            "Retry Destination",
            "Recoveries Pending",
            "Lag (hh:mm:ss)",
            "Avg Latency (ms)",
            "Throughput (rec/s)",
        ]

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = await test_util.capture_separate_and_parse_output(self.rc, ["info", "xdr"])

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)

    async def test_info_unknown_subcommand(self):
        """
        This test asserts that an unknown subcommand to 'info' returns a clear error.
        """
        with self.assertRaises(Exception) as context:
            await test_util.capture_separate_and_parse_output(
                self.rc, ["info", "random"]
            )
        self.assertIn(
            "info: 'random' is not a valid subcommand. See 'help info' for available subcommands.",
            str(context.exception),
        )

    async def test_release(self):
        """
        This test will assert info release output for heading, header, and data structure.
        Note: This test may be skipped if server version < 8.1.1
        """
        exp_heading = "Release Information"
        exp_header = [
            "Node",
            "Architecture",
            "Edition",
            "Version",
            "OS",
            "SHA",
            "EE SHA",
        ]
        expected_num_records = len(self.rc.cluster.nodes)

        # Run command and inspect raw output for unsupported message
        raw_output = await util.capture_stdout(self.rc.execute, ["info", "release"])
        if "info release' is not supported on aerospike versions < 8.1.1" in raw_output:
            self.skipTest("Server version doesn't support release info")

        separated = test_util.get_separate_output(raw_output)
        if not separated:
            self.skipTest("Server did not return release info data")

        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            actual_num_records,
        ) = test_util.parse_output(separated[0])

        self.assertTrue(exp_heading in actual_heading)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(expected_num_records, actual_num_records)

        # Verify data structure - each row should have values for edition and version
        records = [dict(zip(actual_header, row)) for row in actual_data]
        for row in records:
            self.assertIsNotNone(row.get("Edition"))
            self.assertIsNotNone(row.get("Version"))


if __name__ == "__main__":
    unittest.main()
