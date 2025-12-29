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

import asynctest
import pytest

from lib.view.sheet import set_style_json
import lib.live_cluster.live_cluster_root_controller as controller
import lib.utils.util as util
from test.e2e import util as test_util, lib

set_style_json()


@pytest.mark.skip()  # TODO: Are these useful? Do we need to remove them or change them?
class TestInfo(asynctest.TestCase):
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

    async def setUp(self):
        self.rc = await controller.LiveClusterRootController(
            user="admin", password="admin"
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
            "Node ID", 
            "Architecture",
            "Edition",
            "OS",
            "Version",
            "SHA",
            "EE SHA",
        ]
        expected_num_records = len(self.rc.cluster.nodes)

        try:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_num_records,
            ) = await test_util.capture_separate_and_parse_output(self.rc, ["info", "release"])
            
            self.assertTrue(exp_heading in actual_heading)
            self.assertListEqual(exp_header, actual_header)
            self.assertEqual(expected_num_records, actual_num_records)
            
            # Verify data structure - each row should have values for edition and version
            for row in actual_data:
                self.assertIsNotNone(row.get("Edition"))
                self.assertIsNotNone(row.get("Version"))
                
        except Exception as e:
            # Skip test if server doesn't support release info
            if "not supported" in str(e).lower():
                self.skipTest(f"Server version doesn't support release info: {e}")
            else:
                raise


if __name__ == "__main__":
    unittest.main()
