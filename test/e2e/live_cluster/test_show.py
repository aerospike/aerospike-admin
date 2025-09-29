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

import os
import sys
import time
import unittest

import asynctest

import lib.live_cluster.live_cluster_root_controller as controller
import lib.utils.util as util
from test.e2e import lib, util as test_util

sys.path.insert(1, os.getcwd())

from lib.view.sheet import set_style_json

set_style_json()


def print_header(actual_header):
    for item in actual_header:
        print('"' + item + '",')


class TestShowLatenciesDefault(asynctest.TestCase):
    """
    TODO: enable-micro benchmarks
    asinfo -v 'set-config:context=namespace;id=test;enable-benchmarks-write=true' -Uadmin -Padmin
    asinfo -v 'set-config:context=namespace;id=test;enable-benchmarks-read=true' -Uadmin -Padmin
    """

    async def setUp(self):
        lib.start()
        lib.populate_db("show-latencies-test")
        time.sleep(20)

    def tearDown(self):
        lib.stop()

    async def test_latencies(self):
        """
        Asserts <b> read latencies <b> output with heading, header & no of node processed(based on row count).
        """
        exp_heading = "Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">8ms",
            ">64ms",
        ]
        exp_data = [
            ("bar", "test"),
            (
                "read",
                "read-dup-res",
                "read-local",
                "read-repl-ping",
                "read-response",
                "read-restart",
                "read-start",
                "write",
                "write-dup-res",
                "write-master",
                "write-repl-write",
                "write-response",
                "write-restart",
                "write-start",
            ),
        ]
        exp_data_types = [str, str, str, float, float, float, float]
        rc = await controller.LiveClusterRootController([(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin")  # type: ignore
        actual_out = await util.capture_stdout(rc.execute, ["show", "latencies", "-v"])
        output_list = test_util.get_separate_output(actual_out)
        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            actual_no_of_rows,
        ) = test_util.parse_output(output_list[0])
        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)
        self.assertTrue(
            test_util.check_for_types(actual_data, exp_data_types),
            "%s returned the wrong data types" % exp_heading,
        )

        for data in actual_data:
            self.assertTrue(test_util.check_for_subset(data, exp_data))


class TestShowLatenciesWithArguments(asynctest.TestCase):
    @classmethod
    def setUpClass(cls):
        lib.start()
        lib.populate_db("show-latencies-test")
        time.sleep(20)

    async def setUp(self):
        self.rc = await controller.LiveClusterRootController([(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin")  # type: ignore

    @classmethod
    def tearDownClass(self):
        lib.stop()

    async def test_latencies_e_1_b_17(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 1 -b 17 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">2ms",
            ">4ms",
            ">8ms",
            ">16ms",
            ">32ms",
            ">64ms",
            ">128ms",
            ">256ms",
            ">512ms",
            ">1024ms",
            ">2048ms",
            ">4096ms",
            ">8192ms",
            ">16384ms",
            ">32768ms",
            ">65536ms",
        ]
        exp_data_types = [
            str,
            str,
            str,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
        ]

        actual_out = await util.capture_stdout(
            self.rc.execute,
            ["show", "latencies", "-e", "1", "-b", "17"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    async def test_latencies_e_1_b_18(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 1 -b 18 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">2ms",
            ">4ms",
            ">8ms",
            ">16ms",
            ">32ms",
            ">64ms",
            ">128ms",
            ">256ms",
            ">512ms",
            ">1024ms",
            ">2048ms",
            ">4096ms",
            ">8192ms",
            ">16384ms",
            ">32768ms",
            ">65536ms",
        ]
        exp_data_types = [
            str,
            str,
            str,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
        ]

        actual_out = await util.capture_stdout(
            self.rc.execute,
            ["show", "latencies", "-e", "1", "-b", "18"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    async def test_latencies_e_0_b_17(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 0 -b 17 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">2ms",
            ">4ms",
            ">8ms",
            ">16ms",
            ">32ms",
            ">64ms",
            ">128ms",
            ">256ms",
            ">512ms",
            ">1024ms",
            ">2048ms",
            ">4096ms",
            ">8192ms",
            ">16384ms",
            ">32768ms",
            ">65536ms",
        ]
        exp_data_types = [
            str,
            str,
            str,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
        ]

        exp_no_of_rows = len(self.rc.cluster._live_nodes)
        actual_out = await util.capture_stdout(
            self.rc.execute,
            ["show", "latencies", "-e", "0", "-b", "17"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )
            # self.assertEqual(exp_no_of_rows, actual_no_of_rows)

    async def test_latencies_e_17_b_1(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 17 -b 1 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = ["Namespace", "Histogram", "Node", "ops/sec", ">1ms"]
        exp_data_types = [str, str, str, float, float]

        actual_out = await util.capture_stdout(
            self.rc.execute,
            ["show", "latencies", "-e", "17", "-b", "1"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    async def test_latencies_e_100_b_200(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 100 -b 200 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = ["Namespace", "Histogram", "Node", "ops/sec", ">1ms"]
        exp_data_types = [
            str,
            str,
            str,
            float,
            float,
        ]

        actual_out = await util.capture_stdout(
            self.rc.execute,
            ["show", "latencies", "-e", "100", "-b", "200"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    async def test_latencies_e_16_b_2(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 16 -b 2 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = ["Namespace", "Histogram", "Node", "ops/sec", ">1ms", ">65536ms"]
        exp_data_types = [str, str, str, float, float, float]

        actual_out = await util.capture_stdout(
            self.rc.execute,
            ["show", "latencies", "-e", "16", "-b", "2"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    async def test_latencies_e_4_b_7(self):
        """
        Asserts <b> show latencies <b> tables with arguments -e 4 -b 7 display the correct header
        and that each row of data has the corresponding data type.
        """

        # exp_heading = "~read Latency"
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">16ms",
            ">256ms",
            ">4096ms",
            ">65536ms",
        ]
        exp_data_types = [str, str, str, float, float, float, float, float, float]

        actual_out = await util.capture_stdout(
            self.rc.execute,
            ["show", "latencies", "-e", "4", "-b", "7"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                actual_no_of_rows,
            ) = test_util.parse_output(output)
            self.assertListEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    async def test_latencies_group_by_machine_name(self):
        """
        Asserts <b> show latencies <b> with a -m argument which groups tables by machine name
        """
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">8ms",
            ">64ms",
        ]
        exp_data_types = [str, str, str, float, float, float, float]

        actual_out = await util.capture_stdout(
            self.rc.execute, ["show", "latencies", "-m"]
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                _,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )

    async def test_latencies_group_by_machine_name_e_2_8(self):
        """
        Asserts <b> show latencies <b> with a -m argument which groups tables by machine name
        """
        exp_header = [
            "Namespace",
            "Histogram",
            "Node",
            "ops/sec",
            ">1ms",
            ">4ms",
            ">16ms",
            ">64ms",
            ">256ms",
            ">1024ms",
            ">4096ms",
            ">16384ms",
        ]
        exp_data_types = [
            str,
            str,
            str,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
            float,
        ]

        actual_out = await util.capture_stdout(
            self.rc.execute,
            ["show", "latencies", "-m", "-e", "2", "-b", "8"],
        )
        output_list = test_util.get_separate_output(actual_out)

        for output in output_list:
            (
                actual_heading,
                actual_description,
                actual_header,
                actual_data,
                _,
            ) = test_util.parse_output(output)
            self.assertEqual(exp_header, actual_header)
            self.assertTrue(
                test_util.check_for_types(actual_data, exp_data_types),
                "returned the wrong data types",
            )


class TestShowDistribution(asynctest.TestCase):
    output_list = list()
    test_ttl_distri = ""
    bar_ttl_distri = ""

    @classmethod
    def setUpClass(cls):
        lib.start()
        lib.populate_db("show-dis-test")
        cmd = "manage config namespace test param nsup-hist-period to 5"
        test_util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{cmd}' -Uadmin -Padmin"
        )
        time.sleep(20)

    async def setUp(self) -> None:
        self.rc = await controller.LiveClusterRootController(
            [(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin"
        )  # type: ignore

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    async def test_test_ttl(self):
        """
        Asserts TTL Distribution in Seconds for test namespace with heading, header & parameters.
        TODO: test for values as well
        """
        exp_heading = "{} - TTL Distribution in Seconds".format(lib.NAMESPACE)
        exp_description = """Percentage of records having ttl less than or equal to value measured in Seconds"""

        exp_header = [
            "Node",
            "10%",
            "20%",
            "30%",
            "40%",
            "50%",
            "60%",
            "70%",
            "80%",
            "90%",
            "100%",
        ]

        time.sleep(10)

        actual_out = await util.capture_stdout(
            self.rc.execute, ["show", "distribution", "ttl", "for", lib.NAMESPACE]
        )
        output_list = test_util.get_separate_output(actual_out)
        (
            actual_heading,
            actual_description,
            actual_header,
            actual_data,
            num_records,
        ) = test_util.parse_output(output_list[0])

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_description, actual_description)
        self.assertListEqual(exp_header, actual_header)


def get_data(exp_first: str | float | int, data: list[list[str | float | int]]):
    found_values = None

    for values in data:
        if len(data) and values.pop(0) == exp_first:
            found_values = values
            break

    return found_values


class TestShowUsers(asynctest.TestCase):
    async def setUp(self):
        lib.start()
        self.rc = await controller.LiveClusterRootController([(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin")  # type: ignore
        await util.capture_stdout(self.rc.execute, ["enable"])

    def tearDown(self):
        lib.stop()

    async def test_show_users(self):
        exp_title = "Users"
        exp_header = ["User", "Roles", "Read Quota", "Write Quota", "Auth Mode"]

        (
            actual_title,
            _,
            actual_header,
            _,
            _,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    async def test_create_user_with_no_roles(self):
        exp_user = "foo"
        exp_data = ["--", "0", "0", "password,PKI"]
        exp_title = "Users"
        exp_header = ["User", "Roles", "Read Quota", "Write Quota", "Auth Mode"]

        _, _, _, _, num_records = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        exp_num_rows = num_records + 1

        await self.rc.execute(
            ["manage", "acl", "create", "user", exp_user, "password", "bar"],
        )

        time.sleep(1)
        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        actual_roles = get_data(exp_user, actual_data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertListEqual(exp_data, actual_roles)  # type: ignore

    async def test_create_user_with_roles(self):
        exp_user = "foo"
        exp_roles = ["sys-admin", "user-admin"]
        exp_data = [",".join(exp_roles), "0", "0", "password,PKI"]
        exp_title = "Users"
        exp_header = ["User", "Roles", "Read Quota", "Write Quota", "Auth Mode"]

        _, _, _, _, num_records = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        exp_num_rows = num_records + 1

        time.sleep(0.5)
        await util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "user",
                exp_user,
                "password",
                "bar",
                "roles",
                *exp_roles,
            ],
        )
        time.sleep(2)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        actual_data = get_data(exp_user, actual_data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertListEqual(exp_data, actual_data)  # type: ignore

    async def test_delete_a_user(self):
        exp_user = "foo"
        exp_roles = ["sys-admin", "user-admin"]
        exp_title = "Users"
        exp_header = ["User", "Roles", "Read Quota", "Write Quota", "Auth Mode"]

        _, _, _, _, num_records = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        await util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "user",
                exp_user,
                "password",
                "bar",
                "roles",
                *exp_roles,
            ],
        )

        time.sleep(1)
        _, _, _, _, num_records = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        exp_num_rows = num_records - 1

        await util.capture_stdout(
            self.rc.execute, ["manage", "acl", "delete", "user", exp_user]
        )

        time.sleep(1)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        for data in actual_data:
            self.assertNotIn(exp_user, data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    async def test_revoke_user_role(self):
        exp_user = "foo"
        exp_roles = ["sys-admin", "user-admin"]
        exp_title = "Users"
        exp_header = ["User", "Roles", "Read Quota", "Write Quota", "Auth Mode"]

        await util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "user",
                exp_user,
                "password",
                "bar",
                "roles",
                *exp_roles,
                "to-remove",
            ],
        )
        time.sleep(0.25)
        await util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "revoke", "user", exp_user, "roles", "to-remove"],
        )
        time.sleep(0.25)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            _,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users"]
        )

        actual_roles = get_data(exp_user, actual_data)

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertIsNotNone(actual_roles)
        self.assertEqual(",".join(exp_roles), actual_roles[0])


class TestShowUsersStats(asynctest.TestCase):
    async def setUp(self):
        lib.start()
        self.rc = await controller.LiveClusterRootController([(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin")  # type: ignore
        await util.capture_stdout(self.rc.execute, ["enable"])

    def tearDown(self):
        lib.stop()

    async def test_show_users_stats(self):
        exp_title = "Users"
        exp_header = [
            "User",
            "Node",
            "Connections",
            "Read Quota",
            "Read Single Record TPS",
            "Read PI/SI Query Limited RPS",
            "Read PI/SI Query Limitless",
            "Write Quota",
            "Write Single Record TPS",
            "Write PI/SI Query Limited RPS",
            "Write PI/SI Query Limitless",
        ]

        (
            actual_title,
            _,
            actual_header,
            _,
            _,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users", "stat"]
        )

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    async def test_show_single_users_stats(self):
        exp_title = "Users"
        exp_header = [
            "User",
            "Node",
            "Connections",
            "Read Quota",
            "Read Single Record TPS",
            "Read PI/SI Query Limited RPS",
            "Read PI/SI Query Limitless",
            "Write Quota",
            "Write Single Record TPS",
            "Write PI/SI Query Limited RPS",
            "Write PI/SI Query Limitless",
        ]

        (
            actual_title,
            _,
            actual_header,
            _,
            _,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "users", "stat", "admin"]
        )

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)


class TestShowRoles(asynctest.TestCase):
    async def setUp(self):
        lib.start()
        self.rc = await controller.LiveClusterRootController(
            [(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin"
        )  # type: ignore
        await util.capture_stdout(self.rc.execute, ["enable"])

    async def tearDown(self) -> None:
        lib.stop()

    async def test_create_role_with_privileges(self):
        exp_role = "foo"
        exp_privilege = "sys-admin"
        exp_data = [exp_privilege]
        exp_title = "Roles"
        exp_header = ["Role", "Privileges"]

        _, _, _, _, num_records = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        exp_num_rows = num_records + 1

        await util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "role",
                exp_role,
                "priv",
                exp_privilege,
            ],
        )
        time.sleep(0.5)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        actual_data = get_data(exp_role, actual_data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertListEqual(exp_data, actual_data)

    async def test_create_role_with_allowlist(self):
        exp_role = "foo"
        exp_privileges = "write"
        exp_allowlist = ["1.1.1.1", "2.2.2.2"]
        exp_data = [exp_privileges, ",".join(exp_allowlist)]
        exp_title = "Roles"
        exp_header = [
            "Role",
            "Privileges",
            "Allowlist",
        ]

        _, _, _, _, num_records = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        exp_num_rows = num_records + 1

        await util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "create",
                "role",
                exp_role,
                "priv",
                "write",
                "allow",
                *exp_allowlist,
            ],
        )
        time.sleep(0.25)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        actual_data = get_data(exp_role, actual_data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertListEqual(exp_data, actual_data)

    async def test_delete_a_role(self):
        exp_role = "foo"
        exp_privilege = "sys-admin"
        exp_title = "Roles"
        exp_header = [
            "Role",
            "Privileges",
        ]

        _, _, _, _, num_records = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        await util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "create", "role", exp_role, "priv", exp_privilege],
        )
        time.sleep(0.25)

        _, _, _, _, num_records = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        exp_num_rows = num_records - 1

        await util.capture_stdout(
            self.rc.execute, ["manage", "acl", "delete", "role", exp_role]
        )
        time.sleep(0.25)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_records,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        for data in actual_data:
            self.assertNotIn(exp_role, data)

        self.assertEqual(exp_num_rows, actual_num_records)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    async def test_revoke_role(self):
        exp_role = "foo"
        exp_privilege = "read"
        exp_title = "Roles"
        exp_header = [
            "Role",
            "Privileges",
        ]

        await util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "create", "role", exp_role, "priv", exp_privilege],
        )
        await util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "grant", "role", exp_role, "priv", "write"],
        )
        time.sleep(0.5)
        await util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "revoke", "role", exp_role, "priv", "write"],
        )
        time.sleep(0.5)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            _,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        actual_privileges = get_data(exp_role, actual_data)

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(exp_privilege, actual_privileges[0])

    async def test_add_quotas(self):
        exp_role = "foo"
        exp_privilege = "read"
        exp_title = "Roles"
        exp_header = ["Role", "Privileges", "Quotas Read", "Quotas Write"]

        await util.capture_stdout(
            self.rc.execute,
            ["manage", "acl", "create", "role", exp_role, "priv", exp_privilege],
        )

        time.sleep(1)

        await util.capture_stdout(
            self.rc.execute,
            [
                "manage",
                "acl",
                "quotas",
                "role",
                exp_role,
                "read",
                "1000",
                "write",
                "2000",
            ],
        )
        time.sleep(1)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            _,
        ) = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "roles"]
        )

        actual_data = get_data(exp_role, actual_data)
        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual("1000", actual_data[1])
        self.assertEqual("2000", actual_data[2])


class TestShowUdfs(asynctest.TestCase):
    exp_module = "test__.lua"
    udf_contents = """
function get_digest(rec)
    info("Digest:%s", tostring(record.digest(rec)))
    return record.digest(rec)
end
    """

    async def setUp(self):
        lib.start()
        self.path = lib.write_file("test.lua", self.udf_contents)
        self.rc = await controller.LiveClusterRootController(
            [(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin"
        )  # type: ignore
        await util.capture_stdout(self.rc.execute, ["enable"])
        await util.capture_stdout(
            self.rc.execute, ["manage", "udfs", "add", "filler_.lua", "path", self.path]
        )

        time.sleep(2)

    def tearDown(self):
        lib.stop()

    async def test_show_udfs(self):
        exp_title = "UDF Modules"
        exp_header = ["Filename", "Hash", "Type"]

        (
            actual_title,
            _,
            actual_header,
            _,
            _,
        ) = await test_util.capture_separate_and_parse_output(self.rc, ["show", "udfs"])

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)

    async def test_add_udf(self):
        exp_title = "UDF Modules"
        exp_header = ["Filename", "Hash", "Type"]
        exp_module = ["1f662d25b16b7200848a502952c5be7422d448c5", "LUA"]

        _, _, _, _, num_rows = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "udfs"]
        )

        exp_num_rows = num_rows + 1

        await util.capture_stdout(
            self.rc.execute,
            ["manage", "udfs", "add", self.exp_module, "path", self.path],
        )

        time.sleep(1)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_rows,
        ) = await test_util.capture_separate_and_parse_output(self.rc, ["show", "udfs"])

        actual_module = get_data(self.exp_module, actual_data)

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(exp_num_rows, actual_num_rows)
        self.assertListEqual(exp_module, actual_module)

    async def test_remove_udf(self):
        exp_title = "UDF Modules"
        exp_header = ["Filename", "Hash", "Type"]

        await util.capture_stdout(
            self.rc.execute,
            ["manage", "udfs", "add", self.exp_module, "path", self.path],
        )
        time.sleep(0.50)
        _, _, _, _, num_rows = await test_util.capture_separate_and_parse_output(
            self.rc, ["show", "udfs"]
        )

        exp_num_rows = num_rows - 1

        await util.capture_stdout(
            self.rc.execute, ["manage", "udfs", "remove", self.exp_module]
        )
        time.sleep(0.50)

        (
            actual_title,
            _,
            actual_header,
            actual_data,
            actual_num_rows,
        ) = await test_util.capture_separate_and_parse_output(self.rc, ["show", "udfs"])

        self.assertIn(exp_title, actual_title)
        self.assertListEqual(exp_header, actual_header)
        self.assertEqual(exp_num_rows, actual_num_rows)

    async def test_show_single_udf(self):
        """Test showing individual UDF content with show udfs <filename>"""
        # First add a UDF to ensure we have one to test
        await util.capture_stdout(
            self.rc.execute,
            ["manage", "udfs", "add", self.exp_module, "path", self.path],
        )
        time.sleep(1)

        # Test showing the specific UDF content
        output = await util.capture_stdout(
            self.rc.execute, ["show", "udfs", self.exp_module]
        )

        # Verify the output contains expected elements
        self.assertIn(f"UDF Content: {self.exp_module}", output)
        self.assertIn("Filename:", output)
        self.assertIn("Type:", output)
        self.assertIn("Content:", output)
        self.assertIn("function get_digest(rec)", output)  # Part of our test UDF
        self.assertIn("LUA", output)  # UDF type

        # Clean up: remove the UDF we added
        await util.capture_stdout(
            self.rc.execute, ["manage", "udfs", "remove", self.exp_module]
        )

    async def test_show_nonexistent_udf(self):
        """Test showing UDF that doesn't exist"""
        nonexistent_udf = "nonexistent.lua"
        
        output = await util.capture_stdout(
            self.rc.execute, ["show", "udfs", nonexistent_udf]
        )

        # Should contain error message about UDF not found
        self.assertIn("ERROR", output)


class TestShowUserAgents(asynctest.TestCase):
    async def setUp(self):
        lib.start()
        time.sleep(5)  # Wait for cluster to be ready

    def tearDown(self):
        lib.stop()

    async def test_show_user_agents(self):
        """
        Asserts <b> show user-agents </b> output with heading, header & no of user agents displayed.
        """
        exp_heading = "User Agent Information"
        exp_header = [
            "Node",
            "Client Version",
            "App ID",
            "Count",
        ]

        rc = await controller.LiveClusterRootController(
            [(lib.SERVER_IP, lib.PORT, None)], user="admin", password="admin"
        )  # type: ignore

        actual_out = await util.capture_stdout(rc.execute, ["show", "user-agents"])
        output_list = test_util.get_separate_output(actual_out)

        (
            actual_heading,
            _,
            actual_header,
            _,
            actual_no_of_rows,
        ) = test_util.parse_output(output_list[0])

        self.assertTrue(exp_heading in actual_heading)
        self.assertEqual(exp_header, actual_header)

        # Since user agents depend on client connections, we just verify the structure
        # The actual number of rows will depend on connected clients
        self.assertIsInstance(actual_no_of_rows, int)
        self.assertGreaterEqual(actual_no_of_rows, 1)
