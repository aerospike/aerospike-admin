# Copyright 2021-2023 Aerospike, Inc.
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

from mock import patch
from lib.live_cluster.client.constants import ErrorsMsgs
from lib.live_cluster.client.types import ASINFO_RESPONSE_OK
import os
import time
import unittest

import asynctest
from parameterized import parameterized
from test.e2e import lib, util as test_util


class TestManage(asynctest.TestCase):
    def assertStdErrEqual(self, expected, actual):
        split = actual.split("\n")
        actual = []

        for line in split:
            if line.startswith("Seed") or line.startswith("Config"):
                continue

            actual.append(line)

        actual = "\n".join(actual)

        self.assertEqual(expected, actual)


class TestManageACLUsers(TestManage):
    exp_user = "foo"

    def get_args(self, cmd):
        return self._args.format(cmd)

    async def setUp(self):
        lib.start()
        self._args = (
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{{}}' --json -Uadmin -Padmin"
        )

    def tearDown(self) -> None:
        lib.stop()

    def test_can_create_user(self):
        exp_stdout_resp = "Successfully created user {}.".format(self.exp_user)
        exp_stderr_resp = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password test".format(self.exp_user)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_create_user_with_roles(self):
        exp_stdout_resp = "Successfully created user {}.".format(self.exp_user)
        exp_stderr_resp = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password test roles sys-admin data-admin".format(
                    self.exp_user
                )
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_create_user_if_one_exists(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to create user : User already exists."

        test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password test".format(self.exp_user)
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password bar".format(self.exp_user)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    async def test_can_delete_user(self):
        exp_stdout_resp = "Successfully deleted user {}.".format(self.exp_user)
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password test".format(self.exp_user)
            )
        )

        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args("manage acl delete user {}".format(self.exp_user))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    async def test_fail_to_delete_user_if_one_does_not_exist(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to delete user : No user or unrecognized user."
        actual = test_util.run_asadm(
            self.get_args("manage acl delete user dne".format(self.exp_user))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_set_user_password_outputs_expected_values(self):
        # Set up expected input values
        password = "test"
        expected_stdout = "Successfully set password for user {}.".format(self.exp_user)
        expected_stderr = ""

        # Create a user in the access control list
        test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password 'blah'".format(self.exp_user),
            )
        )

        # Set the user's password and check that the output matches the expected values
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl set-password user {} password {}".format(
                    self.exp_user, password
                ),
            )
        )

        self.assertEqual(expected_stdout, actual.stdout)
        self.assertStdErrEqual(expected_stderr, actual.stderr)

    # TODO create fail to set-password test

    def test_successful_password_change_for_user(self):
        exp_password = "test"
        exp_stdout_resp = "Successfully changed password for user {}.".format(
            self.exp_user
        )
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password {}".format(
                    self.exp_user, exp_password
                )
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl change-password user {} old {} new test".format(
                    self.exp_user, exp_password
                )
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_change_user_password_with_wrong_old_password(self):
        # Set up expected input values
        right_password = "test"
        wrong_password = "bar"
        expected_stdout = ""
        expected_stderr = (
            "ERROR: Failed to change password : No password or bad password."
        )

        # Create a user in the access control list with the correct password
        test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password {}".format(
                    self.exp_user, right_password
                ),
            )
        )
        time.sleep(0.5)

        # Attempt to change the user's password with the wrong old password and check that the error message matches the expected value
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl change-password user {} old {} new {}".format(
                    self.exp_user, wrong_password, right_password
                ),
            )
        )

        self.assertEqual(expected_stdout, actual.stdout)
        self.assertStdErrEqual(expected_stderr, actual.stderr)

    def test_can_grant_user_roles(self):
        exp_stdout_resp = "Successfully granted roles to user {}.".format(self.exp_user)
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password test".format(self.exp_user)
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl grant user {} roles read write".format(self.exp_user)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_grant_user_roles_if_user_does_not_exist(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to grant roles : No user or unrecognized user."

        actual = test_util.run_asadm(
            self.get_args("manage acl grant user DNE roles read write")
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_revoke_user_roles(self):
        exp_stdout_resp = "Successfully revoked roles from user {}.".format(
            self.exp_user
        )
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create user {} password test".format(self.exp_user)
            )
        )
        time.sleep(0.5)
        test_util.run_asadm(
            self.get_args(
                "manage acl grant user {} roles read write".format(self.exp_user)
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl revoke user {} roles read write".format(self.exp_user)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_revoke_user_roles_if_user_does_not_exist(self):
        exp_stdout_resp = ""
        exp_stderr_resp = (
            "ERROR: Failed to revoke roles : No user or unrecognized user."
        )

        actual = test_util.run_asadm(
            self.get_args("manage acl revoke user DNE roles read write")
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)


class TestManageACLRoles(TestManage):
    exp_role = "avatar"

    def get_args(self, cmd):
        return self._args.format(cmd)

    def setUp(self):
        lib.start()
        self._args = (
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{{}}' --json -Uadmin -Padmin"
        )

    def tearDown(self) -> None:
        lib.stop()

    def test_can_create_role_with_privilege(self):
        exp_stdout_resp = "Successfully created role {}.".format(self.exp_role)
        exp_stderr_resp = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read write".format(self.exp_role)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_create_role_with_allowlist(self):
        exp_stdout_resp = "Successfully created role {}.".format(self.exp_role)
        exp_stderr_resp = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read allow 1.1.1.1 2.2.2.2".format(
                    self.exp_role
                )
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_create_role_with_privilege_and_allowlist(self):
        exp_stdout_resp = "Successfully created role {}.".format(self.exp_role)
        exp_stderr_resp = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read write allow 1.1.1.1 2.2.2.2".format(
                    self.exp_role
                )
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_create_role_if_one_exists(self):
        expected_stdout_resp = ""
        expected_stderr_resp = "ERROR: Failed to create role : Role already exists."

        test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read write".format(self.exp_role)
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read write".format(self.exp_role)
            )
        )

        self.assertEqual(expected_stdout_resp, actual.stdout)
        self.assertStdErrEqual(expected_stderr_resp, actual.stderr)

    def test_fails_to_create_role_if_privilege_is_invalid(self):
        expected_stdout_resp = ""
        expected_stderr_resp = (
            "ERROR: Failed to create role : No privileges or unrecognized privileges."
        )

        actual = test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv invalid-priv".format(self.exp_role)
            )
        )

        self.assertEqual(expected_stdout_resp, actual.stdout)
        self.assertStdErrEqual(expected_stderr_resp, actual.stderr)

    def test_can_delete_role(self):
        exp_stdout_resp = "Successfully deleted role {}.".format(self.exp_role)
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args("manage acl create role {} priv read".format(self.exp_role))
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args("manage acl delete role {}".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fail_to_delete_role_if_one_does_not_exist(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to delete role : No role or invalid role."

        actual = test_util.run_asadm(
            self.get_args("manage acl delete role {}".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_grant_role_privilege(self):
        exp_stdout_resp = "Successfully granted privilege to role {}.".format(
            self.exp_role
        )
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read allow 1.1.1.1".format(
                    self.exp_role
                )
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args("manage acl grant role {} priv read".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_grant_role_privilege_if_role_does_not_exist(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to grant privilege : No role or invalid role."

        actual = test_util.run_asadm(
            self.get_args("manage acl grant role {} priv read".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_revoke_role_privileges(self):
        exp_stdout_resp = "Successfully revoked privilege from role {}.".format(
            self.exp_role
        )
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args("manage acl create role {} priv read".format(self.exp_role))
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args("manage acl revoke role {} priv read".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_revoke_role_privilege_if_role_does_not_exist(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to revoke privilege : No role or invalid role."

        actual = test_util.run_asadm(
            self.get_args("manage acl revoke role {} priv read".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_add_allowlist_to_role(self):
        exp_stdout_resp = "Successfully updated allowlist for role {}.".format(
            self.exp_role
        )
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv user-admin allow 1.1.1.1".format(
                    self.exp_role
                )
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl allowlist role {} allow 2.2.2.2".format(self.exp_role)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_clear_allowlist_to_role(self):
        exp_stdout_resp = "Successfully cleared allowlist from role {}.".format(
            self.exp_role
        )
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read-write allow 1.1.1.1".format(
                    self.exp_role
                )
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args("manage acl allowlist role {} clear".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_clear_allowlist_if_role_does_not_exist(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to delete allowlist : No role or invalid role."

        actual = test_util.run_asadm(
            self.get_args("manage acl allowlist role {} clear".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr.strip())

    # Setting one vs two quotas gives different success and error messages.
    def test_can_set_quota_to_role(self):
        exp_stdout_resp = "Successfully set quota for role {}.".format(self.exp_role)
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read-write allow 1.1.1.1".format(
                    self.exp_role
                )
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args("manage acl quotas role {} write 2222".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout.strip())
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr.strip())

    def test_can_set_quotas_to_role(self):
        exp_stdout_resp = "Successfully set quotas for role {}.".format(self.exp_role)
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage acl create role {} priv read-write allow 1.1.1.1".format(
                    self.exp_role
                )
            )
        )
        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl quotas role {} read 1111 write 2222".format(self.exp_role)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_set_quotas_to_role_if_bad_quota(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to set quotas : No role or invalid role."

        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage acl quotas role {} read 100 write 100".format(self.exp_role)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout.strip())
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr.strip())

    def test_fails_to_set_quota_to_role_if_bad_quota(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to set quota : No role or invalid role."

        actual = test_util.run_asadm(
            self.get_args("manage acl quotas role {} read 100".format(self.exp_role))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)


class ManageUDFsTest(TestManage):
    TEST_UDF = """
function get_digest(rec)
    info("Digest:%s", tostring(record.digest(rec)))
    return record.digest(rec)
end
"""
    exp_module = "test__.lua"
    other_modules = [
        "test0__.lua",
        "test1__.lua",
        "test2__.lua",
        "test3__.lua",
        "test4__.lua",
        "test5__.lua",
    ]

    def get_args(self, cmd):
        return self._args.format(cmd)

    # @classmethod
    # def setUpClass(cls) -> None:

    def setUp(self):
        lib.start()
        self.path = lib.write_file("test.lua", self.TEST_UDF)
        self._args = (
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{{}}' --json -Uadmin -Padmin"
        )

    def tearDown(self) -> None:
        lib.stop()

    def test_can_add_module_with_relative_path(self):
        exp_stdout_resp = "Successfully added UDF {}.".format(self.exp_module)
        exp_stderr_resp = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage udfs add {} path {}".format(self.exp_module, self.path)
            )
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_add_module_with_absolute_path(self):
        exp_stdout_resp = "Successfully added UDF {}.".format(self.exp_module)
        exp_stderr_resp = ""

        cwd = os.getcwd()
        path = os.path.join(cwd, self.path)
        actual = test_util.run_asadm(
            self.get_args("manage udfs add {} path {}".format(self.exp_module, path))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_add_multiple_modules(self):
        exp_stderr_resp = ""

        for exp_module in self.other_modules:
            exp_stdout_resp = "Successfully added UDF {}.".format(exp_module)
            actual = test_util.run_asadm(
                self.get_args(
                    "manage udfs add {} path {}".format(exp_module, self.path)
                )
            )

            self.assertEqual(exp_stdout_resp, actual.stdout)
            self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fails_to_add_if_path_does_not_exist(self):
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to add UDF {}: Path does not exist.".format(
            self.exp_module
        )
        path = "test/e2e/DNE.lua"

        actual = test_util.run_asadm(
            self.get_args("manage udfs add {} path {}".format(self.exp_module, path))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_can_remove_module(self):
        exp_stdout_resp = "Successfully removed UDF {}.".format(self.exp_module)
        exp_stderr_resp = ""

        test_util.run_asadm(
            self.get_args(
                "manage udfs add {} path {}".format(self.exp_module, self.path)
            )
        )
        time.sleep(1)
        actual = test_util.run_asadm(
            self.get_args("manage udfs remove {}".format(self.exp_module))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)

    def test_fail_to_remove_module_that_does_not_exist(self):
        exp_module = "other_test.lua"
        exp_stdout_resp = ""
        exp_stderr_resp = "ERROR: Failed to remove UDF {} : UDF does not exist.".format(
            exp_module
        )

        actual = test_util.run_asadm(
            self.get_args("manage udfs remove {}".format(exp_module))
        )

        self.assertEqual(exp_stdout_resp, actual.stdout)
        self.assertStdErrEqual(exp_stderr_resp, actual.stderr)


class ManageSindexTest(TestManage):
    exp_sindex = "test-sindex"
    exp_ns = "test"
    exp_set = "testset"
    exp_bin = "test-bin"
    success_msg = "Use 'show sindex' to confirm test-sindex was created successfully."

    def get_args(self, cmd):
        return self._args.format(cmd)

    def setUp(self):
        lib.start()
        self._args = (
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{{}}' --json -Uadmin -Padmin"
        )

    def tearDown(self) -> None:
        lib.stop()

    def test_can_create_string_sindex(self):
        exp_stdout = self.success_msg
        exp_stderr = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex create string {} ns {} set {} bin {}".format(
                    self.exp_sindex, self.exp_ns, self.exp_set, self.exp_bin
                )
            )
        )

        self.assertEqual(exp_stdout, actual.stdout)
        self.assertStdErrEqual(exp_stderr, actual.stderr)

    def test_can_create_numeric_sindex(self):
        exp_stdout = self.success_msg
        exp_stderr = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex create numeric {} ns {} set {} bin {}".format(
                    self.exp_sindex, self.exp_ns, self.exp_set, self.exp_bin
                )
            )
        )

        self.assertEqual(exp_stdout, actual.stdout)
        self.assertStdErrEqual(exp_stderr, actual.stderr)

    def test_can_create_geo2dspehere_sindex(self):
        exp_stdout = self.success_msg
        exp_stderr = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex create geo2dsphere {} ns {} set {} bin {}".format(
                    self.exp_sindex, self.exp_ns, self.exp_set, self.exp_bin
                )
            )
        )

        self.assertEqual(exp_stdout, actual.stdout)
        self.assertStdErrEqual(exp_stderr, actual.stderr)

    def test_can_create_sindex_in_list(self):
        exp_stdout = self.success_msg
        exp_stderr = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex create string {} ns {} set {} bin {} in list".format(
                    self.exp_sindex, self.exp_ns, self.exp_set, self.exp_bin
                )
            )
        )

        self.assertEqual(exp_stdout, actual.stdout)
        self.assertStdErrEqual(exp_stderr, actual.stderr)

    def test_can_create_sindex_in_mapkeys(self):
        exp_stdout = self.success_msg
        exp_stderr = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex create string {} ns {} set {} bin {} in mapkeys".format(
                    self.exp_sindex, self.exp_ns, self.exp_set, self.exp_bin
                )
            )
        )

        self.assertEqual(exp_stdout, actual.stdout)
        self.assertStdErrEqual(exp_stderr, actual.stderr)

    def test_can_create_sindex_in_mapvalues(self):
        exp_stdout = self.success_msg
        exp_stderr = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex create string {} ns {} set {} bin {} in mapvalues".format(
                    self.exp_sindex, self.exp_ns, self.exp_set, self.exp_bin
                )
            )
        )

        self.assertEqual(exp_stdout, actual.stdout)
        self.assertStdErrEqual(exp_stderr, actual.stderr)

    def test_fails_to_create_sindex_in_invalid(self):
        exp_stderr = "ERROR: Failed to create sindex {} : bad 'indextype' - must be one of 'default', 'list', 'mapkeys', 'mapvalues'.".format(
            self.exp_sindex
        )

        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex create string {} ns {} set {} bin {} in invalid".format(
                    self.exp_sindex, self.exp_ns, self.exp_set, self.exp_bin
                )
            )
        )

        self.assertStdErrEqual(exp_stderr, actual.stderr)

    def test_can_delete_sindex(self):
        exp_stdout = "Successfully deleted sindex {}.".format(self.exp_sindex)
        exp_stderr = ""

        test_util.run_asadm(
            self.get_args(
                "manage sindex create string {} ns {} set {} bin {}".format(
                    self.exp_sindex, self.exp_ns, self.exp_set, self.exp_bin
                )
            )
        )

        time.sleep(0.5)
        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex delete {} ns {} set {}".format(
                    self.exp_sindex, self.exp_ns, self.exp_set
                )
            )
        )

        self.assertEqual(exp_stdout, actual.stdout)
        self.assertStdErrEqual(exp_stderr, actual.stderr)

    def test_fails_to_delete_sindex_that_does_not_exist(self):
        exp_stdout = "Successfully deleted sindex {}.".format(self.exp_sindex)
        exp_stderr = ""

        actual = test_util.run_asadm(
            self.get_args(
                "manage sindex delete {} ns {} set {}".format(
                    self.exp_sindex, self.exp_ns, self.exp_set
                )
            )
        )

        self.assertEqual(exp_stdout, actual.stdout)
        self.assertStdErrEqual(exp_stderr, actual.stderr)


class ManageConfigTests(unittest.TestCase):
    def get_args(self, cmd):
        return self._args.format(cmd)

    @classmethod
    def setUpClass(cls) -> None:
        lib.start()
        cls._args = (
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{{}}' --json -Uadmin -Padmin"
        )

    @classmethod
    def tearDownClass(cls) -> None:
        lib.stop()

    """
    test_print_info_responses_namespace_set does not exist because flash or pmem index-type
    must be configured.
    """

    @parameterized.expand(
        [
            (
                "manage config logging file {} param misc to info".format(lib.LOG_PATH),
                "Set Logging Context misc to info",
                ["Node", "Response"],
            ),
            (
                "manage config service param batch-max-buffers-per-queue to 255",
                "Set Service Param batch-max-buffers-per-queue to 255",
                ["Node", "Response"],
            ),
            (
                "manage config network fabric param channel-ctrl-recv-threads to 4",
                "Set Network Param channel-ctrl-recv-threads to 4",
                ["Node", "Response"],
            ),
            (
                "manage config network heartbeat param mtu to 0",
                "Set Network Param mtu to 0",
                ["Node", "Response"],
            ),
            (
                "manage config security param privilege-refresh-period to 300",
                "Set Security Param privilege-refresh-period to 300",
                ["Node", "Response"],
            ),
            (
                "manage config security ldap param polling-period to 300",
                "Set Security Param polling-period to 300",
                ["Node", "Response"],
            ),
            (
                "manage config namespace test param allow-ttl-without-nsup to false",
                "Set Namespace Param allow-ttl-without-nsup to false",
                ["Node", "Response"],
            ),
            (
                "manage config namespace test storage-engine param cache-replica-writes to false",
                "Set Namespace Param cache-replica-writes to false",
                ["Node", "Response"],
            ),
            (
                "manage config namespace test geo2dsphere-within param max-cells to 12",
                "Set Namespace Param max-cells to 12",
                ["Node", "Response"],
            ),
            (
                "manage config namespace test set testset param stop-writes-count to 0",
                "Set Namespace Set Param stop-writes-count to 0",
                ["Node", "Response"],
            ),
            (
                "manage config xdr param src-id to 1",
                "Set XDR Param src-id to 1",
                ["Node", "Response"],
            ),
        ]
    )
    def test_check_for_OK_response(self, cmd, exp_title, exp_header):
        cp = test_util.run_asadm(self.get_args(cmd))

        separated_stdout = test_util.get_separate_output(cp.stdout)
        result = list(map(test_util.parse_output, separated_stdout))
        (
            actual_title,
            _,
            actual_header,
            actual_values,
            _,
        ) = result[0]

        self.assertEqual(exp_title, actual_title)
        self.assertEqual(exp_header, actual_header)

        for row in actual_values:
            entry = row[1]
            self.assertEqual(entry, ASINFO_RESPONSE_OK)

    def test_for_dc_does_not_exist_error(self):
        cp = test_util.run_asadm(
            self.get_args("manage config xdr dc non-existent param period-ms to 1000")
        )

        separated_stdout = test_util.get_separate_output(cp.stdout)
        result = list(map(test_util.parse_output, separated_stdout))
        (
            _,
            _,
            _,
            actual_values,
            _,
        ) = result[0]

        for row in actual_values:
            entry = row[1]
            self.assertEqual(entry, "DC does not exist")

    def test_for_ns_does_not_exist_error(self):
        cp = test_util.run_asadm(
            self.get_args(
                "manage config namespace non-existent param disallow-expunge to true"
            )
        )

        separated_stdout = test_util.get_separate_output(cp.stdout)
        result = list(map(test_util.parse_output, separated_stdout))
        (
            _,
            _,
            _,
            actual_values,
            _,
        ) = result[0]

        for row in actual_values:
            entry = row[1]
            self.assertEqual(entry, "Namespace does not exist")


class ManageConfigXDRTests(unittest.TestCase):
    NODE = "127.0.0.1:9000"
    DC = "DC2"

    def get_args(self, cmd):
        return self._args.format(cmd)

    @classmethod
    def setUpClass(cls) -> None:
        lib.start(do_reset=False)
        time.sleep(1)
        cls._args = (
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{{}}' --json -Uadmin -Padmin"
        )
        cls.namespace = lib.NAMESPACE
        cls.dc = "my-test-dc"

    @classmethod
    def tearDownClass(cls) -> None:
        lib.stop()

    """
    test_print_info_responses_namespace_set does not exist because flash or pmem index-type
    must be configured.
    """

    @parameterized.expand(
        [
            (
                f"manage config xdr create dc {DC}",
                f"Create XDR DC {DC}",
                ["Node", "Response"],
            ),
            (
                f"manage config xdr dc {DC} param period-ms to 100",
                f"Set XDR DC param period-ms to 100",
                ["Node", "Response"],
            ),
            (
                f"manage config xdr dc {DC} add node {NODE}",
                f"Add XDR Node {NODE} to DC {DC}",
                ["Node", "Response"],
            ),
            (
                f"manage config xdr dc {DC} add namespace {lib.NAMESPACE}",
                f"Add XDR Namespace {lib.NAMESPACE} to DC {DC}",
                ["Node", "Response"],
            ),
            (
                f"manage config xdr dc {DC} namespace {lib.NAMESPACE} param ship-bin-luts to false",
                f"Set XDR Namespace Param ship-bin-luts to false",
                ["Node", "Response"],
            ),
            (
                f"manage config xdr dc {DC} remove namespace {lib.NAMESPACE}",
                f"Remove XDR Namespace {lib.NAMESPACE} from DC {DC}",
                ["Node", "Response"],
            ),
            (
                f"manage config xdr dc {DC} remove node {NODE}",
                f"Remove XDR Node {NODE} from DC {DC}",
                ["Node", "Response"],
            ),
            (
                f"manage config xdr delete dc {DC}",
                f"Delete XDR DC {DC}",
                ["Node", "Response"],
            ),
        ]
    )
    def test_check_for_OK_response(self, cmd, exp_title, exp_header):
        cp = test_util.run_asadm(self.get_args(cmd))
        time.sleep(5)
        separated_stdout = test_util.get_separate_output(cp.stdout)
        result = list(map(test_util.parse_output, separated_stdout))
        (
            actual_title,
            _,
            actual_header,
            actual_values,
            _,
        ) = result[0]

        self.assertEqual(exp_title, actual_title)
        self.assertEqual(exp_header, actual_header)

        for row in actual_values:
            entry = row[1]
            self.assertEqual(entry, ASINFO_RESPONSE_OK)


class ManageTruncateTest(TestManage):
    def get_args(self, cmd):
        return self._args.format(cmd)

    def setUp(self):
        lib.start()
        self._args = f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{{}}' -Uadmin -Padmin"

    def tearDown(self) -> None:
        lib.stop()

    @parameterized.expand(
        [
            (
                f"manage truncate ns test --no-warn",
                "Successfully started truncation for namespace test",
            ),
            (
                f"manage truncate ns test set testset --no-warn",
                "Successfully started truncation for set testset of namespace test",
            ),
        ]
    )
    def test_check_for_OK_response(self, cmd, exp_stdout):
        cp = test_util.run_asadm(self.get_args(cmd))
        stdout = cp.stdout

        self.assertEqual(exp_stdout, stdout.strip())
