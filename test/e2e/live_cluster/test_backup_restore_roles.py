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

import os
import shutil
import time
import unittest

from test.e2e import lib, util as test_util

# 8.2.1 lists backup-admin and restore-admin only with --preview backup-restore.
SERVER_TAG = lib.SERVER_8_2_1_TAG
PREVIEW = ["backup-restore"]
ROLE = "tools-4629-br"
COLLECTINFO_PREFIX = "asadm_tools_4629_"
REFUSED = "No privileges or unrecognized privileges."


def start(preview_features=None):
    lib.stop()
    lib.start(num_nodes=1, docker_tag=SERVER_TAG, preview_features=preview_features)

    return "-h {}:{} --enable -e '{{}}' --json -Uadmin -Padmin".format(
        lib.SERVER_IP, lib.PORT
    )


class RolesMixin:
    args = None

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def tearDown(self):
        test_util.run_asadm(self.args.format("manage acl delete role " + ROLE))

    def run_asadm(self, cmd):
        return test_util.run_asadm(self.args.format(cmd))

    def roles(self, cmd="show roles", args=None):
        cp = test_util.run_asadm((args or self.args).format(cmd))
        out = test_util.get_separate_output(cp.stdout)

        if not out:
            raise AssertionError(
                "no sheet in '{}' output:\n{}\n{}".format(cmd, cp.stdout, cp.stderr)
            )

        _, _, names, values, _ = test_util.parse_output(out[0])

        return {
            record["Role"]: record["Privileges"]
            for record in (dict(zip(names, row)) for row in values)
        }


class TestBackupRestoreRolesWithoutPreview(RolesMixin, unittest.TestCase):
    """8.2.1 without the preview flag neither lists nor accepts codes 5 and 6."""

    @classmethod
    def setUpClass(cls):
        cls.args = start()

    def test_show_roles_leaves_out_backup_and_restore_admin(self):
        roles = self.roles()

        self.assertIn("sys-admin", roles)
        self.assertNotIn("backup-admin", roles)
        self.assertNotIn("restore-admin", roles)

    def test_server_refuses_backup_and_restore_admin(self):
        cp = self.run_asadm("manage acl create role {} priv backup-admin".format(ROLE))

        self.assertIn("ERROR: Failed to create role : " + REFUSED, cp.stderr)
        self.assertEqual(2, cp.returncode)

        cp = self.run_asadm("manage acl create role {} priv read".format(ROLE))

        self.assertEqual("Successfully created role {}.".format(ROLE), cp.stdout)

        cp = self.run_asadm("manage acl grant role {} priv restore-admin".format(ROLE))

        self.assertIn("ERROR: Failed to grant privilege : " + REFUSED, cp.stderr)
        self.assertEqual(2, cp.returncode)
        self.assertEqual({ROLE: "read"}, self.roles("show roles " + ROLE))


class TestBackupRestoreRoles(RolesMixin, unittest.TestCase):
    """TOOLS-4629: privilege codes 5 and 6 on a node started with the preview flag."""

    @classmethod
    def setUpClass(cls):
        cls.args = start(PREVIEW)

    def wait_for_privileges(self, expected):
        cmd = "show roles " + ROLE
        actual = None

        for _ in range(20):
            actual = self.roles(cmd).get(ROLE)

            if actual == expected:
                return

            time.sleep(0.5)

        self.assertEqual(expected, actual)

    def test_show_roles_lists_predefined_backup_and_restore_admin(self):
        roles = self.roles()

        self.assertEqual("backup-admin", roles.get("backup-admin"))
        self.assertEqual("restore-admin", roles.get("restore-admin"))

    def test_show_one_predefined_role(self):
        self.assertEqual(
            {"backup-admin": "backup-admin"}, self.roles("show roles backup-admin")
        )

    def test_create_grant_and_revoke_backup_and_restore_admin(self):
        cp = self.run_asadm("manage acl create role {} priv backup-admin".format(ROLE))
        self.assertEqual("Successfully created role {}.".format(ROLE), cp.stdout)
        self.wait_for_privileges("backup-admin")

        cp = self.run_asadm("manage acl grant role {} priv restore-admin".format(ROLE))
        self.assertEqual(
            "Successfully granted privilege to role {}.".format(ROLE), cp.stdout
        )
        self.wait_for_privileges("backup-admin,restore-admin")

        cp = self.run_asadm("manage acl revoke role {} priv backup-admin".format(ROLE))
        self.assertEqual(
            "Successfully revoked privilege from role {}.".format(ROLE), cp.stdout
        )
        self.wait_for_privileges("restore-admin")

    def test_collectinfo_keeps_roles(self):
        cp = test_util.run_asadm(
            "-h {}:{} -Uadmin -Padmin -e 'collectinfo --output-prefix {}'".format(
                lib.SERVER_IP, lib.PORT, COLLECTINFO_PREFIX
            )
        )
        path = test_util.get_collectinfo_path(cp, COLLECTINFO_PREFIX)

        try:
            roles = self.roles(args="-cf {} --json -e '{{}}'".format(path))
        finally:
            os.remove(path)
            shutil.rmtree(path.removesuffix(".tgz"), ignore_errors=True)

        self.assertEqual("backup-admin", roles.get("backup-admin"))
        self.assertEqual("restore-admin", roles.get("restore-admin"))
