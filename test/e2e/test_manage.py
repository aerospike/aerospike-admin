import os
import sys
import unittest

import lib.basiccontroller as controller
import lib.utils.util as util
from test.e2e import test_util

sys.path.insert(1, os.getcwd())

class TestManageACLUsers(unittest.TestCase):
    output_list = list()

    @classmethod
    def setUpClass(cls):
        cls.rc = controller.BasicRootController(user='admin', password='admin')

    @classmethod
    def tearDownClass(cls):
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'acl', 'delete', 'user', 'foo'])
        cls.rc = None

    @classmethod
    def setUp(cls):
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'acl', 'delete', 'user', 'foo'])

    def test_can_create_user(self):
        exp_user = 'foo'
        exp_stdout_resp = 'Successfully created user {}'.format(exp_user)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', 'test'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_create_user_with_roles(self):
        exp_user = 'foo'
        exp_stdout_resp = 'Successfully created user {}'.format(exp_user)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', 'test', 'roles', 'sys-admin', 'data-admin'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    
    def test_fails_to_create_user_if_one_exists(self):
        exp_user = 'foo'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to create user : User already exists'

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', 'test'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', 'bar'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_delete_user(self):
        exp_user = 'foo'
        exp_stdout_resp = 'Successfully deleted user {}'.format(exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', 'test'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'delete', 'user', exp_user])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fail_to_delete_user_if_one_does_not_exist(self):
        exp_user = 'foo'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to delete user : No user or unrecognized user'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'delete', 'user', exp_user])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_set_user_password(self):
        exp_user = 'foo'
        exp_password = 'test'
        exp_stdout_resp = 'Successfully set password for user {}'.format(exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', ''])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'set-password', 'user', exp_user, 'password', exp_password])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_set_user_password(self):
        exp_user = 'foo'
        exp_password = 'test'
        exp_stdout_resp = 'Successfully set password for user {}'.format(exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', ''])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'set-password', 'user', exp_user, 'password', exp_password])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_change_user_password(self):
        exp_user = 'foo'
        exp_password = 'test'
        exp_stdout_resp = 'Successfully changed password for user {}'.format(exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', exp_password])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'change-password', 'user', exp_user, 'old', exp_password, 'new', 'test'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_change_user_password_when_old_is_wrong(self):
        exp_user = 'foo'
        right_password = 'test'
        wrong_password = 'bar'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to change password : No password or bad password'

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', right_password])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'change-password', 'user', exp_user, 'old', wrong_password, 'new', 'test'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_grant_user_roles(self):
        exp_user = 'foo'
        exp_stdout_resp = 'Successfully granted roles to user {}'.format(exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', 'test'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'grant', 'user', exp_user, 'roles', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_grant_user_roles_if_user_does_not_exist(self):
        exp_user = 'foo'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to grant roles : No user or unrecognized user'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'grant', 'user', exp_user, 'roles', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_revoke_user_roles(self):
        exp_user = 'foo'
        exp_stdout_resp = 'Successfully revoked roles from user {}'.format(exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', exp_user, 'password', 'test'])
        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'grant', 'user', exp_user, 'roles', 'read', 'write'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'revoke', 'user', exp_user, 'roles', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_revoke_user_roles_if_user_does_not_exist(self):
        exp_user = 'foo'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to revoke roles : No user or unrecognized user'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'revoke', 'user', exp_user, 'roles', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

class TestManageACLRoles(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rc = controller.BasicRootController(user='admin', password='admin')

    @classmethod
    def tearDownClass(cls):
        cls.rc = None

    # @classmethod
    def setUp(cls):
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'acl', 'delete', 'role', 'avatar'])

    def test_can_create_role_with_privilege(self):
        exp_role = 'avatar'
        exp_stdout_resp = 'Successfully created role {}'.format(exp_role)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'priv', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_create_role_with_allowlist(self):
        exp_role = 'avatar'
        exp_stdout_resp = 'Successfully created role {}'.format(exp_role)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'allow', '1.1.1.1', '2.2.2.2'])

        self.assertEqual(exp_stderr_resp, actual_stderr.strip())
        self.assertEqual(exp_stdout_resp, actual_stdout.strip())

    def test_can_create_role_with_privilege_and_allowlist(self):
        exp_role = 'avatar'
        exp_stdout_resp = 'Successfully created role {}'.format(exp_role)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'priv', 'read', 'write', 'allow', '1.1.1.1', '2.2.2.2'])

        self.assertEqual(exp_stderr_resp, actual_stderr.strip())
        self.assertEqual(exp_stdout_resp, actual_stdout.strip())

    
    def test_fails_to_create_role_if_one_exists(self):
        exp_role = 'avatar'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to create role : Role already exists'

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'priv', 'read', 'write'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'priv', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_create_role_if_privilege_is_invalid(self):
        exp_role = 'avatar'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to create role : No privleges or unrecognized privileges'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'priv', 'invalid-priv'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_delete_role(self):
        exp_role = 'avatar'
        exp_stdout_resp = 'Successfully deleted role {}'.format(exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'priv', 'read'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'delete', 'role', exp_role])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fail_to_delete_role_if_one_does_not_exist(self):
        exp_role = 'avatar'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to delete role : No role or invalid role'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'delete', 'role', exp_role])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_grant_role_privilege(self):
        exp_role = 'avatar'
        exp_stdout_resp = 'Successfully granted privilege to role {}'.format(exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'allow', '1.1.1.1'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'grant', 'role', exp_role, 'priv', 'read'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_grant_role_privilege_if_role_does_not_exist(self):
        exp_role = 'avatar'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to grant privilege : No role or invalid role'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'grant', 'role', exp_role, 'priv', 'read'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_revoke_role_privileges(self):
        exp_role = 'avatar'
        exp_stdout_resp = 'Successfully revoked privilege from role {}'.format(exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'priv', 'read'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'revoke', 'role', exp_role, 'priv', 'read'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_revoke_role_privilege_if_role_does_not_exist(self):
        exp_role = 'avatar'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to revoke privileges : No role or invalid role'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'revoke', 'role', exp_role, 'priv', 'read',])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_add_allowlist_to_role(self):
        exp_role = 'avatar'
        exp_stdout_resp = "Successfully updated allowlist for role {}".format(exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'allow', '1.1.1.1'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'allowlist', 'role', exp_role, 'allow', '2.2.2.2'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_clear_allowlist_to_role(self):
        exp_role = 'avatar'
        exp_stdout_resp = "Successfully cleared allowlist from role {}".format(exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', exp_role, 'allow', '1.1.1.1'])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'allowlist', 'role', exp_role, 'clear'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_clear_allowlist_if_role_does_not_exist(self):
        exp_role = 'avatar'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to delete whitelist : No role or invalid role'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'allowlist', 'role', exp_role, 'clear'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())