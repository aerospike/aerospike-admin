import os
import time
import unittest

import lib.basiccontroller as controller
import lib.utils.util as util
from test.e2e import test_util

class TestManageACLUsers(unittest.TestCase):
    exp_user = 'foo'

    @classmethod
    def setUpClass(cls):
        cls.rc = controller.BasicRootController(user='admin', password='admin')

    @classmethod
    def tearDownClass(cls):
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'acl', 'delete', 'user', cls.exp_user])
        cls.rc = None

    @classmethod
    def setUp(cls):
        # Added since tests were failing.  I assume because the server response
        # comes before the request is commited to SMD or security layer.
        time.sleep(.25)
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'acl', 'delete', 'user', cls.exp_user])
        time.sleep(.25)

    def test_can_create_user(self):
        exp_stdout_resp = 'Successfully created user {}'.format(self.exp_user)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', 'test'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_create_user_with_roles(self):
        exp_stdout_resp = 'Successfully created user {}'.format(self.exp_user)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', 'test', 'roles', 'sys-admin', 'data-admin'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    
    def test_fails_to_create_user_if_one_exists(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to create user : User already exists'

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', 'test'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', 'bar'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_delete_user(self):
        exp_stdout_resp = 'Successfully deleted user {}'.format(self.exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', 'test'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'delete', 'user', self.exp_user])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fail_to_delete_user_if_one_does_not_exist(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to delete user : No user or unrecognized user'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'delete', 'user', self.exp_user])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_set_user_password(self):
        exp_password = 'test'
        exp_stdout_resp = 'Successfully set password for user {}'.format(self.exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', ''])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'set-password', 'user', self.exp_user, 'password', exp_password])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_set_user_password(self):
        exp_password = 'test'
        exp_stdout_resp = 'Successfully set password for user {}'.format(self.exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', ''])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'set-password', 'user', self.exp_user, 'password', exp_password])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_change_user_password(self):
        exp_password = 'test'
        exp_stdout_resp = 'Successfully changed password for user {}'.format(self.exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', exp_password])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'change-password', 'user', self.exp_user, 'old', exp_password, 'new', 'test'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_change_user_password_when_old_is_wrong(self):
        right_password = 'test'
        wrong_password = 'bar'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to change password : No password or bad password'

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', right_password])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'change-password', 'user', self.exp_user, 'old', wrong_password, 'new', 'test'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_grant_user_roles(self):
        exp_stdout_resp = 'Successfully granted roles to user {}'.format(self.exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', 'test'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'grant', 'user', self.exp_user, 'roles', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_grant_user_roles_if_user_does_not_exist(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to grant roles : No user or unrecognized user'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'grant', 'user', self.exp_user, 'roles', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_revoke_user_roles(self):
        exp_stdout_resp = 'Successfully revoked roles from user {}'.format(self.exp_user)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'user', self.exp_user, 'password', 'test'])
        time.sleep(.5)
        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'grant', 'user', self.exp_user, 'roles', 'read', 'write'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'revoke', 'user', self.exp_user, 'roles', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_revoke_user_roles_if_user_does_not_exist(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to revoke roles : No user or unrecognized user'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'revoke', 'user', self.exp_user, 'roles', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

class TestManageACLRoles(unittest.TestCase):
    exp_role = 'avatar'

    @classmethod
    def setUpClass(cls):
        cls.rc = controller.BasicRootController(user='admin', password='admin')

    @classmethod
    def tearDownClass(cls):
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'acl', 'delete', 'role', cls.exp_role])
        cls.rc = None

    @classmethod
    def setUp(cls):
        # Added since tests were failing.  I assume because the server response
        # comes before the request is commited to SMD or security layer.
        time.sleep(.25)
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'acl', 'delete', 'role', cls.exp_role])
        time.sleep(.25)

    def test_can_create_role_with_privilege(self):
        exp_stdout_resp = 'Successfully created role {}'.format(self.exp_role)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'priv', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_create_role_with_allowlist(self):
        exp_stdout_resp = 'Successfully created role {}'.format(self.exp_role)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'allow', '1.1.1.1', '2.2.2.2'])

        self.assertEqual(exp_stderr_resp, actual_stderr.strip())
        self.assertEqual(exp_stdout_resp, actual_stdout.strip())

    def test_can_create_role_with_privilege_and_allowlist(self):
        exp_stdout_resp = 'Successfully created role {}'.format(self.exp_role)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'priv', 'read', 'write', 'allow', '1.1.1.1', '2.2.2.2'])

        self.assertEqual(exp_stderr_resp, actual_stderr.strip())
        self.assertEqual(exp_stdout_resp, actual_stdout.strip())

    
    def test_fails_to_create_role_if_one_exists(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to create role : Role already exists'

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'priv', 'read', 'write'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'priv', 'read', 'write'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_create_role_if_privilege_is_invalid(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to create role : No privleges or unrecognized privileges'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'priv', 'invalid-priv'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_delete_role(self):
        exp_stdout_resp = 'Successfully deleted role {}'.format(self.exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'priv', 'read'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'delete', 'role', self.exp_role])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fail_to_delete_role_if_one_does_not_exist(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to delete role : No role or invalid role'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'delete', 'role', self.exp_role])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_grant_role_privilege(self):
        exp_stdout_resp = 'Successfully granted privilege to role {}'.format(self.exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'allow', '1.1.1.1'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'grant', 'role', self.exp_role, 'priv', 'read'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_grant_role_privilege_if_role_does_not_exist(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to grant privilege : No role or invalid role'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'grant', 'role', self.exp_role, 'priv', 'read'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_revoke_role_privileges(self):
        exp_stdout_resp = 'Successfully revoked privilege from role {}'.format(self.exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'priv', 'read'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'revoke', 'role', self.exp_role, 'priv', 'read'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_revoke_role_privilege_if_role_does_not_exist(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to revoke privileges : No role or invalid role'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'revoke', 'role', self.exp_role, 'priv', 'read',])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_add_allowlist_to_role(self):
        exp_stdout_resp = "Successfully updated allowlist for role {}".format(self.exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'allow', '1.1.1.1'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'allowlist', 'role', self.exp_role, 'allow', '2.2.2.2'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_clear_allowlist_to_role(self):
        exp_stdout_resp = "Successfully cleared allowlist from role {}".format(self.exp_role)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'acl', 'create', 'role', self.exp_role, 'allow', '1.1.1.1'])
        time.sleep(.5)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'allowlist', 'role', self.exp_role, 'clear'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_clear_allowlist_if_role_does_not_exist(self):
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to delete whitelist : No role or invalid role'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'acl', 'allowlist', 'role', self.exp_role, 'clear'])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

class ManageUDFsTest(unittest.TestCase):
    exp_module = 'test.lua'
    path = 'test/e2e/test.lua'
    other_modules = [
        'test0.lua',
        'test1.lua',
        'test2.lua',
        'test3.lua',
        'test4.lua',
        'test5.lua'
    ]

    @classmethod
    def setUpClass(cls):
        cls.rc = controller.BasicRootController(user='admin', password='admin')
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'udfs', 'remove', cls.exp_module])

    @classmethod
    def tearDownClass(cls):
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'udfs', 'remove', cls.exp_module])

        for module in cls.other_modules:
            util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'udfs', 'remove', module])

        cls.rc = None

    @classmethod
    def setUp(cls):
        util.capture_stdout_and_stderr(cls.rc.execute, ['manage', 'udfs', 'remove', cls.exp_module])
        time.sleep(.5)


    def test_can_add_module_with_relative_path(self):
        exp_module = 'test.lua'
        exp_stdout_resp = 'Successfully added UDF {}'.format(exp_module)
        exp_stderr_resp = ''

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'udfs', 'add', exp_module, 'path', self.path])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_add_module_with_absolute_path(self):
        exp_module = 'test.lua'
        exp_stdout_resp = 'Successfully added UDF {}'.format(exp_module)
        exp_stderr_resp = ''

        cwd = os.getcwd()
        path = os.path.join(cwd, self.path)
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'udfs', 'add', exp_module, 'path', path])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_add_multiple_modules(self):
        exp_stderr_resp = ''

        module_names = [
            'test0.lua',
            'test1.lua',
            'test2.lua',
            'test3.lua',
            'test4.lua',
            'test5.lua',
        ]

        for exp_module in module_names:
            exp_stdout_resp = 'Successfully added UDF {}'.format(exp_module)
            actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'udfs', 'add', exp_module, 'path', self.path])

            self.assertEqual(exp_stdout_resp, actual_stdout.strip())
            self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fails_to_add_if_path_does_not_exist(self):
        exp_module = 'test.lua'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to add UDF {}: Path does not exist'.format(exp_module)
        path = 'test/e2e/DNE.lua'

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'udfs', 'add', exp_module, 'path', path])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_can_remove_module(self):
        exp_module = 'test.lua'
        exp_stdout_resp = 'Successfully removed UDF {}'.format(exp_module)
        exp_stderr_resp = ''

        util.capture_stdout(self.rc.execute, ['manage', 'udfs', 'add', exp_module, 'path', self.path])
        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'udfs', 'remove', exp_module])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())

    def test_fail_to_remove_module_that_does_not_exist(self):
        exp_module = 'other_test.lua'
        exp_stdout_resp = ''
        exp_stderr_resp = 'Failed to remove UDF {}: UDF does not exist'.format(exp_module)

        actual_stdout, actual_stderr = util.capture_stdout_and_stderr(self.rc.execute, ['manage', 'udfs', 'remove', exp_module])

        self.assertEqual(exp_stdout_resp, actual_stdout.strip())
        self.assertEqual(exp_stderr_resp, actual_stderr.strip())