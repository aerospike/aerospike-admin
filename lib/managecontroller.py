from lib.utils import util
from lib.controllerlib import BasicCommandController, CommandHelp
from lib.client.info import ASProtocolError
from getpass import getpass
from logging import DEBUG


@CommandHelp('"manage" is used to manage users, roles, udf, sindex, and dynamic configs.')
class ManageController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            # "sindex": ManageSIndexController,
            "acl": ManageACLController,
            # "udfs": ManageUdfsController,
            # "config": ManageConfigController,
            # "truncate": ManageTruncateController,
        }

        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)

@CommandHelp('"manage" is used to manage users, roles, udf, sindex, and dynamic configs.')
class ManageACLController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            "users": ManageUsersController,
            "roles": ManageRolesController,
        }

        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp('"show config" is used to display Aerospike configuration settings')
class ManageUsersController(BasicCommandController):

    def __init__(self):
        self.controller_map = {
            'create': ManageUsersCreateController,
            'drop': ManageUsersDropController,
            'set-password': ManageUsersSetPasswordController,
            'change-password': ManageUsersChangePasswordController,
            'grant': ManageUsersGrantController,
            'revoke': ManageUsersRevokeController,
        }
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageUsersCreateController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['password', 'roles'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.logger.error("Missing username.")
            self.execute_help(['manage', 'acl', 'users', 'create'])
            return  

        username = line.pop(0)
        password = None
        roles = None

        if len(self.mods['password']):
            password = self.mods['password'][0]
        else:
            password = getpass('Enter password for new user {}:'.format(username))

        roles = list(filter(lambda x: x != ',', self.mods['roles']))

        print(username, password, roles)

        # # TODO: Only make manage requests to principle node
        result = self.cluster.admin_create_user(username, password, roles, nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully created user {}'.format(username))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageUsersDropController(BasicCommandController):

    def __init__(self):
        self.modifiers = set()
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.logger.error("Missing username.")
            self.execute_help(['manage', 'acl', 'users', 'drop'])
            return  

        username = line.pop(0)

        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_delete_user(username, nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully dropped user {}'.format(username))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageUsersSetPasswordController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['password'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.logger.error("Missing username.")
            self.execute_help(['manage', 'acl', 'users', 'set-password'])
            return

        username = line.pop(0)
        password = None

        if len(self.mods['password']):
            password = self.mods['password'][0]
        else:
            password = getpass('Enter password for user {}:'.format(username))

        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_set_password(username, password, nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully set password for user {}'.format(username))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageUsersChangePasswordController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['old', 'new'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.logger.error("Missing username.")
            self.execute_help(['manage', 'acl', 'users', 'change-password'])
            return

        username = line.pop(0)
        old_password = None
        new_password = None

        if len(self.mods['old']):
            old_password = self.mods['old'][0]
        else:
            old_password = getpass('Enter old password:')

        if len(self.mods['new']):
            new_password = self.mods['new'][0]
        else:
            new_password = getpass('Enter new password:')

        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_set_password(
            username, 
            old_password, 
            new_password, 
            nodes=self.nodes
        )
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully changed password for user {}'.format(username))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageUsersGrantController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['roles'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.logger.error("Missing username.")
            self.execute_help(['manage', 'acl', 'users', 'grant'])
            return  

        username = line.pop(0)
        roles = list(filter(lambda x: x != ',', self.mods['roles']))

        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_grant_roles(username, roles, nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully granted roles to user {}'.format(username))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageUsersRevokeController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['roles'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.logger.error("Missing username.")
            self.execute_help(['manage', 'acl', 'users', 'revoke'])
            return  

        username = line.pop(0)
        roles = list(filter(lambda x: x != ',', self.mods['roles']))

        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_revoke_roles(username, roles, nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully revoked roles from user {}'.format(username))


@CommandHelp('"show config" is used to display Aerospike configuration settings')
class ManageRolesController(BasicCommandController):

    def __init__(self):
        self.controller_map = {
            'create': ManageRolesCreateController,
            'drop': ManageRolesDropController,
            'grant': ManageRolesGrantController,
            'revoke': ManageRolesRevokeController,
            'allowlist': ManageRolesAllowListController
        }
        self.modifiers = set()

        self.default_roles = [
            "data-admin",
            "read",
            "read-write",
            "read-write-udf",
            "sys-admin",
            "user-admin",
            "write"
        ]

    def _do_default(self, line):
        self.execute_help(line)

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageRolesCreateController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['allow'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.logger.error("Missing role name.")
            self.execute_help(['manage', 'acl', 'roles', 'create'])
            return  

        role_name = line.pop(0)
        privileges = []
        allowlist = list(filter(lambda x: x != ',', self.mods['allow']))

        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_create_role(role_name, privileges, whitelist=allowlist, nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully created role {}'.format(role_name))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageRolesDropController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['roles'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.logger.error("Missing role name.")
            self.execute_help(['manage', 'acl', 'roles', 'drop'])
            return  

        role_name = line.pop(0)

        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_drop_role(role_name, nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully dropped role {}'.format(role_name))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageRolesGrantController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['priv', 'ns', 'set'])
        self.controller_map = {}

    def _execute_help(self):
        self.execute_help(['manage', 'acl', 'roles', 'revoke'])

    def _do_default(self, line):

        if not len(line):
            self._execute_help()
            self.logger.error("Missing role name.")
            return  

        role_name = line.pop(0)
        
        if not len(self.mods['priv']):
            self._execute_help()
            self.logger.error("Privilege required.")
            return

        privilege = self.mods['priv'][0]

        if len(self.mods['set']) and not len(self.mods['ns']):
            self._execute_help()
            self.logger.error("A set must be accompanied by a namespace.")
            return
        
        if len(self.mods['ns']):
            privilege += '.' + self.mods['ns'][0]

            if len(self.mods['set']):
                privilege += '.' + self.mods['set'][0]

        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_add_privileges(role_name, [privilege], nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully granted privileges to role {}'.format(role_name))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageRolesRevokeController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['priv', 'ns', 'set'])
        self.controller_map = {}

    def _execute_help(self):
        self.execute_help(['manage', 'acl', 'roles', 'revoke'])

    def _do_default(self, line):

        if not len(line):
            self._execute_help()
            self.logger.error("Missing role name.")
            return  

        role_name = line.pop(0)
        
        if not len(self.mods['priv']):
            self._execute_help()
            self.logger.error("Privilege required.")
            return

        privilege = self.mods['priv'][0]

        if len(self.mods['set']) and not len(self.mods['ns']):
            self._execute_help()
            self.logger.error("A set must be accompanied by a namespace.")
            return
        
        if len(self.mods['ns']):
            privilege += '.' + self.mods['ns'][0]

            if len(self.mods['set']):
                privilege += '.' + self.mods['set'][0]

        
        # TODO: Only make manage requests to principle node
        result = self.cluster.admin_delete_privileges(role_name, [privilege], nodes=self.nodes)
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.logger.info('Successfully revoked privileges from role {}'.format(role_name))

@CommandHelp(
    "create <username> password [grant <role1>,[role2],. . .]",
)
class ManageRolesAllowListController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['clear', 'allow'])
        self.controller_map = {}

    def _execute_help(self):
        self.execute_help(['manage', 'acl', 'roles', 'allowlist'])

    @util.logthis('asadm', DEBUG)
    def _do_default(self, line):

        if not len(line):
            self._execute_help()
            self.logger.error("Missing role name.")
            return  

        role_name = line.pop(0)

        clear = util.check_arg_and_delete_from_mods(
            line=line,
            arg='clear',
            default=False,
            modifiers=self.modifiers,
            mods=self.mods
        )

        allowlist = list(filter(lambda x: x != ',', self.mods['allow']))

        if not clear and not len(allowlist):
            self._execute_help()
            self.logger.error("Missing allowlist.")
            return

        result = None

        # TODO: Only make manage requests to principle node
        if clear:
            result = self.cluster.admin_delete_whitelist(role_name, nodes=self.nodes)
        else:
            result = self.cluster.admin_set_whitelist(role_name, allowlist, nodes=self.nodes)
        
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        if clear:
            self.logger.info('Successfully cleared allowlist from role {}'.format(role_name))
        else:
            self.logger.info('Successfully added allowlist to role {}'.format(role_name))
