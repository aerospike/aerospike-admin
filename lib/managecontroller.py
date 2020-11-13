from lib.utils import util
from lib.controllerlib import CommandHelp, BasicCommandController
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

@CommandHelp('"manage acl" is used to manage users and roles.')
class ManageACLController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            "users": ManageUsersController,
            "roles": ManageRolesController,
        }

        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp('"manage acl users" is used manage users and their roles.')
class ManageUsersController(BasicCommandController):

    def __init__(self):
        self.controller_map = {
            'create': ManageUsersCreateController,
            'delete': ManageUsersDropController,
            'set-password': ManageUsersSetPasswordController,
            'change-password': ManageUsersChangePasswordController,
            'grant': ManageUsersGrantController,
            'revoke': ManageUsersRevokeController,
        }
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    "create <username> [password <password>] [roles <role1> <role2> ...]",
    "   username        - Name of new user.",
    "   password        - Password for the new user.  User will be prompted if no",
    "                     password is provided.",
    "   roles           - Roles to be granted to the user. Default: None"
)
class ManageUsersCreateController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['password', 'roles'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.execute_help(line)
            self.logger.error("Username is required")
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

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_create_user(username, password, roles, nodes=[principle_node])
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully created user {}".format(username))

@CommandHelp(
    "delete <username>",
    "  username           - User to delete.",
)
class ManageUsersDropController(BasicCommandController):

    def __init__(self):
        self.modifiers = set()
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.execute_help(line)
            self.logger.error("Username is required")
            return  

        username = line.pop(0)

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_delete_user(username, nodes=[principle_node])
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully deleted user {}".format(username))

@CommandHelp(
    "set-password <username> [password <password>]",
    "  username           - User with no password set.",
    "  password           - Password for the new user.  User will be prompted if no",
    "                       password is provided.",
)
class ManageUsersSetPasswordController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['password'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.execute_help(line)
            self.logger.error("Username is required")
            return

        username = line.pop(0)
        password = None

        if len(self.mods['password']):
            password = self.mods['password'][0]
        else:
            password = getpass('Enter password for user {}:'.format(username))

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_set_password(username, password, nodes=[principle_node])
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully set password for user {}".format(username))

@CommandHelp(
    "change-password <username> [old <old-password>] [new <new-password>]",
    "  username           - User that needs a new password.",
    "  old                - Current password for user.  User will be",
    "                       prompted if no password is provided.",
    "  new                - New password for user.  User will be prompted "
    "                       if no password is provided.",
)
class ManageUsersChangePasswordController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['old', 'new'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.execute_help(line)
            self.logger.error("Username is required")
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

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_set_password(
            username, 
            old_password, 
            new_password, 
            nodes=[principle_node]
        )
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully changed password for user {}".format(username))

@CommandHelp(
    "grant <username> roles <role1> [<role2> [...]]",
    "  username        - User to have roles added.",
    "  roles           - Roles to be add to user.",
)
class ManageUsersGrantController(BasicCommandController):

    def __init__(self):
        self.modifiers = set([])
        self.required_modifiers = set(['roles'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.execute_help(line)
            self.logger.error("Username is required")
            return  

        username = line.pop(0)
        roles = list(filter(lambda x: x != ',', self.mods['roles']))
        principle_node = self.cluster.get_expected_principal()

        result = self.cluster.admin_grant_roles(username, roles, nodes=[principle_node])
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully granted roles to user {}".format(username))

@CommandHelp(
    "revoke <username> roles <role1> [<role2> [...]]",
    "  username        - User to have roles deleted.",
    "  roles           - Roles to delete from user.",
)
class ManageUsersRevokeController(BasicCommandController):

    def __init__(self):
        self.modifiers = set([])
        self.required_modifiers = set(['roles'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.execute_help(line)
            self.logger.error("Username is required")
            return  

        username = line.pop(0)
        roles = list(filter(lambda x: x != ',', self.mods['roles']))

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_revoke_roles(username, roles, nodes=[principle_node])
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully revoked roles from user {}".format(username))


@CommandHelp('"manage acl roles" is used manage roles and their privileges or allowlist.')
class ManageRolesController(BasicCommandController):

    def __init__(self):
        self.controller_map = {
            'create': ManageRolesCreateController,
            'delete': ManageRolesDropController,
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
    "create <role-name> priv <privilege> [ns <namespace> [set <set>]]> allow <addr1> [<addr2> [...]]",
    "  role-name     - Name of new role.",
    "  priv          - Privilege for the new role. Some privileges are not limited to a global scope",
    "                  Scopes are either global, per namespace, or per namespace and set.",
    "                  For more information: ",
    "                  https://www.aerospike.com/docs/operations/configure/security/access-control/#privileges-permissions-and-scopes",
    "                  default: None",
    "  ns            - Namespace scope of privilege.",
    "                  defualt: None",
    "  set           - Set scope of privilege. Namespace scope is required.",
    "                  defualt: None",
    "  allow         - Addresses of nodes that a role will be allowed to connect",
    "                  to.",
    "                  default: None"
)
class ManageRolesCreateController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['priv', 'ns', 'set', 'allow'])
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.execute_help(line)
            self.logger.error("Role name is required")
            return  

        role_name = line.pop(0)
        privilege = None
        allowlist = list(filter(lambda x: x != ',', self.mods['allow']))

        if len(self.mods['priv']):
            privilege = self.mods['priv'][0]

        if not len(allowlist) and privilege is None:
            self.execute_help(line)
            self.logger.error('Privilege or allowlist is required')
            return

        if len(self.mods['set']) and not len(self.mods['ns']):
            self.execute_help(line)
            self.logger.error("A set must be accompanied by a namespace.")
            return
        
        if len(self.mods['ns']):
            privilege += '.' + self.mods['ns'][0]

            if len(self.mods['set']):
                privilege += '.' + self.mods['set'][0]

        # admin_create_role expects a list of privileges but the UI excepts one.
        privilege = [] if privilege is None else [privilege]

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_create_role(
            role_name, 
            privileges=privilege, 
            whitelist=allowlist, 
            nodes=[principle_node]
        )
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result('Successfully created role {}'.format(role_name))

@CommandHelp(
    "delete <role-name>",
    "  role-name     - Name of role to delete.",
)
class ManageRolesDropController(BasicCommandController):

    def __init__(self):
        self.controller_map = {}

    def _do_default(self, line):

        if len(line) == 0:
            self.execute_help(line)
            self.logger.error("Role name is required")
            return

        role_name = line.pop(0)

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin__role(role_name, nodes=[principle_node])
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully deleted role {}".format(role_name))

@CommandHelp(
    "grant <role-name> priv <privilege> [ns <namespace> [set <set>]]>",
    "  role-name     - Role to have privilege added.",
    "  priv          - Privilege to be added to role.",
    "  ns            - Namespace scope of privilege.",
    "                  defualt: None",
    "  set           - Set scope of privilege. Namespace scope is required.",
    "                  defualt: None",
)
class ManageRolesGrantController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['ns', 'set'])
        self.required_modifiers = set(['priv'])
        self.controller_map = {}

    def _do_default(self, line):

        if not len(line):
            self.execute_help(line)
            self.logger.error("Role name is required")
            return  

        role_name = line.pop(0)

        privilege = self.mods['priv'][0]

        if len(self.mods['set']) and not len(self.mods['ns']):
            self.execute_help(line)
            self.logger.error("A set must be accompanied by a namespace.")
            return
        
        if len(self.mods['ns']):
            privilege += '.' + self.mods['ns'][0]

            if len(self.mods['set']):
                privilege += '.' + self.mods['set'][0]

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_add_privileges(role_name, [privilege], nodes=[principle_node])
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully granted privilege to role {}".format(role_name))

@CommandHelp(
    "revoke <role-name> priv <privilege> [ns <namespace> [set <set>]]>",
    "  role-name     - Role to have privilege deleted.",
    "  priv          - Privilege to delete from role.",
    "  ns            - Namespace scope of privilege",
    "                  defualt: None",
    "  set           - Set scope of privilege. Namespace scope is required.",
    "                  defualt: None",
)
class ManageRolesRevokeController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['ns', 'set'])
        self.required_modifiers = set(['priv'])
        self.controller_map = {}

    def _do_default(self, line):

        if not len(line):
            self.execute_help(line)
            self.logger.error("Role name is required")
            return  

        role_name = line.pop(0)

        privilege = self.mods['priv'][0]

        if len(self.mods['set']) and not len(self.mods['ns']):
            self.execute_help(line)
            self.logger.error("A set must be accompanied by a namespace")
            return
        
        if len(self.mods['ns']):
            privilege += '.' + self.mods['ns'][0]

            if len(self.mods['set']):
                privilege += '.' + self.mods['set'][0]

        
        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_delete_privileges(role_name, [privilege], nodes=[principle_node])
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully revoked privilege from role {}".format(role_name))

@CommandHelp(
    "allowlist <role-name> allow <addr1> [<addr2> [...]]",
    "  role-name     - Role that will have new allowlist.",
    "  allow         - Addresses of nodes that a role will be allowed to connect",
    "                  to. This command erases and re-assigns the allowlist",
    "  clear         - Clears allowlist from role. Either 'allow' or 'clear' is",
    "                  required.",
)
class ManageRolesAllowListController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['clear', 'allow'])
        self.controller_map = {}

    @util.logthis('asadm', DEBUG)
    def _do_default(self, line):

        if not len(line):
            self.execute_help(line)
            self.logger.error("Role name is required")
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
            self.execute_help(line)
            self.logger.error("Allowlist or clear is required.")
            return

        result = None
        principle_node = self.cluster.get_expected_principal()

        if clear:
            result = self.cluster.admin_delete_whitelist(role_name, nodes=[principle_node])
        else:
            result = self.cluster.admin_set_whitelist(role_name, allowlist, nodes=[principle_node])
        
        result = result[list(result.keys())[0]]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        if clear:
            self.view.print_result("Successfully cleared allowlist from role {}".format(role_name))
        else:
            self.view.print_result("Successfully added allowlist to role {}".format(role_name))
