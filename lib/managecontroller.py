import os
from lib.utils import util
from lib.controllerlib import CommandHelp, BasicCommandController
from lib.client.info import ASProtocolError
from getpass import getpass
from logging import DEBUG


@CommandHelp('"manage" is used to manage users, roles, udf, sindex, and dynamic configs.')
class ManageController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            "acl": ManageACLController,
            "udfs": ManageUdfsController,
            # "sindex": ManageSIndexController,
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
            "create": ManageACLCreateController,
            "delete": ManageACLDeleteController,
            "grant": ManageACLGrantController,
            "revoke": ManageACLRevokeController,
            "set-password": ManageACLSetPasswordUserController,
            "change-password": ManageACLChangePasswordUserController,
            "allowlist": ManageACLAllowListRoleController
        }

    def _do_default(self, line):
        self.execute_help(line)

class ManageACLCreateController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            "user": ManageACLCreateUserController,
            "role": ManageACLCreateRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)

class ManageACLDeleteController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            "user": ManageACLDeleteUserController,
            "role": ManageACLDeleteRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)

class ManageACLGrantController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            "user": ManageACLGrantUserController,
            "role": ManageACLGrantRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)

class ManageACLRevokeController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            "user": ManageACLRevokeUserController,
            "role": ManageACLRevokeRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)

@CommandHelp(
    "create user <username> [password <password>] [roles <role1> <role2> ...]",
    "   username        - Name of new user.",
    "   password        - Password for the new user.  User will be prompted if no",
    "                     password is provided.",
    "   roles           - Roles to be granted to the user. Default: None"
)
class ManageACLCreateUserController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['password', 'roles'])
        self.required_modifiers = set(['line'])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        password = None
        roles = None

        if len(self.mods['password']):
            password = self.mods['password'][0]
        else:
            password = getpass('Enter password for new user {}:'.format(username))

        roles = list(filter(lambda x: x != ',', self.mods['roles']))
        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_create_user(username, password, roles, nodes=[principle_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully created user {}".format(username))

@CommandHelp(
    "delete user <username>",
    "  username           - User to delete.",
)
class ManageACLDeleteUserController(BasicCommandController):

    def __init__(self):
        self.required_modifiers = set(['line'])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        principle_node = self.cluster.get_expected_principal()

        result = self.cluster.admin_delete_user(username, nodes=[principle_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully deleted user {}".format(username))

@CommandHelp(
    "set-password user <username> [password <password>]",
    "  username           - User with no password set.",
    "  password           - Password for the new user.  User will be prompted if no",
    "                       password is provided.",
)
class ManageACLSetPasswordUserController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['password'])
        self.required_modifiers = set(['line'])
        self.controller_map = {}

    def _do_default(self, line):
        username = util.get_arg_and_delete_from_mods(
            line=line,
            arg='user',
            return_type=str,
            default='',
            modifiers=self.required_modifiers,
            mods=self.mods
        )
        password = None

        if len(self.mods['password']):
            password = self.mods['password'][0]
        else:
            password = getpass('Enter password for user {}:'.format(username))

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_set_password(username, password, nodes=[principle_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully set password for user {}".format(username))

@CommandHelp(
    "change-password user <username> [old <old-password>] [new <new-password>]",
    "  username           - User that needs a new password.",
    "  old                - Current password for user.  User will be",
    "                       prompted if no password is provided.",
    "  new                - New password for user.  User will be prompted ",
    "                       if no password is provided.",
)
class ManageACLChangePasswordUserController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['old', 'new'])
        self.required_modifiers = set(['user'])
        self.controller_map = {}

    def _do_default(self, line):
        username = util.get_arg_and_delete_from_mods(
            line=line,
            arg='user',
            return_type=str,
            default='',
            modifiers=self.required_modifiers,
            mods=self.mods
        )
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
        result = self.cluster.admin_change_password(
            username, 
            old_password, 
            new_password, 
            nodes=[principle_node]
        )
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully changed password for user {}".format(username))

@CommandHelp(
    "grant user <username> roles <role1> [<role2> [...]]",
    "  username        - User to have roles added.",
    "  roles           - Roles to be add to user.",
)
class ManageACLGrantUserController(BasicCommandController):

    def __init__(self):
        self.required_modifiers = set(['line', 'roles'])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        roles = list(filter(lambda x: x != ',', self.mods['roles']))
        principle_node = self.cluster.get_expected_principal()

        result = self.cluster.admin_grant_roles(username, roles, nodes=[principle_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully granted roles to user {}".format(username))

@CommandHelp(
    "revoke user <username> roles <role1> [<role2> [...]]",
    "  username        - User to have roles deleted.",
    "  roles           - Roles to delete from user.",
)
class ManageACLRevokeUserController(BasicCommandController):

    def __init__(self):
        self.required_modifiers = set(['line', 'roles'])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        roles = list(filter(lambda x: x != ',', self.mods['roles']))

        principle_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_revoke_roles(username, roles, nodes=[principle_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully revoked roles from user {}".format(username))


@CommandHelp(
    "create role <role-name> priv <privilege> [ns <namespace> [set <set>]]> allow <addr1> [<addr2> [...]]",
    "  role-name     - Name of new role.",
    "  priv          - Privilege for the new role. Some privileges are not", 
    "                  limited to a global scope. Scopes are either global, per", 
    "                  namespace, or per namespace and set. For more ",
    "                  information: ",
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
class ManageACLCreateRoleController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['priv', 'ns', 'set', 'allow'])
        self.required_modifiers = set(['line'])
        self.controller_map = {}

    def _do_default(self, line):
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
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result('Successfully created role {}'.format(role_name))

@CommandHelp(
    "delete role <role-name>",
    "  role-name     - Name of role to delete.",
)
class ManageACLDeleteRoleController(BasicCommandController):

    def __init__(self):
        self.required_modifiers = set(['line'])
        self.controller_map = {}

    def _do_default(self, line):
        role_name = line.pop(0)
        principle_node = self.cluster.get_expected_principal()

        result = self.cluster.admin_delete_role(role_name, nodes=[principle_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully deleted role {}".format(role_name))

@CommandHelp(
    "grant role <role-name> priv <privilege> [ns <namespace> [set <set>]]>",
    "  role-name     - Role to have privilege added.",
    "  priv          - Privilege to be added to role.",
    "  ns            - Namespace scope of privilege.",
    "                  defualt: None",
    "  set           - Set scope of privilege. Namespace scope is required.",
    "                  defualt: None",
)
class ManageACLGrantRoleController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['ns', 'set'])
        self.required_modifiers = set(['line', 'priv'])
        self.controller_map = {}

    def _do_default(self, line):
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
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully granted privilege to role {}".format(role_name))

@CommandHelp(
    "revoke role <role-name> priv <privilege> [ns <namespace> [set <set>]]>",
    "  role-name     - Role to have privilege deleted.",
    "  priv          - Privilege to delete from role.",
    "  ns            - Namespace scope of privilege",
    "                  defualt: None",
    "  set           - Set scope of privilege. Namespace scope is required.",
    "                  defualt: None",
)
class ManageACLRevokeRoleController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['ns', 'set'])
        self.required_modifiers = set(['line', 'priv'])
        self.controller_map = {}

    def _do_default(self, line):
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
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        self.view.print_result("Successfully revoked privilege from role {}".format(role_name))

@CommandHelp(
    "allowlist role <role-name> allow <addr1> [<addr2> [...]]",
    "  role-name     - Role that will have new allowlist.",
    "  allow         - Addresses of nodes that a role will be allowed to connect",
    "                  to. This command erases and re-assigns the allowlist",
    "allowlist role <role-name> clear",
    "  role-name     - Role that will have new allowlist.",
    "  clear         - Clears allowlist from role. Either 'allow' or 'clear' is",
    "                  required.",
)
class ManageACLAllowListRoleController(BasicCommandController):

    def __init__(self):
        self.modifiers = set(['clear', 'allow'])
        self.required_modifiers = set(['role'])
        self.controller_map = {}

    def _do_default(self, line):
        role_name = util.get_arg_and_delete_from_mods(
            line=line,
            arg='role',
            return_type=str,
            default='',
            modifiers=self.required_modifiers,
            mods=self.mods
        )

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
        
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result.message)
            return
        elif isinstance(result, Exception):
            raise result
        
        if clear:
            self.view.print_result("Successfully cleared allowlist from role {}".format(role_name))
        else:
            self.view.print_result("Successfully updated allowlist for role {}".format(role_name))
@CommandHelp('"manage udfs" is used to add and remove user defined functions.')
class ManageUdfsController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            'add': ManageUdfsAddController,
            'remove': ManageUdfsRemoveController,
        }

    # @util.logthis('asadm', DEBUG)
    def _do_default(self, line):
        self.execute_help(line)

@CommandHelp(
    "add <module-name> path <module-path>",
    "  module-name   - Name of module to be stored in the server.  Can be different",
    "                  from file in path but must end with an extension.",
    "  path          - Path to the udf module.  Can be either absolute or relative",
    "                  to the current working directory.",
)
class ManageUdfsAddController(BasicCommandController):
    def __init__(self):
        self.required_modifiers = set(['line', 'path'])

    def _do_default(self, line):
        udf_name = line.pop(0)
        udf_path = self.mods['path'][0]

        if not os.path.isfile(udf_path):
            udf_path = os.path.join(os.getcwd(), udf_path)

        if not os.path.isfile(udf_path):
            self.logger.error('Failed to add UDF {}: Path does not exist'.format(udf_name))
            return

        with open(udf_path) as udf_file:
            udf_str = udf_file.read()

        principle_node = self.cluster.get_expected_principal()

        resp = self.cluster.info_udf_put(udf_name, udf_str, nodes=[principle_node])
        resp = list(resp.values())[0]

        if isinstance(resp, Exception):
            raise resp
        
        if resp != 'ok':
            self.logger.error('Failed to add UDF: {}'.format(resp))
            return

        self.view.print_result("Successfully added UDF {}".format(udf_name))

@CommandHelp(
    "remove <module-name>",
    "  module-name   - Name of module stored in the server that should be removed.",
)
class ManageUdfsRemoveController(BasicCommandController):
    def __init__(self):
        self.required_modifiers = set(['line'])

    def _do_default(self, line):
        udf_name = line.pop(0)
        principal_node = self.cluster.get_expected_principal()

        # Get names of existing udfs
        existing_udfs = self.cluster.info_udf_list(nodes=[principal_node])
        existing_udfs = list(existing_udfs.values())[0]
        existing_names = existing_udfs.keys()

        if udf_name not in existing_names:
            self.logger.error('Failed to remove UDF {}: UDF does not exist'.format(udf_name))
            return

        resp = self.cluster.info_udf_remove(udf_name, nodes=[principal_node])
        resp = list(resp.values())[0]

        if isinstance(resp, Exception):
            raise resp

        if resp != 'ok':
            self.logger.error('Failed to remove UDF: {}'.format(resp))
            return

        self.view.print_result("Successfully removed UDF {}".format(udf_name))
        
            
