from datetime import datetime
from lib.view import terminal
import os
from lib.utils import util
from lib.controllerlib import CommandHelp, BasicCommandController
from lib.client.info import ASProtocolError
from getpass import getpass
from logging import DEBUG

class ManageLeafCommandController(BasicCommandController):
    warn = False

    def prompt_challenge(self, message=''):
        challenge = hex(hash(datetime.now()))[2:8]
        
        if message :
            self.view.print_result(message)

        self.view.print_result(
                        "Confirm that you want to proceed by typing ".format(message) + 
                        terminal.bold() + challenge + terminal.unbold() + 
                        ", or anything else to cancel."
        )
        user_input = input()
        user_input = user_input.strip()

        if challenge != user_input:
            return False

        return True

@CommandHelp('"manage" is used to manage users, roles, udf, sindex, and dynamic configs.')
class ManageController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            "acl": ManageACLController,
            "udfs": ManageUdfsController,
            "sindex": ManageSIndexController,
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
class ManageACLCreateUserController(ManageLeafCommandController):

    def __init__(self):
        self.modifiers = set(['password', 'roles'])
        self.required_modifiers = set(['line'])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        password = None
        roles = None
        warn = None # TODO

        if len(self.mods['password']):
            password = self.mods['password'][0]
        else:
            password = getpass('Enter password for new user {}:'.format(username))

        if warn and not self.prompt_challenge(self.view, ''):
                return

        roles = list(filter(lambda x: x != ',', self.mods['roles']))

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_create_user(username, password, roles, nodes=[principal_node])
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
class ManageACLDeleteUserController(ManageLeafCommandController):

    def __init__(self):
        self.required_modifiers = set(['line'])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        principal_node = self.cluster.get_expected_principal()

        if self.warn and not self.prompt_challenge():
            return

        result = self.cluster.admin_delete_user(username, nodes=[principal_node])
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
class ManageACLSetPasswordUserController(ManageLeafCommandController):

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

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_set_password(username, password, nodes=[principal_node])
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
class ManageACLChangePasswordUserController(ManageLeafCommandController):

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

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_change_password(
            username, 
            old_password, 
            new_password, 
            nodes=[principal_node]
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
class ManageACLGrantUserController(ManageLeafCommandController):

    def __init__(self):
        self.required_modifiers = set(['line', 'roles'])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        roles = list(filter(lambda x: x != ',', self.mods['roles']))
        principal_node = self.cluster.get_expected_principal()

        if self.warn and not self.prompt_challenge():
            return

        result = self.cluster.admin_grant_roles(username, roles, nodes=[principal_node])
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
class ManageACLRevokeUserController(ManageLeafCommandController):

    def __init__(self):
        self.required_modifiers = set(['line', 'roles'])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        roles = list(filter(lambda x: x != ',', self.mods['roles']))

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_revoke_roles(username, roles, nodes=[principal_node])
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
class ManageACLCreateRoleController(ManageLeafCommandController):

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

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_create_role(
            role_name, 
            privileges=privilege, 
            whitelist=allowlist, 
            nodes=[principal_node]
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
class ManageACLDeleteRoleController(ManageLeafCommandController):

    def __init__(self):
        self.required_modifiers = set(['line'])
        self.controller_map = {}

    def _do_default(self, line):
        role_name = line.pop(0)
        principal_node = self.cluster.get_expected_principal()

        if self.warn and not self.prompt_challenge():
                    return

        result = self.cluster.admin_delete_role(role_name, nodes=[principal_node])
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
class ManageACLGrantRoleController(ManageLeafCommandController):

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

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_add_privileges(role_name, [privilege], nodes=[principal_node])
        result = list(result.values())[0]

        if self.warn and not self.prompt_challenge():
            return

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
class ManageACLRevokeRoleController(ManageLeafCommandController):

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

        if self.warn and not self.prompt_challenge():
            return
        
        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_delete_privileges(role_name, [privilege], nodes=[principal_node])
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
class ManageACLAllowListRoleController(ManageLeafCommandController):

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

        if self.warn and not self.prompt_challenge():
            return

        result = None
        principal_node = self.cluster.get_expected_principal()

        if clear:
            result = self.cluster.admin_delete_whitelist(role_name, nodes=[principal_node])
        else:
            result = self.cluster.admin_set_whitelist(role_name, allowlist, nodes=[principal_node])
        
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
class ManageUdfsAddController(ManageLeafCommandController):
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

        principal_node = self.cluster.get_expected_principal()

        if self.warn:
            existing_udfs = self.cluster.info_udf_list(nodes=[principal_node])
            existing_udfs = list(existing_udfs.values())[0]
            existing_names = existing_udfs.keys()

            if (udf_name in existing_names and
                not self.prompt_challenge("You are about to write over an existing UDF module.")):
                    return

        resp = self.cluster.info_udf_put(udf_name, udf_str, nodes=[principal_node])
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
class ManageUdfsRemoveController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(['line'])

    def _do_default(self, line):
        udf_name = line.pop(0)
        principal_node = self.cluster.get_expected_principal()

        # Get names of existing udfs
        existing_udfs = self.cluster.info_udf_list(nodes=[principal_node])
        existing_udfs = list(existing_udfs.values())[0]
        existing_names = existing_udfs.keys()

        # The server does not check this as of 5.3 and will return success even
        # if it does not exist.
        if udf_name not in existing_names:
            self.logger.error('Failed to remove UDF {}: UDF does not exist'.format(udf_name))
            return

        if (self.warn and
            not self.prompt_challenge("You are about to remove a UDF module that may be in use.")):
                return

        resp = self.cluster.info_udf_remove(udf_name, nodes=[principal_node])
        resp = list(resp.values())[0]

        if isinstance(resp, Exception):
            raise resp

        if resp != 'ok':
            self.logger.error('Failed to remove UDF: {}'.format(resp))
            return

        self.view.print_result("Successfully removed UDF {}".format(udf_name))


@CommandHelp('"manage udfs" is used to add and remove user defined functions.')
class ManageSIndexController(BasicCommandController):
    def __init__(self):
        self.controller_map = {
            'create': ManageSIndexCreateController,
            'delete': ManageSIndexDeleteController,
        }

    def _do_default(self, line):
        self.execute_help(line)
            
@CommandHelp('"manage udfs" is used to add and remove user defined functions.')
class ManageSIndexCreateController(ManageLeafCommandController):
    
    def __init__(self):
        self.required_modifiers = set(['line', 'ns', 'bin'])
        self.modifiers = set(['set', 'in'])

    def _do_default(self, line):
        self.execute_help(line)

    def _do_create(self, line, bin_type):
        index_name = line.pop(0)
        namespace = util.get_arg_and_delete_from_mods(
            line=line,
            arg='ns',
            return_type=str,
            default='',
            modifiers=self.required_modifiers,
            mods=self.mods
        )
        set_ = util.get_arg_and_delete_from_mods(
            line=line,
            arg='set',
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods
        )
        bin_name = util.get_arg_and_delete_from_mods(
            line=line,
            arg='bin',
            return_type=str,
            default='',
            modifiers=self.required_modifiers,
            mods=self.mods
        )
        index_type = util.get_arg_and_delete_from_mods(
            line=line,
            arg='in',
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods
        )

        index_type = index_type.lower() if index_type else None
        bin_type = bin_type.lower()

        if (self.warn and 
            not self.prompt_challenge('Adding a secondary index will cause longer restart times.')):
                return

        principal_node = self.cluster.get_expected_principal()
        resp = self.cluster.info_sindex_create(index_name, namespace, bin_name, bin_type, index_type, set_, nodes=[principal_node])
        resp = list(resp.values())[0]

        if resp != 'ok':
            self.logger.error("Failed to create sindex {} : {}".format(index_name, resp))
            return

        self.view.print_result("Successfully created sindex {}".format(index_name))

    
    # Hack for auto-complete 
    def do_numeric(self, line):
        self._do_create(line, 'numeric')

    # Hack for auto-complete 
    def do_string(self, line):
        self._do_create(line, 'string')

    # Hack for auto-complete 
    def do_geo2dsphere(self, line):
        self._do_create(line, 'geo2dsphere')

@CommandHelp('"manage udfs" is used to add and remove user defined functions.')
class ManageSIndexDeleteController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(['line', 'ns'])
        self.modifiers = set(['set'])

    def _do_default(self, line):
        index_name = line.pop(0)
        namespace = util.get_arg_and_delete_from_mods(
            line=line,
            arg='ns',
            return_type=str,
            default='',
            modifiers=self.required_modifiers,
            mods=self.mods
        )
        set_ = util.get_arg_and_delete_from_mods(
            line=line,
            arg='set',
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods
        )

        principal_node = self.cluster.get_expected_principal()

        if self.warn:
            sindex_data = self.cluster.info_sindex_statistics(namespace, index_name, nodes=[principal_node])
            sindex_data = list(sindex_data.values())[0]
            num_keys = sindex_data.get('keys', 0)

            if not self.prompt_challenge('The secondary index {} has {} keys indexed.'.format(index_name, num_keys)):
                return

        resp = self.cluster.info_sindex_delete(index_name, namespace, set_, nodes=[principal_node])
        resp = list(resp.values())[0]

        if resp != 'ok':
            self.logger.error("Failed to delete sindex {} : {}".format(index_name, resp))
            return

        self.view.print_result("Successfully deleted sindex {}".format(index_name))