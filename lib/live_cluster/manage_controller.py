import os
import logging
from datetime import datetime
from dateutil import parser as date_parser
from getpass import getpass
from functools import reduce
from concurrent.futures import ThreadPoolExecutor

from lib.view import terminal
from lib.utils import constants, util, version
from lib.base_controller import CommandHelp
from lib.get_controller import GetConfigController
from lib.utils.lookup_dict import PrefixDict
from .client import (
    ASInfoClusterStableError,
    ASInfoError,
    ASProtocolError,
    BoolConfigType,
    EnumConfigType,
    StringConfigType,
    IntConfigType,
)
from .live_cluster_command_controller import LiveClusterCommandController
from lib.get_controller import GetJobsController

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


class ManageLeafCommandController(LiveClusterCommandController):
    warn = False

    def prompt_challenge(self, message=""):
        challenge = hex(hash(datetime.now()))[2:8]

        if message:
            self.view.print_result(message)

        self.view.print_result(
            "Confirm that you want to proceed by typing "
            + terminal.bold()
            + challenge
            + terminal.unbold()
            + ", or cancel by typing anything else."
        )
        user_input = input()
        user_input = user_input.strip()

        if challenge != user_input:
            return False

        return True


@CommandHelp(
    '"manage" is used for administrative tasks like managing users, roles, udf, and',
    'sindexes. It should be used in conjunction with the "show users" and "show roles"',
    "command.",
)
class ManageController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "jobs": ManageJobsController,
            "recluster": ManageReclusterController,
            "quiesce": ManageQuiesceController,
            "revive": ManageReviveController,
            "roster": ManageRosterController,
            "truncate": ManageTruncateController,
            "udfs": ManageUdfsController,
            "sindex": ManageSIndexController,
            "config": ManageConfigController,
            "acl": ManageACLController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp('"manage acl" is used to manage users and roles.')
class ManageACLController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "create": ManageACLCreateController,
            "delete": ManageACLDeleteController,
            "grant": ManageACLGrantController,
            "revoke": ManageACLRevokeController,
            "set-password": ManageACLSetPasswordUserController,
            "change-password": ManageACLChangePasswordUserController,
            "allowlist": ManageACLAllowListRoleController,
            "quotas": ManageACLQuotasRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp("")
class ManageACLCreateController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "user": ManageACLCreateUserController,
            "role": ManageACLCreateRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp("")
class ManageACLDeleteController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "user": ManageACLDeleteUserController,
            "role": ManageACLDeleteRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp("")
class ManageACLGrantController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "user": ManageACLGrantUserController,
            "role": ManageACLGrantRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp("")
class ManageACLRevokeController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "user": ManageACLRevokeUserController,
            "role": ManageACLRevokeRoleController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    "Usage: create user <username> [password <password>] [roles <role1> <role2> ...]",
    "   username        - Name of the new user.",
    "   password        - Password for the new user. User will be prompted if no",
    "                     password is provided.",
    "   roles           - Roles to be granted to the user.",
    "                     [default: None]",
)
class ManageACLCreateUserController(ManageLeafCommandController):
    def __init__(self):
        self.modifiers = set(["password", "roles"])
        self.required_modifiers = set(["line"])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        password = None
        roles = None

        password = util.get_arg_and_delete_from_mods(
            line,
            arg="password",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        if password is None:
            password = getpass("Enter password for new user {}:".format(username))

        roles = self.mods["roles"]

        # Accept "role" instead of "roles", If another modifier is added the logic may
        #  need to change.
        if len(roles) == 0 and len(line) != 0 and line[0] == "role":
            line.pop(0)
            roles = line

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_create_user(
            username, password, roles, nodes=[principal_node]
        )
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result("Successfully created user {}.".format(username))


@CommandHelp(
    "Usage: delete user <username>",
    "  username           - User to delete.",
)
class ManageACLDeleteUserController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(["line"])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        principal_node = self.cluster.get_expected_principal()

        if self.warn and not self.prompt_challenge():
            return

        result = self.cluster.admin_delete_user(username, nodes=[principal_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result("Successfully deleted user {}.".format(username))


@CommandHelp(
    "Usage: set-password user <username> [password <password>]",
    "  username           - User to have password set.",
    "  password           - Password for the user.  A prompt will appear if no",
    "                       password is provided.",
)
class ManageACLSetPasswordUserController(ManageLeafCommandController):
    def __init__(self):
        self.modifiers = set(["password"])
        self.required_modifiers = set(["line"])
        self.controller_map = {}

    def _do_default(self, line):
        username = util.get_arg_and_delete_from_mods(
            line=line,
            arg="user",
            return_type=str,
            default="",
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        password = None

        if len(self.mods["password"]):
            password = self.mods["password"][0]
        else:
            password = getpass("Enter new password for user {}:".format(username))

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_set_password(
            username, password, nodes=[principal_node]
        )
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result(
            "Successfully set password for user {}.".format(username)
        )


@CommandHelp(
    "Usage: change-password user <username> [old <old-password>] [new <new-password>]",
    "  username           - User that needs a new password.",
    "  old                - Current password for the user. User will be",
    "                       prompted if no password is provided.",
    "  new                - New password for the user. User will be prompted ",
    "                       if no password is provided.",
)
class ManageACLChangePasswordUserController(ManageLeafCommandController):
    def __init__(self):
        self.modifiers = set(["old", "new"])
        self.required_modifiers = set(["user"])
        self.controller_map = {}

    def _do_default(self, line):
        username = util.get_arg_and_delete_from_mods(
            line=line,
            arg="user",
            return_type=str,
            default="",
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        old_password = None
        new_password = None

        if len(self.mods["old"]):
            old_password = self.mods["old"][0]
        else:
            old_password = getpass("Enter old password:")

        if len(self.mods["new"]):
            new_password = self.mods["new"][0]
        else:
            new_password = getpass("Enter new password:")

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_change_password(
            username, old_password, new_password, nodes=[principal_node]
        )
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result(
            "Successfully changed password for user {}.".format(username)
        )


@CommandHelp(
    "Usage: grant user <username> roles <role1> [<role2> [...]]",
    "  username        - User to have roles granted.",
    "  roles           - Roles to add to the user.",
)
class ManageACLGrantUserController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(["line", "roles"])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        roles = self.mods["roles"]
        principal_node = self.cluster.get_expected_principal()

        if self.warn and not self.prompt_challenge():
            return

        result = self.cluster.admin_grant_roles(username, roles, nodes=[principal_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result(
            "Successfully granted roles to user {}.".format(username)
        )


@CommandHelp(
    "Usage: revoke user <username> roles <role1> [<role2> [...]]",
    "  username        - User to have roles revoked.",
    "  roles           - Roles to delete from the user.",
)
class ManageACLRevokeUserController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(["line", "roles"])
        self.controller_map = {}

    def _do_default(self, line):
        username = line.pop(0)
        roles = self.mods["roles"]

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_revoke_roles(
            username, roles, nodes=[principal_node]
        )
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result(
            "Successfully revoked roles from user {}.".format(username)
        )


class ManageACLRolesLeafCommandController(ManageLeafCommandController):
    def _supports_quotas(self, nodes):
        build_resp = self.cluster.info_build(nodes=nodes)
        build = list(build_resp.values())[0]

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_QUOTAS_FIRST_VERSION
        ):
            return False

        return True


@CommandHelp(
    "Usage: create role <role-name> priv <privilege> [ns <namespace> [set <set>]] [allow <addr1> [<addr2> [...]]] [read <read-quota>] [write <write-quota>]",
    "  role-name     - Name of the new role.",
    "  priv          - Privilege for the new role. Some privileges are not",
    "                  limited to a global scope. Scopes are either global, per",
    "                  namespace, or per namespace and set.",
    "                  [default: None]",
    "  ns            - Namespace scope of privilege.",
    "                  [default: None]",
    "  set           - Set scope of privilege. Namespace scope is required.",
    "                  [default: None]",
    "  allow         - Addresses of nodes that a role will be allowed to connect",
    "                  to a cluster from.",
    "                  [default: None]",
    "  read          - Quota for read transaction (TPS).",
    "  write         - Quota for write transaction (TPS).",
)
class ManageACLCreateRoleController(ManageACLRolesLeafCommandController):
    def __init__(self):
        self.modifiers = set(["ns", "set", "allow", "read", "write"])
        self.required_modifiers = set(["line", "priv"])
        self.controller_map = {}

    # Overridden because of conflict between 'read' privilege and 'read' modifier
    # causes 'priv read' or 'priv write' to parse incorrectly
    def parse_modifiers(self, line, duplicates_in_line_allowed=False):
        line_copy = line[:]
        groups = super().parse_modifiers(
            line, duplicates_in_line_allowed=duplicates_in_line_allowed
        )

        if len(groups["priv"]) == 0 and "priv" in line_copy:
            priv_index = line_copy.index("priv") + 1

            if len(line_copy) > priv_index and line_copy[priv_index] in {
                "read",
                "write",
            }:
                groups["priv"].append(line_copy[priv_index])

        return groups

    def _do_default(self, line):
        role_name = line.pop(0)
        privilege = None
        allowlist = self.mods["allow"]
        principal_node = self.cluster.get_expected_principal()

        # Can't use util.get_arg_and_delete_from_mods because of conflict
        # between read modifier and read privilege
        read_quota = self.mods["read"][0] if len(self.mods["read"]) else None
        write_quota = self.mods["write"][0] if len(self.mods["write"]) else None

        if read_quota is not None or write_quota is not None:
            if not self._supports_quotas([principal_node]):
                self.logger.warning(
                    "'read' and 'write' modifiers are not supported on aerospike versions <= 5.5"
                )

        try:
            if read_quota is not None:
                read_quota = int(read_quota)
            if write_quota is not None:
                write_quota = int(write_quota)
        except ValueError:
            self.logger.error("Quotas must be integers.")
            return

        if len(self.mods["priv"]):
            privilege = self.mods["priv"][0]

        if len(self.mods["set"]) and not len(self.mods["ns"]):
            self.logger.error("A set must be accompanied by a namespace.")
            return

        if len(self.mods["ns"]):
            privilege += "." + self.mods["ns"][0]

            if len(self.mods["set"]):
                privilege += "." + self.mods["set"][0]

        # admin_create_role expects a list of privileges but the UI excepts one.
        privilege = [] if privilege is None else [privilege]

        if self.warn and not self.prompt_challenge():
            return

        result = self.cluster.admin_create_role(
            role_name,
            privileges=privilege,
            whitelist=allowlist,
            read_quota=read_quota,
            write_quota=write_quota,
            nodes=[principal_node],
        )
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result("Successfully created role {}.".format(role_name))


@CommandHelp(
    "Usage: delete role <role-name>",
    "  role-name     - Role to delete.",
)
class ManageACLDeleteRoleController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(["line"])
        self.controller_map = {}

    def _do_default(self, line):
        role_name = line.pop(0)

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_delete_role(role_name, nodes=[principal_node])
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result("Successfully deleted role {}.".format(role_name))


@CommandHelp(
    "Usage: grant role <role-name> priv <privilege> [ns <namespace> [set <set>]]>",
    "  role-name     - Role to have the privilege granted.",
    "  priv          - Privilege to be added to the role.",
    "  ns            - Namespace scope of privilege.",
    "                  [default: None]",
    "  set           - Set scope of privilege. Namespace scope is required.",
    "                  [default: None]",
)
class ManageACLGrantRoleController(ManageLeafCommandController):
    def __init__(self):
        self.modifiers = set(["ns", "set"])
        self.required_modifiers = set(["line", "priv"])
        self.controller_map = {}

    def _do_default(self, line):
        role_name = line.pop(0)
        privilege = self.mods["priv"][0]

        if len(self.mods["set"]) and not len(self.mods["ns"]):
            self.execute_help(line)
            self.logger.error("A set must be accompanied by a namespace.")
            return

        if len(self.mods["ns"]):
            privilege += "." + self.mods["ns"][0]

            if len(self.mods["set"]):
                privilege += "." + self.mods["set"][0]

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_add_privileges(
            role_name, [privilege], nodes=[principal_node]
        )
        result = list(result.values())[0]

        if self.warn and not self.prompt_challenge():
            return

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result(
            "Successfully granted privilege to role {}.".format(role_name)
        )


@CommandHelp(
    "Usage: revoke role <role-name> priv <privilege> [ns <namespace> [set <set>]]>",
    "  role-name     - Role to have privilege revoked.",
    "  priv          - Privilege to delete from the role.",
    "  ns            - Namespace scope of privilege",
    "                  [default: None]",
    "  set           - Set scope of privilege. Namespace scope is required.",
    "                  [default: None]",
)
class ManageACLRevokeRoleController(ManageLeafCommandController):
    def __init__(self):
        self.modifiers = set(["ns", "set"])
        self.required_modifiers = set(["line", "priv"])
        self.controller_map = {}

    def _do_default(self, line):
        role_name = line.pop(0)
        privilege = self.mods["priv"][0]

        if len(self.mods["set"]) and not len(self.mods["ns"]):
            self.execute_help(line)
            self.logger.error("A set must be accompanied by a namespace")
            return

        if len(self.mods["ns"]):
            privilege += "." + self.mods["ns"][0]

            if len(self.mods["set"]):
                privilege += "." + self.mods["set"][0]

        if self.warn and not self.prompt_challenge():
            return

        principal_node = self.cluster.get_expected_principal()
        result = self.cluster.admin_delete_privileges(
            role_name, [privilege], nodes=[principal_node]
        )
        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result(
            "Successfully revoked privilege from role {}.".format(role_name)
        )


@CommandHelp(
    "Usage: allowlist role <role-name> allow <addr1> [<addr2> [...]]",
    "  role-name     - Role that will have the new allowlist.",
    "  allow         - Addresses of nodes that a role will be allowed to connect",
    "                  from. This command erases and re-assigns the allowlist",
    "Usage: allowlist role <role-name> clear",
    "  role-name     - Role that will have the allowlist cleared.",
    "  clear         - Clears allowlist from the role. Either 'allow' or 'clear' is",
    "                  required.",
)
class ManageACLAllowListRoleController(ManageLeafCommandController):
    def __init__(self):
        self.modifiers = set(["clear", "allow"])
        self.required_modifiers = set(["role"])

    def _do_default(self, line):
        role_name = util.get_arg_and_delete_from_mods(
            line=line,
            arg="role",
            return_type=str,
            default="",
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        clear = util.check_arg_and_delete_from_mods(
            line=line,
            arg="clear",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        allowlist = self.mods["allow"]

        if not clear and not len(allowlist):
            self.execute_help(line)
            self.logger.error("Allowlist or clear is required.")
            return

        if self.warn and not self.prompt_challenge():
            return

        result = None
        principal_node = self.cluster.get_expected_principal()

        if clear:
            result = self.cluster.admin_delete_whitelist(
                role_name, nodes=[principal_node]
            )
        else:
            result = self.cluster.admin_set_whitelist(
                role_name, allowlist, nodes=[principal_node]
            )

        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        if clear:
            self.view.print_result(
                "Successfully cleared allowlist from role {}.".format(role_name)
            )
        else:
            self.view.print_result(
                "Successfully updated allowlist for role {}.".format(role_name)
            )


@CommandHelp(
    "Usage: quotas role <role-name> [read <read-quota>]|[write <write-quota>]",
    "  role-name     - Role to assign a quota",
    "  read          - Quota for read transaction (TPS). To give a role",
    "                  an unlimited quota enter 0",
    "  write         - Quota for write transaction (TPS).",
    "  Note: A read or write quota is required. Not providing a quota will",
    "        leave it unchanged.",
)
class ManageACLQuotasRoleController(ManageACLRolesLeafCommandController):
    def __init__(self):
        self.modifiers = set(["write", "read"])
        self.required_modifiers = set(["role"])

    # Overridden because of conflict between 'read' role and 'read' modifier
    # causes 'role read' or 'role write' to parse incorrectly
    def parse_modifiers(self, line, duplicates_in_line_allowed=False):
        line_copy = line[:]
        groups = super().parse_modifiers(
            line, duplicates_in_line_allowed=duplicates_in_line_allowed
        )

        if len(groups["role"]) == 0 and "role" in line_copy:
            role_index = line_copy.index("role") + 1

            if len(line_copy) > role_index and line_copy[role_index] in {
                "read",
                "write",
            }:
                groups["role"].append(line_copy[role_index])

        return groups

    def _do_default(self, line):
        principal_node = self.cluster.get_expected_principal()

        if not self._supports_quotas([principal_node]):
            self.logger.error(
                "'manage quotas' is not supported on aerospike versions <= 5.5"
            )
            return

        role = util.get_arg_and_delete_from_mods(
            line=line,
            arg="role",
            return_type=str,
            default="",
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        read_quota = util.get_arg_and_delete_from_mods(
            line=line,
            arg="read",
            default=None,
            return_type=str,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        write_quota = util.get_arg_and_delete_from_mods(
            line=line,
            arg="write",
            default=None,
            return_type=str,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        if read_quota is None and write_quota is None:
            self.logger.error("'read' or 'write' is required.")
            return

        try:
            if read_quota is not None:
                read_quota = int(read_quota)
            if write_quota is not None:
                write_quota = int(write_quota)
        except ValueError:
            self.logger.error("Quotas must be integers.")
            return

        if self.warn and not self.prompt_challenge():
            return

        result = self.cluster.admin_set_quotas(
            role, read_quota=read_quota, write_quota=write_quota, nodes=[principal_node]
        )

        result = list(result.values())[0]

        if isinstance(result, ASProtocolError):
            self.logger.error(result)
            return
        elif isinstance(result, Exception):
            raise result

        self.view.print_result(
            "Successfully set quota{} for role {}.".format(
                "s" if read_quota is not None and write_quota is not None else "", role
            )
        )


@CommandHelp(
    '"manage udfs" is used to add and remove user defined functions. It should be used',
    'in conjunction with the "show udfs" command.',
)
class ManageUdfsController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "add": ManageUdfsAddController,
            "remove": ManageUdfsRemoveController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    "Usage: add <module-name> path <module-path>",
    "  module-name   - Name of module to be stored in the server.  Can be different",
    "                  from file in path but must end with an extension.",
    "  path          - Path to the udf module.  Can be either absolute or relative",
    "                  to the current working directory.",
)
class ManageUdfsAddController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(["line", "path"])

    def _do_default(self, line):
        udf_name = line.pop(0)
        udf_path = self.mods["path"][0]

        if not os.path.isfile(udf_path):
            udf_path = os.path.join(os.getcwd(), udf_path)

        if not os.path.isfile(udf_path):
            self.logger.error(
                "Failed to add UDF {}: Path does not exist.".format(udf_name)
            )
            return

        with open(udf_path) as udf_file:
            udf_str = udf_file.read()

        principal_node = self.cluster.get_expected_principal()

        if self.warn:
            existing_udfs = self.cluster.info_udf_list(nodes=[principal_node])
            existing_udfs = list(existing_udfs.values())[0]
            existing_names = existing_udfs.keys()

            if udf_name in existing_names and not self.prompt_challenge(
                "You're about to write over an existing UDF module."
            ):
                return

        resp = self.cluster.info_udf_put(udf_name, udf_str, nodes=[principal_node])
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Successfully added UDF {}.".format(udf_name))


@CommandHelp(
    "Usage: remove <module-name>",
    "  module-name   - Name of module to remove as stored in the server.",
)
class ManageUdfsRemoveController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(["line"])

    def _do_default(self, line):
        udf_name = line.pop(0)

        if self.warn and not self.prompt_challenge(
            "You're about to remove a UDF module that may be in use."
        ):
            return

        principal_node = self.cluster.get_expected_principal()
        resp = self.cluster.info_udf_remove(udf_name, nodes=[principal_node])
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Successfully removed UDF {}.".format(udf_name))


@CommandHelp(
    '"manage sindex" is used to create and delete secondary indexes. It should be used',
    'in conjunction with the "show sindex" or "info sindex" command.',
)
class ManageSIndexController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "create": ManageSIndexCreateController,
            "delete": ManageSIndexDeleteController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    "Usage: create <bin-type> <index-name> ns <ns> [set <set>] bin <bin-name> [in <index-type>]",
    "  bin-type    - The bin type of the provided <bin-name>. Should be one of the following values:",
    "                  numeric, string, or geo2dsphere",
    "  index-name    - Name of the secondary index to be created. Should be 20 characters",
    '                  or less and not contain ":" or ";".',
    "  ns            - Name of namespace to create the secondary index on.",
    "  set           - Name of set to create the secondary index on.",
    "  bin           - Name of bin to create secondary index on.",
    "  in            - Specifies how the secondary index is to collect keys:",
    "                  list: Specifies to use the elements of a list as keys.",
    "                  mapkeys: Specifies to use the keys of a map as keys.",
    "                  mapvalues: Specifies to use the values of a map as keys.",
    "                  [default: Specifies to use the contents of a bin as keys.]",
)
class ManageSIndexCreateController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(["line", "ns", "bin"])
        self.modifiers = set(["set", "in"])

    def _do_default(self, line):
        self.execute_help(line)

    def _do_create(self, line, bin_type):
        index_name = line.pop(0)
        namespace = util.get_arg_and_delete_from_mods(
            line=line,
            arg="ns",
            return_type=str,
            default="",
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        set_ = util.get_arg_and_delete_from_mods(
            line=line,
            arg="set",
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        bin_name = util.get_arg_and_delete_from_mods(
            line=line,
            arg="bin",
            return_type=str,
            default="",
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        index_type = util.get_arg_and_delete_from_mods(
            line=line,
            arg="in",
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        index_type = index_type.lower() if index_type else None
        bin_type = bin_type.lower()

        if self.warn and not self.prompt_challenge(
            "Adding a secondary index will cause longer restart times."
        ):
            return

        principal_node = self.cluster.get_expected_principal()
        resp = self.cluster.info_sindex_create(
            index_name,
            namespace,
            bin_name,
            bin_type,
            index_type,
            set_,
            nodes=[principal_node],
        )
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Successfully created sindex {}.".format(index_name))

    # Hack for auto-complete
    def do_numeric(self, line):
        self._do_create(line, "numeric")

    # Hack for auto-complete
    def do_string(self, line):
        self._do_create(line, "string")

    # Hack for auto-complete
    def do_geo2dsphere(self, line):
        self._do_create(line, "geo2dsphere")


@CommandHelp(
    "Usage: delete <index-name> ns <ns> [set <set>]",
    "  index-name    - Name of the secondary index to be deleted.",
    "  ns            - Namespace where the sindex resides.",
    "  set           - Set where the sindex resides.",
)
class ManageSIndexDeleteController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = set(["line", "ns"])
        self.modifiers = set(["set"])

    def _do_default(self, line):
        index_name = line.pop(0)
        namespace = util.get_arg_and_delete_from_mods(
            line=line,
            arg="ns",
            return_type=str,
            default="",
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        set_ = util.get_arg_and_delete_from_mods(
            line=line,
            arg="set",
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        principal_node = self.cluster.get_expected_principal()

        if self.warn:
            sindex_data = self.cluster.info_sindex_statistics(
                namespace, index_name, nodes=[principal_node]
            )
            sindex_data = list(sindex_data.values())[0]
            num_keys = sindex_data.get("keys", 0)

            if not self.prompt_challenge(
                "The secondary index {} has {} keys indexed.".format(
                    index_name, num_keys
                )
            ):
                return

        resp = self.cluster.info_sindex_delete(
            index_name, namespace, set_, nodes=[principal_node]
        )
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Successfully deleted sindex {}.".format(index_name))


class ManageConfigLeafController(ManageLeafCommandController):
    PARAM = "param"
    TO = "to"

    def extract_param_value(self, line):
        param = util.get_arg_and_delete_from_mods(
            line=line,
            arg=self.PARAM,
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        value = util.get_arg_and_delete_from_mods(
            line=line,
            arg=self.TO,
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        return param, value

    def _complete_subcontext(self, contexts):
        subcontexts = None
        current_context = []
        possible_completions = []
        to_complete = ""

        for context in contexts:
            current_context.append(context)

            if subcontexts is not None:

                # If context is not valid subcontext then it is probably a prefix
                if context not in subcontexts:
                    logger.debug(
                        "ManageConfigLeafController: Possible completions for %s: %s",
                        context,
                        subcontexts,
                    )
                    possible_completions = subcontexts
                    to_complete = context
                    break

            subcontexts = self.cluster.config_subcontext(current_context[:])

            subcontexts = reduce(
                lambda x, y: list(set(x) | set(y)), subcontexts.values()
            )

            # Remove subcontext without dynamic config params
            for subcontext in subcontexts[:]:
                subcontext_params = self.cluster.config_params(
                    current_context + [subcontext]
                )

                intersection = reduce(
                    lambda x, y: list(set(x) | set(y)),
                    subcontext_params.values(),
                )

                if len(intersection) == 0:
                    subcontexts.remove(subcontext)

            possible_completions = subcontexts

            logger.debug(
                "ManageConfigLeafController: Possible sub-contexts %s",
                possible_completions,
            )

        return to_complete, possible_completions

    def _complete_params(self, contexts):
        cluster_params = self.cluster.config_params(contexts)
        intersection = reduce(
            lambda x, y: list(set(x) | set(y)), cluster_params.values()
        )

        logger.debug(
            "ManageConfigLeafController: Possible params {}".format(intersection)
        )

        return intersection

    def _complete_values(self, contexts, param):
        config_type = self.cluster.config_type(contexts, param)
        possible_completions = []

        if config_type:
            config_type = list(config_type.values())[0]

            if config_type.dynamic:
                if isinstance(config_type, EnumConfigType):
                    possible_completions = config_type.enum
                elif isinstance(config_type, BoolConfigType):
                    possible_completions = ["true", "false"]
                elif isinstance(config_type, IntConfigType):
                    possible_completions = ["<int>"]
                elif isinstance(config_type, StringConfigType):
                    possible_completions = ["<string>"]

        logger.debug(
            "ManageConfigLeafController: Possible value {}".format(possible_completions)
        )

        return possible_completions

    def complete(self, line):
        logger.debug(
            "ManageConfigLeafController: Complete context {} and line {}".format(
                self.context, line
            )
        )

        # They typed a top level context with no space.
        if len(line) == 0:
            return [self.context[-1]]

        # They type a modifier with no space.
        if line[-1] in {self.PARAM, self.TO}:
            return [line[-1]]

        self._init()
        contexts = self.context[:]
        arg = None

        # hack to remove unwanted contexts
        contexts.remove("manage")
        contexts.remove("config")

        if self.controller_arg is not None:
            arg = line.pop(0)

            # They likely forgot to type argument after the cmd. i.e
            # manage config namespace <NS> <---- forgot <NS>
            if arg in self.required_modifiers | self.modifiers | {
                self.controller_arg,
            }:
                return []

            # Give hint like namespace <NS>
            if arg == "":
                return ["<{}>".format(self.controller_arg)]

            # They are still typing the name of the namespace, set, etc.
            if len(line) == 0:
                return []

        if len(line) != 0 and line[0] in self.controller_map:
            logger.debug(
                "ManageConfigLeafController: Found context {} with own controller".format(
                    line[0]
                )
            )
            cmd = line.pop(0)
            return self.commands.get(cmd)[0].complete(line)

        # Get contexts and subcontext.
        while len(line) != 0:
            val = line[0]

            # Once modifer is found that is the end of contexts
            if val in self.required_modifiers | self.modifiers:
                break

            line.pop(0)

            if val:
                contexts.append(val)

        logger.debug(
            "ManageConfigLeafController: context to complete {}".format(contexts)
        )

        p_success, param = util.fetch_argument(line, self.PARAM, "")
        v_success, value = util.fetch_argument(line, self.TO, "")

        if p_success:
            line.remove(param)

        if v_success:
            line.remove(value)

        p_success = p_success or self.PARAM in line
        v_success = v_success or self.TO in line
        possible_completions = []
        to_complete = ""
        next_token = None

        # Complete a sub-context
        if not p_success and not v_success:
            to_complete, possible_completions = self._complete_subcontext(contexts)

        # Complete a config parameter
        elif p_success and not v_success:
            line.remove(self.PARAM)
            to_complete = param
            possible_completions = self._complete_params(contexts)
            next_token = self.TO

        # Complete a parameter value
        elif p_success and v_success:
            line.remove(self.TO)
            to_complete = value
            possible_completions = self._complete_values(contexts, param)

        # What the user entered is not a prefix for completions.
        if len(possible_completions) == 0:
            return []

        completions = PrefixDict()

        for possible in possible_completions:
            completions.add(possible, possible)

        possible_completions = completions.get_key(to_complete)

        if len(possible_completions) == 1:
            # They either typed a space or some garbage value
            if possible_completions[0] == to_complete:
                # Auto complete self.TO
                if next_token is not None:
                    if len(line) == 0:
                        return ["{} {}".format(possible_completions[0], next_token)]
                    if line[-1] == "":
                        return [next_token]

                if len(line):
                    return []

        return possible_completions

    def prompt_challenge(self, message):
        if self.nodes == "all":
            message = "{} on all nodes".format(message)

        else:
            nodes = self.cluster.get_nodes(self.nodes)
            nodes = map(lambda x: x.ip, nodes)
            nodes_str = ", ".join(nodes)
            message = "{} on nodes: {}".format(message, nodes_str)

        return super().prompt_challenge(message=message)


@CommandHelp('"manage config" is used to change dynamic configuration')
class ManageConfigController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "logging": ManageConfigLoggingController,
            "service": ManageConfigServiceController,
            "network": ManageConfigNetworkController,
            "security": ManageConfigSecurityController,
            "namespace": ManageConfigNamespaceController,
            "xdr": ManageConfigXDRController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    "Usage: logging file <log-file-name> param <parameter> to <value>",
    "  file          - Name of log file as shown in the aerospike.conf.",
    "  param         - The logging context.",
    "  to            - The logging level to assign.",
)
class ManageConfigLoggingController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set(["file", self.PARAM, self.TO])
        self.modifiers = set(["with"])

    def _do_default(self, line):
        param, value = self.extract_param_value(line)
        file = util.get_arg_and_delete_from_mods(
            line=line,
            arg="file",
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        if self.warn and not self.prompt_challenge(
            "Change logging context {} to {} for file {}".format(param, value, file)
        ):
            return

        resp = self.cluster.info_set_config_logging(
            file, param, value, nodes=self.nodes
        )

        title = "Set Logging Context {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: service param <parameter> to <value>",
    "  param         - The service configuration parameter.",
    "  to            - The value to assign to the parameter.",
)
class ManageConfigServiceController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set([self.PARAM, self.TO])
        self.modifiers = set(["with"])
        self.require_recluster = set(["cluster-name"])

    def _do_default(self, line):
        param, value = self.extract_param_value(line)

        if self.warn and not self.prompt_challenge(
            "Change service param {} to {}".format(param, value)
        ):
            return

        resp = self.cluster.info_set_config_service(param, value, nodes=self.nodes)

        title = "Set Service Param {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)

        if param in self.require_recluster:
            self.view.print_result(
                'Run "manage recluster" for your changes to {} to take affect.'.format(
                    param
                )
            )


@CommandHelp(
    "Usage: network <subcontext> param <parameter> to <value>",
    "  subcontext    - The network subcontext where the parameter is located.",
    "  param         - The network configuration parameter.",
    "  to            - The value to assign to the parameter.",
)
class ManageConfigNetworkController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set([self.PARAM, self.TO])
        self.modifiers = set(["with"])

    def _do_default(self, line):
        param, value = self.extract_param_value(line)

        if len(line) == 0 or line[0] in self.required_modifiers | self.modifiers:
            self.execute_help(line)
            self.logger.error("Subcontext required.")
            return

        subcontext = line.pop(0)

        if self.warn and not self.prompt_challenge(
            "Change network {} param {} to {}".format(subcontext, param, value)
        ):
            return

        resp = self.cluster.info_set_config_network(
            param, value, subcontext, nodes=self.nodes
        )

        title = "Set Network Param {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: security [<subcontext>] param <parameter> to <value>",
    "  subcontext    - The security subcontext where the parameter is located.",
    "                  [default: None]",
    "  param         - The security configuration parameter.",
    "  to            - The value to assign to the parameter.",
)
class ManageConfigSecurityController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set([self.PARAM, self.TO])
        self.modifiers = set(["with"])

    def _do_default(self, line):
        param, value = self.extract_param_value(line)
        subcontext = None

        # Handles new sub-contexts so they run even without auto-complete
        if len(line) and line[0] not in self.required_modifiers | self.modifiers:
            subcontext = line.pop(0)

        if self.warn and not self.prompt_challenge(
            "Change security{} param {} to {}".format(
                " " + subcontext if subcontext else "", param, value
            )
        ):
            return

        resp = self.cluster.info_set_config_security(
            param, value, subcontext, nodes=self.nodes
        )

        title = "Set Security Param {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: namespace <ns> [<subcontext>] param <parameter> to <value>",
    "  ns            - The name of the namespace you would like to configure.",
    "  subcontext    - The namespace subcontext where the parameter is located.",
    "                  [default: None]",
    "  param         - The namespace configuration parameter.",
    "  to            - The value to assign to the parameter.",
)
class ManageConfigNamespaceController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set([self.PARAM, self.TO])
        self.modifiers = set(["with"])
        self.controller_arg = "ns"
        self.controller_map = {
            "set": ManageConfigNamespaceSetController,
        }
        self.require_recluster = set(["prefer-uniform-balance", "rack-id"])

        # Config params that require another to be set.
        self.param_pairs = {
            "compression-level": "enable-compression",
            "ship-sets": "ship-only-specified-sets",
        }

    def _do_default(self, line):
        param, value = self.extract_param_value(line)
        namespace = self.mods["namespace"][0]
        subcontext = None

        if len(line) and line[0] not in self.required_modifiers | self.modifiers:
            subcontext = line.pop(0)

        if self.warn and not self.prompt_challenge(
            "Change namespace {}{} param {} to {}".format(
                namespace, " " + subcontext if subcontext else "", param, value
            )
        ):
            return

        resp = self.cluster.info_set_config_namespace(
            param, value, namespace, subcontext=subcontext, nodes=self.nodes
        )

        title = "Set Namespace Param {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)

        if param in self.require_recluster:
            self.view.print_result(
                'Run "manage recluster" for your changes to {} to take affect.'.format(
                    param
                )
            )

        if param in self.param_pairs.keys():
            self.view.print_result(
                'The parameter "{}" must also be set.'.format(self.param_pairs[param])
            )


@CommandHelp(
    "Usage: namespace <ns> set <set> param <parameter> to <value>",
    "  ns            - The namespace you would like to configure.",
    "  set           - The set subcontext you would like to configure.",
    "  param         - The namespace configuration parameter.",
    "  to            - The value to assign to the parameter.",
)
class ManageConfigNamespaceSetController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set([self.PARAM, self.TO])
        self.modifiers = set(["with"])
        self.controller_arg = "set"

    def _do_default(self, line):
        param, value = self.extract_param_value(line)
        namespace = self.mods["namespace"][0]
        set_ = self.mods["set"][0]

        if self.warn and not self.prompt_challenge(
            "Change namespace {} set {} param {} to {}".format(
                namespace, set_, param, value
            )
        ):
            return

        resp = self.cluster.info_set_config_namespace(
            param, value, namespace, set_=set_, nodes=self.nodes
        )

        title = "Set Namespace Set Param {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: xdr param <parameter> to <value>",
    "  param         - The XDR configuration parameter.",
    "  to         - The value to assign to the parameter.",
)
class ManageConfigXDRController(ManageConfigLeafController):
    def __init__(self):
        self.modifiers = set(["with"])
        self.required_modifiers = set([self.PARAM, self.TO])
        self.controller_map = {
            "dc": ManageConfigXDRDCController,
            "create": ManageConfigXDRCreateController,
            "delete": ManageConfigXDRDeleteController,
        }

    def _do_default(self, line):
        param, value = self.extract_param_value(line)

        if self.warn and not self.prompt_challenge(
            "Change XDR param {} to {}".format(param, value)
        ):
            return

        resp = self.cluster.info_set_config_xdr(param, value, nodes=self.nodes)

        title = "Set XDR Param {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: xdr create dc <dc>",
    "  dc            - The name of the XDR datacenter you would like to create.",
)
class ManageConfigXDRCreateController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set(["dc"])
        self.modifiers = set(["with"])

    def _do_default(self, line):
        dc = util.get_arg_and_delete_from_mods(
            line=line,
            arg="dc",
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        if self.warn and not self.prompt_challenge("Create XDR DC {}".format(dc)):
            return

        resp = self.cluster.info_set_config_xdr_create_dc(dc, nodes=self.nodes)

        title = "Create XDR DC {}".format(dc)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: xdr delete dc <dc>",
    "  dc            - The name of the XDR datacenter you would like to delete.",
)
class ManageConfigXDRDeleteController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set(["dc"])
        self.modifiers = set(["with"])

    def _do_default(self, line):
        dc = util.get_arg_and_delete_from_mods(
            line=line,
            arg="dc",
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        if self.warn and not self.prompt_challenge("Delete XDR DC {}".format(dc)):
            return

        resp = self.cluster.info_set_config_xdr_delete_dc(dc, nodes=self.nodes)

        title = "Delete XDR DC {}".format(dc)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: xdr dc <dc> param <parameter> to <value>",
    "  dc            - The XDR datacenter you would like to configure.",
    "  param         - The XDR configuration parameter.",
    "  to         - The value to assign to the parameter.",
)
class ManageConfigXDRDCController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set([self.PARAM, self.TO])
        self.modifiers = set(["with"])
        self.controller_arg = "dc"
        self.controller_map = {
            "namespace": ManageConfigXDRDCNamespaceController,
            "add": ManageConfigXDRDCAddController,
            "remove": ManageConfigXDRDCRemoveController,
        }
        self.param_pairs = {
            "auth-user": "auth-password-file",
            "auth-password-file": "auth-user",
        }

    def execute_help(self, line, indent=0, method=None):
        return super().execute_help(
            line, indent=indent, method=method, print_modifiers=False
        )

    def _do_default(self, line):
        param, value = self.extract_param_value(line)
        dc = self.mods["dc"][0]

        if self.warn and not self.prompt_challenge(
            "Change XDR DC {} param {} to {}".format(dc, param, value)
        ):
            return

        resp = self.cluster.info_set_config_xdr(param, value, dc=dc, nodes=self.nodes)

        title = "Set XDR DC param {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)

        if param in self.param_pairs.keys():
            self.view.print_result(
                'The parameter "{}" must also be set.'.format(self.param_pairs[param])
            )


@CommandHelp("")
class ManageConfigXDRDCAddController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "node": ManageConfigXDRDCAddNodeController,
            "namespace": ManageConfigXDRDCAddNamespaceController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    "Usage: xdr dc <dc> add node <ip:port>",
    "  dc            - The XDR datacenter you would like to configure.",
    "  node          - The node address to add to the datacenter.",
)
class ManageConfigXDRDCAddNodeController(ManageConfigLeafController):
    def __init__(self):
        self.modifiers = set(["with"])
        self.controller_arg = "ip:port"

    def _do_default(self, line):
        dc = self.mods["dc"][0]
        node = self.mods["node"][0]

        if self.warn and not self.prompt_challenge(
            "Add node {} to DC {}".format(node, dc)
        ):
            return

        resp = self.cluster.info_set_config_xdr_add_node(dc, node, nodes=self.nodes)

        title = "Add XDR Node {} to DC {}".format(node, dc)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: xdr dc <dc> add namespace <ns> [rewind <seconds>|all]",
    "  dc            - The XDR datacenter you would like to configure.",
    "  namespace     - The namespace to add to the datacenter.",
    "  rewind        - Number of seconds to rewind a namespace's shipment of records.",
    "                  Use 'all' to restart shipment completely.",
    "  Note: When you are rewinding, the namespace to rewind must already have been",
    "        configured.",
)
class ManageConfigXDRDCAddNamespaceController(ManageConfigLeafController):
    def __init__(self):
        self.modifiers = set(["with", "rewind"])
        self.controller_arg = "ns"

    def _do_default(self, line):
        dc = self.mods["dc"][0]
        namespace = self.mods["namespace"][0]
        rewind = util.get_arg_and_delete_from_mods(
            line=line,
            arg="rewind",
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        if self.warn:
            if rewind is not None and not self.prompt_challenge(
                "Add namespace {} to DC {} with rewind {}".format(namespace, dc, rewind)
            ):
                return
            elif not self.prompt_challenge(
                "Add namespace {} to DC {}".format(namespace, dc)
            ):
                return

        resp = self.cluster.info_set_config_xdr_add_namespace(
            dc, namespace, rewind, nodes=self.nodes
        )

        title = "Add XDR Namespace {} to DC {}".format(namespace, dc)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp("")
class ManageConfigXDRDCRemoveController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "node": ManageConfigXDRDCRemoveNodeController,
            "namespace": ManageConfigXDRDCRemoveNamespaceController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    "Usage: xdr dc <dc> remove node <ip:port>",
    "  dc            - The XDR datacenter you would like to configure.",
    "  node          - The node address to remove from the datacenter.",
)
class ManageConfigXDRDCRemoveNodeController(ManageConfigLeafController):
    def __init__(self):
        self.modifiers = set(["with"])
        self.controller_arg = "node:port"

    def _do_default(self, line):
        dc = self.mods["dc"][0]
        node = self.mods["node"][0]

        if self.warn and not self.prompt_challenge(
            "Remove node {} from DC {}".format(node, dc)
        ):
            return

        resp = self.cluster.info_set_config_xdr_remove_node(dc, node, nodes=self.nodes)

        title = "Remove XDR Node {} from DC {}".format(node, dc)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: xdr dc <dc> remove namespace <ns>",
    "  dc            - The XDR datacenter you would like to configure.",
    "  namespace     - The namespace to remove from the datacenter.",
)
class ManageConfigXDRDCRemoveNamespaceController(ManageConfigLeafController):
    def __init__(self):
        self.modifiers = set(["with"])
        self.controller_arg = "ns"

    def _do_default(self, line):
        dc = self.mods["dc"][0]
        namespace = self.mods["namespace"][0]

        if self.warn and not self.prompt_challenge(
            "Remove namespace {} from DC {}".format(namespace, dc)
        ):
            return

        resp = self.cluster.info_set_config_xdr_remove_namespace(
            dc, namespace, nodes=self.nodes
        )

        title = "Remove XDR Namespace {} from DC {}".format(namespace, dc)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    "Usage: xdr dc <dc> namespace <ns> param <parameter> to <value>",
    "  dc            - The XDR datacenter you would like to configure.",
    "  namespace     - The datacenter namespace you would like to configure.",
    "  param         - The security configuration parameter.",
    "  to            - The value to assign to the parameter.",
)
class ManageConfigXDRDCNamespaceController(ManageConfigLeafController):
    def __init__(self):
        self.required_modifiers = set([self.PARAM, self.TO])
        self.modifiers = set(["with"])
        self.controller_arg = "ns"

    def _do_default(self, line):
        param, value = self.extract_param_value(line)
        dc = self.mods["dc"][0]
        namespace = self.mods["namespace"][0]

        if self.warn and not self.prompt_challenge(
            "Change XDR DC {} namespace {} param {} to {}".format(
                dc, namespace, param, value
            )
        ):
            return

        resp = self.cluster.info_set_config_xdr(
            param, value, dc=dc, namespace=namespace, nodes=self.nodes
        )

        title = "Set XDR Namespace Param {} to {}".format(param, value)
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)


@CommandHelp(
    '"manage truncate" is used to delete multiple records in the Aerospike cluster.',
    'Since the changes performed by this command are critical "--warn" is on by default.',
    "Usage: truncate ns <ns> [set <set>] [undo]|[before <iso-8601-or-unix-epoch> iso-8601|unix-epoch]",
    "  namespace     - The namespace you would like to truncate or undo truncation.",
    "  set           - The set you would like to truncate or undo truncation",
    "                  [default: None]",
    "  undo          - Remove the associated SMD (System Meta Data) files entry and",
    "                  allow (some) previously truncated records to be resurrected on",
    "                  the next cold restart.",
    "                  [default: false]",
    "  before        - Deletes every record in the given namespace or set whose lut is",
    "                  older than the given time. Time can be either an iso-8601 formatted",
    '                  datetime followed by the literal "iso-8601" or unix-epoch',
    '                  followed by the literal "unix-epoch".',
    "                  [default: Now]",
    "Options:",
    "  --no-warn     - Turn off --warn mode. This is not advised.",
)
class ManageTruncateController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = {"ns"}
        self.modifiers = {"set", "before", "undo"}

    def _parse_lut(self):
        lut_datetime = None  # datetime object
        lut_epoch_time = None  #
        error = None
        before = self.mods["before"]

        if len(before):
            seconds = None
            nanoseconds = None

            if len(before) != 2:
                error = (
                    'Last update time must be followed by "unix-epoch" or "iso-8601".'
                )
                return lut_datetime, lut_epoch_time, error

            if "unix-epoch" in before:
                before.remove("unix-epoch")
                lut_time = before[0]

                try:
                    # Create a naive datetime object.
                    lut_datetime = datetime.utcfromtimestamp(float(lut_time))
                except ValueError:
                    error = "Invalid unix-epoch format."
                    return lut_datetime, lut_epoch_time, error

                lut_time = lut_time.split(".")
                seconds = lut_time[0]
                nanoseconds = []

            elif "iso-8601" in before:
                before.remove("iso-8601")
                lut_time = before[0]

                try:
                    lut_datetime = date_parser.isoparse(lut_time)
                except ValueError:
                    error = "Invalid iso-8601 format."
                    return lut_datetime, lut_epoch_time, error

                if lut_datetime.tzinfo is None:
                    error = "iso-8601 format must contain a timezone."
                    return lut_datetime, lut_epoch_time, error

                lut_time = str(lut_datetime.timestamp())
                lut_time = lut_time.split(".")
                seconds = lut_time[0]

            else:
                # They used something besides "unix-epoch" or "iso-8601"
                error = (
                    'Last update time must be followed by "unix-epoch" or "iso-8601".'
                )
                return lut_datetime, lut_epoch_time, error

            # server gives ambiguous error when not exactly the right num of digits.
            if len(seconds) > 10:
                error = "Date provided is too far in the future."
                return lut_datetime, lut_epoch_time, error

            if len(seconds) < 10:
                error = "Date provided is too far in the past."
                return lut_datetime, lut_epoch_time, error

            if len(lut_time) == 2:
                nanoseconds = list(lut_time[1])

            while len(nanoseconds) < 9:
                nanoseconds.append("0")

            lut_epoch_time = "".join(seconds) + "".join(nanoseconds[0:9])

            logger.debug("ManageTruncate epoch time %s", lut_epoch_time)

        return lut_datetime, lut_epoch_time, error

    def _get_namespace_master_objects(self, namespace):
        """
        Get total number of unique objects in a namespace accross the cluster.
        Calculated as the
        sum(all master objects in namespace for each node)
        """
        namespace_stats = self.cluster.info_namespace_statistics(namespace, nodes="all")
        namespace_stats = list(namespace_stats.values())
        master_objects_per_node = map(
            lambda x: int(x.get("master_objects", "0")), namespace_stats
        )
        total_num_master_objects = reduce(
            lambda x, y: x + y, master_objects_per_node, 0
        )
        return str(total_num_master_objects)

    def _get_set_master_objects(self, namespace, set_):
        """
        Get total number of unique objects in a set accross the cluster.
        Calculated as the
        sum(all objects in set for each node) // effective_repl_factor
        """
        set_stats = self.cluster.info_set_statistics(namespace, set_, nodes="all")
        set_stats = set_stats.values()
        namespace_stats = self.cluster.info_namespace_statistics(
            namespace, nodes="random"
        )
        namespace_stats = list(namespace_stats.values())[0]

        # effective_repl_factor added 3.15.3
        effective_repl_factor = int(namespace_stats.get("effective_repl_factor", "1"))
        objects_per_node = map(lambda x: int(x.get("objects", "0")), set_stats)
        total_num_objects = reduce(lambda x, y: x + y, objects_per_node, 0)
        total_num_master_objects = total_num_objects // effective_repl_factor

        return str(total_num_master_objects)

    def _format_date(self, lut_datetime):
        timezone_str = lut_datetime.strftime("%Z")

        if timezone_str == "":
            timezone_str = lut_datetime.strftime("%z")
            if timezone_str == "":
                # The user likely gave an epoch time.
                timezone_str = "UTC"
            else:
                timezone_str = "UTC" + timezone_str[0:3] + ":" + timezone_str[3:]

        formatted = lut_datetime.strftime(
            "%H:%M:%S.%f {} on %B %d, %Y".format(timezone_str)
        )
        formatted = terminal.fg_green() + formatted + terminal.fg_not_green()

        return formatted

    def _generate_warn_prompt(self, namespace, set_, master_objects, lut_datetime):
        prompt_str = "You're about to truncate up to {} records from".format(
            master_objects
        )

        if set_ is not None:
            prompt_str += " set {} for".format(set_)

        prompt_str += " namespace {}".format(namespace)

        if lut_datetime is not None:
            formatted_date = self._format_date(lut_datetime)
            prompt_str += " with LUT before {}".format(formatted_date)

        return prompt_str

    def _do_default(self, line):
        unrecognized = None

        warn = not util.check_arg_and_delete_from_mods(
            line=line,
            arg="--no-warn",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        # TODO: Build an option into the controller that strictly checks modifiers.
        # This is especially important with truncate.
        if self.mods["line"]:
            unrecognized = self.mods["line"]
        if len(self.mods["ns"]) > 1:  # required
            unrecognized = self.mods["ns"]
        if len(self.mods["set"]) != 1 and "set" in line:
            unrecognized = self.mods["set"]
        if len(self.mods["before"]) != 2 and "before" in line:
            unrecognized = self.mods["before"]

        if unrecognized is not None:
            self.logger.error("Unrecognized input: {}".format(" ".join(unrecognized)))
            return

        namespace = self.mods["ns"][0]
        set_ = util.get_arg_and_delete_from_mods(
            line=line,
            arg="set",
            return_type=str,
            default=None,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )
        undo = util.check_arg_and_delete_from_mods(
            line=line,
            arg="undo",
            default=False,
            modifiers=self.required_modifiers,
            mods=self.mods,
        )

        if self.mods["before"] and undo:
            self.execute_help(line)
            self.logger.error('"undo" and "before" are mutually exclusive.')
            return

        lut_datetime, lut_epoch_time, error = self._parse_lut()

        if error is not None:
            self.logger.error(error)
            return

        if warn:
            prompt = None

            if undo:
                prompt = ""
            else:
                total_num_master_objects = None

                if set_ is None:
                    total_num_master_objects = self._get_namespace_master_objects(
                        namespace
                    )

                else:
                    total_num_master_objects = self._get_set_master_objects(
                        namespace, set_
                    )

                prompt = self._generate_warn_prompt(
                    namespace, set_, total_num_master_objects, lut_datetime
                )

            if not self.prompt_challenge(prompt):
                return

        if undo:
            resp = self.cluster.info_truncate_undo(namespace, set_, nodes="principal")
        else:
            resp = self.cluster.info_truncate(
                namespace, set_, lut_epoch_time, nodes="principal"
            )

        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        if undo:
            if set_ is None:
                self.view.print_result(
                    "Successfully triggered undoing truncation for namespace {} on next cold restart".format(
                        namespace
                    )
                )
            else:
                self.view.print_result(
                    "Successfully triggered undoing truncation for set {} of namespace {} on next cold restart".format(
                        set_, namespace
                    )
                )
        else:
            if set_ is None:
                self.view.print_result(
                    "Successfully started truncation for namespace {}".format(namespace)
                )
            else:
                self.view.print_result(
                    "Successfully started truncation for set {} of namespace {}".format(
                        set_, namespace
                    )
                )


@CommandHelp(
    '"manage recluster" is used to recluster an Aerospike cluster. This is',
    "necessary for certain configuration changes to take effect.",
    "Usage: recluster",
)
class ManageReclusterController(ManageLeafCommandController):
    def __init__(self):
        pass

    def _do_default(self, line):
        resp = self.cluster.info_recluster(nodes="principal")
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Successfully started recluster")


@CommandHelp(
    '"manage quiesce" causes a node to avoid participating as a replica after the next recluster event.',
    "Usage: quiesce with node1 [node2 [...]] [undo]",
    "  with          - The node(s) to quiesce. Acceptable values are ip:port, node-id, or FQDN.",
    "  undo          - Revert the effects of the quiesce on the next recluster event.",
    "                  [default: false]",
)
class ManageQuiesceController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = {"with"}
        self.modifiers = {"undo"}

    def _do_default(self, line):
        undo = util.check_arg_and_delete_from_mods(
            line, arg="undo", default=False, modifiers=self.modifiers, mods=self.mods
        )

        if self.warn:
            if undo:
                prompt = "You are about to undo quiescing of node(s): {}"
            else:
                prompt = "You are about to quiesce node(s): {}"

            if not self.prompt_challenge(prompt.format(", ".join(self.nodes))):
                return

        resp = None
        title = None

        if undo:
            title = "Undo Quiesce for Nodes"
            resp = self.cluster.info_quiesce_undo(nodes=self.nodes)
        else:
            title = "Quiesce Nodes"
            resp = self.cluster.info_quiesce(nodes=self.nodes)

        self.view.print_info_responses(title, resp, self.cluster, **self.mods)
        self.view.print_result(
            'Run "manage recluster" for your changes to take affect.'
        )


@CommandHelp(
    '"manage revive" is used to revive dead partitions in a namespace running in strong',
    "consistency mode.",
    "Usage: revive ns <ns>",
    "  ns            - A namespace with dead partitions.",
)
class ManageReviveController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = {"ns"}
        self.modifiers = {"with"}

    def _do_default(self, line):
        ns = self.mods["ns"][0]

        if self.warn and not self.prompt_challenge(
            "You are about to revive namespace {}".format(ns)
        ):
            return

        resp = self.cluster.info_revive(ns, nodes=self.nodes)

        title = "Revive Namespace Partitions"
        self.view.print_info_responses(title, resp, self.cluster, **self.mods)
        self.view.print_result(
            'Run "manage recluster" for your changes to take affect.'
        )


class ManageRosterLeafCommandController(ManageLeafCommandController):
    def _check_and_log_cluster_stable(self, stable_data):
        cluster_key = None
        warning_str = "The cluster is unstable. It is advised that you do not manage the roster. Run 'info network' for more information."

        for resp in stable_data.values():
            if isinstance(resp, ASInfoClusterStableError):
                self.logger.warning(warning_str)
                return False

            if isinstance(resp, ASInfoError):
                raise resp

            if cluster_key is not None and cluster_key != resp:
                self.logger.warning(warning_str)
                return False

            cluster_key = resp

        return True

    def _check_and_log_nodes_in_observed(self, observed, nodes):
        diff = set(nodes) - set(observed)

        if len(diff):
            self.logger.warning(
                "The following node(s) are not found in the observed list or have a\n"
                + "different configured rack-id: {}",
                ", ".join(list(diff)),
            )
            return False

        return True


@CommandHelp(
    '"manage roster" is used to modify the clusters roster. It',
    'should be used in conjunction with the "show roster" command',
)
class ManageRosterController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "add": ManageRosterAddController,
            "remove": ManageRosterRemoveController,
            "stage": ManageRosterStageController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    '"manage roster add" is used to add node(s) to the pending-roster. Since the changes',
    'performed by this command are critical "--warn" is on by default.',
    "Usage: add nodes node_id1[@rack_id] [node_id2[@rack_id1] [...]] ns <ns>",
    "  nodes         - The node(s) to add to the pending-roster.",
    "  ns            - The namespace of the pending-roster.",
    "Options:",
    "  --no-warn     - Turn off --warn mode. This is not advised.",
)
class ManageRosterAddController(ManageRosterLeafCommandController):
    def __init__(self):
        self.required_modifiers = {"nodes", "ns"}
        self.getter = GetConfigController(self.cluster)

    def _do_default(self, line):
        ns = self.mods["ns"][0]
        warn = not util.check_arg_and_delete_from_mods(
            line=line,
            arg="--no-warn",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )
        current_roster = util.Future(
            self.cluster.info_roster, ns, nodes="principal"
        ).start()
        cluster_stable = util.Future(
            self.cluster.info_cluster_stable, nodes=self.nodes
        ).start()

        current_roster = current_roster.result()
        cluster_stable = cluster_stable.result()
        current_roster = list(current_roster.values())[0]

        if isinstance(current_roster, ASInfoError):
            self.logger.error(current_roster)
            return
        elif isinstance(current_roster, Exception):
            raise current_roster

        new_roster = list(current_roster["pending_roster"])
        new_roster.extend(self.mods["nodes"])

        if warn:
            self._check_and_log_cluster_stable(cluster_stable)
            self._check_and_log_nodes_in_observed(
                current_roster["observed_nodes"], self.mods["nodes"]
            )

            if not self.prompt_challenge(
                "You are about to set the pending-roster for namespace {} to: {}".format(
                    ns, ", ".join(new_roster)
                )
            ):
                return

        resp = self.cluster.info_roster_set(
            self.mods["ns"][0], new_roster, nodes="principal"
        )
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Node(s) successfully added to pending-roster.")
        self.view.print_result(
            'Run "manage recluster" for your changes to take affect.'
        )


@CommandHelp(
    '"manage roster remove" is used to remove node(s) from the pending-roster. Since the',
    'changes performed by this command are critical "--warn" is on by default.',
    "Usage: remove nodes node_id1[@rack_id] [node_id2[@rack_id1] [...]] ns <ns>",
    "  nodes         - The node(s) to remove from the pending-roster.",
    "  ns            - The namespace of the pending-roster..",
    "Options:",
    "  --no-warn     - Turn off --warn mode. This is not advised.",
)
class ManageRosterRemoveController(ManageRosterLeafCommandController):
    def __init__(self):
        self.required_modifiers = {"nodes", "ns"}

    def _do_default(self, line):
        ns = self.mods["ns"][0]
        warn = not util.check_arg_and_delete_from_mods(
            line=line,
            arg="--no-warn",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )
        current_roster = util.Future(
            self.cluster.info_roster, ns, nodes="principal"
        ).start()
        cluster_stable = util.Future(
            self.cluster.info_cluster_stable, nodes=self.nodes
        ).start()

        current_roster = current_roster.result()
        cluster_stable = cluster_stable.result()
        current_roster = list(current_roster.values())[0]

        if isinstance(current_roster, ASInfoError):
            self.logger.error(current_roster)
            return
        elif isinstance(current_roster, Exception):
            raise current_roster

        new_roster = list(current_roster["pending_roster"])
        missing_nodes = []

        for rm_node in self.mods["nodes"]:
            try:
                new_roster.remove(rm_node)
            except ValueError:
                missing_nodes.append(rm_node)

        if warn:
            if len(missing_nodes):
                self.logger.warning(
                    "The following nodes are not in the pending-roster: {}",
                    ", ".join(missing_nodes),
                )

            self._check_and_log_cluster_stable(cluster_stable)

            if not self.prompt_challenge(
                "You are about to set the pending-roster for namespace {} to: {}".format(
                    ns, ", ".join(new_roster)
                )
            ):
                return

        resp = self.cluster.info_roster_set(ns, new_roster, nodes="principal")
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Node(s) successfully removed from pending-roster.")
        self.view.print_result(
            'Run "manage recluster" for your changes to take affect.'
        )


@CommandHelp("")
class ManageRosterStageController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "nodes": ManageRosterStageNodesController,
            "observed": ManageRosterStageObservedController,
        }


@CommandHelp(
    '"manage roster stage nodes" is used to overwrite the nodes in the pending-roster.',
    'Since the changes performed by this command are critical "--warn" is on by default.',
    "Usage: roster stage nodes node_id1[@rack_id1] [node_id2[@rack_id2] [...]] ns <ns>",
    "  nodes         - The node(s) to include in the new pending-roster.",
    "  ns            - The namespace of the pending-roster.",
    "Options:",
    "  --no-warn     - Turn off --warn mode. This is not advised.",
)
class ManageRosterStageNodesController(ManageRosterLeafCommandController):
    def __init__(self):
        self.required_modifiers = {"line", "ns"}

    def _do_default(self, line):
        new_roster = self.mods["line"]
        ns = self.mods["ns"][0]
        warn = not util.check_arg_and_delete_from_mods(
            line=line,
            arg="--no-warn",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        if warn:
            cluster_stable = util.Future(
                self.cluster.info_cluster_stable, nodes=self.nodes
            ).start()
            current_roster = util.Future(
                self.cluster.info_roster, ns, nodes="principal"
            ).start()

            cluster_stable = cluster_stable.result()
            current_roster = current_roster.result()
            current_roster = list(current_roster.values())[0]

            if isinstance(current_roster, ASInfoError):
                self.logger.error(current_roster)
                return
            elif isinstance(current_roster, Exception):
                raise current_roster

            self._check_and_log_cluster_stable(cluster_stable)
            self._check_and_log_nodes_in_observed(
                current_roster["observed_nodes"], self.mods["line"]
            )

            if not self.prompt_challenge(
                "You are about to set the pending-roster for namespace {} to: {}".format(
                    ns, ", ".join(new_roster)
                )
            ):
                return

        resp = self.cluster.info_roster_set(ns, new_roster, nodes="principal")
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Pending roster successfully set.")
        self.view.print_result(
            'Run "manage recluster" for your changes to take affect.'
        )


@CommandHelp(
    '"manage roster stage observed" automatically adds observed-nodes to the',
    "pending-roster.",
    "Usage: roster stage observed ns <ns>",
    "  ns            - The namespace of the pending-roster you would like to set.",
)
class ManageRosterStageObservedController(ManageRosterLeafCommandController):
    def __init__(self):
        self.required_modifiers = {"ns"}

    def _do_default(self, line):
        ns = self.mods["ns"][0]
        current_roster = util.Future(
            self.cluster.info_roster, ns, nodes="principal"
        ).start()
        cluster_stable = util.Future(
            self.cluster.info_cluster_stable, nodes=self.nodes
        ).start()

        current_roster = current_roster.result()
        cluster_stable = cluster_stable.result()
        current_roster = list(current_roster.values())[0]

        if isinstance(current_roster, ASInfoError):
            self.logger.error(current_roster)
            return
        elif isinstance(current_roster, Exception):
            raise current_roster

        new_roster = current_roster["observed_nodes"]

        if not self._check_and_log_cluster_stable(cluster_stable) or self.warn:
            if not self.prompt_challenge(
                "You are about to set the pending-roster for namespace {} to: {}".format(
                    ns, ", ".join(new_roster)
                )
            ):
                return

        resp = self.cluster.info_roster_set(ns, new_roster, nodes="principal")
        resp = list(resp.values())[0]

        if isinstance(resp, ASInfoError):
            self.logger.error(resp)
            return
        elif isinstance(resp, Exception):
            raise resp

        self.view.print_result("Pending roster now contains observed nodes.")
        self.view.print_result(
            'Run "manage recluster" for your changes to take affect.'
        )


class ManageJobsController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {"kill": ManageJobsKillController}

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    '"manage jobs kill" is used to abort jobs.',
)
class ManageJobsKillController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "trids": ManageJobsKillTridController,
            "all": ManageJobsKillAllController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    '"manage jobs kill trids" is used to abort jobs using their transaction ids.',
    "Usage: kill trids <trid1> [<trid2> [...]]",
    "  trid          - The transaction ids of the jobs you would like to kill.",
)
class ManageJobsKillTridController(ManageLeafCommandController):
    def __init__(self):
        self.required_modifiers = {"line"}
        self.getter = GetJobsController(self.cluster)

    def _kill_trid(self, executor, node, module, trid):
        if module == constants.JobType.SCAN:
            return executor.submit(self.cluster.info_scan_abort, trid, nodes=[node])
        elif module == constants.JobType.QUERY:
            return executor.submit(self.cluster.info_query_abort, trid, nodes=[node])
        else:
            return executor.submit(
                self.cluster.info_jobs_kill,
                module,
                trid,
                nodes=[node],
            )

    def _do_default(self, line):
        trids = self.mods["line"]
        jobs_data = self.getter.get_all()
        requests_ = []
        responses = {}

        if self.warn and not self.prompt_challenge(
            "You're about to kill the following transactions: {}".format(
                ", ".join(trids)
            )
        ):
            return

        # Dict key hierarchy is currently module -> host -> trid.
        # We want trid at the top.  i.e. trid -> module -> host for quick lookup
        for module, host_data in jobs_data.items():
            jobs_data[module] = util.flip_keys(host_data)

        jobs_data = util.flip_keys(jobs_data)

        with ThreadPoolExecutor(max_workers=len(trids)) as executor:
            for trid in list(trids):
                if trid in jobs_data:
                    module, host_data = list(jobs_data[trid].items())[0]
                    for host, job_data in host_data.items():
                        requests_.append(
                            (
                                host,
                                trid,
                                job_data,
                                self._kill_trid(executor, host, module, trid),
                            )
                        )

        if not requests_:
            self.logger.error("The provided trid(s) could not be found.")

        for request in requests_:
            host, trid, job_data, resp = request
            resp = list(resp.result().values())[0]

            if host not in responses:
                responses[host] = {}

            job_data["response"] = resp
            responses[host][trid] = job_data

        self.view.killed_jobs(self.cluster, responses, **self.mods)


@CommandHelp()
class ManageJobsKillAllController(LiveClusterCommandController):
    def __init__(self):
        self.controller_map = {
            "scans": ManageJobsKillAllScansController,
        }

    def _do_default(self, line):
        self.execute_help(line)


@CommandHelp(
    '"manage jobs kill all scans" is used to abort all scan jobs.',
    "Usage: kill all scans",
)
class ManageJobsKillAllScansController(ManageLeafCommandController):
    def __init__(self):
        self.modifiers = {"with"}

    def _do_default(self, line):
        if self.warn:
            if self.nodes == "all":
                if not self.prompt_challenge(
                    "You're about to kill all scan jobs on all nodes."
                ):
                    return
            else:
                if not self.prompt_challenge(
                    "You're about to kill all scan jobs on node(s): {}.".format(
                        ", ".join(self.nodes)
                    )
                ):
                    return

        resp = self.cluster.info_scan_abort_all(nodes=self.nodes)

        self.view.print_info_responses("Kill Jobs", resp, self.cluster, **self.mods)
