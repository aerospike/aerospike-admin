####
#
# Copyright 2013-2020 Aerospike, Inc.
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
#
####

import sys
import struct
from ctypes import create_string_buffer		 # gives us pre-allocated bufs
from time import time
from enum import IntEnum, unique
from socket import error as SocketError

from lib.utils.util import bytes_to_str, str_to_bytes, logthis
from lib.utils.constants import AuthMode
from logging import DEBUG

try:
    import bcrypt
    hasbcrypt = True
except:
    # bcrypt not installed. This should only be
    # fatal when authentication is required.
    hasbcrypt = False


# There are three different headers referenced here in the code. I am adding
# this description in the hopes that it will clear up confusion about the number
# of variable with the name "header" in them.
# 1. Protocol Header 
# That is 8 bytes that come before every info/security
# response.  You can find a description of this header here:
# https://aerospike.atlassian.net/wiki/spaces/DEV/pages/857899427/Wire+Protocol
# under "Aerospike Protocol Header".
# 2. Admin Header
# That is 16 bytes that follow the the protocol header. 12 of these bytes are
# not used. You can find a description of this header here:
# https://aerospike.atlassian.net/wiki/spaces/AER/pages/44171287/Security+Wire+Protocol
# 3. Field Header
# That is 5 bytes that come before every field no matter the type.
#
# |1|1|  6  |1|1|1|1|    12    | 4 |1| field data . . .| next field . . .|

_STRUCT_PROTOCOL_HEADER = struct.Struct('! B B 3h')
_STRUCT_UINT8 = struct.Struct('! B')
_STRUCT_UINT32 = struct.Struct('! I')
_STRUCT_FIELD_HEADER = struct.Struct("! I B")
_STRUCT_ADMIN_HEADER = struct.Struct('! B B B B 12x')

_PROTOCOL_HEADER_SIZE = _STRUCT_PROTOCOL_HEADER.size

def _pack_uint8(buf, offset, val):
    _STRUCT_UINT8.pack_into(buf, offset, val)
    offset += _STRUCT_UINT8.size
    return offset

def _unpack_uint8(buf, offset):
    val = _STRUCT_UINT8.unpack_from(buf, offset)
    offset += _STRUCT_UINT8.size
    return val, offset

def _pack_uint32(buf, offset, val):
    _STRUCT_UINT32.pack_into(buf, offset, val)
    offset += _STRUCT_UINT32.size
    return offset

def _pack_string(buf, offset, string):
    bytes_field = str_to_bytes(string)
    buf[offset:offset + len(bytes_field)] = bytes_field
    return offset + len(bytes_field)

def _unpack_string(buf, offset, sz):
    val = buf[offset: offset + sz]
    offset += sz
    return val, offset

def _pack_protocol_header(buf, offset, protocol_version, protocol_type, sz):
    proto = (protocol_version << 56) | (protocol_type << 48) | sz
    _STRUCT_PROTOCOL_HEADER.pack_into(
        buf, offset,
        protocol_version, 
        protocol_type, 
        (sz >> 32) & 0xFFFF, 
        (sz >> 16) & 0xFFFF, 
        sz & 0xFFFF
    )
    return offset + _PROTOCOL_HEADER_SIZE

def _unpack_protocol_header(buf, offset=0):
    protocol_header = _STRUCT_PROTOCOL_HEADER.unpack_from(buf, offset=offset)
    protocol_version = protocol_header[0]
    protocol_type = protocol_header[1]
    data_size = (protocol_header[2] << 32) | (protocol_header[3] << 16) | protocol_header[4]
    offset = _PROTOCOL_HEADER_SIZE
    return protocol_version, protocol_type, data_size, offset

def _receive_data(sock, sz):
    pos = 0
    data = None
    while pos < sz:
        chunk = sock.recv(sz - pos)
        if pos == 0:
            data = chunk
        else:
            data += chunk
        pos += len(chunk)
    return data

####### Password hashing ######

def _hash_password(password):
    if isinstance(password, str):
        password = password.encode('utf-8')

    if hasbcrypt == False:
        print("Authentication failed: bcrypt not installed.")
        sys.exit(1)

    if password == None:
        password = ""

    if len(password) != 60 or password.startswith("$2a$") == False:
        password = bcrypt.hashpw(password, _ADMIN_SALT)

    return password

###############################


########### Security ##########

class ASProtocolError(Exception):
    def __init__(self, as_response, message):
        self.message = message + " : " + str(ASResponse(as_response))
        super().__init__(self.message)


_ADMIN_SALT = b"$2a$10$7EqJtq98hPqEX7fNZaFWoO"
_ADMIN_MSG_VERSION = 0
_ADMIN_MSG_TYPE = 2

_ADMIN_HEADER_SIZE = _STRUCT_ADMIN_HEADER.size
_TOTAL_HEADER_SIZE = _PROTOCOL_HEADER_SIZE + _ADMIN_HEADER_SIZE


@unique
class ASCommand(IntEnum):
    AUTHENTICATE = 0
    CREATE_USER = 1
    DROP_USER = 2
    SET_PASSWORD = 3
    CHANGE_PASSWORD = 4
    GRANT_ROLES = 5
    REVOKE_ROLES = 6
    QUERY_USERS = 9
    CREATE_ROLE = 10
    DELETE_ROLE = 11
    ADD_PRIVLEGES = 12
    DELETE_PRIVLEGES = 13
    SET_WHITELIST = 14
    QUERY_ROLES = 16
    LOGIN = 20

@unique
class ASField(IntEnum):
    USER = 0
    PASSWORD = 1
    OLD_PASSWORD = 2
    CREDENTIAL = 3
    CLEAR_PASSWORD = 4
    SESSION_TOKEN = 5
    SESSION_TTL = 6
    ROLES = 10
    ROLE = 11
    PRIVILEGES = 12
    WHITELIST = 13

@unique
class ASPrivilege(IntEnum):
    USER_ADMIN = 0
    SYS_ADMIN = 1
    DATA_ADMIN = 2
    READ = 10
    READ_WRITE = 11
    READ_WRITE_UDF = 12
    WRITE = 13

    @classmethod
    def str_to_enum(cls, privilege_str):
        privilege_str = privilege_str.lower()
        privilege_str = privilege_str.replace('_', '-')

        if privilege_str == 'user-admin':
            return cls.USER_ADMIN
        elif privilege_str == 'sys-admin':
            return cls.SYS_ADMIN
        elif privilege_str == 'data-admin':
            return cls.DATA_ADMIN
        elif privilege_str == 'read':
            return cls.READ
        elif privilege_str == 'read-write':
            return cls.READ_WRITE
        elif privilege_str == 'read-write-udf':
            return cls.READ_WRITE_UDF
        elif privilege_str == 'write':
            return cls.WRITE
        else:
            raise TypeError("Privilege: Not a valid privilege name: {}".format(privilege_str))

@unique
class ASResponse(IntEnum):
    OK = 0
    UNKNOWN_SERVER_ERROR = 1
    SECURITY_NOT_SUPPORTED = 51
    SECURITY_NOT_ENABLED = 52
    INVALID_COMMAND = 54
    UNRECOGNIZED_FIELD_ID = 55
    NO_USER_OR_UNRECOGNIZED_USER = 60
    USER_ALREADY_EXISTS = 61
    NO_PASSWORD_OR_BAD_PASSORD = 62
    NO_CREDENTIAL_OR_BAD_CREDENTIAL = 65
    NO_ROLE_OR_INVALID_ROLE = 70
    ROLE_ALREADY_EXISTS = 71
    NO_PRIVLEGES_OR_UNRECOGNIZED_PRIVILEGES = 72
    BAD_WHITELIST = 73
    NOT_AUTHENTICATED = 80
    ROLE_OR_PRIVILEGE_VIOLATION = 81
    NOT_WHITELISTED = 82

    def __str__(self):
        lower = self.name.lower().split('_')
        lower = ' '.join(lower)
        lower = lower[0].upper() + lower[1:]
        return lower

def _pack_admin_header(buf, offset, scheme, result, command, n_fields):
    _STRUCT_ADMIN_HEADER.pack_into(
        buf, offset, scheme, result, command.value, n_fields)
    offset += _ADMIN_HEADER_SIZE
    return offset

def _unpack_admin_header(buf, offset=_PROTOCOL_HEADER_SIZE):
    admin_header = _STRUCT_ADMIN_HEADER.unpack_from(buf, offset)
    scheme = admin_header[0]
    result_code = admin_header[1]
    command = admin_header[2]
    fields_count = admin_header[3]
    offset += _ADMIN_HEADER_SIZE
    return scheme, result_code, command, fields_count, offset

def _create_admin_header(sz, command, field_count):
    # 4B = field size, 1B = filed type
    protocol_data_size = sz + _ADMIN_HEADER_SIZE + (5 * field_count)
    buffer_size = protocol_data_size + _PROTOCOL_HEADER_SIZE
    buf = create_string_buffer(buffer_size)
    offset = _pack_protocol_header(buf, 0, _ADMIN_MSG_VERSION, _ADMIN_MSG_TYPE, protocol_data_size)
    offset = _pack_admin_header(buf, offset, _ADMIN_MSG_VERSION, 0, command, field_count)
    return buf, offset

def _pack_admin_field_header(buf, offset, field_len, field_type):
    ''' Packs the first 5 bytes in front of every admin field.
    field_len = the number of bytes to follow the 4B Field Length.
    '''
    _STRUCT_FIELD_HEADER.pack_into(buf, offset, field_len, field_type.value)
    offset += _STRUCT_FIELD_HEADER.size
    return offset

def _unpack_admin_field_header(buf, offset):
    field_len, field_type = _STRUCT_FIELD_HEADER.unpack_from(buf, offset)
    offset += _STRUCT_FIELD_HEADER.size
    return field_len, field_type, offset

def _pack_admin_field(buf, offset, as_field, field):
    # 1B = field type?

    # _pack_string() will convert str to bytes, no need to handle here.
    if isinstance(field, str) or isinstance(field, bytes):
        field_len = len(field) + 1
        offset = _pack_admin_field_header(buf, offset, field_len, as_field)
        offset = _pack_string(buf, offset, field)
    elif isinstance(field, list):
        if as_field == ASField.ROLES:
            offset = _pack_admin_roles(buf, offset, field)
        elif as_field == ASField.PRIVILEGES:
            offset = _pack_admin_privileges(buf, offset, field)
        else:
            raise TypeError("_pack_admin_field: Field ID does not accept lists: {}".format(as_field))
    else:
        raise TypeError("_pack_admin_field: Unhandled field type: {}".format(type(field)))

    return offset

def _len_roles(roles):
    # 1B = role_count
    field_len = 1
    for role in roles:
        # 1B = role_name_size
        field_len += len(role) + 1

    return field_len

def _pack_admin_roles(buf, offset, roles):
    field_len = _len_roles(roles) + 1
    role_count = len(roles)

    offset = _pack_admin_field_header(buf, offset, field_len, ASField.ROLES)
    offset = _pack_uint8(buf, offset, role_count)

    for role in roles:
        role_len = len(role)
        offset = _pack_uint8(buf, offset, role_len)
        offset = _pack_string(buf, offset, role)

def _unpack_admin_roles(buf, offset):
    num_roles, offset = _unpack_uint8(buf, offset)
    roles = []

    for _ in range(num_roles):
        role_size, offset = _unpack_uint8(buf, offset)
        role_name, offset = _unpack_string(buf, offset, role_size)
        roles.append(role_name)

    return roles, offset

def _parse_privilege(privilege):
    """ 
    Parses string of the form 'sys-admin.test.testset'
    """
    split_privilege = privilege.split('.')
    permission = ASPrivilege.str_to_enum(split_privilege[0])
    namespace = ''
    set_ = ''

    if len(split_privilege) >= 2:
        namespace = split_privilege[1]

    if len(split_privilege) >= 3:
        set_ = split_privilege[2]

    return permission, namespace, set_


def _len_privileges(privileges):
    # 1B = component count
    field_len = 1

    for privilege in privileges:
        # 1B = permission code ID
        field_len += 1
        permission, namespace, set_ = _parse_privilege(privilege)

        if permission in { 
            ASPrivilege.READ,
            ASPrivilege.READ_WRITE, 
            ASPrivilege.READ_WRITE_UDF,
            ASPrivilege.WRITE
        }:

            # 1B = namespace name len
            field_len += 1
            field_len += len(namespace)
            # 1B = set name len
            field_len += 1
            field_len += len(set_)

    return field_len

@logthis('asadm', DEBUG)
def _pack_admin_privileges(buf, offset, privileges):
    privilege_count = len(privileges)
    field_len = _len_privileges(privileges) + 1 # 1B for field type

    offset = _pack_admin_field_header(buf, offset, field_len, ASField.PRIVILEGES)
    offset = _pack_uint8(buf, offset, privilege_count)

    for privilege in privileges:
        
        permission, namespace, set_ = _parse_privilege(privilege)
        print(permission, namespace, set_)
        offset = _pack_uint8(buf, offset, permission.value)

        if permission in { 
            ASPrivilege.READ,
            ASPrivilege.READ_WRITE, 
            ASPrivilege.READ_WRITE_UDF,
            ASPrivilege.WRITE
        }:
            offset = _pack_uint8(buf, offset, len(namespace))
            offset = _pack_string(buf, offset, namespace)
            offset = _pack_uint8(buf, offset, len(set_))
            offset = _pack_string(buf, offset, set_)

def _c_str_to_bytes(buf):
    return bytes(buf)

def _send_and_get_admin_header(sock, send_buf):
    # OpenSSL wrapper doesn't support ctypes
    send_buf = _c_str_to_bytes(send_buf)

    try:
        sock.sendall(send_buf)
        recv_buf = _receive_data(sock, _TOTAL_HEADER_SIZE)
        rsp_header = _unpack_admin_header(recv_buf, _PROTOCOL_HEADER_SIZE)
    except SocketError as e:
        raise IOError("Error: %s" % str(e))

    return rsp_header

def _authenticate(sock, user, password, password_field_id):
    field_count = 2
    user = str_to_bytes(user)
    password = str_to_bytes(password)
    admin_data_size = len(user) + len(password)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.AUTHENTICATE, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, password_field_id, password)

    try:
        # OpenSSL wrapper doesn't support ctypes
        _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
        return return_code
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise IOError("Error: %s" % str(e))

def authenticate_new(sock, user, session_token):
    return _authenticate(sock, user, password=session_token, password_field_id=ASField.SESSION_TOKEN)

def authenticate_old(sock, user, password):
    return _authenticate(sock, user, password=_hash_password(password), password_field_id=ASField.CREDENTIAL)

# roles is a list of strings representing role names.
@logthis('asadm', DEBUG)
def create_user(sock, user, password, roles):
    """Attempts to create a user in AS.
    user: string,
    password: string (un-hashed),
    roles: list[string],
    Returns: ASResponse
    """
    field_count = 3
    roles_len = _len_roles(roles)
    hashed_password = _hash_password(password)
    admin_data_size = len(user) + len(hashed_password) + roles_len
    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.CREATE_USER, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.PASSWORD, hashed_password)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLES, roles)

    try:
        _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
        return return_code
    except Exception as e:
        raise IOError("Error: %s" % str(e))

@logthis('asadm', DEBUG)
def drop_user(sock, user):
    """Attempts to delete a user in AS.
    user: string,
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(user)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.DROP_USER, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)

    try:
        _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
        return return_code
    except Exception as e:
        raise IOError("Error: %s" % str(e))

@logthis('asadm', DEBUG)
def set_password(sock, user, password):
    """Attempts to set a user password in AS.
    user: string,
    password: string (un-hashed),
    Returns: ASResponse
    """
    field_count = 2
    hashed_password = _hash_password(password)
    admin_data_size = len(user) + len(hashed_password)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.SET_PASSWORD, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.PASSWORD, hashed_password)

    try:
        _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
        return return_code
    except Exception as e:
        raise IOError("Error: %s" % str(e))

@logthis('asadm', DEBUG)
def change_password(sock, user, old_password, new_password):
    """Attempts to change a users passowrd in AS.
    user: string,
    old_password: string (un-hashed),
    new_password: string (un-hashed),
    Returns: ASResponse
    """
    field_count = 3
    hashed_old_password = _hash_password(old_password)
    hashed_new_password = _hash_password(new_password)
    admin_data_size = len(user) + len(hashed_old_password) + len(hashed_old_password)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.CHANGE_PASSWORD, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.OLD_PASSWORD, hashed_old_password)
    offset = _pack_admin_field(send_buf, offset, ASField.PASSWORD, hashed_new_password)

    try:
        _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
        return return_code
    except Exception as e:
        raise IOError("Error: %s" % str(e))

# roles is a list of strings representing role names.
@logthis('asadm', DEBUG)
def grant_roles(sock, user, roles):
    """Attempts to grant roles to user in AS.
    user: string,
    roles: list[string],
    Returns: ASResponse
    """
    field_count = 2
    admin_data_size = len(user) + _len_roles(roles)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.GRANT_ROLES, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLES, roles)

    _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
    return return_code

# roles is a list of strings representing role names.
@logthis('asadm', DEBUG)
def revoke_roles(sock, user, roles):
    """Attempts to remove roles from a user in AS.
    user: string,
    roles: list[string],
    Returns: ASResponse
    """
    field_count = 2
    admin_data_size = len(user) + _len_roles(roles)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.REVOKE_ROLES, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLES, roles)

    _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)

    return return_code

def _query_users(sock, user=None):
    """Attempts to query users and respective roles from AS.
    user: string or None, If none queries all users.
    Returns: ASResponse
    """
    users_dict = {}
    field_count = 0
    admin_data_size = 0

    if user is not None:
        field_count += 1
        admin_data_size = len(user)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.QUERY_USERS, field_count)

    if user is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.USER, user)

        # OpenSSL wrapper doesn't support ctypes
        send_buf = _c_str_to_bytes(send_buf)

    try:
        sock.sendall(send_buf)
        rsp_buf = _receive_data(sock, _PROTOCOL_HEADER_SIZE)
        _, _, data_size, _ = _unpack_protocol_header(rsp_buf)
        rsp_buf = _receive_data(sock, data_size)

        offset = 0

        while offset < data_size:
            _, result_code, _, field_count, offset = _unpack_admin_header(rsp_buf, offset)

            if result_code != ASResponse.OK:
                return result_code, users_dict

            user_name = None
            user_roles = []

            for _ in range(field_count):
                field_len, field_type, offset = _unpack_admin_field_header(rsp_buf, offset)

                if field_type == ASField.USER:
                    user_name, offset = _unpack_string(rsp_buf, offset, field_len)

                    if user_name not in users_dict:
                        users_dict[user_name] = users_dict
                elif field_type == ASField.ROLES:
                    roles, offset = _unpack_admin_roles(rsp_buf, offset)
                    user_roles.append(roles)
                else:
                    offset += field_len

            if user_name is None:
                continue

            users_dict[user_name] = user_roles

        return ASResponse.OK, users_dict

    except SocketError as e:
        raise IOError("Error: %s" % str(e))

@logthis('asadm', DEBUG)
def query_users(sock):
    return _query_users(sock)

@logthis('asadm', DEBUG)
def query_user(sock, user):
    return _query_users(sock, user)

@logthis('asadm', DEBUG)
def create_role(sock, role, privileges=None, whitelist=None):
    """Attempts to create a role in AS with certain privleges and whitelist.
    role: string,
    privileges: list[string]
    whitelist: list[string] of addresses
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(role)
    pack_privileges = privileges is not None and len(privileges)
    pack_whitelist = whitelist is not None and len(whitelist)

    if pack_privileges:
        field_count += 1
        admin_data_size +=  _len_privileges(privileges)

    if pack_whitelist:
        whitelist = ','.join(whitelist)
        field_count += 1
        admin_data_size += len(whitelist)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.CREATE_ROLE, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

    if pack_privileges:
        offset = _pack_admin_field(send_buf, offset, ASField.PRIVILEGES, privileges)

    if pack_whitelist:
        offset = _pack_admin_field(send_buf, offset, ASField.WHITELIST, whitelist)

    _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)

    return return_code

@logthis('asadm', DEBUG)
def delete_role(sock, role):
    """Attempts to delete a role in AS.
    role: string,
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(role)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.DELETE_ROLE, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

    _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)

    return return_code

@logthis('asadm', DEBUG)
def add_privileges(sock, role, privileges):
    """Attempts to add privleges to a role in AS.
    role: string,
    privileges: list[string]
    Returns: ASResponse
    """
    field_count = 2
    admin_data_size = len(role) + _len_privileges(privileges)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.ADD_PRIVLEGES, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)
    offset = _pack_admin_field(send_buf, offset, ASField.PRIVILEGES, privileges)

    _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
    return return_code

@logthis('asadm', DEBUG)
def delete_privileges(sock, role, privileges):
    """Attempts to remove privleges to a role in AS.
    role: string,
    privileges: list[string]
    Returns: ASResponse
    """
    field_count = 2
    admin_data_size = len(role) + _len_privileges(privileges)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.DELETE_PRIVLEGES, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)
    offset = _pack_admin_field(send_buf, offset, ASField.PRIVILEGES, privileges)

    _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
    return return_code

def _set_whitelist(sock, role, whitelist=None):
    """Attempts to add a whitelist to a role in AS.
    role: string,
    privileges: list[string] of addresses
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(role)

    if whitelist is not None:
        whitelist = ','.join(whitelist)
        field_count += 1
        admin_data_size += len(whitelist)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.SET_WHITELIST, field_count)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

    if whitelist is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.WHITELIST, whitelist)

    _, return_code, _, _, _ = _send_and_get_admin_header(sock, send_buf)
    
    return return_code

@logthis('asadm', DEBUG)
def set_whitelist(sock, role, whitelist):
    return _set_whitelist(sock, role, whitelist)

@logthis('asadm', DEBUG)
def delete_whitelist(sock, role):
    return _set_whitelist(sock, role)

def _query_role(sock, role=None):
    """Attempts to query roles and respective privileges from Afield_count: string or None, If none queries all users.
    Returns: ASResponse, {role_name: [privleges: ASPrivilege]}
    """
    role_dict = {}
    field_count = 0
    admin_data_size = 0

    if role is not None:
        field_count += 1
        admin_data_size = len(role)

    send_buf, offset = _create_admin_header(admin_data_size, ASCommand.QUERY_ROLES, field_count)

    if role is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

        # OpenSSL wrapper doesn't support ctypes
        send_buf = _c_str_to_bytes(send_buf)

    try:
        sock.sendall(send_buf)
        rsp_buf = _receive_data(sock, _PROTOCOL_HEADER_SIZE)
        _, _, data_size, _ = _unpack_protocol_header(rsp_buf)
        rsp_buf = _receive_data(sock, data_size)

        offset = 0

        while offset < data_size:
            _, result_code, _, field_count, offset = _unpack_admin_header(rsp_buf, offset)

            if result_code != ASResponse.OK:
                return result_code, role_dict

            role_name = None
            privileges = []
            whitelist = []

            for _ in range(field_count):
                field_len, field_type, offset = _unpack_admin_field_header(rsp_buf, offset)

                if field_type == ASField.USER:
                    role_name, offset = _unpack_string(rsp_buf, offset, field_len)

                    if role_name not in role_dict:
                        role_dict[role_name] = role_name

                elif field_type == ASField.ROLES:
                    roles, offset = _unpack_admin_roles(rsp_buf, offset)
                    privileges.append(roles)
                elif field_type == ASField.WHITELIST:
                    white, offset = _unpack_string(rsp_buf, offset, field_len)
                    whitelist = white.decode('utf-8').split(',')
                else:
                    offset += field_len

            if role_name is None:
                continue

            role_dict[role_name]['privileges'] = privileges
            role_dict[role_name]['whitelist'] = whitelist

        return ASResponse.OK, role_dict

    except SocketError as e:
        raise IOError("Error: %s" % str(e))

@logthis('asadm', DEBUG)
def query_roles(sock):
    return _query_role(sock)

@logthis('asadm', DEBUG)
def query_role(sock, role):
    return _query_role(sock, role)

def _parse_session_info(data, field_count):
    i = 0
    offset = 0
    session_token = None
    session_ttl = None
    while i < field_count:
        field_len, field_id = _STRUCT_FIELD_HEADER.unpack_from(data, offset)
        field_len -= 1
        offset += _STRUCT_FIELD_HEADER.size

        if field_id == ASField.SESSION_TOKEN:
            fmt_str = "%ds" % field_len
            session_token = struct.unpack_from(fmt_str, data, offset)[0]

        elif field_id == ASField.SESSION_TTL:
            fmt_str = ">I"
            session_ttl = struct.unpack_from(fmt_str, data, offset)[0]

        offset += field_len
        i += 1

    return session_token, session_ttl

def login(sock, user, password, auth_mode):
    user = str_to_bytes(user) # bytes for c_struct packing
    password = str_to_bytes(password) # bytes for c_struct packing
    credential = _hash_password(password)

    if auth_mode == AuthMode.INTERNAL:
        field_count = 2
        # 4B = field size, 1B = filed type
        admin_data_size = len(user) + len(credential)
        send_buf, offset = _create_admin_header(admin_data_size, ASCommand.LOGIN, field_count)
        offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
        offset = _pack_admin_field(send_buf, offset, ASField.CREDENTIAL, credential)
    else:
        field_count = 3
        # 4B = field size, 1B = filed type
        admin_data_size = len(user) + len(credential) + len(password)
        send_buf, offset = _create_admin_header(admin_data_size, ASCommand.LOGIN, field_count)
        offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
        offset = _pack_admin_field(send_buf, offset, ASField.CREDENTIAL, credential)
        offset = _pack_admin_field(send_buf, offset, ASField.CLEAR_PASSWORD, password)

    try:
        # OpenSSL wrapper doesn't support ctypes
        send_buf = _c_str_to_bytes(send_buf)

        sock.sendall(send_buf)
        recv_buff = _receive_data(sock, _PROTOCOL_HEADER_SIZE + _ADMIN_HEADER_SIZE)
        _, _, data_size, offset = _unpack_protocol_header(recv_buff)
        _, return_code, _, field_count, _ = _unpack_admin_header(recv_buff)
        data_size -= _ADMIN_HEADER_SIZE

        if return_code != ASResponse.OK:
            # login failed

            if return_code == ASResponse.INVALID_COMMAND:
                # login is invalid command, so cluster does not support ldap
                return authenticate_old(sock, user, password), None, 0

            # login failed
            return return_code, None, 0

        if data_size < 0 or field_count < 1:
            raise IOError("Login failed to retrieve session token")
        recv_buff = _receive_data(sock, data_size)
        session_token, session_ttl = _parse_session_info(recv_buff, field_count)
        session_token = _c_str_to_bytes(session_token)

        if session_ttl is None:
            session_expiration = 0
        else:
            # Subtract 60 seconds from ttl so asadm session expires before server session.
            session_expiration = time() + session_ttl - 60

        return 0, session_token, session_expiration

    except SocketError as e:
        raise IOError("Error: %s" % str(e))


###############################

##### aerospike info call #####

_INFO_MSG_VERSION = 2
_INFO_MSG_TYPE = 1

def _pack_info_field(buf, offset, field):
    field += '\n'
    return _pack_string(buf, offset, field)

def _info_request(sock, buf):
    rsp_data = None
    # request over TCP
    try:
        sock.send(buf)
        # get response
        rsp_hdr = sock.recv(8)
        _, _, data_size, _ = _unpack_protocol_header(rsp_hdr)

        if data_size > 0:
            rsp_data = _receive_data(sock, data_size)

    except Exception as ex:
        raise IOError("Error: %s" % str(ex))

    # parse out responses
    if data_size == 0:
        return None

    return(rsp_data)


def info(sock, names=None):
    if not sock:
        raise IOError("Error: Could not connect to node")
    buf = None
    # Passed a set of names: created output buf
    if names is None:
        buf = create_string_buffer(_PROTOCOL_HEADER_SIZE)
        _pack_protocol_header(buf, 0, _INFO_MSG_VERSION, _INFO_MSG_TYPE, 0)

    elif isinstance(names, str):
        buf_size = _PROTOCOL_HEADER_SIZE + len(names) + 1 # for \n
        buf = create_string_buffer(buf_size)
        offset = 0

        offset = _pack_protocol_header(buf, offset, _INFO_MSG_VERSION, _INFO_MSG_TYPE, len(names) + 1)
        offset = _pack_info_field(buf, offset, names)
    else:
        namestr = "\n".join(names)
        buf_size = _PROTOCOL_HEADER_SIZE + len(namestr) + 1 # for \n
        buf = create_string_buffer(buf_size)
        offset = 0

        offset = _pack_protocol_header(buf, offset, _INFO_MSG_VERSION, _INFO_MSG_TYPE, len(namestr) + 1)
        offset = _pack_info_field(buf, offset, namestr)

    rsp_data = _info_request(sock, buf)
    rsp_data = bytes_to_str(rsp_data)

    if rsp_data == -1 or rsp_data is None:
        return -1

    # if the original request was a single string, return a single string
    if isinstance(names, str):
        lines = rsp_data.split("\n")
        name, sep, value = lines[0].partition("\t")

        if name != names:
            print(" problem: requested name ", names, " got name ", name)
            return(-1)
        return value

    else:
        rdict = dict()
        for line in rsp_data.split("\n"):
            if len(line) < 1:
                # this accounts for the trailing '\n' - cheaper than chomp
                continue
            name, sep, value = line.partition("\t")
            rdict[name] = value
        return rdict

###############################
      