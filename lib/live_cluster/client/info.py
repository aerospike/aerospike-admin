####
#
# Copyright 2013-2021 Aerospike, Inc.
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

import asyncio
import logging
import sys
import struct
from ctypes import create_string_buffer  # gives us pre-allocated bufs
from time import time
from socket import error as SocketError

from .types import (
    ASField,
    ASInfoNotAuthenticatedError,
    ASResponse,
    ASCommand,
    ASPrivilege,
)
from lib.utils import util, constants

try:
    import bcrypt

    hasbcrypt = True
except Exception:
    # bcrypt not installed. This should only be
    # fatal when authentication is required.
    hasbcrypt = False

logger = logging.getLogger("asadm")


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

_STRUCT_PROTOCOL_HEADER = struct.Struct("! B B 3H")
_STRUCT_UINT8 = struct.Struct("! B")
_STRUCT_UINT32 = struct.Struct("! I")
_STRUCT_FIELD_HEADER = struct.Struct("! I B")
_STRUCT_ADMIN_HEADER = struct.Struct("! B B B B 12x")

_PROTOCOL_HEADER_SIZE = _STRUCT_PROTOCOL_HEADER.size


def _pack_uint8(buf, offset, val):
    _STRUCT_UINT8.pack_into(buf, offset, val)
    offset += _STRUCT_UINT8.size
    return offset


def _unpack_uint8(buf, offset):
    val = _STRUCT_UINT8.unpack_from(buf, offset)
    offset += _STRUCT_UINT8.size
    return val[0], offset


def _pack_uint32(buf, offset, val):
    _STRUCT_UINT32.pack_into(buf, offset, val)
    offset += _STRUCT_UINT32.size
    return offset


def _unpack_uint32(buf, offset):
    val = _STRUCT_UINT32.unpack_from(buf, offset)
    offset += _STRUCT_UINT32.size
    return val[0], offset


def _pack_string(buf, offset, string):
    bytes_field = util.str_to_bytes(string)
    buf[offset : offset + len(bytes_field)] = bytes_field
    return offset + len(bytes_field)


def _unpack_string(buf, offset, sz):
    val = buf[offset : offset + sz]
    offset += sz
    return val.decode("utf-8"), offset


def _pack_protocol_header(buf, offset, protocol_version, protocol_type, sz):
    _STRUCT_PROTOCOL_HEADER.pack_into(
        buf,
        offset,
        protocol_version,
        protocol_type,
        (sz >> 32) & 0xFFFF,
        (sz >> 16) & 0xFFFF,
        sz & 0xFFFF,
    )
    return offset + _PROTOCOL_HEADER_SIZE


def _unpack_protocol_header(buf, offset=0):
    protocol_header = _STRUCT_PROTOCOL_HEADER.unpack_from(buf, offset=offset)
    protocol_version = protocol_header[0]
    protocol_type = protocol_header[1]
    data_size = (
        (protocol_header[2] << 32) | (protocol_header[3] << 16) | protocol_header[4]
    )
    offset = _PROTOCOL_HEADER_SIZE
    return protocol_version, protocol_type, data_size, offset


async def _receive_data(reader: asyncio.StreamReader, sz):
    pos = 0
    data = None
    while pos < sz:
        chunk = await reader.read(sz - pos)
        if pos == 0:
            data = chunk
        else:
            data += chunk
        pos += len(chunk)

    return data


####### Password hashing ######


def _hash_password(password):
    if isinstance(password, str):
        password = password.encode("utf-8")

    if hasbcrypt is False:
        print("Authentication failed: bcrypt not installed.")
        sys.exit(1)

    if password is None:
        password = ""

    password = bcrypt.hashpw(password, _ADMIN_SALT)

    return password


###############################


########### Security ##########

_ADMIN_SALT = b"$2a$10$7EqJtq98hPqEX7fNZaFWoO"
_ADMIN_MSG_VERSION = 0
_ADMIN_MSG_TYPE = 2

_ADMIN_HEADER_SIZE = _STRUCT_ADMIN_HEADER.size
_TOTAL_HEADER_SIZE = _PROTOCOL_HEADER_SIZE + _ADMIN_HEADER_SIZE

READ_WRITE_INFO_VALUES = [
    "quota",
    "single-record-tps",
    "scan-query-rps-limited",
    "scan-query-limitless",
]


def _pack_admin_header(buf, offset, scheme, result, command, n_fields):
    _STRUCT_ADMIN_HEADER.pack_into(buf, offset, scheme, result, command.value, n_fields)
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
    # 4B = field size, 1B = field type
    protocol_data_size = (
        sz + _ADMIN_HEADER_SIZE + (_STRUCT_FIELD_HEADER.size * field_count)
    )
    buffer_size = protocol_data_size + _PROTOCOL_HEADER_SIZE
    buf = create_string_buffer(buffer_size)
    offset = _pack_protocol_header(
        buf, 0, _ADMIN_MSG_VERSION, _ADMIN_MSG_TYPE, protocol_data_size
    )
    offset = _pack_admin_header(
        buf, offset, _ADMIN_MSG_VERSION, 0, command, field_count
    )
    return buf, offset


def _pack_admin_field_header(buf, offset, field_len, field_type):
    """Packs the first 5 bytes in front of every admin field.
    field_len = is the size of the "Value" field. Does not include "Type" or
    "Length".
    """
    _STRUCT_FIELD_HEADER.pack_into(buf, offset, field_len + 1, field_type.value)
    offset += _STRUCT_FIELD_HEADER.size
    return offset


def _unpack_admin_field_header(buf, offset):
    field_len, field_type = _STRUCT_FIELD_HEADER.unpack_from(buf, offset)
    offset += _STRUCT_FIELD_HEADER.size
    return field_len, field_type, offset


def _pack_admin_field(buf, offset, as_field, field):

    # _pack_string() will convert str to bytes, no need to handle here.
    if as_field in {ASField.READ_QUOTA, ASField.WRITE_QUOTA}:
        if isinstance(field, str):
            try:
                field = int(field)
            except ValueError:
                raise TypeError(
                    "_pack_admin_field: Field ID {} could not cast str {} to int".format(
                        as_field, field
                    )
                )

        field_len = _STRUCT_UINT32.size
        offset = _pack_admin_field_header(buf, offset, field_len, as_field)
        offset = _pack_uint32(buf, offset, field)
    elif isinstance(field, str) or isinstance(field, bytes):
        field_len = len(field)
        offset = _pack_admin_field_header(buf, offset, field_len, as_field)
        offset = _pack_string(buf, offset, field)
    elif isinstance(field, list):
        if as_field == ASField.ROLES:
            offset = _pack_admin_roles(buf, offset, field)
        elif as_field == ASField.PRIVILEGES:
            offset = _pack_admin_privileges(buf, offset, field)
        else:
            raise TypeError(
                "_pack_admin_field: Field ID {} does not accept lists".format(as_field)
            )
    else:
        raise TypeError(
            "_pack_admin_field: Unhandled field type: {}".format(type(field))
        )

    return offset


def _len_roles(roles):
    # 1B = role_count
    field_len = 1
    for role in roles:
        # 1B = role_name_size
        field_len += len(role) + 1

    return field_len


def _pack_admin_roles(buf, offset, roles):
    field_len = _len_roles(roles)
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
    split_privilege = privilege.split(".")
    permission = ASPrivilege.str_to_enum(split_privilege[0])
    namespace = ""
    set_ = ""

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

        if not ASPrivilege(permission).is_global_only_scope():
            # 1B = namespace name len
            field_len += 1
            field_len += len(namespace)
            # 1B = set name len
            field_len += 1
            field_len += len(set_)

    return field_len


def _pack_admin_privileges(buf, offset, privileges):
    privilege_count = len(privileges)
    field_len = _len_privileges(privileges)

    offset = _pack_admin_field_header(buf, offset, field_len, ASField.PRIVILEGES)
    offset = _pack_uint8(buf, offset, privilege_count)

    for privilege in privileges:

        permission, namespace, set_ = _parse_privilege(privilege)
        offset = _pack_uint8(buf, offset, permission.value)

        if not ASPrivilege(permission).is_global_only_scope():
            offset = _pack_uint8(buf, offset, len(namespace))
            offset = _pack_string(buf, offset, namespace)
            offset = _pack_uint8(buf, offset, len(set_))
            offset = _pack_string(buf, offset, set_)

    return offset


def _unpack_admin_privileges(buf, offset):
    num_privileges, offset = _unpack_uint8(buf, offset)
    privileges = []

    for _ in range(num_privileges):
        permission_code, offset = _unpack_uint8(buf, offset)
        privilege = ASPrivilege(permission_code)
        privilege_str = [str(privilege)]

        if not privilege.is_global_only_scope():
            namespace_len, offset = _unpack_uint8(buf, offset)
            namespace, offset = _unpack_string(buf, offset, namespace_len)
            set_len, offset = _unpack_uint8(buf, offset)
            set_, offset = _unpack_string(buf, offset, set_len)

            if namespace:
                privilege_str.append(namespace)

                if set_:
                    privilege_str.append(set_)

        privilege_str = ".".join(privilege_str)
        privileges.append(privilege_str)

    return privileges, offset


def _unpack_admin_read_write_info(buf, offset):
    num_stat, offset = _unpack_uint8(buf, offset)
    stats = []

    for _ in range(num_stat):
        stat, offset = _unpack_uint32(buf, offset)
        stats.append(stat)

    return stats, offset


def _c_str_to_bytes(buf):
    return bytes(buf)


async def _send_and_get_admin_header(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, send_buf
):
    # OpenSSL wrapper doesn't support ctypes
    send_buf = _c_str_to_bytes(send_buf)

    try:
        writer.write(send_buf)
        await writer.drain()
        recv_buf = await _receive_data(reader, _TOTAL_HEADER_SIZE)
        rsp_header = _unpack_admin_header(recv_buf, _PROTOCOL_HEADER_SIZE)
    except SocketError as e:
        raise IOError("Error: %s" % str(e))

    return rsp_header


async def _authenticate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    user,
    password,
    password_field_id,
    auth_mode,
):
    if auth_mode != constants.AuthMode.PKI:
        field_count = 2
        admin_data_size = len(user) + len(password)

        send_buf, offset = _create_admin_header(
            admin_data_size, ASCommand.AUTHENTICATE, field_count
        )

        offset = _pack_admin_field(send_buf, offset, ASField.USER, user)

    else:
        field_count = 1
        admin_data_size = len(password)

        send_buf, offset = _create_admin_header(
            admin_data_size, ASCommand.AUTHENTICATE, field_count
        )

    offset = _pack_admin_field(send_buf, offset, password_field_id, password)

    try:
        # OpenSSL wrapper doesn't support ctypes
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except Exception as e:
        import traceback

        traceback.print_exc()
        raise IOError("Error: %s" % str(e))


async def authenticate_new(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    user,
    session_token,
    auth_mode,
):
    return await _authenticate(
        reader,
        writer,
        user,
        password=session_token,
        password_field_id=ASField.SESSION_TOKEN,
        auth_mode=auth_mode,
    )


async def authenticate_old(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    user,
    password,
    auth_mode,
):
    return await _authenticate(
        reader,
        writer,
        user,
        password=_hash_password(password),
        password_field_id=ASField.CREDENTIAL,
        auth_mode=auth_mode,
    )


# roles is a list of strings representing role names.
async def create_user(reader, writer, user, password, roles):
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
    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.CREATE_USER, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.PASSWORD, hashed_password)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLES, roles)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except Exception as e:
        raise IOError("Error: %s" % str(e))


async def drop_user(reader, writer, user):
    """Attempts to delete a user in AS.
    user: string,
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(user)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.DROP_USER, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except Exception as e:
        raise IOError("Error: %s" % str(e))


async def set_password(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, user, password
):
    """Attempts to set a user password in AS.
    user: string,
    password: string (un-hashed),
    Returns: ASResponse
    """
    field_count = 2
    hashed_password = _hash_password(password)
    admin_data_size = len(user) + len(hashed_password)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.SET_PASSWORD, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.PASSWORD, hashed_password)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def change_password(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    user,
    old_password,
    new_password,
):
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

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.CHANGE_PASSWORD, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(
        send_buf, offset, ASField.OLD_PASSWORD, hashed_old_password
    )
    offset = _pack_admin_field(send_buf, offset, ASField.PASSWORD, hashed_new_password)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


# roles is a list of strings representing role names.
async def grant_roles(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, user, roles
):
    """Attempts to grant roles to user in AS.
    user: string,
    roles: list[string],
    Returns: ASResponse
    """
    field_count = 2
    admin_data_size = len(user) + _len_roles(roles)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.GRANT_ROLES, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLES, roles)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


# roles is a list of strings representing role names.
async def revoke_roles(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, user, roles
):
    """Attempts to remove roles from a user in AS.
    user: string,
    roles: list[string],
    Returns: ASResponse
    """
    field_count = 2
    admin_data_size = len(user) + _len_roles(roles)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.REVOKE_ROLES, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
    offset = _pack_admin_field(send_buf, offset, ASField.ROLES, roles)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def _query_users(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, user=None
):
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

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.QUERY_USERS, field_count
    )

    if user is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.USER, user)

    # OpenSSL wrapper doesn't support ctypes
    send_buf = _c_str_to_bytes(send_buf)

    try:
        writer.write(send_buf)
        await writer.drain()

        while True:
            rsp_buf = await _receive_data(reader, _PROTOCOL_HEADER_SIZE)
            _, _, data_size, _ = _unpack_protocol_header(rsp_buf)
            rsp_buf = await _receive_data(reader, data_size)
            offset = 0

            # Each loop will process a user:role pair.
            while offset < data_size:
                _, result_code, _, field_count, offset = _unpack_admin_header(
                    rsp_buf, offset
                )

                if result_code != ASResponse.OK:
                    if result_code == ASResponse.QUERY_END:
                        result_code = ASResponse.OK

                    return result_code, users_dict

                user_name = None
                user_roles = []
                read_info = None
                write_info = None
                connections = None

                for _ in range(field_count):
                    field_len, field_type, offset = _unpack_admin_field_header(
                        rsp_buf, offset
                    )
                    field_len -= 1

                    if field_type == ASField.USER:
                        user_name, offset = _unpack_string(rsp_buf, offset, field_len)

                        if user_name not in users_dict:
                            users_dict[user_name] = {}

                    elif field_type == ASField.ROLES:
                        roles, offset = _unpack_admin_roles(rsp_buf, offset)
                        user_roles.extend(roles)

                    elif field_type == ASField.READ_INFO:
                        read_info, offset = _unpack_admin_read_write_info(
                            rsp_buf, offset
                        )
                    elif field_type == ASField.WRITE_INFO:
                        write_info, offset = _unpack_admin_read_write_info(
                            rsp_buf, offset
                        )
                    elif field_type == ASField.CONNECTIONS:
                        connections, offset = _unpack_uint32(rsp_buf, offset)
                    else:
                        offset += field_len

                if user_name is None:
                    continue

                users_dict[user_name]["roles"] = user_roles

                if read_info:
                    # The precedent is for everything returned to be strings
                    users_dict[user_name]["read-info"] = {}

                    for name, value in zip(READ_WRITE_INFO_VALUES, read_info):
                        users_dict[user_name]["read-info"][name] = value

                if write_info:
                    users_dict[user_name]["write-info"] = {}

                    for name, value in zip(READ_WRITE_INFO_VALUES, write_info):
                        users_dict[user_name]["write-info"][name] = value

                if connections:
                    users_dict[user_name]["connections"] = connections

    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def query_users(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    return await _query_users(reader, writer)


async def query_user(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, user):
    return await _query_users(reader, writer, user)


async def create_role(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    role,
    privileges=None,
    whitelist=None,
    read_quota=None,
    write_quota=None,
):
    """Attempts to create a role in AS with certain privleges and whitelist. Either
    privilege or whitelist should be provided.
    role: string,
    privileges: list[string]
    whitelist: list[string] of addresses
    read_quota: string or int
    write_quota: string or int
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(role)
    pack_privileges = privileges is not None and len(privileges)
    pack_whitelist = whitelist is not None and len(whitelist)

    if pack_privileges:
        field_count += 1
        admin_data_size += _len_privileges(privileges)

    if pack_whitelist:
        whitelist = ",".join(whitelist)
        field_count += 1
        admin_data_size += len(whitelist)

    if read_quota is not None:
        field_count += 1
        admin_data_size += _STRUCT_UINT32.size

    if write_quota is not None:
        field_count += 1
        admin_data_size += _STRUCT_UINT32.size

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.CREATE_ROLE, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

    if pack_privileges:
        offset = _pack_admin_field(send_buf, offset, ASField.PRIVILEGES, privileges)

    if pack_whitelist:
        offset = _pack_admin_field(send_buf, offset, ASField.WHITELIST, whitelist)

    if read_quota is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.READ_QUOTA, read_quota)

    if write_quota is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.WRITE_QUOTA, write_quota)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def delete_role(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role):
    """Attempts to delete a role in AS.
    role: string,
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(role)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.DELETE_ROLE, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def add_privileges(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role, privileges
):
    """Attempts to add privleges to a role in AS.
    role: string,
    privileges: list[string]
    Returns: ASResponse
    """
    field_count = 2
    admin_data_size = len(role) + _len_privileges(privileges)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.ADD_PRIVLEGES, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)
    offset = _pack_admin_field(send_buf, offset, ASField.PRIVILEGES, privileges)

    _, return_code, _, _, _ = await _send_and_get_admin_header(reader, writer, send_buf)
    return return_code


async def delete_privileges(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role, privileges
):
    """Attempts to remove privleges to a role in AS.
    role: string,
    privileges: list[string]
    Returns: ASResponse
    """
    field_count = 2
    admin_data_size = len(role) + _len_privileges(privileges)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.DELETE_PRIVLEGES, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)
    offset = _pack_admin_field(send_buf, offset, ASField.PRIVILEGES, privileges)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def _set_whitelist(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role, whitelist=None
):
    """Attempts to add a whitelist to a role in AS.
    role: string,
    privileges: list[string] of addresses
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(role)

    if whitelist is not None:
        whitelist = ",".join(whitelist)
        field_count += 1
        admin_data_size += len(whitelist)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.SET_WHITELIST, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

    if whitelist is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.WHITELIST, whitelist)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def set_whitelist(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role, whitelist
):
    return await _set_whitelist(reader, writer, role, whitelist)


async def delete_whitelist(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role
):
    return await _set_whitelist(reader, writer, role)


async def _set_quotas(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    role,
    read_quota=None,
    write_quota=None,
):
    """Attempts to add a quota to a role in AS.
    role: string,
    read_quota: int or str representing an int,
    write_quota: int or str representing an int,
    Returns: ASResponse
    """
    field_count = 1
    admin_data_size = len(role)

    if read_quota is not None:
        field_count += 1
        admin_data_size += _STRUCT_UINT32.size

    if write_quota is not None:
        field_count += 1
        admin_data_size += _STRUCT_UINT32.size

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.SET_RATE_QUOTAS, field_count
    )
    offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

    if read_quota is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.READ_QUOTA, read_quota)

    if write_quota is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.WRITE_QUOTA, write_quota)

    try:
        _, return_code, _, _, _ = await _send_and_get_admin_header(
            reader, writer, send_buf
        )
        return return_code
    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def set_quotas(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    role,
    read_quota=None,
    write_quota=None,
):
    return await _set_quotas(reader, writer, role, read_quota, write_quota)


async def delete_quotas(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    role,
    read_quota=False,
    write_quota=False,
):
    """
    NOT IN USE
    """
    read = None
    write = None

    if read_quota:
        read = 0

    if write_quota:
        write = 0

    return await _set_quotas(reader, writer, role, read, write)


async def _query_role(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role=None
):
    """Attempts to query roles and respective privileges from Afield_count: string or None, If none queries all users.
    Returns: ASResponse, {role_name: [privleges: ASPrivilege]}
    """
    role_dict = {}
    field_count = 0
    admin_data_size = 0

    if role is not None:
        field_count += 1
        admin_data_size = len(role)

    send_buf, offset = _create_admin_header(
        admin_data_size, ASCommand.QUERY_ROLES, field_count
    )

    if role is not None:
        offset = _pack_admin_field(send_buf, offset, ASField.ROLE, role)

    # OpenSSL wrapper doesn't support ctypes
    send_buf = _c_str_to_bytes(send_buf)

    try:
        writer.write(send_buf)
        await writer.drain()

        while True:
            rsp_buf = await _receive_data(reader, _PROTOCOL_HEADER_SIZE)
            _, _, data_size, _ = _unpack_protocol_header(rsp_buf)
            rsp_buf = await _receive_data(reader, data_size)

            offset = 0

            while offset < data_size:
                _, result_code, _, field_count, offset = _unpack_admin_header(
                    rsp_buf, offset
                )

                if result_code != ASResponse.OK:
                    if result_code == ASResponse.QUERY_END:
                        result_code = ASResponse.OK

                    return result_code, role_dict

                role_name = None
                privileges = []
                whitelist = []
                read_quota = None
                write_quota = None

                for _ in range(field_count):
                    field_len, field_type, offset = _unpack_admin_field_header(
                        rsp_buf, offset
                    )
                    field_len -= 1

                    if field_type == ASField.ROLE:
                        role_name, offset = _unpack_string(rsp_buf, offset, field_len)

                        if role_name not in role_dict:
                            role_dict[role_name] = role_name

                    elif field_type == ASField.PRIVILEGES:
                        roles, offset = _unpack_admin_privileges(rsp_buf, offset)
                        privileges.extend(roles)
                    elif field_type == ASField.WHITELIST:
                        white, offset = _unpack_string(rsp_buf, offset, field_len)
                        whitelist = white.split(",")
                    elif field_type == ASField.READ_QUOTA:
                        read_quota, offset = _unpack_uint32(rsp_buf, offset)
                    elif field_type == ASField.WRITE_QUOTA:
                        write_quota, offset = _unpack_uint32(rsp_buf, offset)
                    else:
                        offset += field_len

                if role_name is None:
                    continue

                role_dict[role_name] = {}
                role_dict[role_name]["privileges"] = privileges
                role_dict[role_name]["whitelist"] = whitelist

                if read_quota:
                    # The precedent is for everything returned to be strings
                    role_dict[role_name]["read-quota"] = str(read_quota)

                if write_quota:
                    role_dict[role_name]["write-quota"] = str(write_quota)

    except SocketError as e:
        raise IOError("Error: %s" % str(e))


async def query_roles(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    return await _query_role(reader, writer)


async def query_role(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, role):
    return await _query_role(reader, writer, role)


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


async def login(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    user,
    password,
    auth_mode,
):
    credential = _hash_password(password)

    if auth_mode == constants.AuthMode.INTERNAL:
        field_count = 2
        # 4B = field size, 1B = field type
        admin_data_size = len(user) + len(credential)
        send_buf, offset = _create_admin_header(
            admin_data_size, ASCommand.LOGIN, field_count
        )
        offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
        offset = _pack_admin_field(send_buf, offset, ASField.CREDENTIAL, credential)
    elif auth_mode == constants.AuthMode.PKI:
        field_count = 0
        send_buf, offset = _create_admin_header(0, ASCommand.LOGIN, field_count)
    else:
        field_count = 3
        # 4B = field size, 1B = field type
        admin_data_size = len(user) + len(credential) + len(password)
        send_buf, offset = _create_admin_header(
            admin_data_size, ASCommand.LOGIN, field_count
        )
        offset = _pack_admin_field(send_buf, offset, ASField.USER, user)
        offset = _pack_admin_field(send_buf, offset, ASField.CREDENTIAL, credential)
        offset = _pack_admin_field(send_buf, offset, ASField.CLEAR_PASSWORD, password)

    try:
        # OpenSSL wrapper doesn't support ctypes
        send_buf = _c_str_to_bytes(send_buf)
        writer.write(send_buf)
        await writer.drain()
        recv_buff = await _receive_data(
            reader, _PROTOCOL_HEADER_SIZE + _ADMIN_HEADER_SIZE
        )
        _, _, data_size, offset = _unpack_protocol_header(recv_buff)
        _, return_code, _, field_count, _ = _unpack_admin_header(recv_buff)
        data_size -= _ADMIN_HEADER_SIZE

        if return_code != ASResponse.OK:
            # login failed

            if return_code == ASResponse.INVALID_COMMAND:
                # login is invalid command, so cluster does not support ldap
                return authenticate_old(reader, writer, user, password), None, 0

            # login failed
            return return_code, None, 0

        if data_size < 0 or field_count < 1:
            raise IOError("Login failed to retrieve session token")
        recv_buff = await _receive_data(reader, data_size)
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
    field += "\n"
    return _pack_string(buf, offset, field)


async def _info_request(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, buf
):
    rsp_data = None
    # request over TCP
    try:
        if not isinstance(buf, bytes):
            buf = bytes(buf)  # OpenSSL does not support c-types

        writer.write(buf)
        await writer.drain()
        # get response
        rsp_hdr = await reader.read(8)
        _, _, data_size, _ = _unpack_protocol_header(rsp_hdr)

        if data_size > 0:
            rsp_data = await _receive_data(reader, data_size)

    except Exception as ex:
        raise IOError("Error: %s" % str(ex))

    # parse out responses
    if data_size == 0:
        return None

    return rsp_data


async def info(reader, writer, names=None):
    if not reader or not writer:
        raise IOError("Error: Could not connect to node")
    buf = None
    # Passed a set of names: created output buf
    if names is None:
        buf = create_string_buffer(_PROTOCOL_HEADER_SIZE)
        _pack_protocol_header(buf, 0, _INFO_MSG_VERSION, _INFO_MSG_TYPE, 0)

    elif isinstance(names, str):
        buf_size = _PROTOCOL_HEADER_SIZE + len(names) + 1  # for \n
        buf = create_string_buffer(buf_size)
        offset = 0

        offset = _pack_protocol_header(
            buf, offset, _INFO_MSG_VERSION, _INFO_MSG_TYPE, len(names) + 1
        )
        offset = _pack_info_field(buf, offset, names)
    else:
        namestr = "\n".join(names)
        buf_size = _PROTOCOL_HEADER_SIZE + len(namestr) + 1  # for \n
        buf = create_string_buffer(buf_size)
        offset = 0

        offset = _pack_protocol_header(
            buf, offset, _INFO_MSG_VERSION, _INFO_MSG_TYPE, len(namestr) + 1
        )
        offset = _pack_info_field(buf, offset, namestr)

    rsp_data = await _info_request(reader, writer, buf)
    rsp_data = util.bytes_to_str(rsp_data)

    if rsp_data == -1 or rsp_data is None:
        return -1

    # if the original request was a single string, return a single string
    if isinstance(names, str):
        lines = rsp_data.split("\n")
        name, sep, value = lines[0].partition("\t")

        if name != names:
            if "not authenticated" in name.lower():
                return ASInfoNotAuthenticatedError("Connection failed", name)
            else:
                logger.debug(
                    "Unexpected key %s in info response %s. Expected key: %s",
                    name,
                    lines,
                    names,
                )
        return value

    else:
        rdict = dict()
        for line in rsp_data.split("\n"):
            if "not authenticated" in line.lower():
                return ASInfoNotAuthenticatedError("Connection failed", line)
            if len(line) < 1:
                # this accounts for the trailing '\n' - cheaper than chomp
                continue
            name, sep, value = line.partition("\t")

            if name not in names:
                logger.debug(
                    "Unexpected key %s in info response %s. Exceptable keys: %s",
                    name,
                    line,
                    names,
                )

            rdict[name] = value
        return rdict


###############################
