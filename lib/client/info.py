#!/bin/sh
""":"
for interp in python3 python python2 ; do
   command -v > /dev/null "$interp" && exec "$interp" "$0" "$@"
done
echo >&2 "No Python interpreter found!"
exit 1
":"""
####
#
# Copyright 2013-2018 Aerospike, Inc.
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
# Aerospike python library
#
#

import sys
import struct
from ctypes import create_string_buffer		 # gives us pre-allocated buffers
from time import time
import types

try:
    import bcrypt
    hasbcrypt = True
except:
    # bcrypt not installed. This should only be
    # fatal when authentication is required.
    hasbcrypt = False

from lib.utils.constants import AuthMode

#
# COMPATIBILITY COMPATIBILITY COMPATIBILITY
#
# So the 'struct' class went through lots of (good) improvements in
# 2.5, but we want to support old use as well as new. Write a few
# functions similar to the 2.5 ones, and either use builtin or
# pure based on what's available
#


def my_unpack_from(fmt_str, buf, offset):
    sz = struct.calcsize(fmt_str)
    return struct.unpack(fmt_str, buf[offset:offset + sz])


def my_pack_into(fmt_str, buf, offset, *args):
    tmp_array = struct.pack(fmt_str, *args)
    buf[offset:offset + len(tmp_array)] = tmp_array

# 2.5+ has this nice partition call


def partition_25(s, sep):
    return(s.partition(sep))

# 2.4- doesn't


def partition_old(s, sep):
    idx = s.find(sep)
    if idx == -1:
        return(s, "", "")
    return(s[:idx], sep, s[idx + 1:])

admin_header_fmt = '! Q B B B B 12x'
proto_header_fmt = '! Q'

g_proto_header = None
g_partition = None
g_struct_admin_header_in = None
g_struct_admin_header_out = None

# 2.5, this will succeed
try:
    g_proto_header = struct.Struct(proto_header_fmt)
    g_struct_admin_header_in = struct.Struct(admin_header_fmt)
    g_struct_admin_header_out = struct.Struct(admin_header_fmt)
    g_partition = partition_25

# pre 2.5, if there's no Struct submember, so use my workaround pack/unpack
except:
    struct.unpack_from = my_unpack_from
    struct.pack_into = my_pack_into
    g_partition = partition_old


def _receivedata(sock, sz):
    pos = 0
    while pos < sz:
        chunk = sock.recv(sz - pos)
        if pos == 0:
            data = chunk
        else:
            data += chunk
        pos += len(chunk)
    return data

####### Password hashing ######

def _hashpassword(password):
    if hasbcrypt == False:
        print "Authentication failed: bcrypt not installed."
        sys.exit(1)

    if password == None:
        password = ""

    if len(password) != 60 or password.startswith("$2a$") == False:
        password = bcrypt.hashpw(password, "$2a$10$7EqJtq98hPqEX7fNZaFWoO")

    return password

###############################


########### Security ##########

_OK = 0
_INVALID_COMMAND = 54

_ADMIN_MSG_VERSION = 0
_ADMIN_MSG_TYPE = 2

_AUTHENTICATE = 0
_LOGIN = 20

_USER_FIELD_ID = 0
_CREDENTIAL_FIELD_ID = 3
_CLEAR_PASSWORD_FIELD_ID = 4
_SESSION_TOKEN_FIELD_ID = 5
_SESSION_TTL_FIELD_ID = 6

_HEADER_SIZE = 24
_HEADER_REMAINING = 16


def _admin_write_header(sz, command, field_count):
    send_buf = create_string_buffer(sz)      # from ctypes
    sz = (_ADMIN_MSG_VERSION << 56) | (_ADMIN_MSG_TYPE << 48) | (sz - 8)

    if g_struct_admin_header_out != None:
        g_struct_admin_header_out.pack_into(
            send_buf, 0, sz, 0, 0, command, field_count)
    else:
        struct.pack_into(
            admin_header_fmt, send_buf, 0, sz, 0, 0, command, field_count)

    return send_buf


def _admin_parse_header(data):
    if g_struct_admin_header_in != None:
        rv = g_struct_admin_header_in.unpack(data)
    else:
        rv = struct.unpack(admin_header_fmt, data)

    return rv


def _parse_session_info(data, field_count):
    i = 0
    offset = 0
    session_token = None
    session_ttl = None
    while i < field_count:
        field_len, field_id = struct.unpack_from("! I B", data, offset)
        field_len -= 1
        offset += 5

        if field_id == _SESSION_TOKEN_FIELD_ID:
            fmt_str = "%ds" % field_len
            session_token = struct.unpack_from(fmt_str, data, offset)[0]

        elif field_id == _SESSION_TTL_FIELD_ID:
            fmt_str = ">I"
            session_ttl = struct.unpack_from(fmt_str, data, offset)[0]

        offset += field_len
        i += 1

    return session_token, session_ttl



def _buffer_to_string(buf):
    buf_str = ""
    for s in buf:
        buf_str += s
    return buf_str


def _authenticate(sock, user, password, password_field_id):
    sz = len(user) + len(password) + 34 # 2 * 5 + 24
    send_buf = _admin_write_header(sz, _AUTHENTICATE, 2)
    fmt_str = "! I B %ds I B %ds" % (len(user), len(password))
    struct.pack_into(fmt_str, send_buf, _HEADER_SIZE,
                     len(user) + 1, _USER_FIELD_ID, user,
                     len(password) + 1, password_field_id, password)
    try:
        # OpenSSL wrapper doesn't support ctypes
        send_buf = _buffer_to_string(send_buf)
        sock.sendall(send_buf)
        recv_buff = _receivedata(sock, _HEADER_SIZE)
        rv = _admin_parse_header(recv_buff)
        return rv[2]
    except Exception as ex:
        raise IOError("Error: %s" % str(ex))

def authenticate_new(sock, user, session_token):
    return _authenticate(sock, user, password=session_token, password_field_id=_SESSION_TOKEN_FIELD_ID)

def authenticate_old(sock, user, password):
    return _authenticate(sock, user, password=_hashpassword(password), password_field_id=_CREDENTIAL_FIELD_ID)

def login(sock, user, password, auth_mode):
    credential = _hashpassword(password)

    if auth_mode == AuthMode.INTERNAL:
        sz = len(user) + len(credential) + 34 # 2 * 5 + 24
        send_buf = _admin_write_header(sz, _LOGIN, 2)
        fmt_str = "! I B %ds I B %ds" % (len(user), len(credential))
        struct.pack_into(fmt_str, send_buf, _HEADER_SIZE,
                         len(user) + 1, _USER_FIELD_ID, user,
                         len(credential) + 1, _CREDENTIAL_FIELD_ID, credential)

    else:
        sz = len(user) + len(credential) + len(password) + 39  # 3 * 5 + 24
        send_buf = _admin_write_header(sz, _LOGIN, 3)
        fmt_str = "! I B %ds I B %ds I B %ds" % (len(user), len(credential), len(password))
        struct.pack_into(fmt_str, send_buf, _HEADER_SIZE,
                         len(user) + 1, _USER_FIELD_ID, user,
                         len(credential) + 1, _CREDENTIAL_FIELD_ID, credential,
                         len(password) + 1, _CLEAR_PASSWORD_FIELD_ID, password)

    try:
        # OpenSSL wrapper doesn't support ctypes
        send_buf = _buffer_to_string(send_buf)
        sock.sendall(send_buf)
        recv_buff = _receivedata(sock, _HEADER_SIZE)
        rv = _admin_parse_header(recv_buff)

        result = rv[2]
        if result != _OK:
            # login failed

            if result == _INVALID_COMMAND:
                # login is invalid command, so cluster does not support ldap
                return authenticate_old(sock, user, password), None, 0

            # login failed
            return result, None, 0

        sz = int(rv[0] & 0xFFFFFFFFFFFF) - _HEADER_REMAINING
        field_count = rv[4]
        if sz < 0 or field_count < 1:
            raise IOError("Login failed to retrieve session token")

        recv_buff = _receivedata(sock, sz)
        session_token, session_ttl = _parse_session_info(recv_buff, field_count)
        session_token = _buffer_to_string(session_token)

        if session_ttl is None:
            session_expiration = 0
        else:
            # Subtract 60 seconds from ttl so asadm session expires before server session.
            session_expiration = time() + session_ttl - 60

        return 0, session_token, session_expiration

    except Exception as ex:
        raise IOError("Error: %s" % str(ex))




###############################

##### aerospike info call #####

_INFO_MSG_VERSION = 2
_INFO_MSG_TYPE = 1

def _info_request(sock, buf):

    # request over TCP
    try:
        sock.send(buf)
        # get response
        rsp_hdr = sock.recv(8)
        q = struct.unpack_from(proto_header_fmt, rsp_hdr, 0)
        sz = q[0] & 0xFFFFFFFFFFFF
        if sz > 0:
            rsp_data = _receivedata(sock, sz)
    except Exception as ex:
        raise IOError("Error: %s" % str(ex))

    # parse out responses
    if sz == 0:
        return None

    return(rsp_data)


def info(sock, names=None):
    if not sock:
        raise IOError("Error: Could not connect to node")
    # Passed a set of names: created output buffer

    if names == None:
        q = (_INFO_MSG_VERSION << 56) | (_INFO_MSG_TYPE << 48)
        if g_proto_header != None:
            buf = g_proto_header.pack(q)
        else:
            buf = struct.pack(proto_header_fmt, q)

    elif type(names) == types.StringType:
        q = (_INFO_MSG_VERSION << 56) | (_INFO_MSG_TYPE << 48) | (len(names) + 1)
        fmt_str = "! Q %ds B" % len(names)
        buf = struct.pack(fmt_str, q, names, 10)

    else:  # better be iterable of strings
        # annoyingly, join won't post-pend a seperator. So make a new list
        # with all the seps in
        names_l = []
        for name in names:
            names_l.append(name)
            names_l.append("\n")
        namestr = "".join(names_l)
        q = (_INFO_MSG_VERSION << 56) | (_INFO_MSG_TYPE << 48) | (len(namestr))
        fmt_str = "! Q %ds" % len(namestr)
        buf = struct.pack(fmt_str, q, namestr)

    rsp_data = _info_request(sock, buf)

    if rsp_data == -1 or rsp_data is None:
        return -1

    # if the original request was a single string, return a single string
    if type(names) == types.StringType:
        lines = rsp_data.split("\n")
        name, sep, value = g_partition(lines[0], "\t")

        if name != names:
            print " problem: requested name ", names, " got name ", name
            return(-1)
        return value

    else:
        rdict = dict()
        for line in rsp_data.split("\n"):
            if len(line) < 1:
                # this accounts for the trailing '\n' - cheaper than chomp
                continue
            name, sep, value = g_partition(line, "\t")
            rdict[name] = value
        return rdict

###############################
