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

import logging
import socket
import warnings
import asyncio

from .types import ASResponse, ASProtocolError
from .info import (
    add_privileges,
    authenticate_new,
    authenticate_old,
    change_password,
    create_role,
    create_user,
    delete_privileges,
    delete_role,
    delete_whitelist,
    drop_user,
    grant_roles,
    info,
    login,
    query_role,
    query_roles,
    query_user,
    query_users,
    revoke_roles,
    set_password,
    set_quotas,
    delete_quotas,
    set_whitelist,
)
from lib.utils.constants import AuthMode

try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from OpenSSL import SSL
    HAVE_PYOPENSSL = True
except ImportError:
    HAVE_PYOPENSSL = False


class ASSocket:
    logger = logging.getLogger("asadm")

    def __init__(
        self, ip, port, tls_name, user, password, auth_mode, ssl_context, timeout=5
    ):
        self.sock = None
        self.ip = ip
        self.port = port
        self.tls_name = tls_name
        self.user = user
        self.password = password
        self.auth_mode = auth_mode
        self.ssl_context = ssl_context
        self._timeout = timeout

    def _wrap_socket(self, sock, ctx):
        if ctx:
            if HAVE_PYOPENSSL:
                sock = SSL.Connection(ctx, sock)
            else:
                raise ImportError("No module named pyOpenSSL")

        return sock

    def _create_socket_for_addrinfo(self, addrinfo):
        sock = None
        try:
            # sock_info format : (family, socktype, proto, canonname, sockaddr)
            addr_family = addrinfo[0]
            sock_addr = addrinfo[4]

            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)

            sock = self._wrap_socket(sock, self.ssl_context)
            sock.connect(sock_addr)

            if self.ssl_context:
                try:
                    sock.set_app_data(self.tls_name)

                    # timeout on wrapper might give errors
                    sock.setblocking(1)

                    sock.do_handshake()
                except Exception as tlse:
                    print("TLS connection exception: " + str(tlse))
                    if sock:
                        sock.close()
                        sock = None
                    return None

        except Exception:
            sock = None
            pass

        return sock

    def _create_socket(self):

        sock = None
        for addrinfo in socket.getaddrinfo(
            self.ip, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM
        ):
            # for DNS it will try all possible addresses
            try:
                sock = self._create_socket_for_addrinfo(addrinfo)
                if sock:
                    break
            except Exception:
                pass
        return sock

    async def login(self):
        if self.auth_mode != AuthMode.PKI and self.user is None:
            return True

        if not self.sock:
            return False

        resp_code, self.session_token, self.session_expiration = await login(
            self.reader, self.writer, self.user, self.password, self.auth_mode
        )

        if resp_code != ASResponse.OK:
            raise ASProtocolError(resp_code, "Login failed")

        return True

    async def authenticate(self, session_token):
        if self.auth_mode != AuthMode.PKI and self.user is None:
            return True

        if not self.sock:
            return False
        if session_token is None:
            # old authentication
            resp_code = await authenticate_old(
                self.reader, self.writer, self.user, self.password, self.auth_mode
            )
        else:
            # new authentication with session_token
            resp_code = await authenticate_new(
                self.reader, self.writer, self.user, session_token, self.auth_mode
            )

        if resp_code != ASResponse.OK:
            raise ASProtocolError(resp_code, "Unable to authenticate")

        return True

    def get_session_info(self):
        return self.session_token, self.session_expiration

    async def connect(self):
        try:
            self.sock = self._create_socket()
            if not self.sock:
                return False
            self.reader, self.writer = await asyncio.open_connection(sock=self.sock)
        except Exception as e:
            self.logger.debug(e, include_traceback=True)
            return False
        return True

    async def is_connected(self):
        if not self.sock:
            return False

        try:
            result = await self.info("node")

            if result is None or result == -1:
                return False

        except Exception as e:
            self.logger.debug(e, include_traceback=True)
            return False

        return True

    async def close(self):

        if self.sock:
            try:
                self.sock = None
                self.writer.close()
                await self.writer.wait_closed()
                self.writer = None
                self.reader = None
            except Exception:
                pass

        return

    def settimeout(self, timeout):
        self.sock.settimeout(timeout)

    async def info(self, command):
        return await info(self.reader, self.writer, command)

    async def create_user(self, user, password, roles):
        rsp_code = await create_user(self.reader, self.writer, user, password, roles)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to create user")

        return ASResponse.OK

    async def delete_user(self, user):
        rsp_code = await drop_user(self.reader, self.writer, user)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to delete user")

        return ASResponse.OK

    async def set_password(self, user, password):
        rsp_code = await set_password(self.reader, self.writer, user, password)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to set password")

        return ASResponse.OK

    async def change_password(self, user, old_password, new_password):
        rsp_code = await change_password(
            self.reader, self.writer, user, old_password, new_password
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to change password")

        return ASResponse.OK

    async def grant_roles(self, user, roles):
        rsp_code = await grant_roles(self.reader, self.writer, user, roles)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to grant roles")

        return ASResponse.OK

    async def revoke_roles(self, user, roles):
        rsp_code = await revoke_roles(self.reader, self.writer, user, roles)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to revoke roles")

        return ASResponse.OK

    async def query_users(self):
        rsp_code, users_dict = await query_users(self.reader, self.writer)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to query users")

        return users_dict

    async def query_user(self, user):
        rsp_code, users_dict = await query_user(self.reader, self.writer, user)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to query user")

        return users_dict

    async def create_role(
        self, role, privileges, whitelist=None, read_quota=None, write_quota=None
    ):
        rsp_code = await create_role(
            self.reader,
            self.writer,
            role,
            privileges,
            whitelist,
            read_quota,
            write_quota,
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to create role")

        return ASResponse.OK

    async def delete_role(self, role):
        rsp_code = await delete_role(self.reader, self.writer, role)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to delete role")

        return ASResponse.OK

    async def add_privileges(self, role, privileges):
        rsp_code = await add_privileges(self.reader, self.writer, role, privileges)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to grant privilege")

        return ASResponse.OK

    async def delete_privileges(self, role, privileges):
        rsp_code = await delete_privileges(self.reader, self.writer, role, privileges)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to revoke privilege")

        return ASResponse.OK

    async def set_whitelist(self, role, whitelist):
        rsp_code = await set_whitelist(self.reader, self.writer, role, whitelist)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to set allowlist")

        return ASResponse.OK

    async def delete_whitelist(self, role):
        rsp_code = await delete_whitelist(self.reader, self.writer, role)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to delete allowlist")

        return ASResponse.OK

    async def set_quotas(self, role, read_quota=None, write_quota=None):
        rsp_code = await set_quotas(
            self.reader, self.writer, role, read_quota, write_quota
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(
                rsp_code,
                "Failed to set quota{}".format(
                    "s" if read_quota is not None and write_quota is not None else ""
                ),
            )

        return ASResponse.OK

    async def delete_quotas(self, role, read_quota=False, write_quota=False):
        """
        NOT IN USE
        """
        rsp_code = await delete_quotas(
            self.reader, self.writer, role, read_quota, write_quota
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(
                rsp_code,
                "Failed to delete quota{}".format(
                    "s" if read_quota and write_quota else ""
                ),
            )

        return ASResponse.OK

    async def query_roles(self):
        rsp_code, role_dict = await query_roles(self.reader, self.writer)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to query roles")

        return role_dict

    async def query_role(self, role):
        rsp_code, role_dict = await query_role(self.reader, self.writer, role)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, "Failed to query role")

        return role_dict
