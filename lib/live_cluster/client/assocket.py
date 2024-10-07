# Copyright 2013-2023 Aerospike, Inc.
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

from .types import ASProtocolExcFactory, ASResponse, ASProtocolError
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

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    from OpenSSL import SSL


class _AsyncioSSLConnectionAdapter(SSL.Connection):
    def recv(self, bufsiz: int, flags: int | None = None) -> bytes:
        """Custom wrapper around SSL.Connection.recv that raises a BlockingIOError instead of SSL.WantReadError
        since pyOpenSSL.SSL.Connection (basically a socket) is not compatible with asyncio streams and raises SSL.WantReadError
        in cases when no data is available to read. If we raise SSL.WantReadError asyncio will close the underlying socket
        and not allow retries. By raising BlockingIOError asyncio will retry the read operation. See: TOOLS-2267 for more info
        """
        try:
            return super().recv(bufsiz, flags)
        except SSL.WantReadError:
            raise BlockingIOError("Wrapped SSL.WantReadError")


logger = logging.getLogger(__name__)


class ASSocket:
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
            sock = _AsyncioSSLConnectionAdapter(ctx, sock)

        return sock

    async def _create_socket_for_addrinfo(self, addrinfo):
        sock = None
        try:
            # sock_info format : (family, socktype, proto, canonname, sockaddr)
            addr_family = addrinfo[0]
            sock_addr = addrinfo[4]

            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            sock = self._wrap_socket(sock, self.ssl_context)
            sock.setblocking(False)

            """We are creating our own socket, optionally wrapping it with an SSL.Context (not the same as ssl.SSLContext)
            to get an SSL.Connection (same interface as a socket.socket). Further up the stack we pass this socket to asyncio.open_connection
            to create streams. The preferred way of creating a socket would be to
            allow asyncio create the socket (ssl or not) by passing the ssl_context (or None) to asyncio.open_connection. However, ssl_context must
            be an instance of ssl.SSLContext, which is not compatible with SSL.Context which is what we use. SSL.Context enables a higher level
            of control over certificate verification which we need (see ./ssl_context.py). Another solution might be to create a custom implementation
            of the asyncio Transport that uses pyOpenSSL.SSL.Context (or use https://github.com/horazont/aioopenssl) but that would be a 
            considerable amount of work.
            """
            await asyncio.wait_for(
                asyncio.get_event_loop().sock_connect(sock, sock_addr), self._timeout
            )

            if self.ssl_context:
                try:
                    sock.set_app_data(self.tls_name)

                    """Hack, we must do that handshake here so we can pass the connected socket to asyncio.open_connection.
                    The loop handles the handshake on a non-blocking socket otherwise a blocking socket would block the event loop.
                    """

                    async def _handshake():
                        while True:
                            try:
                                sock.do_handshake()
                                break
                            except (SSL.WantReadError, SSL.WantWriteError):
                                await asyncio.sleep(0.01)

                    await asyncio.wait_for(_handshake(), self._timeout)

                except Exception as tlse:
                    logger.debug(f"TLS connection exception {type(tlse)}: {str(tlse)}")
                    if sock:
                        sock.close()
                        sock = None
                    return None

        except Exception as e:
            logger.debug("Failed to connect to socket %s", e)
            sock = None
            pass

        return sock

    async def _create_socket(self):
        sock = None
        for addrinfo in socket.getaddrinfo(
            self.ip, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM
        ):
            # for DNS it will try all possible addresses
            try:
                sock = await self._create_socket_for_addrinfo(addrinfo)
                if sock:
                    break
            except Exception:
                logger.debug("Failed to create socket to %s", addrinfo)
                raise
        return sock

    async def login(self):
        if self.auth_mode != AuthMode.PKI and self.user is None:
            return True

        if not self.sock:
            return False

        resp_code, self.session_token, self.session_expiration = await asyncio.wait_for(
            login(self.reader, self.writer, self.user, self.password, self.auth_mode),
            self._timeout,
        )

        if resp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(resp_code, "Login failed")

        return True

    async def authenticate(self, session_token):
        if self.auth_mode != AuthMode.PKI and self.user is None:
            return True

        if not self.sock:
            return False
        if session_token is None:
            # old authentication
            resp_code = await asyncio.wait_for(
                authenticate_old(
                    self.reader, self.writer, self.user, self.password, self.auth_mode
                ),
                self._timeout,
            )
        else:
            # new authentication with session_token
            resp_code = await asyncio.wait_for(
                authenticate_new(
                    self.reader, self.writer, self.user, session_token, self.auth_mode
                ),
                self._timeout,
            )

        if resp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(resp_code, "Unable to authenticate")

        return True

    def get_session_info(self):
        return self.session_token, self.session_expiration

    async def connect(self):
        try:
            self.sock = await self._create_socket()
            if not self.sock:
                return False
            self.reader, self.writer = await asyncio.open_connection(sock=self.sock)
        except Exception as e:
            logger.debug(e, exc_info=True)
            raise

        return True

    async def is_connected(self):
        if not self.sock:
            return False

        try:
            result = await self.info("node")

            if result is None:
                return False

        except Exception as e:
            logger.debug(e, exc_info=True)
            return False

        return True

    async def close(self):
        if self.sock:
            try:
                self.sock = None
                self.writer.close()
                await asyncio.wait_for(self.writer.wait_closed(), self._timeout)
                self.writer = None
                self.reader = None
            except Exception:
                pass

        return

    async def info(self, command):
        return await asyncio.wait_for(
            info(self.reader, self.writer, command), self._timeout
        )

    async def create_user(self, user, password, roles):
        rsp_code = await asyncio.wait_for(
            create_user(self.reader, self.writer, user, password, roles), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to create user")

        return ASResponse.OK

    async def delete_user(self, user):
        rsp_code = await asyncio.wait_for(
            drop_user(self.reader, self.writer, user), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to delete user")

        return ASResponse.OK

    async def set_password(self, user, password):
        rsp_code = await asyncio.wait_for(
            set_password(self.reader, self.writer, user, password), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to set password")

        return ASResponse.OK

    async def change_password(self, user, old_password, new_password):
        rsp_code = await asyncio.wait_for(
            change_password(self.reader, self.writer, user, old_password, new_password),
            self._timeout,
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to change password")

        return ASResponse.OK

    async def grant_roles(self, user, roles):
        rsp_code = await asyncio.wait_for(
            grant_roles(self.reader, self.writer, user, roles), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to grant roles")

        return ASResponse.OK

    async def revoke_roles(self, user, roles):
        rsp_code = await asyncio.wait_for(
            revoke_roles(self.reader, self.writer, user, roles), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to revoke roles")

        return ASResponse.OK

    async def query_users(self):
        rsp_code, users_dict = await asyncio.wait_for(
            query_users(self.reader, self.writer), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to query users")

        return users_dict

    async def query_user(self, user):
        rsp_code, users_dict = await asyncio.wait_for(
            query_user(self.reader, self.writer, user), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to query user")

        return users_dict

    async def create_role(
        self, role, privileges, whitelist=None, read_quota=None, write_quota=None
    ):
        rsp_code = await asyncio.wait_for(
            create_role(
                self.reader,
                self.writer,
                role,
                privileges,
                whitelist,
                read_quota,
                write_quota,
            ),
            self._timeout,
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to create role")

        return ASResponse.OK

    async def delete_role(self, role):
        rsp_code = await asyncio.wait_for(
            delete_role(self.reader, self.writer, role), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to delete role")

        return ASResponse.OK

    async def add_privileges(self, role, privileges):
        rsp_code = await asyncio.wait_for(
            add_privileges(self.reader, self.writer, role, privileges), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to grant privilege")

        return ASResponse.OK

    async def delete_privileges(self, role, privileges):
        rsp_code = await asyncio.wait_for(
            delete_privileges(self.reader, self.writer, role, privileges), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(
                rsp_code, "Failed to revoke privilege"
            )

        return ASResponse.OK

    async def set_whitelist(self, role, whitelist):
        rsp_code = await asyncio.wait_for(
            set_whitelist(self.reader, self.writer, role, whitelist), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to set allowlist")

        return ASResponse.OK

    async def delete_whitelist(self, role):
        rsp_code = await asyncio.wait_for(
            delete_whitelist(self.reader, self.writer, role), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(
                rsp_code, "Failed to delete allowlist"
            )

        return ASResponse.OK

    async def set_quotas(self, role, read_quota=None, write_quota=None):
        rsp_code = await asyncio.wait_for(
            set_quotas(self.reader, self.writer, role, read_quota, write_quota),
            self._timeout,
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(
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
        rsp_code = await asyncio.wait_for(
            delete_quotas(self.reader, self.writer, role, read_quota, write_quota),
            self._timeout,
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(
                rsp_code,
                "Failed to delete quota{}".format(
                    "s" if read_quota and write_quota else ""
                ),
            )

        return ASResponse.OK

    async def query_roles(self):
        rsp_code, role_dict = await asyncio.wait_for(
            query_roles(self.reader, self.writer), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to query roles")

        return role_dict

    async def query_role(self, role):
        rsp_code, role_dict = await asyncio.wait_for(
            query_role(self.reader, self.writer, role), self._timeout
        )

        if rsp_code != ASResponse.OK:
            raise ASProtocolExcFactory.create_exc(rsp_code, "Failed to query role")

        return role_dict
