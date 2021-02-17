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

from lib.client.info import (
    ASResponse,
    ASProtocolError,
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
    set_whitelist
 )
import socket
import warnings

try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.filterwarnings("ignore", message="Python 3.5 support will be dropped in the next release of cryptography. Please upgrade your Python.")
        import cryptography
        from cryptography import utils
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from OpenSSL import SSL
    HAVE_PYOPENSSL = True
except ImportError:
    HAVE_PYOPENSSL = False


class ASSocket():

    def __init__(self, ip, port, tls_name, user, password, auth_mode, ssl_context, timeout=5):
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
        for addrinfo in socket.getaddrinfo(self.ip, self.port, socket.AF_UNSPEC,
                                           socket.SOCK_STREAM):
            # for DNS it will try all possible addresses
            try:
                sock = self._create_socket_for_addrinfo(addrinfo)
                if sock:
                    break
            except Exception:
                pass
        return sock

    def login(self):
        if self.user is None:
            return True

        if not self.sock:
            return False

        resp_code, self.session_token, self.session_expiration = login(self.sock, self.user, self.password, self.auth_mode)

        if resp_code != ASResponse.OK:
            self.sock.close()
            return False

        return True

    def authenticate(self, session_token):
        if self.user is None:
            return True

        if not self.sock:
            return False

        if session_token is None:
            # old authentication
            resp_code = authenticate_old(self.sock, self.user, self.password)
        else:
            # new authentication with session_token
            resp_code = authenticate_new(self.sock, self.user, session_token)

        if resp_code != ASResponse.OK:
            print("Authentication failed for", self.user, ": ", str(ASResponse(resp_code)))
            self.sock.close()
            return False

        return True

    def get_session_info(self):
        return self.session_token, self.session_expiration

    def connect(self):
        try:
            self.sock = self._create_socket()

            if not self.sock:
                return False
        except Exception:
            return False
        return True

    def is_connected(self):
        if not self.sock:
            return False

        try:
            result = self.info("node")
            
            if result is None or result == -1:
                return False

        except Exception:
            return False

        return True

    def close(self):

        if self.sock:
            try:
                self.sock.close()
                self.sock = None

            except Exception:
                pass

        return

    def settimeout(self, timeout):
        self.sock.settimeout(timeout)

    def info(self, command):
        return info(self.sock, command)

    def create_user(self, user, password, roles):
        rsp_code = create_user(self.sock, user, password, roles)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to create user')

    def delete_user(self, user):
        rsp_code = drop_user(self.sock, user)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to drop user')

    def set_password(self, user, password):
        rsp_code = set_password(self.sock, user, password)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to set password')

    def change_password(self, user, old_password, new_password):
        rsp_code = change_password(self.sock, user, old_password, new_password)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to change password')

    def grant_roles(self, user, roles):
        rsp_code = grant_roles(self.sock, user, roles)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to grant roles')

    def revoke_roles(self, user, roles):
        rsp_code = revoke_roles(self.sock, user, roles)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to revoked roles')

    def query_users(self):
        rsp_code, users_dict = query_users(self.sock)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to query users')

        return users_dict

    def query_user(self, user):
        rsp_code, users_dict = query_user(self.sock, user)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to query user')

        return users_dict

    def create_role(self, role, privileges, whitelist=None):
        rsp_code = create_role(self.sock, role, privileges, whitelist)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to create role')

    def delete_role(self, role):
        rsp_code = delete_role(self.sock, role)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to delete role')

    def add_privileges(self, role, privileges):
        rsp_code = add_privileges(self.sock, role, privileges)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to add privileges')

    def delete_privileges(self, role, privileges):
        rsp_code = delete_privileges(self.sock, role, privileges)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to delete privileges')

    def set_whitelist(self, role, whitelist):
        rsp_code = set_whitelist(self.sock, role, whitelist)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to set whitelist')

    def delete_whitelist(self, role):
        rsp_code = delete_whitelist(self.sock, role)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to delete whitelist')

    def query_roles(self):
        rsp_code, role_dict = query_roles(self.sock)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to query roles')

        return role_dict

    def query_role(self, role):
        rsp_code, role_dict = query_role(self.sock, role)

        if rsp_code != ASResponse.OK:
            raise ASProtocolError(rsp_code, 'Failed to query role')

        return role_dict

