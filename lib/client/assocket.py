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

from __future__ import print_function
from builtins import str
from builtins import object

import socket
import warnings

from lib.client.info import authenticate_old, authenticate_new, info, login

try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)

        try:
            # for python < 2.7.7 cryptography throws warning
            import cryptography
            from cryptography import utils
            warnings.simplefilter('ignore', cryptography.utils.DeprecatedIn23)
        except Exception:
            pass

        from OpenSSL import SSL
    HAVE_PYOPENSSL = True
except ImportError:
    HAVE_PYOPENSSL = False


class ASSocket(object):

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

        rc, self.session_token, self.session_expiration = login(self.sock, self.user, self.password, self.auth_mode)

        if rc != 0:
            print("Login failed for", self.user, ":", rc)
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
            rc = authenticate_old(self.sock, self.user, self.password)
        else:
            # new authentication with session_token
            rc = authenticate_new(self.sock, self.user, session_token)

        if rc != 0:
            print("Authentication failed for", self.user, ":", rc)
            self.sock.close()
            return False

        return True

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
            result = self.execute("node")

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

    def execute(self, command):
        return info(self.sock, command)

    def get_session_info(self):
        return self.session_token, self.session_expiration
