# Copyright 2013-2017 Aerospike, Inc.
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

import socket
import warnings

from lib.client.info import authenticate, info

try:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from OpenSSL import SSL
    HAVE_PYOPENSSL = True
except ImportError:
    HAVE_PYOPENSSL = False


class ASSocket:

    def __init__(self, node, ip, port, pool_size=3):
        self.sock = None
        self.node = node
        self.ip = ip
        self.port = port
        self.pool_size = pool_size

    def _wrap_socket(self, sock, ctx):
        if ctx:
            if HAVE_PYOPENSSL:
                sock = SSL.Connection(ctx, sock)
            else:
                raise ImportError("No module named pyOpenSSL")

        return sock

    def _create_socket_for_addrinfo(self, addrinfo, tls_name=None, user=None,
                                    password=None, ssl_context=None):
        sock = None
        try:
            # sock_info format : (family, socktype, proto, canonname, sockaddr)
            addr_family = addrinfo[0]
            sock_addr = addrinfo[4]

            sock = socket.socket(addr_family, socket.SOCK_STREAM)
            if not ssl_context:
                sock.settimeout(5.0)
            # timeout on wrapper might give errors
            sock = self._wrap_socket(sock, ssl_context)
            sock.connect(sock_addr)
            if ssl_context:
                try:
                    sock.set_app_data(tls_name)
                    sock.do_handshake()
                except Exception as tlse:
                    print "TLS connection exception: " + str(tlse)
                    if sock:
                        sock.close()
                        sock = None
                    return None
            if user != None:
                rc = authenticate(sock, user, password)
                if rc != 0:
                    print "Authentication failed for ", user, ": ", rc
                    sock.close()
                    return None
        except Exception:
            sock = None
            pass
        return sock

    def _create_socket(self, host, port, tls_name=None, user=None,
                       password=None, ssl_context=None):

        sock = None
        for addrinfo in socket.getaddrinfo(host, port, socket.AF_UNSPEC,
                                           socket.SOCK_STREAM):
            # for DNS it will try all possible addresses
            try:
                sock = self._create_socket_for_addrinfo(addrinfo, tls_name,
                                                        user, password, ssl_context=ssl_context)
                if sock:
                    break
            except Exception:
                pass
        return sock

    def connect(self):
        try:
            self.sock = self._create_socket(self.ip, self.port,
                                            tls_name=self.node.tls_name, user=self.node.user,
                                            password=self.node.password,
                                            ssl_context=self.node.ssl_context)

            if not self.sock:
                return False
        except Exception:
            return False
        return True

    def is_connected(self):
        if not self.sock:
            return False
        result = self.execute("node")
        if result is None or result == -1:
            return False
        return True

    def close(self, force=False):
        if self.sock:
            try:
                if (not force
                        and (len(self.node.socket_pool[self.port])
                             < self.pool_size)):

                    self.sock.settimeout(None)
                    self.node.socket_pool[self.port].add(self)
                else:
                    self.sock.close()
                    self.sock = None
            except Exception:
                pass
        return

    def settimeout(self, timeout):
        self.sock.settimeout(timeout)

    def execute(self, command):
        return info(self.sock, command)
