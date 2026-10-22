# Copyright 2026 Aerospike, Inc.
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
"""An in-process Secret Agent for tests."""

import socket
import socketserver
import ssl
import threading
from typing import Callable, Self

from lib.secret_agent import _wire

_CONN_TIMEOUT = 10.0


class _TCPServer(socketserver.ThreadingTCPServer):
    request_queue_size = 128


class FakeSecretAgent:
    """A fake Secret Agent on 127.0.0.1.

    Use it as a context manager, or call start() and stop().

    Args:
        secrets: Values by resource and key, returned as stored, so store them
            base64-encoded for a client that decodes. A request without a
            resource is looked up under the "" resource.
        ssl_context: Server-side context. Enables TLS.
        handler: Replaces the protocol and is given each connection, for
            responses a real agent would never send.
    """

    def __init__(
        self,
        secrets: dict[str, dict[str, str]] | None = None,
        *,
        ssl_context: ssl.SSLContext | None = None,
        handler: Callable[[socket.socket], None] | None = None,
    ) -> None:
        self.secrets = {r: dict(v) for r, v in (secrets or {}).items()}
        self.ssl_context = ssl_context
        self.handler = handler
        self._server = None
        self._thread = None

    @property
    def host(self) -> str:
        return self._server.server_address[0]

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    @property
    def address(self) -> str:
        return "{}:{}".format(self.host, self.port)

    def start(self) -> Self:
        server = _TCPServer(("127.0.0.1", 0), _Handler)
        server.daemon_threads = True
        server.agent = self
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        self._thread.start()

        return self

    def stop(self) -> None:
        if self._server is None:
            return

        self._server.shutdown()
        self._server.server_close()
        self._thread.join()
        self._server = None

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    def lookup(self, request: dict | None) -> dict:
        """Return the response for a decoded request."""
        if request is None:
            return {"Error": "malformed request"}

        resource = request.get("Resource", "")
        key = request.get("SecretKey", "")
        value = self.secrets.get(resource, {}).get(key)

        if value is None:
            return {
                "Error": "secret {!r} not found in resource {!r}".format(key, resource)
            }

        return {"SecretValue": value}


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        agent = self.server.agent
        sock = self.request
        sock.settimeout(_CONN_TIMEOUT)

        if agent.ssl_context is not None:
            try:
                sock = agent.ssl_context.wrap_socket(sock, server_side=True)
            except (OSError, ValueError):
                return

        try:
            if agent.handler is not None:
                agent.handler(sock)
                return

            request = read_message(sock)
            sock.sendall(_wire.encode(agent.lookup(request)))
        except OSError:
            pass


def read_message(sock: socket.socket) -> dict | None:
    """Read one framed message.

    Args:
        sock: The connection.

    Returns:
        The decoded message, or None when it is malformed.
    """
    header = _recv_exact(sock, _wire.HEADER.size)

    try:
        size = _wire.body_size(header)
    except _wire.ProtocolError:
        return None

    return _wire.decode(_recv_exact(sock, size))


def frame(body: bytes, magic: int = _wire.MAGIC) -> bytes:
    """Frame raw body bytes, for handlers that send broken responses.

    Args:
        body: The body.
        magic: The header magic number.

    Returns:
        The framed message.
    """
    return _wire.HEADER.pack(magic, len(body)) + body


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError("connection closed")

        data += chunk

    return data
