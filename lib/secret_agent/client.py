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

import base64
import math
import socket
import ssl
import time

from lib.secret_agent import _wire
from lib.secret_agent.address import DEFAULT_HOST, DEFAULT_PORT, parse_port
from lib.secret_agent.errors import (
    InvalidConfigError,
    InvalidResponseError,
    RequestFailedError,
)
from lib.secret_agent.ref import SecretRef, is_secret, parse_ref

DEFAULT_TIMEOUT = 1.0

_TRAILING_WHITESPACE = " \t\n\r\f\v"


class SecretAgentClient:
    """Fetches secrets from an Aerospike Secret Agent over TCP.

    The client opens one connection per request and is safe to share between
    threads. As in the Aerospike C tools, secret values are base64-decoded, so
    the agent must be configured with convert-to-base64.

    Args:
        host: Agent hostname or IP address. With TLS it must be in the agent's
            certificate.
        port: Agent port.
        timeout: Seconds allowed for each request, from connect to response.
            Name resolution is not covered.
        ssl_context: Client context from new_ssl_context. Enables TLS.

    Raises:
        InvalidConfigError: A setting is invalid.
    """

    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int | str = DEFAULT_PORT,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not host:
            raise InvalidConfigError("host is required")

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise InvalidConfigError("invalid timeout {!r}".format(timeout))

        self._host = host
        self._port = parse_port(port)
        self._timeout = float(timeout)
        self._ssl_context = ssl_context

    @property
    def address(self) -> str:
        """The agent address used in error messages."""
        if ":" in self._host:
            return "[{}]:{}".format(self._host, self._port)

        return "{}:{}".format(self._host, self._port)

    def resolve(self, value: str) -> str:
        """Resolve a value that may be a secrets:[<resource>:]<key> reference.

        The fetched secret is returned as is and must not be parsed again, for
        example as an env: or file: value.

        Args:
            value: An option value.

        Returns:
            The fetched secret, or value unchanged when it is not a reference.

        Raises:
            SecretAgentError: The reference is invalid or the fetch failed.
        """
        if not is_secret(value):
            return value

        return self._fetch_text(parse_ref(value))

    def get_secret(self, resource: str, key: str) -> str:
        """Fetch a secret.

        Args:
            resource: Agent resource. Empty leaves it out of the request, as
                with a secrets:<key> reference.
            key: Key within the resource.

        Returns:
            The secret.

        Raises:
            SecretAgentError: The key is empty or the fetch failed.
        """
        if not key:
            raise InvalidConfigError("empty secret key")

        return self._fetch_text(SecretRef(resource, key))

    def _fetch_text(self, ref: SecretRef) -> str:
        text = _utf8(self._fetch(ref))

        if text is None:
            raise InvalidResponseError("secret for {} is not valid UTF-8".format(ref))

        if "\x00" in text:
            raise InvalidResponseError("secret for {} contains a NUL byte".format(ref))

        return text

    def _fetch(self, ref: SecretRef) -> bytes:
        deadline = time.monotonic() + self._timeout
        request = {"SecretKey": ref.key}

        if ref.resource:
            request["Resource"] = ref.resource

        try:
            message = _wire.encode(request)
        except _wire.ProtocolError as e:
            raise InvalidConfigError("request for {}: {}".format(ref, e)) from None

        try:
            sock = self._connect(deadline)
        except OSError as e:
            raise RequestFailedError(
                "connect to {} for {}: {}".format(self.address, ref, _reason(e))
            ) from e

        with sock:
            try:
                _set_timeout(sock, deadline)
                sock.sendall(message)
            except OSError as e:
                raise RequestFailedError(
                    "send request for {}: {}".format(ref, _reason(e))
                ) from e

            header = _recv_exact(sock, _wire.HEADER.size, deadline, ref)

            try:
                size = _wire.body_size(header)
            except _wire.ProtocolError as e:
                raise InvalidResponseError(
                    "response for {}: {}".format(ref, e)
                ) from None

            body = _recv_exact(sock, size, deadline, ref)

        response = _wire.decode(body)

        if response is None:
            raise InvalidResponseError("malformed response for {}".format(ref))

        error = response.get("Error")
        value = response.get("SecretValue")

        if not isinstance(error, (str, type(None))) or not isinstance(
            value, (str, type(None))
        ):
            raise InvalidResponseError("malformed response for {}".format(ref))

        # Like the C client, any Error field fails the request, even an empty one.
        if error is not None:
            raise RequestFailedError("agent error for {}: {}".format(ref, error))

        encoded = (value or "").rstrip(_TRAILING_WHITESPACE)

        if not encoded:
            raise InvalidResponseError("empty secret for {}".format(ref))

        data = _b64decode(encoded)

        if data is None:
            raise InvalidResponseError("secret for {} is not valid base64".format(ref))

        return data

    def _connect(self, deadline: float) -> socket.socket:
        sock = socket.create_connection(
            (self._host, self._port), timeout=_remaining(deadline)
        )

        if self._ssl_context is None:
            return sock

        try:
            _set_timeout(sock, deadline)

            return self._ssl_context.wrap_socket(sock, server_hostname=self._host)
        except BaseException:
            sock.close()
            raise


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise TimeoutError("timed out")

    return remaining


def _set_timeout(sock: socket.socket, deadline: float) -> None:
    sock.settimeout(_remaining(deadline))


def _recv_exact(
    sock: socket.socket, size: int, deadline: float, ref: SecretRef
) -> bytes:
    chunks = []

    while size > 0:
        try:
            _set_timeout(sock, deadline)
            chunk = sock.recv(min(size, 65536))
        except OSError as e:
            raise RequestFailedError(
                "read response for {}: {}".format(ref, _reason(e))
            ) from e

        if not chunk:
            raise RequestFailedError(
                "read response for {}: connection closed by the agent".format(ref)
            )

        chunks.append(chunk)
        size -= len(chunk)

    return b"".join(chunks)


def _reason(e: BaseException) -> str:
    return getattr(e, "strerror", None) or str(e) or type(e).__name__


# Their exceptions can hold the secret, so callers raise outside the except
# block.
def _b64decode(data: str) -> bytes | None:
    try:
        return base64.b64decode(data, validate=True)
    except ValueError:
        return None


def _utf8(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None
