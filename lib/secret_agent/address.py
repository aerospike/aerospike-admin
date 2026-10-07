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
"""Secret Agent address syntax, as accepted by --sa-address in the C tools."""

import ipaddress

from lib.secret_agent.errors import InvalidConfigError

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 3005


def parse_port(port: int | str) -> int:
    """Validate a port.

    Args:
        port: Port as an int or a decimal string.

    Returns:
        The port, from 1 to 65535.

    Raises:
        InvalidConfigError: port is not a valid port.
    """
    if isinstance(port, bool):
        raise InvalidConfigError("invalid port {}".format(port))

    if isinstance(port, str):
        if not (port.isascii() and port.isdigit() and len(port) <= 5):
            raise InvalidConfigError("invalid port {}".format(port))

        port = int(port)

    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise InvalidConfigError("invalid port {}".format(port))

    return port


def parse_address(address: str) -> tuple[str, int | None]:
    """Split <host>[:<port>] or [<ipv6>][:<port>] into host and port.

    An unbracketed host with more than one colon must be an IPv6 address and
    has no port.

    Args:
        address: The address.

    Returns:
        The host, without brackets, and the port, or None when the address
        does not give one.

    Raises:
        InvalidConfigError: address is not valid.
    """
    port = None

    if address.startswith("["):
        host, bracket, rest = address[1:].partition("]")

        if not bracket or not _is_ipv6(host):
            raise _invalid(address)

        if rest:
            if not rest.startswith(":"):
                raise _invalid(address)

            port = _address_port(rest[1:], address)
    elif address.count(":") == 1:
        host, _, port_str = address.partition(":")
        port = _address_port(port_str, address)
    else:
        host = address

        if ":" in host and not _is_ipv6(host):
            raise _invalid(address)

    if not host:
        raise _invalid(address)

    return host, port


def _address_port(port: str, address: str) -> int:
    try:
        return parse_port(port)
    except InvalidConfigError:
        raise _invalid(address) from None


def _is_ipv6(host: str) -> bool:
    addr, percent, zone = host.partition("%")

    if percent and not zone:
        return False

    try:
        ipaddress.IPv6Address(addr)
    except ValueError:
        return False

    return True


def _invalid(address: str) -> InvalidConfigError:
    return InvalidConfigError("invalid address {}".format(address))
