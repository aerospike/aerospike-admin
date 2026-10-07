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
"""asadm's Secret Agent settings: the --sa-* options and the [secret-agent]
config section, merged the way asbackup and aql merge them."""

from typing import Any, Callable, Self

from lib.secret_agent import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    SecretAgentClient,
    SecretAgentError,
    new_ssl_context,
    parse_address,
    parse_port,
)
from lib.utils.password_source import PasswordSourceError

SECTION = "secret-agent"
OPTIONS = ("sa-address", "sa-port", "sa-timeout", "sa-cafile")
DEFAULT_TIMEOUT_MS = 1000
_MAX_TIMEOUT_MS = 2**31 - 1


def fetcher(args: Any) -> Callable[[str], str]:
    """Return a function that fetches a secrets: reference with the agent
    settings in args. Settings are read and checked, and the client created,
    on first use, so runs without secrets: values never touch them."""
    client = None

    def fetch(ref: str) -> str:
        nonlocal client

        if client is None:
            client = SecretAgentSettings.from_args(args).new_client()

        return client.resolve(ref)

    return fetch


def file_section(conf_dict: dict, instance: str | None) -> tuple[str, dict]:
    """Return the section name and its values: [secret-agent_<instance>] when
    it exists, [secret-agent] otherwise."""
    if instance:
        name = "{}_{}".format(SECTION, instance)

        if name in conf_dict:
            return name, dict(conf_dict[name])

    return SECTION, dict(conf_dict.get(SECTION, {}))


class SecretAgentSettings:
    """Agent settings from the config file, then the command line. Within one
    source an explicit sa-port beats a port in sa-address, and the command line
    beats the config file. Invalid values raise PasswordSourceError."""

    def __init__(self, section_name: str, file_values: dict, cli_values: dict) -> None:
        self.host = DEFAULT_HOST
        self.port = DEFAULT_PORT
        self.timeout_ms = DEFAULT_TIMEOUT_MS
        self.cafile = None

        self._apply(file_values, section_name)
        self._apply(cli_values, None)

    @classmethod
    def from_args(cls, args: Any) -> Self:
        section_name, file_values = getattr(args, "secret_agent_section", (SECTION, {}))
        cli_values = {
            option: getattr(args, option.replace("-", "_"), None) for option in OPTIONS
        }

        return cls(section_name, file_values, cli_values)

    def new_client(self) -> SecretAgentClient:
        ssl_context = None

        if self.cafile:
            try:
                ssl_context = new_ssl_context(self.cafile)
            except SecretAgentError as e:
                raise PasswordSourceError("--sa-cafile: {}".format(e)) from None

        return SecretAgentClient(
            self.host,
            self.port,
            timeout=self.timeout_ms / 1000,
            ssl_context=ssl_context,
        )

    def _apply(self, values: dict, section: str | None) -> None:
        """Apply one source. section is None for the command line."""
        address = values.get("sa-address")
        port = values.get("sa-port")
        timeout = values.get("sa-timeout")
        cafile = values.get("sa-cafile")
        address_port = None

        if address is not None:
            try:
                self.host, address_port = parse_address(str(address))
            except SecretAgentError:
                raise _invalid("sa-address", address, section) from None

        if port is not None:
            try:
                self.port = parse_port(port)
            except SecretAgentError:
                raise _invalid("sa-port", port, section) from None
        elif address_port is not None:
            self.port = address_port

        if timeout is not None:
            self.timeout_ms = _parse_timeout(timeout, section)

        if cafile:
            self.cafile = cafile


def _parse_timeout(value: object, section: str | None) -> int:
    timeout = value

    if isinstance(value, str) and value.isascii() and value.isdigit():
        timeout = int(value) if len(value) <= 10 else None

    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, int)
        or not 1 <= timeout <= _MAX_TIMEOUT_MS
    ):
        raise _invalid("sa-timeout", value, section)

    return timeout


def _invalid(option: str, value: object, section: str | None) -> PasswordSourceError:
    if section is None:
        message = "--{}: invalid value {}".format(option, value)

        if option == "sa-timeout":
            message += ", expected an integer from 1 to {}".format(_MAX_TIMEOUT_MS)

        return PasswordSourceError(message)

    return PasswordSourceError(
        "invalid value {} for {} in the [{}] config section".format(
            value, option, section
        )
    )
