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
config section."""

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
OPTIONS = ("sa-address", "sa-port", "sa-timeout", "sa-ca-file", "sa-cafile")
DEFAULT_TIMEOUT_MS = 1000
_MAX_TIMEOUT_MS = 2**31 - 1
_EXPECTED = {
    "sa-address": "<host>[:<port>] or [<ipv6>][:<port>]",
    "sa-port": "an integer from 1 to 65535",
    "sa-timeout": "an integer from 1 to {}".format(_MAX_TIMEOUT_MS),
    "sa-ca-file": "a path to a CA certificate file",
    "sa-cafile": "a path to a CA certificate file",
}


def fetcher(args: Any) -> Callable[[str], str]:
    """Return a function that fetches a secrets: reference with the agent
    settings in args. The settings are checked now, as in the C tools. The CA
    file is read, and the client created, on first use, so runs without
    secrets: values never read it."""
    settings = SecretAgentSettings.from_args(args)
    client = None

    def fetch(ref: str) -> str:
        nonlocal client

        if client is None:
            client = settings.new_client()

        return client.resolve(ref)

    return fetch


def file_section(conf_dict: dict, instance: str | None) -> tuple[str, object]:
    """Return the section name and its values: [secret-agent_<instance>] when
    it exists, [secret-agent] otherwise."""
    if instance:
        name = "{}_{}".format(SECTION, instance)

        if name in conf_dict:
            return name, conf_dict[name]

    return SECTION, conf_dict.get(SECTION, {})


def is_section(name: str) -> bool:
    return name == SECTION or name.startswith(SECTION + "_")


def check_section(name: str, values: object) -> dict:
    """Return a config file section with its keys lowercased, so they match
    without regard to case. Raises PasswordSourceError when the section has a
    key or value that cannot be used."""
    if not isinstance(values, dict):
        raise PasswordSourceError(
            'invalid value "{}" for {}, expected a [{}] config section'.format(
                values, name, name
            )
        )

    values = {k.lower(): v for k, v in values.items()}

    for key in values:
        if key not in OPTIONS:
            raise PasswordSourceError(
                "unknown key {} in the [{}] config section".format(key, name)
            )

    SecretAgentSettings([(name, values)], {})

    return values


class SecretAgentSettings:
    """Agent settings from each config file in the order they are read, then
    the command line, as in the C tools. Within one source an explicit sa-port
    beats a port in sa-address and sa-ca-file beats sa-cafile, and a later
    source beats an earlier one. Invalid values raise PasswordSourceError."""

    def __init__(self, file_sections: list[tuple[str, dict]], cli_values: dict) -> None:
        self.host = DEFAULT_HOST
        self.port = DEFAULT_PORT
        self.timeout_ms = DEFAULT_TIMEOUT_MS
        self.cafile = None
        self.cafile_option = None

        for section_name, file_values in file_sections:
            self._apply(file_values, section_name)

        self._apply(cli_values, None)

    @classmethod
    def from_args(cls, args: Any) -> Self:
        cli_values = {
            option: getattr(args, option.replace("-", "_"), None) for option in OPTIONS
        }

        return cls(getattr(args, "secret_agent_sections", []), cli_values)

    def new_client(self) -> SecretAgentClient:
        ssl_context = None

        if self.cafile:
            try:
                ssl_context = new_ssl_context(self.cafile)
            except SecretAgentError as e:
                raise PasswordSourceError(
                    "{}: {}".format(self.cafile_option, e)
                ) from None

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
        address_port = None

        if address is not None:
            if not isinstance(address, str):
                raise _invalid("sa-address", address, section)

            try:
                self.host, address_port = parse_address(address)
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

        for option in ("sa-cafile", "sa-ca-file"):
            cafile = values.get(option)

            if cafile is None:
                continue

            if not isinstance(cafile, str) or not cafile:
                raise _invalid(option, cafile, section)

            self.cafile = cafile
            self.cafile_option = _option_label(option, section)


def _option_label(option: str, section: str | None) -> str:
    if section is None:
        return "--" + option

    return "{} in the [{}] config section".format(option, section)


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
        return PasswordSourceError(
            '--{}: invalid value "{}", expected {}'.format(
                option, value, _EXPECTED[option]
            )
        )

    return PasswordSourceError(
        'invalid value "{}" for {} in the [{}] config section, expected {}'.format(
            value, option, section, _EXPECTED[option]
        )
    )
