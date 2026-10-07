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
"""Resolve a password option value that may point at where the password lives.

The forms match the PasswordFlag in tools-common-go:

    env:<VAR>       value of environment variable VAR
    env-b64:<VAR>   base64 decoded value of environment variable VAR
    b64:<VALUE>     base64 decoded VALUE
    file:<PATH>     contents of PATH, less one trailing line ending
    secrets:...     fetched from the Aerospike Secret Agent, when the caller
                    passes fetch_secret
    anything else   the literal password

Error messages name the option and the source but never the password.
"""

import base64
import os
from typing import Callable

from lib.secret_agent import SecretAgentError


class PasswordSourceError(Exception):
    carries_its_own_message = True


def resolve(
    value: str, option: str, fetch_secret: Callable[[str], str] | None = None
) -> str:
    kind, sep, rest = value.partition(":")

    if not sep:
        return value

    if kind == "env":
        source = "environment variable " + rest
        password = _read_env(rest, option)
    elif kind == "env-b64":
        source = "environment variable " + rest
        password = _decode_b64(_read_env(rest, option), option, source)
    elif kind == "b64":
        source = "b64: value"
        password = _decode_b64(rest, option, source)
    elif kind == "file":
        source = "file " + rest
        password = _to_text(_read_file(rest, option), option, source)
    elif kind == "secrets" and fetch_secret is not None:
        source = value
        password = _fetch_secret(fetch_secret, value, option)
    else:
        return value

    if not password:
        raise PasswordSourceError(
            "{}: password from {} is empty".format(option, source)
        )

    return password


def _fetch_secret(fetch_secret: Callable[[str], str], ref: str, option: str) -> str:
    try:
        return fetch_secret(ref)
    except PasswordSourceError:
        raise
    except SecretAgentError as e:
        raise PasswordSourceError("{}: {}".format(option, e)) from None
    except Exception:
        # asadm exits silently on unexpected errors; never lose this one.
        raise PasswordSourceError(
            "{}: secret agent request for {} failed".format(option, ref)
        ) from None


def _read_env(name: str, option: str) -> str:
    value = os.environ.get(name)

    if not value:
        raise PasswordSourceError(
            "{}: environment variable {} is not set or empty".format(option, name)
        )

    if not _is_utf8(value):
        raise _not_utf8(option, "environment variable " + name)

    return value


def _read_file(path: str, option: str) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise PasswordSourceError(
            "{}: cannot read file {}: {}".format(option, path, e.strerror or e)
        ) from None

    if data.endswith(b"\r\n"):
        return data[:-2]

    if data.endswith(b"\n"):
        return data[:-1]

    return data


def _decode_b64(payload: str, option: str, source: str) -> str:
    # Go's base64.StdEncoding skips CR and LF, so wrapped input still decodes.
    data = _b64decode(payload.replace("\r", "").replace("\n", ""))

    if data is None:
        raise PasswordSourceError("{}: invalid base64 in {}".format(option, source))

    if data.endswith(b"\n"):
        data = data[:-1]

    return _to_text(data, option, source)


def _to_text(data: bytes, option: str, source: str) -> str:
    text = _utf8_decode(data)

    if text is None:
        raise _not_utf8(option, source)

    return text


def _not_utf8(option: str, source: str) -> PasswordSourceError:
    return PasswordSourceError(
        "{}: password from {} is not valid UTF-8".format(option, source)
    )


# Their exceptions hold the secret, so callers raise outside the except block.
def _b64decode(payload: str) -> bytes | None:
    try:
        return base64.b64decode(payload, validate=True)
    except ValueError:
        return None


def _utf8_decode(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _is_utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False

    return True
