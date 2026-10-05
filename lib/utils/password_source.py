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
    anything else   the literal password

Error messages name the option and the source but never the password.
"""

import base64
import os


class PasswordSourceError(Exception):
    carries_its_own_message = True


def resolve(value: str, option: str) -> str:
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
    else:
        return value

    if not password:
        raise PasswordSourceError(
            "{}: password from {} is empty".format(option, source)
        )

    return password


def _read_env(name: str, option: str) -> str:
    value = os.environ.get(name)

    if not value:
        raise PasswordSourceError(
            "{}: environment variable {} is not set or empty".format(option, name)
        )

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
    payload = payload.replace("\r", "").replace("\n", "")

    try:
        data = base64.b64decode(payload, validate=True)
    except ValueError:
        raise PasswordSourceError(
            "{}: invalid base64 in {}".format(option, source)
        ) from None

    if data.endswith(b"\n"):
        data = data[:-1]

    return _to_text(data, option, source)


def _to_text(data: bytes, option: str, source: str) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise PasswordSourceError(
            "{}: password from {} is not valid UTF-8".format(option, source)
        ) from None
