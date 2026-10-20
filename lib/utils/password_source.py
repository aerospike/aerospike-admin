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

Limits and messages match the C tools. max_len caps every value, literal or
read from a source, and file: falls back to PASSWORD_FILE_MAX_LEN without one.
With first_line=True file: uses only the first line.

Error messages name the option and the source but never the password.
"""

import base64
import os

PASSWORD_MAX_LEN = 63
TLS_KEYFILE_PASSWORD_MAX_LEN = 1024
PASSWORD_FILE_MAX_LEN = 4999

_SOURCES = ("env", "env-b64", "b64", "file")


class PasswordSourceError(Exception):
    carries_its_own_message = True


def has_source(value: str) -> bool:
    kind, sep, _ = value.partition(":")

    return bool(sep) and kind in _SOURCES


def check_len(password: str, option: str, max_len: int) -> None:
    _check_bytes(password.encode("utf-8", "surrogatepass"), option, max_len, "password")


def resolve(
    value: str, option: str, *, max_len: int = 0, first_line: bool = False
) -> str:
    if not has_source(value):
        check_len(value, option, max_len)
        return value

    kind, _, rest = value.partition(":")

    if not rest and kind != "b64":
        raise PasswordSourceError(
            "{}: {}: requires {}".format(
                option, kind, "a path" if kind == "file" else "a variable name"
            )
        )

    if kind == "env":
        password = _read_env(rest, option)
        what = "value from environment variable " + rest
    elif kind == "env-b64":
        source = "environment variable " + rest
        password = _decode_b64(_read_env(rest, option), option, source)
        what = "decoded value from " + source
    elif kind == "b64":
        password = _decode_b64(rest, option, "b64: value")
        what = "decoded b64: value"
    else:
        return _read_file(rest, option, max_len, first_line)

    _check_bytes(password.encode("utf-8"), option, max_len, what)

    return password


def _read_env(name: str, option: str) -> str:
    value = os.environ.get(name)

    if not value:
        raise PasswordSourceError(
            "{}: environment variable {} is not set or empty".format(option, name)
        )

    if not _is_utf8(value):
        raise _not_utf8(option, "environment variable " + name)

    return value


def _read_file(path: str, option: str, max_len: int, first_line: bool) -> str:
    max_len = max_len or PASSWORD_FILE_MAX_LEN
    data = _read_head(path, option, max_len + len(b"\r\n") + 1, first_line)
    line_ended = False

    if first_line:
        line = data.split(b"\n", 1)[0].split(b"\r", 1)[0]
        line_ended = len(line) < len(data)
        data = line

    if b"\0" in data:
        raise PasswordSourceError(
            "{}: file {} contains a NUL byte".format(option, path)
        )

    if data.endswith(b"\r\n"):
        data = data[:-2]
    elif data.endswith(b"\n"):
        data = data[:-1]

    _check_bytes(data, option, max_len, "value from file " + path)

    if not data:
        raise PasswordSourceError(
            "{}: password from {}file {} is empty".format(
                option, "first line of " if line_ended else "", path
            )
        )

    return _to_text(data, option, "file " + path)


# read1 so file:/dev/zero or a FIFO whose writer stays open returns at once.
def _read_head(path: str, option: str, cap: int, first_line: bool) -> bytes:
    data = b""

    try:
        with open(path, "rb") as f:
            while len(data) < cap:
                chunk = f.read1(cap - len(data))

                if not chunk:
                    break

                data += chunk

                if b"\0" in chunk or (
                    first_line and (b"\n" in chunk or b"\r" in chunk)
                ):
                    break
    except OSError as e:
        raise PasswordSourceError(
            "{}: cannot read file {}: {}".format(option, path, e.strerror or e)
        ) from None

    return data


def _check_bytes(data: bytes, option: str, max_len: int, what: str) -> None:
    if max_len and len(data) > max_len:
        raise PasswordSourceError(
            "{}: {} is longer than {} bytes".format(option, what, max_len)
        )


def _decode_b64(payload: str, option: str, source: str) -> str:
    # Go's base64.StdEncoding skips CR and LF, so wrapped input still decodes.
    data = _b64decode(payload.replace("\r", "").replace("\n", ""))

    if data is None:
        raise PasswordSourceError("{}: invalid base64 in {}".format(option, source))

    if b"\0" in data:
        raise PasswordSourceError(
            "{}: {} decodes to a value containing a NUL byte".format(option, source)
        )

    if data.endswith(b"\n"):
        data = data[:-1]

    if not data:
        raise PasswordSourceError(
            "{}: password from {} is empty".format(option, source)
        )

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
