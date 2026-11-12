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
"""Secret Agent message framing: an 8-byte header (magic, then the big-endian
body length) followed by a JSON body."""

import json
import struct

MAGIC = 0x51DEC1CC
HEADER = struct.Struct(">II")
MAX_MESSAGE_SIZE = 1 << 20


class ProtocolError(Exception):
    pass


def encode(message: dict) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")

    if len(body) > MAX_MESSAGE_SIZE:
        raise ProtocolError(
            "message of {} bytes exceeds limit of {}".format(
                len(body), MAX_MESSAGE_SIZE
            )
        )

    return HEADER.pack(MAGIC, len(body)) + body


def body_size(header: bytes) -> int:
    magic, size = HEADER.unpack(header)

    if magic != MAGIC:
        raise ProtocolError("invalid magic number {:#x}".format(magic))

    if size > MAX_MESSAGE_SIZE:
        raise ProtocolError(
            "body of {} bytes exceeds limit of {}".format(size, MAX_MESSAGE_SIZE)
        )

    return size


# json's exceptions keep the document, which can hold a secret, so callers
# raise outside the except block.
def decode(body: bytes) -> dict | None:
    try:
        message = json.loads(body)
    except (ValueError, RecursionError):
        return None

    return message if isinstance(message, dict) else None
