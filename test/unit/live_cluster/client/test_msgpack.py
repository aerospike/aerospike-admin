# Copyright 2022-2023 Aerospike, Inc.
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

import unittest
from lib.live_cluster.client.ctx import ASValues, CDTContext, CTXItems

from lib.live_cluster.client.msgpack import (
    AS_BYTES_BLOB,
    AS_BYTES_STRING,
    ASPacker,
    CTXItemWireType,
)


class MsgPackTest(unittest.TestCase):
    def setUp(self):
        self.packer = ASPacker()

    def pack(self, val) -> bytes:
        self.packer.pack(val)
        return self.packer.bytes()

    def test_pack_as_string_fixstr(self):
        string = "abcd"
        as_string = ASValues.ASString(string)
        expected = bytes([0xA5, AS_BYTES_STRING]) + bytes(string, encoding="utf-8")

        actual = self.pack(as_string)

        self.assertEqual(expected, actual)

    def test_pack_as_string_8(self):
        string = "abcdefghijklmnopqrstuvwxyz123456"
        as_string = ASValues.ASString(string)
        expected = bytearray([0xD9, 33, AS_BYTES_STRING])
        expected.extend(bytearray(string, encoding="ascii"))

        actual = self.pack(as_string)

        self.assertEqual(expected, actual)

    def test_pack_as_bytes_fixstr(self):
        string = b"abcd"
        as_string = ASValues.ASBytes(string)
        expected = bytearray([0xA5, AS_BYTES_BLOB])
        expected.extend(bytearray(string))

        actual = self.pack(as_string)

        self.assertEqual(expected, actual)

    def test_pack_as_bool_false(self):
        actual = self.pack(ASValues.ASBool(False))
        self.assertEqual(bytes([0xC2]), actual)

    def test_pack_as_bool_true(self):
        actual = self.pack(ASValues.ASBool(True))
        self.assertEqual(bytes([0xC3]), actual)

    def test_pack_cdt_ctx(self):
        ctx = CDTContext(
            [
                CTXItems.ListIndex(1),
                CTXItems.ListRank(2),
                CTXItems.MapIndex(3),
                CTXItems.MapRank(4),
                CTXItems.MapKey(ASValues.ASString("abcd")),
                CTXItems.ListValue(ASValues.ASBool(True)),
                CTXItems.MapValue(ASValues.ASInt(5)),
            ]
        )

        expected = (
            bytes([0x9E])
            + bytes([CTXItemWireType.AS_CDT_CTX_LIST_INDEX, 1])
            + bytes([CTXItemWireType.AS_CDT_CTX_LIST_RANK, 2])
            + bytes([CTXItemWireType.AS_CDT_CTX_MAP_INDEX, 3])
            + bytes([CTXItemWireType.AS_CDT_CTX_MAP_RANK, 4])
            + bytes([CTXItemWireType.AS_CDT_CTX_MAP_KEY])
            + bytes([0xA5, AS_BYTES_STRING])
            + bytes("abcd", encoding="utf-8")
            + bytes([CTXItemWireType.AS_CDT_CTX_LIST_VALUE, 0xC3])
            + bytes([CTXItemWireType.AS_CDT_CTX_MAP_VALUE, 5])
        )

        actual = self.pack(ctx)

        self.assertEqual(expected, actual)
