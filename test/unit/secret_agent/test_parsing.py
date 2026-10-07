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

import unittest

from parameterized import parameterized

from lib.secret_agent import (
    InvalidConfigError,
    SecretRef,
    is_secret,
    parse_address,
    parse_port,
    parse_ref,
)
from lib.secret_agent import _wire


class RefTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("secrets:res:key", "res", "key"),
            ("secrets:key", "", "key"),
            ("secrets:a:b:key", "a:b", "key"),
            ("secrets::key", "", "key"),
            (
                "secrets:arn:aws:secretsmanager:us-east-1:1:secret:db:password",
                "arn:aws:secretsmanager:us-east-1:1:secret:db",
                "password",
            ),
        ]
    )
    def test_parse(self, value, resource, key):
        self.assertEqual(parse_ref(value), SecretRef(resource, key))

    @parameterized.expand([("secrets:",), ("secrets:res:",), ("res:key",), ("",)])
    def test_invalid(self, value):
        with self.assertRaises(InvalidConfigError):
            parse_ref(value)

    def test_error_does_not_echo_literal(self):
        with self.assertRaises(InvalidConfigError) as cm:
            parse_ref("hunter2")

        self.assertNotIn("hunter2", str(cm.exception))

    def test_is_secret(self):
        self.assertTrue(is_secret("secrets:res:key"))
        self.assertFalse(is_secret("secret:res:key"))
        self.assertFalse(is_secret("Secrets:res:key"))
        self.assertFalse(is_secret("env:X"))

    @parameterized.expand(
        [("secrets:res:key",), ("secrets:key",), ("secrets:a:b:key",)]
    )
    def test_str_round_trips(self, value):
        self.assertEqual(str(parse_ref(value)), value)


class AddressTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("127.0.0.1", "127.0.0.1", None),
            ("127.0.0.1:4000", "127.0.0.1", 4000),
            ("agent.example.com:1", "agent.example.com", 1),
            ("localhost:65535", "localhost", 65535),
            ("::1", "::1", None),
            ("fe80::1%lo0", "fe80::1%lo0", None),
            ("[::1]", "::1", None),
            ("[::1]:4000", "::1", 4000),
            ("[fe80::1%lo0]:3005", "fe80::1%lo0", 3005),
            ("[2001:db8::1]:3005", "2001:db8::1", 3005),
        ]
    )
    def test_parse(self, address, host, port):
        self.assertEqual(parse_address(address), (host, port))

    @parameterized.expand(
        [
            ("",),
            (":3005",),
            ("host:",),
            ("host:0",),
            ("host:65536",),
            ("host:+1",),
            ("host:x",),
            ("host:٣",),
            ("host:3005:x",),
            ("10.0.0.1:3005:1",),
            ("[]:3005",),
            ("[::1",),
            ("[::1]x",),
            ("[::1]:",),
            ("[host:3005:x]",),
            ("[host:3005:x]:3005",),
            ("[fe80::1%]:3005",),
            ("fe80::1%",),
            ("[localhost]:3005",),
            ("[127.0.0.1]:3005",),
        ]
    )
    def test_invalid(self, address):
        with self.assertRaises(InvalidConfigError):
            parse_address(address)

    @parameterized.expand([(1, 1), ("3005", 3005), (65535, 65535)])
    def test_port(self, value, port):
        self.assertEqual(parse_port(value), port)

    @parameterized.expand(
        [(0,), (65536,), ("0",), ("-1",), ("",), (True,), (3005.0,), ("1" * 5000,)]
    )
    def test_invalid_port(self, value):
        with self.assertRaises(InvalidConfigError):
            parse_port(value)


class WireTest(unittest.TestCase):
    def test_encode(self):
        message = _wire.encode({"SecretKey": "key", "Resource": "res"})
        body = b'{"SecretKey":"key","Resource":"res"}'
        self.assertEqual(message, _wire.HEADER.pack(_wire.MAGIC, len(body)) + body)

    def test_encode_too_large(self):
        with self.assertRaises(_wire.ProtocolError):
            _wire.encode({"SecretKey": "k" * _wire.MAX_MESSAGE_SIZE})

    def test_body_size(self):
        self.assertEqual(_wire.body_size(_wire.HEADER.pack(_wire.MAGIC, 12)), 12)

    @parameterized.expand(
        [
            ("bad_magic", _wire.HEADER.pack(0xDEADBEEF, 2)),
            ("too_large", _wire.HEADER.pack(_wire.MAGIC, _wire.MAX_MESSAGE_SIZE + 1)),
        ]
    )
    def test_body_size_invalid(self, _, header):
        with self.assertRaises(_wire.ProtocolError):
            _wire.body_size(header)

    @parameterized.expand(
        [
            ("truncated", b'{"SecretValue":"hunter2'),
            ("not_object", b'"hunter2"'),
            ("deep_nesting", b"[" * 200000),
        ]
    )
    def test_decode_invalid(self, _, body):
        self.assertIsNone(_wire.decode(body))


if __name__ == "__main__":
    unittest.main()
