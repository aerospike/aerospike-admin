# Copyright 2013-2025 Aerospike, Inc.
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

import asyncio
import warnings

import unittest

from lib.live_cluster.client import client_util


class UtilTest(unittest.IsolatedAsyncioTestCase):
    def test_info_to_dict(self):
        value = "a=1;b=@;c=c;d=1@"
        expected = {"a": "1", "b": "@", "c": "c", "d": "1@"}
        result = client_util.info_to_dict(value)
        self.assertEqual(
            result, expected, "info_to_dict did not return the expected result"
        )
        value = ":".join(value.split(";"))
        result = client_util.info_to_dict(value, ":")
        self.assertEqual(
            result, expected, "info_to_dict did not return the expected result"
        )

        value = "dc-name=REMOTE_DC_1:nodes=2000:10:3:0:0:0:100:d+3000:int-ext-ipmap=172.68.17.123"
        expected = {
            "int-ext-ipmap": "172.68.17.123",
            "nodes": "2000:10:3:0:0:0:100:d+3000",
            "dc-name": "REMOTE_DC_1",
        }
        result = client_util.info_to_dict(
            value, ":", ignore_field_without_key_value_delimiter=False
        )
        self.assertEqual(
            result, expected, "info_to_dict did not return the expected result"
        )

    def test_info_to_dict_multi_level(self):
        value = "ns=test:rack_1=BCD10DFA9290C00,BB910DFA9290C00:rack_2=BD710DFA9290C00,BC310DFA9290C00;ns=bar:rack_1=BD710DFA9290C00,BB910DFA9290C00:rack_2=BC310DFA9290C00,BCD10DFA9290C00"
        expected = {
            "test": {
                "rack_2": "BD710DFA9290C00,BC310DFA9290C00",
                "ns": "test",
                "rack_1": "BCD10DFA9290C00,BB910DFA9290C00",
            },
            "bar": {
                "rack_2": "BC310DFA9290C00,BCD10DFA9290C00",
                "ns": "bar",
                "rack_1": "BD710DFA9290C00,BB910DFA9290C00",
            },
        }
        result = client_util.info_to_dict_multi_level(value, "ns")
        self.assertEqual(
            result,
            expected,
            "info_to_dict_multi_level did not return the expected result",
        )

        value = "dc-name=REMOTE_DC:dc-type=aerospike:tls-name=:dc-security-config-file=/private/aerospike/security_credentials_REMOTE_DC.txt:nodes=2000:10:3:0:0:0:100:d+3000,192.168.100.147+3000:int-ext-ipmap=:dc-connections=64:dc-connections-idle-ms=55000:dc-use-alternate-services=false:namespaces=test;dc-name=NEW_DC:dc-type=aerospike:tls-name=:dc-security-config-file=/private/aerospike/security_credentials_NEW_DC.txt:nodes=2000:10:3:0:0:0:101:d+3000,192.168.100.147+3000:int-ext-ipmap=:dc-connections=32:dc-connections-idle-ms=55000:dc-use-alternate-services=false:namespaces=test"
        expected = {
            "NEW_DC": {
                "dc-security-config-file": "/private/aerospike/security_credentials_NEW_DC.txt",
                "tls-name": "",
                "dc-name": "NEW_DC",
                "dc-connections-idle-ms": "55000",
                "dc-use-alternate-services": "false",
                "int-ext-ipmap": "",
                "dc-connections": "32",
                "namespaces": "test",
                "nodes": "2000:10:3:0:0:0:101:d+3000,192.168.100.147+3000",
                "dc-type": "aerospike",
            },
            "REMOTE_DC": {
                "dc-security-config-file": "/private/aerospike/security_credentials_REMOTE_DC.txt",
                "tls-name": "",
                "dc-name": "REMOTE_DC",
                "dc-connections-idle-ms": "55000",
                "dc-use-alternate-services": "false",
                "int-ext-ipmap": "",
                "dc-connections": "64",
                "namespaces": "test",
                "nodes": "2000:10:3:0:0:0:100:d+3000,192.168.100.147+3000",
                "dc-type": "aerospike",
            },
        }
        result = client_util.info_to_dict_multi_level(
            value,
            ["dc-name", "DC_Name"],
            delimiter1=";",
            delimiter2=":",
            ignore_field_without_key_value_delimiter=False,
        )
        self.assertEqual(
            result,
            expected,
            "info_to_dict_multi_level did not return the expected result",
        )

    def test_info_colon_to_dict(self):
        value = "a=1:b=@:c=c:d=1@"
        expected = {"a": "1", "b": "@", "c": "c", "d": "1@"}
        result = client_util.info_colon_to_dict(value)
        self.assertEqual(
            result, expected, "info_colon_to_dict did not return the expected result"
        )

    def test_info_to_list(self):
        value = "a=1;b=@;c=c;d=1@"
        expected = ["a=1", "b=@", "c=c", "d=1@"]
        result = client_util.info_to_list(value)
        self.assertEqual(
            result, expected, "info_to_list did not return the expected result"
        )
        value = "a=1:b=@:c=c:d=1@"
        result = client_util.info_to_list(value, ":")
        self.assertEqual(
            result, expected, "info_to_list did not return the expected result"
        )

    def test_info_to_tuple(self):
        value = "a=1;b=@;c=c;d=1@"
        expected = ("a=1", "b=@", "c=c", "d=1@")
        result = client_util.info_to_tuple(value, ";")
        self.assertEqual(
            result, expected, "info_to_tuple did not return the expected result"
        )
        value = "a=1:b=@:c=c:d=1@"
        result = client_util.info_to_tuple(value)
        self.assertEqual(
            result, expected, "info_to_tuple did not return the expected result"
        )

    def test_find_dns(self):
        self.assertEqual(
            client_util.find_dns(None),
            None,
            "find_dns did not return the expected result",
        )
        self.assertEqual(
            client_util.find_dns([]),
            None,
            "find_dns did not return the expected result",
        )
        result = client_util.find_dns(["[2001:db8:85a3::8a2e]:6666", "127.0.0.1"])
        expected = None
        self.assertEqual(
            result, expected, "find_dns did not return the expected result"
        )
        result = client_util.find_dns(
            ["[2001:db8:85a3::8a2e]:6666", "127.0.0.1", "abcd"]
        )
        expected = "abcd"
        self.assertEqual(
            result, expected, "find_dns did not return the expected result"
        )

    def test_parse_peers_string(self):
        peers_str = "10,3000,[[BB9050011AC4202,tls_name,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]"
        result = client_util.parse_peers_string(peers_str)
        expected = [
            "10",
            "3000",
            "[[BB9050011AC4202,tls_name,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]",
        ]
        self.assertEqual(
            result, expected, "parse_peers_string did not return the expected result"
        )
        result = client_util.parse_peers_string(expected[2])
        expected = [
            "[BB9050011AC4202,tls_name,[172.17.0.1]]",
            "[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]",
        ]
        self.assertEqual(
            result, expected, "parse_peers_string did not return the expected result"
        )
        result = client_util.parse_peers_string("[2001:db8:85a3::8a2e]:6666", delim=":")
        expected = ["[2001:db8:85a3::8a2e]", "6666"]
        self.assertEqual(
            result, expected, "parse_peers_string did not return the expected result"
        )
        result = client_util.parse_peers_string("127.0.0.1", delim=":")
        expected = ["127.0.0.1"]
        self.assertEqual(
            result, expected, "parse_peers_string did not return the expected result"
        )

    async def test_concurrent_map(self):
        value = range(10)
        expected = [v * v for v in value]

        async def wait(v):
            await asyncio.sleep((11 - v) / 10)
            return v * v

        result = await client_util.concurrent_map(wait, value)
        self.assertEqual(
            list(result), expected, "concurrent_map did not return the expected result"
        )

    def test_flatten(self):
        value = [
            (("172.17.0.1", 3000, None),),
            (("2001:db8:85a3::8a2e", 6666, None), ("172.17.0.3", 3004, None)),
        ]
        expected = [
            ("172.17.0.1", 3000, None),
            ("2001:db8:85a3::8a2e", 6666, None),
            ("172.17.0.3", 3004, None),
        ]
        result = client_util.flatten(value)
        self.assertEqual(result, expected, "flatten did not return the expected result")

    def test_remove_suffix(self):
        value = "test-message-value"
        expected = "test-message"
        result = client_util.remove_suffix(value, "-value")
        self.assertEqual(
            result, expected, "remove_suffix did not return the expected result"
        )

        result = client_util.remove_suffix(value + "     ", "-value")
        self.assertEqual(
            result, expected, "remove_suffix did not return the expected result"
        )

        result = client_util.remove_suffix(value, "wrongsuffix")
        self.assertEqual(
            result, value, "remove_suffix did not return the expected result"
        )

        result = client_util.remove_suffix(123, "-value")
        self.assertEqual(
            result, 123, "remove_suffix did not return the expected result"
        )
