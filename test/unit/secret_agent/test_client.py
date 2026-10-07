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

import base64
import os
import tempfile
import threading
import time
import traceback
import unittest

from parameterized import parameterized

from lib.secret_agent import (
    InvalidConfigError,
    InvalidResponseError,
    RequestFailedError,
    SecretAgentClient,
    SecretAgentError,
    new_ssl_context,
)
from lib.secret_agent import _wire
from lib.secret_agent.testing import FakeSecretAgent, frame, read_message
from test.unit.secret_agent import pki as test_pki

VALUE = "hunter2"
UNREACHABLE_PORT = 1


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


AGENT_DATA = {
    "aql": {
        "password": b64(VALUE.encode()),
        "newline": b64(VALUE.encode()) + "\n",
        "whitespace": " \t\r\n",
        "not-base64": VALUE,
        "binary": b64(b"\xff" + VALUE.encode()),
        "nul": b64(VALUE.encode() + b"\x00"),
        "empty": "",
        "env-like": b64(b"env:HOME"),
    },
    "": {"bare": b64(b"no-resource")},
}


def agent_client(agent: FakeSecretAgent, **kwargs) -> SecretAgentClient:
    kwargs.setdefault("timeout", 10)

    return SecretAgentClient(agent.host, agent.port, **kwargs)


def assert_no_leak(test: unittest.TestCase, error: Exception) -> None:
    text = "".join(traceback.format_exception(error))
    test.assertNotIn(VALUE, text)


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.agent = FakeSecretAgent(AGENT_DATA).start()
        self.addCleanup(self.agent.stop)
        self.client = agent_client(self.agent)

    def test_resolve(self):
        self.assertEqual(self.client.resolve("secrets:aql:password"), VALUE)

    @parameterized.expand(
        [("plain",), ("",), ("env:HOME",), ("file:/etc/hosts",), ("Secrets:a:b",)]
    )
    def test_resolve_passes_literals_through(self, value):
        self.assertEqual(self.client.resolve(value), value)

    def test_resolve_without_resource(self):
        self.assertEqual(self.client.resolve("secrets:bare"), "no-resource")

    def test_resolved_value_is_not_parsed_again(self):
        self.assertEqual(self.client.resolve("secrets:aql:env-like"), "env:HOME")

    def test_get_secret(self):
        self.assertEqual(self.client.get_secret("aql", "password"), VALUE)
        self.assertEqual(self.client.get_secret("", "bare"), "no-resource")

    def test_trailing_newline_is_trimmed_before_decoding(self):
        self.assertEqual(self.client.get_secret("aql", "newline"), VALUE)

    @parameterized.expand(
        [
            ("whitespace", "empty secret"),
            ("empty", "empty secret"),
            ("not-base64", "is not valid base64"),
            ("binary", "is not valid UTF-8"),
            ("nul", "contains a NUL byte"),
        ]
    )
    def test_unusable_value(self, key, message):
        with self.assertRaises(InvalidResponseError) as cm:
            self.client.get_secret("aql", key)

        self.assertIn(message, str(cm.exception))
        self.assertIn("secrets:aql:" + key, str(cm.exception))
        assert_no_leak(self, cm.exception)

    def test_agent_error(self):
        with self.assertRaises(RequestFailedError) as cm:
            self.client.resolve("secrets:aql:missing")

        self.assertIn("agent error for secrets:aql:missing", str(cm.exception))

    @parameterized.expand([("secrets:aql:",), ("secrets:",)])
    def test_invalid_reference(self, value):
        with self.assertRaises(InvalidConfigError):
            self.client.resolve(value)

    def test_empty_key(self):
        with self.assertRaises(InvalidConfigError):
            self.client.get_secret("aql", "")

    def test_concurrent_use(self):
        errors = []

        def fetch():
            try:
                if self.client.resolve("secrets:aql:password") != VALUE:
                    errors.append("wrong value")
            except SecretAgentError as e:
                errors.append(e)

        threads = [threading.Thread(target=fetch) for _ in range(32)]

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(errors, [])


class RequestTest(unittest.TestCase):
    def capture(self, ref):
        requests = []

        def respond(sock):
            requests.append(read_message(sock))
            sock.sendall(_wire.encode({"SecretValue": b64(VALUE.encode())}))

        with FakeSecretAgent(handler=respond) as agent:
            agent_client(agent).resolve(ref)

        return requests

    def test_resource_is_sent(self):
        self.assertEqual(
            self.capture("secrets:aql:password"),
            [{"SecretKey": "password", "Resource": "aql"}],
        )

    def test_empty_resource_is_left_out(self):
        self.assertEqual(self.capture("secrets:password"), [{"SecretKey": "password"}])
        self.assertEqual(self.capture("secrets::password"), [{"SecretKey": "password"}])


class TransportTest(unittest.TestCase):
    def test_unreachable(self):
        client = SecretAgentClient("127.0.0.1", UNREACHABLE_PORT)

        with self.assertRaises(RequestFailedError) as cm:
            client.resolve("secrets:aql:password")

        self.assertIn(
            "connect to 127.0.0.1:1 for secrets:aql:password", str(cm.exception)
        )

    def test_timeout(self):
        def never_reply(sock):
            read_message(sock)
            time.sleep(5)

        with FakeSecretAgent(handler=never_reply) as agent:
            client = agent_client(agent, timeout=0.2)
            start = time.monotonic()

            with self.assertRaises(RequestFailedError) as cm:
                client.resolve("secrets:aql:password")

            self.assertLess(time.monotonic() - start, 3)
            self.assertIn("timed out", str(cm.exception))

    def test_timeout_covers_the_whole_response(self):
        message = _wire.encode({"SecretValue": b64(VALUE.encode())})

        def drip(sock):
            read_message(sock)

            for byte in message:
                sock.sendall(bytes([byte]))
                time.sleep(0.1)

        with FakeSecretAgent(handler=drip) as agent:
            client = agent_client(agent, timeout=0.5)
            start = time.monotonic()

            with self.assertRaises(RequestFailedError):
                client.resolve("secrets:aql:password")

            self.assertLess(time.monotonic() - start, 2)

    def test_response_in_chunks(self):
        message = _wire.encode({"SecretValue": b64(VALUE.encode())})

        def chunks(sock):
            read_message(sock)

            for i in range(0, len(message), 5):
                sock.sendall(message[i : i + 5])
                time.sleep(0.01)

        with FakeSecretAgent(handler=chunks) as agent:
            self.assertEqual(agent_client(agent).resolve("secrets:a:b"), VALUE)

    @parameterized.expand(
        [
            ("bad_magic", frame(b"{}", magic=0xDEADBEEF), InvalidResponseError),
            (
                "malformed_body",
                frame(b'{"SecretValue":"' + VALUE.encode()),
                InvalidResponseError,
            ),
            (
                "not_an_object",
                frame(b'"' + VALUE.encode() + b'"'),
                InvalidResponseError,
            ),
            ("deep_nesting", frame(b"[" * 200000), InvalidResponseError),
            (
                "value_not_a_string",
                frame(b'{"SecretValue":["' + VALUE.encode() + b'"]}'),
                InvalidResponseError,
            ),
            ("error_not_a_string", frame(b'{"Error":1}'), InvalidResponseError),
            (
                "empty_error_with_value",
                frame(b'{"Error":"","SecretValue":"aHVudGVyMg=="}'),
                RequestFailedError,
            ),
            (
                "oversized",
                _wire.HEADER.pack(_wire.MAGIC, 1 << 21),
                InvalidResponseError,
            ),
            (
                "truncated",
                frame(b'{"SecretValue":"' + VALUE.encode() + b'"}')[:12],
                RequestFailedError,
            ),
            ("closed", b"", RequestFailedError),
        ]
    )
    def test_broken_agent(self, _, response, error):
        def respond(sock):
            read_message(sock)
            sock.sendall(response)

        with FakeSecretAgent(handler=respond) as agent:
            with self.assertRaises(error) as cm:
                agent_client(agent).resolve("secrets:aql:password")

        assert_no_leak(self, cm.exception)


class TLSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.pki = test_pki.generate(cls.tmp.name)

        other = os.path.join(cls.tmp.name, "other")
        os.mkdir(other)
        cls.untrusted = test_pki.generate(other)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def fetch(self, **client_kwargs):
        with FakeSecretAgent(
            AGENT_DATA, ssl_context=self.pki.server_context()
        ) as agent:
            return agent_client(agent, **client_kwargs).resolve("secrets:aql:password")

    def test_ca(self):
        ctx = new_ssl_context(self.pki.ca_file)
        self.assertEqual(self.fetch(ssl_context=ctx), VALUE)

    def test_untrusted_ca(self):
        ctx = new_ssl_context(self.untrusted.ca_file)

        with self.assertRaises(RequestFailedError):
            self.fetch(ssl_context=ctx)

    def test_plaintext_to_tls_agent(self):
        with self.assertRaises(SecretAgentError):
            self.fetch()

    @parameterized.expand([("/nonexistent/ca.pem",), ("bad\x00path",)])
    def test_invalid_ca_file(self, ca_file):
        with self.assertRaises(InvalidConfigError):
            new_ssl_context(ca_file)


class ClientConfigTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("zero_timeout", {"timeout": 0}),
            ("negative_timeout", {"timeout": -1}),
            ("infinite_timeout", {"timeout": float("inf")}),
            ("nan_timeout", {"timeout": float("nan")}),
            ("bool_timeout", {"timeout": True}),
            ("bad_port", {"port": 0}),
            ("empty_host", {"host": ""}),
        ]
    )
    def test_invalid(self, _, kwargs):
        with self.assertRaises(InvalidConfigError):
            SecretAgentClient(**kwargs)

    def test_defaults(self):
        self.assertEqual(SecretAgentClient().address, "127.0.0.1:3005")

    def test_ipv6_address(self):
        self.assertEqual(SecretAgentClient("::1", 4000).address, "[::1]:4000")


if __name__ == "__main__":
    unittest.main()
