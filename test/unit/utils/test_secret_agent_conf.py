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

from lib.utils.password_source import PasswordSourceError
from lib.utils.secret_agent_conf import SecretAgentSettings, file_section


def settings(file_values=None, cli_values=None, section="secret-agent"):
    return SecretAgentSettings(section, file_values or {}, cli_values or {})


class PrecedenceTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("defaults", {}, {}, "127.0.0.1", 3005),
            ("cli_address", {}, {"sa-address": "agent"}, "agent", 3005),
            ("cli_address_port", {}, {"sa-address": "agent:4000"}, "agent", 4000),
            ("cli_port", {}, {"sa-port": "4000"}, "127.0.0.1", 4000),
            ("ipv6", {}, {"sa-address": "[::1]:4000"}, "::1", 4000),
            (
                "explicit_port_beats_address_port",
                {},
                {"sa-address": "agent:4000", "sa-port": "5000"},
                "agent",
                5000,
            ),
            (
                "config_explicit_port_beats_address_port",
                {"sa-address": "agent:4000", "sa-port": 5000},
                {},
                "agent",
                5000,
            ),
            (
                "cli_address_port_beats_config_port",
                {"sa-port": 5000},
                {"sa-address": "agent:4000"},
                "agent",
                4000,
            ),
            (
                "cli_port_beats_config_address_port",
                {"sa-address": "agent:4000"},
                {"sa-port": "5000"},
                "agent",
                5000,
            ),
            (
                "config_port_applies_to_cli_address_without_port",
                {"sa-port": 5000},
                {"sa-address": "agent"},
                "agent",
                5000,
            ),
            (
                "cli_beats_config",
                {"sa-address": "conf:5000"},
                {"sa-address": "cli:4000"},
                "cli",
                4000,
            ),
            ("config_port_as_string", {"sa-port": "4000"}, {}, "127.0.0.1", 4000),
        ]
    )
    def test_address(self, _, file_values, cli_values, host, port):
        s = settings(file_values, cli_values)
        self.assertEqual((s.host, s.port), (host, port))

    def test_timeout_and_cafile(self):
        s = settings(
            {"sa-timeout": 250, "sa-cafile": "/conf-ca.pem"},
            {"sa-timeout": "500"},
        )
        self.assertEqual(s.timeout_ms, 500)
        self.assertEqual(s.cafile, "/conf-ca.pem")


class ValidationTest(unittest.TestCase):
    @parameterized.expand(
        [
            (
                "address",
                {"sa-address": "host:3005:x"},
                "--sa-address: invalid value host:3005:x",
            ),
            ("port", {"sa-port": "0"}, "--sa-port: invalid value 0"),
            ("port_range", {"sa-port": "70000"}, "--sa-port: invalid value 70000"),
            (
                "zero_timeout",
                {"sa-timeout": "0"},
                "--sa-timeout: invalid value 0, expected an integer from 1 to 2147483647",
            ),
            (
                "negative_timeout",
                {"sa-timeout": "-5"},
                "--sa-timeout: invalid value -5, expected an integer from 1 to 2147483647",
            ),
            (
                "text_timeout",
                {"sa-timeout": "1s"},
                "--sa-timeout: invalid value 1s, expected an integer from 1 to 2147483647",
            ),
        ]
    )
    def test_command_line(self, _, cli_values, message):
        with self.assertRaises(PasswordSourceError) as cm:
            settings(cli_values=cli_values)

        self.assertEqual(str(cm.exception), message)

    def test_config_section(self):
        with self.assertRaises(PasswordSourceError) as cm:
            settings({"sa-port": 0}, section="secret-agent_prod")

        self.assertEqual(
            str(cm.exception),
            "invalid value 0 for sa-port in the [secret-agent_prod] config section",
        )

    def test_bad_cafile_fails_when_the_client_is_created(self):
        s = settings(cli_values={"sa-cafile": "/nonexistent/ca.pem"})

        with self.assertRaises(PasswordSourceError) as cm:
            s.new_client()

        self.assertIn(
            "--sa-cafile: cannot load TLS CA file /nonexistent/ca.pem",
            str(cm.exception),
        )


class FileSectionTest(unittest.TestCase):
    CONF = {
        "secret-agent": {"sa-address": "default"},
        "secret-agent_prod": {"sa-address": "prod"},
    }

    def test_without_instance(self):
        self.assertEqual(
            file_section(self.CONF, None), ("secret-agent", {"sa-address": "default"})
        )

    def test_instance_section_replaces_default(self):
        self.assertEqual(
            file_section(self.CONF, "prod"),
            ("secret-agent_prod", {"sa-address": "prod"}),
        )

    def test_instance_falls_back_to_default(self):
        self.assertEqual(
            file_section(self.CONF, "dev"), ("secret-agent", {"sa-address": "default"})
        )

    def test_no_section(self):
        self.assertEqual(file_section({}, "dev"), ("secret-agent", {}))


if __name__ == "__main__":
    unittest.main()
