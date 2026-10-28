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

import tempfile
import unittest

from parameterized import parameterized

from lib.utils.password_source import PasswordSourceError
from lib.utils.secret_agent_conf import SecretAgentSettings, file_section
from test.unit.secret_agent import pki


def settings(file_values=None, cli_values=None, section="secret-agent"):
    return SecretAgentSettings([(section, file_values or {})], cli_values or {})


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

    def test_command_line_beats_config_per_key(self):
        s = settings(
            {
                "sa-address": "conf",
                "sa-port": 5000,
                "sa-timeout": 250,
                "sa-ca-file": "/conf.pem",
            },
            {"sa-port": "4000"},
        )
        self.assertEqual(
            (s.host, s.port, s.timeout_ms, s.cafile), ("conf", 4000, 250, "/conf.pem")
        )

    def test_later_file_beats_earlier_per_key(self):
        s = SecretAgentSettings(
            [
                ("secret-agent", {"sa-address": "first:4000", "sa-timeout": 250}),
                ("secret-agent", {"sa-address": "second", "sa-ca-file": "/b.pem"}),
            ],
            {},
        )
        self.assertEqual(
            (s.host, s.port, s.timeout_ms, s.cafile), ("second", 4000, 250, "/b.pem")
        )

    @parameterized.expand([("min", 1), ("max", 2147483647)])
    def test_timeout_range(self, _, value):
        for file_values, cli_values in (
            ({"sa-timeout": value}, {}),
            ({"sa-timeout": str(value)}, {}),
            ({}, {"sa-timeout": str(value)}),
        ):
            with self.subTest(file_values=file_values, cli_values=cli_values):
                self.assertEqual(settings(file_values, cli_values).timeout_ms, value)

    @parameterized.expand(
        [
            ("config_c_spelling", {"sa-cafile": "/c.pem"}, {}, "/c.pem"),
            ("config_go_spelling", {"sa-ca-file": "/go.pem"}, {}, "/go.pem"),
            ("cli_go_spelling", {}, {"sa-ca-file": "/go.pem"}, "/go.pem"),
            (
                "config_go_spelling_beats_c_spelling",
                {"sa-ca-file": "/go.pem", "sa-cafile": "/c.pem"},
                {},
                "/go.pem",
            ),
            (
                "cli_go_spelling_beats_c_spelling",
                {},
                {"sa-cafile": "/c.pem", "sa-ca-file": "/go.pem"},
                "/go.pem",
            ),
            (
                "cli_c_spelling_beats_config_go_spelling",
                {"sa-ca-file": "/conf.pem"},
                {"sa-cafile": "/cli.pem"},
                "/cli.pem",
            ),
            (
                "cli_go_spelling_beats_config_c_spelling",
                {"sa-cafile": "/conf.pem"},
                {"sa-ca-file": "/cli.pem"},
                "/cli.pem",
            ),
        ]
    )
    def test_cafile_spellings(self, _, file_values, cli_values, cafile):
        self.assertEqual(settings(file_values, cli_values).cafile, cafile)


class ValidationTest(unittest.TestCase):
    @parameterized.expand(
        [
            (
                "address",
                {"sa-address": "host:3005:x"},
                "--sa-address: invalid value host:3005:x,"
                " expected <host>[:<port>] or [<ipv6>][:<port>]",
            ),
            (
                "port",
                {"sa-port": "0"},
                "--sa-port: invalid value 0, expected an integer from 1 to 65535",
            ),
            (
                "port_range",
                {"sa-port": "70000"},
                "--sa-port: invalid value 70000, expected an integer from 1 to 65535",
            ),
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

    @parameterized.expand(
        [
            ("too_large", "2147483648"),
            ("far_too_large", "99999999999"),
            ("decimal", "1000.0"),
            ("signed", "+5"),
            ("padded", " 5"),
            ("non_ascii_digit", "５"),
        ]
    )
    def test_command_line_timeout(self, _, value):
        with self.assertRaises(PasswordSourceError) as cm:
            settings(cli_values={"sa-timeout": value})

        self.assertEqual(
            str(cm.exception),
            "--sa-timeout: invalid value {}, expected an integer from 1 to"
            " 2147483647".format(value),
        )

    @parameterized.expand(
        [
            ("zero", 0),
            ("negative", -5),
            ("too_large", 2147483648),
            ("float", 1000.0),
            ("bool", True),
            ("zero_string", "0"),
            ("text", "1s"),
        ]
    )
    def test_config_timeout(self, _, value):
        with self.assertRaises(PasswordSourceError) as cm:
            settings({"sa-timeout": value})

        self.assertEqual(
            str(cm.exception),
            "invalid value {} for sa-timeout in the [secret-agent] config section,"
            " expected an integer from 1 to 2147483647".format(value),
        )

    def test_config_section(self):
        with self.assertRaises(PasswordSourceError) as cm:
            settings({"sa-port": 0}, section="secret-agent_prod")

        self.assertEqual(
            str(cm.exception),
            "invalid value 0 for sa-port in the [secret-agent_prod] config section,"
            " expected an integer from 1 to 65535",
        )

    @parameterized.expand(
        [
            ("ca_file", {}, {"sa-ca-file": ""}, "--sa-ca-file"),
            ("legacy_cafile", {}, {"sa-cafile": ""}, "--sa-cafile"),
            (
                "ca_file_with_legacy_cafile",
                {},
                {"sa-ca-file": "", "sa-cafile": "{ca}"},
                "--sa-ca-file",
            ),
            (
                "command_line_over_config",
                {"sa-ca-file": "{ca}"},
                {"sa-ca-file": ""},
                "--sa-ca-file",
            ),
            (
                "config_ca_file",
                {"sa-ca-file": ""},
                {},
                "sa-ca-file in the [secret-agent] config section",
            ),
            (
                "config_legacy_cafile",
                {"sa-cafile": ""},
                {},
                "sa-cafile in the [secret-agent] config section",
            ),
            (
                "config_ca_file_with_legacy_cafile",
                {"sa-ca-file": "", "sa-cafile": "{ca}"},
                {},
                "sa-ca-file in the [secret-agent] config section",
            ),
        ]
    )
    def test_empty_cafile_is_an_error(self, _, file_values, cli_values, option):
        """An empty CA file path is an error. It must not turn TLS off or let the
        other spelling or an earlier source win."""
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        ca = pki.generate(tmpdir.name).ca_file

        def fill(values):
            return {k: v.format(ca=ca) for k, v in values.items()}

        with self.assertRaises(PasswordSourceError) as cm:
            settings(fill(file_values), fill(cli_values)).new_client()

        self.assertIn(option, str(cm.exception))

    @parameterized.expand([("sa-ca-file",), ("sa-cafile",)])
    def test_bad_cafile_fails_when_the_client_is_created(self, option):
        s = settings(cli_values={option: "/nonexistent/ca.pem"})

        with self.assertRaises(PasswordSourceError) as cm:
            s.new_client()

        self.assertIn(
            "--{}: cannot load TLS CA file /nonexistent/ca.pem".format(option),
            str(cm.exception),
        )

    @parameterized.expand([("sa-ca-file",), ("sa-cafile",)])
    def test_bad_cafile_from_the_config_file_names_its_key_and_section(self, option):
        s = settings({option: "/nonexistent/ca.pem"}, section="secret-agent_prod")

        with self.assertRaises(PasswordSourceError) as cm:
            s.new_client()

        self.assertIn(
            "{} in the [secret-agent_prod] config section: cannot load TLS CA file"
            " /nonexistent/ca.pem".format(option),
            str(cm.exception),
        )
        self.assertNotIn("--", str(cm.exception))

    def test_cafile_error_names_the_spelling_that_won(self):
        s = settings(
            cli_values={"sa-cafile": "/legacy.pem", "sa-ca-file": "/nonexistent.pem"}
        )

        with self.assertRaises(PasswordSourceError) as cm:
            s.new_client()

        self.assertIn(
            "--sa-ca-file: cannot load TLS CA file /nonexistent.pem", str(cm.exception)
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

    def test_instance_section_drops_keys_only_in_default(self):
        conf = {
            "secret-agent": {"sa-address": "default", "sa-ca-file": "/default.pem"},
            "secret-agent_prod": {"sa-address": "prod"},
        }
        self.assertEqual(
            file_section(conf, "prod"), ("secret-agent_prod", {"sa-address": "prod"})
        )

    def test_instance_falls_back_to_default(self):
        self.assertEqual(
            file_section(self.CONF, "dev"), ("secret-agent", {"sa-address": "default"})
        )

    def test_no_section(self):
        self.assertEqual(file_section({}, "dev"), ("secret-agent", {}))


if __name__ == "__main__":
    unittest.main()
