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
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from parameterized import parameterized

from lib.secret_agent.testing import FakeSecretAgent
from lib.utils import conf
from lib.utils.constants import AuthMode
from lib.utils.password_source import PasswordSourceError
from test.unit.secret_agent import pki

ASADM = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "asadm.py"
)
PW = "s3cr3t-pw"
PW_B64 = base64.b64encode(PW.encode()).decode()
UNSET = "ASADM_TEST_UNSET_PASSWORD_VAR"
HELP_INDENT = "\n" + " " * 22
KEYFILE_PASSWORD_HELP = (
    " --tls-keyfile-password=password"
    + HELP_INDENT
    + HELP_INDENT.join(
        [
            "Password to load protected tls-keyfile.",
            "It can be one of the following:",
            "1) Environment variable: 'env:<VAR>', used exactly as set",
            "2) Base64 encoded environment variable: 'env-b64:<VAR>'",
            "3) Base64 encoded string: 'b64:<BASE64>'",
            "4) File: 'file:<PATH>', the first line of the file",
            "5) Aerospike Secret Agent: 'secrets:<resource>:<key>'",
            "6) String: 'PASSWORD'",
            "Prefixes are case-sensitive. A base64 value may be line wrapped,",
            "and one trailing newline is dropped after decoding.",
            "A password that itself begins with 'env:', 'env-b64:', 'b64:',",
            "'file:' or 'secrets:' must be given as 'b64:'.",
            "Surrounding whitespace is trimmed before the form is read. A",
            "password with surrounding whitespace must be given as 'b64:'.",
            "The password is read only when a key file is set. It must be at",
            "most 1024 bytes.",
            "A value fetched with 'secrets:' is used as-is.",
            "Default: none",
            "User will be prompted on command line if --tls-keyfile-password",
            "specified and no password is given. The typed password",
            "accepts the forms above except 'secrets:'.",
        ]
    )
    + "\n"
)
SECRET_AGENT_HELP = "\n".join(
    [
        "[secret-agent]",
        " Aerospike Secret Agent used for 'secrets:<resource>:<key>' passwords.",
        " In a config file, set these in the [secret-agent] section as sa-address,",
        " sa-port, sa-timeout and sa-ca-file.",
        ' --sa-address=HOST    HOST is "<host>[:<port>]" or "[<ipv6>][:<port>]".',
        "                      Secret Agent hostname or IP address.",
        "                      Default: 127.0.0.1:3005",
        " --sa-port=PORT       Secret Agent port, 1 to 65535.",
        "                      Overrides a port in --sa-address.",
        "                      Default: 3005",
        " --sa-timeout=ms      Timeout in milliseconds for Secret Agent requests, an",
        "                      integer from 1 to 2147483647.",
        "                      Default: 1000",
        " --sa-ca-file=path    Path to a CA certificate file. Enables TLS to the Secret",
        "                      Agent and verifies its certificate against this CA. The",
        "                      agent's hostname or IP address must be in the certificate.",
        "                      Default: none",
        "",
    ]
)


class ResolvePasswordSourcesTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

        env = patch.dict(os.environ, {"AS_PASS": PW, "KP": PW})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop(UNSET, None)

        stderr = patch("sys.stderr", io.StringIO())
        stderr.start()
        self.addCleanup(stderr.stop)

    def write_file(self, name, content):
        path = os.path.join(self.tmpdir.name, name)
        with open(path, "w") as f:
            f.write(content)
        return path

    def load(self, *argv, config=None):
        if config is None:
            argv = ("--no-config-file",) + argv
        else:
            argv = (
                "--only-config-file",
                self.write_file("astools.conf", config),
            ) + argv

        with patch("sys.argv", ["asadm", *argv]):
            args, _ = conf.loadconfig(conf.get_cli_args())

        conf.resolve_password_sources(args)
        return args

    def test_password_env_space_separated(self):
        args = self.load("-U", "admin", "-P", "env:AS_PASS")
        self.assertEqual(args.password, PW)

    def test_password_attached_forms(self):
        for argv in (
            ("-U", "admin", "-Pb64:" + PW_B64),
            ("-U", "admin", "--password=b64:" + PW_B64),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(self.load(*argv).password, PW)

    def test_password_file(self):
        path = self.write_file("pw", PW + "\n")
        args = self.load("-U", "admin", "--password", "file:" + path)
        self.assertEqual(args.password, PW)

    def test_password_literal(self):
        args = self.load("-U", "admin", "-P", "pa:ss")
        self.assertEqual(args.password, "pa:ss")

    def test_password_is_not_stripped(self):
        args = self.load("-U", "admin", "-P", " env:AS_PASS ")
        self.assertEqual(args.password, " env:AS_PASS ")

    def test_password_from_config_file(self):
        args = self.load(config='[cluster]\nuser = "admin"\npassword = "env:AS_PASS"\n')
        self.assertEqual(args.password, PW)

    def test_password_from_config_instance(self):
        args = self.load(
            "--instance",
            "a",
            config='[cluster_a]\nuser = "admin"\npassword = "b64:{}"\n'.format(PW_B64),
        )
        self.assertEqual(args.password, PW)

    def test_password_resolved_after_merge(self):
        args = self.load(
            "-P",
            "env:AS_PASS",
            config='[cluster]\nuser = "admin"\npassword = "env:{}"\n'.format(UNSET),
        )
        self.assertEqual(args.password, PW)

    def test_bare_password_left_for_prompt(self):
        args = self.load("-U", "admin", "-P")
        self.assertEqual(args.password, conf.DEFAULTPASSWORD)

    def test_missing_password_left_for_prompt(self):
        args = self.load("-U", "admin")
        self.assertEqual(args.password, conf.DEFAULTPASSWORD)

    def test_password_not_resolved_without_user(self):
        with self.assertLogs(conf.logger, "WARNING"):
            args = self.load("-P", "env:" + UNSET)

        self.assertEqual(args.password, "env:" + UNSET)

    def test_password_error(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load("-U", "admin", "-P", "env:" + UNSET)

        self.assertEqual(
            str(cm.exception),
            "--password: environment variable {} is not set or empty".format(UNSET),
        )

    def test_password_from_source_limited_to_63_bytes(self):
        with patch.dict(os.environ, {"AS_LONG": "x" * 64}):
            with self.assertRaises(PasswordSourceError) as cm:
                self.load("-U", "admin", "-P", "env:AS_LONG")

        self.assertEqual(
            str(cm.exception),
            "--password: value from environment variable AS_LONG is longer than 63 bytes",
        )

    def test_literal_password_limited_to_63_bytes(self):
        args = self.load("-U", "admin", "-P", "x" * 63)
        self.assertEqual(args.password, "x" * 63)

        for password in ("x" * 64, "é" * 32):
            with self.subTest(password=password):
                with self.assertRaises(PasswordSourceError) as cm:
                    self.load("-U", "admin", "-P", password)

                self.assertEqual(
                    str(cm.exception), "--password: password is longer than 63 bytes"
                )

    def test_literal_password_from_config_file_limited_to_63_bytes(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                config='[cluster]\nuser = "admin"\npassword = "{}"\n'.format("x" * 64)
            )

        self.assertEqual(
            str(cm.exception),
            "password in config file: password is longer than 63 bytes",
        )

    def test_password_error_from_config_file(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load(config='[cluster]\nuser = "admin"\npassword = "b64:!!"\n')

        self.assertEqual(
            str(cm.exception), "password in config file: invalid base64 in b64: value"
        )

    def test_password_error_from_config_instance(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                "--instance",
                "x",
                config=(
                    '[cluster]\nuser = "admin"\npassword = "env:AS_PASS"\n'
                    '[cluster_x]\nuser = "admin"\npassword = "env:{}"\n'.format(UNSET)
                ),
            )

        self.assertEqual(
            str(cm.exception),
            "password in config file: environment variable {} is not set or empty".format(
                UNSET
            ),
        )

    def test_password_label_follows_the_value_used(self):
        config = '[cluster]\nuser = "admin"\npassword = "env:AS_PASS"\n'

        for argv, label in (
            ((), "password in config file"),
            (("-P", "env:AS_PASS"), "--password"),
            (("-P",), "--password"),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(
                    conf.option_label(self.load(*argv, config=config), "password"),
                    label,
                )

        self.assertEqual(
            conf.option_label(self.load("-U", "admin"), "password"), "--password"
        )

    def test_command_line_password_error_overrides_config_file(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                "-P",
                "file:",
                config='[cluster]\nuser = "admin"\npassword = "env:AS_PASS"\n',
            )

        self.assertEqual(str(cm.exception), "--password: file: requires a path")

    def test_password_with_empty_name(self):
        for value, message in (
            ("env:", "--password: env: requires a variable name"),
            ("env-b64:", "--password: env-b64: requires a variable name"),
            ("file:", "--password: file: requires a path"),
            ("b64:", "--password: password from b64: value is empty"),
        ):
            with self.subTest(value=value):
                with self.assertRaises(PasswordSourceError) as cm:
                    self.load("-U", "admin", "-P", value)

                self.assertEqual(str(cm.exception), message)

    def test_no_user_warns_for_a_source(self):
        for argv, config, label in (
            (("-P", "env:" + UNSET), None, "--password"),
            (("-P", "file:"), None, "--password"),
            ((), '[cluster]\npassword = "b64:!!"\n', "password in config file"),
        ):
            with self.subTest(argv=argv, config=config):
                with self.assertLogs(conf.logger, "WARNING") as logs:
                    self.load(*argv, config=config)

                self.assertEqual(
                    [r.getMessage() for r in logs.records],
                    [label + ": ignored because no user is set"],
                )

    def test_no_user_does_not_warn_for_a_literal(self):
        for argv in (("-P", "x" * 64), ("-P",), ("-P", "ENV:" + UNSET), ()):
            with self.subTest(argv=argv), self.assertNoLogs(conf.logger, "WARNING"):
                self.load(*argv)

    def test_pki_skips_password_resolution(self):
        for argv in (
            ("-U", "admin", "--auth", "pki", "-P", "env:" + UNSET),
            ("-U", "admin", "--auth", "Pki", "-P", "x" * 64),
        ):
            with self.subTest(argv=argv), self.assertNoLogs(conf.logger, "WARNING"):
                self.assertEqual(self.load(*argv).password, argv[-1])

        with self.assertNoLogs(conf.logger, "WARNING"):
            args = self.load(
                config='[cluster]\nauth = "pki"\npassword = "env:{}"\n'.format(UNSET)
            )

        self.assertEqual(args.password, "env:" + UNSET)

    def test_pki_leaves_bare_password_for_prompt(self):
        args = self.load("-U", "admin", "--auth", "PKI", "-P")
        self.assertEqual(args.password, conf.DEFAULTPASSWORD)

    def test_keyfile_password_env(self):
        args = self.load(
            "--tls-enable",
            "--tls-keyfile",
            "/k.pem",
            "--tls-keyfile-password",
            "env:KP",
        )
        self.assertEqual(args.tls_keyfile_password, PW)

    def test_keyfile_password_env_b64_from_config_file(self):
        with patch.dict(os.environ, {"KP_B64": PW_B64}):
            args = self.load(
                config=(
                    "[cluster]\ntls-enable = true\n"
                    'tls-keyfile = "/k.pem"\n'
                    'tls-keyfile-password = "env-b64:KP_B64"\n'
                )
            )
        self.assertEqual(args.tls_keyfile_password, PW)

    def test_keyfile_password_file(self):
        path = self.write_file("kp", PW + "\r\n")
        args = self.load(
            "--tls-enable",
            "--tls-keyfile",
            "/k.pem",
            "--tls-keyfile-password",
            "file:" + path,
        )
        self.assertEqual(args.tls_keyfile_password, PW)

    def test_keyfile_password_file_is_not_stripped(self):
        path = self.write_file("kp", "  " + PW + "  \n\n")
        args = self.load(
            "--tls-enable",
            "--tls-keyfile",
            "/k.pem",
            "--tls-keyfile-password",
            "file:" + path,
        )
        self.assertEqual(args.tls_keyfile_password, "  " + PW + "  ")

    def test_keyfile_password_file_empty_first_line(self):
        path = self.write_file("kp", "\n" + PW + "\n")

        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                "--tls-enable",
                "--tls-keyfile",
                "/k.pem",
                "--tls-keyfile-password",
                "file:" + path,
            )

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: password from first line of file {} is empty".format(
                path
            ),
        )

    def test_keyfile_password_file_uses_first_line(self):
        path = self.write_file("kp", PW + "\nsecond line\n")
        args = self.load(
            "--tls-enable",
            "--tls-keyfile",
            "/k.pem",
            "--tls-keyfile-password",
            "file:" + path,
        )
        self.assertEqual(args.tls_keyfile_password, PW)

    def test_keyfile_password_limited_to_1024_bytes(self):
        tls = ("--tls-enable", "--tls-keyfile", "/k.pem", "--tls-keyfile-password")
        path = self.write_file("kp", "x" * 1025 + "\n")

        with patch.dict(os.environ, {"KP": "x" * 1024}):
            for value in ("x" * 1024, "env:KP"):
                with self.subTest(value=value[:8]):
                    args = self.load(*tls, value)
                    self.assertEqual(args.tls_keyfile_password, "x" * 1024)

        with patch.dict(os.environ, {"KP": "x" * 1025}):
            for value, message in (
                ("x" * 1025, "password is longer than 1024 bytes"),
                (
                    "env:KP",
                    "value from environment variable KP is longer than 1024 bytes",
                ),
                (
                    "file:" + path,
                    "value from file {} is longer than 1024 bytes".format(path),
                ),
            ):
                with self.subTest(value=value[:8]):
                    with self.assertRaises(PasswordSourceError) as cm:
                        self.load(*tls, value)

                    self.assertEqual(
                        str(cm.exception), "--tls-keyfile-password: " + message
                    )

    def test_keyfile_password_label_follows_the_value_used(self):
        config = (
            "[cluster]\ntls-enable = true\n"
            'tls-keyfile = "/k.pem"\n'
            'tls-keyfile-password = "env:{}"\n'.format(UNSET)
        )

        for argv, label in (
            ((), "tls-keyfile-password in config file"),
            (("--tls-keyfile-password", "env:" + UNSET), "--tls-keyfile-password"),
        ):
            with self.subTest(argv=argv):
                with self.assertRaises(PasswordSourceError) as cm:
                    self.load(*argv, config=config)

                self.assertEqual(
                    str(cm.exception),
                    "{}: environment variable {} is not set or empty".format(
                        label, UNSET
                    ),
                )

    def test_keyfile_password_from_command_line_overrides_config_file(self):
        args = self.load(
            "--tls-keyfile-password",
            "env:KP",
            config=(
                "[cluster]\ntls-enable = true\n"
                'tls-keyfile = "/k.pem"\n'
                'tls-keyfile-password = "env:{}"\n'.format(UNSET)
            ),
        )
        self.assertEqual(args.tls_keyfile_password, PW)

    def test_padded_keyfile_password_from_config_file(self):
        args = self.load(
            config=(
                "[cluster]\ntls-enable = true\n"
                'tls-keyfile = "/k.pem"\n'
                'tls-keyfile-password = " env:KP "\n'
            )
        )
        self.assertEqual(args.tls_keyfile_password, PW)

    def test_bare_keyfile_password_left_for_prompt(self):
        args = self.load(
            "--tls-enable", "--tls-keyfile", "/k.pem", "--tls-keyfile-password"
        )
        self.assertEqual(args.tls_keyfile_password, conf.DEFAULTPASSWORD)

    def test_keyfile_password_not_resolved_when_unused(self):
        for argv in (
            ("--tls-keyfile", "/k.pem", "--tls-keyfile-password", "env:" + UNSET),
            ("--tls-enable", "--tls-keyfile-password", "env:" + UNSET),
        ):
            with self.subTest(argv=argv):
                args = self.load(*argv)
                self.assertEqual(args.tls_keyfile_password, "env:" + UNSET)

    def test_keyfile_password_error(self):
        path = os.path.join(self.tmpdir.name, "missing")

        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                "--tls-enable",
                "--tls-keyfile",
                "/k.pem",
                "--tls-keyfile-password",
                "file:" + path,
            )

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: cannot read file {}: No such file or directory".format(
                path
            ),
        )


class ResolveSecretsTest(ResolvePasswordSourcesTest):
    """secrets: values, fetched from a fake Secret Agent."""

    def setUp(self):
        super().setUp()

        self.agent = FakeSecretAgent(
            {
                "aql": {
                    "password": PW_B64,
                    "keypass": PW_B64,
                    "envlike": base64.b64encode(b"env:AS_PASS").decode(),
                }
            }
        ).start()
        self.addCleanup(self.agent.stop)

    def test_password(self):
        args = self.load(
            "-U",
            "admin",
            "-P",
            "secrets:aql:password",
            "--sa-address",
            self.agent.address,
        )
        self.assertEqual(args.password, PW)

    def test_option_order(self):
        args = self.load(
            "--sa-address",
            self.agent.address,
            "-P",
            "secrets:aql:password",
            "-U",
            "admin",
        )
        self.assertEqual(args.password, PW)

    def test_address_and_port(self):
        args = self.load(
            "-U",
            "admin",
            "-P",
            "secrets:aql:password",
            "--sa-address",
            self.agent.host,
            "--sa-port",
            str(self.agent.port),
        )
        self.assertEqual(args.password, PW)

    def test_value_is_not_parsed_again(self):
        args = self.load(
            "-U",
            "admin",
            "-P",
            "secrets:aql:envlike",
            "--sa-address",
            self.agent.address,
        )
        self.assertEqual(args.password, "env:AS_PASS")

    def test_keyfile_password(self):
        args = self.load(
            "--tls-enable",
            "--tls-keyfile",
            "/k.pem",
            "--tls-keyfile-password",
            "secrets:aql:keypass",
            "--sa-address",
            self.agent.address,
        )
        self.assertEqual(args.tls_keyfile_password, PW)

    def test_config_file(self):
        args = self.load(
            config=(
                '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-address = "{}"\n'.format(self.agent.address)
            )
        )
        self.assertEqual(args.password, PW)

    def test_config_file_port(self):
        args = self.load(
            config=(
                '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-address = "{}"\nsa-port = {}\n'.format(
                    self.agent.host, self.agent.port
                )
            )
        )
        self.assertEqual(args.password, PW)

    def test_config_file_timeout_in_quotes(self):
        """sa-timeout accepts a quoted number, as sa-port does."""
        args = self.load(
            config=(
                '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-address = "{}"\nsa-timeout = "1000"\n'.format(
                    self.agent.address
                )
            )
        )
        self.assertEqual(args.password, PW)

    def test_config_file_keys_ignore_case(self):
        """As in the C tools."""
        args = self.load(
            config=(
                '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nSA-Address = "{}"\nSA-TIMEOUT = 1000\n'.format(
                    self.agent.address
                )
            )
        )
        self.assertEqual(args.password, PW)

    def test_instance_section_keys_ignore_case(self):
        args = self.load(
            "--instance",
            "a",
            config=(
                '[cluster_a]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent_a]\nSA-ADDRESS = "{}"\n'.format(self.agent.address)
            ),
        )
        self.assertEqual(args.password, PW)

    def test_instance_falls_back_to_secret_agent_section(self):
        args = self.load(
            "--instance",
            "a",
            config=(
                '[cluster_a]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-address = "{}"\n'.format(self.agent.address)
            ),
        )
        self.assertEqual(args.password, PW)

    def test_instance_section_replaces_secret_agent_section(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                "--instance",
                "a",
                config=(
                    '[cluster_a]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                    '[secret-agent]\nsa-address = "{}"\n'
                    '[secret-agent_a]\nsa-address = "127.0.0.1:1"\n'.format(
                        self.agent.address
                    )
                ),
            )

        self.assertIn(
            "connect to 127.0.0.1:1 for secrets:aql:password", str(cm.exception)
        )

    def load_with_user_config(self, user_config, *argv):
        """Loads ~/.aerospike/astools.conf, then the files in argv, as asadm does
        without --only-config-file."""
        home = os.path.join(self.tmpdir.name, "home") + "/"
        os.makedirs(home)

        with open(home + "astools.conf", "w") as f:
            f.write(user_config)

        with patch("lib.utils.conf.ADMIN_HOME", home), patch(
            "sys.argv", ["asadm", *argv]
        ):
            args, _ = conf.loadconfig(conf.get_cli_args())

        conf.resolve_password_sources(args)
        return args

    def test_later_config_file_address_port_beats_earlier_port(self):
        """Each file is applied in turn, as in the C tools: within one file an
        explicit sa-port wins, and a later file's sa-address port wins."""
        args = self.load_with_user_config(
            '[secret-agent]\nsa-port = "1"\n',
            "--config-file",
            self.write_file(
                "later.conf",
                '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-address = "{}"\n'.format(self.agent.address),
            ),
        )
        self.assertEqual(args.password, PW)

    def test_earlier_instance_section_does_not_hide_a_later_file(self):
        args = self.load_with_user_config(
            '[secret-agent_e]\nsa-port = "1"\n',
            "--instance",
            "e",
            "--config-file",
            self.write_file(
                "later.conf",
                '[cluster_e]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-address = "{}"\n'.format(self.agent.address),
            ),
        )
        self.assertEqual(args.password, PW)

    def test_include_applies_after_the_file_that_includes_it(self):
        include = self.write_file(
            "include.conf",
            '[secret-agent]\nsa-address = "{}"\n'.format(self.agent.address),
        )
        args = self.load(
            config=(
                '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-port = "1"\n'
                '[include]\nfile = "{}"\n'.format(include)
            )
        )
        self.assertEqual(args.password, PW)

    def test_include_cafile_beats_the_including_files_ca_file(self):
        include = self.write_file(
            "include.conf", '[secret-agent]\nsa-cafile = "/nonexistent/include.pem"\n'
        )

        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                config=(
                    '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                    '[secret-agent]\nsa-ca-file = "/nonexistent/main.pem"\n'
                    '[include]\nfile = "{}"\n'.format(include)
                )
            )

        self.assertIn("/nonexistent/include.pem", str(cm.exception))

    def test_command_line_beats_config_file(self):
        args = self.load(
            "--sa-address",
            self.agent.address,
            config=(
                '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-address = "127.0.0.1:1"\n'
            ),
        )
        self.assertEqual(args.password, PW)

    def test_missing_secret(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                "-U",
                "admin",
                "-P",
                "secrets:aql:missing",
                "--sa-address",
                self.agent.address,
            )

        self.assertTrue(
            str(cm.exception).startswith(
                "--password: agent error from {} for secrets:aql:missing:".format(
                    self.agent.address
                )
            ),
            str(cm.exception),
        )

    def test_agent_unreachable(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load(
                "--tls-enable",
                "--tls-keyfile",
                "/k.pem",
                "--tls-keyfile-password",
                "secrets:aql:keypass",
                "--sa-address",
                "127.0.0.1:1",
            )

        self.assertTrue(
            str(cm.exception).startswith(
                "--tls-keyfile-password: connect to 127.0.0.1:1 for secrets:aql:keypass"
            ),
            str(cm.exception),
        )

    def test_invalid_agent_option(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load("-U", "admin", "-P", "secrets:aql:password", "--sa-port", "0")

        self.assertEqual(
            str(cm.exception),
            '--sa-port: invalid value "0", expected an integer from 1 to 65535',
        )

    @parameterized.expand(
        [
            (
                "port",
                "--sa-port",
                "0",
                '--sa-port: invalid value "0", expected an integer from 1 to 65535',
            ),
            (
                "timeout",
                "--sa-timeout",
                "0",
                '--sa-timeout: invalid value "0", expected an integer from 1 to'
                " 2147483647",
            ),
            (
                "address",
                "--sa-address",
                "host:3005:x",
                '--sa-address: invalid value "host:3005:x", expected <host>[:<port>]'
                " or [<ipv6>][:<port>]",
            ),
            (
                "empty_ca_file",
                "--sa-ca-file",
                "",
                '--sa-ca-file: invalid value "", expected a path to a CA certificate'
                " file",
            ),
        ]
    )
    def test_agent_options_checked_without_secrets(self, _, option, value, message):
        """As in asbackup, a bad --sa-* value stops every connecting run."""
        for argv in (("-U", "admin", "-P", "admin"), ()):
            with self.subTest(argv=argv):
                with self.assertRaises(PasswordSourceError) as cm:
                    self.load(*argv, option, value)

                self.assertEqual(str(cm.exception), message)

    def test_ca_file_is_read_only_for_a_secret(self):
        args = self.load(
            "-U", "admin", "-P", "admin", "--sa-ca-file", "/nonexistent/ca.pem"
        )
        self.assertEqual(args.password, "admin")

    def test_unselected_sections_are_not_checked(self):
        """Only the section --instance selects is read, as in asbackup and aql."""
        for argv, config in (
            (
                (),
                'secret-agent_dev = "not a table"\n'
                '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-address = "{}"\n'
                "[secret-agent_prod]\nsa-port = 0\nsa-time-out = 1\n",
            ),
            (
                ("--instance", "x"),
                '[cluster_x]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                "[secret-agent]\nsa-port = 0\nsa-time-out = 1\n"
                '[secret-agent_x]\nsa-address = "{}"\n',
            ),
        ):
            with self.subTest(argv=argv):
                with patch("lib.utils.conf.logger") as logger:
                    args = self.load(*argv, config=config.format(self.agent.address))

                self.assertEqual(args.sagent_config_errors, [])
                logger.critical.assert_not_called()
                self.assertEqual(args.password, PW)

    def test_secret_agent_section_checked_without_an_instance_section(self):
        path = self.write_file("astools.conf", "[secret-agent]\nsa-port = 0\n")

        with patch("lib.utils.conf.logger") as logger:
            args = self.load_config_file(path, "--instance", "y")

        self.assertEqual(
            args.sagent_config_errors,
            [
                'Config file error: {} invalid value "0" for sa-port in the'
                " [secret-agent] config section, expected an integer from 1 to"
                " 65535".format(path)
            ],
        )
        logger.critical.assert_not_called()

    def test_selected_section_that_is_not_a_table(self):
        path = self.write_file("astools.conf", 'secret-agent_dev = "agent:3005"\n')

        with patch("lib.utils.conf.logger") as logger:
            args = self.load_config_file(path, "--instance", "dev")

        self.assertEqual(
            args.sagent_config_errors,
            [
                'Config file error: {} invalid value "agent:3005" for'
                " secret-agent_dev, expected a [secret-agent_dev] config"
                " section".format(path)
            ],
        )
        logger.critical.assert_not_called()

    @parameterized.expand([("collectinfo", "-c"), ("log_analyzer", "-l")])
    def test_bad_section_keeps_the_rest_of_the_file(self, _, mode):
        """A bad [secret-agent] section costs the file none of its other
        sections and does not set the exit code. asadm stops only the runs that
        connect."""
        include = self.write_file("include.conf", "[secret-agent]\nsa-time-out = 1\n")
        path = self.write_file(
            "astools.conf",
            "[cluster]\nport = 3100\n[asadm]\nno-color = true\n"
            '[secret-agent]\nsa-port = 0\n[include]\nfile = "{}"\n'.format(include),
        )

        with patch("sys.argv", ["asadm", "--only-config-file", path, mode]), patch(
            "lib.utils.conf.logger"
        ) as logger:
            args, seeds = conf.loadconfig(conf.get_cli_args())

        self.assertEqual(seeds, [("127.0.0.1", 3100, None)])
        self.assertTrue(args.no_color)
        logger.critical.assert_not_called()
        self.assertEqual(
            args.sagent_config_errors,
            [
                'Config file error: {} invalid value "0" for sa-port in the'
                " [secret-agent] config section, expected an integer from 1 to"
                " 65535".format(path),
                "Config file error: {} unknown key sa-time-out in the"
                " [secret-agent] config section".format(include),
            ],
        )

    def load_config_file(self, path, *argv):
        with patch("sys.argv", ["asadm", "--only-config-file", path, *argv]):
            args, _ = conf.loadconfig(conf.get_cli_args())

        conf.resolve_password_sources(args)
        return args

    def assert_config_file_error_is_not_fatal(self, path, log, message):
        """As on master: the file is skipped or read as missing and the run goes
        on, with or without secrets:."""
        for password, expected in (("secrets:aql:password", PW), ("admin", "admin")):
            with self.subTest(password=password):
                with patch("lib.utils.conf.logger") as logger:
                    args = self.load_config_file(
                        path,
                        "-U",
                        "admin",
                        "-P",
                        password,
                        "--sa-address",
                        self.agent.address,
                    )

                self.assertEqual(args.sagent_config_errors, [])
                self.assertEqual(args.password, expected)
                self.assertIn(message, str(getattr(logger, log).call_args_list))

                if log != "critical":
                    logger.critical.assert_not_called()

    @unittest.skipIf(
        sys.platform == "win32" or os.geteuid() == 0, "needs file permissions"
    )
    def test_unreadable_file_is_read_as_missing(self):
        path = self.write_file("astools.conf", "[secret-agent]\nsa-port = 1\n")
        os.chmod(path, 0)
        self.assert_config_file_error_is_not_fatal(path, "warning", "Permission denied")

    def test_directory_is_read_as_missing(self):
        self.assert_config_file_error_is_not_fatal(
            self.tmpdir.name, "warning", "Is a directory"
        )

    def assert_parse_error_refuses_secrets(self, path, unparsed, log, message):
        """The file is skipped and a run without secrets: goes on, as on master.
        No secret is fetched, since the file may have held the agent's CA."""
        requests = self.record_requests()
        argv = ("-U", "admin", "--sa-address", self.agent.address)

        with patch("lib.utils.conf.logger") as logger:
            args = self.load_config_file(path, *argv, "-P", "admin")

        self.assertEqual(args.password, "admin")
        self.assertIn(message, str(getattr(logger, log).call_args_list))

        with patch("lib.utils.conf.logger"), self.assertRaises(
            PasswordSourceError
        ) as cm:
            self.load_config_file(path, *argv, "-P", "secrets:aql:password")

        self.assertEqual(
            str(cm.exception),
            "--password: cannot fetch secrets:aql:password: config file {} could"
            " not be loaded".format(unparsed),
        )
        self.assertEqual(requests, [])

    # toml raises IndexError, not a ValueError, for the inline table typo.
    PARSE_ERRORS = [("section", "[cluster\n"), ("inline_table", "t = { = 1 }\n")]

    @parameterized.expand(PARSE_ERRORS)
    def test_parse_error_skips_the_file(self, _, typo):
        path = self.write_file("astools.conf", typo)
        self.assert_parse_error_refuses_secrets(
            path, path, "critical", "Config file parse error: " + path
        )

    @parameterized.expand(PARSE_ERRORS)
    def test_parse_error_in_included_file_skips_it(self, _, typo):
        include = self.write_file("include.conf", typo)
        path = self.write_file(
            "astools.conf", '[include]\nfile = "{}"\n'.format(include)
        )
        self.assert_parse_error_refuses_secrets(
            path, include, "error", "Config file parse error: " + include
        )

    @unittest.skipIf(
        sys.platform == "win32" or os.geteuid() == 0, "needs file permissions"
    )
    def test_unreadable_include_directory_refuses_secrets(self):
        directory = os.path.join(self.tmpdir.name, "conf.d")
        os.mkdir(directory)
        os.chmod(directory, 0)
        self.addCleanup(os.chmod, directory, 0o700)
        path = self.write_file(
            "astools.conf", '[include]\ndirectory = "{}"\n'.format(directory)
        )
        self.assert_parse_error_refuses_secrets(
            path,
            directory,
            "warning",
            "'Config file read error : %s %s', '{}', 'Permission denied'".format(
                directory
            ),
        )

    def test_missing_include_directory_is_ignored(self):
        path = self.write_file(
            "astools.conf",
            '[include]\ndirectory = "{}"\n'.format(
                os.path.join(self.tmpdir.name, "missing")
            ),
        )
        args = self.load_config_file(
            path,
            "-U",
            "admin",
            "-P",
            "secrets:aql:password",
            "--sa-address",
            self.agent.address,
        )
        self.assertEqual(args.password, PW)

    def test_include_directory_skips_a_bad_entry(self):
        directory = os.path.join(self.tmpdir.name, "conf.d")
        os.mkdir(directory)
        readme = os.path.join(directory, "README")

        with open(readme, "w") as f:
            f.write("Put astools.conf files here.\n")

        path = self.write_file(
            "astools.conf", '[include]\ndirectory = "{}"\n'.format(directory)
        )
        self.assert_parse_error_refuses_secrets(
            path, readme, "error", "Config file parse error: " + directory
        )

    def test_file_that_is_not_utf8_refuses_secrets(self):
        path = os.path.join(self.tmpdir.name, "astools.conf")

        with open(path, "wb") as f:
            f.write(b'[secret-agent]\nsa-ca-file = "/ca\xff.pem"\n')

        self.assert_parse_error_refuses_secrets(
            path, path, "critical", "Config file parse error: " + path
        )

    def test_parse_error_refuses_a_secret_from_another_file(self):
        """The CA file sits in an include that does not parse, so fetching the
        secret would send it to the agent in plaintext."""
        include = self.write_file(
            "include.conf", '[secret-agent]\nsa-ca-file = "/ca.pem"\n[cluster\n'
        )
        path = self.write_file(
            "astools.conf",
            '[cluster]\nuser = "admin"\npassword = "secrets:aql:password"\n'
            '[secret-agent]\nsa-address = "{}"\n[include]\nfile = "{}"\n'.format(
                self.agent.address, include
            ),
        )
        requests = self.record_requests()

        with patch("lib.utils.conf.logger"), self.assertRaises(
            PasswordSourceError
        ) as cm:
            self.load_config_file(path)

        self.assertEqual(
            str(cm.exception),
            "password in config file: cannot fetch secrets:aql:password: config"
            " file {} could not be loaded".format(include),
        )
        self.assertEqual(requests, [])

    def test_empty_legacy_cafile_next_to_ca_file_is_not_checked(self):
        """On the command line only the CA option that wins is checked, as in
        asbackup, aql and the asinfo wrapper."""
        for argv in (
            ("--sa-ca-file", "/ca.pem", "--sa-cafile", ""),
            ("--sa-cafile", "", "--sa-ca-file", "/ca.pem"),
        ):
            with self.subTest(argv=argv):
                args = self.load("-U", "admin", "-P", "admin", *argv)
                self.assertEqual(args.password, "admin")

    def test_file_that_includes_itself(self):
        path = os.path.join(self.tmpdir.name, "astools.conf")
        self.write_file("astools.conf", '[include]\nfile = "{}"\n'.format(path))
        self.assert_config_file_error_is_not_fatal(
            path, "error", "Config file parse error: " + path
        )

    def test_expanded_value_is_not_a_reference(self):
        ref = "secrets:aql:password"
        os.environ["SA_REF"] = ref
        os.environ["SA_REF_B64"] = base64.b64encode(ref.encode()).decode()
        path = self.write_file("ref", ref + "\n")

        for value in (
            "b64:" + base64.b64encode(ref.encode()).decode(),
            "env:SA_REF",
            "env-b64:SA_REF_B64",
            "file:" + path,
        ):
            with self.subTest(value=value):
                args = self.load(
                    "-U", "admin", "-P", value, "--sa-address", "127.0.0.1:1"
                )
                self.assertEqual(args.password, ref)

    def test_expanded_config_value_is_not_a_reference(self):
        ref = "secrets:aql:password"
        args = self.load(
            config=(
                '[cluster]\nuser = "admin"\npassword = "b64:{}"\n'
                '[secret-agent]\nsa-address = "127.0.0.1:1"\n'
            ).format(base64.b64encode(ref.encode()).decode())
        )
        self.assertEqual(args.password, ref)

    def test_go_cafile_spelling_in_config(self):
        with patch("lib.utils.conf.logger") as logger:
            args = self.load(
                "-U",
                "admin",
                "-P",
                "admin",
                config='[secret-agent]\nsa-ca-file = "/ca.pem"\n',
            )

        logger.critical.assert_not_called()
        self.assertEqual(args.password, "admin")

    def test_c_cafile_spelling_is_deprecated_on_the_command_line(self):
        with patch("lib.utils.conf.logger") as logger:
            args = self.load("--sa-cafile", "/ca.pem")

        logger.warning.assert_called_once_with(
            "Argument %s is deprecated. %s", "--sa-cafile", "Use --sa-ca-file instead."
        )
        self.assertEqual(args.sa_cafile, "/ca.pem")

    def test_c_cafile_spelling_in_config_is_not_deprecated(self):
        with patch("lib.utils.conf.logger") as logger:
            self.load(config='[secret-agent]\nsa-cafile = "/ca.pem"\n')

        logger.warning.assert_not_called()
        logger.critical.assert_not_called()

    def test_unknown_config_key_is_rejected(self):
        with patch("lib.utils.conf.logger"):
            args = self.load(config='[secret-agent]\nsa-tls-name = "agent"\n')

        self.assertEqual(
            args.sagent_config_errors,
            [
                "Config file error: {} unknown key sa-tls-name in the [secret-agent]"
                " config section".format(os.path.join(self.tmpdir.name, "astools.conf"))
            ],
        )

    def record_requests(self):
        requests = []
        lookup = self.agent.lookup

        def record(request):
            requests.append(request)
            return lookup(request)

        self.agent.lookup = record
        return requests

    def test_user_is_never_fetched(self):
        ref = "secrets:aql:password"

        for argv, config in (
            (("-U", ref, "-P", ref), None),
            ((), '[cluster]\nuser = "{0}"\npassword = "{0}"\n'.format(ref)),
        ):
            with self.subTest(argv=argv, config=config):
                args = self.load(
                    *argv, "--sa-address", self.agent.address, config=config
                )

                self.assertEqual(args.user, ref)
                self.assertEqual(args.password, PW)

    def test_no_fetch_without_user(self):
        requests = self.record_requests()

        for argv, config, label in (
            (("-P", "secrets:aql:password"), None, "--password"),
            (
                (),
                '[cluster]\npassword = "secrets:aql:password"\n',
                "password in config file",
            ),
        ):
            with self.subTest(argv=argv, config=config):
                with self.assertLogs(conf.logger, "WARNING") as logs:
                    args = self.load(
                        *argv, "--sa-address", self.agent.address, config=config
                    )

                self.assertEqual(args.password, "secrets:aql:password")
                self.assertEqual(
                    [r.getMessage() for r in logs.records],
                    [label + ": ignored because no user is set"],
                )

        self.assertEqual(requests, [])

    def test_ca_file_beats_legacy_cafile_in_either_order(self):
        ca_file = ("--sa-ca-file", "/nonexistent/ca-file.pem")
        legacy = ("--sa-cafile", "/nonexistent/cafile.pem")

        for flags in (ca_file + legacy, legacy + ca_file):
            with self.subTest(flags=flags):
                with self.assertRaises(PasswordSourceError) as cm:
                    self.load(
                        "-U",
                        "admin",
                        "-P",
                        "secrets:aql:password",
                        "--sa-address",
                        self.agent.address,
                        *flags,
                    )

                self.assertEqual(
                    str(cm.exception),
                    '--sa-ca-file: cannot load CA file "/nonexistent/ca-file.pem": No'
                    " such file or directory",
                )

    def test_empty_ca_file_is_an_error(self):
        """An empty CA file path is an error, not a fallback to plaintext."""
        requests = self.record_requests()

        for option in ("--sa-ca-file", "--sa-cafile"):
            with self.subTest(option=option):
                with self.assertRaises(PasswordSourceError) as cm:
                    self.load(
                        "-U",
                        "admin",
                        "-P",
                        "secrets:aql:password",
                        "--sa-address",
                        self.agent.address,
                        option,
                        "",
                    )

                self.assertIn(option, str(cm.exception))

        self.assertEqual(requests, [])

    def test_instance_section_ignores_keys_only_in_secret_agent_section(self):
        args = self.load(
            "--instance",
            "a",
            config=(
                '[cluster_a]\nuser = "admin"\npassword = "secrets:aql:password"\n'
                '[secret-agent]\nsa-ca-file = "/nonexistent/default.pem"\n'
                '[secret-agent_a]\nsa-address = "{}"\n'.format(self.agent.address)
            ),
        )
        self.assertEqual(args.password, PW)


@unittest.skipIf(sys.platform == "win32", "needs a POSIX shell")
class BadSecretAgentSectionTest(unittest.TestCase):
    """A [secret-agent] section asadm cannot use stops asadm before it asks any
    agent for a secret or connects to the cluster, as in the C tools. Any other
    config file problem does not."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

        self.agent = FakeSecretAgent({"aql": {"password": PW_B64}}).start()
        self.addCleanup(self.agent.stop)
        self.requests = []
        lookup = self.agent.lookup

        def record(request):
            self.requests.append(request)
            return lookup(request)

        self.agent.lookup = record

        self.cluster_connections = []
        self.cluster = FakeSecretAgent(
            handler=lambda sock: self.cluster_connections.append(sock.getpeername())
        ).start()
        self.addCleanup(self.cluster.stop)

        directory = os.path.join(self.tmpdir.name, "ca")
        os.mkdir(directory)
        self.ca_file = pki.generate(directory).ca_file

    def write_file(self, name, content):
        path = os.path.join(self.tmpdir.name, name)

        with open(path, "w") as f:
            f.write(content)

        return path

    def run_asadm(self, config, *argv, password="secrets:aql:password"):
        path = self.write_file("astools.conf", config.format(ca=self.ca_file))
        home = os.path.join(self.tmpdir.name, "home")
        os.makedirs(home, exist_ok=True)

        return subprocess.run(
            [sys.executable, ASADM, "--only-config-file", path]
            + ["-h", self.cluster.address, "-U", "admin", "-P", password]
            + ["--sa-address", self.agent.address, *argv],
            capture_output=True,
            text=True,
            env=dict(os.environ, HOME=home),
            stdin=subprocess.DEVNULL,
            timeout=60,
        )

    def assert_stopped_before_any_request(self, cp):
        output = cp.stdout + cp.stderr
        self.assertNotEqual(cp.returncode, 0, output)
        self.assertEqual(self.requests, [], output)
        self.assertEqual(self.cluster_connections, [], output)

    @parameterized.expand(
        [
            ("asinfo_mode", "--asinfo-mode", "-e", "build"),
            ("execute", "-e", "info network"),
        ]
    )
    def test_unknown_key_with_ca_file(self, _, *argv):
        cp = self.run_asadm(
            '[secret-agent]\nsa-ca-file = "{ca}"\nsa-time-out = 500\n', *argv
        )
        self.assert_stopped_before_any_request(cp)
        self.assertIn("sa-time-out", cp.stderr)

    def test_unknown_key_in_instance_section(self):
        cp = self.run_asadm(
            '[secret-agent_a]\nsa-ca-file = "{ca}"\nsa-time-out = 500\n',
            "--instance",
            "a",
            "-e",
            "info network",
        )
        self.assert_stopped_before_any_request(cp)
        self.assertIn("sa-time-out", cp.stderr)

    def test_wrong_type_names_key_and_section(self):
        cp = self.run_asadm(
            '[secret-agent]\nsa-ca-file = "{ca}"\nsa-timeout = 1000.0\n',
            "-e",
            "info network",
        )
        self.assert_stopped_before_any_request(cp)
        self.assertIn(
            'invalid value "1000.0" for sa-timeout in the [secret-agent] config'
            " section, expected an integer from 1 to 2147483647",
            cp.stderr,
        )

    @parameterized.expand(
        [
            ("execute", "-e", "info network"),
            ("asinfo_mode", "--asinfo-mode", "-e", "build"),
        ]
    )
    def test_bad_command_line_value_without_secrets(self, _, *argv):
        cp = self.run_asadm("", *argv, "--sa-port", "0", password="admin")
        self.assert_stopped_before_any_request(cp)
        self.assertIn(
            '--sa-port: invalid value "0", expected an integer from 1 to 65535',
            cp.stderr,
        )

    def assert_reached_the_cluster(self, cp, password):
        output = cp.stdout + cp.stderr
        self.assertNotEqual(self.cluster_connections, [], output)

        if password.startswith("secrets:"):
            self.assertNotEqual(self.requests, [], output)

    @parameterized.expand(
        [
            (name, config, password)
            for name, config, passwords in (
                ("parse_error", "[cluster\n", ("admin",)),
                (
                    "unselected_section",
                    "[secret-agent_dev]\nsa-time-out = 500\n",
                    ("secrets:aql:password", "admin"),
                ),
            )
            for password in passwords
        ]
    )
    def test_other_config_problem_does_not_stop_the_run(self, _, config, password):
        cp = self.run_asadm(config, "-e", "info network", password=password)
        self.assert_reached_the_cluster(cp, password)

    def test_parse_error_stops_a_secret_before_any_request(self):
        """The CA file sits in an include that does not parse, so fetching the
        secret would send it to the agent in plaintext."""
        include = self.write_file(
            "include.conf",
            '[secret-agent]\nsa-ca-file = "{}"\n[cluster\n'.format(self.ca_file),
        )
        cp = self.run_asadm(
            '[include]\nfile = "{}"\n'.format(include), "-e", "info network"
        )
        self.assert_stopped_before_any_request(cp)
        self.assertIn(
            "--password: cannot fetch secrets:aql:password: config file {} could not"
            " be loaded".format(include),
            cp.stderr,
        )

    @parameterized.expand([("sa-ca-file",), ("sa-cafile",)])
    def test_empty_ca_file(self, key):
        """An empty CA file path is an error, not a fallback to plaintext."""
        cp = self.run_asadm(
            '[secret-agent]\n{} = ""\n'.format(key), "-e", "info network"
        )
        self.assert_stopped_before_any_request(cp)
        self.assertIn("{} in the [secret-agent] config section".format(key), cp.stderr)

    def test_unknown_key_without_secrets(self):
        cp = self.run_asadm(
            "[secret-agent]\nsa-time-out = 500\n",
            "-e",
            "info network",
            password="admin",
        )
        self.assert_stopped_before_any_request(cp)
        self.assertIn("sa-time-out", cp.stderr)

    def test_unknown_key_in_included_file(self):
        include = self.write_file(
            "include.conf",
            '[secret-agent]\nsa-ca-file = "{}"\nsa-time-out = 500\n'.format(
                self.ca_file
            ),
        )
        cp = self.run_asadm(
            '[include]\nfile = "{}"\n'.format(include), "-e", "info network"
        )
        self.assert_stopped_before_any_request(cp)

    def test_other_section_error_does_not_drop_the_ca_file(self):
        """The file's CA must not be lost with the rest of the file, so the
        plaintext agent never sees a request."""
        cp = self.run_asadm(
            '[cluster]\nhots = "127.0.0.1"\n[secret-agent]\nsa-ca-file = "{ca}"\n',
            "-e",
            "info network",
        )
        output = cp.stdout + cp.stderr
        self.assertNotEqual(cp.returncode, 0, output)
        self.assertEqual([r for r in self.requests if r is not None], [], output)
        self.assertEqual(self.cluster_connections, [], output)


class TypedPasswordTest(unittest.TestCase):
    def test_typed_password_limited_to_63_bytes(self):
        conf.check_typed_password("x" * 63, AuthMode.INTERNAL)

        for password in ("x" * 64, "é" * 32):
            with self.subTest(password=password):
                with self.assertRaises(PasswordSourceError) as cm:
                    conf.check_typed_password(password, AuthMode.INTERNAL)

                self.assertEqual(
                    str(cm.exception), "--password: password is longer than 63 bytes"
                )

    def test_typed_password_not_checked_with_pki(self):
        conf.check_typed_password("x" * 64, AuthMode.PKI)

    def test_piped_password_is_trimmed(self):
        for piped in (
            " s3cr3t \r\n",
            " s3cr3t \n",
            "\t s3cr3t ",
            "s3cr3t\r",
            "s3cr3t\nmore\n",
        ):
            with self.subTest(piped=piped), patch("sys.stdin", io.StringIO(piped)):
                self.assertEqual(conf.read_piped_password(), "s3cr3t")

    def test_piped_password_read_is_bounded(self):
        for args, read in (((), 66), ((1024,), 1027)):
            with self.subTest(args=args):
                stdin = io.StringIO("x" * 100_000)

                with patch("sys.stdin", stdin):
                    self.assertEqual(conf.read_piped_password(*args), "x" * read)

                self.assertEqual(stdin.tell(), read)

    def test_cut_off_piped_password_is_not_trimmed(self):
        piped = " " * 10 + "x" * 100_000

        with patch("sys.stdin", io.StringIO(piped)):
            self.assertEqual(conf.read_piped_password(), piped[:66])

    def test_typed_keyfile_password_accepts_the_forms(self):
        with patch.dict(os.environ, {"KP": PW}):
            self.assertEqual(conf.resolve_keyfile_password("env:KP"), PW)
            self.assertEqual(conf.resolve_keyfile_password(" \v\fenv:KP \t\r\n"), PW)
            self.assertEqual(conf.resolve_keyfile_password(" env:KP"), " env:KP")

    def test_typed_keyfile_password_limited_to_1024_bytes(self):
        self.assertEqual(conf.resolve_keyfile_password("x" * 1024), "x" * 1024)

        with self.assertRaises(PasswordSourceError) as cm:
            conf.resolve_keyfile_password("x" * 1025)

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: password is longer than 1024 bytes",
        )


class PasswordHelpTest(unittest.TestCase):
    def test_help_lists_every_form(self):
        out = io.StringIO()
        with patch("sys.stdout", out):
            conf.print_config_help()

        help_text = out.getvalue()
        self.assertEqual(help_text.count("'env:<VAR>'"), 2)
        self.assertEqual(help_text.count("'env-b64:<VAR>'"), 2)
        self.assertEqual(help_text.count("'b64:<BASE64>'"), 2)
        self.assertEqual(help_text.count("'file:<PATH>'"), 2)
        self.assertEqual(help_text.count("'secrets:<resource>:<key>'"), 3)
        self.assertIn("[secret-agent]", help_text)

        for option in ("--sa-address", "--sa-port", "--sa-timeout", "--sa-ca-file"):
            self.assertIn(option, help_text)
        self.assertNotIn("--sa-cafile", help_text)
        self.assertNotIn("varaible", help_text)

    def test_usage_hides_c_cafile_spelling(self):
        err = io.StringIO()

        with patch("sys.argv", ["asadm", "--bogus"]), patch("sys.stderr", err):
            with self.assertRaises(SystemExit):
                conf.get_cli_args()

        self.assertIn("--sa-ca-file", err.getvalue())
        self.assertNotIn("--sa-cafile", err.getvalue())

    def test_help_password_block(self):
        out = io.StringIO()
        with patch("sys.stdout", out):
            conf.print_config_help()

        indent = "\n" + " " * 22
        block = (
            " -P, --password       Password used to authenticate with cluster. Default: none"
            + indent
            + indent.join(
                [
                    "It can be one of the following:",
                    "1) Environment variable: 'env:<VAR>', used exactly as set",
                    "2) Base64 encoded environment variable: 'env-b64:<VAR>'",
                    "3) Base64 encoded string: 'b64:<BASE64>'",
                    "4) File: 'file:<PATH>', the whole file less one trailing '\\n' or",
                    "   '\\r\\n'. PATH should name a regular file.",
                    "5) Aerospike Secret Agent: 'secrets:<resource>:<key>'",
                    "6) String: 'PASSWORD'",
                    "Prefixes are case-sensitive. A base64 value may be line wrapped,",
                    "and one trailing newline is dropped after decoding. A 'b64:' value",
                    "on the command line is as visible as a literal password.",
                    "A password that itself begins with 'env:', 'env-b64:', 'b64:',",
                    "'file:' or 'secrets:' must be given as 'b64:' or typed at the",
                    "prompt.",
                    "The password is read only when a user is set and the auth mode is",
                    "not PKI. It must be at most 63 bytes.",
                    "A value fetched with 'secrets:' is used as-is.",
                    "User will be prompted on command line if -P specified and no",
                    "password is given. The typed password is used as is. A password",
                    "piped on stdin has surrounding whitespace trimmed.",
                ]
            )
            + "\n"
        )
        self.assertIn(block, out.getvalue())

    def test_help_keyfile_password_block(self):
        out = io.StringIO()
        with patch("sys.stdout", out):
            conf.print_config_help()

        self.assertIn(KEYFILE_PASSWORD_HELP, out.getvalue())

    def test_help_secret_agent_block(self):
        out = io.StringIO()
        with patch("sys.stdout", out):
            conf.print_config_help()

        self.assertIn(SECRET_AGENT_HELP, out.getvalue())


if __name__ == "__main__":
    unittest.main()
