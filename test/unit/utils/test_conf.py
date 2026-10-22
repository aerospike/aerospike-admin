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
import tempfile
import unittest
from unittest.mock import patch

from lib.utils import conf
from lib.utils.constants import AuthMode
from lib.utils.password_source import PasswordSourceError

PW = "s3cr3t-pw"
PW_B64 = base64.b64encode(PW.encode()).decode()
UNSET = "ASADM_TEST_UNSET_PASSWORD_VAR"


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
        args = self.load("-U", "admin", "-P", "secrets:resource:key")
        self.assertEqual(args.password, "secrets:resource:key")

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
        self.assertNotIn("varaible", help_text)

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
                    "5) String: 'PASSWORD'",
                    "Prefixes are case-sensitive. A base64 value may be line wrapped,",
                    "and one trailing newline is dropped after decoding. A 'b64:' value",
                    "on the command line is as visible as a literal password.",
                    "A password that itself begins with 'env:', 'env-b64:', 'b64:' or",
                    "'file:' must be given as 'b64:' or typed at the prompt.",
                    "The password is read only when a user is set and the auth mode is",
                    "not PKI. It must be at most 63 bytes.",
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

        indent = "\n" + " " * 22
        block = (
            " --tls-keyfile-password=password"
            + indent
            + indent.join(
                [
                    "Password to load protected tls-keyfile.",
                    "It can be one of the following:",
                    "1) Environment variable: 'env:<VAR>', used exactly as set",
                    "2) Base64 encoded environment variable: 'env-b64:<VAR>'",
                    "3) Base64 encoded string: 'b64:<BASE64>'",
                    "4) File: 'file:<PATH>', the first line of the file",
                    "5) String: 'PASSWORD'",
                    "Prefixes are case-sensitive. A base64 value may be line wrapped,",
                    "and one trailing newline is dropped after decoding.",
                    "A password that itself begins with 'env:', 'env-b64:', 'b64:' or",
                    "'file:' must be given as 'b64:'.",
                    "Surrounding whitespace is trimmed before the form is read.",
                    "The password is read only when a key file is set. It must be at",
                    "most 1024 bytes.",
                    "Default: none",
                    "User will be prompted on command line if --tls-keyfile-password",
                    "specified and no password is given. The typed password",
                    "accepts the forms above.",
                ]
            )
            + "\n"
        )
        self.assertIn(block, out.getvalue())


if __name__ == "__main__":
    unittest.main()
