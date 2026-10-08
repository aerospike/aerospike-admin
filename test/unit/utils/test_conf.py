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
        args = self.load("-P", "env:" + UNSET)
        self.assertEqual(args.password, "env:" + UNSET)

    def test_password_error(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load("-U", "admin", "-P", "env:" + UNSET)

        self.assertEqual(
            str(cm.exception),
            "--password: environment variable {} is not set or empty".format(UNSET),
        )

    def test_password_error_from_config_file(self):
        with self.assertRaises(PasswordSourceError) as cm:
            self.load(config='[cluster]\nuser = "admin"\npassword = "b64:!!"\n')

        self.assertEqual(str(cm.exception), "--password: invalid base64 in b64: value")

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


if __name__ == "__main__":
    unittest.main()
