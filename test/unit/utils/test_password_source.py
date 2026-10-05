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
import unittest
from unittest.mock import patch

from parameterized import parameterized

from lib.utils.password_source import PasswordSourceError, resolve

SECRET = "s3cr3t-pw"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


SECRET_B64 = b64(SECRET.encode())


class ResolveLiteralTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("plain", "my-password"),
            ("empty", ""),
            ("surrounding_spaces", "  my-password  "),
            ("colon_inside", "pa:ss"),
            ("unknown_prefix", "secrets:resource:key"),
            ("prefix_is_case_sensitive", "ENV:AS_PASS"),
            ("prefix_needs_exact_match", " env:AS_PASS"),
            ("b64_prefix_is_case_sensitive", "B64:" + SECRET_B64),
            ("file_prefix_is_case_sensitive", "File:/nonexistent"),
        ]
    )
    def test_literal_is_returned_unchanged(self, _, value):
        with patch.dict(os.environ, {"AS_PASS": SECRET}):
            self.assertEqual(resolve(value, "--password"), value)


class ResolveEnvTest(unittest.TestCase):
    def test_env(self):
        with patch.dict(os.environ, {"AS_PASS": SECRET}):
            self.assertEqual(resolve("env:AS_PASS", "--password"), SECRET)

    def test_env_value_is_not_parsed_again(self):
        with patch.dict(os.environ, {"AS_PASS": "env:OTHER", "OTHER": SECRET}):
            self.assertEqual(resolve("env:AS_PASS", "--password"), "env:OTHER")

    def test_env_value_is_used_as_is(self):
        with patch.dict(os.environ, {"AS_PASS": " pw \n"}):
            self.assertEqual(resolve("env:AS_PASS", "--password"), " pw \n")

    def test_env_unset(self):
        with patch.dict(os.environ, clear=True):
            with self.assertRaises(PasswordSourceError) as cm:
                resolve("env:AS_PASS", "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: environment variable AS_PASS is not set or empty",
        )

    def test_env_empty(self):
        with patch.dict(os.environ, {"AS_PASS": ""}):
            with self.assertRaises(PasswordSourceError) as cm:
                resolve("env:AS_PASS", "--tls-keyfile-password")

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: environment variable AS_PASS is not set or empty",
        )


class ResolveEnvB64Test(unittest.TestCase):
    def test_env_b64(self):
        with patch.dict(os.environ, {"AS_PASS_B64": SECRET_B64}):
            self.assertEqual(resolve("env-b64:AS_PASS_B64", "--password"), SECRET)

    def test_env_b64_drops_one_trailing_newline(self):
        with patch.dict(os.environ, {"AS_PASS_B64": b64(b"pw\n")}):
            self.assertEqual(resolve("env-b64:AS_PASS_B64", "--password"), "pw")

    def test_env_b64_unset(self):
        with patch.dict(os.environ, clear=True):
            with self.assertRaises(PasswordSourceError) as cm:
                resolve("env-b64:AS_PASS_B64", "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: environment variable AS_PASS_B64 is not set or empty",
        )

    def test_env_b64_invalid(self):
        with patch.dict(os.environ, {"KP_B64": SECRET}):
            with self.assertRaises(PasswordSourceError) as cm:
                resolve("env-b64:KP_B64", "--tls-keyfile-password")

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: invalid base64 in environment variable KP_B64",
        )

    def test_env_b64_decodes_to_empty(self):
        with patch.dict(os.environ, {"AS_PASS_B64": b64(b"\n")}):
            with self.assertRaises(PasswordSourceError) as cm:
                resolve("env-b64:AS_PASS_B64", "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: password from environment variable AS_PASS_B64 is empty",
        )


class ResolveB64Test(unittest.TestCase):
    def test_b64(self):
        self.assertEqual(resolve("b64:" + SECRET_B64, "--password"), SECRET)

    def test_b64_drops_only_one_trailing_newline(self):
        self.assertEqual(resolve("b64:" + b64(b"pw\n\n"), "--password"), "pw\n")

    def test_b64_keeps_trailing_carriage_return(self):
        self.assertEqual(resolve("b64:" + b64(b"pw\r"), "--password"), "pw\r")

    def test_b64_ignores_line_wrapping(self):
        wrapped = SECRET_B64[:8] + "\r\n" + SECRET_B64[8:]
        self.assertEqual(resolve("b64:" + wrapped, "--password"), SECRET)

    def test_b64_decoded_value_is_not_parsed_again(self):
        with patch.dict(os.environ, {"AS_PASS": SECRET}):
            self.assertEqual(
                resolve("b64:" + b64(b"env:AS_PASS"), "--password"), "env:AS_PASS"
            )

    @parameterized.expand(
        [
            ("not_base64", "b64:" + SECRET),
            ("missing_padding", "b64:cHc"),
            ("url_safe_alphabet", "b64:-_-_"),
            ("data_after_padding", "b64:cHc=cHc="),
            ("non_ascii", "b64:cHcé"),
        ]
    )
    def test_b64_invalid(self, _, value):
        with self.assertRaises(PasswordSourceError) as cm:
            resolve(value, "--password")

        self.assertEqual(str(cm.exception), "--password: invalid base64 in b64: value")

    @parameterized.expand(
        [("empty_payload", "b64:"), ("only_newline", "b64:" + b64(b"\n"))]
    )
    def test_b64_decodes_to_empty(self, _, value):
        with self.assertRaises(PasswordSourceError) as cm:
            resolve(value, "--password")

        self.assertEqual(
            str(cm.exception), "--password: password from b64: value is empty"
        )

    def test_b64_not_utf8(self):
        with self.assertRaises(PasswordSourceError) as cm:
            resolve("b64:" + b64(b"\xff\xfe"), "--password")

        self.assertEqual(
            str(cm.exception), "--password: password from b64: value is not valid UTF-8"
        )


class ResolveFileTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write(self, data: bytes) -> str:
        path = os.path.join(self.tmpdir.name, "pw")
        with open(path, "wb") as f:
            f.write(data)
        return path

    @parameterized.expand(
        [
            ("no_line_ending", b"s3cr3t-pw", SECRET),
            ("lf", b"s3cr3t-pw\n", SECRET),
            ("crlf", b"s3cr3t-pw\r\n", SECRET),
            ("only_one_lf", b"s3cr3t-pw\n\n", SECRET + "\n"),
            ("only_one_crlf", b"s3cr3t-pw\r\n\r\n", SECRET + "\r\n"),
            ("lone_cr_kept", b"s3cr3t-pw\r", SECRET + "\r"),
            ("spaces_kept", b"  s3cr3t-pw  \n", "  " + SECRET + "  "),
            ("inner_crlf_kept", b"a\r\nb\n", "a\r\nb"),
            ("utf8", "päss\n".encode("utf-8"), "päss"),
        ]
    )
    def test_file(self, _, data, expected):
        path = self.write(data)
        self.assertEqual(resolve("file:" + path, "--password"), expected)

    def test_file_contents_are_not_parsed_again(self):
        path = self.write(b"env:AS_PASS\n")
        with patch.dict(os.environ, {"AS_PASS": SECRET}):
            self.assertEqual(resolve("file:" + path, "--password"), "env:AS_PASS")

    def test_file_missing(self):
        path = os.path.join(self.tmpdir.name, "missing")
        with self.assertRaises(PasswordSourceError) as cm:
            resolve("file:" + path, "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: cannot read file {}: No such file or directory".format(path),
        )

    def test_file_is_directory(self):
        with self.assertRaises(PasswordSourceError) as cm:
            resolve("file:" + self.tmpdir.name, "--tls-keyfile-password")

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: cannot read file {}: Is a directory".format(
                self.tmpdir.name
            ),
        )

    @unittest.skipIf(os.geteuid() == 0, "root can read any file")
    def test_file_unreadable(self):
        path = self.write(SECRET.encode())
        os.chmod(path, 0)

        with self.assertRaises(PasswordSourceError) as cm:
            resolve("file:" + path, "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: cannot read file {}: Permission denied".format(path),
        )

    @parameterized.expand([("empty", b""), ("lf_only", b"\n"), ("crlf_only", b"\r\n")])
    def test_file_empty(self, _, data):
        path = self.write(data)
        with self.assertRaises(PasswordSourceError) as cm:
            resolve("file:" + path, "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: password from file {} is empty".format(path),
        )

    def test_file_not_utf8(self):
        path = self.write(b"\xff\xfe\n")
        with self.assertRaises(PasswordSourceError) as cm:
            resolve("file:" + path, "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: password from file {} is not valid UTF-8".format(path),
        )


class ResolveErrorsHideSecretTest(unittest.TestCase):
    def test_errors_never_carry_the_secret(self):
        cases = [
            ("b64:" + SECRET, {}),
            ("env-b64:KP_B64", {"KP_B64": SECRET}),
        ]

        for value, env in cases:
            with self.subTest(value=value), patch.dict(os.environ, env):
                with self.assertRaises(PasswordSourceError) as cm:
                    resolve(value, "--password")

                self.assertNotIn(SECRET, str(cm.exception))
                self.assertIsNone(cm.exception.__cause__)
                self.assertTrue(cm.exception.__suppress_context__)

    def test_error_carries_its_own_message(self):
        self.assertTrue(PasswordSourceError.carries_its_own_message)


if __name__ == "__main__":
    unittest.main()
