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
import traceback
import unittest
from unittest.mock import patch

from parameterized import parameterized

from lib.secret_agent import RequestFailedError
from lib.utils.password_source import PasswordSourceError, resolve

PW = "s3cr3t-pw"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


PW_B64 = b64(PW.encode())


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
            ("b64_prefix_is_case_sensitive", "B64:" + PW_B64),
            ("file_prefix_is_case_sensitive", "File:/nonexistent"),
        ]
    )
    def test_literal_is_returned_unchanged(self, _, value):
        with patch.dict(os.environ, {"AS_PASS": PW}):
            self.assertEqual(resolve(value, "--password"), value)


class ResolveEnvTest(unittest.TestCase):
    def test_env(self):
        with patch.dict(os.environ, {"AS_PASS": PW}):
            self.assertEqual(resolve("env:AS_PASS", "--password"), PW)

    def test_env_value_is_not_parsed_again(self):
        with patch.dict(os.environ, {"AS_PASS": "env:OTHER", "OTHER": PW}):
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

    @unittest.skipUnless(os.supports_bytes_environ, "needs a bytes environment")
    def test_env_not_utf8(self):
        for value in ("env:AS_BAD", "env-b64:AS_BAD"):
            with self.subTest(value=value), patch.dict(os.environ):
                os.environb[b"AS_BAD"] = b"\xff" + PW.encode()

                with self.assertRaises(PasswordSourceError) as cm:
                    resolve(value, "--password")

            self.assertEqual(
                str(cm.exception),
                "--password: password from environment variable AS_BAD is not valid UTF-8",
            )


class ResolveEnvB64Test(unittest.TestCase):
    def test_env_b64(self):
        with patch.dict(os.environ, {"AS_PASS_B64": PW_B64}):
            self.assertEqual(resolve("env-b64:AS_PASS_B64", "--password"), PW)

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
        with patch.dict(os.environ, {"KP_B64": PW}):
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
        self.assertEqual(resolve("b64:" + PW_B64, "--password"), PW)

    def test_b64_drops_only_one_trailing_newline(self):
        self.assertEqual(resolve("b64:" + b64(b"pw\n\n"), "--password"), "pw\n")

    def test_b64_keeps_trailing_carriage_return(self):
        self.assertEqual(resolve("b64:" + b64(b"pw\r"), "--password"), "pw\r")

    def test_b64_ignores_line_wrapping(self):
        wrapped = PW_B64[:8] + "\r\n" + PW_B64[8:]
        self.assertEqual(resolve("b64:" + wrapped, "--password"), PW)

    def test_b64_decoded_value_is_not_parsed_again(self):
        with patch.dict(os.environ, {"AS_PASS": PW}):
            self.assertEqual(
                resolve("b64:" + b64(b"env:AS_PASS"), "--password"), "env:AS_PASS"
            )

    @parameterized.expand(
        [
            ("not_base64", "b64:" + PW),
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
            ("no_line_ending", b"s3cr3t-pw", PW),
            ("lf", b"s3cr3t-pw\n", PW),
            ("crlf", b"s3cr3t-pw\r\n", PW),
            ("only_one_lf", b"s3cr3t-pw\n\n", PW + "\n"),
            ("only_one_crlf", b"s3cr3t-pw\r\n\r\n", PW + "\r\n"),
            ("lone_cr_kept", b"s3cr3t-pw\r", PW + "\r"),
            ("spaces_kept", b"  s3cr3t-pw  \n", "  " + PW + "  "),
            ("inner_crlf_kept", b"a\r\nb\n", "a\r\nb"),
            ("utf8", "päss\n".encode("utf-8"), "päss"),
        ]
    )
    def test_file(self, _, data, expected):
        path = self.write(data)
        self.assertEqual(resolve("file:" + path, "--password"), expected)

    def test_file_contents_are_not_parsed_again(self):
        path = self.write(b"env:AS_PASS\n")
        with patch.dict(os.environ, {"AS_PASS": PW}):
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
        path = self.write(PW.encode())
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
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write(self, name, data: bytes, mode=0o600) -> str:
        path = os.path.join(self.tmpdir.name, name)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, mode)
        return path

    def assert_secret_hidden(self, value, env=None):
        with patch.dict(os.environ, env or {}):
            with self.assertRaises(PasswordSourceError) as cm:
                resolve(value, "--password")

        err = cm.exception
        self.assertIsNone(err.__cause__)
        self.assertTrue(err.__context__ is None or err.__suppress_context__)

        shown = "".join(traceback.format_exception(err))
        chained = err.__context__
        while chained is not None:
            shown += repr(chained)
            chained = chained.__cause__ or chained.__context__

        self.assertNotIn(PW, shown)
        self.assertNotIn(PW_B64, shown)

    def test_b64_errors(self):
        self.assert_secret_hidden("b64:" + PW)
        self.assert_secret_hidden("b64:" + PW_B64 + "é")
        self.assert_secret_hidden("b64:" + b64(b"\xff" + PW.encode()))

    def test_env_b64_errors(self):
        self.assert_secret_hidden("env-b64:KP_B64", {"KP_B64": PW})
        self.assert_secret_hidden("env-b64:KP_B64", {"KP_B64": PW_B64 + "é"})
        self.assert_secret_hidden(
            "env-b64:KP_B64", {"KP_B64": b64(b"\xff" + PW.encode())}
        )

    def test_env_not_utf8_error(self):
        bad = os.fsdecode(b"\xff" + PW.encode())
        self.assert_secret_hidden("env:AS_BAD", {"AS_BAD": bad})

    def test_file_not_utf8_error(self):
        path = self.write("pw", b"\xff" + PW.encode() + b"\n")
        self.assert_secret_hidden("file:" + path)

    @unittest.skipIf(os.geteuid() == 0, "root can read any file")
    def test_file_read_error(self):
        path = self.write("pw", PW.encode(), mode=0)
        self.assert_secret_hidden("file:" + path)

    def test_error_carries_its_own_message(self):
        self.assertTrue(PasswordSourceError.carries_its_own_message)


class ResolveSecretTest(unittest.TestCase):
    REF = "secrets:aql:pw"

    def resolve(self, fetch):
        return resolve(self.REF, "--password", fetch)

    def test_secret_is_fetched(self):
        refs = []

        def fetch(ref):
            refs.append(ref)
            return PW

        self.assertEqual(self.resolve(fetch), PW)
        self.assertEqual(refs, [self.REF])

    def test_fetched_value_is_not_parsed_again(self):
        self.assertEqual(self.resolve(lambda _: "env:AS_PASS"), "env:AS_PASS")

    def test_agent_error_names_the_option(self):
        def fetch(_):
            raise RequestFailedError("agent error for secrets:aql:pw: not found")

        with self.assertRaises(PasswordSourceError) as cm:
            self.resolve(fetch)

        self.assertEqual(
            str(cm.exception), "--password: agent error for secrets:aql:pw: not found"
        )

    def test_settings_error_passes_through(self):
        def fetch(_):
            raise PasswordSourceError("--sa-port: invalid value 0")

        with self.assertRaises(PasswordSourceError) as cm:
            self.resolve(fetch)

        self.assertEqual(str(cm.exception), "--sa-port: invalid value 0")

    def test_unexpected_error_still_fails_without_detail(self):
        def fetch(_):
            raise RuntimeError(PW)

        with self.assertRaises(PasswordSourceError) as cm:
            self.resolve(fetch)

        self.assertEqual(
            str(cm.exception),
            "--password: secret agent request for secrets:aql:pw failed",
        )
        self.assertNotIn(PW, "".join(traceback.format_exception(cm.exception)))


if __name__ == "__main__":
    unittest.main()
