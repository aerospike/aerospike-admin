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
import traceback
import unittest
from unittest.mock import patch

from parameterized import parameterized

from lib.utils.password_source import (
    PASSWORD_MAX_LEN,
    TLS_KEYFILE_PASSWORD_MAX_LEN,
    PasswordSourceError,
    check_len,
    has_source,
    resolve,
)

PW = "s3cr3t-pw"
LIMITS = [
    ("password", "--password", PASSWORD_MAX_LEN, False),
    ("keyfile", "--tls-keyfile-password", TLS_KEYFILE_PASSWORD_MAX_LEN, True),
]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


PW_B64 = b64(PW.encode())


class HasSourceTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("env", "env:AS_PASS", True),
            ("env_b64", "env-b64:AS_PASS", True),
            ("b64", "b64:" + PW_B64, True),
            ("file", "file:/pw", True),
            ("empty_name", "env:", True),
            ("literal", PW, False),
            ("empty", "", False),
            ("no_colon", "env", False),
            ("case_sensitive", "ENV:AS_PASS", False),
            ("leading_space", " env:AS_PASS", False),
            ("unknown_prefix", "secrets:resource:key", False),
        ]
    )
    def test_has_source(self, _, value, expected):
        self.assertEqual(has_source(value), expected)


class CheckLenTest(unittest.TestCase):
    def test_at_limit(self):
        check_len("x" * PASSWORD_MAX_LEN, "--password", PASSWORD_MAX_LEN)

    @parameterized.expand(
        [("ascii", "x" * (PASSWORD_MAX_LEN + 1)), ("utf8_bytes", "é" * 32)]
    )
    def test_over_limit(self, _, password):
        with self.assertRaises(PasswordSourceError) as cm:
            check_len(password, "--password", PASSWORD_MAX_LEN)

        self.assertEqual(
            str(cm.exception), "--password: password is longer than 63 bytes"
        )


class ResolveEmptyNameTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("env", "env:", "env: requires a variable name"),
            ("env_b64", "env-b64:", "env-b64: requires a variable name"),
            ("file", "file:", "file: requires a path"),
        ]
    )
    def test_empty_name(self, _, value, message):
        for name, option, max_len, first_line in LIMITS:
            with self.subTest(name):
                with patch("builtins.open") as open_mock, self.assertRaises(
                    PasswordSourceError
                ) as cm:
                    resolve(value, option, max_len=max_len, first_line=first_line)

                open_mock.assert_not_called()
                self.assertEqual(str(cm.exception), option + ": " + message)


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

    def test_env_b64_decodes_to_nul(self):
        with patch.dict(os.environ, {"AS_PASS_B64": b64(b"p\0w")}):
            with self.assertRaises(PasswordSourceError) as cm:
                resolve("env-b64:AS_PASS_B64", "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: environment variable AS_PASS_B64 decodes to a value "
            "containing a NUL byte",
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

    @parameterized.expand(
        [("leading", b"\0pw"), ("inner", b"p\0w"), ("before_newline", b"pw\0\n")]
    )
    def test_b64_decodes_to_nul(self, _, data):
        with self.assertRaises(PasswordSourceError) as cm:
            resolve("b64:" + b64(data), "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: b64: value decodes to a value containing a NUL byte",
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
            str(cm.exception), "--password: password from file {} is empty".format(path)
        )

    @parameterized.expand(
        [("leading", b"\0pw\n"), ("inner", b"p\0w\n"), ("after_newline", b"pw\n\0")]
    )
    def test_file_nul(self, _, data):
        path = self.write(data)
        with self.assertRaises(PasswordSourceError) as cm:
            resolve("file:" + path, "--password")

        self.assertEqual(
            str(cm.exception), "--password: file {} contains a NUL byte".format(path)
        )

    def test_file_not_utf8(self):
        path = self.write(b"\xff\xfe\n")
        with self.assertRaises(PasswordSourceError) as cm:
            resolve("file:" + path, "--password")

        self.assertEqual(
            str(cm.exception),
            "--password: password from file {} is not valid UTF-8".format(path),
        )


class ResolveFirstLineTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write(self, data: bytes) -> str:
        path = os.path.join(self.tmpdir.name, "pw")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def resolve(self, value):
        return resolve(
            value,
            "--tls-keyfile-password",
            max_len=TLS_KEYFILE_PASSWORD_MAX_LEN,
            first_line=True,
        )

    def test_env_value_is_used_as_set(self):
        with patch.dict(os.environ, {"AS_PASS": " pw \n"}):
            self.assertEqual(self.resolve("env:AS_PASS"), " pw \n")

    @parameterized.expand(
        [
            ("no_line_ending", b"s3cr3t-pw", PW),
            ("lf", b"s3cr3t-pw\nsecond\n", PW),
            ("crlf", b"s3cr3t-pw\r\nsecond", PW),
            ("lone_cr", b"s3cr3t-pw\rsecond", PW),
            ("blank_lines_after", b"s3cr3t-pw\n\n", PW),
            ("nul_after_first_line", b"s3cr3t-pw\n\0", PW),
            ("spaces_kept", b"  s3cr3t-pw  \n", "  " + PW + "  "),
            ("tab_kept", b"\ts3cr3t-pw", "\t" + PW),
            ("whitespace_only_line_kept", b"  \n\n", "  "),
        ]
    )
    def test_file_first_line_as_read(self, _, data, expected):
        path = self.write(data)
        self.assertEqual(self.resolve("file:" + path), expected)

    @parameterized.expand(
        [
            ("empty_first_line", b"\n" + PW.encode() + b"\n", "first line of file"),
            ("crlf_only", b"\r\n", "first line of file"),
            ("empty", b"", "file"),
        ]
    )
    def test_file_empty(self, _, data, what):
        path = self.write(data)
        with self.assertRaises(PasswordSourceError) as cm:
            self.resolve("file:" + path)

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: password from {} {} is empty".format(what, path),
        )

    def test_file_nul_in_first_line(self):
        path = self.write(b"s3cr3t\0pw\n")
        with self.assertRaises(PasswordSourceError) as cm:
            self.resolve("file:" + path)

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: file {} contains a NUL byte".format(path),
        )

    def test_file_first_line_limit(self):
        at_limit = b"x" * TLS_KEYFILE_PASSWORD_MAX_LEN
        path = self.write(at_limit + b"\r\n" + b"y" * 4096)
        self.assertEqual(self.resolve("file:" + path), at_limit.decode())

        path = self.write(at_limit + b"x\nsecond\n")
        with self.assertRaises(PasswordSourceError) as cm:
            self.resolve("file:" + path)

        self.assertEqual(
            str(cm.exception),
            "--tls-keyfile-password: value from file {} is longer than 1024 bytes".format(
                path
            ),
        )


class ResolveMaxLenTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def write(self, data: bytes) -> str:
        path = os.path.join(self.tmpdir.name, "pw")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def values(self, pw: bytes):
        os.environ["AS_PASS"] = pw.decode()
        os.environ["AS_PASS_B64"] = b64(pw)
        path = self.write(pw + b"\r\n")
        return [
            (pw.decode(), "password"),
            ("env:AS_PASS", "value from environment variable AS_PASS"),
            (
                "env-b64:AS_PASS_B64",
                "decoded value from environment variable AS_PASS_B64",
            ),
            ("b64:" + b64(pw), "decoded b64: value"),
            ("file:" + path, "value from file " + path),
        ]

    @parameterized.expand(LIMITS)
    def test_at_limit(self, _, option, max_len, first_line):
        pw = b"x" * max_len
        with patch.dict(os.environ):
            for value, _ in self.values(pw):
                with self.subTest(value=value[:16]):
                    self.assertEqual(
                        resolve(value, option, max_len=max_len, first_line=first_line),
                        pw.decode(),
                    )

    @parameterized.expand(LIMITS)
    def test_over_limit(self, _, option, max_len, first_line):
        for pw in (b"x" * (max_len + 1), "é".encode() * (max_len // 2 + 1)):
            with patch.dict(os.environ):
                for value, what in self.values(pw):
                    with self.subTest(value=value[:16], pw_len=len(pw)):
                        with self.assertRaises(PasswordSourceError) as cm:
                            resolve(
                                value, option, max_len=max_len, first_line=first_line
                            )

                        self.assertEqual(
                            str(cm.exception),
                            "{}: {} is longer than {} bytes".format(
                                option, what, max_len
                            ),
                        )

    def test_no_limit_by_default(self):
        long_pw = "x" * (TLS_KEYFILE_PASSWORD_MAX_LEN + 1)
        self.assertEqual(resolve(long_pw, "--password"), long_pw)
        with patch.dict(os.environ, {"AS_PASS": long_pw}):
            self.assertEqual(resolve("env:AS_PASS", "--password"), long_pw)


@unittest.skipUnless(hasattr(os, "mkfifo"), "needs mkfifo")
class ResolveBoundedReadTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmpdir.cleanup)

    def fifo(self, first: bytes, rest: bytes | None) -> str:
        """Writes first, then rest forever, or holds the pipe open if rest is None."""
        path = os.path.join(self.tmpdir.name, "fifo")
        os.mkfifo(path)
        done = threading.Event()

        def writer():
            try:
                with open(path, "wb", buffering=0) as f:
                    f.write(first)
                    while not done.is_set():
                        if rest is None:
                            done.wait(0.05)
                        else:
                            f.write(rest)
            except BrokenPipeError:
                pass

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()

        def stop():
            done.set()
            thread.join(5)

        self.addCleanup(stop)
        return path

    def run_with_timeout(self, fn):
        result = {}

        def target():
            try:
                result["value"] = fn()
            except PasswordSourceError as e:
                result["error"] = str(e)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        thread.join(5)
        self.assertFalse(thread.is_alive(), "read did not stop")
        return result

    @parameterized.expand(LIMITS)
    def test_dev_zero(self, _, option, max_len, first_line):
        if not os.path.exists("/dev/zero"):
            self.skipTest("needs /dev/zero")

        result = self.run_with_timeout(
            lambda: resolve(
                "file:/dev/zero", option, max_len=max_len, first_line=first_line
            )
        )
        self.assertEqual(
            result, {"error": option + ": file /dev/zero contains a NUL byte"}
        )

    @parameterized.expand(LIMITS)
    def test_endless_writer(self, _, option, max_len, first_line):
        path = self.fifo(b"x", b"x" * 1024)
        result = self.run_with_timeout(
            lambda: resolve(
                "file:" + path, option, max_len=max_len, first_line=first_line
            )
        )
        self.assertEqual(
            result,
            {
                "error": "{}: value from file {} is longer than {} bytes".format(
                    option, path, max_len
                )
            },
        )

    @parameterized.expand(LIMITS)
    def test_reads_at_most_limit_plus_three_bytes(self, _, option, max_len, first_line):
        path = self.fifo(b"x" * (max_len + 3), None)
        result = self.run_with_timeout(
            lambda: resolve(
                "file:" + path, option, max_len=max_len, first_line=first_line
            )
        )
        self.assertEqual(
            result,
            {
                "error": "{}: value from file {} is longer than {} bytes".format(
                    option, path, max_len
                )
            },
        )

    def test_keyfile_writer_left_open_after_first_line(self):
        path = self.fifo(PW.encode() + b"\n", None)
        result = self.run_with_timeout(
            lambda: resolve(
                "file:" + path,
                "--tls-keyfile-password",
                max_len=TLS_KEYFILE_PASSWORD_MAX_LEN,
                first_line=True,
            )
        )
        self.assertEqual(result, {"value": PW})


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
        self.assert_secret_hidden("b64:" + b64(PW.encode() + b"\0"))

    def test_env_b64_errors(self):
        self.assert_secret_hidden("env-b64:KP_B64", {"KP_B64": PW})
        self.assert_secret_hidden("env-b64:KP_B64", {"KP_B64": PW_B64 + "é"})
        self.assert_secret_hidden(
            "env-b64:KP_B64", {"KP_B64": b64(b"\xff" + PW.encode())}
        )
        self.assert_secret_hidden(
            "env-b64:KP_B64", {"KP_B64": b64(PW.encode() + b"\0")}
        )

    def test_env_not_utf8_error(self):
        bad = os.fsdecode(b"\xff" + PW.encode())
        self.assert_secret_hidden("env:AS_BAD", {"AS_BAD": bad})

    def test_file_not_utf8_error(self):
        path = self.write("pw", b"\xff" + PW.encode() + b"\n")
        self.assert_secret_hidden("file:" + path)

    def test_file_nul_error(self):
        path = self.write("pw", PW.encode() + b"\0")
        self.assert_secret_hidden("file:" + path)

    @unittest.skipIf(os.geteuid() == 0, "root can read any file")
    def test_file_read_error(self):
        path = self.write("pw", PW.encode(), mode=0)
        self.assert_secret_hidden("file:" + path)

    def test_error_carries_its_own_message(self):
        self.assertTrue(PasswordSourceError.carries_its_own_message)


if __name__ == "__main__":
    unittest.main()
