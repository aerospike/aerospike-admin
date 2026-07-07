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

import unittest
from unittest.mock import patch

from lib.base_controller import ShellException
from lib.live_cluster.client.types import (
    ASClusterError,
    ASInfoError,
    ASNoNodesError,
    ASProtocolError,
    ASResponse,
)
from lib.utils.logger import logger


class LoggerAllowlistTest(unittest.TestCase):
    """Verify the BaseLogger allowlist that decides whether to dump a Python
    traceback for an exception logged via `logger.error()`.

    The contract these tests pin down is the user-visible promise of every
    typed error in this codebase: passing an instance of one of the allowlisted
    exception classes to `logger.error()` must NOT cause `traceback.print_exc`
    to fire — the user sees a single clean error line instead of a stack
    trace. Plain exceptions must continue to dump tracebacks so unexpected
    failures stay diagnosable.

    These tests exercise the real `BaseLogger._handle_exception` code path
    (no mocks of the logger itself), so removing or reordering an isinstance
    check in `lib/utils/logger.py` will break them.
    """

    def _assert_no_traceback(self, exc: Exception):
        """Call logger.error(exc) and assert traceback.print_exc is NOT
        triggered by the BaseLogger allowlist."""
        with patch("lib.utils.logger.traceback.print_exc") as mock_print_exc:
            logger.error(exc)
        mock_print_exc.assert_not_called()

    def _assert_traceback(self, exc: Exception):
        """Call logger.error(exc) and assert traceback.print_exc IS called —
        confirms the allowlist is exclusive, not a free pass for every type."""
        with patch("lib.utils.logger.traceback.print_exc") as mock_print_exc:
            logger.error(exc)
        mock_print_exc.assert_called_once()

    def test_no_nodes_error_suppresses_traceback(self):
        """Primary contract: the new ASNoNodesError must be treated as a
        clean error by the logger. This guards against someone removing the
        `ASClusterError` line in BaseLogger._handle_exception."""
        self._assert_no_traceback(ASNoNodesError())

    def test_cluster_error_base_suppresses_traceback(self):
        """The whole ASClusterError hierarchy is on the allowlist, not just
        ASNoNodesError. Future cluster-level error types (auth, TLS, etc.)
        that subclass ASClusterError will inherit clean handling for free."""
        self._assert_no_traceback(ASClusterError("some cluster problem"))

    def test_shell_exception_suppresses_traceback(self):
        """Regression guard for the pre-existing ShellException entry."""
        self._assert_no_traceback(ShellException("bad command"))

    def test_as_info_error_suppresses_traceback(self):
        """Regression guard for the pre-existing ASInfoError entry."""
        self._assert_no_traceback(ASInfoError("info failed"))

    def test_as_protocol_error_suppresses_traceback(self):
        """Regression guard for the pre-existing ASProtocolError entry."""
        self._assert_no_traceback(ASProtocolError(ASResponse.OK, "protocol issue"))

    def test_generic_exception_still_dumps_traceback(self):
        """Negative case: unknown exception types must still produce a
        traceback so unexpected failures remain diagnosable. Without this,
        the allowlist test above could pass trivially if the logger never
        printed tracebacks at all."""
        self._assert_traceback(RuntimeError("unexpected"))

    def test_io_error_still_dumps_traceback(self):
        """IOError is what the cluster client used to raise. The cleanup
        only removed it for the no-nodes path; raw IOError elsewhere must
        still be treated as an unexpected failure."""
        self._assert_traceback(IOError("disk full"))


if __name__ == "__main__":
    unittest.main()
