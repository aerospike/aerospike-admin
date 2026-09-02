# Copyright 2025 Aerospike, Inc.
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

import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


def _run(script: str) -> subprocess.CompletedProcess:
    """Run a script in a fresh interpreter.

    Import order is a process-wide fact: by the time this test runs, the suite has
    already imported half the tree, so the ordering these tests are about can only
    be observed in a new process.
    """
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


class LoggerImportOrderTest(unittest.TestCase):
    def test_modules_imported_after_this_one_get_a_base_logger(self):
        """asadm.py imports lib.utils.logger first so that setLoggerClass runs
        before any other module calls logging.getLogger. A module whose logger is
        a plain logging.Logger silently stops setting the exit code."""
        script = (
            "import lib.utils.logger;"
            "import lib.base_controller, lib.utils.util;"
            "import lib.live_cluster.client.cluster as cluster;"
            "from lib.utils.logger import BaseLogger;"
            "print(all(isinstance(m.logger, BaseLogger) "
            "for m in (lib.base_controller, lib.utils.util, cluster)))"
        )

        result = _run(script)

        self.assertEqual(result.stdout.strip(), "True", result.stderr)

    def test_error_from_a_module_logger_sets_the_exit_code(self):
        """The reason the class matters: BaseLogger.error is what sets exit code 2."""
        script = (
            "import lib.utils.logger;"
            "import lib.live_cluster.client.cluster as cluster;"
            "cluster.logger.error('boom');"
            "print(lib.utils.logger.get_exit_code())"
        )

        result = _run(script)

        self.assertEqual(result.stdout.strip(), "2", result.stderr)

    def test_importing_this_module_does_not_load_the_client(self):
        """Importing the exception types here would create lib.base_controller's
        and the client's loggers before setLoggerClass, so this module asks the
        exception whether it explains itself instead of naming their types."""
        script = (
            "import sys;"
            "import lib.utils.logger;"
            "print(any(m.startswith('lib.live_cluster') or m == 'lib.base_controller' "
            "for m in sys.modules))"
        )

        result = _run(script)

        self.assertEqual(result.stdout.strip(), "False", result.stderr)


class SelfDescribingExceptionTest(unittest.TestCase):
    """The exceptions whose message is the whole story: BaseLogger prints them
    without a traceback, and each one says so itself."""

    def test_the_self_describing_exceptions_are_marked(self):
        from lib.base_controller import ShellException
        from lib.live_cluster.client import ASInfoError, ASProtocolError
        from lib.utils.logger import _carries_its_own_message

        self.assertTrue(_carries_its_own_message(ShellException("nope")))
        self.assertTrue(_carries_its_own_message(ASInfoError("nope")))
        self.assertTrue(_carries_its_own_message(ASProtocolError(0, "nope")))

    def test_the_subclasses_inherit_the_mark(self):
        from lib.live_cluster.client.types import (
            ASInfoResponseError,
            ASProtocolConnectionError,
        )
        from lib.utils.logger import _carries_its_own_message

        self.assertTrue(_carries_its_own_message(ASInfoResponseError("nope", "fail")))
        self.assertTrue(_carries_its_own_message(ASProtocolConnectionError(0, "nope")))

    def test_an_ordinary_exception_still_gets_a_traceback(self):
        from lib.utils.logger import _carries_its_own_message

        self.assertFalse(_carries_its_own_message(ValueError("boom")))


if __name__ == "__main__":
    unittest.main()
