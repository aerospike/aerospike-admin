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

import os
import shutil
import tarfile
import tempfile
import unittest

from test.e2e import util


class UnreadableBundleTests(unittest.TestCase):
    """Bundles asadm cannot fully read. Only the bundle is read, so no server is needed."""

    def setUp(self):
        self.work_dir = tempfile.mkdtemp(prefix="asadm_bundle_errors_")
        self.addCleanup(shutil.rmtree, self.work_dir, ignore_errors=True)

    def _bundle_with_ascinfo(self, data):
        content = os.path.join(self.work_dir, "content")

        with open(content, "wb") as content_file:
            content_file.write(data)

        archive = os.path.join(self.work_dir, "collect_info_20261116_191136.tgz")

        with tarfile.open(archive, "w:gz") as tar:
            tar.add(
                content,
                arcname="collect_info_20261116_191136/20261116_191136_ascinfo.json",
            )

        return archive

    def _assert_error_not_a_traceback(self, archive):
        cp = util.run_asadm(f"-cf {archive} -e 'info network'")

        self.assertNotIn("Traceback", cp.stderr)
        self.assertEqual(cp.returncode, 1, cp.stderr)
        self.assertIn(
            f"ERROR: Could not read a cluster snapshot from {archive}", cp.stderr
        )
        self.assertIn("20261116_191136_ascinfo.json", cp.stderr)

    def test_an_ascinfo_that_is_not_json_is_an_error_not_a_traceback(self):
        archive = self._bundle_with_ascinfo(b"{not json")

        self._assert_error_not_a_traceback(archive)

    def test_an_ascinfo_that_is_not_utf8_is_an_error_not_a_traceback(self):
        archive = self._bundle_with_ascinfo(
            b'{"2026-11-16 19:11:36 UTC": {"c\xe9": {}}}'
        )

        self._assert_error_not_a_traceback(archive)

    def test_an_ascinfo_that_is_a_bare_number_is_an_error_not_a_traceback(self):
        archive = self._bundle_with_ascinfo(b"5")

        self._assert_error_not_a_traceback(archive)

    def test_a_snapshot_that_is_a_bare_number_is_an_error_not_a_traceback(self):
        archive = self._bundle_with_ascinfo(b'{"2026-11-16 19:11:36 UTC": 5}')

        self._assert_error_not_a_traceback(archive)

    def test_a_cluster_that_is_a_bare_number_is_an_error_not_a_traceback(self):
        archive = self._bundle_with_ascinfo(b'{"2026-11-16 19:11:36 UTC": {"c": 5}}')

        self._assert_error_not_a_traceback(archive)

    def test_service_statistics_that_are_a_bare_number_still_show_the_node(self):
        archive = self._bundle_with_ascinfo(
            b'{"2026-11-16 19:11:36 UTC": {"c": {"10.0.0.1:3000": '
            b'{"as_stat": {"statistics": {"service": 5}}}}}}'
        )

        cp = util.run_asadm(f"-cf {archive} -e 'info network'")

        self.assertNotIn("Traceback", cp.stderr)
        self.assertEqual(cp.returncode, 0, cp.stderr)
        self.assertIn("Network Information (2026-11-16 19:11:36 UTC)", cp.stdout)
        self.assertIn("10.0.0.1:3000", cp.stdout)


if __name__ == "__main__":
    unittest.main()
