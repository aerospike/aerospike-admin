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

import unittest

from parameterized import parameterized

from lib.collectinfo_analyzer.collectinfo_command_controller import (
    has_node_data,
    warn_no_data,
)

LOGGER = "lib.collectinfo_analyzer.collectinfo_command_controller"


class HasNodeDataTest(unittest.TestCase):
    @parameterized.expand(
        [
            ("no_timestamps", {}),
            ("section_absent_on_every_node", {"ts": {}}),
            ("empty_dict_per_node", {"ts": {"n1": {}, "n2": {}}}),
            ("failed_sub_call", {"ts": {"n1": ""}}),
            ("empty_list", {"ts": {"n1": []}}),
            ("exception", {"ts": {"n1": Exception("boom")}}),
            ("snapshot_is_not_a_dict", {"ts": Exception("boom")}),
        ]
    )
    def test_empty(self, _, data):
        self.assertFalse(has_node_data(data))

    @parameterized.expand(
        [
            ("one_node", {"ts": {"n1": {"k": "v"}}}),
            ("one_node_of_many", {"ts": {"n1": {}, "n2": [{"k": "v"}]}}),
            ("later_snapshot", {"t1": {}, "t2": {"n1": {"k": "v"}}}),
        ]
    )
    def test_has_data(self, _, data):
        self.assertTrue(has_node_data(data))


class WarnNoDataTest(unittest.TestCase):
    def test_names_the_command_and_the_missing_data(self):
        with self.assertLogs(LOGGER, level="WARNING") as cm:
            warn_no_data("show masking", "masking rules")

        self.assertEqual(
            cm.records[0].getMessage(),
            "show masking: no masking rules in this collectinfo.",
        )

    def test_names_the_filter_that_matched_nothing(self):
        with self.assertLogs(LOGGER, level="WARNING") as cm:
            warn_no_data("show masking", "masking rules", "namespace test set demo")

        self.assertEqual(
            cm.records[0].getMessage(),
            "show masking: no masking rules match namespace test set demo in this collectinfo.",
        )

    def test_logs_at_warning_so_it_reaches_stderr_without_failing_the_command(self):
        with self.assertLogs(LOGGER, level="WARNING") as cm:
            warn_no_data("show roles", "roles")

        self.assertEqual(cm.records[0].levelname, "WARNING")
