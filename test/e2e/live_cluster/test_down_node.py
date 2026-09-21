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

import time
import unittest

from test.e2e import lib, util as test_util

# One unreachable peer costs at most one connect timeout per cold start. The bound is
# generous so the test fails only on a real regression, not on a slow CI host. The
# per-session backoff cannot be observed here: every run_asadm is a new process, so
# the unit tests in test_cluster.py are what pin it.
SINGLE_COMMAND_BUDGET_SEC = 30


class TestCommandsWithADownNode(unittest.TestCase):
    """
    A node that is gone (container removed, so connects hang rather than being
    refused) must not stop the surviving nodes answering, and must not stall the
    command that reaches them.
    """

    def setUp(self):
        lib.stop()
        lib.start(num_nodes=2)
        self.args = "-h {}:{} --enable -e '{{}}' -Uadmin -Padmin".format(
            lib.SERVER_IP, lib.PORT
        )

    def tearDown(self):
        lib.stop()

    def stop_second_node(self):
        """Remove the peer outright: a stopped container drops packets, which is the
        reported case (connects time out) rather than being refused."""
        container = lib.NODES[1]

        if container is None:
            self.skipTest("second node was not started")

        container.stop()
        container.remove()
        lib.NODES[1] = None

        # Let the surviving node notice, so the crawl sees a peer it cannot reach.
        time.sleep(5)

    def run_asadm(self, cmd):
        return test_util.run_asadm(self.args.format(cmd))

    def test_info_still_answers_with_a_peer_down(self):
        self.stop_second_node()

        cp = self.run_asadm("info network")
        combined = cp.stdout + cp.stderr

        self.assertNotIn("Unable to find any Aerospike nodes", combined, combined)
        self.assertNotIn("Traceback", combined, combined)
        self.assertIn(str(lib.PORT), cp.stdout, cp.stdout)

    def test_asinfo_still_answers_with_a_peer_down(self):
        self.stop_second_node()

        cp = self.run_asadm('asinfo -v "build"')
        combined = cp.stdout + cp.stderr

        self.assertNotIn("Unable to find any Aerospike nodes", combined, combined)
        self.assertNotIn("Traceback", combined, combined)
        self.assertIn("returned", cp.stdout, cp.stdout)

    def test_a_down_peer_does_not_stall_a_command(self):
        self.stop_second_node()

        start = time.time()
        cp = self.run_asadm('asinfo -v "build"')
        elapsed = time.time() - start

        self.assertNotIn("Traceback", cp.stdout + cp.stderr)
        self.assertLess(elapsed, SINGLE_COMMAND_BUDGET_SEC, cp.stdout + cp.stderr)


if __name__ == "__main__":
    unittest.main()
