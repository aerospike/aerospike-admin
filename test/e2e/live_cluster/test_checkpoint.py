# Copyright 2021-2026 Aerospike, Inc.
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

PREVIEW = ["index-checkpoint"]
TERMINAL_STATES = {"done", "failed"}


def checkpoint_template():
    """
    'index-checkpoint-path' cannot live in the shared template: it is preview-gated,
    so every other e2e cluster would have to boot with --preview or cf_crash_nostack.
    """
    with open(lib.absolute_path("aerospike_latest.conf")) as f:
        content = f.read()

    marker = "\tproto-fd-max 1024\n"

    if marker not in content:
        raise AssertionError("service stanza anchor missing from the template")

    return content.replace(
        marker, marker + "\tindex-checkpoint-path " + lib.CKPT_DIR + "\n"
    )


class TestCheckpoint(unittest.TestCase):
    """
    TOOLS-3976 - index checkpoint. EE only, preview-gated, and it TERMINATES the node:
    checkpoint-save copies the shmem segments, leaves the cluster, then parks serving
    only checkpoint-status. Every test here gets its own cluster and tears it down.
    """

    def setUp(self):
        # lib.start() is a no-op while lib.RUNNING, so a previous test that died before
        # its stop() would hand us ITS cluster - one with no 'index-checkpoint-path'.
        # These tests park a node, so inheriting someone else's cluster would take a
        # node out from under the rest of the suite. Guarantee our own.
        lib.stop()
        lib.start(
            template_content=checkpoint_template(),
            preview_features=PREVIEW,
            ckpt_dir=lib.CKPT_DIR,
        )
        self.args = "-h {}:{} --enable -e '{{}}' -Uadmin -Padmin".format(
            lib.SERVER_IP, lib.PORT
        )
        self.node = "{}:{}".format(lib.SERVER_IP, lib.PORT)

    def tearDown(self):
        lib.stop()

    def run_asadm(self, cmd, json=False):
        args = self.args.format(cmd)

        if json:
            args += " --json"

        return test_util.run_asadm(args)

    def status_records(self, cmd="manage checkpoint status"):
        cp = self.run_asadm(cmd, json=True)
        out = test_util.get_separate_output(cp.stdout)

        if not out:
            raise AssertionError(
                "no sheet in '{}' output:\n{}\n{}".format(cmd, cp.stdout, cp.stderr)
            )

        _, _, names, values, _ = test_util.parse_output(out[0])

        return [dict(zip(names, row)) for row in values]

    def test_status_before_any_save(self):
        """A configured but un-checkpointed namespace reports state 'none', 0/0."""
        records = self.status_records()

        self.assertTrue(records, "expected a row per configured namespace")

        namespaces = {record["Namespace"] for record in records}

        self.assertIn(lib.NAMESPACE, namespaces)

        for record in records:
            self.assertEqual(record["State"], "none")
            self.assertEqual(record["Files"], "0/0")
            self.assertEqual(record["Parked"], "False")

    def test_bare_command_is_status(self):
        """'manage checkpoint' with no subcommand reads; it never saves."""
        self.assertEqual(
            self.status_records("manage checkpoint"), self.status_records()
        )

    def test_status_rejects_a_parameter(self):
        # checkpoint-status takes no parameters; asadm must surface the refusal rather
        # than render an empty table.
        cp = test_util.run_asadm(
            self.args.format('asinfo -v "checkpoint-status:namespace=test"')
        )

        self.assertIn("takes no parameters", cp.stdout + cp.stderr)

    def require_checkpoint_configured(self):
        """
        Fail before parking anything if 'index-checkpoint-path' did not take. An
        unconfigured server answers with an error and renders no sheet; a server
        where every namespace opted out still parks on save - a destructive no-op -
        and renders no namespace rows either.
        """
        records = self.status_records()

        self.assertTrue(
            records, "'index-checkpoint-path' is not in effect - refusing to save"
        )

    def test_save_parks_the_node_and_status_still_reads_it(self):
        """
        The end-to-end path: save, the node leaves the cluster and parks, and
        'manage checkpoint status' must still reach it. asadm marks a parked node not
        alive (it refuses 'build'), so this is what regressed the default node scope.
        """
        self.require_checkpoint_configured()

        cp = self.run_asadm(
            "manage checkpoint save --no-warn --no-wait with {}".format(self.node)
        )

        self.assertNotIn("ERROR", cp.stderr, cp.stderr)

        deadline = time.time() + 120
        records = []

        while time.time() < deadline:
            records = self.status_records()

            if records and all(
                record["State"] in TERMINAL_STATES for record in records
            ):
                break

            time.sleep(2)

        self.assertTrue(records, "never read a checkpoint status from the parked node")

        for record in records:
            self.assertEqual(
                record["State"],
                "done",
                "checkpoint did not complete: {}".format(record),
            )

            done, _, total = record["Files"].partition("/")

            self.assertEqual(done, total)
            self.assertNotEqual(total, "0")

    def test_save_is_idempotent_while_parked(self):
        """Re-issuing against a parked node reports state, it does not error."""
        self.require_checkpoint_configured()

        self.run_asadm(
            "manage checkpoint save --no-warn --no-wait with {}".format(self.node)
        )

        deadline = time.time() + 120

        while time.time() < deadline:
            records = self.status_records()

            if records and all(
                record["State"] in TERMINAL_STATES for record in records
            ):
                break

            time.sleep(2)

        cp = self.run_asadm(
            "manage checkpoint save --no-warn --no-wait with {}".format(self.node)
        )
        combined = cp.stdout + cp.stderr

        self.assertIn("checkpoint-save already", combined, combined)


if __name__ == "__main__":
    unittest.main()
