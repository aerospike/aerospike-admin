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

import glob
import os
import shutil
import signal
import tarfile
import tempfile
import time
import unittest

from test.e2e import lib, util

COLLECTINFO_PREFIX = "asadm_test_interrupt_"
# The sysinfo step's iostat call. Any other iostat call, such as the one in health's
# local system stats, fails at once.
IOSTAT_STAND_IN = """#!/bin/sh
if [ "$*" = "-y -x 5 4" ]; then
  echo $$ > "{pid_file}"
  exec sleep 120
fi
exit 1
"""


def asadm_args(command):
    return f"-h {lib.SERVER_IP}:{lib.PORT} -Uadmin -Padmin -e '{command}'"


class HealthTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=1)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def test_interrupt_during_the_wait_between_snapshots(self):
        asadm = util.AsadmProcess("--debug " + asadm_args("health -n 2 -s 60"))

        self.assertTrue(
            asadm.wait_for_stderr("Snapshot 1", 60), asadm.output.stderr[-2000:]
        )
        asadm.interrupt()
        returncode, elapsed = asadm.wait(30)

        self.assertEqual(returncode, 130, asadm.output.stderr[-2000:])
        self.assertLess(elapsed, 5)

    def test_negative_interval_is_rejected(self):
        asadm = util.AsadmProcess(asadm_args("health -s -1"))
        returncode, _ = asadm.wait(30)

        self.assertEqual(returncode, 2, asadm.output.stderr)

    def test_huge_interval_is_rejected(self):
        asadm = util.AsadmProcess(asadm_args("health -s 99999999999"))
        returncode, _ = asadm.wait(30)

        self.assertEqual(returncode, 2, asadm.output.stderr)


class CollectinfoSysinfoInterruptTest(unittest.TestCase):
    """The nodes are at 127.0.0.1 and asadm finds no aerospike/aerospike-server
    container, so it treats them as local and runs the sysinfo step."""

    @classmethod
    def setUpClass(cls):
        lib.start(num_nodes=1)

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def setUp(self):
        bin_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, bin_dir, ignore_errors=True)
        self.pid_file = os.path.join(bin_dir, "iostat.pid")
        iostat = os.path.join(bin_dir, "iostat")

        with open(iostat, "w") as f:
            f.write(IOSTAT_STAND_IN.format(pid_file=self.pid_file))

        os.chmod(iostat, 0o755)
        self.env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"])

    def _iostat_pid(self, timeout):
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if os.path.exists(self.pid_file):
                with open(self.pid_file) as f:
                    pid = f.read().strip()

                if pid:
                    return int(pid)

            time.sleep(0.2)

        return None

    def _kill_if_running(self, pid):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _bundles(self, prefix):
        """Also cleans up the directories of runs that never got archived."""
        for entry in glob.glob("/tmp/%s*" % prefix):
            if os.path.isdir(entry):
                self.addCleanup(shutil.rmtree, entry, ignore_errors=True)
            else:
                self.addCleanup(os.remove, entry)

        return sorted(glob.glob("/tmp/%s*.tgz" % prefix))

    def _interrupt_during_sysinfo(
        self, command="collectinfo", sig=signal.SIGINT, group=False, repeat=1
    ):
        prefix = "%s%s_%d_" % (COLLECTINFO_PREFIX, self._testMethodName, time.time())
        asadm = util.AsadmProcess(
            asadm_args(
                command.replace("collectinfo", "collectinfo --output-prefix " + prefix)
            ),
            env=self.env,
        )
        pid = self._iostat_pid(180)
        self.assertIsNotNone(pid, asadm.output.stderr[-2000:])
        self.addCleanup(self._kill_if_running, pid)

        for i in range(repeat):
            if i:
                time.sleep(1)

            asadm.interrupt(sig, group)

        returncode, elapsed = asadm.wait(60)

        return pid, returncode, elapsed, asadm.output, self._bundles(prefix)

    def assert_interrupted(self, returncode, elapsed, output, bundles):
        self.assertEqual(returncode, 130, output.stderr[-2000:])
        self.assertLess(elapsed, 10)
        self.assertNotIn("--ignore-errors", output.stderr)
        self.assertIn("interrupted", output.stderr)
        self.assertEqual(len(bundles), 1, output.stderr[-2000:])
        self.assert_archive_holds_all_sysinfo(bundles[0])

    def assert_archive_holds_all_sysinfo(self, bundle):
        """Nothing may still be writing sysinfo.log once it is archived."""
        with tarfile.open(bundle) as tf:
            member = next(
                (m for m in tf.getmembers() if m.name.endswith("sysinfo.log")), None
            )
            self.assertIsNotNone(member, tf.getnames())
            archived = tf.extractfile(member).read()

        time.sleep(2)
        on_disk = os.path.join(bundle[: -len(".tgz")], os.path.basename(member.name))

        if os.path.exists(on_disk):
            with open(on_disk, "rb") as f:
                self.assertEqual(f.read(), archived)

    def assert_sysinfo_command_stopped(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_interrupt_during_sysinfo(self):
        pid, *result = self._interrupt_during_sysinfo()

        self.assert_interrupted(*result)
        self.assert_sysinfo_command_stopped(pid)

    def test_interrupt_during_sysinfo_with_ignore_errors(self):
        pid, *result = self._interrupt_during_sysinfo("collectinfo --ignore-errors")

        self.assert_interrupted(*result)
        self.assert_sysinfo_command_stopped(pid)

    def test_sigterm_during_sysinfo(self):
        pid, *result = self._interrupt_during_sysinfo(sig=signal.SIGTERM)

        self.assert_interrupted(*result)
        self.assert_sysinfo_command_stopped(pid)

    def test_repeated_interrupts_from_the_terminal(self):
        """A second Ctrl-C used to land in the interpreter's exit-time thread join."""
        _, returncode, elapsed, output, bundles = self._interrupt_during_sysinfo(
            group=True, repeat=3
        )

        self.assertNotIn("Traceback", output.stderr)
        self.assertNotIn("Exception ignored", output.stderr)
        self.assert_interrupted(returncode, elapsed, output, bundles)

    def test_interrupt_stops_the_rest_of_the_command_list(self):
        _, *result = self._interrupt_during_sysinfo("collectinfo; info network")
        output = result[2]

        self.assertNotIn("Network Information", output.stdout)
        self.assert_interrupted(*result)

    def test_interrupt_stops_watch(self):
        _, returncode, elapsed, output, bundles = self._interrupt_during_sysinfo(
            "watch 1 3 collectinfo"
        )

        self.assertLess(elapsed, 10)
        self.assertEqual(len(bundles), 1, output.stderr[-2000:])
