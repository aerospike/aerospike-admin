# Copyright 2023 Aerospike, Inc.
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
from typing import Any, Callable
import unittest
from parameterized import parameterized, parameterized_class
from lib.utils import version

from test.e2e import util
from .. import lib

TEST_UDF = """
function get_digest(rec)
    info("Digest:%s", tostring(record.digest(rec)))
    return record.digest(rec)
end

function get_key(rec)
    info("Key:%s", tostring(record.key(rec)))
    return record.key(rec)
end

function get_ttl(rec)
    info("ttl:%s", tostring(record.ttl(rec)))
    return record.ttl(rec)
end

function get_gen(rec)
    info("gen:%s", tostring(record.gen(rec)))
    return record.gen(rec)
end

function get_setname(rec)
    info("setname:%s", tostring(record.setname(rec)))
    return record.setname(rec)
end

function get_numbins(rec)
    info("numbins:%s", tostring(record.numbins(rec)))
    return record.numbins(rec)
end

function get_bin_names(rec)
    info("bin_names:%s", tostring(record.bin_names(rec)))
    return record.bin_names(rec)
end

function set_ttl(rec, ttl)
    record.set_ttl(rec, ttl)
    aerospike:update(rec)
    return record.set_ttl(rec)
end

function rem_key(rec)
    record.drop_key(rec)
    aerospike:update(rec)
    return record.key(rec)
end
"""


class Cmd:
    def __init__(self, cmd: str, server_filter: Callable[[str], bool] | None = None):
        self.cmd = cmd
        self.server_filter = server_filter

    def check_skip(self, tc: unittest.TestCase, server_version: str):
        if self.server_filter and not self.server_filter(server_version):
            tc.skipTest(f"Skipping test for server version {server_version}")

    def __hash__(self) -> int:
        return hash(self.cmd)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Cmd):
            return self.cmd == other.cmd
        return False


CMDS = [
    Cmd("info network"),
    Cmd("info namespace object"),
    Cmd("info namespace usage"),
    Cmd("info set"),
    Cmd("info xdr"),
    Cmd("info sindex"),
    Cmd("show config namespace"),
    Cmd("show config network"),
    Cmd("show config security"),
    Cmd("show config service"),
    Cmd("show config dc"),
    Cmd("show config xdr dc"),
    Cmd("show config xdr filter"),
    Cmd("show config xdr namespace"),
    Cmd("show statistics namespace"),
    Cmd("show statistics service"),
    Cmd("show statistics sindex"),
    Cmd("show statistics sets"),
    Cmd(
        "show statistics bins",
        lambda v: v != "latest"
        and version.LooseVersion(v) < version.LooseVersion("7.0.0"),
    ),
    Cmd("show statistics dc"),
    Cmd("show statistics xdr dc"),
    Cmd("show statistics xdr namespace"),
    Cmd("show latencies -v"),
    Cmd("show distribution time_to_live"),  # TODO: Causing issues on github actions
    Cmd("show distribution object_size"),
    Cmd("show mapping ip"),
    Cmd("show mapping node"),
    Cmd("show pmap"),
    Cmd("show best-practices"),
    Cmd("show jobs queries"),
    Cmd("show racks"),
    Cmd("show roster"),
    Cmd("show roles"),
    Cmd("show users"),
    Cmd("show users admin"),
    Cmd("show users statistics"),
    Cmd("show users statistics admin"),
    Cmd("show udfs"),
    Cmd("show sindex"),
    Cmd("show stop-writes"),
    Cmd("summary"),
    Cmd(f"generate config with all"),
]
NOT_IN_CI_MODE = [
    Cmd("show mapping ip"),
    Cmd("show mapping node"),
    Cmd("show pmap"),
    Cmd(f"generate config with all"),
]


class TableRenderTestCase(unittest.TestCase):
    def assertEntryNotError(self, entry: dict[str, Any]):
        raw_data = entry["raw"]
        conv_data = entry["converted"]
        self.assertNotEqual(raw_data, "error")
        self.assertNotEqual(conv_data, "~~")

    def assertRecordNotError(self, record: dict[str, Any]):
        for col_name, data in record.items():
            if isinstance(list(data.values())[0], dict):
                for col_name, data2 in data.items():
                    print(data2)
                    self.assertEntryNotError(data2)
            else:
                print(data)
                self.assertEntryNotError(data)

    def check_cmd_for_errors(self, cp: util.CompletedProcess):
        self.assertEqual(cp.returncode, 0, "Incorrect return code")

        if "traceback" in cp.stderr:
            self.fail("Traceback found in stderr")


@parameterized_class(
    [
        {"template_file": "aerospike_latest.conf", "docker_tag": "latest"},
        # {"template_file": "aerospike_6.x.conf", "docker_tag": "6.4.0.7"}, # Add this
        # to all tests once we create multiple test workflows. I am thinking one for
        # unittest, one for e2e against latest, and another that is e2e against all
        # notable versions i.e. 4.9, 5.6, 6.4
    ]
)
class TableRenderNoErrorTests(TableRenderTestCase):
    template_file = ""
    docker_tag = ""

    @classmethod
    def setUpClass(cls):
        lib.start(template_file=cls.template_file, docker_tag=cls.docker_tag)
        lib.populate_db("no-error-test")
        lib.create_sindex("a-index", "numeric", lib.NAMESPACE, "a", "no-error-test")
        lib.create_xdr_filter(lib.NAMESPACE, lib.DC, "kxGRSJMEk1ECo2FnZRU=")
        lib.upload_udf("metadata.lua", TEST_UDF)
        cmd = "manage config namespace test param nsup-hist-period to 5; manage config namespace test param enable-benchmarks-write to true; manage config namespace test param enable-benchmarks-read to true"
        util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{cmd}' -Uadmin -Padmin"
        )
        time.sleep(30)
        cmd = "collectinfo --output-prefix asadm_test_"
        cls.collectinfo_cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -e '{cmd}' -Uadmin -Padmin"
        )

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    @parameterized.expand(CMDS)
    def test_live_cmds_for_errors(self, cmd: Cmd):
        cmd.check_skip(self, self.docker_tag)
        args = f"-h {lib.SERVER_IP}:{lib.PORT} -e '{cmd.cmd}' --json -Uadmin -Padmin"
        o = util.run_asadm(args)
        self.check_cmd_for_errors(o)

    @parameterized.expand(list(set(CMDS).difference(NOT_IN_CI_MODE)))
    def test_collectinfo_cmds_for_errors(self, cmd: Cmd):
        cmd.check_skip(self, self.docker_tag)
        collectinfo_path = util.get_collectinfo_path(
            self.collectinfo_cp, "/tmp/asadm_test_"
        )
        args = "-cf {} -e '{}' --json".format(collectinfo_path, cmd.cmd)
        o = util.run_asadm(args)
        print(o.stdout)
        print(o.stderr)

        self.check_cmd_for_errors(o)


class TableRenderNodeUnreachableTests(TableRenderTestCase):
    @classmethod
    def setUpClass(cls):
        lib.start()
        lib.populate_db("no-error-test")
        lib.create_sindex("a-index", "numeric", lib.NAMESPACE, "a", "no-error-test")
        lib.create_xdr_filter(lib.NAMESPACE, lib.DC, "kxGRSJMEk1ECo2FnZRU=")
        lib.upload_udf("metadata.lua", TEST_UDF)
        lib.start_server(lib.PORT, lib.DEFAULT_N_NODES + 1, access_address="1.1.1.1")
        cmd = "manage config namespace test param nsup-hist-period to 5; manage config namespace test param enable-benchmarks-write to true; manage config namespace test param enable-benchmarks-read to true"
        util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} --enable -e '{cmd}' -Uadmin -Padmin"
        )
        time.sleep(30)
        cmd = "collectinfo --output-prefix asadm_test_"
        cls.collectinfo_cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -e '{cmd}' -Uadmin -Padmin"
        )

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    @parameterized.expand(CMDS)
    def test_live_cmds_for_errors(self, cmd):
        args = f"-h {lib.SERVER_IP}:{lib.PORT} -e '{cmd}' --json -Uadmin -Padmin"
        o = util.run_asadm(args)
        self.check_cmd_for_errors(o)

    @parameterized.expand(list(set(CMDS).difference(NOT_IN_CI_MODE)))
    def test_collectinfo_cmds_for_errors(self, cmd):
        collectinfo_path = util.get_collectinfo_path(
            self.collectinfo_cp, "/tmp/asadm_test_"
        )
        args = "-cf {} -e '{}' --json".format(collectinfo_path, cmd)
        o = util.run_asadm(args)
        print(o.stdout)
        print(o.stderr)

        self.check_cmd_for_errors(o)
