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

import json
import shlex
import time
from typing import Any
import unittest
from parameterized import parameterized

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


class TableRenderTests(unittest.TestCase):
    CMDS = [
        ("info network"),
        ("info namespace object"),
        ("info namespace usage"),
        ("info set"),
        ("info xdr"),
        ("info sindex"),
        ("show config namespace"),
        ("show config network"),
        ("show config security"),
        ("show config service"),
        ("show config dc"),
        ("show config xdr dc"),
        ("show config xdr filter"),
        ("show config xdr namespace"),
        ("show statistics namespace"),
        ("show statistics service"),
        ("show statistics sindex"),
        ("show statistics sets"),
        ("show statistics bins"),
        ("show statistics dc"),
        ("show statistics xdr dc"),
        ("show statistics xdr namespace"),
        ("show latencies -v"),
        ("show distribution time_to_live"),  # TODO: Causing issues on github actions
        ("show distribution object_size"),
        ("show mapping ip"),
        ("show mapping node"),
        ("show pmap"),
        ("show best-practices"),
        ("show jobs queries"),
        ("show racks"),
        ("show roster"),
        ("show roles"),
        ("show users"),
        ("show users admin"),
        ("show users statistics"),
        ("show users statistics admin"),
        ("show udfs"),
        ("show sindex"),
        ("show stop-writes"),
    ]
    NOT_IN_CI_MODE = ["show mapping ip", "show mapping node", "show pmap"]

    @classmethod
    def setUpClass(cls):
        lib.start()
        lib.populate_db("no-error-test")
        lib.create_sindex("a-index", "numeric", lib.NAMESPACE, "a", "no-error-test")
        lib.create_xdr_filter(lib.NAMESPACE, lib.DC, "kxGRSJMEk1ECo2FnZRU=")
        lib.upload_udf("metadata.lua", TEST_UDF)
        util.run_asadm(
            "-h {} --enable -e '{}' -Uadmin -Padmin".format(
                lib.SERVER_IP,
                "manage config namespace test param nsup-hist-period to 10; manage config namespace test param enable-benchmarks-write to true; manage config namespace test param enable-benchmarks-read to true",
            )
        )
        time.sleep(60000)
        cls.collectinfo_cp = util.run_asadm(
            "-h {} -e '{}' -Uadmin -Padmin".format(
                lib.SERVER_IP, "collectinfo --output-prefix asadm_test_"
            )
        )

    @classmethod
    def tearDownClass(cls):
        lib.stop()

    def assertEntryNotError(self, tc: unittest.TestCase, entry: dict[str, Any]):
        raw_data = entry["raw"]
        conv_data = entry["converted"]
        tc.assertNotEqual(raw_data, "error")
        tc.assertNotEqual(conv_data, "~~")

    def assertRecordNotError(self, tc: unittest.TestCase, record: dict[str, Any]):
        for col_name, data in record.items():
            if isinstance(list(data.values())[0], dict):
                for col_name, data2 in data.items():
                    print(data2)
                    self.assertEntryNotError(tc, data2)
            else:
                print(data)
                self.assertEntryNotError(tc, data)

    def check_cmd_for_errors(self, cp: util.CompletedProcess):
        self.assertEqual(cp.returncode, 0, "Incorrect return code")

        try:
            stdout_dicts = util.get_separate_output(cp.stdout)
        except Exception as e:
            self.fail("Unable to unmarshal json: {}".format(e))

        if len(stdout_dicts) > 1:
            self.fail(
                "This command returned multiple tables and should not for this test."
            )
        if len(stdout_dicts) == 0:
            self.fail(
                "This command returned no tables. There should be exactly 1 for this test."
            )

        if "traceback" in cp.stderr:
            self.fail("Traceback found in stderr")

        for group in stdout_dicts[0]["groups"]:
            for record in group["records"]:
                self.assertRecordNotError(self, record)

    @parameterized.expand(CMDS)
    def test_live_cmds_for_errors(self, cmd):
        args = "-h {} -e '{}' --json -Uadmin -Padmin".format(lib.SERVER_IP, cmd)
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
