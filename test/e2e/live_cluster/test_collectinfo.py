# Copyright 2013-2021 Aerospike, Inc.
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
import re
import time
import unittest

from parameterized import parameterized
import asynctest
from test.e2e import lib, util

TEST_UDF = """
function get_digest(rec)
    info("Digest:%s", tostring(record.digest(rec)))
    return record.digest(rec)
end
"""


class TestCollectinfo(asynctest.TestCase):
    # Formate: (cmd to run, [keys to ignore when comparing collectinfo vs live mode])
    CMDS = [
        ("info network", ["Uptime", "Client Conns"]),
        ("info namespace object", []),
        ("info namespace usage", []),
        ("info set", []),
        ("info xdr", ["Lag (hh:mm:ss)"]),
        ("info sindex", []),
        ("show config namespace", []),
        ("show config network", []),
        ("show config security", []),
        ("show config service", []),
        ("show config dc", []),
        ("show config xdr dc", []),
        ("show config xdr filter", []),
        ("show config xdr namespace", []),
        (
            "show statistics namespace",
            [
                "current_time",
            ],
        ),
        (
            "show statistics service",
            [
                "uptime",
                "time_since_rebalance",
                "system_total_cpu_pct",
                "system_user_cpu_pct",
                "system_kernel_cpu_pct",
                "system_free_mem_kbytes",
                "system_free_mem_pct",
                "system_thp_mem_kbytes",
                "process_cpu_pct",
                "info_queue",
                "info_complete",
                "heartbeat_received_foreign",
                "heap_mapped_kbytes",
                "heap_efficiency_pct",
                "heap_allocated_kbytes",
                "heap_active_kbytes",
                "client_connections_opened",
                "client_connections_closed",
                "client_connections",
            ],
        ),
        ("show statistics sindex", []),
        ("show statistics sets", []),
        ("show statistics bins", []),
        ("show statistics dc", ["retry_no_node", "lag", "lap_us"]),
        ("show statistics xdr dc", ["retry_no_node", "lag", "lap_us"]),
        ("show statistics xdr namespace", ["retry_no_node", "lag"]),
        ("show latencies -v -e 1 -b 17", []),
        ("show distribution time_to_live", []),
        # "show distribution object_size", # TODO: Fix differences between two outputs
        ("show pmap", []),
        ("show best-practices", []),
        ("show jobs queries", ["Time Since Done"]),
        ("show racks", []),
        ("show roster", []),
        ("show roles", []),
        ("show users", ["Connections"]),
        ("show udfs", []),
        ("show sindex", []),
        ("health", []),
    ]
    maxDiff = None

    @classmethod
    def get_cmds(cls) -> list[str]:
        return list(map(lambda x: x[0], cls.CMDS))

    @classmethod
    def parse_multi_tables_into_maps(cls, output_str: str) -> dict[str, str]:
        cmds = cls.get_cmds()
        split_lines = output_str.splitlines()
        regex = r"^~~~\s[\w\s\-_]+\s~~~$"
        cmd_map = {}
        line_idx = 0
        start = 999
        end = 0

        while line_idx < len(split_lines):
            line = split_lines[line_idx]
            if re.match(regex, line) and line_idx < len(split_lines):
                end = line_idx
                if start < end:
                    cmd_map[cmds[len(cmd_map)]] = "\n".join(split_lines[start:end])
                start = line_idx + 1
            line_idx += 1

        end = line_idx
        if start < end and len(cmd_map) < len(cmds):
            cmd_map[cmds[len(cmd_map)]] = "\n".join(split_lines[start:end])

        if len(cmd_map) != len(cmds):
            raise Exception(
                "Failed to parse all the tables. Mismatch between cmds and tables: {} != {}".format(
                    len(cmd_map),
                    len(cmds),
                )
            )

        return cmd_map

    @classmethod
    def rm_timestamp_from_map(cls, map):
        for key in map:
            map[key] = re.sub(r"([0-9]{2}:){2}[0-9]{2}", "", map[key])

    @classmethod
    def clean_tables(cls, map):
        for key in map:
            map[key] = re.sub(r"([0-9]{2}:){2}[0-9]{2}", "", map[key])
            map[key] = re.sub(r"\n$", "", map[key])
            map[key] = map[key].replace("\n\n", "")

    @classmethod
    def unmarshal_json_tables(cls, map):
        for key in map:
            try:
                map[key] = json.loads(map[key])
            except:
                # Probably 'health' cmd which has no json mode.
                pass

    @classmethod
    def setUpClass(cls):
        lib.start()
        set_ = "collect-info-testset"
        lib.populate_db(set_)
        lib.create_sindex("a-index", "numeric", lib.NAMESPACE, "a", "no-error-test")
        lib.upload_udf("metadata.lua", TEST_UDF)

        def record_set(record):
            (key, meta, bins) = record

        query = lib.CLIENT.query(lib.NAMESPACE, set_)
        query.foreach(record_set)
        time.sleep(60)
        # time.sleep(300000)

        collectinfo_cmd = "collectinfo --output-prefix asadm_test_"
        live_mode_cmds = cls.get_cmds()
        live_mode_cmds.append(collectinfo_cmd)
        live_mode_cp = util.run_asadm(
            "-h {} -e '{}' -Uadmin -Padmin --json --pmap".format(
                lib.SERVER_IP, "; ".join(live_mode_cmds)
            )
        )

        # with open("out.txt", "w") as f:
        #     f.write(live_mode_cp.stdout)
        # with open("err.txt", "w") as f:
        #     f.write(live_mode_cp.stderr)

        out = live_mode_cp.stdout
        cls.live_mode_map = cls.parse_multi_tables_into_maps(out)
        cls.clean_tables(cls.live_mode_map)
        cls.unmarshal_json_tables(cls.live_mode_map)

        # with open("live_map.txt", "w") as f:
        #     f.write(json.dumps(cls.live_mode_map, indent=2))

        collectinfo_path = util.get_collectinfo_path(live_mode_cp, "/tmp/asadm_test")

        if not collectinfo_path:
            raise Exception(
                "Could not determine collectinfo path to be used in tests\n {}".format(
                    live_mode_cp.stderr
                )
            )

        collectinfo_mode_cp = util.run_asadm(
            "-cf {} --json -e '{}'".format(collectinfo_path, "; ".join(cls.get_cmds()))
        )

        # with open("out-cf.txt", "w") as f:
        #     f.write(collectinfo_mode_cp.stdout)
        # with open("err-cf.txt", "w") as f:
        #     f.write(collectinfo_mode_cp.stderr)

        cls.collectinfo_map = cls.parse_multi_tables_into_maps(
            collectinfo_mode_cp.stdout
        )
        cls.clean_tables(cls.collectinfo_map)
        cls.unmarshal_json_tables(cls.collectinfo_map)

        # with open("collectinfo_map.txt", "w") as f:
        #     f.write(json.dumps(cls.collectinfo_map, indent=2))

    @classmethod
    def tearDownClass(cls) -> None:
        lib.stop()

    def assertTableDictEqual(self, d1, d2, ignore_keys=None):
        if isinstance(d1, str) or isinstance(d1, int) or isinstance(d1, float):
            return d1 == d2
        if isinstance(d1, list) and isinstance(d2, list):
            if len(d1) != len(d2):
                return False
            for idx, _ in enumerate(d1):
                if not self.assertTableDictEqual(d1[idx], d2[idx], ignore_keys):
                    return False
                return True

        if not (isinstance(d1, dict) and isinstance(d2, dict)):
            self.fail(
                f"d1 and d2 should both be dicts but found {type(d1)} and {type(d2)}"
            )

        if set(d1.keys()) != set(d2.keys()):
            return False

        for key in d1:
            if not ignore_keys or key not in ignore_keys:
                if not self.assertTableDictEqual(d1[key], d2[key], ignore_keys):
                    return False

        return True

    @parameterized.expand(CMDS)
    def test_compare_collectinfo_to_live(self, cmd: str, ignore_keys: list[str] | None):
        if not self.assertTableDictEqual(
            self.live_mode_map[cmd],
            self.collectinfo_map[cmd],
            ignore_keys=ignore_keys,
        ):
            self.assertEqual(self.live_mode_map[cmd], self.collectinfo_map[cmd])
