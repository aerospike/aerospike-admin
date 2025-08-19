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

import json
import re
import time
from typing import Any, Callable
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
        ("info network", ["Uptime", "Client Conns"], None),
        ("info namespace object", [], None),
        ("info namespace usage", ["System Memory"], None),
        ("info set", [], None),
        ("info xdr", ["Lag (hh:mm:ss)"], None),
        ("info sindex", [], None),
        ("info transactions", [], None),
        (
            "show config namespace",
            [
                "title",
                "storage-engine.file[0]",
                "storage-engine.stripe[0]",
                "conflict-resolution-policy",
                "mrt-duration",
                "read-consistency-level-override",
                "replication-factor",
                "strong-consistency",
                "write-commit-level-override",
            ],
            None,
        ),
        ("show config network", [], None),
        ("show config security", [], None),
        ("show config service", [], None),
        ("show config dc", [], None),
        ("show config xdr dc", [], None),
        ("show config xdr filter", [], None),
        ("show config xdr namespace", [], None),
        ("show statistics namespace", ["current_time", "migrate_rx_instances"], None),
        # (
        #     "show statistics service",  # Too many differing stats to compare. Leaving for reference.
        #     [
        #         "uptime",
        #         "time_since_rebalance",
        #         "system_total_cpu_pct",
        #         "system_user_cpu_pct",
        #         "system_kernel_cpu_pct",
        #         "system_free_mem_kbytes",
        #         "system_free_mem_pct",
        #         "system_thp_mem_kbytes",
        #         "process_cpu_pct",
        #         "info_queue",
        #         "info_complete",
        #         "heartbeat_received_foreign",
        #         "heap_mapped_kbytes",
        #         "heap_efficiency_pct",
        #         "heap_allocated_kbytes",
        #         "heap_active_kbytes",
        #         "client_connections_opened",
        #         "client_connections_closed",
        #         "client_connections",
        #     ],
        #     None,
        # ),
        ("show statistics sindex", [], None),
        (
            "show statistics sets",
            [
                "title",
                "ns",
                "set",
                "objects",
                "data_used_bytes",
                "disable-eviction",
                "enable-index",
            ],
            None,
        ),
        ("show statistics bins", [], None),
        ("show statistics dc", ["retry_no_node", "lag", "lap_us"], None),
        ("show statistics xdr dc", ["retry_no_node", "lag", "lap_us"], None),
        ("show statistics xdr namespace", ["retry_no_node", "lag"], None),
        ("show latencies -v -e 1 -b 17", [], None),
        ("show distribution time_to_live", [], None),
        ("show pmap", [], None),
        ("show best-practices", [], None),
        (
            "show jobs queries",
            ["Time Since Done"],
            lambda x: sorted(
                x, key=lambda x: x["Node"]["raw"]
            ),  # Only works if a single query has be created
        ),  # Sort the records
        ("show racks", [], None),
        ("show roster", [], None),
        ("show roles", [], None),
        ("show users", ["Connections"], None),
        ("show users stat", ["Connections"], None),
        ("show udfs", [], None),
        ("show sindex", [], None),
        ("show stop-writes", ["Usage", "Usage%", "Namespace", "Set"], None),
        ("health", [], None),
        ("summary", [], None),
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
            except json.JSONDecodeError as e:
                # Handle the case where we have multiple JSON objects (like show statistics namespace)
                if "Extra data" in str(e):
                    # For show statistics namespace, we have multiple JSON objects for different namespaces
                    # Let's try to parse just the first JSON object
                    content = map[key].strip()
                    # Find the first complete JSON object
                    brace_count = 0
                    end_pos = 0
                    for i, char in enumerate(content):
                        if char == "{":
                            brace_count += 1
                        elif char == "}":
                            brace_count -= 1
                            if brace_count == 0:
                                end_pos = i + 1
                                break

                    if end_pos > 0:
                        try:
                            first_json = content[:end_pos]
                            map[key] = json.loads(first_json)
                        except json.JSONDecodeError:
                            # If even the first JSON object fails, keep as string
                            pass
                    else:
                        # Couldn't find a complete JSON object, keep as string
                        pass
                else:
                    # Other JSON decode errors, keep as string
                    # Probably 'health' cmd which has no json mode.
                    pass

    @classmethod
    def setUpClass(cls):
        lib.start()

        set_ = "collect-info-testset"
        namespace_ = "test"
        namespace_sc_ = "test_sc"
        lib.populate_db(set_, namespace=namespace_)
        lib.populate_db(set_, namespace=namespace_sc_)
        lib.create_sindex("a-index", "numeric", lib.NAMESPACE, "a", "no-error-test")
        lib.create_xdr_filter(lib.NAMESPACE, lib.DC, "kxGRSJMEk1ECo2FnZRU=")
        lib.upload_udf("metadata.lua", TEST_UDF)

        # Wait for recluster to complete
        time.sleep(5)

        def record_set(record):
            (key, meta, bins) = record

        query = lib.CLIENT.query(namespace_, set_)
        query.foreach(record_set)

        query_sc = lib.CLIENT.query(namespace_sc_, set_)
        query_sc.foreach(record_set)
        time.sleep(60)
        # time.sleep(300000)

        collectinfo_cmd = "collectinfo --output-prefix asadm_test_"
        live_mode_cmds = cls.get_cmds()
        live_mode_cmds.append(collectinfo_cmd)
        cmds = "; ".join(live_mode_cmds)
        live_mode_cp = util.run_asadm(
            f"-h {lib.SERVER_IP}:{lib.PORT} -e '{cmds}' -Uadmin -Padmin --json --pmap --timeout 20"
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

    def assertTableDictEqual(
        self,
        d1,
        d2,
        ignore_keys=None,
        transform_recs: Callable[[list[Any]], list[Any]] | None = None,
    ):
        if isinstance(d1, str) or isinstance(d1, int) or isinstance(d1, float):
            return d1 == d2
        if isinstance(d1, list) and isinstance(d2, list):
            if len(d1) != len(d2):
                return False

            for idx, _ in enumerate(d1):
                if not self.assertTableDictEqual(
                    d1[idx], d2[idx], ignore_keys, transform_recs
                ):
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
                if key == "records" and transform_recs:
                    d1[key] = transform_recs(d1[key])
                    d2[key] = transform_recs(d2[key])
                if not self.assertTableDictEqual(
                    d1[key], d2[key], ignore_keys, transform_recs
                ):
                    return False

        return True

    @parameterized.expand(CMDS)
    def test_compare_collectinfo_to_live(
        self,
        cmd: str,
        ignore_keys: list[str] | None,
        transform_recs: Callable[[list[Any]], list[Any]] | None = None,
    ):
        if not self.assertTableDictEqual(
            self.live_mode_map[cmd],
            self.collectinfo_map[cmd],
            ignore_keys=ignore_keys,
            transform_recs=transform_recs,
        ):
            self.assertEqual(self.live_mode_map[cmd], self.collectinfo_map[cmd])
