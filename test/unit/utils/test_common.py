# Copyright 2021-2023 Aerospike, Inc.
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

from datetime import datetime
import asynctest
from parameterized import parameterized
import unittest

from lib.utils import common, util


class ComputeLicenseDataSizeTest(asynctest.TestCase):
    maxDiff = None

    def run_test_case(
        self,
        namespace_stats,
        server_builds,
        license_data_usage,
        allow_unstable,
        expected_summary_dict: common.SummaryDict,
    ):
        # merge expected summary with init summary output so we don't have put the entire thing
        # in the test
        expected_summary_dict = util.deep_merge_dicts(
            common._initialize_summary_output(namespace_stats.keys()),
            expected_summary_dict,
        )  # type: ignore
        summary_dict = common._initialize_summary_output(namespace_stats.keys())

        common.compute_license_data_size(
            namespace_stats=namespace_stats,
            license_data_usage=license_data_usage,
            server_builds=server_builds,
            allow_unstable=allow_unstable,
            summary_dict=summary_dict,
        )

        self.assertDictEqual(
            expected_summary_dict, summary_dict, "Input: " + str(namespace_stats)
        )

    def test_success_with_out_agent(self):
        test_cases = [
            {
                "ns_stats": {},
                "license_data": None,
                "server_builds": {},
                "allow_unstable": False,
                "exp_summary_dict": {},
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 99000,
                        }
                    }
                },
                "license_data": None,
                "server_builds": {"1.1.1.1": "5.0.0.0"},
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {"license_data": {"latest": 46000}},
                    "NAMESPACES": {"foo": {"license_data": {"latest": 46000}}},
                },
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 99000,
                        },
                        "2.2.2.2": {
                            "master_objects": 100,
                            "effective_replication_factor": 0,  # tie-breaker node
                            "pmem_used_bytes": 99000,
                        },
                    }
                },
                "server_builds": {"1.1.1.1": "5.0.0.0"},
                "license_data": {},
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {"latest": int((99000 / 2) - (35 * 100))}
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {"latest": int((99000 / 2) - (35 * 100))}
                        }
                    },
                },
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 99000,
                        },
                        "2.2.2.2": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,  # tie-breaker node
                            "pmem_used_bytes": 99000,
                        },
                    }
                },
                "server_builds": {"1.1.1.1": "5.0.0.0", "2.2.2.2": "6.0.0.0"},
                "license_data": {},
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {
                            "latest": int(
                                ((99000 / 2) - (35 * 100)) + ((99000 / 2) - (39 * 100))
                            )
                        }
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {
                                "latest": int(
                                    ((99000 / 2) - (35 * 100))
                                    + ((99000 / 2) - (39 * 100))
                                )
                            }
                        }
                    },
                },
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "device_used_bytes": 7200,
                        }
                    }
                },
                "server_builds": {"1.1.1.1": "5.0.0.0"},
                "license_data": None,
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {"license_data": {"latest": 100}},
                    "NAMESPACES": {"foo": {"license_data": {"latest": 100}}},
                },
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 8000,
                            "memory_used_bytes": 800,
                        }
                    },
                    "bar": {
                        "1.1.1.1": {
                            "master_objects": 50,
                            "effective_replication_factor": 3,
                            "device_used_bytes": 6000,
                            "memory_used_bytes": 3300,
                        }
                    },
                },
                "license_data": None,
                "server_builds": {"1.1.1.1": "5.0.0.0"},
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {"license_data": {"latest": 500 + 250}},
                    "NAMESPACES": {
                        "foo": {"license_data": {"latest": 500}},
                        "bar": {"license_data": {"latest": 250}},
                    },
                },
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "device_used_bytes": 7200,
                            "memory_used_bytes": 800,
                        },
                        "2.2.2.2": {
                            "master_objects": 10,
                            "effective_replication_factor": 2,
                            "device_used_bytes": 3200,
                            "memory_used_bytes": 10000,
                        },
                    },
                    "bar": {
                        "1.1.1.1": {
                            "master_objects": 50,
                            "effective_replication_factor": 3,
                            "pmem_used_bytes": 50000,
                        },
                        "2.2.2.2": {
                            "master_objects": 10,
                            "effective_replication_factor": 3,
                            "pmem_used_bytes": 10000,
                        },
                    },
                },
                "license_data": None,
                "allow_unstable": False,
                "server_builds": {"1.1.1.1": "5.0.0.0", "2.2.2.2": "5.0.0.0"},
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {
                            "latest": int(
                                ((7200 + 3200) / 2)
                                - (110 * 35)
                                + ((50000 + 10000) / 3)
                                - (35 * 60)
                            )
                        },
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {
                                "latest": int(((7200 + 3200) / 2) - (110 * 35))
                            }
                        },
                        "bar": {
                            "license_data": {
                                "latest": int(((50000 + 10000) / 3) - (35 * 60))
                            }
                        },
                    },
                },
            },
        ]

        for tc in test_cases:
            self.run_test_case(
                tc["ns_stats"],
                tc["server_builds"],
                tc["license_data"],
                tc["allow_unstable"],
                tc["exp_summary_dict"],
            )

    def test_success_with_agent(self):
        test_cases = [
            {
                "ns_stats": {"foo": {}},
                "license_data": {
                    "license_usage": {
                        "count": 1,
                        "entries": [
                            {
                                "time": "2022-04-07T22:59:47",
                                "unique_data_bytes": 500,
                                "level": "info",
                                "cluster_stable": True,
                                "namespaces": {"foo": {"unique_data_bytes": 100}},
                            }
                        ],
                    },
                },
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {
                            "latest_time": datetime.fromisoformat(
                                "2022-04-07T22:59:47"
                            ),
                            "latest": 500,
                            "min": 500,
                            "max": 500,
                            "avg": 500,
                        }
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {
                                "latest_time": datetime.fromisoformat(
                                    "2022-04-07T22:59:47"
                                ),
                                "latest": 100,
                                "min": 100,
                                "max": 100,
                                "avg": 100,
                            }
                        }
                    },
                },
            },
            {
                "ns_stats": {"foo": {}},
                "license_data": {
                    "license_usage": {
                        "count": 1,
                        "entries": [
                            {
                                "time": "2022-04-07T22:59:47",
                                "unique_data_bytes": 500,
                                "level": "info",
                                "cluster_stable": True,
                                "namespaces": {"foo": {"unique_data_bytes": 100}},
                            },
                            {
                                "latest_time": "2022-04-07T22:59:47",
                                "unique_data_bytes": 0,
                                "level": "error",
                                "namespaces": {"foo": {"unique_data_bytes": 100}},
                            },
                        ],
                    }
                },
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {
                            "latest_time": datetime.fromisoformat(
                                "2022-04-07T22:59:47"
                            ),
                            "latest": 500,
                            "min": 500,
                            "max": 500,
                            "avg": 500,
                        }
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {
                                "latest_time": datetime.fromisoformat(
                                    "2022-04-07T22:59:47"
                                ),
                                "latest": 100,
                                "min": 100,
                                "max": 100,
                                "avg": 100,
                            }
                        }
                    },
                },
            },
            {
                "ns_stats": {"foo": {}},
                "license_data": {
                    "license_usage": {
                        "count": 2,
                        "entries": [
                            {
                                "time": "2022-04-07T22:58:47",
                                "unique_data_bytes": 500,
                                "level": "info",
                                "cluster_stable": True,
                                "namespaces": {"foo": {"unique_data_bytes": 1000}},
                            },
                            {
                                "time": "2022-04-07T22:59:47",
                                "unique_data_bytes": 100,
                                "level": "info",
                                "cluster_stable": True,
                                "namespaces": {"foo": {"unique_data_bytes": 500}},
                            },
                            {"unique_data_bytes": 0, "level": "error"},
                        ],
                    }
                },
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {
                            "latest_time": datetime.fromisoformat(
                                "2022-04-07T22:59:47"
                            ),
                            "latest": 100,
                            "min": 100,
                            "max": 500,
                            "avg": 300,
                        }
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {
                                "latest_time": datetime.fromisoformat(
                                    "2022-04-07T22:59:47"
                                ),
                                "latest": 500,
                                "min": 500,
                                "max": 1000,
                                "avg": 750,
                            }
                        }
                    },
                },
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 99000,
                        }
                    }
                },
                "license_data": {
                    "license_usage": {
                        "count": 3,
                        "entries": [
                            {"unique_data_bytes": 500, "level": "error"},
                            {"unique_data_bytes": 100, "level": "error"},
                            {"unique_data_bytes": 0, "level": "error"},
                        ],
                    }
                },
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {"license_data": {"latest": 46000}},
                    "NAMESPACES": {"foo": {"license_data": {"latest": 46000}}},
                },
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 99000,
                        }
                    }
                },
                "license_data": {
                    "license_usage": {
                        "count": 2,
                        "entries": [
                            {
                                "time": "2022-04-07T22:58:47",
                                "unique_data_bytes": 500,
                                "level": "info",
                                "cluster_stable": False,
                                "namespaces": {"foo": {"unique_data_bytes": 1000}},
                            },
                            {
                                "time": "2022-04-07T22:59:47",
                                "unique_data_bytes": 100,
                                "level": "info",
                                "cluster_stable": False,
                                "namespaces": {"foo": {"unique_data_bytes": 500}},
                            },
                            {"unique_data_bytes": 0, "level": "error"},
                        ],
                    }
                },
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {"license_data": {"latest": 46000}},
                    "NAMESPACES": {"foo": {"license_data": {"latest": 46000}}},
                },
            },
            {
                "ns_stats": {"foo": {}},
                "license_data": {
                    "license_usage": {
                        "count": 2,
                        "entries": [
                            {
                                "time": "2022-04-07T22:58:47",
                                "unique_data_bytes": 500,
                                "level": "info",
                                "cluster_stable": False,
                                "namespaces": {"foo": {"unique_data_bytes": 1000}},
                            },
                            {
                                "time": "2022-04-07T22:59:47",
                                "unique_data_bytes": 100,
                                "level": "info",
                                "cluster_stable": False,
                                "namespaces": {"foo": {"unique_data_bytes": 500}},
                            },
                            {"unique_data_bytes": 0, "level": "error"},
                        ],
                    }
                },
                "allow_unstable": True,
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {
                            "latest_time": datetime.fromisoformat(
                                "2022-04-07T22:59:47"
                            ),
                            "latest": 100,
                            "min": 100,
                            "max": 500,
                            "avg": 300,
                        }
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {
                                "latest_time": datetime.fromisoformat(
                                    "2022-04-07T22:59:47"
                                ),
                                "latest": 500,
                                "min": 500,
                                "max": 1000,
                                "avg": 750,
                            }
                        }
                    },
                },
            },
            {
                "ns_stats": {"foo": {}},
                "license_data": {
                    "license_usage": {
                        "count": 2,
                        "entries": [
                            {
                                "time": "2022-04-07T22:58:47",
                                "unique_data_bytes": 500,
                                "level": "info",
                                "cluster_stable": True,
                                "namespaces": {"foo": {"unique_data_bytes": 1000}},
                            },
                            {
                                "time": "2022-04-07T22:59:47",
                                "unique_data_bytes": 100,
                                "level": "info",
                                "cluster_stable": False,
                                "namespaces": {"foo": {"unique_data_bytes": 500}},
                            },
                            {"unique_data_bytes": 0, "level": "error"},
                        ],
                    }
                },
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {
                            "latest_time": datetime.fromisoformat(
                                "2022-04-07T22:58:47"
                            ),
                            "latest": 500,
                            "min": 500,
                            "max": 500,
                            "avg": 500,
                        }
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {
                                "latest_time": datetime.fromisoformat(
                                    "2022-04-07T22:58:47"
                                ),
                                "latest": 1000,
                                "min": 1000,
                                "max": 1000,
                                "avg": 1000,
                            }
                        }
                    },
                },
            },
        ]

        for tc in test_cases:
            self.run_test_case(
                tc["ns_stats"],
                {"1.1.1.1": "5.0.0.0"},
                tc["license_data"],
                tc["allow_unstable"],
                tc["exp_summary_dict"],
            )


class CreateStopWritesSummaryTests(asynctest.TestCase):
    maxDiff = None

    @staticmethod
    def create_tc(
        service_stats=None,
        ns_stats=None,
        ns_config=None,
        set_stats=None,
        set_config=None,
        expected=None,
    ):
        return (
            service_stats if service_stats else {},
            ns_stats if ns_stats else {},
            ns_config if ns_config else {},
            set_stats if set_stats else {},
            set_config if set_config else {},
            expected if expected else {},
        )

    @parameterized.expand(
        [
            create_tc(),
            create_tc(
                service_stats={
                    "1.1.1.1": {
                        "cluster_clock_skew_ms": "256",
                        "cluster_clock_skew_stop_writes_sec": "20",
                    },
                },
                ns_stats={
                    "1.1.1.1": {"ns1": {"clock_skew_stop_writes": "false"}},
                },
                ns_config={
                    "1.1.1.1": {
                        "ns1": {"strong-consistency": "false", "nsup-period": "0"}
                    },
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "cluster_clock_skew_ms"): {
                            "stop_writes": False,
                            "metric": "cluster_clock_skew_ms",
                            "metric_usage": 256,
                            "metric_threshold": 20000,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # cluster_clock_skew_ms does not trigger stop writes when clock_skew_stop_writes is false
            create_tc(
                service_stats={
                    "1.1.1.1": {
                        "cluster_clock_skew_ms": "200001",
                        "cluster_clock_skew_stop_writes_sec": "20",
                    },
                },
                ns_stats={
                    "1.1.1.1": {"ns1": {"clock_skew_stop_writes": "false"}},
                },
                ns_config={
                    "1.1.1.1": {
                        "ns1": {"strong-consistency": "false", "nsup-period": "0"}
                    },
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "cluster_clock_skew_ms"): {
                            "stop_writes": False,
                            "metric": "cluster_clock_skew_ms",
                            "metric_usage": 200001,
                            "metric_threshold": 20000,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # cluster_clock_skew_ms triggers stop writes when clock_skew_stop_writes is true
            create_tc(
                service_stats={
                    "1.1.1.1": {
                        "cluster_clock_skew_ms": "200001",  # <<
                        "cluster_clock_skew_stop_writes_sec": "20",
                    },
                },
                ns_stats={
                    "1.1.1.1": {"ns1": {"clock_skew_stop_writes": "true"}},  # <<
                },
                ns_config={
                    "1.1.1.1": {
                        "ns1": {"strong-consistency": "false", "nsup-period": "0"}
                    },
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "cluster_clock_skew_ms"): {
                            "stop_writes": True,
                            "metric": "cluster_clock_skew_ms",
                            "metric_usage": 200001,
                            "metric_threshold": 20000,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # nsup-period is not zero and strong consistency causes default metric_threshold
            create_tc(
                service_stats={
                    "1.1.1.1": {
                        "cluster_clock_skew_ms": "256",
                        "cluster_clock_skew_stop_writes_sec": "20",
                    },
                },
                ns_stats={
                    "1.1.1.1": {"ns1": {"clock_skew_stop_writes": "true"}},  # <<
                },
                ns_config={
                    "1.1.1.1": {
                        "ns1": {"strong-consistency": "false", "nsup-period": "999"}
                    },
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "cluster_clock_skew_ms"): {
                            "stop_writes": False,
                            "metric": "cluster_clock_skew_ms",
                            "metric_usage": 256,
                            "metric_threshold": 40000,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes not triggered by system_free_mem_pct
            create_tc(
                {
                    "1.1.1.1": {
                        "system_free_mem_pct": "90",
                    },
                },
                {
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "false",
                        }
                    },
                },
                {
                    "1.1.1.1": {"ns1": {"stop-writes-sys-memory-pct": "90"}},
                },
                {},
                {},
                {
                    "1.1.1.1": {
                        ("ns1", None, "system_free_mem_pct"): {
                            "metric": "system_free_mem_pct",
                            "config": "stop-writes-sys-memory-pct",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes triggered by system_free_mem_pct
            create_tc(
                service_stats={
                    "1.1.1.1": {
                        "system_free_mem_pct": "90",
                    },
                },
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "false",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"stop-writes-sys-memory-pct": "90"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "system_free_mem_pct"): {
                            "metric": "system_free_mem_pct",
                            "config": "stop-writes-sys-memory-pct",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes not triggered by device_available_pct
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "device_available_pct": "50",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.min-avail-pct": "55"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "device_available_pct"): {
                            "metric": "device_available_pct",
                            "config": "storage-engine.min-avail-pct",
                            "stop_writes": False,
                            "metric_usage": 50,
                            "metric_threshold": 55,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "device_available_pct": "56",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.min-avail-pct": "55"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "device_available_pct"): {
                            "metric": "device_available_pct",
                            "config": "storage-engine.min-avail-pct",
                            "stop_writes": True,
                            "metric_usage": 56,
                            "metric_threshold": 55,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "pmem_available_pct": "56",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.min-avail-pct": "55"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "pmem_available_pct"): {
                            "metric": "pmem_available_pct",
                            "config": "storage-engine.min-avail-pct",
                            "stop_writes": True,
                            "metric_usage": 56,
                            "metric_threshold": 55,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "data_avail_pct": "56",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.stop-writes-avail-pct": "55"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "data_avail_pct"): {
                            "metric": "data_avail_pct",
                            "config": "storage-engine.stop-writes-avail-pct",
                            "stop_writes": True,
                            "metric_usage": 56,
                            "metric_threshold": 55,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes not triggered by data_avail_pct
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "data_avail_pct": "56",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.stop-writes-avail-pct": "55"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "data_avail_pct"): {
                            "metric": "data_avail_pct",
                            "config": "storage-engine.stop-writes-avail-pct",
                            "stop_writes": True,
                            "metric_usage": 56,
                            "metric_threshold": 55,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes triggered by data_avail_pct
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "data_avail_pct": "56",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.min-avail-pct": "55"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "data_avail_pct"): {
                            "metric": "data_avail_pct",
                            "config": "storage-engine.min-avail-pct",
                            "stop_writes": True,
                            "metric_usage": 56,
                            "metric_threshold": 55,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes not triggered by device_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "device_used_bytes": "10",
                            "device_total_bytes": "100",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.max-used-pct": "90"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "device_used_bytes"): {
                            "metric": "device_used_bytes",
                            "config": "storage-engine.max-used-pct",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes is triggered by device_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "device_used_bytes": "90",
                            "device_total_bytes": "100",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.max-used-pct": "90"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "device_used_bytes"): {
                            "metric": "device_used_bytes",
                            "config": "storage-engine.max-used-pct",
                            "stop_writes": True,
                            "metric_usage": 90,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes not triggered by pmem_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "pmem_used_bytes": "10",
                            "pmem_total_bytes": "100",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.max-used-pct": "90"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "pmem_used_bytes"): {
                            "metric": "pmem_used_bytes",
                            "config": "storage-engine.max-used-pct",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes is triggered by pmem_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "pmem_used_bytes": "90",
                            "pmem_total_bytes": "100",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.max-used-pct": "90"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "pmem_used_bytes"): {
                            "metric": "pmem_used_bytes",
                            "config": "storage-engine.max-used-pct",
                            "stop_writes": True,
                            "metric_usage": 90,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes not triggered by data_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "data_used_bytes": "10",
                            "data_total_bytes": "100",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.stop-writes-used-pct": "90"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "data_used_bytes"): {
                            "metric": "data_used_bytes",
                            "config": "storage-engine.stop-writes-used-pct",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes is triggered by data_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "data_used_bytes": "90",
                            "data_total_bytes": "100",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.stop-writes-used-pct": "90"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "data_used_bytes"): {
                            "metric": "data_used_bytes",
                            "config": "storage-engine.stop-writes-used-pct",
                            "stop_writes": True,
                            "metric_usage": 90,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes is not triggered by memory_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "memory_used_bytes": "10",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"stop-writes-pct": "90", "memory-size": "100"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "memory_used_bytes"): {
                            "metric": "memory_used_bytes",
                            "config": "stop-writes-pct",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes is triggered by memory_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "memory_used_bytes": "90",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"stop-writes-pct": "90", "memory-size": "100"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "memory_used_bytes"): {
                            "metric": "memory_used_bytes",
                            "config": "stop-writes-pct",
                            "stop_writes": True,
                            "metric_usage": 90,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes is not triggered by set.memory_data_bytes
            create_tc(
                set_stats={
                    "1.1.1.1": {
                        ("ns1", "set1"): {
                            "memory_data_bytes": "10",
                            "device_data_bytes": "0",
                        }
                    }
                },
                set_config={"1.1.1.1": {("ns1", "set1"): {"stop-writes-size": "100"}}},
                expected={
                    "1.1.1.1": {
                        ("ns1", "set1", "memory_data_bytes"): {
                            "metric": "memory_data_bytes",
                            "config": "stop-writes-size",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 100,
                            "namespace": "ns1",
                            "set": "set1",
                        },
                    }
                },
            ),
            # stop_writes is triggered by set.memory_data_bytes
            create_tc(
                set_stats={
                    "1.1.1.1": {
                        ("ns1", "set1"): {
                            "memory_data_bytes": "100",
                        }
                    }
                },
                set_config={"1.1.1.1": {("ns1", "set1"): {"stop-writes-size": "100"}}},
                expected={
                    "1.1.1.1": {
                        ("ns1", "set1", "memory_data_bytes"): {
                            "metric": "memory_data_bytes",
                            "config": "stop-writes-size",
                            "stop_writes": True,
                            "metric_usage": 100,
                            "metric_threshold": 100,
                            "namespace": "ns1",
                            "set": "set1",
                        },
                    }
                },
            ),
            # stop_writes is not triggered by set.device_data_bytes
            create_tc(
                set_stats={
                    "1.1.1.1": {
                        ("ns1", "set1"): {
                            "memory_data_bytes": "0",
                            "device_data_bytes": "10",
                        }
                    }
                },
                set_config={"1.1.1.1": {("ns1", "set1"): {"stop-writes-size": "100"}}},
                expected={
                    "1.1.1.1": {
                        ("ns1", "set1", "device_data_bytes"): {
                            "metric": "device_data_bytes",
                            "config": "stop-writes-size",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 100,
                            "namespace": "ns1",
                            "set": "set1",
                        },
                    }
                },
            ),
            # stop_writes is triggered by set.device_data_bytes
            create_tc(
                set_stats={
                    "1.1.1.1": {
                        ("ns1", "set1"): {
                            "device_data_bytes": "100",
                        }
                    }
                },
                set_config={"1.1.1.1": {("ns1", "set1"): {"stop-writes-size": "100"}}},
                expected={
                    "1.1.1.1": {
                        ("ns1", "set1", "device_data_bytes"): {
                            "metric": "device_data_bytes",
                            "config": "stop-writes-size",
                            "stop_writes": True,
                            "metric_usage": 100,
                            "metric_threshold": 100,
                            "namespace": "ns1",
                            "set": "set1",
                        },
                    }
                },
            ),
            # stop_writes is not triggered by set.objects
            create_tc(
                set_stats={
                    "1.1.1.1": {
                        ("ns1", "set1"): {
                            "objects": "10",
                        }
                    }
                },
                set_config={"1.1.1.1": {("ns1", "set1"): {"stop-writes-count": "100"}}},
                expected={
                    "1.1.1.1": {
                        ("ns1", "set1", "objects"): {
                            "metric": "objects",
                            "config": "stop-writes-count",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 100,
                            "namespace": "ns1",
                            "set": "set1",
                        },
                    }
                },
            ),
            # stop_writes is triggered by set.objects
            create_tc(
                set_stats={
                    "1.1.1.1": {
                        ("ns1", "set1"): {
                            "objects": "100",
                        }
                    }
                },
                set_config={"1.1.1.1": {("ns1", "set1"): {"stop-writes-count": "100"}}},
                expected={
                    "1.1.1.1": {
                        ("ns1", "set1", "objects"): {
                            "metric": "objects",
                            "config": "stop-writes-count",
                            "stop_writes": True,
                            "metric_usage": 100,
                            "metric_threshold": 100,
                            "namespace": "ns1",
                            "set": "set1",
                        },
                    }
                },
            ),
        ],
    )
    def test_summary_creation(
        self, service_stats, ns_stats, ns_config, set_stats, set_config, expected
    ):
        self.assertDictEqual(
            common.create_stop_writes_summary(
                service_stats, ns_stats, ns_config, set_stats, set_config
            ),
            expected,
        )

    @parameterized.expand(
        [
            ({"1.1.1.1": {}, "2.2.2.2": {}}, False),
            (
                {
                    "1.1.1.1": {("test", "testset", "a"): {"stop_writes": False}},
                    "2.2.2.2": {("test", "testset", "a"): {"stop_writes": False}},
                },
                False,
            ),
            (
                {
                    "1.1.1.1": {
                        ("test", "testset", "a"): {"stop_writes": False},
                        ("bar", "testset", "a"): {"stop_writes": False},
                    },
                    "2.2.2.2": {
                        ("test", "testset", "a"): {"stop_writes": False},
                        ("bar", "testset", "a"): {"stop_writes": True},
                    },
                },
                True,
            ),
        ]
    )
    def test_active_stop_writes(self, stop_writes_dict, expected):
        self.assertEqual(
            common.active_stop_writes(stop_writes_dict),
            expected,
        )
