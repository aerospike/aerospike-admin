# Copyright 2021-2025 Aerospike, Inc.
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
from mock import patch

from lib.utils import common, util


class ComputeLicenseDataSizeTest(asynctest.TestCase):
    maxDiff = None

    def run_test_case(
        self,
        namespace_stats,
        server_builds,
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
            server_builds=server_builds,
            summary_dict=summary_dict,
        )

        self.assertDictEqual(
            expected_summary_dict, summary_dict, "Input: " + str(namespace_stats)
        )

    @parameterized.expand(
        [
            (
                {
                    "ns_stats": {},
                    "server_builds": {},
                    "exp_summary_dict": {},
                },
            ),
            (
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
                    "server_builds": {"1.1.1.1": "5.0.0.0"},
                    "exp_summary_dict": {
                        "CLUSTER": {"license_data": {"latest": 46000}},
                        "NAMESPACES": {"foo": {"license_data": {"latest": 46000}}},
                    },
                },
            ),
            (
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
                    "exp_summary_dict": {
                        "CLUSTER": {
                            "license_data": {"latest": int((99000 / 2) - (35 * 100))}
                        },
                        "NAMESPACES": {
                            "foo": {
                                "license_data": {
                                    "latest": int((99000 / 2) - (35 * 100))
                                }
                            }
                        },
                    },
                },
            ),
            (
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
                    "exp_summary_dict": {
                        "CLUSTER": {
                            "license_data": {
                                "latest": int(
                                    ((99000 / 2) - (35 * 100))
                                    + ((99000 / 2) - (39 * 100))
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
            ),
            (
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
                    "exp_summary_dict": {
                        "CLUSTER": {"license_data": {"latest": 100}},
                        "NAMESPACES": {"foo": {"license_data": {"latest": 100}}},
                    },
                },
            ),
            (
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
                    "server_builds": {"1.1.1.1": "5.0.0.0"},
                    "exp_summary_dict": {
                        "CLUSTER": {"license_data": {"latest": 500 + 250}},
                        "NAMESPACES": {
                            "foo": {"license_data": {"latest": 500}},
                            "bar": {"license_data": {"latest": 250}},
                        },
                    },
                },
            ),
            (
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
                    "server_builds": {"1.1.1.1": "5.0.0.0", "2.2.2.2": "5.0.0.0"},
                    "exp_summary_dict": {
                        "CLUSTER": {
                            "license_data": {
                                "latest": int(
                                    ((7200 + 3200) / 2)  # foo
                                    - (110 * 35)
                                    + ((50000 + 10000) / 3)  # bar
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
            ),
            (
                {
                    "ns_stats": {
                        "foo": {
                            "1.1.1.1": {
                                "master_objects": 100,
                                "effective_replication_factor": 2,
                                "data_used_bytes": 7200,
                                "data_compression_ratio": 0.5,
                            },
                            "2.2.2.2": {
                                "master_objects": 10,
                                "effective_replication_factor": 2,
                                "data_used_bytes": 3200,
                                "data_compression_ratio": 0.2,
                            },
                        },
                        "bar": {
                            "1.1.1.1": {
                                "master_objects": 50,
                                "effective_replication_factor": 3,
                                "data_used_bytes": 50000,
                            },
                            "2.2.2.2": {
                                "master_objects": 10,
                                "effective_replication_factor": 3,
                                "data_used_bytes": 10000,
                            },
                        },
                    },
                    "server_builds": {"1.1.1.1": "5.0.0.0", "2.2.2.2": "5.0.0.0"},
                    "exp_summary_dict": {
                        "CLUSTER": {
                            "license_data": {
                                "latest": int(
                                    ((7200 / 0.5 + 3200 / 0.2) / 2)  # foo
                                    - (110 * 35)
                                    + ((50000 + 10000) / 3)  # bar
                                    - (35 * 60)
                                )
                            },
                        },
                        "NAMESPACES": {
                            "foo": {
                                "license_data": {
                                    "latest": int(
                                        ((7200 / 0.5 + 3200 / 0.2) / 2) - (110 * 35)
                                    )
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
            ),
        ]
    )
    def test_success_with_out_agent(self, tc):
        self.run_test_case(
            tc["ns_stats"],
            tc["server_builds"],
            tc["exp_summary_dict"],
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
                            "stop_writes": True,
                            "metric_usage": 50,
                            "metric_threshold": 55,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes triggered by device_available_pct
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
                            "stop_writes": False,
                            "metric_usage": 56,
                            "metric_threshold": 55,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes not triggered by pmem_available_pct
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
                            "stop_writes": False,
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
                            "data_avail_pct": "55",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"storage-engine.stop-writes-avail-pct": "56"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "data_avail_pct"): {
                            "metric": "data_avail_pct",
                            "config": "storage-engine.stop-writes-avail-pct",
                            "stop_writes": True,
                            "metric_usage": 55,
                            "metric_threshold": 56,
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
                    "1.1.1.1": {"ns1": {"storage-engine.min-avail-pct": "55"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "data_avail_pct"): {
                            "metric": "data_avail_pct",
                            "config": "storage-engine.min-avail-pct",
                            "stop_writes": False,
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
            # stop_writes is not triggered by data_used_bytes
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
            # stop_writes is not triggered by index_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "index_used_bytes": "10",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {"ns1": {"indexes-memory-budget": "90"}},
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "index_used_bytes"): {
                            "metric": "index_used_bytes",
                            "config": "indexes-memory-budget",
                            "stop_writes": False,
                            "metric_usage": 10,
                            "metric_threshold": 90,
                            "namespace": "ns1",
                        },
                    }
                },
            ),
            # stop_writes is triggered by index_used_bytes
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "ns1": {
                            "stop_writes": "true",
                            "index_used_bytes": "90",
                        }
                    },
                },
                ns_config={
                    "1.1.1.1": {
                        "ns1": {
                            "indexes-memory-budget": "90",
                        }
                    },
                },
                expected={
                    "1.1.1.1": {
                        ("ns1", None, "index_used_bytes"): {
                            "metric": "index_used_bytes",
                            "config": "indexes-memory-budget",
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
                            "device_data_bytes": "100000",
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
                            "device_data_bytes": "100000",
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
            # stop_writes is not triggered by set.data_used_bytes
            create_tc(
                set_stats={
                    "1.1.1.1": {
                        ("ns1", "set1"): {
                            "data_used_bytes": "10",
                            "device_data_bytes": "0",
                        }
                    }
                },
                set_config={"1.1.1.1": {("ns1", "set1"): {"stop-writes-size": "100"}}},
                expected={
                    "1.1.1.1": {
                        ("ns1", "set1", "data_used_bytes"): {
                            "metric": "data_used_bytes",
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
            # stop_writes is triggered by set.data_used_bytes
            create_tc(
                set_stats={
                    "1.1.1.1": {
                        ("ns1", "set1"): {
                            "data_used_bytes": "100",
                        }
                    }
                },
                set_config={"1.1.1.1": {("ns1", "set1"): {"stop-writes-size": "100"}}},
                expected={
                    "1.1.1.1": {
                        ("ns1", "set1", "data_used_bytes"): {
                            "metric": "data_used_bytes",
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
    def test_stop_writes_summary_creation(
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


class CreateSummaryTests(unittest.TestCase):
    maxDiff = None

    @staticmethod
    def create_tc(
        service_stats={},
        ns_stats={},
        xdr_dc_stats={},
        metadata={},
        service_configs={},
        ns_configs={},
        security_configs={},
        expected={},
    ):
        namespaces = list(expected.get("NAMESPACES", {}).keys())
        hosts = ns_stats.keys()
        builds = metadata.setdefault("server_build", {})

        for host in hosts:
            builds.setdefault(host, "7.0.0")
            service_stats.setdefault(host, {})
            for ns in namespaces:
                ns_stats.setdefault(host, {}).setdefault(ns, {})
                ns_configs.setdefault(host, {}).setdefault(ns, {})

        init_expected = common._initialize_summary_output(namespaces)
        expected = util.deep_merge_dicts(init_expected, expected)

        return (
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
            init_expected,
        )

    @parameterized.expand(
        [
            # Test Devices Counts
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "storage-engine.device[0]": 0,
                            "replication-factor": 1,
                        },
                        "bar": {
                            "storage-engine.device": 0,
                            "storage-engine.file[0]": 0,
                            "storage-engine.file": 0,
                            "replication-factor": 2,
                        },
                    },
                    "2.2.2.2": {
                        "test": {
                            "storage-engine.device[0]": 0,
                            "replication-factor": 1,
                        },
                        "bar": {
                            "storage-engine.device": 0,
                            "storage-engine.file[0]": 0,
                            "storage-engine.file": 0,
                            "replication-factor": 2,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "device_count": 8,
                        "device_count_per_node": 4,
                        "ns_count": 2,
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "devices_total": 2,
                            "devices_per_node": 1,
                            "repl_factor": [1],
                            "compression_enabled": False,
                        },
                        "bar": {
                            "devices_total": 6,
                            "devices_per_node": 3,
                            "repl_factor": [2],
                            "compression_enabled": False,
                        },
                    },
                },
            ),
            # Test Pre 7.0 Memory Usage. Shmem is not displayed in this case by choice
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "memory_used_bytes": 1024,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "memory_used_bytes": 1024,
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "storage-engine": "memory",
                            "memory-size": 2048,
                            "index-type": "shmem",
                            "replication-factor": 1,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "storage-engine": "memory",
                            "memory-size": 2048,
                            "index-type": "shmem",
                            "replication-factor": 1,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Index-on-shmem"],
                        "ns_count": 2,
                        "license_data": {
                            "latest": 0
                        },  # memory_data_used_bytes and memory_index_used_bytes are used for license calculation
                        "memory_data_and_indexes": {
                            "total": 4096,
                            "used": 2048,
                            "used_pct": 50.0,
                            "avail": 2048,
                            "avail_pct": 50.0,
                        },
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "memory_data_and_indexes": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 0},
                            "compression_enabled": False,
                        },
                        "bar": {
                            "memory_data_and_indexes": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 0},
                            "compression_enabled": False,
                        },
                    },
                },
            ),
            # Test Pre 7.0 Pmem/Pmem-index usage
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "memory_used_bytes": 1024,
                            "index_pmem_used_bytes": 512,
                            "pmem_used_bytes": 1024,
                            "pmem_total_bytes": 2048,
                            "pmem_available_pct": 50,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "memory_used_bytes": 1024,
                            "index_pmem_used_bytes": 512,
                            "pmem_used_bytes": 1024,
                            "pmem_total_bytes": 2048,
                            "pmem_available_pct": 50,
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "memory-size": 2048,
                            "storage-engine": "pmem",
                            "index-type": "pmem",
                            "index-type.mounts-size-limit": 1024,
                            "replication-factor": 1,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "memory-size": 2048,
                            "storage-engine": "pmem",
                            "index-type": "pmem",
                            "index-type.mounts-size-limit": 1024,
                            "replication-factor": 1,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Index-on-pmem"],
                        "ns_count": 2,
                        "license_data": {"latest": 2048},
                        "memory_data_and_indexes": {
                            "total": 4096,
                            "used": 2048,
                            "used_pct": 50.0,
                            "avail": 2048,
                            "avail_pct": 50.0,
                        },
                        "pmem_index": {
                            "total": 2048,
                            "used": 1024,
                            "used_pct": 50.0,
                            "avail": 1024,
                            "avail_pct": 50.0,
                        },
                        "pmem": {
                            "total": 4096,
                            "used": 2048,
                            "used_pct": 50.0,
                            "avail": 2048.0,
                            "avail_pct": 50.0,
                        },
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "index_type": "pmem",
                            "memory_data_and_indexes": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024,
                                "avail_pct": 50.0,
                            },
                            "pmem_index": {
                                "total": 1024,
                                "used": 512,
                                "used_pct": 50.0,
                                "avail": 512,
                                "avail_pct": 50.0,
                            },
                            "pmem": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                        "bar": {
                            "index_type": "pmem",
                            "memory_data_and_indexes": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024,
                                "avail_pct": 50.0,
                            },
                            "pmem_index": {
                                "total": 1024,
                                "used": 512,
                                "used_pct": 50.0,
                                "avail": 512,
                                "avail_pct": 50.0,
                            },
                            "pmem": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                    },
                },
            ),
            # Test Pre 7.0 Device/Flash-index Usage
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "index_flash_used_bytes": 512,
                            "device_used_bytes": 1024,
                            "device_total_bytes": 2048,
                            "device_available_pct": 50,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "index_flash_used_bytes": 512,
                            "device_used_bytes": 1024,
                            "device_total_bytes": 2048,
                            "device_available_pct": 50,
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "storage-engine": "device",
                            "index-type": "flash",
                            "index-type.mounts-size-limit": 1024,
                            "replication-factor": 1,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "storage-engine": "device",
                            "index-type": "flash",
                            "index-type.mounts-size-limit": 1024,
                            "replication-factor": 1,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Index-on-flash"],
                        "ns_count": 2,
                        "license_data": {"latest": 2048},
                        "compression_enabled": False,
                        "flash_index": {
                            "total": 2048,
                            "used": 1024,
                            "used_pct": 50.0,
                            "avail": 1024,
                            "avail_pct": 50.0,
                        },
                        "device": {
                            "total": 4096,
                            "used": 2048,
                            "used_pct": 50.0,
                            "avail": 2048.0,
                            "avail_pct": 50.0,
                        },
                    },
                    "NAMESPACES": {
                        "test": {
                            "index_type": "flash",
                            "flash_index": {
                                "total": 1024,
                                "used": 512,
                                "used_pct": 50.0,
                                "avail": 512,
                                "avail_pct": 50.0,
                            },
                            "device": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                        "bar": {
                            "index_type": "flash",
                            "flash_index": {
                                "total": 1024,
                                "used": 512,
                                "used_pct": 50.0,
                                "avail": 512,
                                "avail_pct": 50.0,
                            },
                            "device": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                    },
                },
            ),
            # Test New 7.0 Memory/Shmem-index usage
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "index_used_bytes": 512,
                            "data_used_bytes": 1024,
                            "data_total_bytes": 2048,
                            "data_avail_pct": 50,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "index_used_bytes": 512,
                            "data_used_bytes": 1024,
                            "data_total_bytes": 2048,
                            "data_avail_pct": 50,
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "storage-engine": "memory",
                            "index-type": "shmem",  # shmem index has no mounts-budget
                            "replication-factor": 1,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "storage-engine": "memory",
                            "index-type": "shmem",  # shmem index has no mounts-budget
                            "replication-factor": 1,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Index-on-shmem"],
                        "ns_count": 2,
                        "license_data": {"latest": 2048},
                        "shmem_index": {
                            "used": 1024,
                        },
                        "memory": {
                            "total": 4096,
                            "used": 2048,
                            "used_pct": 50.0,
                            "avail": 2048.0,
                            "avail_pct": 50.0,
                        },
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "index_type": "shmem",
                            "shmem_index": {
                                "used": 512,
                            },
                            "memory": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                        "bar": {
                            "index_type": "shmem",
                            "shmem_index": {
                                "used": 512,
                            },
                            "memory": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                    },
                },
            ),
            # Test New 7.0 Device/Flash-index usage
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "index_used_bytes": 512,
                            "data_used_bytes": 1024,
                            "data_total_bytes": 2048,
                            "data_avail_pct": 50,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "index_used_bytes": 512,
                            "data_used_bytes": 1024,
                            "data_total_bytes": 2048,
                            "data_avail_pct": 50,
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "storage-engine": "device",
                            "index-type": "flash",
                            "index-type.mounts-budget": "1024",
                            "replication-factor": 1,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "storage-engine": "device",
                            "index-type": "flash",
                            "index-type.mounts-budget": "1024",
                            "replication-factor": 1,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Index-on-flash"],
                        "ns_count": 2,
                        "license_data": {"latest": 2048},
                        "flash_index": {
                            "total": 2048,
                            "used": 1024,
                            "used_pct": 50.0,
                            "avail": 1024,
                            "avail_pct": 50.0,
                        },
                        "device": {
                            "total": 4096,
                            "used": 2048,
                            "used_pct": 50.0,
                            "avail": 2048.0,
                            "avail_pct": 50.0,
                        },
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "index_type": "flash",
                            "flash_index": {
                                "total": 1024,
                                "used": 512,
                                "used_pct": 50.0,
                                "avail": 512,
                                "avail_pct": 50.0,
                            },
                            "device": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                        "bar": {
                            "index_type": "flash",
                            "flash_index": {
                                "total": 1024,
                                "used": 512,
                                "used_pct": 50.0,
                                "avail": 512,
                                "avail_pct": 50.0,
                            },
                            "device": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                    },
                },
            ),
            # Test New 7.0 Pmem/Pmem-index usage
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "index_used_bytes": 512,
                            "data_used_bytes": 1024,
                            "data_total_bytes": 2048,
                            "data_avail_pct": 50,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "index_used_bytes": 512,
                            "data_used_bytes": 1024,
                            "data_total_bytes": 2048,
                            "data_avail_pct": 50,
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "storage-engine": "pmem",
                            "index-type": "pmem",
                            "index-type.mounts-budget": "1024",
                            "replication-factor": 1,
                        },
                    },
                    "2.2.2.2": {
                        "bar": {
                            "storage-engine": "pmem",
                            "index-type": "pmem",
                            "index-type.mounts-budget": "1024",
                            "replication-factor": 1,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Index-on-pmem"],
                        "ns_count": 2,
                        "license_data": {"latest": 2048},
                        "pmem_index": {
                            "total": 2048,
                            "used": 1024,
                            "used_pct": 50.0,
                            "avail": 1024,
                            "avail_pct": 50.0,
                        },
                        "pmem": {
                            "total": 4096,
                            "used": 2048,
                            "used_pct": 50.0,
                            "avail": 2048.0,
                            "avail_pct": 50.0,
                        },
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "index_type": "pmem",
                            "pmem_index": {
                                "total": 1024,
                                "used": 512,
                                "used_pct": 50.0,
                                "avail": 512,
                                "avail_pct": 50.0,
                            },
                            "pmem": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                        "bar": {
                            "index_type": "pmem",
                            "pmem_index": {
                                "total": 1024,
                                "used": 512,
                                "used_pct": 50.0,
                                "avail": 512,
                                "avail_pct": 50.0,
                            },
                            "pmem": {
                                "total": 2048,
                                "used": 1024,
                                "used_pct": 50.0,
                                "avail": 1024.0,
                                "avail_pct": 50.0,
                            },
                            "repl_factor": [1],
                            "license_data": {"latest": 1024},
                            "compression_enabled": False,
                        },
                    },
                },
            ),
            # Test Compression Ratio usage
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "data_compression_ratio": "0.73",  # Post 7.0
                        },
                        "bar": {
                            "device_compression_ratio": "0.74",  # Pre 7.0
                        },
                        "foo": {
                            "pmem_compression_ratio": "0.75",  # Pre 7.0
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "replication-factor": 1,
                        },
                        "bar": {
                            "replication-factor": 1,
                        },
                        "foo": {
                            "replication-factor": 1,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Compression"],
                        "ns_count": 3,
                        "license_data": {"latest": 0},
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "compression_ratio": 0.73,
                            "repl_factor": [1],
                            "license_data": {"latest": 0},
                            "compression_enabled": False,
                        },
                        "bar": {
                            "compression_ratio": 0.74,
                            "repl_factor": [1],
                            "license_data": {"latest": 0},
                            "compression_enabled": False,
                        },
                        "foo": {
                            "compression_ratio": 0.75,
                            "repl_factor": [1],
                            "license_data": {"latest": 0},
                            "compression_enabled": False,
                        },
                    },
                },
            ),
            # Test License Usage Pre-8.0 and Post-8.0
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "pmem_used_bytes": 40000,
                            "memory_used_bytes": 500,
                            "index_used_bytes": 200,
                            "master_objects": 200,
                            "effective_replication_factor": 2,
                        },
                        "bar": {
                            "data_used_bytes": 1000,
                            "data_compression_ratio": 0.5,
                            "master_objects": 200,
                            "effective_replication_factor": 2,
                        },
                    },
                    "2.2.2.2": {
                        "test": {
                            "pmem_used_bytes": 40000,
                            "memory_used_bytes": 500,
                            "index_used_bytes": 200,
                            "master_objects": 200,
                            "effective_replication_factor": 2,
                        },
                        "bar": {
                            "data_used_bytes": 1000,
                            "data_compression_ratio": 0.5,
                            "master_objects": 200,
                            "effective_replication_factor": 2,
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "storage-engine": "pmem",
                            "replication-factor": 2,
                        },
                        "bar": {
                            "storage-engine": "device",
                            "replication-factor": 2,
                        },
                    },
                    "2.2.2.2": {
                        "test": {
                            "storage-engine": "pmem",
                            "replication-factor": 2,
                        },
                        "bar": {
                            "storage-engine": "device",
                            "replication-factor": 2,
                        },
                    },
                },
                metadata={
                    "server_build": {
                        "1.1.1.1": "7.0.0",
                        "2.2.2.2": "8.0.0",
                    }
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Compression"],
                        "active_ns": 2,
                        "cluster_name": [],
                        "cluster_size": [],
                        "device_count": 0,
                        "device_count_per_node": 0,
                        "device_count_same_across_nodes": True,
                        # Total license usage = 32200 (32200 from test + 0 from bar)
                        "license_data": {"latest": 32200},
                        "migrations_in_progress": False,
                        "ns_count": 2,
                        "os_version": [],
                        "server_version": [],
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "device_count_same_across_nodes": True,
                            "devices_per_node": 0,
                            "devices_total": 0,
                            # Mixed version license calculation (per-host):
                            # Actual calculated value from current implementation
                            "license_data": {"latest": 32200},
                            "master_objects": 400,  # Summed across nodes (200 * 2)
                            "migrations_in_progress": False,
                            "rack_aware": False,
                            "repl_factor": [2],
                            "compression_enabled": False,
                        },
                        "bar": {
                            "compression_ratio": 0.5,
                            "device_count_same_across_nodes": True,
                            "devices_per_node": 0,
                            "devices_total": 0,
                            # Mixed version license calculation (per-host):
                            # Negative values are clamped to 0
                            "license_data": {"latest": 0},
                            "master_objects": 400,  # Summed across nodes (200 * 2)
                            "migrations_in_progress": False,
                            "rack_aware": False,
                            "repl_factor": [2],
                            "compression_enabled": False,
                        },
                    },
                },
            ),
        ]
    )
    def test_create_summary_namespace_usage_stats(
        self,
        service_stats,
        ns_stats,
        xdr_dc_stats,
        metadata,
        service_configs,
        ns_configs,
        security_configs,
        expected,
    ):
        actual = common.create_summary(
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
        )

        self.assertDictEqual(actual, expected)

    @parameterized.expand(
        [
            # Test Compression Ratio usage
            create_tc(
                ns_stats={
                    "1.1.1.1": {
                        "test": {
                            "data_compression_ratio": "0.73",  # Post 7.0
                        },
                        "bar": {
                            "device_compression_ratio": "0.74",  # Pre 7.0
                        },
                        "foo": {
                            "pmem_compression_ratio": "0.75",  # Pre 7.0
                        },
                    },
                },
                ns_configs={
                    "1.1.1.1": {
                        "test": {
                            "replication-factor": 1,
                        },
                        "bar": {
                            "replication-factor": 1,
                        },
                        "foo": {
                            "replication-factor": 1,
                        },
                    },
                },
                expected={
                    "CLUSTER": {
                        "active_features": ["Compression"],
                        "ns_count": 3,
                        "license_data": {"latest": 0},
                        "compression_enabled": False,
                    },
                    "NAMESPACES": {
                        "test": {
                            "compression_ratio": 0.73,
                            "repl_factor": [1],
                            "license_data": {"latest": 0},
                            "compression_enabled": False,
                        },
                        "bar": {
                            "compression_ratio": 0.74,
                            "repl_factor": [1],
                            "license_data": {"latest": 0},
                            "compression_enabled": False,
                        },
                        "foo": {
                            "compression_ratio": 0.75,
                            "repl_factor": [1],
                            "license_data": {"latest": 0},
                            "compression_enabled": False,
                        },
                    },
                },
            ),
        ]
    )
    def test_create_summary_compression_ratio(
        self,
        service_stats,
        ns_stats,
        xdr_dc_stats,
        metadata,
        service_configs,
        ns_configs,
        security_configs,
        expected,
    ):
        actual = common.create_summary(
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
        )

        self.assertDictEqual(actual, expected)

    def test_create_summary_compression_enabled(self):
        """Test compression detection when feature-key has asdb-compression=true"""
        feature_keys = {
            "127.0.0.1:3000": {"asdb-compression": "true", "asdb-xdr": "true"}
        }

        service_stats = {"127.0.0.1:3000": {}}
        ns_stats = {
            "127.0.0.1:3000": {
                "test": {
                    "memory_used_bytes": "1000000",
                    "device_used_bytes": "2000000",
                    "replication-factor": "1",
                    "master_objects": "100",
                }
            }
        }
        xdr_dc_stats = {"127.0.0.1:3000": {}}
        metadata = {"server_build": {"127.0.0.1:3000": "7.0.0"}}
        service_configs = {"127.0.0.1:3000": {}}
        ns_configs = {"127.0.0.1:3000": {"test": {}}}
        security_configs = {"127.0.0.1:3000": {}}

        actual = common.create_summary(
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
            feature_keys=feature_keys,
        )

        # Check compression enabled flags
        self.assertTrue(actual["CLUSTER"]["compression_enabled"])
        self.assertTrue(actual["NAMESPACES"]["test"]["compression_enabled"])

    def test_create_summary_compression_disabled(self):
        """Test compression detection when feature-key has asdb-compression=false"""
        feature_keys = {
            "127.0.0.1:3000": {"asdb-compression": "false", "asdb-xdr": "true"}
        }

        service_stats = {"127.0.0.1:3000": {}}
        ns_stats = {
            "127.0.0.1:3000": {
                "test": {
                    "memory_used_bytes": "1000000",
                    "device_used_bytes": "2000000",
                    "replication-factor": "1",
                    "master_objects": "100",
                }
            }
        }
        xdr_dc_stats = {"127.0.0.1:3000": {}}
        metadata = {"server_build": {"127.0.0.1:3000": "7.0.0"}}
        service_configs = {"127.0.0.1:3000": {}}
        ns_configs = {"127.0.0.1:3000": {"test": {}}}
        security_configs = {"127.0.0.1:3000": {}}

        actual = common.create_summary(
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
            feature_keys=feature_keys,
        )

        # Check compression disabled flags
        self.assertFalse(actual["CLUSTER"]["compression_enabled"])
        self.assertFalse(actual["NAMESPACES"]["test"]["compression_enabled"])

    def test_create_summary_no_feature_keys(self):
        """Test backward compatibility when no feature_keys provided"""
        service_stats = {"127.0.0.1:3000": {}}
        ns_stats = {
            "127.0.0.1:3000": {
                "test": {
                    "memory_used_bytes": "1000000",
                    "device_used_bytes": "2000000",
                    "replication-factor": "1",
                    "master_objects": "100",
                }
            }
        }
        xdr_dc_stats = {"127.0.0.1:3000": {}}
        metadata = {"server_build": {"127.0.0.1:3000": "7.0.0"}}
        service_configs = {"127.0.0.1:3000": {}}
        ns_configs = {"127.0.0.1:3000": {"test": {}}}
        security_configs = {"127.0.0.1:3000": {}}

        actual = common.create_summary(
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
        )

        # Check compression defaults to disabled
        self.assertFalse(actual["CLUSTER"]["compression_enabled"])
        self.assertFalse(actual["NAMESPACES"]["test"]["compression_enabled"])

    def test_create_summary_mixed_compression_settings(self):
        """Test compression detection with multiple nodes having mixed compression settings"""
        # One node with compression enabled, one without
        feature_keys = {
            "127.0.0.1:3000": {"asdb-compression": "true", "asdb-xdr": "true"},
            "127.0.0.2:3000": {"asdb-compression": "false", "asdb-xdr": "true"},
        }

        service_stats = {
            "127.0.0.1:3000": {},
            "127.0.0.2:3000": {},
        }
        ns_stats = {
            "127.0.0.1:3000": {
                "test": {
                    "memory_used_bytes": "1000000",
                    "device_used_bytes": "2000000",
                    "replication-factor": "1",
                    "master_objects": "100",
                }
            },
            "127.0.0.2:3000": {
                "test": {
                    "memory_used_bytes": "1000000",
                    "device_used_bytes": "2000000",
                    "replication-factor": "1",
                    "master_objects": "100",
                }
            },
        }
        xdr_dc_stats = {"127.0.0.1:3000": {}, "127.0.0.2:3000": {}}
        metadata = {
            "server_build": {"127.0.0.1:3000": "7.0.0", "127.0.0.2:3000": "7.0.0"}
        }
        service_configs = {"127.0.0.1:3000": {}, "127.0.0.2:3000": {}}
        ns_configs = {"127.0.0.1:3000": {"test": {}}, "127.0.0.2:3000": {"test": {}}}
        security_configs = {"127.0.0.1:3000": {}, "127.0.0.2:3000": {}}

        actual = common.create_summary(
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
            feature_keys=feature_keys,
        )

        # If ANY node has compression enabled, the cluster should be marked as compressed
        self.assertTrue(actual["CLUSTER"]["compression_enabled"])
        self.assertTrue(actual["NAMESPACES"]["test"]["compression_enabled"])

    def test_create_summary_feature_keys_with_exception(self):
        """Test compression detection when feature_keys contains exceptions"""
        feature_keys = {
            "127.0.0.1:3000": {"asdb-compression": "true"},
            "127.0.0.2:3000": Exception("Connection error"),
        }

        service_stats = {
            "127.0.0.1:3000": {},
            "127.0.0.2:3000": {},
        }
        ns_stats = {
            "127.0.0.1:3000": {
                "test": {
                    "memory_used_bytes": "1000000",
                    "device_used_bytes": "2000000",
                    "replication-factor": "1",
                    "master_objects": "100",
                }
            },
            "127.0.0.2:3000": {
                "test": {
                    "memory_used_bytes": "1000000",
                    "device_used_bytes": "2000000",
                    "replication-factor": "1",
                    "master_objects": "100",
                }
            },
        }
        xdr_dc_stats = {"127.0.0.1:3000": {}, "127.0.0.2:3000": {}}
        metadata = {
            "server_build": {"127.0.0.1:3000": "7.0.0", "127.0.0.2:3000": "7.0.0"}
        }
        service_configs = {"127.0.0.1:3000": {}, "127.0.0.2:3000": {}}
        ns_configs = {"127.0.0.1:3000": {"test": {}}, "127.0.0.2:3000": {"test": {}}}
        security_configs = {"127.0.0.1:3000": {}, "127.0.0.2:3000": {}}

        actual = common.create_summary(
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
            feature_keys=feature_keys,
        )

        # Should still detect compression from the valid node
        self.assertTrue(actual["CLUSTER"]["compression_enabled"])
        self.assertTrue(actual["NAMESPACES"]["test"]["compression_enabled"])

    def test_create_summary_empty_feature_keys(self):
        """Test compression detection with empty feature_keys dict"""
        feature_keys = {}

        service_stats = {"127.0.0.1:3000": {}}
        ns_stats = {
            "127.0.0.1:3000": {
                "test": {
                    "memory_used_bytes": "1000000",
                    "device_used_bytes": "2000000",
                    "replication-factor": "1",
                    "master_objects": "100",
                }
            }
        }
        xdr_dc_stats = {"127.0.0.1:3000": {}}
        metadata = {"server_build": {"127.0.0.1:3000": "7.0.0"}}
        service_configs = {"127.0.0.1:3000": {}}
        ns_configs = {"127.0.0.1:3000": {"test": {}}}
        security_configs = {"127.0.0.1:3000": {}}

        actual = common.create_summary(
            service_stats,
            ns_stats,
            xdr_dc_stats,
            metadata,
            service_configs,
            ns_configs,
            security_configs,
            feature_keys=feature_keys,
        )

        # Should default to disabled with empty feature_keys
        self.assertFalse(actual["CLUSTER"]["compression_enabled"])
        self.assertFalse(actual["NAMESPACES"]["test"]["compression_enabled"])


class CollectInstalledPackagesTest(unittest.TestCase):
    """Test cases for _collect_installed_packages function"""

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_rpm_only_system(self, mock_shell_cmd, mock_which):
        """Test collection on RPM-based system (RHEL/CentOS/Fedora)"""
        # Setup: rpm exists, dpkg doesn't
        mock_which.side_effect = lambda cmd: "/usr/bin/rpm" if cmd == "rpm" else None
        mock_shell_cmd.return_value = ("package1-1.0\npackage2-2.0\npackage3-3.0", None)

        result, error = common._collect_installed_packages()

        # Verify shell_command was called with correct arguments
        mock_shell_cmd.assert_called_once_with(["rpm", "-qa"])
        # Verify output format
        self.assertIn("['rpm -qa']", result)
        self.assertIn("package1-1.0", result)
        self.assertIn("package2-2.0", result)
        self.assertIn("package3-3.0", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_dpkg_query_system(self, mock_shell_cmd, mock_which):
        """Test collection on Debian/Ubuntu with dpkg-query"""

        # Setup: dpkg-query exists, rpm doesn't
        def which_side_effect(cmd):
            if cmd == "dpkg-query":
                return "/usr/bin/dpkg-query"
            return None

        mock_which.side_effect = which_side_effect
        mock_shell_cmd.return_value = ("package1\t1.0\npackage2\t2.0", None)

        result, error = common._collect_installed_packages()

        # Verify
        mock_shell_cmd.assert_called_once_with(["dpkg-query", "-W"])
        self.assertIn("['dpkg-query -W']", result)
        self.assertIn("package1", result)
        self.assertIn("package2", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_dpkg_fallback(self, mock_shell_cmd, mock_which):
        """Test fallback to dpkg when dpkg-query not available"""

        # Setup: only dpkg exists
        def which_side_effect(cmd):
            if cmd == "dpkg":
                return "/usr/bin/dpkg"
            return None

        mock_which.side_effect = which_side_effect
        mock_shell_cmd.return_value = (
            "ii  package1  1.0  Description\nii  package2  2.0  Description",
            None,
        )

        result, error = common._collect_installed_packages()

        # Verify
        mock_shell_cmd.assert_called_once_with(["dpkg", "-l"])
        self.assertIn("['dpkg -l']", result)
        self.assertIn("package1", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_both_rpm_and_dpkg(self, mock_shell_cmd, mock_which):
        """Test system with both package managers (edge case)"""

        # Setup: both exist (unusual but possible)
        def which_side_effect(cmd):
            if cmd in ["rpm", "dpkg-query"]:
                return f"/usr/bin/{cmd}"
            return None

        mock_which.side_effect = which_side_effect
        mock_shell_cmd.side_effect = [
            ("rpm-package-1.0\nrpm-package-2.0", None),
            ("deb-package\t1.0\ndeb-package2\t2.0", None),
        ]

        result, error = common._collect_installed_packages()

        # Verify both commands called
        self.assertEqual(mock_shell_cmd.call_count, 2)
        self.assertIn("['rpm -qa']", result)
        self.assertIn("['dpkg-query -W']", result)
        self.assertIn("rpm-package", result)
        self.assertIn("deb-package", result)
        # Verify sections are separated
        self.assertIn("\n\n", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    def test_no_package_manager(self, mock_which):
        """Test system with no supported package manager"""
        mock_which.return_value = None

        result, error = common._collect_installed_packages()

        # Verify error message
        self.assertIn("['packages']", result)
        self.assertIn("No supported package manager", result)
        self.assertIn("rpm or dpkg", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_shell_command_with_error(self, mock_shell_cmd, mock_which):
        """Test handling of shell command errors"""
        mock_which.return_value = "/usr/bin/rpm"
        mock_shell_cmd.return_value = ("package1-1.0", "permission denied")

        result, error = common._collect_installed_packages()

        # Verify error is included in output
        self.assertIn("['rpm -qa']", result)
        self.assertIn("package1-1.0", result)
        self.assertIn("Error: permission denied", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_shell_command_error_only(self, mock_shell_cmd, mock_which):
        """Test handling when shell command returns only error, no output"""
        mock_which.return_value = "/usr/bin/rpm"
        mock_shell_cmd.return_value = ("", "command not found")

        result, error = common._collect_installed_packages()

        # Verify error is included even with no output
        self.assertIn("['rpm -qa']", result)
        self.assertIn("Error: command not found", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_empty_package_list(self, mock_shell_cmd, mock_which):
        """Test handling of empty package list (no packages installed)"""
        mock_which.return_value = "/usr/bin/rpm"
        mock_shell_cmd.return_value = ("", None)

        result, error = common._collect_installed_packages()

        # Should still have header but no packages
        self.assertIn("['rpm -qa']", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_whitespace_handling(self, mock_shell_cmd, mock_which):
        """Test that whitespace in output is properly stripped"""
        mock_which.return_value = "/usr/bin/rpm"
        mock_shell_cmd.return_value = (
            "  package1-1.0  \n  package2-2.0  \n\n",
            "  warning message  ",
        )

        result, error = common._collect_installed_packages()

        # Verify whitespace is stripped
        self.assertIn("['rpm -qa']", result)
        self.assertIn("package1-1.0", result)
        self.assertIn("Error: warning message", result)
        # Should not have excessive whitespace
        self.assertNotIn("  package1", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_dpkg_query_preferred_over_dpkg(self, mock_shell_cmd, mock_which):
        """Test that dpkg-query is preferred when both dpkg-query and dpkg exist"""

        # Setup: both dpkg-query and dpkg exist
        def which_side_effect(cmd):
            if cmd in ["dpkg-query", "dpkg"]:
                return f"/usr/bin/{cmd}"
            return None

        mock_which.side_effect = which_side_effect
        mock_shell_cmd.return_value = ("package1\t1.0", None)

        result, error = common._collect_installed_packages()

        # Verify dpkg-query was used, not dpkg -l
        mock_shell_cmd.assert_called_once_with(["dpkg-query", "-W"])
        self.assertIn("['dpkg-query -W']", result)
        self.assertNotIn("['dpkg -l']", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_multiple_errors_in_multi_manager_system(self, mock_shell_cmd, mock_which):
        """Test error handling when both package managers return errors"""

        # Setup: both exist
        def which_side_effect(cmd):
            if cmd in ["rpm", "dpkg-query"]:
                return f"/usr/bin/{cmd}"
            return None

        mock_which.side_effect = which_side_effect
        mock_shell_cmd.side_effect = [
            ("rpm-pkg-1.0", "rpm warning"),
            ("deb-pkg\t1.0", "dpkg warning"),
        ]

        result, error = common._collect_installed_packages()

        # Verify both outputs and errors are present
        self.assertIn("['rpm -qa']", result)
        self.assertIn("['dpkg-query -W']", result)
        self.assertIn("rpm-pkg-1.0", result)
        self.assertIn("deb-pkg", result)
        self.assertIn("Error: rpm warning", result)
        self.assertIn("Error: dpkg warning", result)
        self.assertIsNone(error)

    @patch("lib.utils.common.shutil.which")
    @patch("lib.utils.common.util.shell_command")
    def test_special_characters_in_package_names(self, mock_shell_cmd, mock_which):
        """Test handling of special characters in package names"""
        mock_which.return_value = "/usr/bin/rpm"
        mock_shell_cmd.return_value = (
            "package-with-dashes-1.0\npackage_with_underscores-2.0\npackage.with.dots-3.0",
            None,
        )

        result, error = common._collect_installed_packages()

        # Verify special characters are preserved
        self.assertIn("package-with-dashes", result)
        self.assertIn("package_with_underscores", result)
        self.assertIn("package.with.dots", result)
        self.assertIsNone(error)
