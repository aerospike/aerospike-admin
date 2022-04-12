from datetime import datetime
import unittest

from lib.utils import common


class ComputeLicenseDataSizeTest(unittest.TestCase):
    maxDiff = None

    def run_test_case(
        self,
        namespace_stats,
        license_data_usage,
        allow_unstable,
        expected_summary_dict: common.SummaryDict,
    ):
        # merge expected summary with init summary output so we don't have put the entire thing
        # in the test
        expected_summary_dict = common._deep_merge_dicts(
            common._initialize_summary_output(namespace_stats.keys()),
            expected_summary_dict,
        )

        summary_dict = common._initialize_summary_output(namespace_stats.keys())

        common._compute_license_data_size(
            namespace_stats,
            license_data_usage,
            allow_unstable,
            summary_dict,
        )

        self.assertDictEqual(expected_summary_dict, summary_dict)

    def test_success_with_out_agent(self):
        test_cases = [
            {
                "ns_stats": {},
                "license_data": {},
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
                "license_data": {},
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
                            "device_used_bytes": 7200,
                        }
                    }
                },
                "license_data": {},
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
                "license_data": {},
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
                "license_data": {},
                "allow_unstable": False,
                "exp_summary_dict": {
                    "CLUSTER": {
                        "license_data": {
                            "latest": ((7200 + 3200) / 2)
                            - (110 * 35)
                            + ((50000 + 10000) / 3)
                            - (35 * 60)
                        },
                    },
                    "NAMESPACES": {
                        "foo": {
                            "license_data": {"latest": ((7200 + 3200) / 2) - (110 * 35)}
                        },
                        "bar": {
                            "license_data": {
                                "latest": ((50000 + 10000) / 3) - (35 * 60)
                            }
                        },
                    },
                },
            },
        ]

        for tc in test_cases:

            with self.subTest("msg"):
                self.run_test_case(
                    tc["ns_stats"],
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
            with self.subTest():
                self.run_test_case(
                    tc["ns_stats"],
                    tc["license_data"],
                    tc["allow_unstable"],
                    tc["exp_summary_dict"],
                )
