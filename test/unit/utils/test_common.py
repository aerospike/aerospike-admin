import unittest

from lib.utils import common


class ComputeLicenseDataSizeTest(unittest.TestCase):
    def run_test_case(self, namespace_stats, license_data_usage, expected_cluster_dict):
        summary_dict = common._initialize_summary_output(namespace_stats.keys())
        cluster_dict = summary_dict["CLUSTER"]

        common.compute_license_data_size(
            namespace_stats=namespace_stats,
            cluster_dict=cluster_dict,
            license_data_usage=license_data_usage,
        )

        self.assertDictEqual(expected_cluster_dict, cluster_dict)

    def test_success_with_out_agent(self):
        test_cases = [
            {
                "ns_stats": {},
                "license_data": {},
                "exp_cluster_dict": {},
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
                "exp_cluster_dict": {"license_data": {"latest": 46000}},
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
                "exp_cluster_dict": {"license_data": {"latest": 100}},
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
                "exp_cluster_dict": {"license_data": {"latest": 500 + 250}},
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
                "exp_cluster_dict": {
                    "license_data": {
                        "latest": ((7200 + 3200) / 2) - (110 * 35) + 20000 - (35 * 60)
                    }
                },
            },
        ]

        for tc in test_cases:
            summary_dict = common._initialize_summary_output(tc["ns_stats"].keys())
            summary_dict["CLUSTER"]["license_data"] = tc["exp_cluster_dict"].get(
                "license_data", 0
            )

            self.run_test_case(
                tc["ns_stats"],
                tc["license_data"],
                summary_dict["CLUSTER"],
            )

    def test_success_with_agent(self):
        test_cases = [
            {
                "ns_stats": {},
                "license_data": {
                    "license_usage": {
                        "count": 1,
                        "entries": [{"unique_data_bytes": 500, "level": "info"}],
                    },
                },
                "exp_cluster_dict": {
                    "license_data": {"latest": 500, "min": 500, "max": 500, "avg": 500}
                },
            },
            {
                "ns_stats": {},
                "license_data": {
                    "license_usage": {
                        "count": 2,
                        "entries": [
                            {"unique_data_bytes": 500, "level": "info"},
                            {"unique_data_bytes": 0, "level": "error"},
                        ],
                    }
                },
                "exp_cluster_dict": {
                    "license_data": {"latest": 500, "min": 500, "max": 500, "avg": 500}
                },
            },
            {
                "ns_stats": {},
                "license_data": {
                    "license_usage": {
                        "count": 2,
                        "entries": [
                            {"unique_data_bytes": 500, "level": "info"},
                            {"unique_data_bytes": 100, "level": "info"},
                            {"unique_data_bytes": 0, "level": "error"},
                        ],
                    }
                },
                "exp_cluster_dict": {
                    "license_data": {"latest": 100, "min": 100, "max": 500, "avg": 300}
                },
            },
            {
                "ns_stats": {},
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
                "exp_cluster_dict": {
                    "license_data": {
                        "latest": None,
                        "min": None,
                        "max": None,
                        "avg": None,
                    }
                },
            },
        ]

        for tc in test_cases:
            summary_dict = common._initialize_summary_output(tc["ns_stats"].keys())
            summary_dict["CLUSTER"]["license_data"] = tc["exp_cluster_dict"].get(
                "license_data", 0
            )

            self.run_test_case(
                tc["ns_stats"],
                tc["license_data"],
                summary_dict["CLUSTER"],
            )
