import unittest

from lib.utils import common


class ComputeLicenseDataSizeTest(unittest.TestCase):
    def run_test_case(self, namespace_stats, expected_cluster_dict):
        summary_dict = common._initialize_summary_output(namespace_stats.keys())
        cluster_dict = summary_dict["CLUSTER"]

        common._compute_license_data_size(
            namespace_stats=namespace_stats,
            cluster_dict=cluster_dict,
        )

        self.assertDictEqual(expected_cluster_dict, cluster_dict)

    def test_success(self):
        test_cases = [
            {
                "ns_stats": {},
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
                "exp_cluster_dict": {"license_data": 46000},
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 99000,
                            "device_used_bytes": 3200,
                        }
                    }
                },
                "exp_cluster_dict": {"license_data": 47600},
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 99000,
                            "device_used_bytes": 3200,
                            "memory_used_bytes": 800,
                        }
                    },
                    "bar": {
                        "1.1.1.1": {
                            "master_objects": 50,
                            "effective_replication_factor": 3,
                            "pmem_used_bytes": 50000,
                            "device_used_bytes": 3800,
                            "memory_used_bytes": 3300,
                        }
                    },
                },
                "exp_cluster_dict": {"license_data": 65283},
            },
            {
                "ns_stats": {
                    "foo": {
                        "1.1.1.1": {
                            "master_objects": 100,
                            "effective_replication_factor": 2,
                            "pmem_used_bytes": 99000,
                            "device_used_bytes": 3200,
                            "memory_used_bytes": 800,
                        },
                        "2.2.2.2": {
                            "master_objects": 10,
                            "effective_replication_factor": 2,
                            "memory_used_bytes": 10000,
                        },
                    },
                    "bar": {
                        "1.1.1.1": {
                            "master_objects": 50,
                            "effective_replication_factor": 3,
                            "pmem_used_bytes": 50000,
                            "device_used_bytes": 3800,
                            "memory_used_bytes": 3300,
                        },
                        "2.2.2.2": {
                            "master_objects": 10,
                            "effective_replication_factor": 3,
                            "memory_used_bytes": 10000,
                        },
                    },
                },
                "exp_cluster_dict": {"license_data": 72917},
            },
        ]

        for tc in test_cases:
            summary_dict = common._initialize_summary_output(tc["ns_stats"].keys())
            summary_dict["CLUSTER"]["license_data"] = tc["exp_cluster_dict"].get(
                "license_data", 0
            )

            self.run_test_case(
                tc["ns_stats"],
                summary_dict["CLUSTER"],
            )
