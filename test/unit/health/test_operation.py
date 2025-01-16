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

import unittest

from lib.health import operation


class OperationTest(unittest.TestCase):
    def test_BinaryOperation(self):
        op = operation.BinaryOperation("*")
        arg1 = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (1, [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (2, []),
                        ("CONFIG3", "KEY"): (3, []),
                    },
                }
            }
        }
        expected = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (3, [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (6, []),
                        ("CONFIG3", "KEY"): (9, []),
                    },
                }
            }
        }
        arg2 = (3, [])
        result = op.operate(arg1=arg1, arg2=arg2)
        self.assertEqual(
            result,
            expected,
            "BinaryOperation.operate did not return the expected result",
        )

        expected = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG3", "KEY"): (9, [(True, 9, True)]),
                        ("CONFIG2", "KEY"): (6, [(True, 6, True)]),
                    },
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (3, [(True, 3, True)])},
                }
            }
        }
        result = op.operate(arg1=arg1, arg2=arg2, save_param=True)
        self.assertEqual(
            result,
            expected,
            "BinaryOperation.operate did not return the expected result",
        )

    def test_ApplyOperation(self):
        op = operation.ApplyOperation("ANY")
        arg2 = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (1, [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (2, []),
                        ("CONFIG3", "KEY"): (3, []),
                    },
                }
            }
        }

        arg1 = (1, [])

        result = op.operate(arg1=arg1, arg2=arg2, result_comp_op="<")
        expected = (True, [])
        self.assertEqual(
            result,
            expected,
            "ApplyOperation.operate did not return the expected result",
        )

        op = operation.ApplyOperation("ALL")
        result = op.operate(arg1=arg1, arg2=arg2, result_comp_op="<", save_param=True)
        expected = (False, [(True, False, True)])
        self.assertEqual(
            result,
            expected,
            "ApplyOperation.operate did not return the expected result",
        )

    def test_SimpleOperation(self):
        op = operation.SimpleOperation("SPLIT")
        arg1 = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): ("1,2,3", [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): ("abcdef", []),
                        ("CONFIG3", "KEY"): ("test1,test1", []),
                    },
                }
            }
        }

        arg2 = (",", [])
        result = op.operate(arg1=arg1, arg2=arg2)
        expected = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG3", "KEY"): (["test1", "test1"], []),
                        ("CONFIG2", "KEY"): (["abcdef"], []),
                    },
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (["1", "2", "3"], [])},
                }
            }
        }
        self.assertEqual(
            result,
            expected,
            "SimpleOperation.operate did not return the expected result",
        )

        op = operation.SimpleOperation("UNIQUE")
        expected = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG3", "KEY"): (False, [(True, False, True)]),
                        ("CONFIG2", "KEY"): (True, [(True, True, True)]),
                    },
                    ("NS1", "NAMESPACE"): {
                        ("CONFIG1", "KEY"): (True, [(True, True, True)])
                    },
                }
            }
        }
        result = op.operate(arg1=result, arg2=arg2, save_param=True)
        self.assertEqual(
            result,
            expected,
            "SimpleOperation.operate did not return the expected result",
        )

    def test_AggOperation(self):
        op = operation.AggOperation("+")
        arg1 = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (1, [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (2, []),
                        ("CONFIG3", "KEY"): (3, []),
                    },
                }
            }
        }
        result = op.operate(arg1=arg1, group_by=["CLUSTER", "NAMESPACE"])
        expected = {
            ("C1", "CLUSTER"): {
                ("NS2", "NAMESPACE"): (5.0, []),
                ("NS1", "NAMESPACE"): (1.0, []),
            }
        }
        self.assertEqual(
            result, expected, "AggOperation.operate did not return the expected result"
        )

        op = operation.AggOperation("COUNT")
        result = op.operate(arg1=arg1)
        expected = {("C1", "CLUSTER"): (1, [])}
        self.assertEqual(
            result, expected, "AggOperation.operate did not return the expected result"
        )

        op = operation.AggOperation("COUNT_ALL")
        result = op.operate(arg1=arg1)
        expected = {("C1", "CLUSTER"): (3, [])}
        self.assertEqual(
            result, expected, "AggOperation.operate did not return the expected result"
        )

    def test_ComplexOperation(self):
        op = operation.ComplexOperation("SD_ANOMALY")

        arg1 = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {
                        ("CONFIG1", "KEY"): (3, []),
                        ("CONFIG6", "KEY"): (3, []),
                        ("CONFIG7", "KEY"): (3, []),
                    },
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (3, []),
                        ("CONFIG3", "KEY"): (3, []),
                        ("CONFIG4", "KEY"): (3, []),
                        ("CONFIG5", "KEY"): (30000, []),
                    },
                }
            }
        }
        result = op.operate(
            arg1=arg1,
            group_by=["CLUSTER", "NODE"],
            result_comp_op="==",
            result_comp_val=(1, []),
        )
        expected = {("C1", "CLUSTER"): {("N1", "NODE"): (True, [])}}
        self.assertEqual(
            result,
            expected,
            "ComplexOperation.operate did not return the expected result",
        )

        arg1 = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {
                        ("CONFIG1", "KEY"): (3, []),
                        ("CONFIG6", "KEY"): (3, []),
                        ("CONFIG7", "KEY"): (3, []),
                    },
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (3, []),
                        ("CONFIG3", "KEY"): (3, []),
                        ("CONFIG4", "KEY"): (3, []),
                        ("CONFIG5", "KEY"): (3, []),
                    },
                }
            }
        }
        result = op.operate(
            arg1=arg1,
            group_by=["CLUSTER", "NODE"],
            result_comp_op="==",
            result_comp_val=(1, []),
        )
        expected = {("C1", "CLUSTER"): {("N1", "NODE"): (False, [])}}
        self.assertEqual(
            result,
            expected,
            "ComplexOperation.operate did not return the expected result",
        )

    def test_AssertDetailOperation(self):
        op = operation.AssertDetailOperation("==")
        data = {
            ("C1", "CLUSTER"): {
                ("N1", "NODE"): {
                    ("NS1", "NAMESPACE"): {("CONFIG1", "KEY"): (1, [])},
                    ("NS2", "NAMESPACE"): {
                        ("CONFIG2", "KEY"): (2, []),
                        ("CONFIG3", "KEY"): (3, []),
                    },
                }
            }
        }
        result = op.operate(
            data=data,
            check_val=(2, []),
            error="error",
            category="category",
            level="level",
            description="description",
            success_msg="success",
        )
        expected = (
            "assert_result",
            {
                "Category": ["CATEGORY"],
                "Description": "description",
                "Successmsg": "success",
                "Level": "level",
                "Failmsg": "error",
                "Keys": [("C1/N1/NS1/CONFIG1", None), ("C1/N1/NS2/CONFIG3", None)],
                "Success": False,
            },
        )
        self.assertEqual(
            result,
            expected,
            "AssertDetailOperation.operate did not return the expected result",
        )
