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

import unittest
import warnings
from pytest import PytestUnraisableExceptionWarning
from mock import create_autospec, patch
from mock.mock import MagicMock
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)

from lib.collectinfo_analyzer.get_controller import (
    GetConfigController,
    GetStatisticsController,
)

from lib.utils import constants


class GetConfigControllerTest(unittest.TestCase):
    def setUp(self):
        self.log_handler = create_autospec(CollectinfoLogHandler)
        self.controller = GetConfigController(self.log_handler)

    def test_get_namespace(self):
        self.log_handler.info_getconfig.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}, "abc": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}, "abc": {"b"}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"abc": {"b"}, "aab": {"b"}},
                "2.2.2.2": {"abc": {"b"}, "aab": {}},
            }
        }

        actual = self.controller.get_namespace(for_mods=["aab", "ab"])

        self.assertDictEqual(actual, expected)
        self.log_handler.info_getconfig.assert_called_with(
            stanza=constants.CONFIG_NAMESPACE
        )

    def test_get_set(self):
        self.log_handler.info_getconfig.return_value = {
            "timestamp": {
                "1.1.1.1": {
                    ("aaa", "sss"): {"a"},
                    ("aab", "sst"): {"b"},
                    ("abc", "stu"): {"c"},
                },
                "2.2.2.2": {
                    ("aaa", "sss"): {"c"},
                    ("aab", "sst"): {},
                    ("abc", "stu"): {"b"},
                },
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {
                    ("aab", "sst"): {"b"},
                    ("abc", "stu"): {"c"},
                },
                "2.2.2.2": {
                    ("aab", "sst"): {},
                    ("abc", "stu"): {"b"},
                },
            }
        }

        actual = self.controller.get_sets(for_mods=["ab", "st"])
        self.assertDictEqual(actual, expected)
        self.log_handler.info_getconfig.assert_called_with(stanza=constants.CONFIG_SET)

    def test_get_xdr(self):
        self.log_handler.info_getconfig.return_value = {
            "timestamp": {
                "1.1.1.1": {"a": 1},
                "2.2.2.2": {"b": 2},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"a": 1},
                "2.2.2.2": {"b": 2},
            }
        }

        actual = self.controller.get_xdr()

        self.assertDictEqual(actual, expected)
        self.log_handler.info_getconfig.assert_called_with(stanza=constants.CONFIG_XDR)

    def test_get_xdr_dcs_with_filter(self):
        self.log_handler.info_getconfig.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}, "abc": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}, "abc": {"b"}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}},
            }
        }

        actual = self.controller.get_xdr_dcs(for_mods=["aa"])

        self.assertDictEqual(actual, expected)
        self.log_handler.info_getconfig.assert_called_with(stanza=constants.CONFIG_DC)

    def test_get_xdr_dcs(self):
        self.log_handler.info_getconfig.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}, "abc": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}, "abc": {"b"}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}, "abc": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}, "abc": {"b"}},
            }
        }

        actual = self.controller.get_xdr_dcs()

        self.log_handler.info_getconfig.assert_called_with(stanza=constants.CONFIG_DC)
        self.assertDictEqual(actual, expected)

    def test_get_xdr_namespaces(self):
        self.log_handler.info_getconfig.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {},
            }
        }

        actual = self.controller.get_xdr_namespaces()

        self.log_handler.info_getconfig.assert_called_with(
            stanza=constants.CONFIG_XDR_NS
        )
        self.assertDictEqual(actual, expected)

    def test_get_xdr_filters_with_filter(self):
        self.log_handler.info_getconfig.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {"aa": {}}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {"ccc": {"test": {"a"}}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {},
            }
        }

        actual = self.controller.get_xdr_namespaces(for_mods=["test", "aa"])

        self.log_handler.info_getconfig.assert_called_with(
            stanza=constants.CONFIG_XDR_NS
        )
        self.assertDictEqual(actual, expected)

    def test_get_xdr_namespaces_with_filter(self):
        self.log_handler.get_node_id_to_ip_mapping.return_value = {
            "1": "1.1.1.1",
            "2": "2.2.2.2",
            "3": "3.3.3.3",
        }
        self.log_handler.get_principal.return_value = "1"
        self.log_handler.info_getconfig.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {"aa": {}}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {"ccc": {"test": {"a"}}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
            }
        }

        actual = self.controller.get_xdr_filters(for_mods=["aa", "test"])

        self.log_handler.info_getconfig.assert_called_with(
            stanza=constants.CONFIG_XDR_FILTER
        )
        self.assertDictEqual(actual, expected)


class GetStatisticsControllerTest(unittest.TestCase):
    def setUp(self):
        self.log_handler = patch(
            "lib.collectinfo_analyzer.collectinfo_handler.log_handler.CollectinfoLogHandler",
            MagicMock(),
        ).start()
        self.controller = GetStatisticsController(self.log_handler)

    def test_get_namespace(self):
        self.log_handler.info_statistics.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}, "abc": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}, "abc": {"b"}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"abc": {"b"}, "aab": {"b"}},
                "2.2.2.2": {"abc": {"b"}, "aab": {}},
            }
        }

        actual = self.controller.get_namespace(for_mods=["aab", "ab"])

        self.assertDictEqual(actual, expected)
        self.log_handler.info_statistics.assert_called_with(
            stanza=constants.STAT_NAMESPACE
        )

    def test_get_set(self):
        self.log_handler.info_statistics.return_value = {
            "timestamp": {
                "1.1.1.1": {
                    ("aaa", "sss"): {"a"},
                    ("aab", "sst"): {"b"},
                    ("abc", "stu"): {"c"},
                },
                "2.2.2.2": {
                    ("aaa", "sss"): {"c"},
                    ("aab", "sst"): {},
                    ("abc", "stu"): {"b"},
                },
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {
                    ("aab", "sst"): {"b"},
                    ("abc", "stu"): {"c"},
                },
                "2.2.2.2": {
                    ("aab", "sst"): {},
                    ("abc", "stu"): {"b"},
                },
            }
        }

        actual = self.controller.get_sets(for_mods=["ab", "st"])
        self.assertDictEqual(actual, expected)
        self.log_handler.info_statistics.assert_called_with(stanza=constants.STAT_SETS)

    def test_get_xdr(self):
        self.log_handler.info_statistics.return_value = {
            "timestamp": {
                "1.1.1.1": {"a": 1},
                "2.2.2.2": {"b": 2},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"a": 1},
                "2.2.2.2": {"b": 2},
            }
        }

        actual = self.controller.get_xdr()

        self.assertDictEqual(actual, expected)
        self.log_handler.info_statistics.assert_called_with(stanza=constants.STAT_XDR)

    def test_get_xdr_dcs_with_filter(self):
        self.log_handler.info_statistics.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}, "abc": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}, "abc": {"b"}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}},
            }
        }

        actual = self.controller.get_xdr_dcs(for_mods=["aa"])

        self.assertDictEqual(actual, expected)
        self.log_handler.info_statistics.assert_called_with(stanza=constants.STAT_DC)

    def test_get_xdr_dcs(self):
        self.log_handler.info_statistics.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}, "abc": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}, "abc": {"b"}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"a"}, "aab": {"b"}, "abc": {"b"}},
                "2.2.2.2": {"aaa": {"c"}, "aab": {}, "abc": {"b"}},
            }
        }

        actual = self.controller.get_xdr_dcs()

        self.log_handler.info_statistics.assert_called_with(stanza=constants.STAT_DC)
        self.assertDictEqual(actual, expected)

    def test_get_xdr_namespaces(self):
        self.log_handler.info_statistics.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {},
            }
        }

        actual = self.controller.get_xdr_namespaces()

        self.log_handler.info_statistics.assert_called_with(
            stanza=constants.STAT_XDR_NS
        )
        self.assertDictEqual(actual, expected)

    def test_get_xdr_namespaces_with_filter(self):
        self.log_handler.info_statistics.return_value = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {"aa": {}}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {"ccc": {"test": {"a"}}},
            }
        }
        expected = {
            "timestamp": {
                "1.1.1.1": {"aaa": {"test": {"a"}}, "aab": {}},
                "2.2.2.2": {"aaa": {"test": {"a"}}, "aab": {"test1": {}}},
                "3.3.3.3": {},
            }
        }

        actual = self.controller.get_xdr_namespaces(for_mods=["test", "aa"])

        self.log_handler.info_statistics.assert_called_with(
            stanza=constants.STAT_XDR_NS
        )
        self.assertDictEqual(actual, expected)
