import asynctest
from mock import AsyncMock
from parameterized import parameterized

from lib.utils.conf_gen import (
    ConvertCommaSeparatedToList,
    ConvertIndexedToList,
    CopyToIntermediateDict,
    CreateIntermediateDict,
    GetConfigStep,
    InterListKey,
    InterNamedSectionKey,
    InterUnnamedSectionKey,
    RemoveEmptyGeo2DSpheres,
    RemoveRedundantNestedKeys,
    RemoveSecurityIfNotEnabled,
    RemoveXDRIfNoDCs,
    ServerVersionCheck,
    SplitColonSeparatedValues,
    SplitSubcontexts,
)


class GetConfigStepTest(asynctest.TestCase):
    async def test_supported_version(self):
        config_getter_mock = AsyncMock()
        metadata_getter_mock = AsyncMock()
        config_getter_mock.get_logging.return_value = "logging"
        config_getter_mock.get_service.return_value = "service"
        config_getter_mock.get_network.return_value = "network"
        config_getter_mock.get_security.return_value = "security"
        config_getter_mock.get_namespace.return_value = "namespaces"
        config_getter_mock.get_sets.return_value = "sets"
        config_getter_mock.get_rack_ids.return_value = "rack-ids"
        config_getter_mock.get_xdr.return_value = "xdr"
        config_getter_mock.get_xdr_dcs.return_value = "xdr-dcs"
        config_getter_mock.get_xdr_namespaces.return_value = "xdr-namespaces"
        metadata_getter_mock.get_builds.return_value = {
            "1.1.1.1": "5.1.0.0",
            "2.2.2.2": "5.0.0.0",
        }

        step = GetConfigStep(config_getter_mock, metadata_getter_mock)
        context_dict = {}
        await step(context_dict)

        self.assertEqual(context_dict["logging"], "logging")
        self.assertEqual(context_dict["service"], "service")
        self.assertEqual(context_dict["network"], "network")
        self.assertEqual(context_dict["security"], "security")
        self.assertEqual(context_dict["namespaces"], "namespaces")
        self.assertEqual(context_dict["sets"], "sets")
        self.assertEqual(context_dict["rack-ids"], "rack-ids")
        self.assertEqual(context_dict["xdr"], "xdr")
        self.assertEqual(context_dict["xdr-dcs"], "xdr-dcs")
        self.assertEqual(context_dict["xdr-namespaces"], "xdr-namespaces")
        self.assertEqual(
            context_dict["builds"],
            {
                "1.1.1.1": "5.1.0.0",
                "2.2.2.2": "5.0.0.0",
            },
        )


class ServerVersionCheckTest(asynctest.TestCase):
    async def test_unsupported_version(self):
        context_dict = {
            "builds": {
                "1.1.1.1": "5.1.0.0",
                "2.2.2.2": "4.9.9.0",
            }
        }

        with self.assertRaises(NotImplementedError) as context:
            await ServerVersionCheck()(context_dict)

    async def test_supported_version(self):
        context_dict = {
            "builds": {
                "1.1.1.1": "5.1.0.0",
                "2.2.2.2": "5.9.9.0",
            }
        }

        await ServerVersionCheck()(context_dict)


class CreateIntermediateDictTest(asynctest.TestCase):
    async def test_create_intermediate_dict(self):
        context_dict = {
            "logging": {"a": 1},
            "service": {"b": 2},
            "network": {"c": 3},
            "security": {"d": 4},
            "namespaces": {"e": 5},
            "xdr": {"f": 6},
        }

        await CreateIntermediateDict()(context_dict)

        self.assertEqual(
            set(context_dict["intermediate"].keys()), {"a", "b", "c", "d", "e", "f"}
        )


class CopyToIntermediateDictTest(asynctest.TestCase):
    maxDiff = None

    async def test_copy_to_intermediate(self):
        context_dict = {
            "intermediate": {"1.1.1.1": 1},
            "logging": {
                "1.1.1.1": {
                    "stderr": {"a": 1},
                    "aerospike.log": {"b": 1},
                    "/dev/null": {"c": 1},
                }
            },
            "service": {"1.1.1.1": {"a": 1}},
            "network": {"1.1.1.1": {"a": 1}},
            "security": {"1.1.1.1": {"a": 1}},
            "namespaces": {"1.1.1.1": {"test": {"a": 1}, "bar": {"b": 1}}},
            "sets": {"1.1.1.1": {("test", "testset"): 1, ("bar", "barset"): 1}},
            "xdr": {"1.1.1.1": {"a": 1}},
            "xdr-dcs": {"1.1.1.1": {"dc1": {"a": 1}, "dc2": {"b": 1}}},
            "xdr-namespaces": {"1.1.1.1": {"dc1": {"test": 1}, "dc2": {"bar": 2}}},
        }

        await CopyToIntermediateDict()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {
                    InterUnnamedSectionKey("logging"): {
                        InterUnnamedSectionKey("console"): {"a": 1},
                        InterNamedSectionKey("file", "aerospike.log"): {"b": 1},
                        InterUnnamedSectionKey("syslog"): {"c": 1, "path": "/dev/null"},
                    },
                    InterUnnamedSectionKey("service"): {"a": 1},
                    InterUnnamedSectionKey("network"): {"a": 1},
                    InterUnnamedSectionKey("security"): {"a": 1},
                    InterNamedSectionKey("namespace", "test"): {
                        "a": 1,
                        InterNamedSectionKey("set", "testset"): 1,
                    },
                    InterNamedSectionKey("namespace", "bar"): {
                        "b": 1,
                        InterNamedSectionKey("set", "barset"): 1,
                    },
                    InterUnnamedSectionKey("xdr"): {
                        "a": 1,
                        InterNamedSectionKey("dc", "dc1"): {
                            "a": 1,
                            InterNamedSectionKey("namespace", "test"): 1,
                        },
                        InterNamedSectionKey("dc", "dc2"): {
                            "b": 1,
                            InterNamedSectionKey("namespace", "bar"): 2,
                        },
                    },
                }
            },
        )


class SplitSubcontextsTest(asynctest.TestCase):
    maxDiff = None

    async def test_split_subcontexts(self):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    "index-type": "pmem",
                    "index-type.a": "1",
                    "index-type.b": "2",
                    "network.info.bar": "a",
                    "network.heartbeat.foo": "b",
                },
                "2.2.2.2": {
                    "network.info.bar": "a",
                    "network.heartbeat.foo": "b",
                },
            }
        }

        await SplitSubcontexts()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {
                    InterUnnamedSectionKey("network"): {
                        InterUnnamedSectionKey("info"): {"bar": "a"},
                        InterUnnamedSectionKey("heartbeat"): {"foo": "b"},
                    },
                    InterNamedSectionKey("index-type", "pmem"): {
                        "a": "1",
                        "b": "2",
                    },
                },
                "2.2.2.2": {
                    InterUnnamedSectionKey("network"): {
                        InterUnnamedSectionKey("info"): {"bar": "a"},
                        InterUnnamedSectionKey("heartbeat"): {"foo": "b"},
                    },
                },
            },
        )


class ConvertIndexedToListTest(asynctest.TestCase):
    maxDiff = None

    async def test_convert_indexed_to_list(self):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {"a": {"b[1]": "1", "b[0]": "2", "b[2]": "3"}},
            }
        }

        await ConvertIndexedToList()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {"a": {InterListKey("b"): ["2", "1", "3"]}},
            },
        )


class ConvertCommaSeparatedToListTest(asynctest.TestCase):
    maxDiff = None

    async def test_convert_indexed_to_list(self):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {"a": {"b": "2,1,3"}},
            }
        }

        await ConvertCommaSeparatedToList()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {"a": {InterListKey("b"): ["2", "1", "3"]}},
            },
        )


class RemoveSecurityIfNotEnabledTest(asynctest.TestCase):
    maxDiff = None

    async def test_remove_security_if_not_enabled(
        self,
    ):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    InterUnnamedSectionKey("security"): {"enable-security": "false"}
                },
                "2.2.2.2": {
                    InterUnnamedSectionKey("security"): {"enable-security": "true"}
                },
                "3.3.3.3": {
                    InterUnnamedSectionKey("security"): {"enable-security": "true"}
                },
                "4.4.4.4": {InterUnnamedSectionKey("security"): {}},
            },
            "builds": {
                "2.2.2.2": "5.7.0",
                "3.3.3.3": "5.6.0",
                "4.4.4.4": "5.7.0",
            },
        }
        await RemoveSecurityIfNotEnabled()(context_dict)

        self.assertDictEqual(
            context_dict,
            {
                "intermediate": {
                    "1.1.1.1": {},
                    "2.2.2.2": {InterUnnamedSectionKey("security"): {}},
                    "3.3.3.3": {
                        InterUnnamedSectionKey("security"): {"enable-security": "true"}
                    },
                    "4.4.4.4": {},
                },
                "builds": {
                    "2.2.2.2": "5.7.0",
                    "3.3.3.3": "5.6.0",
                    "4.4.4.4": "5.7.0",
                },
            },
        )


class RemoveEmptyGeo2DSphereTest(asynctest.TestCase):
    maxDiff = None

    async def test_remove_empty_geo2dsphere(
        self,
    ):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    InterNamedSectionKey("namespace", "test"): {
                        InterUnnamedSectionKey("geo2dsphere-within"): {}
                    }
                },
                "2.2.2.2": {
                    InterNamedSectionKey("namespace", "test"): {
                        InterUnnamedSectionKey("geo2dsphere-within"): {"a": "1"}
                    }
                },
            }
        }

        await RemoveEmptyGeo2DSpheres()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {InterNamedSectionKey("namespace", "test"): {}},
                "2.2.2.2": {
                    InterNamedSectionKey("namespace", "test"): {
                        InterUnnamedSectionKey("geo2dsphere-within"): {"a": "1"}
                    }
                },
            },
        )


class RemoveXDRIfNoDCsTest(asynctest.TestCase):
    maxDiff = None

    async def test_remove_xdr_if_no_dcs(
        self,
    ):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {InterUnnamedSectionKey("xdr"): {"dcs": "dc1,dc2"}},
                "2.2.2.2": {InterUnnamedSectionKey("xdr"): {}},
            }
        }

        await RemoveXDRIfNoDCs()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {InterUnnamedSectionKey("xdr"): {"dcs": "dc1,dc2"}},
                "2.2.2.2": {},
            },
        )


class SplitColonSeparatedValuesTest(asynctest.TestCase):
    async def test_split_colon_separated_values(self):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {"a": "1.1.1.1:3000", "cipher-suites": "ALL:!aNULL:!eNULL"},
                "2.2.2.2": {"a": "1.1.1.1:3000", "cipher-suites": "ALL:!aNULL:!eNULL"},
            }
        }

        await SplitColonSeparatedValues()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {"a": "1.1.1.1 3000", "cipher-suites": "ALL:!aNULL:!eNULL"},
                "2.2.2.2": {"a": "1.1.1.1 3000", "cipher-suites": "ALL:!aNULL:!eNULL"},
            },
        )


class RemoveRedundantNestedKeysTest(asynctest.TestCase):
    maxDiff = None

    async def test_remove_redundant_nested_keys(self):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    InterUnnamedSectionKey("xdr"): {
                        "dcs": "dc1",
                        InterNamedSectionKey("dc", "dc1"): {
                            "namespaces": "test",
                            InterNamedSectionKey("namespace", "test"): {"a": 1},
                        },
                    }
                }
            },
        }

        await RemoveRedundantNestedKeys()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {
                    InterUnnamedSectionKey("xdr"): {
                        InterNamedSectionKey("dc", "dc1"): {
                            InterNamedSectionKey("namespace", "test"): {"a": 1}
                        },
                    }
                }
            },
        )
