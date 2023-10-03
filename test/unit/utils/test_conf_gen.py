import asynctest
from mock import AsyncMock
from parameterized import parameterized
from lib.live_cluster.client.config_handler import BaseConfigHandler, IntConfigType

from lib.utils.conf_gen import (
    ConvertCommaSeparatedToList,
    ConvertIndexedSubcontextsToNamedSection,
    ConvertIndexedToList,
    CopyToIntermediateDict,
    CreateIntermediateDict,
    GetConfigStep,
    InterListKey,
    InterLoggingContextKey,
    InterNamedSectionKey,
    InterUnnamedSectionKey,
    RemoveDefaultAndNonExistentKeys,
    RemoveEmptyContexts,
    RemoveNullOrEmptyValues,
    RemoveInvalidKeysFoundInSchemas,
    RemoveSecurityIfNotEnabled,
    ServerVersionCheck,
    SplitColonSeparatedValues,
    SplitSubcontexts,
)


class GetConfigStepTest(asynctest.TestCase):
    async def test_get_config(self):
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

        step = GetConfigStep(config_getter_mock, metadata_getter_mock, "all")
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


class ConvertIndexedSubcontextsToNamedSectionTest(asynctest.TestCase):
    maxDiff = None

    async def test_convert_indexed_to_list(self):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    InterUnnamedSectionKey("network"): {
                        InterUnnamedSectionKey("tls[0]"): {
                            "name": "tls-name",
                            "b": "2",
                            "c": "3",
                        }
                    }
                },
            }
        }

        await ConvertIndexedSubcontextsToNamedSection()(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {
                    InterUnnamedSectionKey("network"): {
                        InterNamedSectionKey("tls", "tls-name"): {
                            "b": "2",
                            "c": "3",
                        }
                    },
                }
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


class RemoveSecurityIfNotEnabledTests(asynctest.TestCase):
    maxDiff = None

    async def test_remove_security(
        self,
    ):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    InterUnnamedSectionKey("security"): {"enable-security": "false"},
                },
                "2.2.2.2": {
                    InterUnnamedSectionKey("security"): {"enable-security": "true"},
                },
                "3.3.3.3": {
                    InterUnnamedSectionKey("security"): {"enable-security": "true"}
                },
                "4.4.4.4": {InterUnnamedSectionKey("security"): {}},
                "5.5.5.5": {
                    InterUnnamedSectionKey("security"): {
                        "other-security-config": 1
                    }  # In the future if enable-security is removed we don't want to remove the other configs
                },
                "6.6.6.6": {InterUnnamedSectionKey("security"): {}},
                "7.7.7.7": {
                    InterUnnamedSectionKey("security"): {
                        "enable-security": "true",
                        InterUnnamedSectionKey("log"): {},
                    },
                },
            },
            "builds": {
                "1.1.1.1": "not-used",
                "2.2.2.2": "5.7.0",
                "3.3.3.3": "5.6.0",
                "4.4.4.4": "5.7.0",
                "5.5.5.5": "7.0.0",
                "6.6.6.6": "5.6.0",
                "7.7.7.7": "5.6.0",
            },
        }
        await RemoveSecurityIfNotEnabled()(context_dict)

        self.assertDictEqual(
            context_dict,
            {
                "intermediate": {
                    "1.1.1.1": {},
                    "2.2.2.2": {
                        InterUnnamedSectionKey("security"): {},
                    },
                    "3.3.3.3": {
                        InterUnnamedSectionKey("security"): {"enable-security": "true"}
                    },
                    "4.4.4.4": {},
                    "5.5.5.5": {
                        InterUnnamedSectionKey("security"): {"other-security-config": 1}
                    },
                    "6.6.6.6": {},
                    "7.7.7.7": {
                        InterUnnamedSectionKey("security"): {
                            "enable-security": "true",
                            InterUnnamedSectionKey("log"): {},
                        },
                    },
                },
                "builds": {
                    "1.1.1.1": "not-used",
                    "2.2.2.2": "5.7.0",
                    "3.3.3.3": "5.6.0",
                    "4.4.4.4": "5.7.0",
                    "5.5.5.5": "7.0.0",
                    "6.6.6.6": "5.6.0",
                    "7.7.7.7": "5.6.0",
                },
            },
        )


class RemoveEmptyContextsTests(asynctest.TestCase):
    maxDiff = None

    async def test(
        self,
    ):
        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    InterUnnamedSectionKey("security"): {"enable-security": "false"},
                    InterNamedSectionKey("namespace", "test"): {
                        InterUnnamedSectionKey("geo2dsphere-within"): {}
                    },
                },
                "2.2.2.2": {
                    InterUnnamedSectionKey("security"): {"enable-security": "true"},
                    InterNamedSectionKey("namespace", "test"): {
                        InterUnnamedSectionKey("geo2dsphere-within"): {"a": "1"}
                    },
                },
                "3.3.3.3": {
                    InterUnnamedSectionKey("security"): {"enable-security": "true"}
                },
                "4.4.4.4": {InterUnnamedSectionKey("security"): {}},
                "5.5.5.5": {
                    InterUnnamedSectionKey("security"): {
                        "other-security-config": 1
                    }  # In the future if enable-security is removed we don't want to remove the other configs
                },
                "6.6.6.6": {InterUnnamedSectionKey("security"): {}},
                "7.7.7.7": {
                    InterUnnamedSectionKey("security"): {
                        InterUnnamedSectionKey("log"): {}
                    },
                },
            },
            "builds": {
                "1.1.1.1": "not-used",
                "2.2.2.2": "5.7.0",
                "3.3.3.3": "5.6.0",
                "4.4.4.4": "5.7.0",
                "5.5.5.5": "7.0.0",
                "6.6.6.6": "5.6.0",
                "7.7.7.7": "5.6.0",
            },
        }
        await RemoveEmptyContexts()(context_dict)

        self.assertDictEqual(
            context_dict,
            {
                "intermediate": {
                    "1.1.1.1": {
                        InterUnnamedSectionKey("security"): {"enable-security": "false"}
                    },
                    "2.2.2.2": {
                        InterUnnamedSectionKey("security"): {"enable-security": "true"},
                        InterNamedSectionKey("namespace", "test"): {
                            InterUnnamedSectionKey("geo2dsphere-within"): {"a": "1"}
                        },
                    },
                    "3.3.3.3": {
                        InterUnnamedSectionKey("security"): {"enable-security": "true"}
                    },
                    "4.4.4.4": {InterUnnamedSectionKey("security"): {}},
                    "5.5.5.5": {
                        InterUnnamedSectionKey("security"): {"other-security-config": 1}
                    },
                    "6.6.6.6": {InterUnnamedSectionKey("security"): {}},
                    "7.7.7.7": {InterUnnamedSectionKey("security"): {}},
                },
                "builds": {
                    "1.1.1.1": "not-used",
                    "2.2.2.2": "5.7.0",
                    "3.3.3.3": "5.6.0",
                    "4.4.4.4": "5.7.0",
                    "5.5.5.5": "7.0.0",
                    "6.6.6.6": "5.6.0",
                    "7.7.7.7": "5.6.0",
                },
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


class RemoveInvalidKeysFoundInSchemasTest(asynctest.TestCase):
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

        await RemoveInvalidKeysFoundInSchemas()(context_dict)

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


class RemoveNullValuesTest(asynctest.TestCase):
    maxDiff = None

    async def test_remove_null_values(self):
        context_dict = {"intermediate": {"1.1.1.1": {"a": "null", "b": "1", "c": ""}}}

        await RemoveNullOrEmptyValues()(context_dict)

        self.assertDictEqual(context_dict["intermediate"], {"1.1.1.1": {"b": "1"}})


class RemoveDefaultValuesTest(asynctest.TestCase):
    maxDiff = None

    async def test_remove_default_values_for_non_logging_contexts(self):
        class MockConfigHandler(BaseConfigHandler):
            def __init__(self, schema_dir: str, version: str, strict: bool):
                pass

            def get_types(self, context: list[str], key: str):
                if context == ["others"] and key == "a":
                    return {"a": IntConfigType(0, 0, False, "1")}
                if context == ["others"] and key == "b":
                    return {"b": None}  # Triggers the call with "bs"
                if context == ["others"] and key == "bs":
                    return {"bs": None}  # Trigger the call with "bes"
                if context == ["others"] and key == "bes":
                    return {"bes": None}  # Triggers the call to get_params
                if context == ["others"] and key == "c":
                    return {"c": IntConfigType(0, 0, False, "default")}
                if context == ["others", "d", "e"] and key == "f":
                    return {"f": IntConfigType(0, 0, False, "2")}
                if context == ["others"] and key == "g":
                    return {"g": None}  # Triggers the call to "gs"
                if context == ["others"] and key == "gs":
                    return {"gs": None}  # Triggers the call to "ges"
                if context == ["others"] and key == "ges":
                    return {"ges": None}  # Triggers the call to "get_params"

                raise Exception(f"Unexpected call to get_types: {context}, {key}")

            def get_params(self, context: list[str]):
                if context == ["others", "b"]:
                    return []
                if context == ["others", "g"]:
                    return ["a"]

                raise Exception(f"Unexpected call to get_params: {context}")

        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    InterUnnamedSectionKey("logging"): {},
                    InterUnnamedSectionKey("others"): {
                        "a": "1",
                        "b": "2",
                        "c": "Not default",
                        "d": {"e": {"f": "2"}},
                        "g": "3",
                    },
                }
            },
            "builds": {"1.1.1.1": "6.4.0"},
        }

        await RemoveDefaultAndNonExistentKeys(MockConfigHandler)(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {
                    InterUnnamedSectionKey("logging"): {},
                    InterUnnamedSectionKey("others"): {
                        "c": "Not default",
                        "d": {"e": {}},
                        "g": "3",
                    },
                }
            },
        )

    async def test_remove_non_default_values_from_logging(self):
        class MockConfigHandler(BaseConfigHandler):
            def __init__(self, schema_dir: str, version: str, strict: bool):
                pass

        context_dict = {
            "intermediate": {
                "1.1.1.1": {
                    InterUnnamedSectionKey("logging"): {
                        InterNamedSectionKey("file", "aerospike.log"): {
                            InterLoggingContextKey("a"): "info",
                            InterLoggingContextKey("b"): "info",
                            InterLoggingContextKey("c"): "info",
                            InterLoggingContextKey("d"): "info",
                            InterLoggingContextKey("e"): "info",
                            InterLoggingContextKey("f"): "info",
                            InterLoggingContextKey("g"): "debug",
                            InterLoggingContextKey("h"): "warning",
                            InterLoggingContextKey("i"): "error",
                            InterLoggingContextKey("j"): "critical",
                            InterLoggingContextKey("k"): "critical",
                        },
                        InterUnnamedSectionKey("console"): {
                            InterLoggingContextKey("a"): "info",
                            InterLoggingContextKey("b"): "debug",
                            InterLoggingContextKey("c"): "warning",
                            InterLoggingContextKey("d"): "error",
                            InterLoggingContextKey("e"): "critical",
                            InterLoggingContextKey("f"): "critical",
                            InterLoggingContextKey("g"): "critical",
                            InterLoggingContextKey("h"): "critical",
                            InterLoggingContextKey("i"): "critical",
                        },
                    },
                }
            },
            "builds": {"1.1.1.1": "6.4.0"},
        }

        await RemoveDefaultAndNonExistentKeys(MockConfigHandler)(context_dict)

        self.assertDictEqual(
            context_dict["intermediate"],
            {
                "1.1.1.1": {
                    InterUnnamedSectionKey("logging"): {
                        InterNamedSectionKey("file", "aerospike.log"): {
                            InterLoggingContextKey("any"): "info",
                            InterLoggingContextKey("g"): "debug",
                            InterLoggingContextKey("h"): "warning",
                            InterLoggingContextKey("i"): "error",
                            InterLoggingContextKey("j"): "critical",
                            InterLoggingContextKey("k"): "critical",
                        },
                        InterUnnamedSectionKey("console"): {
                            InterLoggingContextKey("a"): "info",
                            InterLoggingContextKey("b"): "debug",
                            InterLoggingContextKey("c"): "warning",
                            InterLoggingContextKey("d"): "error",
                            InterLoggingContextKey("any"): "critical",
                        },
                    },
                }
            },
        )
