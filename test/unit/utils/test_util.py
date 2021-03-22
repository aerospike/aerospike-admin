import unittest2 as unittest

from lib.utils import util


class UtilTest(unittest.TestCase):
    def test_get_value_from_dict(self):
        value = {"a": 123, "b": "8.9", "c": "abc"}

        self.assertEqual(
            util.get_value_from_dict(value, "a"),
            123,
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(value, ("b",), return_type=float),
            8.9,
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(
                value, "c", default_value="default", return_type=int
            ),
            "default",
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(value, "d", default_value="default"),
            "default",
            "get_value_from_dict did not return the expected result",
        )
        self.assertEqual(
            util.get_value_from_dict(
                value, ("unknown1", "unknown2", "b"), default_value="default"
            ),
            "8.9",
            "get_value_from_dict did not return the expected result",
        )
