import asyncio
import warnings

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import asynctest

from lib.utils import util


class UtilTest(asynctest.TestCase):
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

    async def test_async_cached(self):
        async def tester(arg1, arg2, sleep):
            await asyncio.sleep(sleep)
            return arg1 + arg2

        tester = util.async_cached(tester, ttl=5.0)

        await tester(1, 2, 0.2)
        await tester(2, 2, 0.2)
        await tester(3, 2, 0.2)

        self.assertEqual(3, await asyncio.wait_for(tester(1, 2, 0.2), 0.1))
        self.assertEqual(4, await asyncio.wait_for(tester(2, 2, 0.2), 0.1))
        self.assertEqual(5, await asyncio.wait_for(tester(3, 2, 0.2), 0.1))
        await self.assertAsyncRaises(
            asyncio.TimeoutError, asyncio.wait_for(tester(1, 2, 5), 0.1)
        )
