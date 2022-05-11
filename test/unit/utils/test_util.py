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
        tester_count = 0

        async def tester(arg1: int, arg2: int, sleep: float) -> int:
            nonlocal tester_count
            tester_count += 1
            await asyncio.sleep(sleep)
            return arg1 + arg2

        cached_tester = util.async_cached(tester, ttl=5.0)

        # insert into cache
        await cached_tester(1, 2, 0.2)
        await cached_tester(2, 2, 0.2)
        await cached_tester(3, 2, 0.2)

        # all cache hits.  Should return faster because in cache
        self.assertEqual(3, await asyncio.wait_for(cached_tester(1, 2, 0.2), 0.1))
        self.assertEqual(4, await asyncio.wait_for(cached_tester(2, 2, 0.2), 0.1))
        self.assertEqual(5, await asyncio.wait_for(cached_tester(3, 2, 0.2), 0.1))

        # not in the cache because it has a different sleep value
        await self.assertAsyncRaises(
            asyncio.TimeoutError, asyncio.wait_for(cached_tester(1, 2, 5), 0.1)
        )

        # Key is in the cache but it is dirty because of the sleep. So it is a miss.
        await asyncio.sleep(5)
        await self.assertAsyncRaises(
            asyncio.TimeoutError, asyncio.wait_for(cached_tester(1, 2, 0.2), 0.1)
        )
        self.assertEqual(tester_count, 5)

        tester_exc_count = 0

        async def tester_exc() -> bool:
            nonlocal tester_exc_count
            if tester_exc_count == 0:
                tester_exc_count += 1
                raise Exception()
            tester_exc_count += 1

            return True

        cached_tester_exc = util.async_cached(tester_exc, ttl=5.0)
        await self.assertAsyncRaises(
            Exception, asyncio.wait_for(cached_tester_exc(), 0.1)
        )
        self.assertTrue(await cached_tester_exc())
