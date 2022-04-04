def assert_exception(self, exception, message, func, *args):
    """
    exception:  The exception type you want thrown.
    message: The message given to the exception when raised, None to not check message
    func:  Function to run
    args: Arguments to func
    """
    exc = None

    try:
        func(*args)
    except Exception as e:
        exc = e

    self.assertIsNotNone(exc, "No exception thrown")
    self.assertIsInstance(exc, exception, "Wrong exception type")

    if message is not None:
        self.assertEqual(str(exc), message, "Correct exception but wrong message")


async def assert_exception_async(self, exception, message, func, *args):
    """
    exception:  The exception type you want thrown.
    message: The message given to the exception when raised, None to not check message
    func:  Function to run
    args: Arguments to func
    """
    exc = None

    try:
        await func(*args)
    except Exception as e:
        exc = e

    self.assertIsNotNone(exc, "No exception thrown")
    self.assertIsInstance(exc, exception, "Wrong exception type")

    if message is not None:
        self.assertEqual(str(exc), message, "Correct exception but wrong message")
