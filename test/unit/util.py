def assert_exception(self, exception, message, func, *args):
    exc = None

    try:
        func(*args)
    except Exception as e:
        exc = e

    self.assertIsNotNone(exc, "No exception thrown")
    self.assertIsInstance(exc, exception, "Wrong exception type")
    self.assertEqual(str(exc), message, "Correct exception but wrong message")
