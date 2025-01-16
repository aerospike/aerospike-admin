# Copyright 2021-2025 Aerospike, Inc.
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
