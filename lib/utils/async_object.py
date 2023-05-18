# Copyright 2022-2023 Aerospike, Inc.
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

from typing import Any, Awaitable, Coroutine, Type, TypeVar


class AsyncObject(object):
    """Inheriting this class allows you to define an async __init__.

    So you can create objects by doing something like `await MyClass(params)`
    """

    Class = TypeVar("Class")

    async def __new__(cls: Type[Class], *args, **kwargs) -> Class:
        instance = super().__new__(cls)
        await instance.__init__(*args, **kwargs)  # type: ignore
        return instance

    async def __init__(self):
        pass
