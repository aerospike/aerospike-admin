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
