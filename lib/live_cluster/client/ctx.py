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

from typing import Any, Generic, TypeVar

T = TypeVar("T")


class ASValue(Generic[T]):
    def __init__(self, value: T):
        self.value = value

    def __eq__(self, __o: object) -> bool:
        return type(self) is type(__o) and self.__dict__ == __o.__dict__

    def __str__(self) -> str:
        return "{}({})".format(type(self), self.value)


class ASValues:
    class ASBool(ASValue[bool]):
        def __init__(self, value: bool):
            super().__init__(value)

    class ASInt(ASValue[int]):
        def __init__(self, value: int):
            super().__init__(value)

    class ASString(ASValue[str]):
        def __init__(self, value: str):
            super().__init__(value)

    class ASBytes(ASValue[bytes]):
        def __init__(self, value: bytes):
            super().__init__(value)

    class ASDouble(ASValue[float]):
        def __init__(self, value: float):
            super().__init__(value)

    """
    Not used.  Here for reference in case they become needed.
    """

    # class ASList(ASValue[list[ASValue]]):
    #     def __init__(self, value: list[ASValue]):
    #         super().__init__(value)

    # class ASMap(ASValue[dict[ASValue, ASValue]]):
    #     def __init__(self, value: dict[ASValue, ASValue]):
    #         super().__init__(value)

    # class ASGeoJson(ASValue[str]):
    #     def __init__(self, value: str):
    #         super().__init__(value)

    # class ASWildCard(ASValue[None]):
    #     def __init__(self):  # maybe could be dict?
    #         super().__init__(None)

    # class ASUndef(ASValue):
    #     def __init__(self):
    #         super().__init__(None)

    # class ASNil(ASValue):
    #     def __init__(self):
    #         super().__init__(None)

    # class ASRec(ASValue):
    #     def __init__(self, value):
    #         super().__init__(value)


class CTXItem(Generic[T]):
    def __init__(self, val: T):
        self.value = val

    def __eq__(self, __o: object) -> bool:
        return type(__o) is type(self) and __o.__dict__ == self.__dict__

    def __str__(self):
        return "{}({})".format(type(self), self.value)


class CTXIntItem(CTXItem[int]):
    def __init__(self, val: int):
        if not isinstance(val, int):
            raise TypeError("CTX value must of type int")

        super().__init__(val)


class CTXParticleItem(CTXItem[ASValue]):
    def __init__(self, val: ASValue):
        if not isinstance(val, ASValue):
            raise TypeError("CTX value must of type ASValue")

        super().__init__(val)


class CTXItems:
    class ListIndex(CTXIntItem):
        pass

    class ListRank(CTXIntItem):
        pass

    class ListValue(CTXParticleItem):
        pass

    class MapIndex(CTXIntItem):
        pass

    class MapRank(CTXIntItem):
        pass

    class MapKey(CTXParticleItem):
        pass

    class MapValue(CTXParticleItem):
        pass


class CDTContext(list[CTXItem]):
    pass
