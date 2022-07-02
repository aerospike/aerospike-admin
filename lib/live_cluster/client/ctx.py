from typing import Any, Generic, TypeVar

T = TypeVar("T")


class ASValue(Generic[T]):
    def __init__(self, value: T):
        self.value = value


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

    class ASList(ASValue[list[ASValue]]):
        def __init__(self, value: list[ASValue]):
            super().__init__(value)

    class ASMap(ASValue[dict[ASValue, ASValue]]):
        def __init__(self, value: dict[ASValue, ASValue]):
            super().__init__(value)

    class ASPair(ASValue[tuple]):
        def __init__(self, value: tuple):
            super().__init__(value)

    class ASBytes(ASValue[bytes]):
        def __init__(self, value: bytes):
            super().__init__(value)

    class ASDouble(ASValue[float]):
        def __init__(self, value: float):
            super().__init__(value)

    class ASGeoJson(ASValue[str]):
        def __init__(self, value: str):
            super().__init__(value)

    class ASWildCard(ASValue[None]):
        def __init__(self):  # maybe could be dict?
            super().__init__(None)

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


class CTXIntItem(CTXItem[int]):
    pass


class CTXParticleItem(CTXItem[ASValue]):
    pass


class CTXItems:
    class ListIndex(CTXIntItem):
        pass

    class ListRank(CTXIntItem):
        pass

    class MapIndex(CTXIntItem):
        pass

    class MapRank(CTXIntItem):
        pass

    class MapKey(CTXParticleItem):
        pass

    # Not needed. Here for reference
    # class ListValue(CTXItem):
    #     def __init__(self, pval: ASValue):
    #         super().__init__(pval=pval)

    # Not needed. Here for reference
    # class MapValue(CTXItem):
    #     def __init__(self, pval: ASValue):
    #         super().__init__(pval=pval)


class CDTContext(list[CTXItem]):
    pass
