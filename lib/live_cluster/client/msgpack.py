import struct
from typing import Union
from msgpack.fallback import Packer
from msgpack import ExtType

from lib.live_cluster.client.ctx import ASValue, ASValues, CDTContext, CTXItem, CTXItems

AS_BYTES_STRING = 3
AS_BYTES_GEOJSON = 23
ASVAL_CMP_EXT_TYPE = 0xFF
ASVAL_CMP_WILDCARD = 0x00


class CTXItemWireType:
    AS_CDT_CTX_LIST_INDEX = 0x10
    AS_CDT_CTX_LIST_RANK = 0x11
    AS_CDT_CTX_LIST_VALUE = 0x13
    AS_CDT_CTX_MAP_INDEX = 0x20
    AS_CDT_CTX_MAP_RANK = 0x21
    AS_CDT_CTX_MAP_KEY = 0x22
    AS_CDT_CTX_MAP_VALUE = 0x23


class ASPacker(Packer):
    def __init__(self, autoreset=False):
        super().__init__(autoreset=autoreset)

    def pack(self, obj):
        if isinstance(obj, ASValue):
            self._pack_as_value(obj)
            return
        elif isinstance(obj, CDTContext):
            self._pack_as_cdt_ctx(obj)
            return

        super().pack(obj)

    def _pack_as_cdt_ctx(self, obj: CDTContext):
        n = len(obj) * 2
        self._pack_array_header(n)

        tmp = self.bytes()

        for item in obj:
            self._pack_as_cdt_item(item)

        return

    def _pack_as_cdt_item(self, obj: CTXItem):
        if isinstance(obj, CTXItems.ListIndex):
            self.pack(CTXItemWireType.AS_CDT_CTX_LIST_INDEX)
        elif isinstance(obj, CTXItems.ListRank):
            self.pack(CTXItemWireType.AS_CDT_CTX_LIST_RANK)
        elif isinstance(obj, CTXItems.MapIndex):
            self.pack(CTXItemWireType.AS_CDT_CTX_MAP_INDEX)
        elif isinstance(obj, CTXItems.MapRank):
            self.pack(CTXItemWireType.AS_CDT_CTX_MAP_RANK)
        elif isinstance(obj, CTXItems.MapKey):
            self.pack(CTXItemWireType.AS_CDT_CTX_MAP_KEY)
            tmp = self.bytes()
        self.pack(obj.value)
        return

    def _pack_as_value(self, obj: ASValue):
        if isinstance(obj, ASValues.ASString):
            val = obj.value
            val = val.encode("utf-8", self._unicode_errors)
            n = len(val) + 1
            if n >= 2**32:
                raise ValueError("String is too large")
            self._pack_raw_header(n)
            self._pack_byte(AS_BYTES_STRING)
            self._buffer.write(val)
            tmp = self.bytes()
            return

        if isinstance(obj, ASValues.ASGeoJson):
            val = obj.value
            val = val.encode("utf-8", self._unicode_errors)
            n = len(val) + 1
            if n >= 2**32:
                raise ValueError("String is too large")
            self._pack_raw_header(n)
            self._pack_byte(AS_BYTES_GEOJSON)
            self._buffer.write(val)
            return

        if isinstance(obj, ASValues.ASPair):
            val = obj.value
            val1, val2 = val
            self._pack_array_header(2)
            self.pack(val1)
            self.pack(val2)
            return

        if isinstance(obj, ASValues.ASList):
            val = obj.value
            n = len(val)
            self._pack_array_header(n)
            for i in range(n):
                self._pack_as_value(val[i])
            return

        if isinstance(obj, ASValues.ASWildCard):
            wildCardExt = ExtType(ASVAL_CMP_EXT_TYPE, ASVAL_CMP_WILDCARD)
            super().pack(wildCardExt)
            return

        self.pack(obj.value)
        return

    def _pack_byte(self, byte):
        self._buffer.write(struct.pack("B", byte))
