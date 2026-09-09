# Copyright 2022-2025 Aerospike, Inc.
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

import base64
import logging
from typing import Optional

from msgpack.fallback import Packer, unpackb

from lib.live_cluster.client.ctx import ASValue, ASValues, CDTContext, CTXItem, CTXItems

logger = logging.getLogger(__name__)

AS_BYTES_STRING = 3
AS_BYTES_BLOB = 4
AS_BYTES_GEOJSON = 23
ASVAL_CMP_EXT_TYPE = 0xFF
ASVAL_CMP_WILDCARD = 0x00

# aerospike-server as/include/exp/exp_wire.h. An expression payload of
# [EXP_AEL_COMPILE, <ael-source>] tells the server to compile the AEL source
# rather than parse a compiled expression tree.
EXP_AEL_COMPILE = 128


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
        """
        For packing an ctx in order to create a secondary index.  The protocol
        for packing a CDT with a CTX has a slightly different format.
        """
        n = len(obj) * 2
        self.pack_array_header(n)

        for item in obj:
            self._pack_as_cdt_item(item)

        return

    def _pack_as_cdt_item(self, obj: CTXItem):
        if isinstance(obj, CTXItems.ListIndex):
            self.pack(CTXItemWireType.AS_CDT_CTX_LIST_INDEX)
        elif isinstance(obj, CTXItems.ListRank):
            self.pack(CTXItemWireType.AS_CDT_CTX_LIST_RANK)
        elif isinstance(obj, CTXItems.ListValue):
            self.pack(CTXItemWireType.AS_CDT_CTX_LIST_VALUE)
        elif isinstance(obj, CTXItems.MapIndex):
            self.pack(CTXItemWireType.AS_CDT_CTX_MAP_INDEX)
        elif isinstance(obj, CTXItems.MapRank):
            self.pack(CTXItemWireType.AS_CDT_CTX_MAP_RANK)
        elif isinstance(obj, CTXItems.MapKey):
            self.pack(CTXItemWireType.AS_CDT_CTX_MAP_KEY)
        elif isinstance(obj, CTXItems.MapValue):
            self.pack(CTXItemWireType.AS_CDT_CTX_MAP_VALUE)
        self.pack(obj.value)
        return

    def _pack_as_value(self, obj: ASValue):
        if isinstance(obj, ASValues.ASString):
            val = obj.value
            val = chr(AS_BYTES_STRING) + val
            self.pack(val)
            return

        if isinstance(obj, ASValues.ASBytes):
            val = obj.value
            val = chr(AS_BYTES_BLOB) + val.decode("utf-8")
            self.pack(val)
            return

        """
        Not used. Here for reference in case one day they are.
        """

        # if isinstance(obj, ASValues.ASGeoJson):
        #     val = obj.value
        #     val = chr(AS_BYTES_GEOJSON) + val
        #     self.pack(val)
        #     return

        # if isinstance(obj, ASValues.ASList):
        #     val = obj.value
        #     n = len(val)
        #     self._pack_array_header(n)
        #     for i in range(n):
        #         self._pack_as_value(val[i])
        #     return

        # if isinstance(obj, ASValues.ASWildCard):
        #     wildCardExt = ExtType(ASVAL_CMP_EXT_TYPE, ASVAL_CMP_WILDCARD)
        #     super().pack(wildCardExt)
        #     return

        self.pack(obj.value)
        return


def pack_ael_expression(ael_src: str) -> str:
    """
    Wrap AEL source in the server's [EXP_AEL_COMPILE, <ael-source>] envelope and
    return it base64 encoded, ready to be sent as the "exp" info parameter.
    """
    packer = ASPacker()
    packer.pack([EXP_AEL_COMPILE, ael_src])

    return base64.b64encode(packer.bytes()).decode("utf-8")


def unpack_ael_expression(exp_base64: str) -> Optional[str]:
    """
    Return the AEL source carried by a base64 encoded
    [EXP_AEL_COMPILE, <ael-source>] envelope. Returns None for anything else,
    including a compiled expression tree or an unparsable value. Never raises.
    """
    try:
        envelope = unpackb(base64.b64decode(exp_base64, validate=True), raw=False)
    except Exception as e:
        logger.debug("Unable to unpack expression %s: %s", exp_base64, e)
        return None

    if (
        isinstance(envelope, (list, tuple))
        and len(envelope) == 2
        and envelope[0] == EXP_AEL_COMPILE
        and isinstance(envelope[1], str)
        and envelope[1]
    ):
        return envelope[1]

    return None
