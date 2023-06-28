# Copyright 2023 Aerospike, Inc.
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

from typing import TypeVar, TypedDict
from typing_extensions import NotRequired

T = TypeVar("T")

# TODO: Could be moved to its own utils.types module.
NodeIP = str
DC = str
NS = str
SET = str
METRIC = str
Users = str
NodeDict = dict[NodeIP, T]
DatacenterDict = dict[DC, T]
NamespaceDict = dict[NS, T]
UsersDict = dict[Users, T]


class StopWritesEntry(TypedDict):
    metric: str
    metric_usage: int | float
    stop_writes: bool
    metric_threshold: NotRequired[int | float]
    config: NotRequired[str]
    namespace: NotRequired[str]
    set: NotRequired[str]


StopWritesEntryKey = tuple[NS, SET, METRIC]
StopWritesDict = NodeDict[dict[StopWritesEntryKey, StopWritesEntry]]
