from typing import TypeVar

from lib.utils.common import UDAEntryNamespaceDict


T = TypeVar("T")

# TODO: Could be moved to its own utils.types module.
NodeDict = dict[str, T]
DatacenterDict = dict[str, T]
NamespaceDict = dict[str, T]
UsersDict = dict[str, T]
