from typing import TypeVar


T = TypeVar("T")

# TODO: Could be moved to its own utils.types module.
NodeDict = dict[str, T]
DatacenterDict = dict[str, T]
NamespaceDict = dict[str, T]
UsersDict = dict[str, T]
