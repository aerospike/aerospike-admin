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

import logging

from lib.base_controller import CommandController
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)

logger = logging.getLogger(__name__)


def has_node_data(data: dict) -> bool:
    """Whether any node, at any timestamp, holds a non-empty value."""
    return any(
        value and not isinstance(value, Exception)
        for nodes in data.values()
        if isinstance(nodes, dict)
        for value in nodes.values()
    )


def warn_no_data(command: str, what: str, filter_desc: str = "") -> None:
    """Say on stderr that the bundle has nothing for a command to show."""
    if filter_desc:
        logger.warning(
            "%s: no %s match %s in this collectinfo.", command, what, filter_desc
        )
    else:
        logger.warning("%s: no %s in this collectinfo.", command, what)


class CollectinfoCommandController(CommandController):
    def __init__(self, log_handler: CollectinfoLogHandler):
        CollectinfoCommandController.log_handler = log_handler
