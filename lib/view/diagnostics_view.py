# Copyright 2025 Aerospike, Inc.
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
"""Table rendering for the collectinfo bundle diagnostics banner.

Every other Sheet lives under lib/view, and rendering one means knowing about
the global JSON-style flag and the global color state. Keeping that here leaves
the diagnostics with findings and prose, and leaves one place to change if the
renderer's globals ever move.
"""

import logging

from lib.view.sheet import Field, Projectors, Sheet, render
from lib.view.sheet.render import get_style_json
from lib.view.terminal import terminal

logger = logging.getLogger(__name__)

node_errors_sheet = Sheet(
    (
        Field("Node", Projectors.String("node_names", None)),
        Field("Sections", Projectors.String("data", "sections")),
        Field("Error", Projectors.String("data", "reason")),
    ),
    from_source=("data", "node_names"),
)


def render_node_errors_table(rows: dict[str, dict[str, str]]) -> str | None:
    """The per-node collection error table, or None to fall back to plain lines.

    Skipped under --json: the sheet renderer consults the global style flag,
    which would embed a JSON document inside the banner's prose. The banner is a
    human artifact regardless of the output mode.

    Rendered with color disabled: the global palette follows stdout, which says
    nothing about the stream the banner lands on, so a colored table would carry
    raw escapes into a redirected stderr.
    """
    if get_style_json():
        return None

    was_color_enabled = terminal.color_enabled
    terminal.enable_color(False)

    try:
        return render(
            node_errors_sheet,
            "Per-node collection errors",
            dict(data=rows, node_names={key: key for key in rows}),
            common=dict(principal="", self_node=""),
        )
    except Exception as e:
        logger.debug("Could not render node error table: %s", e, exc_info=True)
        return None
    finally:
        terminal.enable_color(was_color_enabled)
