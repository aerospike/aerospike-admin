# Copyright 2026 Aerospike, Inc.
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

import asyncio
import contextlib
import os
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from unittest.mock import patch

import bcrypt

from lib.live_cluster.client.assocket import ASSocket

HEARTBEAT_SEC = 0.005
STALL_SEC = 0.02
LIB_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "lib"
)

REPORT: list["Measurement"] = []


@dataclass
class Measurement:
    scenario: str
    wall: float = 0.0
    max_stall: float = 0.0
    stalled: float = 0.0
    info_calls: int = 0
    pool_probes: int = 0
    connects: int = 0
    failed_connects: int = 0
    logins: int = 0
    auths: int = 0
    hashes: int = 0
    timeouts: int = 0
    live_nodes: int | None = None
    blockers: Counter = field(default_factory=Counter)


class Probe:
    """Measures one scenario: event-loop stalls and the asadm line behind them, plus
    socket connects, logins, info calls, password hashes and timeouts."""

    def __init__(self, scenario: str):
        self.measurement = Measurement(scenario)
        self._patches = []

    async def __aenter__(self) -> Measurement:
        self._loop_thread = threading.get_ident()
        self._last_beat = time.monotonic()
        self._done = threading.Event()

        for target, attribute, new in self._counters():
            p = patch.object(target, attribute, new)
            p.start()
            self._patches.append(p)

        self._heartbeat = asyncio.create_task(self._beat())
        self._watchdog = threading.Thread(target=self._watch, daemon=True)
        self._watchdog.start()
        self._start = time.monotonic()

        return self.measurement

    async def __aexit__(self, *exc_info):
        now = time.monotonic()
        self.measurement.wall = now - self._start
        self._record_lag(now - self._last_beat - HEARTBEAT_SEC)
        self._heartbeat.cancel()

        with contextlib.suppress(asyncio.CancelledError):
            await self._heartbeat

        self._done.set()
        self._watchdog.join()

        for p in reversed(self._patches):
            p.stop()

        REPORT.append(self.measurement)

    async def _beat(self):
        while True:
            before = time.monotonic()
            await asyncio.sleep(HEARTBEAT_SEC)
            self._last_beat = time.monotonic()
            self._record_lag(self._last_beat - before - HEARTBEAT_SEC)

    def _record_lag(self, lag):
        if lag >= STALL_SEC:
            self.measurement.max_stall = max(self.measurement.max_stall, lag)
            self.measurement.stalled += lag

    def _watch(self):
        while not self._done.wait(HEARTBEAT_SEC):
            if time.monotonic() - self._last_beat >= STALL_SEC:
                frame = sys._current_frames().get(self._loop_thread)
                self.measurement.blockers[_locate(frame)] += HEARTBEAT_SEC

    def _counters(self):
        m = self.measurement

        def counted(original, counter):
            async def wrapper(sock, *args, **kwargs):
                setattr(m, counter, getattr(m, counter) + 1)

                try:
                    return await original(sock, *args, **kwargs)
                except asyncio.TimeoutError:
                    m.timeouts += 1
                    raise

            return wrapper

        connect = ASSocket.connect

        async def counted_connect(sock):
            m.connects += 1
            connected = await connect(sock)

            if not connected:
                m.failed_connects += 1

            return connected

        hashpw = bcrypt.hashpw

        def counted_hashpw(*args, **kwargs):
            m.hashes += 1
            return hashpw(*args, **kwargs)

        return [
            (ASSocket, "connect", counted_connect),
            (ASSocket, "login", counted(ASSocket.login, "logins")),
            (ASSocket, "authenticate", counted(ASSocket.authenticate, "auths")),
            (ASSocket, "is_connected", counted(ASSocket.is_connected, "pool_probes")),
            (ASSocket, "info", counted(ASSocket.info, "info_calls")),
            (bcrypt, "hashpw", counted_hashpw),
        ]


def _locate(frame) -> str:
    """Innermost asadm (lib/) frame of a blocked loop thread, else its innermost frame."""
    innermost = frame

    while frame is not None:
        filename = frame.f_code.co_filename

        if filename.startswith(LIB_DIR + os.sep):
            path = os.path.relpath(filename, os.path.dirname(LIB_DIR))
            return f"{path}:{frame.f_lineno} {frame.f_code.co_name}"

        frame = frame.f_back

    if innermost is None:
        return "unknown"

    filename = os.path.basename(innermost.f_code.co_filename)
    return f"{filename}:{innermost.f_lineno} {innermost.f_code.co_name}"


def format_report(measurements: list[Measurement]) -> str:
    rows = [
        (
            "scenario",
            "wall",
            "max stall",
            "stalled",
            "info (probes)",
            "connects (failed)",
            "logins/auths",
            "hashes",
            "timeouts",
            "live",
        )
    ]
    blockers = {}

    for m in measurements:
        rows.append(
            (
                m.scenario,
                f"{m.wall:.2f}s",
                f"{m.max_stall * 1000:.0f}ms",
                f"{m.stalled * 1000:.0f}ms",
                f"{m.info_calls} ({m.pool_probes})",
                f"{m.connects} ({m.failed_connects})",
                f"{m.logins}/{m.auths}",
                str(m.hashes),
                str(m.timeouts),
                "-" if m.live_nodes is None else str(m.live_nodes),
            )
        )
        blockers[m.scenario] = m.blockers.most_common(3)

    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    lines = []

    for row in rows:
        lines.append("  ".join(cell.ljust(width) for cell, width in zip(row, widths)))

        for where, seconds in blockers.get(row[0], []):
            lines.append(f"    blocked {seconds * 1000:.0f}ms at {where}")

    return "\n".join(lines)
