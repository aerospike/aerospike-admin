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
"""Reading the export the server's `usage-export` info command returns."""

import datetime
import hashlib
import json
from typing import Any, Iterable

EXPORT_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DISPLAY_TIME_FORMAT = "%Y-%m-%d %H:%M:%S UTC"


def parse(document: bytes) -> dict[str, Any]:
    """The export's data object. ValueError when the document is not an export."""
    value = json.loads(document.decode("utf-8"))

    if not isinstance(value, dict) or not isinstance(value.get("data"), dict):
        raise ValueError("not a usage export")

    return value["data"]


def display_time(value: str) -> str:
    try:
        parsed = datetime.datetime.strptime(value, EXPORT_TIME_FORMAT)
    except (TypeError, ValueError):
        return value

    return parsed.strftime(DISPLAY_TIME_FORMAT)


def ns_hash(cluster: str, name: str) -> str:
    """The server's name for a namespace in the export."""
    return hashlib.sha256((cluster + name).encode()).hexdigest()[:16]


def _records(data: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        record["data"]
        for record in data.get("records") or []
        if isinstance(record, dict) and isinstance(record.get("data"), dict)
    ]


def _samples(data: dict[str, Any]) -> list[dict[str, Any]]:
    samples = [
        sample["data"]
        for record in _records(data)
        for sample in record.get("samples") or []
        if isinstance(sample, dict) and isinstance(sample.get("data"), dict)
    ]

    return sorted(samples, key=lambda s: (str(s.get("date")), str(s.get("time"))))


def account(data: dict[str, Any]) -> str:
    feature_key = data.get("feature_key") or {}
    name = feature_key.get("account-name", "")
    account_id = feature_key.get("account-ID", "")

    if name and account_id:
        return f"{name} ({account_id})"

    return name or account_id


def days(data: dict[str, Any]) -> str:
    dates = sorted(record.get("date", "") for record in _records(data))

    if not dates:
        return "none closed yet"

    if len(dates) == 1:
        return f"{dates[0]}, 1 day"

    return f"{dates[0]} to {dates[-1]}, {len(dates)} days"


def _license_usage(row: dict[str, Any]) -> float | None:
    """The contract's unique data: data_used / rf / (ratio / 1000)."""
    try:
        return row["data_used"] / row["rf"] / (row["ratio"] / 1000)
    except (KeyError, TypeError, ZeroDivisionError):
        return None


def _total_license_usage(rows: list[dict[str, Any]]) -> float | None:
    usages = [_license_usage(row) for row in rows]

    return None if None in usages else sum(usages)


def _time_of_day(sample: dict[str, Any]) -> str:
    try:
        return datetime.datetime.strptime(sample["time"], EXPORT_TIME_FORMAT).strftime(
            "%H:%M:%S"
        )
    except (KeyError, TypeError, ValueError):
        return str(sample.get("time", ""))


def sample_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per sample, oldest first, totalled over the sample's namespaces."""
    rows = []

    for sample in _samples(data):
        namespaces = sample.get("rows") or []
        rows.append(
            {
                "date": sample.get("date"),
                "time": _time_of_day(sample),
                "nodes": sample.get("nodes"),
                "nodes_reported": sample.get("nodes_reported"),
                "migrating": sample.get("migrating"),
                "data_used": sum(row.get("data_used", 0) for row in namespaces),
                "license_usage": _total_license_usage(namespaces),
            }
        )

    return rows


def latest_sample(data: dict[str, Any]) -> dict[str, Any] | None:
    samples = _samples(data)

    return samples[-1] if samples else None


def namespace_rows(
    sample: dict[str, Any], namespaces: Iterable[str]
) -> list[dict[str, Any]]:
    """The sample's namespaces, named where the hash matches a known name."""
    cluster = sample.get("cluster", "")
    names = {ns_hash(cluster, name): name for name in namespaces}

    return [
        {
            "namespace": names.get(row.get("ns"), row.get("ns")),
            "rf": row.get("rf"),
            "ratio": row.get("ratio") / 1000 if row.get("ratio") is not None else None,
            "data_used": row.get("data_used"),
            "license_usage": _license_usage(row),
        }
        for row in sample.get("rows") or []
    ]
