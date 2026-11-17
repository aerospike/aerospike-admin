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

import calendar
import io
import json
import logging
import os
import tarfile
import time
from dataclasses import dataclass
from typing import Any

from lib.base_controller import CommandHelp, ModifierHelp
from lib.live_cluster.client.types import ASInfoResponseError
from lib.live_cluster.get_controller import GetClusterMetadataController
from lib.utils import common, constants, usage_export, util

from .live_cluster_command_controller import LiveClusterCommandController

logger = logging.getLogger(__name__)

NO_USAGE_REPORTING = ("ERROR:4:", "ERROR:25:")


class UsageUnavailable(Exception):
    """The node that answered, its reply verbatim, and whether the cluster has
    usage reporting at all."""

    def __init__(self, node: str, reply: str, supported: bool = True):
        super().__init__(reply)
        self.node = node
        self.reply = reply
        self.supported = supported


@dataclass
class UsageExport:
    node: str
    document: bytes
    data: dict[str, Any]


async def usage_supported(cluster, builds=None) -> bool:
    """Whether every node runs a release with usage reporting. Older servers are
    never sent the command: they log every info command they do not know."""
    if builds is None:
        builds = await GetClusterMetadataController(cluster).get_builds(nodes="all")

    support = await util.check_version_support(
        feature_versions={"usage": constants.SERVER_USAGE_REPORTING_FIRST_VERSION},
        builds=builds,
    )

    return support["usage"]


async def fetch_usage(cluster) -> UsageExport:
    """Any node answers for the whole cluster, so the principal is asked."""
    try:
        replies = await cluster.info_usage(nodes="principal")
    except Exception as e:
        raise UsageUnavailable("", str(e))

    node, reply = next(iter(replies.items()))

    if isinstance(reply, bytes):
        try:
            return UsageExport(node, reply, usage_export.parse(reply))
        except ValueError as e:
            raise UsageUnavailable(node, f"could not decode the reply: {e}")

    if isinstance(reply, ValueError):
        raise UsageUnavailable(node, f"could not decode the reply: {reply}")

    if isinstance(reply, ASInfoResponseError):
        raise UsageUnavailable(
            node,
            reply.raw_response,
            supported=not reply.raw_response.startswith(NO_USAGE_REPORTING),
        )

    raise UsageUnavailable(node, str(reply))


def older_servers_message(command: str) -> str:
    return "'%s' is not supported on aerospike versions < %s" % (
        command,
        constants.SERVER_USAGE_REPORTING_FIRST_VERSION,
    )


def unavailable_message(command: str, error: UsageUnavailable) -> str:
    if not error.supported:
        return (
            f"'{command}' is not supported on this cluster "
            f"({error.node} replied {error.reply})."
        )

    if not error.node:
        return f"Failed to get usage: {error.reply}"

    return f"Failed to get usage from {error.node}: {error.reply}"


def log_unavailable(command: str, error: UsageUnavailable, hint: str = "") -> None:
    if error.supported:
        logger.error(unavailable_message(command, error))
    else:
        logger.warning(unavailable_message(command, error) + hint)


@CommandHelp(
    "Exports the cluster's usage records to a .tgz archive to send to Aerospike.",
    "Open the archive with 'asadm -cf <archive>' and run 'show usage' to view it.",
    "Needs server v. {} or later and a user with the user-admin privilege.".format(
        constants.SERVER_USAGE_REPORTING_FIRST_VERSION
    ),
    usage="[--output-prefix <prefix>]",
    modifiers=(ModifierHelp("--output-prefix", "Output file name prefix."),),
    short_msg="Exports the cluster's usage records",
)
class CollectusageController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set()

    async def _do_default(self, line):
        output_prefix = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--output-prefix",
            return_type=str,
            default="",
            modifiers=self.modifiers,
            mods=self.mods,
        )
        output_prefix = util.strip_string(output_prefix)

        if line:
            logger.error("Unrecognized option(s): {}".format(", ".join(line)))

        builds = await self.cluster.info_build(nodes="all")
        expected_nodes = sorted(builds)
        builds = util.filter_exceptions(builds)

        if not await usage_supported(self.cluster, builds):
            logger.warning(
                "%s. Use 'collect info' instead.",
                older_servers_message("collect usage"),
            )
            return

        try:
            export = await fetch_usage(self.cluster)
        except UsageUnavailable as e:
            log_unavailable("collect usage", e, " Use 'collect info' instead.")
            return

        try:
            names = await self.cluster.info("cluster-name", nodes=[export.node])
            cluster_name = names.get(export.node)
        except Exception:
            cluster_name = None

        timestamp = time.gmtime()
        path = common.get_usage_file_path(timestamp, output_prefix)
        meta = {
            "meta_format_version": 1,
            "asadm_version": str(self.asadm_version),
            "collected_ts_utc": time.strftime(
                constants.COLLECTINFO_TIMESTAMP_FORMAT, timestamp
            ),
            "cluster_name": cluster_name if isinstance(cluster_name, str) else None,
            "cluster_uuid": export.data.get("cluster"),
            "expected_nodes": expected_nodes,
            "responded_nodes": sorted(builds),
            "usage_node": export.node,
        }
        output_time = time.strftime("%Y%m%d_%H%M%S", timestamp)
        top_dir = os.path.basename(path).removesuffix(".tgz")
        members = {
            f"{output_time}_{constants.COLLECTINFO_USAGE_FILENAME}": export.document,
            f"{output_time}_usage_meta.json": json.dumps(meta, indent=2).encode(),
        }

        try:
            with tarfile.open(path, "x:gz") as tar:
                for name, data in members.items():
                    member = tarfile.TarInfo(f"{top_dir}/{name}")
                    member.size = len(data)
                    member.mtime = calendar.timegm(timestamp)
                    tar.addfile(member, io.BytesIO(data))
        except OSError as e:
            logger.error("Failed to write %s: %s", path, e)
            return

        self.view.print_usage_saved(export.data, path, os.path.getsize(path))
