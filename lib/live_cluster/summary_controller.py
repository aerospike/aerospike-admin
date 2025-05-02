# Copyright 2021-2025 Aerospike, Inc.
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
import logging
from typing import Union
from lib.base_controller import CommandHelp, ModifierHelp
from lib.live_cluster.constants import SSH_MODIFIER_HELP, SSH_MODIFIER_USAGE
from lib.utils import common, util
from lib.utils.constants import (
    CONFIG_NAMESPACE,
    CONFIG_SECURITY,
    CONFIG_SERVICE,
)

from .live_cluster_command_controller import LiveClusterCommandController

logger = logging.getLogger(__name__)


@CommandHelp(
    "Displays summary of Aerospike cluster.",
    usage=f"[-l] [{SSH_MODIFIER_USAGE}]",
    modifiers=(
        ModifierHelp(
            "-l",
            "Enable to display namespace output in list view.",
            default="table view",
        ),
        *SSH_MODIFIER_HELP,
    ),
)
class SummaryController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with"])

    async def _do_default(self, line):
        enable_list_view = util.check_arg_and_delete_from_mods(
            line=line, arg="-l", default=False, modifiers=self.modifiers, mods=self.mods
        )

        enable_ssh = util.check_arg_and_delete_from_mods(
            line=line,
            arg="--enable-ssh",
            default=False,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_user = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-user",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_pwd = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-pwd",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_port = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-port",
            return_type=int,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_key = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-key",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        ssh_key_pwd = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-key-pwd",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        server_version = asyncio.create_task(
            self.cluster.info("build", nodes=self.nodes)
        )
        server_edition = asyncio.create_task(
            self.cluster.info("version", nodes=self.nodes)
        )
        cluster_name = asyncio.create_task(
            self.cluster.info("cluster-name", nodes=self.nodes)
        )

        os_version = self.cluster.info_system_statistics(
            nodes=self.nodes,
            ssh_user=ssh_user,
            ssh_pwd=ssh_pwd,
            ssh_key=ssh_key,
            ssh_key_pwd=ssh_key_pwd,
            ssh_port=ssh_port,
            commands=["lsb"],
            enable_ssh=enable_ssh,
        )
        kernel_version = self.cluster.info_system_statistics(
            nodes=self.nodes,
            ssh_user=ssh_user,
            ssh_pwd=ssh_pwd,
            ssh_key_pwd=ssh_key_pwd,
            ssh_port=ssh_port,
            commands=["uname"],
            enable_ssh=enable_ssh,
        )

        service_stats = asyncio.create_task(
            self.cluster.info_statistics(nodes=self.nodes)
        )
        namespace_stats = asyncio.create_task(
            self.cluster.info_all_namespace_statistics(nodes=self.nodes)
        )
        xdr_dc_stats = asyncio.create_task(
            self.cluster.info_all_dc_statistics(nodes=self.nodes)
        )
        service_configs = asyncio.create_task(
            self.cluster.info_get_config(nodes=self.nodes, stanza=CONFIG_SERVICE)
        )
        namespace_configs = asyncio.create_task(
            self.cluster.info_get_config(nodes=self.nodes, stanza=CONFIG_NAMESPACE)
        )
        security_configs = asyncio.create_task(
            self.cluster.info_get_config(nodes=self.nodes, stanza=CONFIG_SECURITY)
        )

        metadata = {}
        metadata["server_version"] = {}
        metadata["server_build"] = {}
        metadata["cluster_name"] = {}

        server_version = await server_version
        server_edition = await server_edition
        cluster_name = await cluster_name

        for node, version in server_version.items():
            if not version or isinstance(version, Exception):
                continue

            metadata["server_build"][node] = version

            if (
                node in server_edition
                and server_edition[node]
                and not isinstance(server_edition[node], Exception)
            ):
                if "enterprise" in server_edition[node].lower():
                    metadata["server_version"][node] = "E-%s" % (str(version))
                elif "community" in server_edition[node].lower():
                    metadata["server_version"][node] = "C-%s" % (str(version))
                elif "federal" in server_edition[node].lower():
                    metadata["server_version"][node] = "F-%s" % (str(version))
                else:
                    metadata["server_version"][node] = version

            else:
                metadata["server_version"][node] = version

            if (
                node in cluster_name
                and cluster_name[node]
                and not isinstance(cluster_name[node], Exception)
            ):
                metadata["cluster_name"][node] = cluster_name[node]

        os_version = await os_version
        kernel_version = await kernel_version

        try:
            try:
                kernel_version = util.flip_keys(kernel_version)["uname"]
            except Exception:
                pass

            os_version = util.flip_keys(os_version)["lsb"]

            if kernel_version:
                for node, version in os_version.items():
                    if not version or isinstance(version, Exception):
                        continue

                    if (
                        node not in kernel_version
                        or not kernel_version[node]
                        or isinstance(kernel_version[node], Exception)
                    ):
                        continue

                    try:
                        ov = version["description"]
                        kv = kernel_version[node]["kernel_release"]
                        version["description"] = str(ov) + " (%s)" % str(kv)
                    except Exception:
                        pass

        except Exception:
            pass

        metadata["os_version"] = os_version

        service_stats = await service_stats
        namespace_stats = await namespace_stats
        xdr_dc_stats = await xdr_dc_stats
        service_configs = await service_configs
        namespace_configs = await namespace_configs
        security_configs = await security_configs

        self.view.print_summary(
            common.create_summary(
                service_stats=service_stats,
                namespace_stats=namespace_stats,
                xdr_dc_stats=xdr_dc_stats,
                metadata=metadata,
                service_configs=service_configs,
                ns_configs=namespace_configs,
                security_configs=security_configs,
            ),
            list_view=enable_list_view,
        )
