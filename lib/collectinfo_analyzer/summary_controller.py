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

from lib.base_controller import CommandHelp, ModifierHelp
from lib.utils import common, constants, util

from .collectinfo_command_controller import CollectinfoCommandController


@CommandHelp(
    "Displays summary of Aerospike cluster.",
    usage=f"[-l]",
    modifiers=(
        ModifierHelp(
            "-l",
            "Enable to display namespace output in list view.",
            default="table view",
        ),
    ),
)
class SummaryController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set([])

    def _do_default(self, line):
        enable_list_view = util.check_arg_and_delete_from_mods(
            line=line, arg="-l", default=False, modifiers=self.modifiers, mods=self.mods
        )

        service_stats = self.log_handler.info_statistics(stanza=constants.STAT_SERVICE)
        namespace_stats = self.log_handler.info_statistics(
            stanza=constants.STAT_NAMESPACE
        )
        xdr_dc_stats = self.log_handler.info_statistics(stanza=constants.STAT_XDR)

        service_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_SERVICE
        )
        namespace_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_NAMESPACE
        )
        security_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_SECURITY
        )

        os_version = self.log_handler.get_sys_data(stanza="lsb")
        kernel_version = self.log_handler.get_sys_data(stanza="uname")
        server_version = self.log_handler.info_meta_data(stanza="asd_build")
        server_edition = self.log_handler.info_meta_data(stanza="edition")

        last_timestamp = sorted(service_stats.keys())[-1]

        cluster_name = {}

        try:
            cinfo_log = self.log_handler.get_cinfo_log_at(timestamp=last_timestamp)
            cluster_name = cinfo_log.get_cluster_name()
        except Exception:
            pass

        metadata = {
            "os_version": {},
            "server_version": {},
            "server_build": {},
            "cluster_name": {},
        }

        server_version = server_version[last_timestamp]
        server_edition = server_edition[last_timestamp]

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

        os_version = os_version[last_timestamp]
        kernel_version = kernel_version[last_timestamp]

        try:
            if kernel_version:
                for node, version in os_version.items():
                    metadata["os_version"][node] = {}
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
                        metadata["os_version"][node]["description"] = str(
                            ov
                        ) + " (%s)" % str(kv)
                    except Exception:
                        pass

        except Exception:
            pass

        self.view.print_summary(
            common.create_summary(
                service_stats=service_stats[last_timestamp],
                namespace_stats=namespace_stats[last_timestamp],
                xdr_dc_stats=xdr_dc_stats[last_timestamp],
                metadata=metadata,
                service_configs=service_configs[last_timestamp],
                ns_configs=namespace_configs[last_timestamp],
                security_configs=security_configs[last_timestamp],
            ),
            list_view=enable_list_view,
        )
