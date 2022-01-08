import asyncio
from lib.utils import common, util
from lib.base_controller import CommandHelp

from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp(
    "Displays summary of Aerospike cluster.",
    "  Options:",
    "    -l                        - Enable to display namespace output in List view. Default: Table view",
    "    --enable-ssh              - Enables the collection of system statistics from a remote server.",
    "    --ssh-user   <string>     - Default user ID for remote servers. This is the ID of a user of the",
    "                                system, not the ID of an Aerospike user.",
    "    --ssh-pwd    <string>     - Default password or passphrase for key for remote servers. This is the",
    "                                user's password for logging into the system, not a password for logging",
    "                                into Aerospike.",
    "    --ssh-port   <int>        - Default SSH port for remote servers. Default: 22",
    "    --ssh-key    <string>     - Default SSH key (file path) for remote servers.",
    "    --ssh-cf     <string>     - Remote System Credentials file path.",
    "                                If the server credentials are not in the credentials file, then",
    "                                authentication is attempted with the default credentials.",
    "                                File format : each line should contain <IP[:PORT]>,<USER_ID>,",
    "                                <PASSWORD or PASSPHRASE>,<SSH_KEY>",
    "                                Example:  1.2.3.4,uid,pwd",
    "                                          1.2.3.4:3232,uid,pwd",
    "                                          1.2.3.4:3232,uid,,key_path",
    "                                          1.2.3.4:3232,uid,passphrase,key_path",
    "                                          [2001::1234:10],uid,pwd",
    "                                          [2001::1234:10]:3232,uid,,key_path",
    "    --agent-host    <host>    - Host IP of the Unique-Data-Agent to collect license data usage.",
    "    --agent-port    <int>     - Port of the Unique-Data-Agent. Default: 8080",
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

        default_user = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-user",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        default_pwd = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-pwd",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        default_ssh_port = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-port",
            return_type=int,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        default_ssh_key = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-key",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        credential_file = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--ssh-cf",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        agent_host = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--agent-host",
            return_type=str,
            default=None,
            modifiers=self.modifiers,
            mods=self.mods,
        )

        agent_port = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--agent-port",
            return_type=str,
            default="8080",
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
            default_user=default_user,
            default_pwd=default_pwd,
            default_ssh_key=default_ssh_key,
            default_ssh_port=default_ssh_port,
            credential_file=credential_file,
            commands=["lsb"],
            collect_remote_data=enable_ssh,
        )
        kernel_version = self.cluster.info_system_statistics(
            nodes=self.nodes,
            default_user=default_user,
            default_pwd=default_pwd,
            default_ssh_key=default_ssh_key,
            default_ssh_port=default_ssh_port,
            credential_file=credential_file,
            commands=["uname"],
            collect_remote_data=enable_ssh,
        )

        license_usage_future = None

        if agent_host is not None:
            # Should happen synchronously so that we can cancel an notify in case of error.
            license_usage_future = asyncio.create_task(
                common.request_license_usage(agent_host, agent_port)
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
            self.cluster.info_get_config(nodes=self.nodes, stanza="service")
        )
        namespace_configs = asyncio.create_task(
            self.cluster.info_get_config(nodes=self.nodes, stanza="namespace")
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
        license_usage = {}

        if license_usage_future is not None:
            license_usage, error = await license_usage_future

            if error is not None:
                self.logger.error(
                    "Failed to retrieve license usage information : {}",
                    str(error),
                )

        service_stats = await service_stats
        namespace_stats = await namespace_stats
        xdr_dc_stats = await xdr_dc_stats
        service_configs = await service_configs
        namespace_configs = await namespace_configs

        return self.view.print_summary(
            common.create_summary(
                service_stats=service_stats,
                namespace_stats=namespace_stats,
                xdr_dc_stats=xdr_dc_stats,
                metadata=metadata,
                service_configs=service_configs,
                ns_configs=namespace_configs,
                license_data_usage=license_usage,
            ),
            list_view=enable_list_view,
        )
