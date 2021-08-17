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
)
class SummaryController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with"])

    def _do_default(self, line):
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

        service_stats = util.Future(
            self.cluster.info_statistics, nodes=self.nodes
        ).start()
        namespace_stats = util.Future(
            self.cluster.info_all_namespace_statistics, nodes=self.nodes
        ).start()
        xdr_dc_stats = util.Future(
            self.cluster.info_all_dc_statistics, nodes=self.nodes
        ).start()

        service_configs = util.Future(
            self.cluster.info_get_config, nodes=self.nodes, stanza="service"
        ).start()
        namespace_configs = util.Future(
            self.cluster.info_get_config, nodes=self.nodes, stanza="namespace"
        ).start()
        cluster_configs = util.Future(
            self.cluster.info_get_config, nodes=self.nodes, stanza="cluster"
        ).start()

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
        server_version = util.Future(
            self.cluster.info, "build", nodes=self.nodes
        ).start()

        server_edition = util.Future(
            self.cluster.info, "version", nodes=self.nodes
        ).start()

        cluster_name = util.Future(
            self.cluster.info, "cluster-name", nodes=self.nodes
        ).start()

        service_stats = service_stats.result()
        namespace_stats = namespace_stats.result()
        xdr_dc_stats = xdr_dc_stats.result()
        service_configs = service_configs.result()
        namespace_configs = namespace_configs.result()
        cluster_configs = cluster_configs.result()
        server_version = server_version.result()
        server_edition = server_edition.result()
        cluster_name = cluster_name.result()

        metadata = {}
        metadata["server_version"] = {}
        metadata["server_build"] = {}
        metadata["cluster_name"] = {}

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

        return util.Future(
            self.view.print_summary,
            common.create_summary(
                service_stats=service_stats,
                namespace_stats=namespace_stats,
                xdr_dc_stats=xdr_dc_stats,
                metadata=metadata,
                service_configs=service_configs,
                ns_configs=namespace_configs,
                cluster_configs=cluster_configs,
            ),
            list_view=enable_list_view,
        )
