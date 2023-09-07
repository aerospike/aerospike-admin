# Copyright 2023-2023 Aerospike, Inc.
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
from os import path
import os
import time

from lib.live_cluster.client.node import Node
from lib.live_cluster.logfile_downloader import LogFileDownloader
from lib.live_cluster.constants import SSH_MODIFIER_HELP, SSH_MODIFIER_USAGE
from lib.live_cluster import ssh

from lib.utils import common, util
from lib.utils.logger import LogFormatter, stderr_log_handler, logger as g_logger
from lib.base_controller import CommandHelp, ModifierHelp

from .live_cluster_command_controller import LiveClusterCommandController

logger = logging.getLogger(__name__)


@CommandHelp(
    "Collects logs for the local node and remote nodes if ssh is enabled and configured. If ssh is not available then it will collect logs from the local node only.",
    usage=f"[{SSH_MODIFIER_USAGE}] [--output-prefix <prefix>]",
    modifiers=(
        *SSH_MODIFIER_HELP,
        ModifierHelp("--output-prefix", "Output directory name prefix."),
    ),
    short_msg="Collects cluster logs",
)
class CollectlogsController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set(["with"])
        self.collectinfo_root_controller = None

    async def _gather_logs(
        self,
        logfile_prefix: str,
        enable_ssh: bool,
        ssh_user: str | None,
        ssh_pwd: str | None,
        ssh_key: str | None,
        ssh_key_pwd: str | None,
        ssh_port: int | None,
    ):
        logger.info("Collecting logs from nodes...")
        ssh_conn_factory = None

        if enable_ssh:
            ssh_config = ssh.SSHConnectionConfig(
                username=ssh_user,
                password=ssh_pwd,
                port=ssh_port,
                private_key=ssh_key,
                private_key_pwd=ssh_key_pwd,
            )

            try:
                ssh_conn_factory = ssh.SSHConnectionFactory(ssh_config)
            except FileNotFoundError as e:
                logger.error(f"Could not create SSH connection: {e}")
                return False

        count = 0

        def local_path_generator(node: Node, filename: str) -> str:
            nonlocal count
            count += 1

            if filename == "stderr":
                filename = "stderr.log"

            return logfile_prefix + node.node_id + "_" + path.basename(filename)  # type: ignore

        # Stores errors that occur after the connection is established
        download_errors = []
        connect_errors = []

        def error_handler(error: Exception, node: Node):
            if isinstance(error, ssh.SSHConnectionError):
                connect_errors.append(error)
            else:
                download_errors.append(error)

        """
        Returned errors are for connection issues. error_handler handles errors after
        authentication.
        """
        try:
            await LogFileDownloader(
                self.cluster, ssh_conn_factory, exception_handler=error_handler
            ).download(local_path_generator)
        except Exception as e:
            raise

        if not connect_errors and not download_errors:
            if count == 0 and not enable_ssh:
                logger.error(
                    "No logs were downloaded. Use --enable-ssh to download logs from remote nodes."
                )
                return False
            else:
                logger.info("Successfully downloaded logs from all nodes.")
        elif len(connect_errors) == len(self.cluster.get_nodes()):
            logger.error("Failed to download logs from all nodes.")
            return False
        elif connect_errors or download_errors:
            logger.error("Failed to download logs from some nodes.")

        return True

    def setup_loggers(self, individual_file_prefix: str):
        debug_file = individual_file_prefix + "collectinfo_debug.log"
        self.debug_output_handler = logging.FileHandler(debug_file)
        self.debug_output_handler.setLevel(logging.DEBUG)
        self.debug_output_handler.setFormatter(LogFormatter())
        self.loggers: list[logging.Logger | logging.Handler] = [
            g_logger,
            stderr_log_handler,  # Controls what is displayed to console
            logging.getLogger(common.__name__),
            logging.getLogger(LogFileDownloader.__module__),
        ]
        self.old_levels = [logger.level for logger in self.loggers]

        g_logger.setLevel(
            logging.DEBUG
        )  # This allows all logs to be logged to handlers

        for logger in self.loggers[1:]:
            # Only set the level to INFO if it is not already set to DEBUG or INFO.
            if logger.level > logging.INFO:
                logger.setLevel(logging.INFO)

        g_logger.addHandler(self.debug_output_handler)

    def teardown_loggers(self):
        g_logger.removeHandler(self.debug_output_handler)
        for logger, level in zip(self.loggers, self.old_levels):
            logger.setLevel(level)

        # TODO: clean up log levels

    ###########################################################################
    # Collectinfo caller functions

    async def _do_default(self, line):
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

        output_prefix = util.get_arg_and_delete_from_mods(
            line=line,
            arg="--output-prefix",
            return_type=str,
            default="",
            modifiers=self.modifiers,
            mods=self.mods,
        )
        output_prefix = util.strip_string(output_prefix)

        timestamp = time.gmtime()
        cf_path_info = common.get_collectinfo_path(
            timestamp,
            output_prefix=output_prefix,
        )

        os.makedirs(cf_path_info.log_dir, exist_ok=True)
        logfile_prefix = path.join(
            cf_path_info.log_dir,
            cf_path_info.files_prefix,
        )
        self.setup_loggers(logfile_prefix)

        try:
            # Coloring might writes extra characters to file, to avoid it we need to
            # disable terminal coloring
            try:
                if not await self._gather_logs(  # TODO: test username password
                    logfile_prefix,
                    enable_ssh,
                    ssh_user,
                    ssh_pwd,
                    ssh_key,
                    ssh_key_pwd,
                    ssh_port,
                ):
                    return
            except Exception as e:
                logger.error(e)
                return

            log_archive_path, success = common.archive_dir(cf_path_info.log_dir)

            if success:
                common.print_collect_summary(
                    log_archive_path,
                )
            else:
                logger.error(
                    "Failed to archive collectinfo logs. See earlier errors for more details."
                )
        finally:
            # printing collectinfo summary
            self.teardown_loggers()
