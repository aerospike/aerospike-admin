import asyncio
from datetime import datetime
import logging
import os
from typing import Callable
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node
from lib.live_cluster.ssh import (
    FileTransfer,
    LocalDst,
    RemoteSrc,
    SFTPError,
    SSHConnection,
    SSHConnectionError,
    SSHConnectionFactory,
    SSHError,
)
from lib.utils import util
from lib.utils.constants import NodeSelection, NodeSelectionType

PathGenerator = Callable[[Node, str], str]
logger = logging.getLogger(__name__)


def format_node_msg(node: Node, msg: str) -> str:
    return f"({node.ip}:{node.port}) {msg}"


class LogFileDownloaderException(Exception):
    pass


class _LogInfo:
    """Base class for log info used by LogFileDownloader to
    store information about individual logs as they move through
    the different stages of the download process.
    """

    def __init__(self, original_src: str) -> None:
        """
        Arguments:
            original_src {str} -- The original path of the log file.
        """
        self.original_src = original_src
        self.local_destination = ""
        self.skip = False


class _LocalLogInfo(_LogInfo):
    pass


class _RemoteLogInfo(_LogInfo):
    """A data class for storing information about a remote log file that is in the
    process of being downloaded.
    """

    def __init__(self, original_src: str) -> None:
        super().__init__(original_src)
        self.tmp_src = ""

    def to_file_transfer(self) -> tuple[RemoteSrc, LocalDst]:
        """Convert the log info to a tuple that can be used by the FileTransfer class.

        Returns:
            tuple[RemoteSrc, LocalDst] -- A tuple containing the remote source and local
        """
        return (self.tmp_src, self.local_destination)


class LogFileDownloader:
    """A class for downloading logs from a cluster and placing them in a user defined
    location.
    """

    def __init__(
        self,
        cluster: Cluster,
        ssh_factory: SSHConnectionFactory | None = None,
        exception_handler: Callable[[Exception, Node], None] | None = None,
    ):
        """Constructor

        Arguments:
            cluster {Cluster} -- Aerospike cluster to download logs from

        Keyword Arguments:
            ssh_factory {SSHConnectionFactory | None} -- An optional factory for
            downloading remote logs. If not set, only local log files can be downloaded.
            exception_handler {Callable[[Exception, Node], None] | None} -- An optional
            callback called with every exception and the associated node that occurs
            during the process of downloading/moving/compressing the file. If not set
            the first exception is raised. (default: {None})
        """
        self.cluster = cluster
        self.ssh_factory = ssh_factory
        self.exception_handler = exception_handler

    async def download(
        self,
        path_gen_func: PathGenerator,
        node_select: NodeSelectionType = NodeSelection.ALL,
    ):
        """Download logs from nodes in the cluster.

        Arguments:
            path_gen_func {PathGenerator} -- Generator function that takes a node and a
            log path and returns a local writable path to store the log. The returned
            path cannot be a directory.


        Keyword Arguments:
            node_select {NodeSelectionType} -- Specify the nodes to download logs from.
            (default: {NodeSelection.ALL})

        Returns:
            Exceptions -- A list of exceptions that occurred during the download
            process.
        """
        nodes = self.cluster.get_nodes(nodes=node_select)
        await asyncio.gather(
            *[self._download_node_logs(node, path_gen_func) for node in nodes],
        )

    async def _create_local_console_log(self, node: Node, tmp_path: str):
        logger.info(
            format_node_msg(
                node,
                f"Local node is logging to console. Storing console log in {tmp_path}",
            )
        )
        if not os.path.exists(os.path.dirname(tmp_path)):
            os.makedirs(os.path.dirname(tmp_path), exist_ok=True)

        p = await util.async_shell_command(
            f"journalctl -u aerospike -a -o cat --since '1 day ago' | grep GMT > {tmp_path}"
        )

        if p is None or p.returncode != 0:
            msg = "Unknown exception occurred while running journalctl"

            if p is not None and p.stderr is not None:
                stderr = await p.stderr.read()
                msg = util.bytes_to_str(stderr).split("\n")[0]

            raise LogFileDownloaderException(
                format_node_msg(
                    node,
                    f"Failed to generate log file from local console log: {msg}",
                )
            )

    async def _create_remote_console_log(
        self, node: Node, conn: SSHConnection, tmp_path: str
    ):
        logger.info(
            format_node_msg(
                node, f"Node is logging to console. Storing console log in {tmp_path}"
            )
        )
        try:
            p = await conn.run(
                f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > {tmp_path}'
            )

            if p.returncode != 0:
                msg = "Unknown exception occurred while running journalctl"

                if p.stderr is not None:
                    msg = util.bytes_to_str(p.stderr).split("\n")[0]

                logger.error(
                    format_node_msg(
                        node,
                        f"Failed to copy journald to {tmp_path}: {msg}",
                    )
                )
                raise LogFileDownloaderException(
                    format_node_msg(
                        node,
                        f"Failed to copy journald to {tmp_path}: {msg}",
                    )
                )
            logger.debug(
                format_node_msg(node, f"Successfully copied journald to {tmp_path}")
            )
        except SSHError as e:
            logger.error(
                format_node_msg(node, f"Failed to copy journald to {tmp_path} : {e}")
            )
            raise

    def _generate_dst_paths(
        self,
        node: Node,
        logs: list[_LogInfo],
        path_gen_func: PathGenerator,
    ):
        for log in logs:
            log.local_destination = path_gen_func(node, log.original_src)
            logger.debug(
                format_node_msg(
                    node,
                    f"{log.original_src} will be copied to {log.local_destination}",
                )
            )

        return logs

    async def _compress_remote_logs(
        self,
        node: Node,
        conn: SSHConnection,
        logs: list[_RemoteLogInfo],
    ) -> list[_RemoteLogInfo]:
        async def _compress_log(log: _RemoteLogInfo):
            if log.skip:
                return

            log.local_destination = (
                log.local_destination
                if log.local_destination.endswith(".gz")
                else log.local_destination + ".gz"
            )
            log.tmp_src = log.tmp_src + ".gz"
            logger.info(
                format_node_msg(
                    node, f"Compressing {log.original_src} to {log.tmp_src}"
                )
            )
            try:
                p = await conn.run(f"gzip -c {log.original_src} > {log.tmp_src}")

                if p.returncode != 0:
                    msg = "Unknown exception occurred while running gzip"

                    if p.stderr is not None:
                        msg = util.bytes_to_str(p.stderr).split("\n")[0]
                    raise LogFileDownloaderException(
                        format_node_msg(
                            node,
                            f"Failed to compress {log.original_src}: {msg}",
                        )
                    )
            except (SSHError, LogFileDownloaderException) as e:
                log.skip = True

                if isinstance(e, LogFileDownloaderException):
                    logger.error(e)
                else:
                    logger.error(
                        format_node_msg(
                            node, f"Failed to compress {log.original_src}: {e}"
                        )
                    )

                if self.exception_handler:
                    self.exception_handler(e, node)
                else:
                    raise

        await asyncio.gather(*[_compress_log(log) for log in logs])
        return logs

    async def _compress_local_logs(
        self,
        node: Node,
        logs: list[_LocalLogInfo],
    ) -> list[_LocalLogInfo]:
        async def _compress_log(log: _LocalLogInfo):
            if log.skip:
                return

            log.local_destination = log.local_destination + ".gz"
            logger.info(
                format_node_msg(
                    node,
                    f"Compressing local file {log.original_src} to {log.local_destination}",
                )
            )

            if not os.path.exists(os.path.dirname(log.local_destination)):
                os.makedirs(os.path.dirname(log.local_destination), exist_ok=True)

            p = await util.async_shell_command(
                f"gzip -c {log.original_src} > {log.local_destination}"
            )

            if p is None or p.returncode != 0:
                msg = "Unknown exception occurred while running gzip"

                if p is not None and p.stderr is not None:
                    stderr = await p.stderr.read()
                    msg = util.bytes_to_str(stderr).split("\n")[0]

                e = LogFileDownloaderException(
                    format_node_msg(
                        node,
                        f"Failed to compress local log file {log.original_src}: {msg}",
                    )
                )
                logger.error(e)
                if self.exception_handler:
                    self.exception_handler(e, node)
                else:
                    raise e

        await asyncio.gather(*[_compress_log(log) for log in logs])
        return logs

    async def _move_local_logs(self, node: Node, path_gen_func: PathGenerator):
        logs = await node.info_logs_ids()
        log_file_info: list[_LocalLogInfo] = []

        for log in logs:
            info = _LocalLogInfo(log)
            log_file_info.append(info)

        self._generate_dst_paths(
            node,
            log_file_info,  # type: ignore
            path_gen_func,
        )

        for log in log_file_info:
            try:
                if "stderr" == log.original_src:
                    log.original_src = log.local_destination
                    await self._create_local_console_log(node, log.local_destination)
            except LogFileDownloaderException as e:
                log.skip = True
                logger.error(str(e))
                if self.exception_handler:
                    self.exception_handler(e, node)
                else:
                    raise

        await self._compress_local_logs(node, log_file_info)

    async def _generate_remote_tmp_paths(
        self, conn: SSHConnection, tmp_prefix: str, file_paths: list[_RemoteLogInfo]
    ):
        async with await conn.start_sftp_client() as sftp_session:
            await sftp_session.makedirs(tmp_prefix)

        for log in file_paths:
            if log.original_src == "stderr":
                log.tmp_src = os.path.join(tmp_prefix, log.original_src + ".log")
            else:
                log.tmp_src = os.path.join(
                    tmp_prefix, os.path.basename(log.original_src)
                )

        return file_paths

    async def _download_remote_logs(self, node: Node, path_gen_func: PathGenerator):
        time_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
        tmp_file_prefix = f"/tmp/{time_prefix}/{node.node_id}/"

        if not self.ssh_factory:
            raise LogFileDownloaderException(
                "SSHConnectionFactory is not defined. Cannot download remote logs."
            )

        try:
            async with await self.ssh_factory.create_connection(node.ip) as conn:
                try:
                    log_file_info: list[_RemoteLogInfo] = []
                    logs = await node.info_logs_ids()

                    for log in logs:
                        info = _RemoteLogInfo(log)
                        log_file_info.append(info)

                    self._generate_dst_paths(node, log_file_info, path_gen_func)  # type: ignore
                    log_file_info = await self._generate_remote_tmp_paths(
                        conn, tmp_file_prefix, log_file_info
                    )

                    for log in log_file_info:
                        if "stderr" == log.original_src:
                            log.original_src = log.tmp_src
                            try:
                                await self._create_remote_console_log(
                                    node, conn, log.tmp_src
                                )
                            except (SSHError, LogFileDownloaderException) as e:
                                logger.error(
                                    format_node_msg(
                                        node,
                                        f"Failed to create log from remote console log: {e}",
                                    )
                                )
                                log.skip = True
                                if self.exception_handler:
                                    self.exception_handler(e, node)
                                else:
                                    raise

                    log_file_info = await self._compress_remote_logs(
                        node, conn, log_file_info
                    )
                    file_paths = [
                        log.to_file_transfer() for log in log_file_info if not log.skip
                    ]

                    errors = await FileTransfer.remote_to_local(
                        file_paths,
                        conn,
                        return_exceptions=self.exception_handler is not None,
                    )

                    for err in errors:
                        if err is None:
                            continue

                        if self.exception_handler:
                            logger.error(
                                format_node_msg(node, f"Failed to download log: {err}")
                            )
                            self.exception_handler(err, node)
                        # else:
                        #     remote_to_local already raises the first exception it encounters
                finally:
                    try:
                        async with await conn.start_sftp_client() as sftp_session:
                            await sftp_session.rmtree(tmp_file_prefix)
                    except Exception as e:
                        logger.debug(
                            format_node_msg(
                                node,
                                f"Failed to remove tmp dir. Maybe it never existed: {e}",
                            )
                        )
        except SSHConnectionError as e:
            logger.error(
                format_node_msg(
                    node,
                    f"Unable to download logs from node. Couldn't SSH login to remote server: {e}",
                )
            )

            if self.exception_handler:
                self.exception_handler(e, node)
            else:
                raise e
        except SFTPError as e:
            logger.error(
                format_node_msg(
                    node,
                    f"Unable to download logs from node. This is likely an issue with your SFTP subsystem : {e}",
                )
            )

            if self.exception_handler:
                self.exception_handler(e, node)
            else:
                raise e
        except SSHError as e:
            logger.error(format_node_msg(node, f"Failed to download logs: {e}"))

            if self.exception_handler:
                self.exception_handler(e, node)
            else:
                raise e

    async def _download_node_logs(self, node: Node, path_gen_func: PathGenerator):
        if node.is_localhost():
            logger.info(format_node_msg(node, "Getting local logs..."))
            await self._move_local_logs(node, path_gen_func)
        elif self.ssh_factory:
            logger.info(format_node_msg(node, "Downloading remote logs..."))
            await self._download_remote_logs(node, path_gen_func)
        else:
            logger.info(
                format_node_msg(
                    node, "Skipping downloading remote logs. SSH is not enabled."
                )
            )
