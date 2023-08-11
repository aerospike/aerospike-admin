import asyncio
from datetime import datetime
import logging
import os
from subprocess import CompletedProcess
import time
from typing import Callable, Iterator
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node
from lib.live_cluster.ssh import (
    FileTransfer,
    LocalDst,
    LocalSrc,
    RemoteSrc,
    SSHConnection,
    SSHConnectionConfig,
    SSHConnectionError,
    SSHConnectionFactory,
    SSHError,
)
from lib.utils import util

PathGenerator = Callable[[Node, str], str]
logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


def format_node_msg(node: Node, msg: str) -> str:
    return f"({node.ip}:{node.port}) {msg}"


class LogFileDownloaderException(Exception):
    pass


class _LogInfo:
    original_src: str  # Where the original log is on the remote node
    local_destination: str  # Where the log will be downloaded to
    skip: bool

    def __init__(self, original_src) -> None:
        self.original_src = original_src
        self.local_destination = ""
        self.skip = False


class _LocalLogInfo(_LogInfo):
    pass


class _RemoteLogInfo(_LogInfo):
    tmp_src: str  # Where the log will be moved to before it is downloaded

    def to_file_transfer(self) -> tuple[RemoteSrc, LocalDst]:
        return (self.tmp_src, self.local_destination)


class LogFileDownloader:
    def __init__(
        self,
        cluster: Cluster,
        enable_ssh: bool = False,
        ssh_config: SSHConnectionConfig | None = None,
        exception_handler: Callable[[Exception, Node], None] | None = None,
    ):
        self.cluster = cluster
        self.enable_ssh = enable_ssh
        self.ssh_config = ssh_config
        self.exception_handler = exception_handler

    async def download(self, path_gen_func: PathGenerator, nodes="all"):
        nodes = self.cluster.get_nodes(nodes=nodes)
        return await asyncio.gather(
            *[self._download_node_logs(node, path_gen_func) for node in nodes],
            return_exceptions=True,
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
                stdout = await p.stdout.read()
                msg = util.bytes_to_str(stderr).split("\n")[0]
                msg += util.bytes_to_str(stdout).split("\n")[0]

            await util.async_shell_command(f"rm -f {tmp_path}")
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
            await conn.run(
                f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > {tmp_path}'
            )
            logger.debug(
                format_node_msg(node, f"Successfully copied journald to {tmp_path}")
            )
        except SSHError as e:
            logger.debug(
                format_node_msg(node, f"Failed to copy journald to {tmp_path} : {e}")
            )
            raise

    async def _generate_dst_paths(
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

            log.local_destination = log.local_destination + ".gz"
            log.tmp_src = log.tmp_src + ".gz"
            logger.info(
                format_node_msg(
                    node, f"Compressing {log.original_src} to {log.tmp_src}"
                )
            )
            try:
                await conn.run(f"gzip -c {log.original_src} > {log.tmp_src}")
            except SSHError as e:
                logger.error(
                    format_node_msg(node, f"Failed to compress {log.original_src}: {e}")
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

                await util.async_shell_command(f"rm -f {log.local_destination}")

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
        logs = await node.info_logs()
        log_file_info: list[_LocalLogInfo] = []

        for log in logs:
            info = _LocalLogInfo(log)
            log_file_info.append(info)

        await self._generate_dst_paths(
            node,
            log_file_info,  # type: ignore
            path_gen_func,
        )

        for log in log_file_info:
            try:
                if "stderr" in log.original_src:
                    log.original_src = log.local_destination
                    await self._create_local_console_log(node, log.local_destination)
            except LogFileDownloaderException as e:
                log.skip = True
                logger.error(str(e))
                if self.exception_handler:
                    self.exception_handler(e, node)
                else:
                    raise

        log_file_info = await self._compress_local_logs(node, log_file_info)

    async def _generate_remote_tmp_paths(
        self, conn, tmp_prefix: str, file_paths: list[_RemoteLogInfo]
    ):
        await conn.run(f"mkdir -p {tmp_prefix}")
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
        conn = None

        try:
            with SSHConnectionFactory(node.ip, self.ssh_config) as conn_factory:
                async with (await conn_factory.create_connection()) as conn:
                    log_file_info: list[_RemoteLogInfo] = []
                    logs = await asyncio.gather(
                        node.info_logs(),
                    )

                    for log in logs:
                        info = _RemoteLogInfo(log)
                        log_file_info.append(info)

                    await self._generate_dst_paths(node, log_file_info, path_gen_func)  # type: ignore
                    log_file_info = await self._generate_remote_tmp_paths(
                        conn, tmp_file_prefix, log_file_info
                    )

                    for log in log_file_info:
                        if "stderr" in log.tmp_src:
                            log.original_src = log.tmp_src
                            try:
                                await self._create_remote_console_log(
                                    node, conn, log.tmp_src
                                )
                            except SSHError as e:
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
                        log.to_file_transfer()
                        for log in log_file_info
                        if log.skip is False
                    ]

                    errors = await FileTransfer.remote_to_local(file_paths, conn)

                    for err in errors:
                        if err is None:
                            continue

                        logger.error(format(node, f"Failed to download log: {err}"))

                        if self.exception_handler:
                            self.exception_handler(err, node)
                        else:
                            raise err

        except SSHConnectionError as e:
            #
            logger.error(
                format_node_msg(
                    node,
                    f"Unable to download logs from node. Couldn't SSH login to remote server: {e}",
                )
            )

            if self.exception_handler:
                self.exception_handler(e, node)
                return
            else:
                raise e
        except SSHError as e:
            logger.error(format(node, f"Failed to download logs: {e}"))
            if self.exception_handler:
                self.exception_handler(e, node)
            else:
                raise e
        finally:
            try:
                # TODO: Could use the sftp session here instead of running a command
                if conn:
                    await conn.run(f"rm -rf {tmp_file_prefix}")
            except Exception:
                logger.debug(
                    format_node_msg(
                        node,
                        f"Failed to remove {tmp_file_prefix}. It probably did not exist.",
                    )
                )

    async def _download_node_logs(self, node: Node, path_gen_func: PathGenerator):
        if node.is_localhost():
            logger.info(format_node_msg(node, "Getting local logs..."))
            await self._move_local_logs(node, path_gen_func)
        elif self.enable_ssh:
            logger.info(format_node_msg(node, "Downloading remote logs..."))
            await self._download_remote_logs(node, path_gen_func)
        else:
            logger.info(
                format_node_msg(
                    node, "Skipping downloading remote logs. SSH is not enabled."
                )
            )
