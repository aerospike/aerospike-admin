import asyncio
from datetime import datetime
import logging
import os
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
    SSHConnectionFactory,
    SSHError,
)

PathGenerator = Callable[[Node, str], str]
logger = logging.getLogger(__name__)


class LogFileDownloader:
    def __init__(
        self,
        cluster: Cluster,
        ssh_config: SSHConnectionConfig | None = None,
        exception_handler=None,
    ):
        self.cluster = cluster
        self.ssh_config = ssh_config
        self.exception_handler = exception_handler

    async def download(self, path_gen_func: PathGenerator, nodes="all"):
        nodes = self.cluster.get_nodes(nodes=nodes)
        await asyncio.gather(
            *[self._download_node_logs(node, path_gen_func) for node in nodes]
        )

    async def _generate_paths(
        self,
        conn: SSHConnection,
        node: Node,
        logs: list[str],
        path_gen_func: PathGenerator,
        tmp_prefix: str,
    ) -> tuple[list[tuple[RemoteSrc, LocalDst]], list[str]]:
        scp_sources: list[tuple[RemoteSrc, LocalDst]] = []
        console_logs = []
        dst_path = None

        for log in logs:
            if log == "stderr":
                dst_path = path_gen_func(node, "aerospike-console.log")
                src_path = os.path.join(tmp_prefix, "aerospike-console.log")

                logger.info(
                    f"({node.ip}:{node.port}) Noe is logging to console. Copying journald to {src_path} before downloading"
                )

                try:
                    await conn.run(
                        f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > {src_path}'
                    )
                    console_logs.append(src_path)
                except SSHError as e:
                    logger.exception(
                        f"({node.ip}:{node.port}) Failed to copy journald to {log} : {e}"
                    )
                    if self.exception_handler:
                        self.exception_handler(
                            e
                        )  # TODO: Think about adding more context to where this occurred
                    else:
                        raise

            else:
                dst_path = path_gen_func(node, log)
                src_path = log

            logger.debug(
                f"{node.ip}:{node.port} {src_path} will be copied to {dst_path}"
            )

            scp_sources.append((src_path, dst_path))

        return scp_sources, console_logs

    async def _compress_logs(
        self,
        conn: SSHConnection,
        scp_sources: list[tuple[RemoteSrc, LocalDst]],
        tmp_prefix: str,
    ) -> list[tuple[RemoteSrc, LocalDst]]:
        new_sources = []

        for scp_source, dst_path in scp_sources:
            scp_source = [scp_source] if isinstance(scp_source, str) else scp_source
            new_paths = []
            dst_path = dst_path + ".gz"

            for src_path in scp_source:
                file_name = os.path.basename(src_path)
                tmp_file = os.path.join(tmp_prefix, file_name + ".gz")
                logger.info(
                    f"{conn._conn.get_extra_info('peername')}: Compressing {src_path} to {tmp_file}"
                )
                try:
                    await conn.run(f"gzip -c {src_path} > {tmp_file}")
                    new_paths.append(tmp_file)
                except SSHError as e:
                    logger.error(f"Failed to compress {src_path}: {e}")
                    if self.exception_handler:
                        self.exception_handler(e)
                    else:
                        raise

            if new_paths:
                new_sources.append((new_paths, dst_path))

        return new_sources

    async def _download_node_logs(self, node: Node, path_gen_func: PathGenerator):
        # TODO: Handle case where node is local and not ssh able
        conn_factory = SSHConnectionFactory(node.ip, self.ssh_config)
        time_prefix = datetime.now().strftime("%Y%m%d_%H%M%S")
        tmp_file_prefix = f"/tmp/{time_prefix}/"
        logger.info(f"Downloading logs from {node.ip}:{node.port}")
        logs, conn = await asyncio.gather(
            node.info_logs(),
            conn_factory.create_connection(),
        )
        console_logs = None

        try:
            await conn.run(f"mkdir -p {tmp_file_prefix}")
            file_paths, console_logs = await self._generate_paths(
                conn, node, list(logs.keys()), path_gen_func, tmp_file_prefix
            )
            file_paths = await self._compress_logs(conn, file_paths, tmp_file_prefix)

            await FileTransfer.remote_to_local(file_paths, conn)

        except SSHError as e:
            pass  # TODO
        finally:
            try:
                if console_logs:
                    await conn.run(f"rm -rf {tmp_file_prefix}")
            except SSHError:
                # TODO
                pass

        conn_factory.close()
