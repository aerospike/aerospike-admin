import asyncio
from datetime import datetime
import logging
import time
from typing import Callable, Iterator
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.client.node import Node
from lib.live_cluster.ssh import (
    SCPCommand,
    SCPLocalDst,
    SCPLocalSrc,
    SCPRemoteSrc,
    SSHConnection,
    SSHConnectionConfig,
    SSHConnectionFactory,
    SSHError,
)

PathGenerator = Callable[[Node, str], str]
logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


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

        for node in nodes:
            await self._download_node_logs(node, path_gen_func)

    async def _generate_paths(
        self,
        conn: SSHConnection,
        node: Node,
        logs: list[str],
        path_gen_func: PathGenerator,
    ) -> tuple[list[SCPRemoteSrc], str | None]:
        scp_sources: list[SCPRemoteSrc] = []
        dst_path = None

        for log in logs:
            if log == "stderr":
                dst_path = path_gen_func(node, "console")
                data_ext = datetime.now().strftime("%Y%m%d_%H%M%S")
                src_path = f"/tmp/aerospike.log-{data_ext}"

                logger.debug(
                    f"Node {node.ip}:{node.port} is logging to console. Copying journald to {src_path} before downloading"
                )

                try:
                    await conn.run(
                        f'journalctl -u aerospike -a -o cat --since "1 day ago" | grep GMT > {log}'
                    )
                except SSHError as e:
                    logger.exception(
                        f"Failed to copy journald to {log} for node {node.ip}:{node.port}: {e}"
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

            scp_sources.append(SCPRemoteSrc(conn, src_path))

        return scp_sources, dst_path

    async def _compress_logs(
        self, conn: SSHConnection, scp_sources: list[SCPRemoteSrc]
    ):
        for scp_source in scp_sources:
            for path in scp_source.paths:
                logger.info(f"Compressing {path}")
                try:
                    await conn.run(f"gzip {path}")
                except SSHError as e:
                    logger.error(f"Failed to compress {path}: {e}")
                    if self.exception_handler:
                        self.exception_handler(e)
                    else:
                        raise

    async def _download_node_logs(self, node: Node, path_gen_func: PathGenerator):
        logger.info(f"Downloading logs from {node.ip}:{node.port}")
        logs, conn = await asyncio.gather(
            node.info_logs(),
            SSHConnectionFactory(node.ip, self.ssh_config).create_connection(),
        )

        scp_sources, dst_path = await self._generate_paths(
            conn, node, list(logs.keys()), path_gen_func
        )

        for scp_source in scp_sources:
            await SCPCommand.remote_to_local(scp_source, dst_path)
