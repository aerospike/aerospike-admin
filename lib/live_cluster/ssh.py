import asyncio
import asyncssh
from lib.live_cluster.client.cluster import Cluster
from lib.utils.logger import logger


class SSHConnection:
    _in_use = False

    def __init__(self, conn: asyncssh.SSHClientConnection):
        self._conn = conn
        SSHConnection._in_use = False

    async def run(self, cmd: str) -> asyncssh.SSHCompletedProcess:
        if self._in_use:
            logger.fatal(
                "SSHConnection is already in use. To make concurrent calls to the same host, create a new connection."
            )

        SSHConnection._in_use = True

        try:
            return await self._conn.run(cmd, check=True, timeout=5)
        except asyncssh.TimeoutError as e:
            raise SSHTimeoutError(e)
        except asyncssh.ProcessError as e:
            raise SSHNonZeroExitCodeError(e)
        except asyncssh.Error as e:
            raise SSHError(e)
        finally:
            SSHConnection._in_use = False

    async def close(self):
        self._conn.close()
        await self._conn.wait_closed()


class SSHConnectionConfig:
    def __init__(
        self,
        port: int | None = None,
        username: str | None = None,
        password: str | None = None,
        private_key: str | None = None,
        private_key_pwd: str | None = None,
    ):
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.private_key_pwd = private_key_pwd


class SCPRemoteSrc:
    def __init__(
        self,
        conn: SSHConnection,
        paths: list[str] | str,
    ):
        self.paths = paths
        self.conn = conn


SCPLocalSrc = list[str] | str
SCPLocalDst = str


class SCPRemoteDest:
    def __init__(
        self,
        conn: SSHConnection,
        path: str,
    ):
        self.path = path
        self.conn = conn


class SCPCommand:
    @staticmethod
    def create_error_handler(errors: list[Exception]):
        def error_handler(exc):
            logger.warning(exc)
            errors.append(exc)

        return error_handler

    @staticmethod
    async def remote_to_local(
        src_paths: SCPRemoteSrc, dest_path: SCPLocalDst, parallel: bool = False
    ):
        src_conns: list[tuple[asyncssh.SSHClientConnection, str]] = []

        for path in src_paths.paths:
            src_conns.append(
                (
                    src_paths.conn._conn,
                    path,
                )
            )

        errors = []
        error_handler = SCPCommand.create_error_handler(errors)

        if parallel:
            # use a new ssh connection for each source path
            await asyncio.gather(
                *[
                    asyncssh.scp(
                        src_conn,
                        dest_path,
                        preserve=True,
                        recurse=True,
                        error_handler=error_handler,  # Won't throw exceptions
                    )
                    for src_conn in src_conns
                ],
            )
        else:
            await asyncssh.scp(
                src_conns,
                dest_path,
                preserve=True,
                recurse=True,
                error_handler=error_handler,  # Won't throw exceptions
            )

        # TODO: need to handle the case where there are no successful transfers

    @staticmethod
    async def remote_to_remote(src_paths: SCPRemoteSrc, dest_path: SCPRemoteDest):
        raise NotImplementedError("remote to remote scp not implemented")

    @staticmethod
    async def local_to_remote(src_paths: SCPLocalSrc, dest_path: SCPRemoteDest):
        raise NotImplementedError("local to remote scp not implemented")


class SSHConnectionFactory:
    def __init__(self, ip, ssh_config: SSHConnectionConfig | None = None):
        self.ip = ip
        self.opts = None

        if ssh_config is not None:
            self.opts = asyncssh.SSHClientConnectionOptions()
            if self.ip:
                self.opts.prepare(host=self.ip)
            if ssh_config.port:
                self.opts.prepare(port=ssh_config.port)
            if ssh_config.username:
                self.opts.prepare(username=ssh_config.username)
            if ssh_config.private_key_pwd:
                self.opts.prepare(passphrase=ssh_config.private_key_pwd)
            if ssh_config.private_key:
                self.opts.prepare(client_keys=ssh_config.private_key)

    # TODO: Maybe connection should be wrapped?
    async def create_connection(self) -> SSHConnection:
        return SSHConnection(await asyncssh.connect(self.ip, options=self.opts))


class SSHError(Exception):
    pass


class SSHTimeoutError(SSHError):
    pass


class SSHNonZeroExitCodeError(SSHError):
    pass
