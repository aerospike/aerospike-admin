import asyncio
import os
import asyncssh
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


class SSHConnection:
    def __init__(self, conn: asyncssh.SSHClientConnection, max_sessions: int = 10):
        self._conn = conn
        self._max_sessions_sem = asyncio.Semaphore(max_sessions)

    async def run(
        self, cmd: str
    ) -> asyncssh.SSHCompletedProcess:  # Might want to wrap this before returning?
        logger.debug(
            f"{self._conn.get_extra_info('peername')}: Running command on remote: {cmd}"
        )
        try:
            async with self._max_sessions_sem:
                return await self._conn.run(cmd, check=True, timeout=10)
        except asyncssh.TimeoutError as e:
            logger.warning(f"Timeout error: {e.reason}")
            raise SSHTimeoutError(e)
        except asyncssh.ProcessError as e:
            logger.warning(f"Process error: {e.stderr}")
            raise SSHNonZeroExitCodeError(e)
        except asyncssh.Error as e:
            logger.warning(f"Generic error: {e.reason}")
            raise SSHError(e)

    async def start_sftp_client(self) -> asyncssh.SFTPClient:
        try:
            return await self._conn.start_sftp_client()
        except (asyncssh.SFTPError, asyncssh.ChannelOpenError) as e:
            raise SFTPConfigError(e)

    async def close(self):
        self._conn.close()
        await self._conn.wait_closed()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()


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


class SSHConnectionFactory:
    """
    Static dict of ip -> (semaphore, Number of SSHConnectionFactory objects using this ip)
    This will allow us to limit the number of connections being created to a single host across all SSHConnectionFactory objects
    """

    class SemaphoreCountValue:
        def __init__(self, semaphore: asyncio.Semaphore, count: int) -> None:
            self.semaphore = semaphore
            self.count = count

    semaphore_host_dict: dict[str, SemaphoreCountValue] = {}

    def __init__(
        self, ssh_config: SSHConnectionConfig | None = None, max_startups: int = 10
    ):
        """
        max_startups: The maximum number connections that can be in the process of initialising at any time.
                      Not to be confused with the maximum number of connections that can be active at any time.
        """
        # self.ip = ip
        self.opts = None
        self.max_startups = max_startups

        if ssh_config is not None:
            kwargs = {}
            if ssh_config.port is not None:
                kwargs["port"] = ssh_config.port
            if ssh_config.username is not None:
                kwargs["username"] = ssh_config.username
            if ssh_config.password is not None:
                kwargs["password"] = ssh_config.password
            if ssh_config.private_key is not None:
                kwargs["client_keys"] = ssh_config.private_key
            if ssh_config.private_key_pwd is not None:
                kwargs["passphrase"] = ssh_config.private_key_pwd

            try:
                self.opts = asyncssh.SSHClientConnectionOptions(
                    **kwargs,
                )
            except FileNotFoundError as e:
                logger.error(e)
                raise

    async def create_connection(self, ip) -> SSHConnection:
        if ip not in SSHConnectionFactory.semaphore_host_dict:
            SSHConnectionFactory.semaphore_host_dict[
                ip
            ] = SSHConnectionFactory.SemaphoreCountValue(
                asyncio.Semaphore(self.max_startups),
                1,
            )
        else:
            SSHConnectionFactory.semaphore_host_dict[ip].count += 1

        logger.debug(f"{ip}: Checking semaphore before creating connection")
        try:
            async with SSHConnectionFactory.semaphore_host_dict[ip].semaphore:
                logger.debug(f"{ip}: Creating connection")
                return SSHConnection(await asyncssh.connect(ip, options=self.opts))
        except (asyncssh.DisconnectError, ConnectionRefusedError) as e:
            raise SSHConnectionError(e)
        finally:
            SSHConnectionFactory.semaphore_host_dict[ip].count -= 1

            if SSHConnectionFactory.semaphore_host_dict[ip].count == 0:
                logger.debug(
                    f"{ip}: Host has no other factories. Cleaning up host semaphore"
                )
                del SSHConnectionFactory.semaphore_host_dict[ip]


RemoteSrc = list[str] | str
RemoteDst = str
LocalSrc = list[str] | str
LocalDst = str


class FileTransfer:
    @staticmethod
    def create_error_handler(errors: list[Exception]):
        def error_handler(exc):
            logger.warning(exc)
            errors.append(exc)

        return error_handler

    @staticmethod
    async def remote_to_local(
        paths: list[tuple[RemoteSrc, LocalDst]],
        src_conn: SSHConnection,
        return_exceptions: bool = False,
    ) -> list[Exception]:
        # TODO: Handle rate limiting
        logger.debug(
            f"{src_conn._conn.get_extra_info('peername')}: Starting remote to local file transfer"
        )
        errors: list[Exception] = []
        tasks = []

        # You can have multiple sftp sessions per connection. The default is 10. We are only using 1 per node here.
        async with await src_conn.start_sftp_client() as sftp_session:
            for src, dst in paths:
                os.makedirs(os.path.dirname(dst), exist_ok=True)

                if isinstance(src, str):
                    src = [src]

                if len(src) > 1:
                    logger.debug(
                        f"{src_conn._conn.get_extra_info('peername')}: Multiple source paths provided for a single destination. Destination must be a path to a directory."
                    )

                logger.debug(
                    f"{src_conn._conn.get_extra_info('peername')}: Initiating transfer of {src[0] if len(src)> 0 else src} to {dst}"
                )
                tasks.append(
                    sftp_session.get(
                        src,
                        dst,
                        recurse=True,
                        preserve=True,
                    )
                )

            errors = await asyncio.gather(
                *tasks, return_exceptions=return_exceptions
            )  # TODO: Should wrap asyncssh errors with out own
            logger.debug("Finished remote to local file transfer")

        return [err for err in errors if err is not None]

    @staticmethod
    async def remote_to_remote(src_paths: RemoteSrc, dest_path: RemoteDst):
        # This can try to run sftp on the remote host to copy files directly from one remote host to another
        # and if that fails it can fallback to remote -> local -> remote
        raise NotImplementedError("remote to remote scp not implemented")

    @staticmethod
    async def local_to_remote(src_paths: LocalSrc, dest_path: RemoteDst):
        raise NotImplementedError("local to remote scp not implemented")


class SSHError(Exception):
    pass


class SSHTimeoutError(SSHError):
    pass


class SSHNonZeroExitCodeError(SSHError):
    pass


class SSHConnectionError(SSHError):
    pass


class SFTPError(SSHError):
    pass


class SFTPConfigError(SFTPError):
    pass
