# Copyright 2013-2025 Aerospike, Inc.
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
import asyncio
from contextlib import asynccontextmanager
from ctypes import ArgumentError
import copy
import logging
import os
import re
import socket
from collections import deque
from OpenSSL import SSL
import threading
import time
import base64
from typing import Any, Callable, Optional, Union
from lib.live_cluster.ssh import (
    SSHConnectionConfig,
    SSHConnectionFactory,
    SSHError,
    SSHNonZeroExitCodeError,
    SSHTimeoutError,
)

from lib.utils import common, constants, util, version, conf_parser
from lib.utils.async_object import AsyncObject

from .constants import ErrorsMsgs, MAX_SOCKET_POOL_SIZE
from .ctx import CDTContext
from .msgpack import ASPacker
from .assocket import ASSocket
from .config_handler import JsonDynamicConfigHandler
from . import client_util
from . import sys_cmd_parser
from .types import (
    ASInfoConfigError,
    ASInfoError,
    ASInfoResponseError,
    ASINFO_RESPONSE_OK,
    ASInfoNotAuthenticatedError,
    ASInfoClusterStableError,
    ASProtocolConnectionError,
    ASProtocolError,
    ASResponse,
    Addr_Port_TLSName,
)

logger = logging.getLogger(__name__)


def get_fully_qualified_domain_name(address, timeout=0.5):
    # TODO: make async
    # note: cannot use timeout lib because signal must be run from the
    #       main thread

    result = [address]

    def helper():
        result[0] = socket.getfqdn(address)

    t = threading.Thread(target=helper)

    t.daemon = True
    t.start()

    t.join(timeout)

    return result[0]


def async_return_exceptions(func):
    async def wrapper(*args, raise_exception=False, **kwargs):
        raise_exception = False
        exception = None

        try:
            return await func(*args, **kwargs)
        except (ASInfoNotAuthenticatedError, ASProtocolConnectionError) as e:
            args[0].alive = False
            exception = e
        except OSError as e:
            args[0].alive = False
            exception = e
        except Exception as e:
            exception = e

        if raise_exception:
            raise

        return exception

    return wrapper


# TODO: May not be needed
def return_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            args[0].alive = False
            return e

    return wrapper


class _SysCmd:
    _uid: int = -1

    @classmethod
    def set_uid(cls, uid):
        cls._uid = uid

    def __init__(
        self,
        name: str,
        ignore_error: bool,
        cmds: list[str],
        parse_func: Callable[[str], dict[str, Any]],
    ) -> None:
        if _SysCmd._uid == -1:
            raise RuntimeError("set_uid not called")

        self.key = name
        self.ignore_error = ignore_error
        self._cmds = cmds
        self._idx = 0
        self._parse_func = parse_func

    def parse(self, command_raw_output: str):
        result = self._parse_func(command_raw_output)
        sys_cmd_parser.type_check_basic_values(
            result
        )  # Not sure if this is still needed.
        return result

    def _is_root(self) -> bool:
        return self._uid == 0

    def __iter__(self):
        self._idx = 0
        return self

    def __next__(self):
        if self._idx >= len(self._cmds):
            raise StopIteration

        cmd = self._cmds[self._idx]
        self._idx += 1

        # Remove sudo if already root. Some systems do not have sudo.
        if self._is_root():
            return cmd.replace("sudo ", "")

        return cmd


class Node(AsyncObject):
    dns_cache = {}
    info_roster_list_fields = ["roster", "pending_roster", "observed_nodes"]
    security_disabled_warning = False  # We only want to warn the user once.

    async def __init__(
        self,
        address,
        port=3000,
        tls_name=None,
        timeout=1,
        user=None,
        password=None,
        auth_mode=constants.AuthMode.INTERNAL,
        ssl_context: SSL.Context | None = None,
        consider_alumni=False,
        use_services_alt=False,
        user_agent=None,
    ) -> None:
        """
        address -- ip or fqdn for this node
        port -- info port for this node
        timeout -- number of seconds to wait before giving up on the node
        If address is ip then get fqdn else get ip
        store ip in self.ip
        store fqdn in self.fqdn
        store port in self.port

        NOTE: would be nice if the port could either be the service or telnet
        access port. Can we detect from the socket?
        ALSO NOTE: May be better to just use telnet instead?
        """
        self.ip: str = address
        self.port: int = port
        self._timeout = timeout
        self.user = user
        self.password = password
        self.auth_mode = auth_mode
        self.tls_name: Union[str, None] = tls_name
        self.ssl_context = ssl_context
        if ssl_context:
            self.enable_tls = True
        else:
            self.enable_tls = False
        self.consider_alumni = consider_alumni
        self.use_services_alt = use_services_alt
        self.peers: list[tuple[Addr_Port_TLSName]] = []
        self.is_admin_node = False  # Track if this is an admin node

        # session token
        self.session_token: bytes | None = None
        self.session_expiration = 0
        self.perform_login = True
        self.user_agent = user_agent
        self.build = None

        # TODO: Remove remote sys stats from Node class
        _SysCmd.set_uid(os.getuid())
        self.sys_cmds: list[_SysCmd] = [
            _SysCmd(
                "hostname",
                False,
                ["hostname -I", "hostname"],
                sys_cmd_parser.parse_hostname_section,
            ),
            _SysCmd(
                "top",
                False,
                ["top -n1 -b", "top -l 1"],
                sys_cmd_parser.parse_top_section,
            ),
            _SysCmd(
                "lsb",
                False,
                ["lsb_release -a", "ls /etc|grep release|xargs -I f cat /etc/f"],
                sys_cmd_parser.parse_lsb_release_section,
            ),
            _SysCmd(
                "meminfo",
                False,
                ["cat /proc/meminfo", "vmstat -s"],
                sys_cmd_parser.parse_meminfo_section,
            ),
            _SysCmd(
                "interrupts",
                False,
                ["cat /proc/interrupts", ""],
                sys_cmd_parser.parse_interrupts_section,
            ),
            _SysCmd(
                "iostat",
                False,
                ["iostat -y -x 5 1", ""],
                sys_cmd_parser.parse_iostat_section,
            ),
            _SysCmd(
                "dmesg",
                False,
                ["dmesg -T", "dmesg"],
                sys_cmd_parser.parse_dmesg_section,
            ),
            _SysCmd(
                "limits",
                False,
                ['sudo pgrep asd | xargs -I f sh -c "sudo cat /proc/f/limits"', ""],
                sys_cmd_parser.parse_limits_section,
            ),
            _SysCmd("lscpu", False, ["lscpu", ""], sys_cmd_parser.parse_lscpu_section),
            _SysCmd(
                "sysctlall",
                False,
                ["sudo sysctl vm fs", ""],
                sys_cmd_parser.parse_sysctlall_section,
            ),
            _SysCmd(
                "iptables",
                False,
                ["sudo iptables -S", ""],
                sys_cmd_parser.parse_iptables_section,
            ),
            _SysCmd(
                "hdparm",
                False,
                [
                    'sudo fdisk -l |grep Disk |grep dev | cut -d " " -f 2 | cut -d ":" -f 1 | xargs sudo hdparm -I 2>/dev/null',
                    "",
                ],
                sys_cmd_parser.parse_hdparm_section,
            ),
            _SysCmd("df", False, ["df -h", ""], sys_cmd_parser.parse_df_section),
            _SysCmd(
                "free-m", False, ["free -m", ""], sys_cmd_parser.parse_free_m_section
            ),
            _SysCmd(
                "uname", False, ["uname -a", ""], sys_cmd_parser.parse_uname_section
            ),
            _SysCmd(
                "scheduler",
                True,
                [
                    'ls /sys/block/{sd*,xvd*,nvme*}/queue/scheduler |xargs -I f sh -c "echo f; cat f;"',
                    "",
                ],
                sys_cmd_parser.parse_scheduler_section,
            ),
            # Todo: Add more commands for other cloud platform detection
            _SysCmd(
                "environment",
                False,
                ["curl -m 1 -s http://169.254.169.254/1.0/", "uname"],
                sys_cmd_parser.parse_environment_section,
            ),
            _SysCmd(
                "ethtool",
                False,
                [
                    'sudo netstat -i | tr -s [:blank:] | cut -d" " -f1 | tail -n +3 | grep -v -E "lo|docker" | xargs --max-lines=1 -i{} sh -c "echo ethtool -S {}; ethtool -S {}"'
                ],
                sys_cmd_parser.parse_ethtool_section,
            ),
        ]

        # hack, _key needs to be defines before info calls... but may have
        # wrong (localhost) address before info_service is called. Will set
        # again after that call.

        self._key = hash(self.create_key(address, self.port))
        self.peers_generation = -1
        self.service_addresses = []
        self._initialize_socket_pool()
        await self.connect(
            address, port
        )  # TODO Init and connect steps should be separate
        self.localhost = False

        if address.lower() == "localhost" or address == "127.0.0.1":
            p = await util.async_shell_command(
                "docker ps | tail -n +2 | awk '{print $2}' | grep 'aerospike/aerospike-server'"
            )

            if not p or p.returncode != 0:
                """
                Check if any docker containers are running. If they are then lets assume
                that an aerospike node is not running on localhost since this affects how
                we gather logs and the aerospike.conf file
                """

                self.localhost = True

        elif self.alive:
            try:
                """
                This could still result in self.localhost being False if the node
                has access-address or alternate-access-addres (in the case of
                --use-alternate) configured to something other than what is returned
                by hostname -I. This could occur in cloud environments where the
                external IP is different than the internal IP.
                """
                p = await util.async_shell_command("hostname -I")

                if p and p.returncode == 0 and p.stdout:
                    stdout = (await p.stdout.read()).decode("utf-8").strip()
                    self.localhost = self._is_any_my_ip(stdout.split())
            except Exception as e:
                pass

        # configurations from conf file
        self.as_conf_data = {}

        if self.alive:
            self.conf_schema_handler = JsonDynamicConfigHandler(
                constants.CONFIG_SCHEMAS_HOME, await self.info_build()
            )

    def _initialize_socket_pool(self):
        logger.debug("%s:%s init socket pool", self.ip, self.port)
        self.socket_pool: dict[int, deque[ASSocket]] = {}
        self.socket_pool[self.port] = deque(maxlen=MAX_SOCKET_POOL_SIZE)

    def _is_any_my_ip(self, ips):
        if not ips:
            return False
        s_a = [a[0] for a in self.service_addresses]
        if set(ips).intersection(set(s_a)):
            return True
        return False

    async def _node_connect(self):
        node_info_cmd = "node"
        build_info_cmd = "build"
        peers_generation_info_cmd = "peers-generation"

        # First call: minimal info to determine build and node id.
        node_info_response = await self._info_cinfo(
            [node_info_cmd, build_info_cmd, peers_generation_info_cmd],
            self.ip,
            self.port,
            disable_cache=True,
        )

        self.build = node_info_response.get(build_info_cmd)
        server_supports_admin_info_call = False

        try:
            server_supports_admin_info_call = version.LooseVersion(self.build) >= (
                version.LooseVersion(constants.SERVER_ADMIN_PORT_FIRST_VERSION)
            )
        except Exception as e:
            logger.debug(
                "unable to parse build version '%s' for node %s:%s error:%s",
                self.build,
                self.ip,
                self.port,
                e,
            )

        if server_supports_admin_info_call:
            logger.debug("build version %s supports admin port", self.build)
            connection_info_response = None
            connection_info_cmd = "connection"
            try:
                connection_info_response = await self._info_cinfo(
                    connection_info_cmd, self.ip, self.port, disable_cache=True
                )
            except ASInfoError as e:
                logger.debug(
                    "unable to get connection info for node %s:%s error:%s",
                    self.ip,
                    self.port,
                    e,
                )

            if self._is_admin_port_enabled(connection_info_response):
                logger.debug("admin port is enabled for ip %s", self.ip)
                self.is_admin_node = True

                # Disable peer discovery for admin node
                peers = []

                # Use admin info call instead of service info call
                admin_info_cmd = self._get_admin_info_call()
                admin_info_response = await self._info_cinfo(
                    admin_info_cmd, self.ip, disable_cache=True
                )
                admin_addresses = self._info_service_helper(admin_info_response)
                logger.debug(
                    "admin address discovered for node %s: %s",
                    node_info_response[node_info_cmd],
                    admin_addresses,
                )

                return (
                    node_info_response[node_info_cmd],
                    admin_addresses,
                    peers,
                    node_info_response[peers_generation_info_cmd],
                )
        else:
            logger.debug("build version %s does not support admin port", self.build)

        service_info_cmd = self._get_service_info_call()
        peers_info_cmds = self._get_info_peers_list_calls()

        # Non-admin path: fetch service addresses and peers in a single call.
        service_peers_response = await self._info_cinfo(
            [service_info_cmd] + peers_info_cmds,
            self.ip,
            self.port,
            disable_cache=True,
        )
        service_addresses = self._info_service_helper(
            service_peers_response[service_info_cmd]
        )
        peers = (
            self._aggregate_peers(
                [service_peers_response[call] for call in peers_info_cmds]
            )
            if peers_info_cmds
            else []
        )

        return (
            node_info_response[node_info_cmd],
            service_addresses,
            peers,
            node_info_response[peers_generation_info_cmd],
        )

    async def connect(self, address, port):
        try:
            if not await self.login():
                raise IOError(
                    "Login Error"
                )  # TODO: Better error message that is displayed to user to indicate the node is reachable but we could not login

            # At startup the socket_pool is empty.  Login adds its socket to the pool.
            # This ensures that the following call uses the same socket as login(). This is
            # needed when a load balancer is used because the session token received from login
            # will be for a specific node.
            (
                self.node_id,
                service_addresses,
                self.peers,
                self.peers_generation,
            ) = await self._node_connect()
            logger.debug(
                "%s:%s connect discovered node_id=%s service_addresses=%s peers=%s",
                self.ip,
                self.port,
                self.node_id,
                service_addresses,
                self.peers,
            )

            if isinstance(self.node_id, Exception):
                raise self.node_id

            # Original address may not be the service address, the
            # following will ensure we have the service address
            if not isinstance(service_addresses, Exception):
                self.service_addresses = service_addresses
            # else : might be it's IP is not available, node should try all old
            # service addresses

            await self.close()
            self._initialize_socket_pool()
            current_host = (self.ip, self.port, self.tls_name)

            if not self.service_addresses or current_host not in self.service_addresses:
                # if asd >= 3.10 and node has only IPv6 address
                self.service_addresses.append(current_host)

            for i, s in enumerate(self.service_addresses):
                try:
                    logger.debug(
                        "%s:%s attempting service address idx=%s addr=%s "
                        "original_host=%s",
                        self.ip,
                        self.port,
                        i,
                        s,
                        current_host,
                    )
                    # calling update ip again because info_service may have provided a
                    # different IP than what was seeded.
                    self.ip = s[0]
                    self.port = s[1]

                    # Most common case
                    if s[0] == current_host[0] and s[1] == current_host[1] and i == 0:
                        await self._update_IP(self.ip, self.port)
                        # The following info requests were already made
                        # no need to do again
                        break

                    # IP address have changed. Not common.
                    # Re-fetch all node info including build version, as this could be
                    # a different server or the same server upgraded/replaced at new IP
                    self.node_id, _, self.peers, self.build, self.peers_generation = (
                        await asyncio.gather(
                            self.info_node(),
                            self._update_IP(self.ip, self.port),
                            self.info_peers_list(),
                            self.info_build(disable_cache=True),
                            self.info_peers_generation(),
                        )
                    )

                    if not isinstance(self.node_id, Exception):
                        break

                except Exception:
                    logger.debug(
                        "%s:%s service address %s failed during connect",
                        self.ip,
                        self.port,
                        s,
                        exc_info=True,
                    )
                    # Sometime unavailable address might be present in service
                    # list, for ex. Down NIC address (server < 3.10).
                    # In such scenario, we want to try all addresses from
                    # service list till we get available address
                    pass

            if isinstance(self.node_id, Exception):
                raise self.node_id

            self._service_IP_port = self.create_key(self.ip, self.port)
            self._key = hash(self._service_IP_port)
            self.new_histogram_version = await self._is_new_histogram_version()
            # Set the user agent for this node
            await self._set_user_agent()
            self.alive = True
        except (ASInfoNotAuthenticatedError, ASProtocolError):
            raise
        except Exception as e:
            logger.debug(e, exc_info=True)  # type: ignore
            # Node is offline... fake a node
            self.ip = address
            self.fqdn = address
            self.port = port
            self._service_IP_port = self.create_key(self.ip, self.port)
            self._key = hash(self._service_IP_port)

            self.node_id = "000000000000000"
            self.service_addresses = [(self.ip, self.port, self.tls_name)]
            self.peers = []
            self.is_admin_node = False
            self.use_new_histogram_format = False
            self.alive = False

    async def refresh_connection(self):
        await self.connect(self.ip, self.port)

    async def needs_refresh(self) -> bool:
        """
        Check if node needs refresh based on its service addresses or peers changes.
        Returns True if node IP, port, service addresses, or peers generation have changed.
        """
        # If node is not alive, definitely need refresh
        if not self.alive:
            logger.debug("Node %s:%s not alive, need refresh", self.ip, self.port)
            return True

        # If no socket pool, need refresh
        if not self.socket_pool or self.port not in self.socket_pool:
            logger.debug("Node %s:%s no socket pool, need refresh", self.ip, self.port)
            return True

        try:
            # Get current service addresses
            info_address_call = (
                self._get_admin_info_call()
                if self.is_admin_node
                else self._get_service_info_call()
            )
            commands = ["node", info_address_call]
            results = await self._info_cinfo(commands, self.ip, disable_cache=True)

            if self.node_id != results["node"]:
                logger.debug(
                    "Node %s:%s node id changed, need refresh", self.ip, self.port
                )
                return True

            refreshed_service_addresses = self._info_service_helper(
                results[info_address_call]
            )

            # Compare with existing service addresses
            if not self._service_addresses_compatible(
                refreshed_service_addresses, info_address_call
            ):
                return True

            # Check if peers have changed (new nodes added to cluster)
            if await self.has_peers_changed():
                logger.debug(
                    "Node %s:%s peers generation changed, need refresh",
                    self.ip,
                    self.port,
                )
                return True

            # No service address changes detected
            logger.debug(
                "Node %s:%s no service address changes detected", self.ip, self.port
            )
            return False

        except Exception as e:
            logger.debug(
                "Error checking service addresses for %s:%s: %s", self.ip, self.port, e
            )
            # If we can't check, assume refresh is needed
            return True

    def _service_addresses_compatible(
        self, refreshed_service_addresses, info_address_call
    ):
        """Check if current address and service addresses are compatible with newly refreshed service addresses.

        Returns:
            True if compatible (no refresh needed) - current connection is in refreshed addresses
            False if not compatible (refresh needed) - current connection is not in refreshed addresses
        """
        refreshed_service_addresses_set = set(refreshed_service_addresses)

        # Get the address we're currently connected to
        current_connection = (self.ip, self.port, self.tls_name)

        if not refreshed_service_addresses_set:
            logger.debug(
                "Node %s:%s has no refreshed service addresses, need refresh",
                self.ip,
                self.port,
            )
            return False

        # If connected via LB: LB won't be in refreshed service addresses → triggers refresh → attempts direct connections
        # If connected directly: Direct address will be in refreshed service addresses → no unnecessary refresh
        # If node removed: Current address won't be in refreshed addresses → triggers refresh to find new connection
        if current_connection not in refreshed_service_addresses_set:
            logger.debug(
                "Node %s:%s connected to an address that's not in %s info call, need refresh",
                self.ip,
                self.port,
                info_address_call,
            )
            return False  # Not compatible - needs refresh

        # current addresses are a subset of refreshed service addresses
        # no need to refresh
        logger.debug(
            "Node %s:%s current address is present in %s info call, no need to refresh",
            self.ip,
            self.port,
            info_address_call,
        )
        return True  # Compatible - no refresh needed

    async def login(self):
        """
        Creates a new socket and gets the session token for authentication. No login
        is done if a user was not provided and PKI is not being used.
        First introduced in 0.2.0. Before security only required a user/pass authentication
        stage rather than a two step login() -> token -> auth().
        """
        if self.auth_mode != constants.AuthMode.PKI and self.user is None:
            logger.debug(
                "%s:%s skipping login because auth_mode=%s and no user provided",
                self.ip,
                self.port,
                self.auth_mode,
            )
            return True

        if not self.perform_login and (
            self.session_expiration == 0 or self.session_expiration > time.time()
        ):
            logger.debug(
                "%s:%s skipping login because session is still valid exp=%s now=%s",
                self.ip,
                self.port,
                self.session_expiration,
                time.time(),
            )
            return True

        sock = ASSocket(
            self.ip,
            self.port,
            self.tls_name,
            self.user,
            self.password,
            self.auth_mode,
            self.ssl_context,
            timeout=self._timeout,
        )

        if not await sock.connect():
            logger.debug(
                "%s:%s failed to connect to socket %s, closing sock at login",
                self.ip,
                self.port,
                sock,
            )
            await sock.close()
            return False

        try:
            if not await sock.login():
                logger.debug(
                    "%s:%s failed to login to socket %s, closing sock at login",
                    self.ip,
                    self.port,
                    sock,
                )
                await sock.close()
                return False
        except ASProtocolError as e:
            if e.as_response == ASResponse.SECURITY_NOT_ENABLED:
                logger.debug(
                    "%s:%s failed to login to socket, security not enabled, ignoring... %s",
                    self.ip,
                    self.port,
                    sock,
                )
                if not Node.security_disabled_warning:
                    logger.warning(e)
                    Node.security_disabled_warning = True
            else:
                logger.debug(
                    "%s:%s failed to login to socket %s, exc: %s, closing sock at login",
                    self.ip,
                    self.port,
                    sock,
                    e,
                )
                await sock.close()
                raise
        except Exception as e:
            # Handle non-ASProtocolError exceptions (e.g., asyncio.TimeoutError)
            logger.debug(
                "%s:%s unexpected exception during login %s, exc: %s, closing sock",
                self.ip,
                self.port,
                sock,
                e,
            )
            await sock.close()
            raise

        self.socket_pool[self.port].append(sock)
        self.session_token, self.session_expiration = sock.get_session_info()
        self.perform_login = False
        logger.debug("%s:%s successful login to socket %s", self.ip, self.port, sock)
        return True

    @property
    def key(self):
        """Get the value of service_IP_port"""
        return self._service_IP_port

    @staticmethod
    def create_key(address, port):
        if address and ":" in address:
            # IPv6 format
            return "[%s]:%s" % (address, port)
        return "%s:%s" % (address, port)

    def __hash__(self):
        return hash(self._key)

    def __eq__(self, other):
        return self._key == other._key

    async def _update_IP(self, address, port):
        if address not in self.dns_cache:
            self.dns_cache[address] = (
                (
                    await asyncio.get_event_loop().getaddrinfo(
                        address, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM
                    )
                )[0][4][0],
                get_fully_qualified_domain_name(address),
            )

        self.ip, self.fqdn = self.dns_cache[address]

    def sock_name(self, use_fqdn=False):
        if use_fqdn:
            address = self.fqdn
        else:
            address = self.ip

        return self.create_key(address, self.port)

    def is_localhost(self):
        return self.localhost

    def __str__(self):
        return self.sock_name()

    async def is_XDR_enabled(self):
        config = await self.info_xdr_config()

        if isinstance(config, Exception):
            return False

        # 'enable-xdr' was removed in XDR5.0, so check that get-config:context=xdr does not return an error.
        if client_util.info_valid(config):
            try:
                xdr_enabled = config["enable-xdr"]
                return xdr_enabled == "true"
            except Exception:
                pass
            return True

        return False

    async def has_peers_changed(self):
        """
        Check if peers have changed by comparing peers-generation.
        Note: Does NOT update peers_generation - that happens in connect() after successful refresh.
        """
        # Admin nodes don't track peer changes
        if getattr(self, "is_admin_node", False):
            return False

        try:
            new_generation = await self.info_peers_generation()
            if self.peers_generation != new_generation:
                # Don't update peers_generation here - it should only be updated
                # after a successful refresh_connection() or node_connect() to avoid missing updates
                # if the refresh fails
                return True
            else:
                return False
        except Exception:
            return True

    async def _is_new_histogram_version(self):
        # Always fetch a fresh build for histogram compatibility checks
        as_version = await self.info_build(disable_cache=True)
        if isinstance(as_version, Exception):
            logger.error("failed to get histogram version: %s", as_version)
            return False
        return common.is_new_histogram_version(as_version)

    async def _set_user_agent(self):
        """
        Sets user agent on the Aerospike connection socket.
        """

        if self.build is None or isinstance(self.build, Exception):
            logger.debug(
                "build version not available for node %s:%s: %s",
                self.ip,
                self.port,
                self.build,
            )
            return

        # user agent was added in 8.1
        if version.LooseVersion(self.build) < version.LooseVersion(
            constants.SERVER_USER_AGENT_FIRST_VERSION
        ):
            logger.debug("build version %s does not support user agent", self.build)
            return

        if self.user_agent is None:
            logger.debug(
                "user agent string not available for node %s:%s",
                self.ip,
                self.port,
            )
            return

        try:
            user_agent_b64 = base64.b64encode(self.user_agent.encode()).decode()
            await self._info_cinfo(
                f"user-agent-set:value={user_agent_b64}", disable_cache=True
            )
        except ASInfoError as e:
            logger.debug(
                "unable to set user agent for node %s:%s got error %s",
                self.ip,
                self.port,
                e,
            )

    async def _get_connection(self, ip, port) -> ASSocket | None:
        sock = None

        try:
            while self.socket_pool.get(port) and len(self.socket_pool[port]) > 0:
                sock = self.socket_pool[port].popleft()  # FIFO: get oldest socket

                if await sock.is_connected():
                    break

                logger.debug("closing sock %s as it is not connected", id(sock))
                await sock.close()
                sock = None

        except Exception as e:
            logger.debug(e, exc_info=True)

        if sock:
            return sock

        sock = ASSocket(
            ip,
            port,
            self.tls_name,
            self.user,
            self.password,
            self.auth_mode,
            self.ssl_context,
            timeout=self._timeout,
        )

        logger.debug("%s:%s created new sock %s", ip, port, id(sock))

        if await sock.connect():
            logger.debug(
                "%s:%s authenticating sock=%s auth_mode=%s has_token=%s "
                "token_exp_in=%ss",
                ip,
                port,
                id(sock),
                self.auth_mode,
                self.session_token is not None,
                self.session_expiration - time.time(),
            )
            try:
                if await sock.authenticate(self.session_token):
                    logger.debug("sock auth successful %s", id(sock))
                    return sock
            except ASProtocolError as e:
                logger.debug(
                    "sock auth failed %s response=%s auth_mode=%s",
                    id(sock),
                    getattr(e, "as_response", None),
                    self.auth_mode,
                )
                if e.as_response == ASResponse.SECURITY_NOT_ENABLED:
                    # A user/pass was provided and security is disabled. This is OK
                    # and a warning should have been displayed at login

                    return sock
                elif (
                    e.as_response == ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL
                    and self.user
                ):
                    # A node likely switched from security disabled to security enable.
                    # In which case the error is caused by login never being called.
                    logger.debug(
                        "trying to sock login again %s ip=%s port=%s auth_mode=%s",
                        id(sock),
                        ip,
                        port,
                        self.auth_mode,
                    )
                    # Re-login on the same socket so the token matches this backend,
                    # invalidate cached token before retry.
                    self.session_token = None
                    self.session_expiration = 0
                    if await sock.login():
                        (
                            self.session_token,
                            self.session_expiration,
                        ) = sock.get_session_info()
                        logger.debug(
                            "sock login refreshed token %s exp=%s",
                            id(sock),
                            self.session_expiration,
                        )
                        return sock
                    else:
                        logger.debug(
                            "sock login retry failed %s ip=%s port=%s auth_mode=%s",
                            id(sock),
                            ip,
                            port,
                            self.auth_mode,
                        )

                logger.debug("closing sock %s as auth failed", id(sock))
                await sock.close()
                raise

        logger.debug("sock connect failed %s", id(sock))
        return None

    @asynccontextmanager
    async def _borrow_socket(self, ip=None, port=None):
        """
        Async context manager for borrowing a socket from the pool.

        On successful exit, the socket is returned to the pool.
        On exception, the socket is closed.

        Usage:
            async with self._borrow_socket(ip, port) as sock:
                result = await sock.info(command)
        """
        if ip is None:
            ip = self.ip
        if port is None:
            port = self.port

        sock = await self._get_connection(ip, port)
        if not sock:
            raise IOError("Could not connect to node %s" % ip)

        try:
            yield sock
            # Success path: return socket to pool
            try:
                self.socket_pool[port].append(sock)
                logger.debug("returned sock %s to pool for port %s", id(sock), port)
            except Exception as e:
                logger.debug(
                    "error adding sock %s to pool %s, closing sock", id(sock), e
                )
                await sock.close()
        except Exception as ex:
            # Error path: close socket and re-raise
            logger.debug("closing sock %s due to exception: %s", id(sock), ex)
            await sock.close()
            raise

    async def close(self):
        try:
            while (
                self.socket_pool.get(self.port) and len(self.socket_pool[self.port]) > 0
            ):
                sock = self.socket_pool[self.port].popleft()
                await sock.close()
            logger.debug("closed all socks for port %s", self.port)
        except Exception:
            pass

        self.socket_pool = None

    ############################################################################
    #
    #                           Info Protocol API
    #
    ############################################################################

    # Need to provide ip to _info_cinfo as to maintain
    # unique key for cache. When we run cluster on VM and asadm on Host then
    # services returns all endpoints of server but some of them might not
    # allowed by Host and VM connection. If we do not provide IP here, then
    # we will get same result from cache for that IP to which asadm can't
    # connect. If this happens while setting ip (connection process) then node
    # will get that ip to which asadm can't connect. It will create new
    # issues in future process.
    @util.async_cached
    async def _info_cinfo(self, command, ip=None, port=None) -> str:
        if ip is None:
            ip = self.ip
        if port is None:
            port = self.port

        async with self._borrow_socket(ip, port) as sock:
            result = await sock.info(command)

            if result is not None:
                logger.debug(
                    "%s:%s info cmd '%s' and sock %s returned %s",
                    self.ip,
                    self.port,
                    command,
                    id(sock),
                    result,
                )
                return result
            else:
                raise ASInfoError("Invalid command '%s'" % command)

    @async_return_exceptions
    async def info(self, command):
        """
        asinfo function equivalent but returns exceptions instead of raising them

        Arguments:
        command -- the info command to execute on this node
        """
        return await self._info(command)

    async def _info(self, command):
        """
        TODO: Start using this as the internal info function. I think mechanism that catches
        and returns exceptions should be done at the cluster level. It can make things difficult
        with a linter when everything could possibly be an exception.

        asinfo function equivalent but raises exceptions instead of returning them

        Arguments:
        command -- the info command to execute on this node
        """
        return await self._info_cinfo(command, self.ip)

    @async_return_exceptions
    async def info_node(self):
        """
        Get this nodes id. asinfo -v "node"

        Returns:
        string -- this node's id.
        """

        return await self._info("node")

    @async_return_exceptions
    async def info_ip_port(self):
        """
        Get this nodes ip:port.

        Returns:
        string -- this node's ip:port.
        """

        return self.create_key(self.ip, self.port)

    ###### Services ######

    # post 3.10 services
    def _info_peers_helper(self, peers) -> list[Addr_Port_TLSName]:
        """
        Takes an info peers list response and returns a list.
        """
        gen_port_peers = client_util.parse_peers_string(peers)
        if not gen_port_peers or len(gen_port_peers) < 3:
            return []
        default_port = 3000
        # TODO not used generation = gen_port_peers[0]
        if gen_port_peers[1]:
            default_port = int(gen_port_peers[1])

        peers_list = client_util.parse_peers_string(gen_port_peers[2])
        if not peers_list or len(peers_list) < 1:
            return []

        p_list = []

        for p in peers_list:
            p_data = client_util.parse_peers_string(p)
            if not p_data or len(p_data) < 3:
                continue

            # TODO - not used node_name = p_data[0]
            tls_name = None
            if p_data[1] and len(p_data[1]) > 0:
                tls_name = p_data[1]

            endpoints = client_util.parse_peers_string(p_data[2])
            if not endpoints or len(endpoints) < 1:
                continue

            if not tls_name:
                tls_name = client_util.find_dns(endpoints)

            endpoint_list = []

            for e in endpoints:
                if "[" in e and "]:" not in e:
                    addr_port = client_util.parse_peers_string(e, delim=",")
                else:
                    addr_port = client_util.parse_peers_string(e, delim=":")

                addr = addr_port[0]
                if addr.startswith("["):
                    addr = addr[1:]

                if addr.endswith("]"):
                    addr = addr[:-1].strip()

                if len(addr_port) > 1 and addr_port[1] and len(addr_port[1]) > 0:
                    port = addr_port[1]
                else:
                    port = default_port

                try:
                    port = int(port)
                except Exception:
                    port = default_port

                endpoint_list.append((addr, port, tls_name))

            p_list.append(tuple(endpoint_list))

        return p_list

    def _get_info_peers_call(self):
        if self.enable_tls:
            return "peers-tls-std"

        return "peers-clear-std"

    @async_return_exceptions
    async def info_peers(self) -> list[Addr_Port_TLSName]:
        """
        Get peers this node knows of that are active

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        # Admin nodes don't have peers
        if getattr(self, "is_admin_node", False):
            return []

        return self._info_peers_helper(await self._info(self._get_info_peers_call()))

    def _get_info_peers_alumni_call(self):
        if self.enable_tls:
            return "alumni-tls-std"

        return "alumni-clear-std"

    def _get_info_peers_alumni_alt_call(self):
        if self.enable_tls:
            return "alumni-tls-alt"

        return "alumni-clear-alt"

    @async_return_exceptions
    async def info_peers_alumni(self) -> list[Addr_Port_TLSName]:
        """
        Get peers this node has ever know of
        Note: info_peers_alumni for server version prior to 4.3.1 gives only old nodes
        which are not part of current cluster.

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        # Admin nodes don't have peers
        if getattr(self, "is_admin_node", False):
            return []

        return self._info_peers_helper(
            await self._info(self._get_info_peers_alumni_call())
        )

    @async_return_exceptions
    async def info_peers_alumni_alt(self) -> list[Addr_Port_TLSName]:
        """
        Get peers this node has ever known of
        Note: info_peers_alumni for server version prior to 4.3.1 gives only old nodes
        which are not part of current cluster.

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        # Admin nodes don't have peers
        if getattr(self, "is_admin_node", False):
            return []

        return self._info_peers_helper(
            await self._info(self._get_info_peers_alumni_alt_call())
        )

    def _get_info_peers_alt_call(self):
        if self.enable_tls:
            return "peers-tls-alt"

        return "peers-clear-alt"

    @async_return_exceptions
    async def info_peers_alt(self) -> list[Addr_Port_TLSName]:
        """
        Get peers this node knows of that are active alternative addresses

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        # Admin nodes don't have peers
        if getattr(self, "is_admin_node", False):
            return []

        return self._info_peers_helper(
            await self._info(self._get_info_peers_alt_call())
        )

    def _get_info_peers_list_calls(self) -> list[str]:
        calls = []
        # at most 2 calls will be needed
        if self.consider_alumni:
            if self.use_services_alt:
                calls.append(self._get_info_peers_alumni_alt_call())
            else:
                calls.append(self._get_info_peers_alumni_call())

        if self.use_services_alt:
            calls.append(self._get_info_peers_alt_call())
        else:
            calls.append(self._get_info_peers_call())

        return calls

    def _aggregate_peers(self, results) -> list[Addr_Port_TLSName]:
        results = [self._info_peers_helper(result) for result in results]
        return list(set().union(*results))

    @async_return_exceptions
    async def info_peers_list(self) -> list[Addr_Port_TLSName]:
        # Admin nodes don't have peers
        if getattr(self, "is_admin_node", False):
            return []

        results = await asyncio.gather(
            *[self._info(call) for call in self._get_info_peers_list_calls()]
        )
        return self._aggregate_peers(results)

    @async_return_exceptions
    async def info_peers_flat_list(self):
        # Admin nodes don't have peers
        if getattr(self, "is_admin_node", False):
            return []

        return client_util.flatten(await self.info_peers_list())

    ###### Services End ######

    ###### Service ######
    # post 3.10 services

    def _info_service_helper(self, service, delimiter=","):
        if not service or isinstance(service, Exception):
            return []
        s = [
            client_util.parse_peers_string(v, ":")
            for v in client_util.info_to_list(service, delimiter=delimiter)
        ]
        return [
            (
                v[0].strip("[]"),
                int(v[1]) if len(v) > 1 and v[1] else int(self.port),
                self.tls_name,
            )
            for v in s
        ]

    def _get_service_info_call(self):
        if self.use_services_alt:
            if self.enable_tls:
                return "service-tls-alt"
            else:
                return "service-clear-alt"

        if self.enable_tls:
            return "service-tls-std"

        return "service-clear-std"

    def _get_admin_info_call(self):
        if self.enable_tls:
            return "admin-tls-std"

        return "admin-clear-std"

    def _is_admin_port_enabled(self, connection_info_response: str) -> bool:
        """
        Check if admin port is enabled on this node.
        Returns:
            bool: true if admin port is enabled, false otherwise.
        """

        if (
            not connection_info_response
            or isinstance(connection_info_response, Exception)
            or "unrecognized command" in connection_info_response
        ):
            logger.debug(
                "admin port not enabled, connection info response is: %s",
                connection_info_response,
            )
            return False

        connection_info = client_util.info_to_dict(connection_info_response)

        # Safely check if admin key exists and equals 'true'
        if connection_info.get("admin", "false") == "true":
            return True

        logger.debug(
            "admin port not enabled for node %s, connection info response is: %s",
            self.ip,
            connection_info_response,
        )
        return False

    @async_return_exceptions
    async def info_service_list(self):
        """
        Get service endpoints of this node.  Changes if tls or service-alt is enabled.

        Returns:
        list -- [(ip,port,tls_name),...]
        """
        resp = await self._info(self._get_service_info_call())
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError(ErrorsMsgs.INFO_SERVER_ERROR_RESPONSE, resp)

        return self._info_service_helper(resp)

    ###### Service End ######

    @async_return_exceptions
    async def info_statistics(self):
        """
        Get statistics for this node. asinfo -v "statistics"

        Returns:
        dictionary -- statistic name -> value
        """
        resp = await self._info("statistics")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get statistics", resp)

        return client_util.info_to_dict(resp)

    @async_return_exceptions
    async def info_namespaces(self):
        """
        Get a list of namespaces for this node. asinfo -v "namespaces"

        Returns:
        list -- list of namespaces
        """
        resp = await self._info("namespaces")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get namespaces", resp)

        return client_util.info_to_list(resp)

    @async_return_exceptions
    async def info_namespace_statistics(self, namespace):
        """
        Get statistics for a namespace.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """

        resp = await self._info("namespace/%s" % namespace)
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError(
                "Failed to get namespace statistics for {}".format(namespace), resp
            )

        ns_stat = client_util.info_to_dict(resp)

        # Due to new server feature namespace add/remove with rolling restart,
        # there is possibility that different nodes will have different namespaces.
        # type = unknown means namespace is not available on this node, so just return empty map.
        if (
            ns_stat
            and not isinstance(ns_stat, Exception)
            and "type" in ns_stat
            and ns_stat["type"] == "unknown"
        ):
            ns_stat = {}
        return ns_stat

    @async_return_exceptions
    async def info_all_namespace_statistics(self):
        namespaces = await self.info_namespaces()

        if isinstance(namespaces, Exception):
            return namespaces

        stats = {}
        for ns in namespaces:
            stats[ns] = await self.info_namespace_statistics(ns)

        return stats

    @async_return_exceptions
    async def info_set_statistics(self, namespace, set_):
        set_stat = await self._info("sets/{}/{}".format(namespace, set_))
        if set_stat.startswith("ERROR") or set_stat.startswith("error"):
            raise ASInfoResponseError("Failed to get set statistics", set_stat)

        if set_stat and set_stat[-1] == ";":
            set_stat = client_util.info_colon_to_dict(set_stat[0:-1])
        else:
            set_stat = client_util.info_colon_to_dict(set_stat)

        return set_stat

    @async_return_exceptions
    async def info_all_set_statistics(self):
        stats = await self._info("sets")
        if stats.startswith("ERROR") or stats.startswith("error"):
            raise ASInfoResponseError("Failed to get set statistics", stats)

        stats = client_util.info_to_list(stats)
        if not stats:
            return {}
        stats.pop()
        stats = [client_util.info_colon_to_dict(stat) for stat in stats]
        sets = {}
        for stat in stats:
            ns_name = util.get_value_from_dict(
                d=stat, keys=("ns_name", "namespace", "ns")
            )
            set_name = util.get_value_from_dict(d=stat, keys=("set_name", "set"))

            key = (ns_name, set_name)
            if key not in sets:
                sets[key] = {}
            set_dict = sets[key]

            set_dict.update(stat)

        return sets

    @async_return_exceptions
    async def info_health_outliers(self):
        stats = await self._info("health-outliers")
        if stats.startswith("ERROR") or stats.startswith("error"):
            raise ASInfoResponseError("Failed to get health outliers", stats)

        stats = client_util.info_to_list(stats)
        if not stats:
            return {}
        stats = [client_util.info_colon_to_dict(stat) for stat in stats]
        health_dict = {}

        for i, stat in enumerate(stats):
            key = "outlier" + str(i)
            health_dict[key] = stat

        return health_dict

    @async_return_exceptions
    async def info_best_practices(self):
        failed_practices = []
        resp = await self._info("best-practices")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get best practices", resp)

        resp_dict = client_util.info_to_dict(resp)

        if (
            "failed_best_practices" in resp_dict
            and resp_dict["failed_best_practices"] != "none"
        ):
            failed_practices = client_util.info_to_list(
                resp_dict["failed_best_practices"], delimiter=","
            )

        return failed_practices

    @async_return_exceptions
    async def info_bin_statistics(self):
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        # bins removed in 7.0
        if version.LooseVersion(build) >= version.LooseVersion(
            constants.SERVER_INFO_BINS_REMOVAL_VERSION
        ):
            logger.debug("bin stats were removed in 7.0")
            return {}

        resp = await self._info("bins")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get bin statistics", resp)

        stats = client_util.info_to_list(resp)
        if not stats:
            return {}
        stats.pop()
        stats = [value.split(":") for value in stats]
        stat_dict = {}

        for stat in stats:
            values = client_util.info_to_list(stat[1], ",")
            values = ";".join([v for v in values if "=" in v])
            values = client_util.info_to_dict(values)
            stat_dict[stat[0]] = values

        return stat_dict

    @async_return_exceptions
    async def info_dc_statistics(self, dc):
        """
        Get statistics for a datacenter.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            err = Exception("Unable to get stats for dc {} : {}".format(dc, build))
            return err

        # XDR 5 created a new API
        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            resp = await self._info("dc/%s" % dc)
            if resp.startswith("ERROR") or resp.startswith("error"):
                raise ASInfoResponseError(
                    "Failed to get DC statistics for {}".format(dc), resp
                )
            return client_util.info_to_dict(resp)

        resp = await self._info("get-stats:context=xdr;dc=%s" % dc)
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError(
                "Failed to get DC statistics for {}".format(dc), resp
            )
        return client_util.info_to_dict(resp)

    @async_return_exceptions
    async def info_all_dc_statistics(self, dcs: list[str] | None = None):
        if dcs is None:
            dcs = await self.info_dcs()

            if isinstance(dcs, Exception):
                err = Exception("Unable to get dcs : ".format(dcs))
                return err

        stat_list = await asyncio.gather(*[self.info_dc_statistics(dc) for dc in dcs])

        return dict(zip(dcs, stat_list))

    @async_return_exceptions
    async def info_XDR_statistics(self):
        """
        Get statistics for XDR

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        # XDR 5 does not have statistics at the xdr context level.  It requires a dc.
        if version.LooseVersion(build) >= version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            return {}

        resp = await self._info("statistics/xdr")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get XDR statistics", resp)
        return client_util.info_to_dict(resp)

    @async_return_exceptions
    async def info_xdr_dc_namespaces_statistics(self, dc: str, namespaces: list[str]):
        all_ns_stats = await asyncio.gather(
            *[
                self._info("get-stats:context=xdr;dc={};namespace={}".format(dc, ns))
                for ns in namespaces
            ]
        )

        all_ns_stats = list(map(client_util.info_to_dict, all_ns_stats))

        return dict(zip(namespaces, all_ns_stats))

    @async_return_exceptions
    async def info_all_xdr_namespaces_statistics(
        self, namespaces: list[str] | None = None, dcs: list[str] | None = None
    ):
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        # New in XDR5. These stats used to be stored at the namespace level
        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            return {}

        if not dcs:
            dcs = await self.info_dcs()

            if isinstance(dcs, Exception):
                err = Exception("Could not retrieve dcs: %s".format(dcs))
                logger.error(err)
                raise err

        async def helper(dc: str):
            dc_config: dict[str, dict[str, Any]] | Exception = (
                await self.info_xdr_dcs_config([dc])
            )

            if isinstance(dc_config, Exception):
                raise Exception("Could not get stats for dc %s : %s", dc, dc_config)

            dc_namespaces = client_util.info_to_list(
                dc_config[dc]["namespaces"], delimiter=","
            )

            if namespaces is not None:
                dc_namespaces = list(set(dc_namespaces).intersection(namespaces))

            return await self.info_xdr_dc_namespaces_statistics(dc, dc_namespaces)

        xdr_namespace_stats = await asyncio.gather(*[helper(dc) for dc in dcs])

        return dict(zip(dcs, xdr_namespace_stats))

    @async_return_exceptions
    async def info_set_config_xdr_create_dc(self, dc):
        dcs = await self.info_dcs()

        if dc in dcs:
            raise ASInfoResponseError(ErrorsMsgs.DC_CREATE_FAIL, ErrorsMsgs.DC_EXISTS)

        build = await self.info_build()
        if isinstance(build, Exception):
            logger.error(build)
            return build

        req = "set-config:context=xdr;dc={};action=create"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc)
        resp = await self._info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(ErrorsMsgs.DC_CREATE_FAIL, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_delete_dc(self, dc):
        dcs = await self.info_dcs()

        logger.debug("Found dcs: %s", dcs)

        if dc not in dcs:
            raise ASInfoResponseError(ErrorsMsgs.DC_DELETE_FAIL, "DC does not exist")

        build = await self.info_build()
        if isinstance(build, Exception):
            logger.error(build)
            return build

        req = "set-config:context=xdr;dc={};action=delete"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc)
        resp = await self._info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(ErrorsMsgs.DC_DELETE_FAIL, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_add_namespace(self, dc, namespace, rewind=None):
        build = await self.info_build()
        if isinstance(build, Exception):
            logger.error(build)
            return build

        req = "set-config:context=xdr;dc={};namespace={};action=add"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc, namespace)

        if rewind:
            if rewind != "all":
                try:
                    int(rewind)
                except ValueError:
                    raise ASInfoResponseError(
                        ErrorsMsgs.DC_NS_ADD_FAIL,
                        ErrorsMsgs.INVALID_REWIND,
                    )
            req += ";rewind={}".format(rewind)

        resp = await self._info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(ErrorsMsgs.DC_NS_ADD_FAIL, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_remove_namespace(self, dc, namespace):
        build = await self.info_build()
        if isinstance(build, Exception):
            logger.error(build)
            return build

        req = "set-config:context=xdr;dc={};namespace={};action=remove"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc, namespace)
        resp = await self._info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(ErrorsMsgs.DC_NS_REMOVE_FAIL, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_add_node(self, dc, node):
        build = await self.info_build()
        if isinstance(build, Exception):
            logger.error(build)
            return build

        req = "set-config:context=xdr;dc={};node-address-port={};action=add"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc, node)
        resp = await self._info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(ErrorsMsgs.DC_NODE_ADD_FAIL, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_remove_node(self, dc, node):
        build = await self.info_build()
        if isinstance(build, Exception):
            logger.error(build)
            return build

        req = "set-config:context=xdr;dc={};node-address-port={};action=remove"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc, node)
        resp = await self._info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(ErrorsMsgs.DC_NODE_REMOVE_FAIL, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr(self, param, value, dc=None, namespace=None):
        if namespace and not dc:
            raise ArgumentError("Namespace must be accompanied by a dc.")

        req = "set-config:context=xdr;{}={}".format(param, value)

        if dc:
            build = await self.info_build()
            if isinstance(build, Exception):
                logger.error(build)
                return build

            if version.LooseVersion(build) < version.LooseVersion(
                constants.SERVER_NEW_XDR5_VERSION
            ):
                req += ";datacenter={}".format(dc)
            else:
                req += ";dc={}".format(dc)

        if namespace:
            req += ";namespace={}".format(namespace)

        resp = await self._info(req)

        if resp != ASINFO_RESPONSE_OK:
            context = ["xdr"]

            if dc:
                context.append("dc")

                if dc not in await self.info_dcs():
                    raise ASInfoResponseError(
                        "Failed to set XDR configuration parameter {} to {}".format(
                            param, value
                        ),
                        ErrorsMsgs.DC_DNE,
                    )

                """
                Server does not return an error if the namespace does not exist on a
                certain dc.
                """

            if namespace:
                context.append("namespace")

            raise ASInfoConfigError(
                "Failed to set XDR configuration parameter {} to {}".format(
                    param, value
                ),
                resp,
                self,
                context,
                param,
                value,
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_logs_ids(self):
        id_file_dict = {}
        resp = await self._info("logs")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get log IDs", resp)

        ls = client_util.info_to_list(resp)

        for pair in ls:
            id, file = pair.split(":")
            id_file_dict[file] = id

        return id_file_dict

    @async_return_exceptions
    async def info_logging_config(self):
        log_ids = await self.info_logs_ids(raise_exception=True)

        async def get_logging_config(log_id):
            resp = await self._info("log/{}".format(log_id))
            if resp.startswith("ERROR") or resp.startswith("error"):
                raise ASInfoResponseError(
                    "Failed to get logging config for {}".format(log_id), resp
                )
            return client_util.info_to_dict(resp, key_value_delimter=":")

        log_names = log_ids.keys()
        configs = await asyncio.gather(
            *[get_logging_config(id) for id in log_ids.values()]
        )

        return dict(zip(log_names, configs))

    @async_return_exceptions
    async def info_set_config_logging(self, file, param, value):
        logs = await self.info_logs_ids()
        error_message = "Failed to set logging configuration parameter {} to {}"

        if file not in logs:
            raise ASInfoResponseError(
                error_message.format(param, value),
                "{} does not exist".format(file),
            )

        resp = await self._info("log-set:id={};{}={}".format(logs[file], param, value))

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoConfigError(
                error_message.format(param, value),
                resp,
                self,
                ["logging"],
                param,
                value,
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_service(self, param, value):
        resp = await self._info("set-config:context=service;{}={}".format(param, value))

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoConfigError(
                "Failed to set service configuration parameter {} to {}".format(
                    param, value
                ),
                resp,
                self,
                ["service"],
                param,
                value,
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_namespace(
        self, param, value, namespace, set_=None, subcontext=None
    ):
        new_param = param
        if subcontext and subcontext not in {"storage-engine", "index-type"}:
            delimiter = "."

            if subcontext == "geo2dsphere-within":
                delimiter = "-"

            new_param = delimiter.join([subcontext, param])

        namespace_info_selector = "id"

        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        if version.LooseVersion(build) >= version.LooseVersion(
            constants.SERVER_INFO_NAMESPACE_SELECTOR_VERSION
        ):
            namespace_info_selector = "namespace"

        req = "set-config:context=namespace;{}={};{}={}".format(
            namespace_info_selector, namespace, new_param, value
        )

        if set_:
            req += ";set={}".format(set_)

        resp = await self._info(req)

        if resp != ASINFO_RESPONSE_OK:
            context = ["namespace"]

            if set_ is not None:
                context.append("set")

            if subcontext is not None:
                context.append(subcontext)

            # Check if namespace exists, but handle potential errors from info_namespaces()
            namespaces = await self.info_namespaces()
            if isinstance(namespaces, Exception):
                logger.error(
                    f"Failed to get namespaces while setting config: {namespaces}"
                )
                return namespaces

            if namespace and namespace not in namespaces:
                raise ASInfoResponseError(
                    "Failed to set namespace configuration parameter {} to {}".format(
                        param, value
                    ),
                    ErrorsMsgs.NS_DNE,
                )

            """
            Server does not return an error if the set does not exist on a
            certain namespace.
            """

            raise ASInfoConfigError(
                "Failed to set namespace configuration parameter {} to {}".format(
                    param, value
                ),
                resp,
                self,
                context,
                param,
                value,
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_network(self, param, value, subcontext):
        new_param = ".".join([subcontext, param])
        resp = await self._info(
            "set-config:context=network;{}={}".format(new_param, value)
        )

        if resp != ASINFO_RESPONSE_OK:
            context = ["network"]

            if subcontext is not None:
                context.append(subcontext)

            raise ASInfoConfigError(
                "Failed to set network configuration parameter {} to {}".format(
                    param, value
                ),
                resp,
                self,
                context,
                param,
                value,
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_security(self, param, value, subcontext=None):
        new_param = param
        if subcontext:
            new_param = ".".join([subcontext, param])

        resp = await self._info(
            "set-config:context=security;{}={}".format(new_param, value)
        )

        if resp != ASINFO_RESPONSE_OK:
            context = ["security"]

            if subcontext is not None:
                context.append(subcontext)

            raise ASInfoConfigError(
                "Failed to set security configuration parameter {} to {}".format(
                    param, value
                ),
                resp,
                self,
                context,
                param,
                value,
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_get_config(self, stanza="", namespace=""):
        """
        Get the complete config for a node. This should include the following
        stanzas: Service, Network, XDR, and Namespace
        Sadly it seems Service and Network are not separable.

        Returns:
        dict -- stanza --> [namespace] --> param --> value
        """
        config = {}

        if stanza == "namespace":
            config = await self.info_namespace_config(namespace)
        elif stanza == "xdr":
            config = await self.info_xdr_config()
        elif not stanza:
            resp = await self._info("get-config:")
            if resp.startswith("ERROR") or resp.startswith("error"):
                raise ASInfoResponseError("Failed to get config", resp)
            config = client_util.info_to_dict(resp)
        else:
            resp = await self._info("get-config:context=%s" % stanza)
            if resp.startswith("ERROR") or resp.startswith("error"):
                raise ASInfoResponseError(
                    f"Failed to get config for context {stanza}", resp
                )
            config = client_util.info_to_dict(resp)
        return config

    @async_return_exceptions
    async def info_single_namespace_config(
        self, getconfig_namespace_command, namespace
    ):
        return client_util.info_to_dict(
            await self._info(f"{getconfig_namespace_command}{namespace}")
        )

    @async_return_exceptions
    async def info_namespace_config(self, namespace=""):
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        namespace_info_selector = "id"
        if version.LooseVersion(build) >= version.LooseVersion(
            constants.SERVER_INFO_NAMESPACE_SELECTOR_VERSION
        ):
            namespace_info_selector = "namespace"

        getconfig_namespace_command = "get-config:context=namespace;{}=".format(
            namespace_info_selector
        )

        if namespace != "":
            return {
                namespace: await self.info_single_namespace_config(
                    getconfig_namespace_command, namespace
                )
            }
        else:
            namespaces = await self.info_namespaces()
            config_list = await client_util.concurrent_map(
                lambda ns: self.info_single_namespace_config(
                    getconfig_namespace_command, ns
                ),
                namespaces,
            )

            return dict(zip(namespaces, config_list))

    @async_return_exceptions
    async def info_xdr_config(self):
        resp = await self._info("get-config:context=xdr")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get XDR config", resp)
        return client_util.info_to_dict(resp)

    @async_return_exceptions
    async def info_xdr_single_dc_config(self, dc):
        resp = await self._info("get-config:context=xdr;dc=%s" % dc)
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError(f"Failed to get XDR DC config for {dc}", resp)
        return client_util.info_to_dict(resp)

    @async_return_exceptions
    async def info_xdr_dcs_config(self, dcs: list[str] | None = None):
        """
        Get config for a datacenter.

        Returns:
        dict -- {dc_name1:{config_name : config_value, ...}, dc_name2:{config_name : config_value, ...}}
        """
        build = None

        if dcs is not None:
            build = await self.info_build()
        else:
            build, dcs = await asyncio.gather(self.info_build(), self.info_dcs())

        if isinstance(build, Exception):
            logger.error(build)
            return build

        # New in XDR5. These stats used to be stored at the namespace level
        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            try:
                configs = await self._info("get-dc-config")
            except Exception as e:
                configs = await self._info("get-dc-config:")

            result = client_util.info_to_dict_multi_level(
                configs,
                ["dc-name", "DC_Name"],
                ignore_field_without_key_value_delimiter=False,
            )

            if isinstance(result, Exception):
                logger.error(result)
                return result

            # No way to get specific DCs back in the pre XDR5 days.
            for dc in list(result.keys()):
                if dc not in dcs:
                    result.pop(dc)

            return result

        if isinstance(dcs, Exception):
            logger.error(dcs)
            return dcs

        result = await asyncio.gather(
            *[self.info_xdr_single_dc_config(dc) for dc in dcs]
        )

        return dict(zip(dcs, result))

    @async_return_exceptions
    async def info_xdr_dc_single_namespace_config(self, dc: str, ns: str):
        resp = await self._info(
            "get-config:context=xdr;dc={};namespace={}".format(dc, ns)
        )
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError(
                f"Failed to get XDR config for DC {dc} and namespace {ns}", resp
            )
        return client_util.info_to_dict(resp)

    @async_return_exceptions
    async def info_xdr_dc_namespaces_config(self, dc: str, namespaces: list[str]):
        """
        Returns multiple namespace configs for a single datacenter.
        namespaces: If None returns all namespaces configured to ship to a datacenter.
                    else it returns config for specified namespaces.
        """
        ns_configs = await asyncio.gather(
            *[self.info_xdr_dc_single_namespace_config(dc, ns) for ns in namespaces]
        )

        return dict(zip(namespaces, ns_configs))

    @async_return_exceptions
    async def info_xdr_namespaces_config(
        self, namespaces: list[str] | None = None, dcs: list[str] | None = None
    ):
        """
        Returns multiple namespace configs for multiple datacenters.
        namespaces: If None returns all namespaces from the specified dcs.
                    Else it returns config for specified namespaces from the specified dcs.
        dcs:        If None returns specified namespaces configs from all dcs.
                    Else it returns specified namespaces from specified dcs.
        Note: Namespaces are checked to see if they are defined for a specific dc before
        the configuration is requested.  If a namespace does not exist on a dc the request
        is skipped.
        """
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        # New in XDR5. XDR Namespace configs used to be defined inside the namespace context.
        # Now they are defined in the xdr.dc context.
        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            return {}

        if not dcs:
            dcs = await self.info_dcs()

        async def helper(dc):
            dc_config = await self.info_xdr_dcs_config([dc])
            dc_namespaces: list[str] = dc_config[dc]["namespaces"].split(",")

            if namespaces is not None:
                dc_namespaces = list(set(namespaces).intersection(dc_namespaces))

            return await self.info_xdr_dc_namespaces_config(dc, dc_namespaces)

        xdr_ns_configs = await asyncio.gather(*[helper(dc) for dc in dcs])

        return dict(zip(dcs, xdr_ns_configs))

    async def _get_xdr_filter_helper(
        self, dc: str
    ) -> common.NamespaceDict[dict[str, str]]:
        str_resp = client_util.info_to_dict_multi_level(
            await self._info("xdr-get-filter:dc={}".format(dc)), keyname="namespace"
        )
        b64_resp = client_util.info_to_dict_multi_level(
            await self._info("xdr-get-filter:dc={};b64=true".format(dc)),
            keyname="namespace",
        )

        for ns in b64_resp.keys():
            str_resp[ns]["b64-exp"] = b64_resp[ns]["exp"]

        return str_resp

    @async_return_exceptions
    async def info_get_xdr_filter(self, dcs: list[str] | None = None):
        if dcs is None:
            dcs = await self.info_dcs()

        filters = await asyncio.gather(*[self._get_xdr_filter_helper(dc) for dc in dcs])

        return dict(zip(dcs, filters))

    @async_return_exceptions
    async def info_get_originalconfig(self, stanza=""):
        """
        Get the original config (from conf file) for a node. This should include the following
        stanzas: Service, Network, XDR, DC, and Namespace

        Returns:
        dict -- stanza --> [namespace] --> param --> value
        """
        config = {}
        if not self.localhost:
            return config

        if not self.as_conf_data:
            self.as_conf_data = conf_parser.parse_file("/etc/aerospike/aerospike.conf")
            if "namespace" in self.as_conf_data:
                for ns in self.as_conf_data["namespace"].keys():
                    if "service" in self.as_conf_data["namespace"][ns]:
                        self.as_conf_data["namespace"][ns] = self.as_conf_data[
                            "namespace"
                        ][ns]["service"]

        try:
            config = self.as_conf_data[stanza]

        except Exception:
            pass

        return config

    def _update_total_latency(self, total_rows, row, has_time_range_col=True):
        """
        Takes a latency information for a single histogram and integrates it into
        the total_rows.  Since most of the values are percentages there is some
        math involve.

        row -- a single histograms values. These values coorespond to ops/sec
        and a specified number of latency buckets, i.e. 1ms, 8ms, 64ms . . .

        total_rows -- The total latency information before the current row is
        integrated.

        total_rows --
        """
        if not row or not isinstance(row, list):
            return total_rows
        if not total_rows:
            total_rows = []
            total_rows.append(row)
            return total_rows

        has_time_range_col = int(has_time_range_col)
        time_range = row[0]
        updated = False

        for total_row in total_rows:
            if not has_time_range_col or total_row[0] == time_range:
                new_sum = float(row[has_time_range_col])
                if new_sum > 0:
                    old_sum = float(total_row[has_time_range_col])
                    for i, transaction_percent in enumerate(
                        total_row[1 + has_time_range_col :]
                    ):
                        row_idx = i + 1 + has_time_range_col
                        old_transactions = float(
                            (old_sum * transaction_percent) / 100.00
                        )
                        new_transactions = float((new_sum * row[row_idx]) / 100.00)
                        total_row[row_idx] = round(
                            float(
                                ((old_transactions + new_transactions) * 100)
                                / (old_sum + new_sum)
                            ),
                            2,
                        )
                    total_row[has_time_range_col] = round(old_sum + new_sum, 2)

                updated = True
                break

        if not updated:
            total_rows.append(copy.deepcopy(row))
        return total_rows

    @async_return_exceptions
    async def info_latency(self, back=None, duration=None, slice_tm=None, ns_set=None):
        cmd = "latency:"
        try:
            if back or back == 0:
                cmd += "back=%d" % (back) + ";"
        except Exception:
            pass

        try:
            if duration or duration == 0:
                cmd += "duration=%d" % (duration) + ";"
        except Exception:
            pass

        try:
            if slice_tm or slice_tm == 0:
                cmd += "slice=%d" % (slice_tm) + ";"
        except Exception:
            pass
        data = {}

        try:
            hist_info = await self._info(cmd)
        except Exception:
            return data
        tdata = hist_info.split(";")
        hist_name = None
        ns = None
        start_time = None
        columns = []
        ns_hist_pattern = r"{([A-Za-z_\d-]+)}-([A-Za-z_-]+)"
        total_key = "total"

        while tdata != []:
            row = tdata.pop(0)
            if not row:
                continue
            row = row.split(",")

            # neglect if error string
            if len(row) < 2:
                continue

            s1, s2 = row[0].split(":", 1)

            if not s1.isdigit():
                m = re.search(ns_hist_pattern, s1)
                if m:
                    ns = m.group(1)
                    hist_name = m.group(2)
                else:
                    ns = None
                    hist_name = s1
                if ns_set and (not ns or ns not in ns_set):
                    hist_name = None
                    continue
                columns = [col.replace("u", "\u03bc") for col in row[1:]]
                start_time = s2
                start_time = client_util.remove_suffix(start_time, "-GMT")
                columns.insert(0, "Time Span")
                continue

            if not hist_name or not start_time:
                continue
            try:
                end_time = row.pop(0)
                end_time = client_util.remove_suffix(end_time, "-GMT")
                row = [float(r) for r in row]
                row.insert(0, "%s->%s" % (start_time, end_time))
                if hist_name not in data:
                    data[hist_name] = {}
                if ns:
                    ns_key = "namespace"
                    if ns_key not in data[hist_name]:
                        data[hist_name][ns_key] = {}
                    if ns not in data[hist_name][ns_key]:
                        data[hist_name][ns_key][ns] = {}
                        data[hist_name][ns_key][ns]["columns"] = columns
                        data[hist_name][ns_key][ns]["values"] = []
                    data[hist_name][ns_key][ns]["values"].append(copy.deepcopy(row))
                if total_key not in data[hist_name]:
                    data[hist_name][total_key] = {}
                    data[hist_name][total_key]["columns"] = columns
                    data[hist_name][total_key]["values"] = []

                data[hist_name][total_key]["values"] = self._update_total_latency(
                    data[hist_name][total_key]["values"], row
                )
                start_time = end_time
            except Exception:
                pass
        return data

    @async_return_exceptions
    async def info_latencies(
        self, buckets=3, exponent_increment=3, verbose=False, ns_set=None
    ):
        """
        Get latencies metrics from this node. asinfo -v "latencies:" -p 3004

        Returns:
        dict -- {'host_address:port': {'histogram_name': {'namespace/total':
        {'namespace_name': {'columns': ['column1', 'column2', . . .], 'values':
        [[val1, val2, . . .]]}}, . . .}}}}
        """

        # If verbose, make additional queries for micro-benchmarks
        cmd_latencies = ["latencies:"]
        data = {}

        if verbose:
            namespaces = []
            if ns_set:
                namespaces = ns_set
            else:
                try:
                    namespaces = (await self._info("namespaces")).split(";")
                except Exception:
                    return data
            micro_benchmarks = [
                "proxy",
                "benchmarks-ops-sub",
                "benchmarks-read",
                "benchmarks-write",
                "benchmarks-udf",
                "benchmarks-udf-sub",
                "benchmarks-batch-sub",
            ]
            cmd_latencies += [
                "latencies:hist={%s}-%s" % (ns, optional)
                for ns in namespaces
                for optional in micro_benchmarks
            ]

            # TOOLS-2984: benchmarks-fabric is not at namespace-level
            cmd_latencies.append("latencies:hist=benchmarks-fabric")

        hist_info = []
        for cmd in cmd_latencies:
            try:
                hist_info.append(await self._info(cmd))
            except Exception:
                return data
            # TOOLS-2964: Error came as ERROR for 7.2 onwards
            if hist_info[-1].startswith("error") or hist_info[-1].startswith("ERROR"):
                hist_info.pop()
                continue

        # example hist info after join:
        # batch-index:;{test}-read:msec,0.0,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00, /
        # 0.00,0.00,0.00,0.00,0.00,0.00,0.00;{test}-write:msec,0.0,0.00,0.00,0.00,0.00,0.00,0.00, /
        # 0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00;{test}-udf:;{test}-query:;{bar}-read:; /
        # {bar}-write:;{bar}-udf:;{bar}-query: /
        hist_info = ";".join(hist_info)
        tdata = hist_info.split(";")
        hist_name = None
        ns = None
        unit_mapping = {"msec": "ms", "usec": "us"}
        time_units = None
        exponent_increment = 1 if exponent_increment <= 0 else exponent_increment
        columns = [
            ">1",
            ">2",
            ">4",
            ">8",
            ">16",
            ">32",
            ">64",
            ">128",
            ">256",
            ">512",
            ">1024",
            ">2048",
            ">4096",
            ">8192",
            ">16384",
            ">32768",
            ">65536",
        ][::exponent_increment][:buckets]
        ns_hist_pattern = r"{([A-Za-z_\d-]+)}-([A-Za-z_-]+)"
        total_key = "total"

        for hist in tdata:
            if not hist:
                continue
            hist_name, hist_data = hist.split(":")
            hist_data = hist_data.split(",")
            m = re.search(ns_hist_pattern, hist_name)

            # Remove empty histograms, len 2 just to be safe
            if len(hist_data) <= 2:
                continue

            if m:
                ns = m.group(1)
                hist_name = m.group(2)
            # Is batch histogram w/o namespace
            else:
                ns = None

            if ns_set and (not ns or ns not in ns_set):
                hist_name = None
                continue

            if time_units is None:
                time_units = hist_data.pop(0)
                columns = ["ops/sec"] + [
                    (col + unit_mapping[time_units]) for col in list(columns)
                ]
            else:
                hist_data.pop(0)

            latency_data = [float(r) for r in hist_data]
            # Remove ops/sec and then add it back in after getting correct latency buckets.
            latency_data = [latency_data[0]] + latency_data[1:][::exponent_increment][
                :buckets
            ]

            try:
                if hist_name not in data:
                    data[hist_name] = {}

                if ns:
                    ns_key = "namespace"

                    if ns_key not in data[hist_name]:
                        data[hist_name][ns_key] = {}

                    if ns not in data[hist_name][ns_key]:
                        data[hist_name][ns_key][ns] = {}
                        data[hist_name][ns_key][ns]["columns"] = columns
                        data[hist_name][ns_key][ns]["values"] = []

                    data[hist_name][ns_key][ns]["values"].append(
                        copy.deepcopy(latency_data)
                    )

                if total_key not in data[hist_name]:
                    data[hist_name][total_key] = {}
                    data[hist_name][total_key]["columns"] = columns
                    data[hist_name][total_key]["values"] = []

                data[hist_name][total_key]["values"] = self._update_total_latency(
                    data[hist_name][total_key]["values"],
                    latency_data,
                    has_time_range_col=False,
                )
            except Exception:
                # Missing histogram
                pass
        return data

    @async_return_exceptions
    async def info_dcs(self):
        """
        Get a list of datacenters for this node. asinfo -v "dcs" -p 3004

        Returns:
        list -- list of dcs
        """
        build = await self.info_build()
        if isinstance(build, Exception):
            logger.error(build)
            return build

        xdr_major_version = int(build[0])

        # for server versions >= 5 using XDR5.0
        if xdr_major_version >= 5:
            xdr_data = client_util.info_to_dict(
                await self._info("get-config:context=xdr")
            )

            if xdr_data is None:
                return []

            dcs = xdr_data.get("dcs", "")

            if dcs == "":
                return []

            return client_util.info_to_list(dcs, delimiter=",")

        dcs = await self._info("dcs")
        if dcs.startswith("ERROR") or dcs.startswith("error"):
            raise ASInfoResponseError("Failed to get DCs", dcs)

        if dcs == "":
            return []

        return client_util.info_to_list(dcs)

    @async_return_exceptions
    async def info_udf_list(self):
        """
        Get list of UDFs stored on the node.

        Returns:
        dict -- {<file-name>: {"filename": <file-name>, "hash": <hash>, "type": 'LUA'}, . . .}
        """
        udf_data = await self._info("udf-list")
        if udf_data.startswith("ERROR") or udf_data.startswith("error"):
            raise ASInfoResponseError("Failed to get UDF list", udf_data)

        if not udf_data:
            return {}

        return client_util.info_to_dict_multi_level(
            udf_data, "filename", delimiter2=","
        )

    @async_return_exceptions
    async def info_udf_get(self, filename):
        """
        Get list of UDFs stored on the node.
        Returns:
        dict -- {<file-name>: {"content": <content>, "type": 'LUA'}, . . .}
        """
        udf_data = await self._info("udf-get:filename={}".format(filename))
        if udf_data.startswith("ERROR") or udf_data.startswith("error"):
            raise ASInfoResponseError("Failed to get UDF", udf_data)

        if not udf_data:
            return {}

        return client_util.info_to_dict(udf_data)

    @async_return_exceptions
    async def info_udf_put(self, udf_file_name, udf_str, udf_type="LUA"):
        """
        Add a udf module.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        content = base64.b64encode(udf_str.encode("ascii"))
        content = content.decode("ascii")
        content_len = len(content)

        command = (
            "udf-put:filename="
            + udf_file_name
            + ";udf-type="
            + udf_type
            + ";content-len="
            + str(content_len)
            + ";content="
            + content
        )
        resp = await self._info(command)

        if resp.lower() not in {ASINFO_RESPONSE_OK, ""}:
            raise ASInfoResponseError(ErrorsMsgs.UDF_UPLOAD_FAIL, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_udf_remove(self, udf_file_name):
        """
        Remove a udf module.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        existing_udfs = await self.info_udf_list()
        existing_names = existing_udfs.keys()

        # Server does not check if udf exists
        if udf_file_name not in existing_names:
            raise ASInfoResponseError(
                "Failed to remove UDF {}".format(udf_file_name), ErrorsMsgs.UDF_DNE
            )
        command = "udf-remove:filename=" + udf_file_name + ";"
        resp = await self._info(command)

        if resp.lower() not in {ASINFO_RESPONSE_OK, ""}:
            raise ASInfoResponseError(
                "Failed to remove UDF {}".format(udf_file_name), resp
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_roster_namespace(self, namespace):
        """
        Show roster information (for namespaces running in strong consistency mode). A
        list with a single element equal to [] indicates an unset roster.

        This is different from info_roster to maintain backwards compatibility with health_check.

        Returns: {"roster": [node_id[@rack_id], ...], "pending_roster": [node_id[@rack_id], ...], "observed_nodes": [node_id[@rack_id], ...]}
        """
        req = "roster:namespace={}".format(namespace)
        resp = await self._info(req)

        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError(ErrorsMsgs.ROSTER_READ_FAIL, resp)

        response = client_util.info_to_dict(resp, delimiter=":")

        for key in response:
            if key in self.info_roster_list_fields:
                if response[key] == "null":
                    response[key] = []
                else:
                    response[key] = client_util.info_to_list(
                        response[key], delimiter=","
                    )

        return response

    @async_return_exceptions
    async def info_roster(self, namespace=None):
        """
        Get roster info. A key_value of ['null'] indicates an unset roster.

        Returns:
        dict -- {ns1:{key_name : key_value, ...}, ns2:{key_name : key_value, ...}}
        """
        if namespace is not None:
            return await self.info_roster_namespace(namespace)

        roster_data = await self._info("roster:")
        if roster_data.startswith("ERROR") or roster_data.startswith("error"):
            raise ASInfoResponseError("Failed to get roster", roster_data)

        if not roster_data:
            return {}

        roster_data = client_util.info_to_dict_multi_level(roster_data, "ns")

        for ns, ns_roster_data in roster_data.items():
            for k, v in ns_roster_data.items():
                if k in self.info_roster_list_fields:
                    ns_roster_data[k] = v.split(",")
                else:
                    ns_roster_data[k] = v

        return roster_data

    @async_return_exceptions
    async def info_roster_set(self, namespace, node_ids):
        """
        Set the pending roster (for namespaces running in strong consistency mode).

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        req = "roster-set:namespace={};nodes={}".format(namespace, ",".join(node_ids))
        resp = await self._info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(
                "Failed to set roster for namespace {}".format(namespace), resp
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_cluster_stable(
        self, cluster_size=None, namespace=None, ignore_migrations=False
    ):
        """
        Used to check if a nodes cluster-state has stabilized by comparing result with
        the result returned for other nodes.

        Returns: str key on success and ASInfoError on failure
        """
        req = "cluster-stable:"
        args = []

        if cluster_size is not None:
            args.append("size={}".format(cluster_size))

        if namespace is not None:
            args.append("namespace={}".format(namespace))

        if ignore_migrations is not False:
            args.append("ignore_migrations={}".format(str(ignore_migrations).lower()))

        req += ";".join(args)

        resp = await self._info(req)

        if "error" in resp.lower():
            raise ASInfoResponseError(ErrorsMsgs.INFO_SERVER_ERROR_RESPONSE, resp)

        return resp

    @async_return_exceptions
    async def info_racks(self):
        """
        Get rack info.
        If roster_rack is returned then that value is used.  Otherwise use rack value.
        roster_rack is the value returned when the rack_id is set via the roster.

        Returns:
        dict -- {ns1:{rack-id: {'rack-id': rack-id, 'nodes': [node1, node2, ...]}, ns2:{...}, ...}
        """
        rack_data = await self._info("racks:")
        if rack_data.startswith("ERROR") or rack_data.startswith("error"):
            raise ASInfoResponseError("Failed to get racks", rack_data)

        if not rack_data:
            return {}

        rack_data = client_util.info_to_dict_multi_level(rack_data, "ns")
        rack_dict = {}

        for ns, ns_rack_data in rack_data.items():
            keys = list(ns_rack_data.keys())
            likes = util.compile_likes(["roster_rack"])
            roster_keys = list(filter(likes.search, keys))

            if not roster_keys:
                likes = util.compile_likes(["^rack"])
                roster_keys = list(filter(likes.search, keys))

            rack_dict[ns] = {}

            for k in roster_keys:
                v = ns_rack_data[k]

                if k == "ns":
                    continue

                try:
                    rack_id = k.split("_")[-1]
                    nodes = v.split(",")

                    rack_dict[ns][rack_id] = {}
                    rack_dict[ns][rack_id]["rack-id"] = rack_id
                    rack_dict[ns][rack_id]["nodes"] = nodes
                except Exception:
                    continue

        return rack_dict

    @async_return_exceptions
    async def info_rack_ids(self):
        """
        Get rack ids for this node for each namespace.

        Returns:
        dict -- {ns1: rack_id, ns2: rack_id, ...}
        """
        resp = await self._info("rack-ids")

        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get rack ids for this node", resp)

        rack_data = {}

        if not resp:
            return {}

        resp = client_util.info_to_list(resp)

        for ns_id in resp:
            ns, id_ = client_util.info_to_tuple(ns_id)

            if id_ != "":
                rack_data[ns] = id_

        return rack_data

    async def _collect_histogram_data(
        self, histogram, command, logarithmic=False, raw_output=False
    ):
        namespaces = await self.info_namespaces()

        data = {}
        datums = await asyncio.gather(
            *[self._info(command % (namespace, histogram)) for namespace in namespaces]
        )

        for namespace, datum in zip(namespaces, datums):
            try:
                if not datum or isinstance(datum, Exception):
                    continue

                if raw_output:
                    data[namespace] = datum

                else:
                    d = common.parse_raw_histogram(
                        histogram, datum, logarithmic, self.new_histogram_version
                    )
                    if d and not isinstance(d, Exception):
                        data[namespace] = d

            except Exception:
                pass

        return data

    @async_return_exceptions
    async def info_histogram(self, histogram, logarithmic=False, raw_output=False):
        if not self.new_histogram_version:
            return await self._collect_histogram_data(
                histogram, command="hist-dump:ns=%s;hist=%s", raw_output=raw_output
            )

        command = "histogram:namespace=%s;type=%s"

        if logarithmic:
            if histogram == "objsz":
                histogram = "object-size"
            return await self._collect_histogram_data(
                histogram,
                command=command,
                logarithmic=logarithmic,
                raw_output=raw_output,
            )

        if histogram == "objsz":
            histogram = "object-size-linear"

        return await self._collect_histogram_data(
            histogram, command=command, logarithmic=logarithmic, raw_output=raw_output
        )

    @async_return_exceptions
    async def info_sindex(self):

        resp = await self._info("sindex-list:")

        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get sindex list", resp)

        return [
            client_util.info_to_dict(v, ":")
            for v in client_util.info_to_list(resp)
            if v != ""
        ]

    @async_return_exceptions
    async def info_user_agents(self):
        """
        Get a list of user agents for this node.
        """
        response = await self._info("user-agents")

        if response.startswith("ERROR") or response.startswith("error"):
            raise ASInfoResponseError("Failed to get user agents", response)

        return [
            client_util.info_to_dict(v, ":")
            for v in client_util.info_to_list(response)
            if v != ""
        ]

    @async_return_exceptions
    async def info_sindex_statistics(self, namespace, indexname):
        """
        Get statistics for a sindex.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """

        resp = await self._info(
            "sindex-stat:namespace=%s;indexname=%s" % (namespace, indexname)
        )
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError(ErrorsMsgs.INFO_SERVER_ERROR_RESPONSE, resp)

        return client_util.info_to_dict(resp)

    @async_return_exceptions
    async def info_sindex_create(
        self,
        index_name: str,
        namespace: str,
        bin_name: str,
        bin_type: str,
        index_type: Optional[str] = None,
        set_: Optional[str] = None,
        ctx: Optional[CDTContext] = None,
        cdt_ctx_base64: Optional[str] = None,
        exp_base64: Optional[str] = None,
        feature_support: dict[str, bool] = {},
    ):
        """
        Create a new secondary index. index_type and set are optional.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        command = "sindex-create:indexname={};".format(index_name)

        if index_type:
            command += "indextype={};".format(index_type)

        namespace_info_selector = "ns"

        if feature_support["namespace_query_selector_support"]:
            namespace_info_selector = "namespace"

        command += "{}={};".format(namespace_info_selector, namespace)

        if set_:
            command += "set={};".format(set_)

        if ctx:
            packer = ASPacker()
            packer.pack(ctx)
            ctx_bytes: bytes = packer.bytes()
            ctx_b64 = base64.b64encode(ctx_bytes)
            ctx_b64 = util.bytes_to_str(ctx_b64)

            command += "context={};".format(ctx_b64)
        elif cdt_ctx_base64:
            # Use pre-encoded base64 context string directly
            command += "context={};".format(cdt_ctx_base64)

        if exp_base64:
            command += "exp={};".format(exp_base64)

            # if expression is passed, use type instead of indexdata
            command += "type={}".format(bin_type)

        else:
            if feature_support["expression_indexing"]:
                command += "bin={};type={}".format(bin_name, bin_type)
            else:
                command += "indexdata={},{}".format(bin_name, bin_type)

        resp = await self._info(command)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(
                "Failed to create sindex {}".format(index_name), resp
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_sindex_delete(
        self, index_name, namespace, set_=None, feature_support: dict[str, bool] = {}
    ):
        """
        Delete a secondary index. set_ must be provided if sindex is created on a set.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        namespace_info_selector = "ns"

        if feature_support["namespace_query_selector_support"]:
            namespace_info_selector = "namespace"

        command = "sindex-delete:{}={};indexname={}".format(
            namespace_info_selector, namespace, index_name
        )

        if set_ is not None:
            command = "sindex-delete:{}={};set={};indexname={}".format(
                namespace_info_selector, namespace, set_, index_name
            )

        resp = await self._info(command)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(
                "Failed to delete sindex {}".format(index_name), resp
            )

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_build(self, disable_cache=False):
        """
        Get Build Version. i.e. w.x.y.z

        Caches the build version after first successful fetch to minimize network calls.
        Exceptions are NOT cached to allow automatic retry on transient failures.

        Args:
            disable_cache: If True, bypass cache and fetch fresh from server

        Returns:
        string -- build version or Exception
        """
        # Return cached version if available, not disabled, and not an exception
        if not disable_cache and self.build and not isinstance(self.build, Exception):
            return self.build

        resp = await self._info("build")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get build", resp)

        # Cache only successful results
        self.build = resp
        return resp

    @async_return_exceptions
    async def info_peers_generation(self):
        """
        Get peers generation.
        """
        resp = await self._info("peers-generation")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get peers generation", resp)
        return resp

    @async_return_exceptions
    async def info_version(self):
        """
        Get server version and edition information. For servers >= 8.1.1, uses info_release
        to get structured edition data. For older servers, uses the traditional
        info("version") command.

        Returns:
        string -- Version string (e.g., "Aerospike Enterprise Edition build 8.1.1.0")
        """

        build = await self.info_build()
        if isinstance(build, Exception):
            return build

        # Check if server supports release info (8.1.1+)
        if version.LooseVersion(build) >= version.LooseVersion(
            constants.SERVER_RELEASE_INFO_FIRST_VERSION
        ):

            # For 8.1.1+ servers, use info_release
            release_info = await self.info_release()
            if isinstance(release_info, Exception):
                return release_info

            # Reconstruct version string from release info
            edition = release_info.get("edition", "")
            version_num = release_info.get("version", "")
            logger.debug(
                f"Using release info command to extract edition='{edition}' and version='{version_num}'"
            )

            if edition and version_num:
                return f"{edition} build {version_num}"
            else:
                # Return error if data is incomplete
                logger.debug(f"Incomplete release data: {release_info}")
                raise ASInfoError(
                    "Incomplete release info data",
                    f"Missing edition or version fields in release info: {release_info}",
                )
        else:
            logger.debug(
                f"Using version info command for server {build} (< {constants.SERVER_RELEASE_INFO_FIRST_VERSION})"
            )

            # Use traditional version command for older servers only
            resp = await self._info("version")
            if resp.startswith("ERROR") or resp.startswith("error"):
                raise ASInfoResponseError("Failed to get version", resp)
            return resp

    @async_return_exceptions
    async def info_release(self):
        """
        Get detailed release information (8.1.1 or later).
        Parses the release response into key/value pairs.
        """

        build = await self.info_build()
        if isinstance(build, Exception):
            return build

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_RELEASE_INFO_FIRST_VERSION
        ):
            raise ASInfoError(
                f"'release' command requires server version {constants.SERVER_RELEASE_INFO_FIRST_VERSION}+",
                f"current version: {build}",
            )

        resp = await self._info("release")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get release info", resp)

        return client_util.info_to_dict(resp)

    @async_return_exceptions
    async def info_feature_key(self):
        """
        Get feature-key information for this node. asinfo -v "feature-key"

        Returns:
        dictionary -- feature name -> value (e.g., {"asdb-compression": "true", ...})
        """
        resp = await self._info("feature-key")
        if resp.startswith("ERROR") or resp.startswith("error"):
            raise ASInfoResponseError("Failed to get feature-key", resp)

        return client_util.info_to_dict(resp)

    async def _use_new_truncate_command(self):
        """
        A new truncate-namespace and truncate-namespace-undo was added to some
        4.3.x, 4.4.x, and 4.5.x but not all
        """
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return False

        for version_ in constants.SERVER_TRUNCATE_NAMESPACE_CMD_FIRST_VERSIONS:
            if version_[1] is not None:
                if version.LooseVersion(version_[0]) <= version.LooseVersion(
                    build
                ) and version.LooseVersion(build) < version.LooseVersion(version_[1]):
                    return True
            else:
                if version.LooseVersion(version_[0]) <= version.LooseVersion(build):
                    return True

        return False

    @async_return_exceptions
    async def info_truncate(self, namespace, set_=None, lut=None):
        """
        Truncate a namespace or set. If namespace and set are provided a set will be
        truncated. Deletes every record in the namespace/set whose last update time (lut)
        is older than the given time.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        req = None
        error_message = None

        if set_ is not None:
            req = "truncate:namespace={};set={}".format(namespace, set_)
            error_message = "Failed to truncate namespace {} set {}".format(
                namespace, set_
            )
        else:
            error_message = "Failed to truncate namespace {}".format(namespace)
            if await self._use_new_truncate_command():
                req = "truncate-namespace:namespace={}".format(namespace)
            else:
                req = "truncate:namespace={}".format(namespace)

        if lut is not None:
            req += ";lut={}".format(lut)

        resp = await self._info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(error_message, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_truncate_undo(self, namespace, set_=None):
        """
        Undo truncation of a namespace or set.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        req = None
        error_message = None

        if set_ is not None:
            req = "truncate-undo:namespace={};set={}".format(namespace, set_)
            error_message = "Failed to undo truncation of namespace {} set {}".format(
                namespace, set_
            )
        else:
            error_message = "Failed to undo truncation of namespace {}".format(
                namespace
            )
            if await self._use_new_truncate_command():
                req = "truncate-namespace-undo:namespace={}".format(namespace)
            else:
                req = "truncate-undo:namespace={}".format(namespace)

        resp = await self._info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError(error_message, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_recluster(self):
        """
        Force the cluster to advance the cluster key and rebalance.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self._info("recluster:")

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to recluster", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_quiesce(self):
        """
        Cause a node to avoid participating as a replica after the next recluster event.
        Quiescing and reclustering before removing a node from the cluster prevents
        client timeouts that may otherwise happen when a node drops from the cluster.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self._info("quiesce:")

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to quiesce", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_quiesce_undo(self):
        """
        Revert the effects of the quiesce on the next recluster event.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self._info("quiesce-undo:")

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to undo quiesce", resp)

        return ASINFO_RESPONSE_OK

    # TODO: Deprecated but still needed to support reading old job type removed in
    # server 5.7.  Should be stripped out at some point.
    @async_return_exceptions
    async def info_jobs(self, module):
        """
        Get all jobs from a particular module. Acceptable values are scan, query, and
        sindex-builder. Jobs command was removed in 6.3.

        Returns: {<trid1>: {trid: <trid1>, . . .}, <trid2>: {trid: <trid2>, . . .}},
        """
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        # jobs command removed in 6.3.0
        if version.LooseVersion(build) >= version.LooseVersion(
            constants.SERVER_JOBS_REMOVAL_VERSION
        ):
            logger.debug(
                "jobs command was removed in %s+", constants.SERVER_JOBS_REMOVAL_VERSION
            )
            return {}

        resp = await self._info("jobs:module={}".format(module))

        if resp.startswith("ERROR") or resp.startswith("error"):
            return {}

        jobs = client_util.info_to_dict_multi_level(resp, "trid")

        return jobs

    @async_return_exceptions
    async def _jobs_helper(self, old_req, new_req):
        req = None

        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        if version.LooseVersion(build) >= version.LooseVersion(
            constants.SERVER_JOBS_REMOVAL_VERSION
        ):
            req = new_req
        else:
            req = old_req

        return await self._info(req)

    @async_return_exceptions
    async def info_query_show(self):
        """
        Get all query jobs. Calls "query-show" if supported (5.7+). Calls "jobs" if not.

        Returns: {<trid1>: {trid: <trid1>, . . .}, <trid2>: {trid: <trid2>, . . .}}
        """
        old_req = "jobs:module=query"
        new_req = "query-show"

        resp = await self._jobs_helper(old_req, new_req)
        resp = client_util.info_to_dict_multi_level(resp, "trid")

        return resp

    @async_return_exceptions
    async def info_scan_show(self):
        """
        Get all scan jobs. Calls "scan-show" if supported (5.7-6.4).  Calls "jobs" if supported (<6.3).
        Both commands were removed in later versions.

        Returns: {<trid1>: {trid: <trid1>, . . .}, <trid2>: {trid: <trid2>, . . .}}
        """
        build = await self.info_build()

        if isinstance(build, Exception):
            logger.error(build)
            return build

        # scan-show removed in 6.4, jobs removed in 6.3
        if version.LooseVersion(build) >= version.LooseVersion(
            constants.SERVER_SCAN_SHOW_REMOVAL_VERSION
        ):
            logger.debug(
                "scan jobs commands were removed in %s+",
                constants.SERVER_SCAN_SHOW_REMOVAL_VERSION,
            )
            return {}

        old_req = "jobs:module=scan"
        new_req = "scan-show"

        resp = await self._jobs_helper(old_req, new_req)
        resp = client_util.info_to_dict_multi_level(resp, "trid")

        return resp

    # TODO: Deprecated but still needed to support killing old job types that have been
    # removed in server 5.7. Should be stripped out at some point.
    @async_return_exceptions
    async def info_jobs_kill(self, module, trid):
        """
        Kill a job.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        req = "jobs:module={};cmd=kill-job;trid={}".format(module, trid)

        resp = await self._info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to kill job", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_scan_abort(self, trid):
        """
        Kill a scan job. Calls "scan-abort" if "scan-show" features exists. Otherwise,
        calls "jobs".  "scan-abort" was supported prior but was not documented until
        server 5.7.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        old_req = "jobs:module=scan;cmd=kill-job;trid={}".format(trid)
        new_req = "scan-abort:trid={}".format(trid)

        resp = await self._jobs_helper(old_req, new_req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to kill job", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_query_abort(self, trid):
        """
        Kill a query job. Calls "query-abort" if "query-show" features exists. Otherwise,
        calls "jobs". Unlike "scan-abort", "query-abort" was not supported until 5.7.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        old_req = "jobs:module=query;cmd=kill-job;trid={}".format(trid)
        new_req = "query-abort:trid={}".format(trid)

        resp = await self._jobs_helper(old_req, new_req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to kill job", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_scan_abort_all(self):
        """
        Abort all scans.  Supported since 3.5 but only documented as of 5.7 :)

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self._info("scan-abort-all:")

        if resp.startswith("OK - number of"):
            return resp.lower()

        raise ASInfoResponseError("Failed to abort all scans", resp)

    @async_return_exceptions
    async def info_query_abort_all(self):
        """
        Abort all queries.  Added in 6.0 when scans were unified into queries.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self._info("query-abort-all:")

        # TODO: Check actual response
        if resp.startswith("OK - number of"):
            return resp.lower()

        raise ASInfoResponseError("Failed to abort all queries", resp)

    @async_return_exceptions
    async def info_revive(self, namespace):
        """
        Used to revive dead partitions in a namespace running in strong consistency mode.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        req = "revive:namespace={}".format(namespace)
        resp = await self._info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to revive", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_masking_add_rule(
        self, namespace, set_, bin_, bin_type, func_name, func_params
    ):
        """
        Add a masking rule.
        """
        req = "masking:namespace={};set={};bin={};type={};function={}".format(
            namespace, set_, bin_, bin_type, func_name
        )

        # Add function parameters to the request
        for param_name, param_value in func_params.items():
            req += ";{}={}".format(param_name, param_value)

        resp = await self._info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to add masking rule", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_masking_remove_rule(self, namespace, set_, bin_, bin_type):
        """
        Remove a masking rule.
        """
        req = "masking:namespace={};set={};bin={};type={};function=remove".format(
            namespace, set_, bin_, bin_type
        )
        resp = await self._info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoResponseError("Failed to remove masking rule", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_masking_list_rules(self, namespace=None, set_=None):
        """
        List masking rules.
        """
        # namespace and set are optional
        masking_show_req = "masking-show:"
        if namespace is not None:
            masking_show_req += "ns={};".format(namespace)
        if set_ is not None:
            masking_show_req += "set={};".format(set_)

        resp = await self._info(masking_show_req)

        if resp.startswith("error") or resp.startswith("ERROR"):
            raise ASInfoResponseError("Failed to list masking rules", resp)

        return [
            client_util.info_to_dict(v, ";")
            for v in client_util.info_to_list(resp, delimiter=":")
            if v != ""
        ]

    ############################################################################
    #
    #                      Admin (Security Protocol) API
    #
    ############################################################################

    async def _admin_cadmin(self, admin_func, args, ip, port=None):
        if port is None:
            port = self.port

        async with self._borrow_socket(ip, port) as sock:
            return await admin_func(sock, *args)

    @async_return_exceptions
    async def admin_create_user(self, user, password, roles):
        """
        Create user.
        user: string
        password: string (un-hashed)
        roles: list[string]

        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.create_user, (user, password, roles), self.ip
        )

    @async_return_exceptions
    async def admin_delete_user(self, user):
        """
        Delete user.
        user: string

        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.delete_user, [user], self.ip)

    @async_return_exceptions
    async def admin_set_password(self, user, password):
        """
        Set user password.
        user: string
        password: string (un-hashed)
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.set_password, (user, password), self.ip
        )

    @async_return_exceptions
    async def admin_change_password(self, user, old_password, new_password):
        """
        Change user password.
        user: string
        old_password: string (un-hashed)
        new_password: string (un-hashed)
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.change_password, (user, old_password, new_password), self.ip
        )

    @async_return_exceptions
    async def admin_grant_roles(self, user, roles):
        """
        Grant roles to user.
        user: string
        roles: list[string]
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.grant_roles, (user, roles), self.ip)

    @async_return_exceptions
    async def admin_revoke_roles(self, user, roles):
        """
        Remove roles from user.
        user: string
        roles: list[string]
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.revoke_roles, (user, roles), self.ip)

    @async_return_exceptions
    async def admin_query_users(self):
        """
        Query users.
        Returns: {username1: [role1, role2, . . .], username2: [. . .],  . . .},
        ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.query_users, (), self.ip)

    @async_return_exceptions
    async def admin_query_user(self, user):
        """
        Query a user.
        user: string
        Returns: {username: [role1, role2, . . .]},
        ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.query_user, [user], self.ip)

    @async_return_exceptions
    async def admin_create_role(
        self, role, privileges, whitelist=None, read_quota=None, write_quota=None
    ):
        """
        Create role with privileges and whitelist.
        role: string
        privileges: list[string]
        whitelist: list[string] (optional)
        read_quota: (optional)
        write_quota: (optional)
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.create_role,
            (role, privileges, whitelist, read_quota, write_quota),
            self.ip,
        )

    @async_return_exceptions
    async def admin_delete_role(self, role):
        """
        Delete role.
        role: string
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.delete_role, [role], self.ip)

    @async_return_exceptions
    async def admin_add_privileges(self, role, privileges):
        """
        Add privileges to role.
        role: string
        privileges: list[string]
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.add_privileges, (role, privileges), self.ip
        )

    @async_return_exceptions
    async def admin_delete_privileges(self, role, privileges):
        """
        Delete privileges from role.
        role: string
        privileges: list[string]
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.delete_privileges, (role, privileges), self.ip
        )

    @async_return_exceptions
    async def admin_set_whitelist(self, role, whitelist):
        """
        Set whitelist for a role.
        role: string
        whitelist: list[string]
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.set_whitelist, (role, whitelist), self.ip
        )

    @async_return_exceptions
    async def admin_delete_whitelist(self, role):
        """
        Delete whitelist for a role.
        role: string
        Returns: 0 (ASResponse.OK) on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.delete_whitelist, [role], self.ip)

    @async_return_exceptions
    async def admin_set_quotas(self, role, read_quota=None, write_quota=None):
        """
        Set rate limit for a role. Either read_quota or write_quota should be
        provided but will be enforced elsewhere.
        role: string
        read_quota: int or string that represents and int
        write_quota: int or string that represents and int
        Returns: None on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.set_quotas, (role, read_quota, write_quota), self.ip
        )

    @async_return_exceptions
    async def admin_delete_quotas(self, role, read_quota=False, write_quota=False):
        """
        NOT IN USE
        Delete rate limit for a role. Either read_quota or write_quota should be
        provided but will be enforced elsewhere.
        role: string
        read_quota: True to delete, False to leave alone
        write_quota: True to delete, False to leave alone
        Returns: None on success, ASProtocolError on fail
        """
        return await self._admin_cadmin(
            ASSocket.delete_quotas, (role, read_quota, write_quota), self.ip
        )

    @async_return_exceptions
    async def admin_query_roles(self):
        """
        Query all roles.
        Returns: { role1:
                    'privileges': [privilege1, ...],
                    'whitelist': [addr1, addr2, ...]
                   role2:
                    'privileges': . . .,
                    'whitelist': . . .
                 },
        ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.query_roles, (), self.ip)

    @async_return_exceptions
    async def admin_query_role(self, role):
        """
        Query a role.
        role: string
        Returns: {role:
                    'privileges': [privilege1, ...],
                    'whitelist': [addr1, addr2, ...]
                 },
        ASProtocolError on fail
        """
        return await self._admin_cadmin(ASSocket.query_role, [role], self.ip)

    ############################################################################
    #
    #                           System Commands
    #
    ############################################################################

    @return_exceptions
    def _get_localhost_system_statistics(self, commands):
        logger.info(
            f"({self.ip}:{self.port}): Collecting system information for localhost..."
        )

        sys_stats = {}

        logger.debug(
            ("%s._get_localhost_system_statistics cmds=%s"),
            self.ip,
            commands,
        )

        for sys_cmd in self.sys_cmds:
            if sys_cmd.key not in commands:
                continue

            for cmd in sys_cmd:
                logger.debug(
                    ("%s._get_localhost_system_statistics running cmd=%s"),
                    self.ip,
                    cmd,
                )
                o, e = util.shell_command([cmd])
                if (e and not sys_cmd.ignore_error) or not o:
                    continue

                try:
                    sys_stats[sys_cmd.key] = sys_cmd.parse(o)
                except Exception as e:
                    logger.debug(f"Failed to parse system cmd {cmd}: {e}")
                    pass

                break

        logger.info(
            f"({self.ip}:{self.port}): Finished collecting system info for localhost."
        )

        return sys_stats

    async def _get_remote_host_system_statistics(
        self,
        commands,
        ssh_user: str | None = None,
        ssh_pwd: str | None = None,
        ssh_key: str | None = None,
        ssh_key_pwd: str | None = None,
        ssh_port: int | None = None,
    ):
        sys_stats = {}
        conn = None

        try:
            conn_config = SSHConnectionConfig(
                username=ssh_user,
                password=ssh_pwd,
                private_key=ssh_key,
                private_key_pwd=ssh_key_pwd,
                port=ssh_port,
            )
            conn_factory = SSHConnectionFactory(conn_config)
            conn = await conn_factory.create_connection(self.ip)
            logger.info(
                f"({self.ip}:{self.port}): Collecting system info for remote host"
            )

        except (SSHError, FileNotFoundError) as e:
            logger.error(
                f"({self.ip}:{self.port}): Ignoring system statistics collection. Couldn't SSH login to remote server: {e}"
            )
            raise

        if not conn:
            return sys_stats

        try:
            # Collects system statistics by running commands sequentially
            for sys_cmd in self.sys_cmds:
                key = sys_cmd.key

                if key not in commands:
                    continue

                # Finds first command that works
                for cmd in sys_cmd:
                    try:
                        cp = await conn.run(cmd)
                        stdout = cp.stdout

                        if stdout is not None:
                            sys_stats[sys_cmd.key] = sys_cmd.parse(
                                util.bytes_to_str(stdout)
                            )
                        break
                    except (SSHNonZeroExitCodeError, SSHTimeoutError):
                        """
                        ProcessError is raised if the command exits with a non-zero exit status.
                        We will try the next command in the list.
                        """
                        continue

            logger.info(
                f"({self.ip}:{self.port}): Finished collecting system info for remote host"
            )

        except SSHError as e:
            # Catches async.ChannelOpenError
            port = "22" if ssh_port is None else str(ssh_port)
            logger.warning(
                f"Ignoring system statistics collection. Couldn't get or parse remote system stats for remote server {self.ip}:{port} : {e}"
            )

        finally:
            await conn.close()

        return sys_stats

    @async_return_exceptions
    async def info_system_statistics(
        self,
        commands=[],
        enable_ssh=False,
        ssh_user=None,
        ssh_pwd=None,
        ssh_key=None,
        ssh_key_pwd=None,
        ssh_port=None,
    ):
        """
        Get statistics for a system.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        logger.debug(
            "ssh_user=%s ssh_pwd=%s ssh_key=%s ssh_port=%s commands=%s enable_ssh=%s",
            self.ip,
            ssh_user,
            ssh_pwd,
            ssh_key,
            ssh_port,
            commands,
            enable_ssh,
        )

        if commands:
            cmd_list = copy.deepcopy(commands)
        else:
            cmd_list = [sys_cmd.key for sys_cmd in self.sys_cmds]

        if self.localhost:
            return self._get_localhost_system_statistics(cmd_list)

        if enable_ssh:
            return await self._get_remote_host_system_statistics(
                cmd_list,
                ssh_user=ssh_user,
                ssh_pwd=ssh_pwd,
                ssh_key=ssh_key,
                ssh_key_pwd=ssh_key_pwd,
                ssh_port=ssh_port,
            )

        return {}

    ############################################################################
    #
    #                            Configuration
    #
    ############################################################################
    @return_exceptions
    def config_subcontext(self, context, dynamic=True):
        return self.conf_schema_handler.get_subcontext(context)

    @return_exceptions
    def config_params(self, context, dynamic=True):
        return self.conf_schema_handler.get_params(context, dynamic=dynamic)

    @return_exceptions
    def config_types(self, context, params):
        return self.conf_schema_handler.get_types(context, params)

    @return_exceptions
    def config_type(self, context, param):
        param_dict = self.conf_schema_handler.get_types(context, param)

        return param_dict[param]
