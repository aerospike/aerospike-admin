# Copyright 2013-2021 Aerospike, Inc.
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
from ctypes import ArgumentError
import copy
import logging
import re
import socket
import threading
import time
import base64
from typing import Optional
from lib.live_cluster.client.ctx import CDTContext
from lib.live_cluster.client.msgpack import ASPacker

from lib.utils import common, constants, util, version, conf_parser
from lib.utils import common, constants, util, version, logger_debug, conf_parser
from lib.utils.async_object import AsyncObject

from .assocket import ASSocket
from .config_handler import JsonDynamicConfigHandler
from . import client_util
from . import sys_cmd_parser
from .types import (
    ASInfoConfigError,
    ASInfoError,
    ASINFO_RESPONSE_OK,
    ASInfoNotAuthenticatedError,
    ASInfoClusterStableError,
    ASProtocolError,
    ASResponse,
    Addr_Port_TLSName,
)

logger = logger_debug.get_debug_logger(__name__, logging.CRITICAL)

#### Remote Server connection module

PXSSH_NO_MODULE = 0  # Non-linux
PXSSH_NEW_MODULE = 1

try:
    from pexpect import pxssh

    PEXPECT_VERSION = PXSSH_NEW_MODULE
except ImportError:
    PEXPECT_VERSION = PXSSH_NO_MODULE


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
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            args[0].alive = False
            return e

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
        ssl_context=None,
        consider_alumni=False,
        use_services_alt=False,
    ):
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
        self.logger = logging.getLogger("asadm")
        self.remote_system_command_prompt = "[#$] "
        self.ip = address
        self.port = port
        self._timeout = timeout
        self.user = user
        self.password = password
        self.auth_mode = auth_mode
        self.tls_name = tls_name
        self.ssl_context = ssl_context
        if ssl_context:
            self.enable_tls = True
        else:
            self.enable_tls = False
        self.consider_alumni = consider_alumni
        self.use_services_alt = use_services_alt
        self.peers: list[tuple[Addr_Port_TLSName]] = []

        # session token
        self.session_token = None
        self.session_expiration = 0
        self.perform_login = True

        # System Details
        self.sys_ssh_port = None
        self.sys_user_id = None
        self.sys_pwd = None
        self.sys_ssh_key = None
        self.sys_credential_file = None
        self.sys_default_ssh_port = None
        self.sys_default_user_id = None
        self.sys_default_pwd = None
        self.sys_default_ssh_key = None
        self.sys_cmds = [
            # format: (command name as in parser, ignore error, command list)
            ("hostname", False, ["hostname -I", "hostname"]),
            ("top", False, ["top -n1 -b", "top -l 1"]),
            (
                "lsb",
                False,
                ["lsb_release -a", "ls /etc|grep release|xargs -I f cat /etc/f"],
            ),
            ("meminfo", False, ["cat /proc/meminfo", "vmstat -s"]),
            ("interrupts", False, ["cat /proc/interrupts", ""]),
            ("iostat", False, ["iostat -y -x 5 1", ""]),
            ("dmesg", False, ["dmesg -T", "dmesg"]),
            (
                "limits",
                False,
                ['sudo  pgrep asd | xargs -I f sh -c "sudo cat /proc/f/limits"', ""],
            ),
            ("lscpu", False, ["lscpu", ""]),
            ("sysctlall", False, ["sudo sysctl vm fs", ""]),
            ("iptables", False, ["sudo iptables -S", ""]),
            (
                "hdparm",
                False,
                [
                    'sudo fdisk -l |grep Disk |grep dev | cut -d " " -f 2 | cut -d ":" -f 1 | xargs sudo hdparm -I 2>/dev/null',
                    "",
                ],
            ),
            ("df", False, ["df -h", ""]),
            ("free-m", False, ["free -m", ""]),
            ("uname", False, ["uname -a", ""]),
            (
                "scheduler",
                True,
                [
                    'ls /sys/block/{sd*,xvd*,nvme*}/queue/scheduler |xargs -I f sh -c "echo f; cat f;"',
                    "",
                ],
            ),
            # Todo: Add more commands for other cloud platform detection
            (
                "environment",
                False,
                ["curl -m 1 -s http://169.254.169.254/1.0/", "uname"],
            ),
            (
                "ethtool",
                False,
                [
                    'sudo netstat -i | tr -s [:blank:] | cut -d" " -f1 | tail -n +3 | grep -v -E "lo|docker" | xargs --max-lines=1 -i{} sh -c "echo ethtool -S {}; ethtool -S {}"'
                ],
            ),
        ]

        # hack, _key needs to be defines before info calls... but may have
        # wrong (localhost) address before info_service is called. Will set
        # again after that call.

        self._key = hash(self.create_key(address, self.port))
        self.peers_generation = -1
        self.service_addresses = []
        self._initialize_socket_pool()
        await self.connect(address, port)
        self.localhost = False

        try:
            if address.lower() == "localhost":
                self.localhost = True
            else:
                o, e = util.shell_command(["hostname -I"])
                self.localhost = self._is_any_my_ip(o.split())
        except Exception:
            pass

        # configurations from conf file
        self.as_conf_data = {}

        # TODO: Put json files in a submodule
        if self.alive:
            self.conf_schema_handler = JsonDynamicConfigHandler(
                constants.CONFIG_SCHEMAS_HOME, await self.info_build()
            )

    def _initialize_socket_pool(self):
        logger.debug("%s:%s init socket pool", self.ip, self.port)
        self.socket_pool: dict[int, set[ASSocket]] = {}
        self.socket_pool[self.port] = set()
        self.socket_pool_max_size = 3

    def _is_any_my_ip(self, ips):
        if not ips:
            return False
        s_a = [a[0] for a in self.service_addresses]
        if set(ips).intersection(set(s_a)):
            return True
        return False

    async def _node_connect(self):
        peers_info_calls = self._get_info_peers_list_calls()
        service_info_call = self._get_service_info_call()
        commands = ["node", service_info_call, "features"] + peers_info_calls
        results = await self._info_cinfo(commands, self.ip, disable_cache=True)

        if isinstance(results, Exception):
            raise results

        node_id = results["node"]
        service_addresses = self._info_service_helper(results[service_info_call])
        features = results["features"]
        peers = self._aggregate_peers([results[call] for call in peers_info_calls])
        return node_id, service_addresses, features, peers

    async def connect(self, address, port):
        try:
            if not await self.login():
                raise IOError("Login Error")

            # At startup the socket_pool is empty.  Login adds its socket to the pool.
            # This ensures that the following call uses the same socket as login(). This is
            # needed when a load balancer is used because the session token received from login
            # will be for a specific node.
            (
                self.node_id,
                service_addresses,
                self.features,
                self.peers,
            ) = await self._node_connect()

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
                    self.node_id, update_ip, self.peers = await asyncio.gather(
                        self.info_node(),
                        self._update_IP(self.ip, self.port),
                        self.info_peers_list(),
                    )

                    if not isinstance(self.node_id, Exception):
                        break

                except Exception:
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
            self.alive = True
        except (ASInfoNotAuthenticatedError, ASProtocolError):
            raise
        except Exception as e:
            self.logger.debug(e, include_traceback=True)  # type: ignore
            # Node is offline... fake a node
            self.ip = address
            self.fqdn = address
            self.port = port
            self._service_IP_port = self.create_key(self.ip, self.port)
            self._key = hash(self._service_IP_port)

            self.node_id = "000000000000000"
            self.service_addresses = [(self.ip, self.port, self.tls_name)]
            self.features = ""
            self.peers = []
            self.use_new_histogram_format = False
            self.alive = False

    async def refresh_connection(self):
        await self.connect(self.ip, self.port)

    async def login(self):
        """
        Creates a new socket and gets the session token for authentication. No login
        is done if a user was not provided and PKI is not being used.
        First introduced in 0.2.0. Before security only required a user/pass authentication
        stage rather than a two step login() -> token -> auth().
        """
        if self.auth_mode != constants.AuthMode.PKI and self.user is None:
            return True

        if not self.perform_login and (
            self.session_expiration == 0 or self.session_expiration > time.time()
        ):
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
                "%s:%s failed to connect to socket %s", self.ip, self.port, sock
            )
            await sock.close()
            return False

        try:
            if not await sock.login():
                self.logger.debug(
                    "%s:%s failed to login to socket %s", self.ip, self.port, sock
                )
                await sock.close()
                return False
        except ASProtocolError as e:
            if e.as_response == ASResponse.SECURITY_NOT_ENABLED:
                self.logger.debug(
                    "%s:%s failed to login to socket, security not enabled, ignoring... %s",
                    self.ip,
                    self.port,
                    sock,
                )
                if not Node.security_disabled_warning:
                    self.logger.warning(e)
                    Node.security_disabled_warning = True
            else:
                self.logger.debug(
                    "%s:%s failed to login to socket %s, exc: %s",
                    self.ip,
                    self.port,
                    sock,
                    e,
                )
                await sock.close()
                raise

        self.socket_pool[self.port].add(sock)
        self.session_token, self.session_expiration = sock.get_session_info()
        self.perform_login = False
        self.logger.debug(
            "%s:%s successful login to socket %s", self.ip, self.port, sock
        )
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

    def __str__(self):
        return self.sock_name()

    async def is_XDR_enabled(self):
        config = await self.info_get_config("xdr")

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

    def is_feature_present(self, feature):
        if not self.features or isinstance(self.features, Exception):
            return False
        return feature in self.features

    async def has_peers_changed(self):
        try:
            new_generation = await self.info("peers-generation")
            if self.peers_generation != new_generation:
                self.peers_generation = new_generation
                return True
            else:
                return False
        except Exception:
            return True

    async def _is_new_histogram_version(self):
        as_version = await self.info_build()
        if isinstance(as_version, Exception):
            return False

        return common.is_new_histogram_version(as_version)

    async def _get_connection(self, ip, port) -> ASSocket:
        sock = None

        try:
            while True:

                sock = self.socket_pool[port].pop()

                if await sock.is_connected():
                    if not self.ssl_context:
                        sock.settimeout(self._timeout)
                    break

                await sock.close()
                sock = None

        except Exception as e:
            self.logger.debug(e, include_traceback=True)
            pass

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

        self.logger.debug("%s:%s created new sock %s", ip, port, id(sock))

        if await sock.connect():
            try:
                if await sock.authenticate(self.session_token):
                    self.logger.debug("sock auth successful %s", id(sock))
                    return sock
            except ASProtocolError as e:
                self.logger.debug("sock auth failed %s", id(sock))
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
                    self.logger.debug("trying to sock login again %s", id(sock))
                    self.perform_login = True
                    await self.login()
                    if await sock.authenticate(self.session_token):
                        self.logger.debug(
                            "sock auth successful on second try %s", id(sock)
                        )
                        return sock

                await sock.close()
                raise

        self.logger.debug("sock connect failed %s", id(sock))
        return None

    async def close(self):
        try:
            while True:
                sock = self.socket_pool[self.port].pop()
                await sock.close()
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

    @async_return_exceptions
    @util.async_cached
    async def _info_cinfo(self, command, ip=None, port=None):
        if ip is None:
            ip = self.ip
        if port is None:
            port = self.port
        result = None

        sock = await self._get_connection(ip, port)
        if not sock:
            raise IOError("Error: Could not connect to node %s" % ip)

        try:
            if sock:
                result = await sock.info(command)
                try:
                    # TODO: same code is in _admin_cadmin. management of socket_pool should
                    # be abstracted.
                    if len(self.socket_pool[port]) < self.socket_pool_max_size:
                        sock.settimeout(None)
                        self.socket_pool[port].add(sock)

                    else:
                        await sock.close()

                except Exception as e:
                    await sock.close()

            if result != -1 and result is not None:
                self.logger.debug(
                    "%s:%s info cmd '%s' and sock %s returned %s",
                    self.ip,
                    self.port,
                    command,
                    id(sock),
                    result,
                )
                return result

            else:
                raise IOError("Error: Invalid command '%s'" % command)

        except Exception as ex:
            if sock:
                await sock.close()

            self.logger.debug(
                "%s:%s info cmd '%s' and sock %s raised %s for",
                self.ip,
                self.port,
                command,
                id(sock),
                ex,
            )
            raise ex

    async def info(self, command):
        """
        asinfo function equivalent

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

        return await self.info("node")

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
    def _info_peers_helper(self, peers) -> list[tuple[Addr_Port_TLSName]]:
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
        else:
            return "peers-clear-std"

    @async_return_exceptions
    async def info_peers(self):
        """
        Get peers this node knows of that are active

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        return self._info_peers_helper(await self.info(self._get_info_peers_call()))

    def _get_info_peers_alumni_call(self):
        if self.enable_tls:
            return "alumni-tls-std"
        else:
            return "alumni-clear-std"

    @async_return_exceptions
    async def info_peers_alumni(self):
        """
        Get peers this node has ever know of
        Note: info_peers_alumni for server version prior to 4.3.1 gives only old nodes
        which are not part of current cluster.

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        return self._info_peers_helper(
            await self.info(self._get_info_peers_alumni_call())
        )

    def _get_info_peers_alt_call(self):
        if self.enable_tls:
            return "peers-tls-alt"
        else:
            return "peers-clear-alt"

    @async_return_exceptions
    async def info_peers_alt(self):
        """
        Get peers this node knows of that are active alternative addresses

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        return self._info_peers_helper(await self.info(self._get_info_peers_alt_call()))

    def _get_info_peers_list_calls(self) -> list[str]:
        calls = []
        # at most 2 calls will be needed
        if self.consider_alumni:
            calls.append(self._get_info_peers_alumni_call())

        if self.use_services_alt:
            calls.append(self._get_info_peers_alt_call())
        else:
            calls.append(self._get_info_peers_call())

        return calls

    def _aggregate_peers(self, results) -> list[tuple[Addr_Port_TLSName]]:
        results = [self._info_peers_helper(result) for result in results]
        return list(set().union(*results))

    @async_return_exceptions
    async def info_peers_list(self) -> list[tuple[Addr_Port_TLSName]]:
        results = await asyncio.gather(
            *[self.info(call) for call in self._get_info_peers_list_calls()]
        )
        return self._aggregate_peers(results)

    @async_return_exceptions
    async def info_peers_flat_list(self):
        return client_util.flatten(await self.info_peers_list())

    ###### Services End ######

    ###### Service ######
    # post 3.10 services

    # @return_exceptions
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

    @async_return_exceptions
    async def info_service_list(self):
        """
        Get service endpoints of this node.  Changes if tls or service-alt is enabled.

        Returns:
        list -- [(ip,port,tls_name),...]
        """
        return self._info_service_helper(await self.info(self._get_service_info_call()))

    ###### Service End ######

    @async_return_exceptions
    async def info_statistics(self):
        """
        Get statistics for this node. asinfo -v "statistics"

        Returns:
        dictionary -- statistic name -> value
        """

        return client_util.info_to_dict(await self.info("statistics"))

    @async_return_exceptions
    async def info_namespaces(self):
        """
        Get a list of namespaces for this node. asinfo -v "namespaces"

        Returns:
        list -- list of namespaces
        """

        return client_util.info_to_list(await self.info("namespaces"))

    @async_return_exceptions
    async def info_namespace_statistics(self, namespace):
        """
        Get statistics for a namespace.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """

        ns_stat = client_util.info_to_dict(await self.info("namespace/%s" % namespace))

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
        set_stat = await self.info("sets/{}/{}".format(namespace, set_))

        if set_stat[-1] == ";":
            set_stat = client_util.info_colon_to_dict(set_stat[0:-1])
        else:
            set_stat = client_util.info_colon_to_dict(set_stat)

        return set_stat

    @async_return_exceptions
    async def info_all_set_statistics(self):
        stats = await self.info("sets")
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
        stats = await self.info("health-outliers")
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
        resp = await self.info("best-practices")

        if isinstance(resp, ASInfoError):
            return resp

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
        stats = client_util.info_to_list(await self.info("bins"))
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
    async def info_XDR_statistics(self):
        """
        Get statistics for XDR

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        build = await self.info_build()

        # for new aerospike version (>=3.8) with
        # xdr-in-asd stats available on service port
        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            return client_util.info_to_dict(await self.info("statistics/xdr"))

        return await self.info_all_dc_statistics()

    @async_return_exceptions
    async def info_set_config_xdr_create_dc(self, dc):
        dcs = await self.info_dcs()
        error_message = "Failed to create XDR datacenter"

        if dc in dcs:
            raise ASInfoError(error_message, "DC already exists")

        build = await self.info_build()
        req = "set-config:context=xdr;dc={};action=create"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc)
        resp = await self.info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoError(error_message, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_delete_dc(self, dc):
        dcs = await self.info_dcs()
        error_message = "Failed to delete XDR datacenter"

        logger.debug("Found dcs: %s", dcs)

        if dc not in dcs:
            raise ASInfoError(error_message, "DC does not exist")

        build = await self.info_build()
        req = "set-config:context=xdr;dc={};action=delete"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc)
        resp = await self.info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoError(error_message, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_add_namespace(self, dc, namespace, rewind=None):
        error_message = "Failed to add namespace to XDR datacenter"

        build = await self.info_build()
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
                    raise ASInfoError(
                        error_message,
                        'Invalid rewind. Must be int or "all"',
                    )
            req += ";rewind={}".format(rewind)

        resp = await self.info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoError(error_message, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_remove_namespace(self, dc, namespace):
        build = await self.info_build()
        req = "set-config:context=xdr;dc={};namespace={};action=remove"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc, namespace)
        resp = await self.info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to remove namespace from XDR datacenter", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_add_node(self, dc, node):
        build = await self.info_build()
        req = "set-config:context=xdr;dc={};node-address-port={};action=add"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc, node)
        resp = await self.info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to add node to XDR datacenter", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr_remove_node(self, dc, node):
        build = await self.info_build()
        req = "set-config:context=xdr;dc={};node-address-port={};action=remove"

        if version.LooseVersion(build) < version.LooseVersion(
            constants.SERVER_NEW_XDR5_VERSION
        ):
            req = req.replace("dc", "datacenter")

        req = req.format(dc, node)
        resp = await self.info(req)

        if resp != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to remove node from XDR datacenter", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_set_config_xdr(self, param, value, dc=None, namespace=None):
        if namespace and not dc:
            raise ArgumentError("Namespace must be accompanied by a dc.")

        req = "set-config:context=xdr;{}={}".format(param, value)

        if dc:
            build = await self.info_build()

            if version.LooseVersion(build) < version.LooseVersion(
                constants.SERVER_NEW_XDR5_VERSION
            ):
                req += ";datacenter={}".format(dc)
            else:
                req += ";dc={}".format(dc)

        if namespace:
            req += ";namespace={}".format(namespace)

        resp = await self.info(req)

        if resp != ASINFO_RESPONSE_OK:
            context = ["xdr"]

            if dc is not None:
                context.append("dc")

            if namespace is not None:
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
    async def info_logs(self):
        id_file_dict = {}
        ls = client_util.info_to_list(await self.info("logs"))

        for pair in ls:
            id, file = pair.split(":")
            id_file_dict[file] = id

        return id_file_dict

    @async_return_exceptions
    async def info_set_config_logging(self, file, param, value):
        logs = await self.info_logs()
        error_message = "Failed to set logging configuration parameter {} to {}"

        if file not in logs:
            raise ASInfoError(
                error_message.format(param, value),
                "{} does not exist".format(file),
            )

        resp = await self.info("log-set:id={};{}={}".format(logs[file], param, value))

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
        resp = await self.info("set-config:context=service;{}={}".format(param, value))

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
        if subcontext and subcontext != "storage-engine":
            delimiter = "."

            if subcontext == "geo2dsphere-within":
                delimiter = "-"

            new_param = delimiter.join([subcontext, param])

        req = "set-config:context=namespace;id={};{}={}".format(
            namespace, new_param, value
        )

        if set_:
            req += ";set={}".format(set_)

        resp = await self.info(req)

        if resp != ASINFO_RESPONSE_OK:
            context = ["namespace"]

            if set_ is not None:
                context.append("set")

            if subcontext is not None:
                context.append(subcontext)

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
        resp = await self.info(
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

        resp = await self.info(
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

    async def xdr_namespace_config_helper(self, xdr_configs, dc, namespace):
        namespace_config = await self.info(
            "get-config:context=xdr;dc=%s;namespace=%s" % (dc, namespace)
        )
        xdr_configs["ns_configs"][dc][namespace] = client_util.info_to_dict(
            namespace_config
        )

    async def xdr_config_helper(self, xdr_configs, dc):
        dc_config = await self.info("get-config:context=xdr;dc=%s" % dc)
        dc_config = client_util.info_to_dict(dc_config)
        xdr_configs["ns_configs"][dc] = {}
        xdr_configs["dc_configs"][dc] = dc_config
        namespaces = dc_config["namespaces"].split(",")

        await asyncio.gather(
            *[
                self.xdr_namespace_config_helper(xdr_configs, dc, namespace)
                for namespace in namespaces
            ]
        )

    @async_return_exceptions
    async def info_get_config(self, stanza="", namespace=""):
        """
        Get the complete config for a node. This should include the following
        stanzas: Service, Network, XDR, and Namespace
        Sadly it seems Service and Network are not seperable.

        Returns:
        dict -- stanza --> [namespace] --> param --> value
        """
        config = {}

        if stanza == "namespace":
            if namespace != "":
                config = {
                    namespace: client_util.info_to_dict(
                        await self.info(
                            "get-config:context=namespace;id=%s" % namespace
                        )
                    )
                }
            else:
                namespace_configs = {}
                namespaces = await self.info_namespaces()
                config_list = await client_util.concurrent_map(
                    lambda ns: self.info_get_config("namespace", ns), namespaces
                )

                for namespace, namespace_config in zip(namespaces, config_list):
                    # info_get_config returns a dict that must be unpacked.
                    namespace_configs[namespace] = namespace_config[namespace]
                config = namespace_configs
        elif stanza == "xdr" and version.LooseVersion(
            await self.info_build()
        ) >= version.LooseVersion(constants.SERVER_NEW_XDR5_VERSION):
            xdr_config = {}
            xdr_config["dc_configs"] = {}
            xdr_config["ns_configs"] = {}
            tmp_xdr_config, dcs = await asyncio.gather(
                self.info("get-config:context=xdr"), self.info_dcs()
            )
            xdr_config["xdr_configs"] = client_util.info_to_dict(tmp_xdr_config)

            await asyncio.gather(
                *[self.xdr_config_helper(xdr_config, dc) for dc in dcs]
            )

            config = xdr_config
        elif not stanza:
            config = client_util.info_to_dict(await self.info("get-config:"))
        else:
            config = client_util.info_to_dict(
                await self.info("get-config:context=%s" % stanza)
            )
        return config

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
            conf_path = "/etc/aerospike/aerospike.conf"
            self.as_conf_data = conf_parser.parse_file(conf_path)
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
            hist_info = await self.info(cmd)
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

        # If ns_set is set filter through all default latencies with ns_set
        # If optional_benchmark is set make additional queries for the
        # optional_benchmark
        cmd_latencies = ["latencies:"]
        data = {}
        if verbose:
            namespaces = []
            if ns_set:
                namespaces = ns_set
            else:
                try:
                    namespaces = (await self.info("namespaces")).split(";")
                except Exception:
                    return data
            optional_benchmarks = [
                "proxy",
                "benchmark-fabric",
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
                for optional in optional_benchmarks
            ]

        hist_info = []
        for cmd in cmd_latencies:
            try:
                hist_info.append(await self.info(cmd))
            except Exception:
                return data
            if hist_info[-1].startswith("error"):
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
        unit_mapping = {"msec": "ms", "usec": "\u03bcs"}
        time_units = None
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
                    col + unit_mapping[time_units] for col in list(columns)
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
        xdr_major_version = int((await self.info_build())[0])

        # for server versions >= 5 using XDR5.0
        if xdr_major_version >= 5:
            xdr_data = client_util.info_to_dict(
                await self.info("get-config:context=xdr")
            )

            if xdr_data is None:
                return []

            dcs = xdr_data.get("dcs", "")

            if dcs == "":
                return []

            return dcs.split(",")

        return client_util.info_to_list(await self.info("dcs"))

    @async_return_exceptions
    async def info_dc_statistics(self, dc):
        """
        Get statistics for a datacenter.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        xdr_major_version = int((await self.info_build())[0])

        # If xdr version is < XDR5.0 return output of old asinfo command.
        if xdr_major_version < 5:
            return client_util.info_to_dict(await self.info("dc/%s" % dc))
        else:
            return client_util.info_to_dict(
                await self.info("get-stats:context=xdr;dc=%s" % dc)
            )

    @async_return_exceptions
    async def info_all_dc_statistics(self):
        dcs = await self.info_dcs()

        if isinstance(dcs, Exception):
            return {}

        result_stats = {}

        stat_list = await asyncio.gather(*[self.info_dc_statistics(dc) for dc in dcs])

        for dc, stat in zip(dcs, stat_list):
            if not stat or isinstance(stat, Exception):
                stat = {}
            result_stats[dc] = stat

        return result_stats

    @async_return_exceptions
    async def info_udf_list(self):
        """
        Get list of UDFs stored on the node.

        Returns:
        dict -- {<file-name>: {"filename": <file-name>, "hash": <hash>, "type": 'LUA'}, . . .}
        """
        udf_data = await self.info("udf-list")

        if not udf_data:
            return {}

        return client_util.info_to_dict_multi_level(
            udf_data, "filename", delimiter2=","
        )

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
        resp = await self.info(command)

        if resp.lower() not in {ASINFO_RESPONSE_OK, ""}:
            raise ASInfoError("Failed to add UDF", resp)

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
            raise ASInfoError(
                "Failed to remove UDF {}".format(udf_file_name), "UDF does not exist"
            )
        command = "udf-remove:filename=" + udf_file_name + ";"
        resp = await self.info(command)

        if resp.lower() not in {ASINFO_RESPONSE_OK, ""}:
            raise ASInfoError("Failed to remove UDF {}".format(udf_file_name), resp)

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
        resp = await self.info(req)

        if resp.startswith("ERROR"):
            raise ASInfoError("Could not retrieve roster for namespace", resp)

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

        roster_data = await self.info("roster:")

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
        resp = await self.info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError(
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

        resp = await self.info(req)

        if isinstance(resp, Exception):
            raise resp

        if "error" in resp.lower():
            if "cluster-not-specified-size" in resp or "unstable-cluster" in resp:
                raise ASInfoClusterStableError("Cluster is unstable", resp)

            raise ASInfoError("Failed to check cluster stability", resp)

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
        rack_data = await self.info("racks:")

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
        resp = await self.info("rack-ids")
        rack_data = {}

        if not resp:
            return {}

        resp = client_util.info_to_list(resp)

        for ns_id in resp:
            ns, id_ = client_util.info_to_tuple(ns_id)

            if id_ != "":
                rack_data[ns] = id_

        return rack_data

    @async_return_exceptions
    async def info_dc_get_config(self):
        """
        Get config for a datacenter.

        Returns:
        dict -- {dc_name1:{config_name : config_value, ...}, dc_name2:{config_name : config_value, ...}}
        """
        configs = await self.info("get-dc-config")

        if not configs or isinstance(configs, Exception):
            configs = await self.info("get-dc-config:")

        if not configs or isinstance(configs, Exception):
            return {}

        return client_util.info_to_dict_multi_level(
            configs,
            ["dc-name", "DC_Name"],
            ignore_field_without_key_value_delimiter=False,
        )

    @async_return_exceptions
    async def info_XDR_get_config(self):
        return await self.info_get_config(stanza="xdr")

    async def _collect_histogram_data(
        self, histogram, command, logarithmic=False, raw_output=False
    ):
        namespaces = await self.info_namespaces()

        data = {}
        datums = await asyncio.gather(
            *[self.info(command % (namespace, histogram)) for namespace in namespaces]
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
        return [
            client_util.info_to_dict(v, ":")
            for v in client_util.info_to_list(await self.info("sindex"))
            if v != ""
        ]

    @async_return_exceptions
    async def info_sindex_statistics(self, namespace, indexname):
        """
        Get statistics for a sindex.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        return client_util.info_to_dict(
            await self.info("sindex/%s/%s" % (namespace, indexname))
        )

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
    ):
        """
        Create a new secondary index. index_type and set are optional.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        command = "sindex-create:indexname={};".format(index_name)

        if index_type:
            command += "indextype={};".format(index_type)

        command += "ns={};".format(namespace)

        if set_:
            command += "set={};".format(set_)

        if ctx:
            packer = ASPacker()
            packer.pack(ctx)
            ctx_bytes: bytes = packer.bytes()
            ctx_b64 = base64.b64encode(ctx_bytes)
            ctx_b64 = util.bytes_to_str(ctx_b64)

            command += "context={};".format(ctx_b64)

        command += "indexdata={},{}".format(bin_name, bin_type)

        resp = await self.info(command)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to create sindex {}".format(index_name), resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_sindex_delete(self, index_name, namespace, set_=None):
        """
        Delete a secondary index. set_ must be provided if sindex is created on a set.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        command = ""

        if set_ is None:
            command = "sindex-delete:ns={};indexname={}".format(namespace, index_name)
        else:
            command = "sindex-delete:ns={};set={};indexname={}".format(
                namespace, set_, index_name
            )

        resp = await self.info(command)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to delete sindex {}".format(index_name), resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_build(self):
        """
        Get Build Version

        Returns:
        string -- build version
        """
        return await self.info("build")

    @async_return_exceptions
    async def info_version(self):
        """
        Get Build Version

        Returns:
        string -- build version
        """
        return await self.info("version")

    async def _use_new_truncate_command(self):
        """
        A new truncate-namespace and truncate-namespace-undo was added to some
        4.3.x, 4.4.x, and 4.5.x but not all
        """
        build = await self.info_build()

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

        resp = await self.info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError(error_message, resp)

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

        resp = await self.info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError(error_message, resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_recluster(self):
        """
        Force the cluster to advance the cluster key and rebalance.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self.info("recluster:")

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to recluster", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_quiesce(self):
        """
        Cause a node to avoid participating as a replica after the next recluster event.
        Quiescing and reclustering before removing a node from the cluster prevents
        client timeouts that may otherwise happen when a node drops from the cluster.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self.info("quiesce:")

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to quiesce", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_quiesce_undo(self):
        """
        Revert the effects of the quiesce on the next recluster event.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self.info("quiesce-undo:")

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to undo quiesce", resp)

        return ASINFO_RESPONSE_OK

    # TODO: Deprecated but still needed to support reading old job type removed in
    # server 5.7.  Should be stripped out at some point.
    @async_return_exceptions
    async def info_jobs(self, module):
        """
        Get all jobs from a particular module. Exceptable values are scan, query, and
        sindex-builder.

        Returns: {<trid1>: {trid: <trid1>, . . .}, <trid2>: {trid: <trid2>, . . .}},
        """
        resp = await self.info("jobs:module={}".format(module))

        if resp.startswith("ERROR"):
            return {}

        jobs = client_util.info_to_dict_multi_level(resp, "trid")

        return jobs

    @async_return_exceptions
    async def _jobs_helper(self, old_req, new_req):
        req = None

        if self.is_feature_present("query-show"):
            req = new_req
        else:
            req = old_req

        return await self.info(req)

    @async_return_exceptions
    async def info_query_show(self):
        """
        Get all query jobs. Calls "query-show" if supported (5.7).  Calls "jobs" if not.

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
        Get all scan jobs. Calls "scan-show" if supported (5.7).  Calls "jobs" if not.

        Returns: {<trid1>: {trid: <trid1>, . . .}, <trid2>: {trid: <trid2>, . . .}}
        """
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

        resp = await self.info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to kill job", resp)

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
            raise ASInfoError("Failed to kill job", resp)

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
            raise ASInfoError("Failed to kill job", resp)

        return ASINFO_RESPONSE_OK

    @async_return_exceptions
    async def info_scan_abort_all(self):
        """
        Abort all scans.  Supported since 3.5 but only documented as of 5.7 :)

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self.info("scan-abort-all:")

        if resp.startswith("OK - number of"):
            return resp.lower()

        raise ASInfoError("Failed to abort all scans", resp)

    @async_return_exceptions
    async def info_query_abort_all(self):
        """
        Abort all queries.  Added in 6.0 when scans were unified into queries.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        resp = await self.info("query-abort-all:")

        # TODO: Check actual response
        if resp.startswith("OK - number of"):
            return resp.lower()

        raise ASInfoError("Failed to abort all queries", resp)

    @async_return_exceptions
    async def info_revive(self, namespace):
        """
        Used to revive dead partitions in a namespace running in strong consistency mode.

        Returns: ASINFO_RESPONSE_OK on success and ASInfoError on failure
        """
        req = "revive:namespace={}".format(namespace)
        resp = await self.info(req)

        if resp.lower() != ASINFO_RESPONSE_OK:
            raise ASInfoError("Failed to revive", resp)

        return ASINFO_RESPONSE_OK

    ############################################################################
    #
    #                      Admin (Security Protocol) API
    #
    ############################################################################

    async def _admin_cadmin(self, admin_func, args, ip, port=None):
        if port is None:
            port = self.port

        result = None
        sock = await self._get_connection(ip, port)

        if not sock:
            raise IOError("Error: Could not connect to node %s" % ip)

        try:
            result = await admin_func(sock, *args)

            # Either restore the socket in the pool or close it if it is full.
            if len(self.socket_pool[port]) < self.socket_pool_max_size:
                sock.settimeout(None)
                self.socket_pool[port].add(sock)
            else:
                await sock.close()

        except Exception:
            if sock:
                await sock.close()

            # Re-raise the last exception
            raise

        return result

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

    def _set_default_system_credentials(
        self,
        default_user=None,
        default_pwd=None,
        default_ssh_key=None,
        default_ssh_port=None,
        credential_file=None,
    ):
        if default_user:
            self.sys_default_user_id = default_user

        if default_pwd:
            self.sys_default_pwd = default_pwd

        if default_ssh_key:
            self.sys_default_ssh_key = default_ssh_key

        self.sys_credential_file = None
        if credential_file:
            self.sys_credential_file = credential_file

        if default_ssh_port:
            try:
                self.sys_default_ssh_port = int(default_ssh_port)
            except Exception:
                pass

    def _set_system_credentials_from_file(self):
        if not self.sys_credential_file:
            return False
        result = False
        f = None
        try:
            try:
                f = open(self.sys_credential_file, "r")
            except IOError as e:
                self.logger.warning(
                    "Ignoring credential file. cannot open credential file. \n%s."
                    % (str(e))
                )
                return result

            for line in f.readlines():
                if not line or not line.strip():
                    continue
                try:
                    line = line.strip().replace("\n", " ").strip().split(",")
                    if len(line) < 2:
                        continue

                    ip = None
                    port = None
                    ip_port = line[0].strip()
                    if not ip_port:
                        continue

                    if "]" in ip_port:
                        # IPv6
                        try:
                            ip_port = ip_port[1:].split("]")
                            ip = ip_port[0].strip()
                            if len(ip_port) > 1:
                                # Removing ':' from port
                                port = int(ip_port[1].strip()[1:])
                        except Exception:
                            pass

                    else:
                        # IPv4
                        try:
                            ip_port = ip_port.split(":")
                            ip = ip_port[0]
                            if len(ip_port) > 1:
                                port = int(ip_port[1].strip())
                        except Exception:
                            pass

                    if ip and self._is_any_my_ip([ip]):
                        self.sys_user_id = line[1].strip()
                        try:
                            self.sys_pwd = line[2].strip()
                            self.sys_ssh_key = line[3].strip()
                        except Exception:
                            pass
                        self.sys_ssh_port = port
                        result = True
                        break

                except Exception:
                    pass
        except Exception as e:
            self.logger.warning("Ignoring credential file.\n%s." % (str(e)))
        finally:
            if f:
                f.close()
        return result

    def _clear_sys_credentials(self):
        self.sys_ssh_port = None
        self.sys_user_id = None
        self.sys_pwd = None
        self.sys_ssh_key = None

    def _set_system_credentials(self):
        self._clear_sys_credentials()
        set = self._set_system_credentials_from_file()
        if set:
            return
        self.sys_user_id = self.sys_default_user_id
        self.sys_pwd = self.sys_default_pwd
        self.sys_ssh_key = self.sys_default_ssh_key
        self.sys_ssh_port = self.sys_default_ssh_port

    def parse_system_live_command(self, command, command_raw_output, parsed_map):
        # Parse live cmd output and create imap
        imap = {}
        sys_cmd_parser.extract_section_from_live_cmd(command, command_raw_output, imap)
        sectionlist = []
        sectionlist.append(command)
        sys_cmd_parser.parse_sys_section(sectionlist, imap, parsed_map)

    @return_exceptions
    def _get_localhost_system_statistics(self, commands):
        sys_stats = {}

        logger.debug(
            ("%s._get_localhost_system_statistics cmds=%s"),
            self.ip,
            commands,
        )

        for _key, ignore_error, cmds in self.sys_cmds:
            if _key not in commands:
                continue

            for cmd in cmds:
                logger.debug(
                    ("%s._get_localhost_system_statistics running cmd=%s"),
                    self.ip,
                    cmd,
                )
                o, e = util.shell_command([cmd])
                if (e and not ignore_error) or not o:
                    continue

                try:
                    self.parse_system_live_command(_key, o, sys_stats)
                except Exception:
                    pass

                break

        return sys_stats

    @return_exceptions
    def _login_remote_system(self, ip, user, pwd, ssh_key=None, port=None):
        s = pxssh.pxssh()
        s.force_password = True
        s.SSH_OPTS = "-o 'NumberOfPasswordPrompts=1'"
        s.login(ip, user, pwd, ssh_key=ssh_key, port=port)
        return s

    @return_exceptions
    def _create_ssh_connection(self, ip, user, pwd, ssh_key=None, port=None):
        if user is None and pwd is None and ssh_key is None:
            raise Exception("Insufficient credentials to connect.")

        if PEXPECT_VERSION == PXSSH_NEW_MODULE:
            return self._login_remote_system(ip, user, pwd, ssh_key, port)

        return None

    @return_exceptions
    def _execute_remote_system_command(self, conn, cmd):
        if not conn or not cmd or PEXPECT_VERSION == PXSSH_NO_MODULE:
            return None

        conn.sendline(cmd)
        if PEXPECT_VERSION == PXSSH_NEW_MODULE:
            conn.prompt()
        else:
            return None
        return conn.before

    @return_exceptions
    def _execute_system_command(self, conn, cmd):
        out = self._execute_remote_system_command(conn, cmd)
        status = self._execute_remote_system_command(conn, "echo $?")
        status = status.split("\r\n")
        status = status[1].strip() if len(status) > 1 else status[0].strip()
        try:
            status = int(status)
        except Exception:
            status = 1

        return status, out

    @return_exceptions
    def _stop_ssh_connection(self, conn):
        if not conn or PEXPECT_VERSION == PXSSH_NO_MODULE:
            return

        if PEXPECT_VERSION == PXSSH_NEW_MODULE:
            conn.logout()
            if conn:
                conn.close()

        self.remote_system_command_prompt = "[#$] "

    @return_exceptions
    def _get_remote_host_system_statistics(self, commands):
        sys_stats = {}

        if PEXPECT_VERSION == PXSSH_NO_MODULE:
            self.logger.warning(
                "Ignoring system statistics collection from node %s. No module named pexpect."
                % (str(self.ip))
            )
            return sys_stats

        sys_stats_collected = False
        self._set_system_credentials()
        max_tries = 1
        tries = 0

        while tries < max_tries and not sys_stats_collected:
            tries += 1
            s = None

            try:
                s = self._create_ssh_connection(
                    self.ip,
                    self.sys_user_id,
                    self.sys_pwd,
                    self.sys_ssh_key,
                    self.sys_ssh_port,
                )
                if not s:
                    raise Exception("Wrong credentials to connect.")

                if isinstance(s, Exception):
                    raise s

            except Exception as e:
                if tries >= max_tries:
                    self.logger.warning(
                        "Ignoring system statistics collection. Couldn't make SSH login to remote server %s:%s. \n%s"
                        % (
                            str(self.ip),
                            "22"
                            if self.sys_ssh_port is None
                            else str(self.sys_ssh_port),
                            str(e),
                        )
                    )

                continue

            try:
                for _key, _, cmds in self.sys_cmds:
                    if _key not in commands:
                        continue

                    for cmd in cmds:
                        try:
                            status, o = self._execute_system_command(s, cmd)
                            if status or not o or isinstance(o, Exception):
                                continue
                            self.parse_system_live_command(_key, o, sys_stats)
                            break

                        except Exception:
                            pass

                sys_stats_collected = True
                self._stop_ssh_connection(s)

            except Exception as e:
                if tries >= max_tries:
                    self.logger.error(
                        "Ignoring system statistics collection. Couldn't get or parse remote system stats for remote server %s:%s. \n%s"
                        % (
                            str(self.ip),
                            "22"
                            if self.sys_ssh_port is None
                            else str(self.sys_ssh_port),
                            str(e),
                        )
                    )

            finally:
                if s and not isinstance(s, Exception):
                    s.close()

        return sys_stats

    @return_exceptions
    def info_system_statistics(
        self,
        default_user=None,
        default_pwd=None,
        default_ssh_key=None,
        default_ssh_port=None,
        credential_file=None,
        commands=[],
        collect_remote_data=False,
    ):
        """
        Get statistics for a system.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        # TODO make async
        logger.debug(
            (
                "%s.info_system_statistics default_user=%s default_pws=%s"
                "default_ssh_key=%s default_ssh_port=%s credential_file=%s"
                "commands=%s collect_remote_data=%s"
            ),
            self.ip,
            default_user,
            default_pwd,
            default_ssh_key,
            default_ssh_port,
            credential_file,
            commands,
            collect_remote_data,
        )

        if commands:
            cmd_list = copy.deepcopy(commands)
        else:
            cmd_list = [_key for _key, _, _ in self.sys_cmds]

        if self.localhost:
            return self._get_localhost_system_statistics(cmd_list)

        if collect_remote_data:
            self._set_default_system_credentials(
                default_user,
                default_pwd,
                default_ssh_key,
                default_ssh_port,
                credential_file,
            )
            return self._get_remote_host_system_statistics(cmd_list)

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
