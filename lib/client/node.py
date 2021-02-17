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

import copy
import logging
import os
import re
import socket
import threading
from time import time

from lib.client import util
from lib.client.assocket import ASSocket
from lib.collectinfo_parser import conf_parser
from lib.collectinfo_parser.full_parser import parse_system_live_command
from lib.utils import common
from lib.utils.constants import AuthMode
from lib.utils.util import shell_command, logthis

#### Remote Server connection module

NO_MODULE = 0
OLD_MODULE = 1
NEW_MODULE = 2

try:
    from pexpect import pxssh

    PEXPECT_VERSION = NEW_MODULE
except ImportError:
    try:
        # For old versions of pexpect ( < 3.0)
        import pexpect
        import pxssh

        PEXPECT_VERSION = OLD_MODULE
    except ImportError:
        PEXPECT_VERSION = NO_MODULE


def getfqdn(address, timeout=0.5):
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


def return_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            args[0].alive = False
            return e

    return wrapper


class Node(object):
    dns_cache = {}
    pool_lock = threading.Lock()

    def __init__(
        self,
        address,
        port=3000,
        tls_name=None,
        timeout=5,
        user=None,
        password=None,
        auth_mode=AuthMode.INTERNAL,
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
        self._update_IP(address, port)
        self.port = port
        self.xdr_port = 3004  # TODO: Find the xdr port
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
        ]

        # hack, _key needs to be defines before info calls... but may have
        # wrong (localhost) address before info_service is called. Will set
        # again after that call.

        self._key = hash(self.create_key(address, self.port))
        self.peers_generation = -1
        self.service_addresses = []
        self._initialize_socket_pool()
        self.connect(address, port)
        self.localhost = False
        try:
            if address.lower() == "localhost":
                self.localhost = True
            else:
                o, e = shell_command(["hostname -I"])
                self.localhost = self._is_any_my_ip(o.split())
        except Exception:
            pass

        # configurations from conf file
        self.conf_data = {}

    def _initialize_socket_pool(self):
        self.socket_pool = {}
        self.socket_pool[self.port] = set()
        self.socket_pool[self.xdr_port] = set()
        self.socket_pool_max_size = 3

    def _is_any_my_ip(self, ips):
        if not ips:
            return False
        s_a = [a[0] for a in self.service_addresses]
        if set(ips).intersection(set(s_a)):
            return True
        return False

    def connect(self, address, port):
        try:
            if not self.login():
                raise IOError("Login Error")

            self.node_id = self.info_node()
            if isinstance(self.node_id, Exception):
                # Not able to connect this address
                raise self.node_id

            self.features = self.info("features")
            self.use_peers_list = self.is_feature_present(feature="peers")

            # Original address may not be the service address, the
            # following will ensure we have the service address
            service_addresses = self.info_service_list()
            if service_addresses and not isinstance(self.service_addresses, Exception):
                self.service_addresses = service_addresses
            # else : might be it's IP is not available, node should try all old
            # service addresses

            self.close()
            self._initialize_socket_pool()
            _current_host = (self.ip, self.port, self.tls_name)
            if (
                not self.service_addresses
                or _current_host not in self.service_addresses
            ):
                # if asd >= 3.10 and node has only IPv6 address
                self.service_addresses.append(_current_host)

            for s in self.service_addresses:
                try:
                    address = s[0]
                    # calling update ip again because info_service may have provided a
                    # different IP than what was seeded.
                    self.ip = address
                    self.node_id = self.info_node()

                    if not isinstance(self.node_id, Exception):
                        self._update_IP(address, self.port)
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
            if self.has_peers_changed():
                self.peers = self.info_peers_list()
            self.new_histogram_version = self._is_new_histogram_version()
            self.alive = True

        except Exception:
            # Node is offline... fake a node
            self.ip = address
            self.fqdn = address
            self.port = port
            self._service_IP_port = self.create_key(self.ip, self.port)
            self._key = hash(self._service_IP_port)

            self.node_id = "000000000000000"
            self.service_addresses = [(self.ip, self.port, self.tls_name)]
            self.features = ""
            self.use_peers_list = False
            self.peers = []
            self.use_new_histogram_format = False
            self.alive = False

    def refresh_connection(self):
        self.connect(self.ip, self.port)

    def login(self):
        if self.user is None:
            return True

        if not self.perform_login and (
            self.session_expiration == 0 or self.session_expiration > time()
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
        if not sock.connect():
            sock.close()
            return False

        if not sock.login():
            sock.close()
            return False

        self.session_token, self.session_expiration = sock.get_session_info()
        self.perform_login = False
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

    def _update_IP(self, address, port):
        if address not in self.dns_cache:
            self.dns_cache[address] = (
                socket.getaddrinfo(address, port, socket.AF_UNSPEC, socket.SOCK_STREAM)[
                    0
                ][4][0],
                getfqdn(address),
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

    def is_XDR_enabled(self):
        config = self.info_get_config("xdr")
        if isinstance(config, Exception):
            return False

        # 'enable-xdr' was removed in XDR5.0, so check that get-config:context=xdr does not return an error.
        if util.info_valid(config):
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

    def has_peers_changed(self):
        try:
            if not self.use_peers_list:
                # old server code < 3.10
                return True
            new_generation = self.info("peers-generation")
            if self.peers_generation != new_generation:
                self.peers_generation = new_generation
                return True
            else:
                return False
        except Exception:
            return True

    def _is_new_histogram_version(self):
        as_version = self.info_build_version()
        if isinstance(as_version, Exception):
            return False

        return common.is_new_histogram_version(as_version)

    def _get_connection(self, ip, port):
        sock = None

        with Node.pool_lock:

            try:
                while True:

                    sock = self.socket_pool[port].pop()

                    if sock.is_connected():
                        if not self.ssl_context:
                            sock.settimeout(self._timeout)
                        break

                    sock.close()
                    sock = None

            except Exception:
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

        if sock.connect():
            if sock.authenticate(self.session_token):
                return sock
            elif self.session_token is not None:
                # login enabled.... might be session_token expired, need to perform login again
                self.perform_login = True

        return None

    def close(self):
        try:
            while True:
                sock = self.socket_pool[self.port].pop()
                sock.close()
        except Exception:
            pass

        try:
            while True:
                sock = self.socket_pool[self.xdr_port].pop()
                sock.close()
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

    @return_exceptions
    @util.cached
    def _info_cinfo(self, command, ip=None, port=None):
        # TODO: citrusleaf.py does not support passing a timeout default is
        # 0.5s
        if ip is None:
            ip = self.ip
        if port is None:
            port = self.port
        result = None

        sock = self._get_connection(ip, port)
        if not sock:
            raise IOError("Error: Could not connect to node %s" % ip)

        try:
            if sock:
                result = sock.info(command)
                try:
                    if len(self.socket_pool[port]) < self.socket_pool_max_size:
                        sock.settimeout(None)
                        self.socket_pool[port].add(sock)

                    else:
                        sock.close()

                except Exception:
                    sock.close()

            if result != -1 and result is not None:
                return result

            else:
                raise IOError("Error: Invalid command '%s'" % command)

        except Exception as ex:
            if sock:
                sock.close()
            raise ex

    @return_exceptions
    def info(self, command):
        """
        asinfo function equivalent

        Arguments:
        command -- the info command to execute on this node
        """
        return self._info_cinfo(command, self.ip)

    @return_exceptions
    @util.cached
    def xdr_info(self, command):
        """
        asinfo -p [xdr-port] equivalent

        Arguments:
        command -- the info command to execute on this node
        """

        return self._info_cinfo(command, self.ip, self.xdr_port)

    @return_exceptions
    def info_node(self):
        """
        Get this nodes id. asinfo -v "node"

        Returns:
        string -- this node's id.
        """

        return self.info("node")

    @return_exceptions
    def info_ip_port(self):
        """
        Get this nodes ip:port.

        Returns:
        string -- this node's ip:port.
        """

        return self.create_key(self.ip, self.port)

    ###### Services ######

    # pre 3.10 services

    @return_exceptions
    def info_services(self):
        """
        Get other services this node knows of that are active

        Returns:
        list -- [(ip,port,tls_name),...]
        """

        return self._info_services_helper(self.info("services"))

    @return_exceptions
    def info_services_alumni(self):
        """
        Get other services this node has ever know of

        Returns:
        list -- [(ip,port,tls_name),...]
        """

        try:
            return self._info_services_helper(self.info("services-alumni"))
        except IOError:
            # Possibly old asd without alumni feature
            return self.info_services()

    @return_exceptions
    def info_services_alt(self):
        """
        Get other services_alternative this node knows of that are active

        Returns:
        list -- [(ip,port,tls_name),...]
        """

        return self._info_services_helper(self.info("services-alternate"))

    @return_exceptions
    def _info_services_helper(self, services):
        """
        Takes an info services response and returns a list.
        """
        if not services or isinstance(services, Exception):
            return []

        s = map(util.info_to_tuple, util.info_to_list(services))
        return [(v[0], int(v[1]), self.tls_name) for v in s]

    # post 3.10 services

    @return_exceptions
    def info_peers(self):
        """
        Get peers this node knows of that are active

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        if self.enable_tls:
            return self._info_peers_helper(self.info("peers-tls-std"))

        return self._info_peers_helper(self.info("peers-clear-std"))

    @return_exceptions
    def info_peers_alumni(self):
        """
        Get peers this node has ever know of

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        if self.enable_tls:
            return self._info_peers_helper(self.info("alumni-tls-std"))
        return self._info_peers_helper(self.info("alumni-clear-std"))

    @return_exceptions
    def info_peers_alt(self):
        """
        Get peers this node knows of that are active alternative addresses

        Returns:
        list -- [(p1_ip,p1_port,p1_tls_name),((p2_ip1,p2_port1,p2_tls_name),(p2_ip2,p2_port2,p2_tls_name))...]
        """
        if self.enable_tls:
            return self._info_peers_helper(self.info("peers-tls-alt"))

        return self._info_peers_helper(self.info("peers-clear-alt"))

    @return_exceptions
    def _info_peers_helper(self, peers):
        """
        Takes an info peers list response and returns a list.
        """
        gen_port_peers = util.parse_peers_string(peers)
        if not gen_port_peers or len(gen_port_peers) < 3:
            return []
        default_port = 3000
        # TODO not used generation = gen_port_peers[0]
        if gen_port_peers[1]:
            default_port = int(gen_port_peers[1])

        peers_list = util.parse_peers_string(gen_port_peers[2])
        if not peers_list or len(peers_list) < 1:
            return []

        p_list = []

        for p in peers_list:
            p_data = util.parse_peers_string(p)
            if not p_data or len(p_data) < 3:
                continue

            # TODO - not used node_name = p_data[0]
            tls_name = None
            if p_data[1] and len(p_data[1]) > 0:
                tls_name = p_data[1]

            endpoints = util.parse_peers_string(p_data[2])
            if not endpoints or len(endpoints) < 1:
                continue

            if not tls_name:
                tls_name = util.find_dns(endpoints)

            endpoint_list = []

            for e in endpoints:
                if "[" in e and "]:" not in e:
                    addr_port = util.parse_peers_string(e, delim=",")
                else:
                    addr_port = util.parse_peers_string(e, delim=":")

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

    @return_exceptions
    def get_alumni_peers(self):
        if self.use_peers_list:
            # Unlike services-alumni, info_peers_alumni for server version prior to 4.3.1 gives
            # only old nodes (which are not part of current cluster), so to get full list we need to
            # add info_peers
            alumni_peers = self.get_peers()
            return list(set(alumni_peers + self.info_peers_alumni()))
        else:
            alumni_services = self.info_services_alumni()
            if alumni_services and not isinstance(alumni_services, Exception):
                return alumni_services
            return self.info_services()

    @return_exceptions
    def get_peers(self, all=False):
        if self.use_peers_list:
            if all:
                return self.info_peers_alt() + self.info_peers()

            if self.use_services_alt:
                return self.info_peers_alt()

            return self.info_peers()

        else:
            if all:
                return self.info_services_alt() + self.info_services()

            if self.use_services_alt:
                return self.info_services_alt()

            return self.info_services()

    @return_exceptions
    def info_peers_list(self):
        if self.consider_alumni:
            return self.get_alumni_peers()
        else:
            return self.get_peers()

    @return_exceptions
    def info_peers_flat_list(self):
        return util.flatten(self.info_peers_list())

    ###### Services End ######

    ###### Service ######

    # pre 3.10 service

    @return_exceptions
    def info_service(self):
        """
        Get service endpoints of this node

        Returns:
        list -- [(ip,port,tls_name),...]
        """

        try:
            return self._info_service_helper(self.info("service"))
        except Exception:
            return []

    @return_exceptions
    def _info_service_helper(self, service, delimiter=";"):
        if not service or isinstance(service, Exception):
            return []
        s = [
            util.parse_peers_string(v, ":")
            for v in util.info_to_list(service, delimiter=delimiter)
        ]
        return [
            (
                v[0].strip("[]"),
                int(v[1]) if len(v) > 1 and v[1] else int(self.port),
                self.tls_name,
            )
            for v in s
        ]

    # post 3.10 services

    @return_exceptions
    def info_service_alt_post310(self):
        """
        Get service alternate endpoints of this node

        Returns:
        list -- [(ip,port,tls_name),...]
        """

        try:
            if self.enable_tls:
                return self._info_service_helper(self.info("service-tls-alt"), ",")

            return self._info_service_helper(self.info("service-clear-alt"), ",")
        except Exception:
            return []

    @return_exceptions
    def info_service_post310(self):
        """
        Get service endpoints of this node

        Returns:
        list -- [(ip,port,tls_name),...]
        """

        try:
            if self.enable_tls:
                return self._info_service_helper(self.info("service-tls-std"), ",")

            return self._info_service_helper(self.info("service-clear-std"), ",")
        except Exception:
            return []

    @return_exceptions
    def info_service_list(self):
        if self.use_peers_list:
            if self.use_services_alt:
                return self.info_service_alt_post310()

            return self.info_service_post310()

        else:
            return self.info_service()

    ###### Service End ######

    @return_exceptions
    def info_statistics(self):
        """
        Get statistics for this node. asinfo -v "statistics"

        Returns:
        dictionary -- statistic name -> value
        """

        return util.info_to_dict(self.info("statistics"))

    @return_exceptions
    def info_namespaces(self):
        """
        Get a list of namespaces for this node. asinfo -v "namespaces"

        Returns:
        list -- list of namespaces
        """

        return util.info_to_list(self.info("namespaces"))

    @return_exceptions
    def info_namespace_statistics(self, namespace):
        """
        Get statistics for a namespace.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """

        ns_stat = util.info_to_dict(self.info("namespace/%s" % namespace))

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

    @return_exceptions
    def info_all_namespace_statistics(self):
        namespaces = self.info_namespaces()

        if isinstance(namespaces, Exception):
            return namespaces

        stats = {}
        for ns in namespaces:
            stats[ns] = self.info_namespace_statistics(ns)

        return stats

    @return_exceptions
    def info_set_statistics(self):
        stats = self.info("sets")
        stats = util.info_to_list(stats)
        if not stats:
            return {}
        stats.pop()
        stats = [util.info_colon_to_dict(stat) for stat in stats]
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

    @return_exceptions
    def info_health_outliers(self):
        stats = self.info("health-outliers")
        stats = util.info_to_list(stats)
        if not stats:
            return {}
        stats = [util.info_colon_to_dict(stat) for stat in stats]
        health_dict = {}

        for i, stat in enumerate(stats):
            key = "outlier" + str(i)
            health_dict[key] = stat

        return health_dict

    @return_exceptions
    def info_bin_statistics(self):
        stats = util.info_to_list(self.info("bins"))
        if not stats:
            return {}
        stats.pop()
        stats = [value.split(":") for value in stats]
        stat_dict = {}

        for stat in stats:
            values = util.info_to_list(stat[1], ",")
            values = ";".join([v for v in values if "=" in v])
            values = util.info_to_dict(values)
            stat_dict[stat[0]] = values

        return stat_dict

    @return_exceptions
    def info_XDR_statistics(self):
        """
        Get statistics for XDR

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        # for new aerospike version (>=3.8) with
        # xdr-in-asd stats available on service port
        if int(self.info_build_version()[0]) < 5:
            if self.is_feature_present("xdr"):
                return util.info_to_dict(self.info("statistics/xdr"))

            return util.info_to_dict(self.xdr_info("statistics"))
        else:
            return self.info_all_dc_statistics()

    @return_exceptions
    def info_get_config(self, stanza="", namespace="", namespace_id=""):
        """
        Get the complete config for a node. This should include the following
        stanzas: Service, Network, XDR, and Namespace
        Sadly it seems Service and Network are not seperable.

        Returns:
        dict -- stanza --> [namespace] --> param --> value
        """
        xdr_major_version = int(self.info_build_version()[0])
        config = {}
        if stanza == "namespace":
            if namespace != "":
                config = {
                    namespace: util.info_to_dict(
                        self.info("get-config:context=namespace;id=%s" % namespace)
                    )
                }
                if namespace_id == "":
                    namespaces = self.info_namespaces()
                    if namespaces and namespace in namespaces:
                        namespace_id = namespaces.index(namespace)
                if namespace_id != "":
                    config[namespace]["nsid"] = str(namespace_id)
            else:
                namespace_configs = {}
                namespaces = self.info_namespaces()
                for index, namespace in enumerate(namespaces):
                    namespace_config = self.info_get_config(
                        "namespace", namespace, namespace_id=index
                    )
                    namespace_config = namespace_config[namespace]
                    namespace_configs[namespace] = namespace_config
                config = namespace_configs

        elif stanza == "" or stanza == "service":
            config = util.info_to_dict(self.info("get-config:"))
        elif stanza == 'xdr' and xdr_major_version >= 5:
            xdr_config = {}
            xdr_config['dc_configs'] = {}
            xdr_config['ns_configs'] = {}
            xdr_config['xdr_configs'] = util.info_to_dict(self.info("get-config:context=xdr"))

            for dc in xdr_config['xdr_configs']['dcs'].split(','):
                dc_config = self.info("get-config:context=xdr;dc=%s" % dc)
                xdr_config['ns_configs'][dc] = {}
                xdr_config['dc_configs'][dc] = util.info_to_dict(dc_config)

                start_namespaces = dc_config.find('namespaces=') + len('namespaces=')
                end_namespaces = dc_config.find(';', start_namespaces)
                namespaces = (ns for ns in dc_config[start_namespaces:end_namespaces].split(','))

                for namespace in namespaces:
                    namespace_config = self.info("get-config:context=xdr;dc=%s;namespace=%s" % (dc, namespace))
                    xdr_config['ns_configs'][dc][namespace] = util.info_to_dict(namespace_config)

            config = xdr_config
        elif stanza != 'all':
            config = util.info_to_dict(
                self.info("get-config:context=%s" % stanza))
        elif stanza == "all":
            config["namespace"] = self.info_get_config("namespace")
            config["service"] = self.info_get_config("service")
            # Server lumps this with service
            # config["network"] = self.info_get_config("network")
        return config

    @return_exceptions
    def info_get_originalconfig(self, stanza=""):
        """
        Get the original config (from conf file) for a node. This should include the following
        stanzas: Service, Network, XDR, DC, and Namespace

        Returns:
        dict -- stanza --> [namespace] --> param --> value
        """
        config = {}
        if not self.localhost:
            return config

        if not self.conf_data:
            conf_path = "/etc/aerospike/aerospike.conf"
            self.conf_data = conf_parser.parse_file(conf_path)
            if "namespace" in self.conf_data:
                for ns in self.conf_data["namespace"].keys():
                    if "service" in self.conf_data["namespace"][ns]:
                        self.conf_data["namespace"][ns] = self.conf_data["namespace"][
                            ns
                        ]["service"]

        try:
            config = self.conf_data[stanza]

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
                                    ((old_transactions + new_transactions) * 100) /
                                    (old_sum + new_sum)
                            ),
                            2,
                        )
                    total_row[has_time_range_col] = round(old_sum + new_sum, 2)

                updated = True
                break

        if not updated:
            total_rows.append(copy.deepcopy(row))
        return total_rows

    @return_exceptions
    def info_latency(self, back=None, duration=None, slice_tm=None, ns_set=None):
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
            hist_info = self.info(cmd)
        except Exception:
            return data
        tdata = hist_info.split(";")
        hist_name = None
        ns = None
        start_time = None
        columns = []
        ns_hist_pattern = "{([A-Za-z_\d-]+)}-([A-Za-z_-]+)"
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
                columns = [col.replace("u", u"\u03bc") for col in row[1:]]
                start_time = s2
                start_time = util.remove_suffix(start_time, "-GMT")
                columns.insert(0, "Time Span")
                continue

            if not hist_name or not start_time:
                continue
            try:
                end_time = row.pop(0)
                end_time = util.remove_suffix(end_time, "-GMT")
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

    @return_exceptions
    def info_latencies(
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
                    namespaces = self.info("namespaces").split(";")
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
                hist_info.append(self.info(cmd))
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
        unit_mapping = {"msec": "ms", "usec": u"\u03bcs"}
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
            except:
                # Missing histogram
                pass
        return data

    @return_exceptions
    def info_dcs(self):
        """
        Get a list of datacenters for this node. asinfo -v "dcs" -p 3004

        Returns:
        list -- list of dcs
        """
        xdr_major_version = int(self.info_build_version()[0])

        # for server versions >= 5 using XDR5.0
        if xdr_major_version >= 5:
            if self.is_feature_present("xdr"):
                return util.dcs_info_to_list(self.info("get-config:context=xdr"))
            else:
                return util.dcs_info_to_list(self.xdr_info("get-config:context=xdr"))

        # for older servers/XDRs
        else:
            if self.is_feature_present("xdr"):
                return util.info_to_list(self.info("dcs"))
            else:
                return util.info_to_list(self.xdr_info("dcs"))

    @return_exceptions
    def info_dc_statistics(self, dc):
        """
        Get statistics for a datacenter.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        xdr_major_version = int(self.info_build_version()[0])

        # If xdr version is < XDR5.0 return output of old asinfo command.
        if xdr_major_version < 5:

            if self.is_feature_present("xdr"):
                return util.info_to_dict(self.info("dc/%s" % dc))
            else:
                return util.info_to_dict(self.xdr_info("dc/%s" % dc))
        else:

            if self.is_feature_present("xdr"):
                return util.info_to_dict(self.info("get-stats:context=xdr;dc=%s" % dc))
            else:
                return util.info_to_dict(
                    self.xdr_info("get-stats:context=xdr;dc=%s" % dc)
                )

    @return_exceptions
    def info_all_dc_statistics(self):
        dcs = self.info_dcs()

        if isinstance(dcs, Exception):
            return {}

        stats = {}
        for dc in dcs:
            stat = self.info_dc_statistics(dc)
            if not stat or isinstance(stat, Exception):
                stat = {}
            stats[dc] = stat

        return stats

    @return_exceptions
    def info_udf_list(self):
        """
        Get config for a udf.

        Returns:
        dict -- {file_name1:{key_name : key_value, ...}, file_name2:{key_name : key_value, ...}}
        """
        udf_data = self.info("udf-list")

        if not udf_data:
            return {}

        return util.info_to_dict_multi_level(udf_data, "filename", delimiter2=",")

    @return_exceptions
    def info_roster(self):
        """
        Get roster info.

        Returns:
        dict -- {ns1:{key_name : key_value, ...}, ns2:{key_name : key_value, ...}}
        """
        roster_data = self.info("roster:")

        if not roster_data:
            return {}

        roster_data = util.info_to_dict_multi_level(roster_data, "ns")
        list_fields = ["roster", "pending_roster", "observed_nodes"]

        for ns, ns_roster_data in roster_data.items():
            for k, v in ns_roster_data.items():
                if k not in list_fields:
                    continue

                try:
                    ns_roster_data[k] = v.split(",")
                except Exception:
                    ns_roster_data[k] = v

        return roster_data

    @return_exceptions
    def info_racks(self):
        """
        Get rack info.

        Returns:
        dict -- {ns1:{rack-id: {'rack-id': rack-id, 'nodes': [node1, node2, ...]}, ns2:{...}, ...}
        """
        rack_data = self.info("racks:")

        if not rack_data:
            return {}

        rack_data = util.info_to_dict_multi_level(rack_data, "ns")
        rack_dict = {}

        for ns, ns_rack_data in rack_data.items():
            rack_dict[ns] = {}

            for k, v in ns_rack_data.items():
                if k == "ns":
                    continue

                try:
                    rack_id = k.split("_")[1]
                    nodes = v.split(",")
                    rack_dict[ns][rack_id] = {}
                    rack_dict[ns][rack_id]["rack-id"] = rack_id
                    rack_dict[ns][rack_id]["nodes"] = nodes
                except Exception:
                    continue

        return rack_dict

    @return_exceptions
    def info_dc_get_config(self):
        """
        Get config for a datacenter.

        Returns:
        dict -- {dc_name1:{config_name : config_value, ...}, dc_name2:{config_name : config_value, ...}}
        """

        if self.is_feature_present("xdr"):
            configs = self.info("get-dc-config")
            if not configs or isinstance(configs, Exception):
                configs = self.info("get-dc-config:")
            if not configs or isinstance(configs, Exception):
                return {}
            return util.info_to_dict_multi_level(
                configs,
                ["dc-name", "DC_Name"],
                ignore_field_without_key_value_delimiter=False,
            )

        configs = self.xdr_info("get-dc-config")
        if not configs or isinstance(configs, Exception):
            return {}
        return util.info_to_dict_multi_level(
            configs,
            ["dc-name", "DC_Name"],
            ignore_field_without_key_value_delimiter=False,
        )

    @return_exceptions
    def info_XDR_get_config(self):
        xdr_configs = self.info_get_config(stanza="xdr")
        # for new aerospike version (>=3.8) with xdr-in-asd config from service
        # port is sufficient
        if self.is_feature_present("xdr"):
            return xdr_configs
        # required for old aerospike server versions (<3.8)
        xdr_configs_xdr = self.xdr_info("get-config")
        if xdr_configs_xdr and not isinstance(xdr_configs_xdr, Exception):
            xdr_configs_xdr = util.info_to_dict(xdr_configs_xdr)
            if xdr_configs_xdr and not isinstance(xdr_configs_xdr, Exception):
                if xdr_configs and not isinstance(xdr_configs, Exception):
                    xdr_configs.update(xdr_configs_xdr)
                else:
                    xdr_configs = xdr_configs_xdr

        return xdr_configs

    def _collect_histogram_data(
        self, histogram, command, logarithmic=False, raw_output=False
    ):
        namespaces = self.info_namespaces()

        data = {}
        for namespace in namespaces:
            try:
                datum = self.info(command % (namespace, histogram))
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

    @return_exceptions
    def info_histogram(self, histogram, logarithmic=False, raw_output=False):
        if not self.new_histogram_version:
            return self._collect_histogram_data(
                histogram, command="hist-dump:ns=%s;hist=%s", raw_output=raw_output
            )

        command = "histogram:namespace=%s;type=%s"

        if logarithmic:
            if histogram == "objsz":
                histogram = "object-size"
            return self._collect_histogram_data(
                histogram,
                command=command,
                logarithmic=logarithmic,
                raw_output=raw_output,
            )

        if histogram == "objsz":
            histogram = "object-size-linear"

        return self._collect_histogram_data(
            histogram, command=command, logarithmic=logarithmic, raw_output=raw_output
        )

    @return_exceptions
    def info_sindex(self):
        return [
            util.info_to_dict(v, ":")
            for v in util.info_to_list(self.info("sindex"))[:-1]
        ]

    @return_exceptions
    def info_sindex_statistics(self, namespace, indexname):
        """
        Get statistics for a sindex.

        Returns:
        dict -- {stat_name : stat_value, ...}
        """
        return util.info_to_dict(self.info("sindex/%s/%s" % (namespace, indexname)))

    @return_exceptions
    def info_build_version(self):
        """
        Get Build Version

        Returns:
        string -- build version
        """
        return self.info("build")


    ############################################################################
    #
    #                      Admin (Security Protocol) API
    #
    ############################################################################

    @logthis('asadm', logging.DEBUG)
    def _admin_cadmin(self, admin_func, args, ip, port=None):
        if port is None:
            port = self.port

        result = None
        sock = self._get_connection(ip, port)

        if not sock:
            raise IOError("Error: Could not connect to node %s" % ip)

        try:
            print(*args)
            result = admin_func(sock, *args)

            # Either restore the socket in the pool or close it if it is full.
            if len(self.socket_pool[port]) < self.socket_pool_max_size:
                sock.settimeout(None)
                self.socket_pool[port].add(sock)
            else:
                sock.close()

        except Exception as e:
            if sock:
                sock.close()
            
            # Re-raise the last exception
            raise 

        return result

    @return_exceptions
    def admin_create_user(self, user, password, roles):
        """
        Create user.
        user: string
        password: string (un-hashed)
        roles: list[string]

        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.create_user, (user, password, roles), self.ip)

    @return_exceptions
    def admin_delete_user(self, user):
        """
        Delete user.
        user: string

        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.delete_user, [user], self.ip)

    @return_exceptions
    def admin_set_password(self, user, password):
        """
        Set user password.
        user: string
        password: string (un-hashed)
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.set_password, (user, password), self.ip)

    @return_exceptions
    def admin_change_password(self, user, old_password, new_password):
        """
        Change user password.
        user: string
        old_password: string (un-hashed)
        new_password: string (un-hashed)
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.change_password, (user, old_password, new_password), self.ip)

    @return_exceptions
    def admin_grant_roles(self, user, roles):
        """
        Grant roles to user.
        user: string
        roles: list[string]
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.grant_roles, (user, roles), self.ip)

    @return_exceptions
    def admin_revoke_roles(self, user, roles):
        """
        Remove roles from user.
        user: string
        roles: list[string]
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.revoke_roles, (user, roles), self.ip)

    @return_exceptions
    def admin_query_users(self):
        """
        Query users.
        Returns: {username1: [role1, role2, . . .], username2: [. . .],  . . .},
        ASProtocolError on fail
        """
        return self._admin_cadmin(ASSocket.query_users, (), self.ip)

    @return_exceptions
    def admin_query_user(self, user):
        """
        Query a user.
        user: string
        Returns: {username: [role1, role2, . . .]},
        ASProtocolError on fail
        """
        return self._admin_cadmin(ASSocket.query_user, [user], self.ip)

    @return_exceptions
    def admin_create_role(self, role, privileges, whitelist=None):
        """
        Create role with privileges and whitelist.
        role: string
        privileges: list[string]
        whitelist: list[string] (optional)
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.create_role, (role, privileges, whitelist), self.ip)

    @return_exceptions
    def admin_delete_role(self, role):
        """
        Delete role.
        role: string
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.delete_role, [role], self.ip)

    @return_exceptions
    def admin_add_privileges(self, role, privileges):
        """
        Add privileges to role.
        role: string
        privileges: list[string]
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.add_privileges, (role, privileges), self.ip)

    @return_exceptions
    def admin_delete_privileges(self, role, privileges):
        """
        Delete privileges from role.
        role: string
        privileges: list[string]
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.delete_privileges, (role, privileges), self.ip)

    @return_exceptions
    def admin_set_whitelist(self, role, whitelist):
        """
        Set whitelist for a role.
        role: string
        whitelist: list[string]
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.set_whitelist, (role, whitelist), self.ip)

    @return_exceptions
    def admin_delete_whitelist(self, role):
        """
        Delete whitelist for a role.
        role: string
        Returns: None on success, ASProtocolError on fail
        """
        self._admin_cadmin(ASSocket.delete_whitelist, [role], self.ip)

    @return_exceptions
    def admin_query_roles(self):
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
        return self._admin_cadmin(ASSocket.query_roles, (), self.ip)

    @return_exceptions
    def admin_query_role(self, role):
        """
        Query a role.
        role: string
        Returns: {role:
                    'privileges': [privilege1, ...],
                    'whitelist': [addr1, addr2, ...]
                 },
        ASProtocolError on fail
        """
        return self._admin_cadmin(ASSocket.query_role, [role], self.ip)


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
                    "Ignoring credential file. Can not open credential file. \n%s."
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

    @return_exceptions
    def _get_localhost_system_statistics(self, commands):
        sys_stats = {}

        self.logger.debug(
            ("{}._get_localhost_system_statistics cmds={}")
            .format(
                self.ip,
                commands,
            ), 
            stackinfo=True
        )
        
        for _key, ignore_error, cmds in self.sys_cmds:
            if _key not in commands:
                continue

            for cmd in cmds:
                self.logger.debug(
                    ("{}._get_localhost_system_statistics running cmd={}")
                    .format(
                        self.ip,
                        cmd,
                    ), 
                    stackinfo=True
                )
                o, e = shell_command([cmd])
                if (e and not ignore_error) or not o:
                    continue

                try:
                    parse_system_live_command(_key, o, sys_stats)
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
    def _spawn_remote_system(self, ip, user, pwd, ssh_key=None, port=None):

        terminal_prompt_msg = "(?i)terminal type"
        ssh_newkey_msg = "(?i)are you sure you want to continue connecting"
        connection_closed_msg = "(?i)connection closed by remote host"
        permission_denied_msg = "(?i)permission denied"
        pwd_passphrase_msg = "(?i)(?:password)|(?:passphrase for key)"

        terminal_type = "vt100"

        ssh_options = "-o 'NumberOfPasswordPrompts=1' "

        if port:
            ssh_options += " -p %s" % (str(port))

        if ssh_key is not None:
            try:
                os.path.isfile(ssh_key)
            except Exception:
                raise Exception("private ssh key %s does not exist" % (str(ssh_key)))

            ssh_options += " -i %s" % (ssh_key)

        s = pexpect.spawn("ssh %s -l %s %s" % (ssh_options, str(user), str(ip)))
        i = s.expect(
            [
                ssh_newkey_msg,
                self.remote_system_command_prompt,
                pwd_passphrase_msg,
                permission_denied_msg,
                terminal_prompt_msg,
                pexpect.TIMEOUT,
                connection_closed_msg,
                pexpect.EOF,
            ],
            timeout=10,
        )

        if i == 0:
            # In this case SSH does not have the public key cached.
            s.sendline("yes")
            i = s.expect(
                [
                    ssh_newkey_msg,
                    self.remote_system_command_prompt,
                    pwd_passphrase_msg,
                    permission_denied_msg,
                    terminal_prompt_msg,
                    pexpect.TIMEOUT,
                ]
            )
        if i == 2:
            # password or passphrase
            if pwd is None:
                raise Exception("Wrong SSH Password None.")

            s.sendline(pwd)
            i = s.expect(
                [
                    ssh_newkey_msg,
                    self.remote_system_command_prompt,
                    pwd_passphrase_msg,
                    permission_denied_msg,
                    terminal_prompt_msg,
                    pexpect.TIMEOUT,
                ]
            )
        if i == 4:
            s.sendline(terminal_type)
            i = s.expect(
                [
                    ssh_newkey_msg,
                    self.remote_system_command_prompt,
                    pwd_passphrase_msg,
                    permission_denied_msg,
                    terminal_prompt_msg,
                    pexpect.TIMEOUT,
                ]
            )
        if i == 7:
            s.close()
            return None

        if i == 0:
            # twice not expected
            s.close()
            return None
        elif i == 1:
            pass
        elif i == 2:
            # password prompt again means input password is wrong
            s.close()
            return None
        elif i == 3:
            # permission denied means input password is wrong
            s.close()
            return None
        elif i == 4:
            # twice not expected
            s.close()
            return None
        elif i == 5:
            # timeout
            # Two possibilities
            # 1. couldn't login
            # 2. couldn't match shell prompt
            # safe option is to pass
            pass
        elif i == 6:
            # connection closed by remote host
            s.close()
            return None
        else:
            # unexpected
            s.close()
            return None

        self.remote_system_command_prompt = "\[PEXPECT\][\$\#] "
        s.sendline("unset PROMPT_COMMAND")

        # sh style
        s.sendline("PS1='[PEXPECT]\$ '")
        i = s.expect([pexpect.TIMEOUT, self.remote_system_command_prompt], timeout=10)
        if i == 0:
            # csh-style.
            s.sendline("set prompt='[PEXPECT]\$ '")
            i = s.expect(
                [pexpect.TIMEOUT, self.remote_system_command_prompt], timeout=10
            )

            if i == 0:
                return None

        return s

    @return_exceptions
    def _create_ssh_connection(self, ip, user, pwd, ssh_key=None, port=None):
        if user is None and pwd is None and ssh_key is None:
            raise Exception("Insufficient credentials to connect.")

        if PEXPECT_VERSION == NEW_MODULE:
            return self._login_remote_system(ip, user, pwd, ssh_key, port)

        if PEXPECT_VERSION == OLD_MODULE:
            return self._spawn_remote_system(ip, user, pwd, ssh_key, port)

        return None

    @return_exceptions
    def _execute_remote_system_command(self, conn, cmd):
        if not conn or not cmd or PEXPECT_VERSION == NO_MODULE:
            return None

        conn.sendline(cmd)
        if PEXPECT_VERSION == NEW_MODULE:
            conn.prompt()
        elif PEXPECT_VERSION == OLD_MODULE:
            conn.expect(self.remote_system_command_prompt)
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
        if not conn or PEXPECT_VERSION == NO_MODULE:
            return

        if PEXPECT_VERSION == NEW_MODULE:
            conn.logout()
            if conn:
                conn.close()
        elif PEXPECT_VERSION == OLD_MODULE:
            conn.sendline("exit")
            i = conn.expect([pexpect.EOF, "(?i)there are stopped jobs"])
            if i == 1:
                conn.sendline("exit")
                conn.expect(pexpect.EOF)
            if conn:
                conn.close()

        self.remote_system_command_prompt = "[#$] "

    @return_exceptions
    def _get_remote_host_system_statistics(self, commands):
        sys_stats = {}

        if PEXPECT_VERSION == NO_MODULE:
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
                            parse_system_live_command(_key, o, sys_stats)
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
        self.logger.debug(
            ("{}.info_system_statistics default_user={} default_pws={}"
            "default_ssh_key={} default_ssh_port={} credential_file={}"
            "commands={} collect_remote_data={}")
            .format(
                self.ip,
                default_user,
                default_pwd, 
                default_ssh_key, 
                default_ssh_port, 
                credential_file, 
                commands,
                collect_remote_data
            ), 
            stackinfo=True
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
