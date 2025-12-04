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

from asyncio import StreamReader
from asyncio.subprocess import Process
from ctypes import ArgumentError
import time
from typing import Any
from unittest.mock import call
import warnings
from pytest import PytestUnraisableExceptionWarning
from mock import MagicMock, patch
import socket
import unittest
from collections import deque

from mock.mock import AsyncMock, Mock, call
import pytest

import lib
from lib.live_cluster.client.ctx import CDTContext, CTXItem, CTXItems
from lib.live_cluster.client.types import (
    ASProtocolError,
    ASProtocolExcFactory,
    ASResponse,
)

from lib.live_cluster.client.constants import ErrorsMsgs
from test.unit import util
from lib.utils import constants
from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.node import _SysCmd, Node
from lib.live_cluster.client import (
    ASINFO_RESPONSE_OK,
    ASInfoConfigError,
    ASInfoResponseError,
)

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    import asynctest


class NodeInitTest(asynctest.TestCase):
    async def setUp(self):
        self.maxDiff = None
        self.ip = "192.1.1.1"
        self.get_fully_qualified_domain_name = patch(
            "lib.live_cluster.client.node.get_fully_qualified_domain_name"
        ).start()
        self.async_shell_cmd_mock = patch(
            "lib.live_cluster.client.node.util.async_shell_command"
        ).start()

        getaddrinfo = patch("socket.getaddrinfo")

        self.addCleanup(patch.stopall)

        lib.live_cluster.client.node.Node.info_build = patch(
            "lib.live_cluster.client.node.Node.info_build", AsyncMock()
        ).start()
        socket.getaddrinfo = getaddrinfo.start()

        lib.live_cluster.client.node.Node.info_build.return_value = "5.0.0.11"
        self.get_fully_qualified_domain_name.return_value = "host.domain.local"
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.1.1.1", 3000))]

        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

        # Here so call count does not include Node initialization

    async def test_init_node(self):
        self.info_mock = lib.live_cluster.client.node.Node._info_cinfo = patch(
            "lib.live_cluster.client.node.Node._info_cinfo", AsyncMock()
        ).start()
        """
        Ensures that we can instantiate a Node and that the node acquires the
        correct information
        """

        def info_side_effect(*args, **kwargs):
            cmd = args[0]
            # First call - admin port detection
            if cmd == "connection":
                return "admin=false"
            if cmd == ["node", "service-clear-std", "peers-clear-std"]:
                return {
                    "node": "A00000000000000",
                    "service-clear-std": "192.3.3.3:4567",
                    "peers-clear-std": "2,3000,[[1A0,,[3.126.208.136]]]",
                }
            elif cmd == "node":
                return "A00000000000000"
            elif cmd == "peers-clear-std":
                return "peers"
            else:
                # Info call was made that was not defined here
                self.fail()

        def shell_side_effect(*args, **kwargs):
            p = AsyncMock(spec=Process)
            p.returncode = 0
            p.stdout = MagicMock(spec=StreamReader)
            p.stdout.read.return_value = b"192.3.3.3"
            return p

        self.async_shell_cmd_mock.side_effect = shell_side_effect
        self.info_mock.side_effect = info_side_effect
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.3.3.3", 4567))]

        n = await Node("192.1.1.1")

        self.assertEqual(n.ip, "192.3.3.3", "IP address is not correct")
        self.assertEqual(n.fqdn, "host.domain.local", "FQDN is not correct")
        self.assertEqual(n.port, 4567, "Port is not correct")
        self.assertEqual(n.node_id, "A00000000000000", "Node Id is not correct")
        self.async_shell_cmd_mock.assert_awaited_once_with("hostname -I")
        self.assertTrue(n.is_localhost())

    async def test_init_node_is_localhost_not_running_in_docker(self):
        self.info_mock = lib.live_cluster.client.node.Node._info_cinfo = patch(
            "lib.live_cluster.client.node.Node._info_cinfo", AsyncMock()
        ).start()
        """
        Similar to the init test but we want to make sure that we determine we are
        running on localhost if aerospike docker container is not running when passing
        in 127.0.0.1
        """

        def info_side_effect(*args, **kwargs):
            cmd = args[0]
            # First call - admin port detection
            if cmd == "connection":
                return "admin=false"
            if cmd == ["node", "service-clear-std", "peers-clear-std"]:
                return {
                    "node": "A00000000000000",
                    "service-clear-std": "192.3.3.3:4567",
                    "peers-clear-std": "2,3000,[[1A0,,[3.126.208.136]]]",
                }
            elif cmd == "node":
                return "A00000000000000"
            elif cmd == "peers-clear-std":
                return "peers"
            else:
                # Info call was made that was not defined here
                self.fail()

        def shell_side_effect(*args, **kwargs):
            p = AsyncMock(spec=Process)
            p.returncode = 1
            return p

        self.async_shell_cmd_mock.side_effect = shell_side_effect
        self.info_mock.side_effect = info_side_effect
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.3.3.3", 4567))]

        n = await Node("127.0.0.1")

        self.assertEqual(n.ip, "192.3.3.3", "IP address is not correct")
        self.assertEqual(n.fqdn, "host.domain.local", "FQDN is not correct")
        self.assertEqual(n.port, 4567, "Port is not correct")
        self.assertEqual(n.node_id, "A00000000000000", "Node Id is not correct")
        self.async_shell_cmd_mock.assert_awaited_once_with(
            "docker ps | tail -n +2 | awk '{print $2}' | grep 'aerospike/aerospike-server'"
        )
        self.assertTrue(n.is_localhost())

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_node_connection_uses_same_socket_as_login(self, as_socket_mock_init):
        # This is important to support the use of load-balancers as a seed node. The login
        # needs to use the same socket as the rest of the calls to establish a connection.
        def as_socket_mock():
            mock = AsyncMock()
            mock.get_session_info = Mock()
            return mock

        as_socket_mock_used_for_login = as_socket_mock()

        i = 0

        def side_effect_init(*args, **kwargs):
            nonlocal i
            sock = None

            if i == 0:
                sock = as_socket_mock_used_for_login
            else:
                sock = as_socket_mock()

            i += 1
            return sock

        as_socket_mock_init.side_effect = side_effect_init
        as_socket_mock_used_for_login.connect.return_value = True
        as_socket_mock_used_for_login.login.returns_value = True
        as_socket_mock_used_for_login.get_session_info.return_value = "token", 59

        def side_effect_info(*args, **kwargs):
            # First call - admin port detection
            if args[0] == "connection":
                return "admin=false"
            elif args[0] == [
                "node",
                "service-clear-std",
                "peers-clear-std",
            ]:
                return {
                    "node": "A0",
                    "service-clear-std": "1.1.1.1:3000;172.17.0.1:3000;172.17.1.1:3000",
                    "peers-clear-std": "10,3000,[[BB9050011AC4202,,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]",
                }
            else:
                self.fail()

        as_socket_mock_used_for_login.info.side_effect = side_effect_info

        await Node("1.1.1.1", user="user")
        as_socket_mock_used_for_login.login.assert_called_once()
        # Login and the node connection info calls
        as_socket_mock_used_for_login.info.assert_has_calls(
            [
                call("connection"),
                call(["node", "service-clear-std", "peers-clear-std"]),
            ],
        )


class NodeTest(asynctest.TestCase):
    async def setUp(self):
        self.maxDiff = None
        self.ip = "192.1.1.1"
        self.get_fully_qualified_domain_name = patch(
            "lib.live_cluster.client.node.get_fully_qualified_domain_name"
        ).start()

        getaddrinfo = patch("socket.getaddrinfo")

        self.addCleanup(patch.stopall)

        lib.live_cluster.client.node.Node.info_build = patch(
            "lib.live_cluster.client.node.Node.info_build", AsyncMock()
        ).start()
        socket.getaddrinfo = getaddrinfo.start()

        lib.live_cluster.client.node.Node.info_build.return_value = "5.0.0.11"
        self.get_fully_qualified_domain_name.return_value = "host.domain.local"
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.1.1.1", 3000))]
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=RuntimeWarning)
            self.node: Node = await Node(self.ip, timeout=0)

        warnings.filterwarnings("error", category=RuntimeWarning)
        warnings.filterwarnings("error", category=PytestUnraisableExceptionWarning)

        # Here so call count does not include Node initialization
        self.info_mock = lib.live_cluster.client.node.Node._info_cinfo = patch(
            "lib.live_cluster.client.node.Node._info_cinfo", AsyncMock()
        ).start()
        self.logger_mock = patch("lib.live_cluster.client.node.logger").start()
        self.node.conf_schema_handler = MagicMock()
        # Ensure build attribute is set for version comparison tests
        self.node.build = "5.0.0.11"
        self.addCleanup(patch.stopall)

    async def test_login_returns_true_if_user_is_none(self):
        self.node.user = None
        self.node.auth_mode = constants.AuthMode.INTERNAL

        self.assertTrue(await self.node.login())

    async def test_login_returns_true_if_session_has_not_expired(self):
        self.node.auth_mode = constants.AuthMode.PKI
        self.node.perform_login = False
        self.node.session_expiration = time.time() + 60

        self.assertTrue(await self.node.login())

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_login_returns_true_if_login_was_successful(self, as_socket_mock):
        as_socket_mock = as_socket_mock.return_value
        self.node.user = True
        as_socket_mock.connect.return_value = True
        as_socket_mock.login.returns_value = True
        as_socket_mock.get_session_info.return_value = "token", 59
        self.assertEqual(self.node.socket_pool, {self.node.port: deque(maxlen=16)})

        self.assertTrue(await self.node.login())

        as_socket_mock.close.assert_not_called()
        self.assertEqual(
            self.node.socket_pool, {self.node.port: deque([as_socket_mock], maxlen=16)}
        )
        self.assertEqual("token", self.node.session_token)
        self.assertEqual(59, self.node.session_expiration)

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_login_returns_false_if_socket_cant_connect(self, as_socket_mock):
        as_socket_mock = as_socket_mock.return_value
        self.node.user = True
        as_socket_mock.connect.return_value = False

        self.assertFalse(await self.node.login())

        as_socket_mock.connect.assert_called_once()
        as_socket_mock.close.assert_called_once()

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_login_raises_except_if_socket_returns_unexpected_error(
        self, as_socket_mock
    ):
        as_socket_mock = as_socket_mock.return_value
        self.node.user = True
        as_socket_mock.connect.return_value = True
        as_socket_mock.login.side_effect = ASProtocolError(
            ASResponse.BAD_RATE_QUOTA, ""
        )

        await self.assertAsyncRaises(ASProtocolError, self.node.login())

        as_socket_mock.close.assert_called_once()

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_login_logs_warning_when_socket_raises_security_not_enabled(
        self, as_socket_mock
    ):
        self.logger_mock.warning = MagicMock()
        as_socket_mock = as_socket_mock.return_value
        self.node.user = True
        as_socket_mock.connect.return_value = True
        as_socket_mock.login.side_effect = Mock(
            side_effect=ASProtocolError(ASResponse.SECURITY_NOT_ENABLED, "")
        )
        as_socket_mock.get_session_info.return_value = ("token", "session-ttl")

        self.assertTrue(await self.node.login())
        self.logger_mock.warning.assert_called_with(
            ASProtocolError(ASResponse.SECURITY_NOT_ENABLED, "")
        )
        as_socket_mock.close.assert_not_called()
        self.assertIsNotNone(self.node.user)
        self.assertFalse(self.node.perform_login)
        self.assertEqual(self.node.session_token, "token")
        self.assertEqual(self.node.session_expiration, "session-ttl")

        # call again to make sure it is not logged twice.
        self.logger_mock.warning.reset_mock()
        self.node.session_expiration = 0
        as_socket_mock.connect.return_value = True
        as_socket_mock.login.side_effect = Mock(
            side_effect=ASProtocolError(ASResponse.SECURITY_NOT_ENABLED, "")
        )
        as_socket_mock.get_session_info.return_value = ("token", "session-ttl")

        self.assertTrue(await self.node.login())
        self.logger_mock.warning.assert_not_called()

    # TODO: Make unit tests for socket pool
    async def test_get_connection_uses_socket_pool(self):
        class ASSocket_Mock(AsyncMock):
            pass

        as_socket_mock1 = ASSocket_Mock()
        as_socket_mock2 = ASSocket_Mock()
        as_socket_mock1.is_connected.return_value = True
        as_socket_mock1.connect.return_value = True
        as_socket_mock1.name = 1
        as_socket_mock2.is_connected.return_value = False
        as_socket_mock2.name = 2
        self.node._initialize_socket_pool()
        self.node.socket_pool[self.node.port].append(as_socket_mock2)
        self.node.socket_pool[self.node.port].append(as_socket_mock1)

        sock = await self.node._get_connection(self.node.ip, self.node.port)

        # just making sure the correct one was returned since we are dealing with a set.
        self.assertEqual(sock.name, 1)

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_get_connection_returns_new_socket(self, as_socket_mock):
        as_socket_mock = as_socket_mock.return_value

        class ASSocket_Mock(AsyncMock):
            pass

        as_socket_in_pool = ASSocket_Mock()
        as_socket_in_pool.is_connected.return_value = False
        self.node.socket_pool[self.node.port].append(as_socket_in_pool)

        self.node.session_token = "session-token"
        as_socket_mock.connect.return_value = True
        as_socket_mock.authenticate.return_value = True

        sock = await self.node._get_connection(self.node.ip, self.node.port)

        self.assertEqual(sock, as_socket_mock)

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_get_connection_returns_None(self, as_socket_mock):
        as_socket_mock = as_socket_mock.return_value
        as_socket_mock.connect.return_value = False

        sock = await self.node._get_connection(self.node.ip, self.node.port)

        self.assertIsNone(sock)

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_get_connection_returns_new_socket_when_security_not_enabled(
        self, as_socket_mock
    ):
        as_socket_mock = as_socket_mock.return_value
        self.node.session_token = "session-token"
        as_socket_mock.connect.return_value = True
        as_socket_mock.authenticate.return_value = AsyncMock(
            side_effect=ASProtocolError(ASResponse.SECURITY_NOT_ENABLED, "foo")
        )

        sock = await self.node._get_connection(self.node.ip, self.node.port)

        # just making sure the correct one was returned since we are dealing with a set.
        self.assertEqual(sock, as_socket_mock)

    @patch("lib.live_cluster.client.node.ASSocket", autospec=True)
    async def test_get_connection_returns_new_socket_when_no_cred_is_returned_and_user_is_provided(
        self, as_socket_mock
    ):
        self.node.user = "admin"
        self.node.perform_login = False
        as_socket_mock = as_socket_mock.return_value
        self.node.session_token = None
        as_socket_mock.connect.return_value = True
        session_token = "new-token"

        def side_effect(token):
            if token is None:
                raise ASProtocolExcFactory.create_exc(
                    ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL, "foo"
                )
            elif token == session_token:
                return True

            return False

        as_socket_mock.authenticate.side_effect = side_effect
        as_socket_mock.get_session_info.return_value = session_token, 0

        sock = await self.node._get_connection(self.node.ip, self.node.port)

        # just making sure the correct one was returned since we are dealing with a set.
        self.assertEqual(sock, as_socket_mock)
        self.assertEqual(self.node.session_token, session_token)

    ###### Services ######

    async def test_info_peers(self):
        """
        Ensure function returns a list of tuples
        """
        self.info_mock.return_value = "10,3000,[[BB9050011AC4202,,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]"
        expected = [
            (("172.17.0.1", 3000, None),),
            (("2001:db8:85a3::8a2e", 6666, None),),
        ]

        services = await self.node.info_peers()

        self.info_mock.assert_called_with("peers-clear-std", self.ip)
        self.assertEqual(
            services, expected, "info_peers did not return the expected result"
        )

        self.info_mock.return_value = "10,4333,[[BB9050011AC4202,peers,[172.17.0.1]],[BB9070011AC4202,peers,[[2001:db8:85a3::8a2e]]]]"
        self.node.enable_tls = True
        expected = [
            (("172.17.0.1", 4333, "peers"),),
            (("2001:db8:85a3::8a2e", 4333, "peers"),),
        ]

        services = await self.node.info_peers()

        self.info_mock.assert_called_with("peers-tls-std", "192.1.1.1")
        self.assertEqual(
            services,
            expected,
            "info_peers with TLS enabled did not return the expected result",
        )

    async def test_info_peers_alumni(self):
        """
        Ensure function returns a list of tuples
        """
        self.info_mock.return_value = "0,3000,[[BB9050011AC4202,,[172.17.0.3]]]"
        expected = [(("172.17.0.3", 3000, None),)]

        services = await self.node.info_peers_alumni()

        self.info_mock.assert_called_with("alumni-clear-std", "192.1.1.1")
        self.assertEqual(
            services, expected, "info_peers_alumni did not return the expected result"
        )

        self.info_mock.return_value = (
            "0,4333,[[BB9050011AC4202,peers-alumni,[172.17.0.3]]]"
        )
        self.node.enable_tls = True
        expected = [(("172.17.0.3", 4333, "peers-alumni"),)]

        services = await self.node.info_peers_alumni()

        self.info_mock.assert_called_with("alumni-tls-std", "192.1.1.1")
        self.assertEqual(
            services,
            expected,
            "info_peers_alumni with TLS enabled did not return the expected result",
        )

    async def test_info_peers_alt(self):
        """
        Ensure function returns a list of tuples
        """
        self.info_mock.return_value = "0,3000,[[BB9050011AC4202,,[172.17.0.2]]]"
        expected = [(("172.17.0.2", 3000, None),)]

        services = await self.node.info_peers_alt()

        self.info_mock.assert_called_with("peers-clear-alt", "192.1.1.1")
        self.assertEqual(
            services, expected, "info_peers_alt did not return the expected result"
        )

        self.info_mock.return_value = (
            "0,4333,[[BB9050011AC4202,peers-alt,[172.17.0.2]]]"
        )
        self.node.enable_tls = True
        expected = [(("172.17.0.2", 4333, "peers-alt"),)]

        services = await self.node.info_peers_alt()

        self.info_mock.assert_called_with("peers-tls-alt", "192.1.1.1")
        self.assertEqual(
            services,
            expected,
            "info_peers_alt with TLS enabled did not return the expected result",
        )

    async def test_info_peers_list(self):
        self.info_mock.return_value = "0,3000,[[BB9050011AC4202,,[172.17.0.2]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]]]]"
        self.node.use_services_alt = True
        expected = [
            (("172.17.0.2", 3000, None),),
            (("2001:db8:85a3::8a2e", 3000, None),),
        ]

        peers_list = await self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-clear-alt", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(services-alt) did not return the expected result",
        )

        self.node.use_services_alt = False
        self.node.consider_alumni = False
        self.info_mock.return_value = "10,3000,[[BB9050011AC4202,,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]"
        expected = [
            (("172.17.0.1", 3000, None),),
            (("2001:db8:85a3::8a2e", 6666, None),),
        ]

        peers_list = await self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-clear-std", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers) did not return the expected result",
        )

        self.info_mock.return_value = "10,4333,[[BB9050011AC4202,peers,[172.17.0.1]],[BB9070011AC4202,peers,[[2001:db8:85a3::8a2e]]]]"
        self.node.enable_tls = True
        expected = [
            (("172.17.0.1", 4333, "peers"),),
            (("2001:db8:85a3::8a2e", 4333, "peers"),),
        ]

        peers_list = await self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-tls-std", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers with tls enabled) did not return the expected result",
        )

        self.node.enable_tls = False
        self.info_mock.return_value = "0,3000,[[BB9050011AC4202,,[172.17.0.2]]]"
        self.node.use_services_alt = True
        expected = [(("172.17.0.2", 3000, None),)]

        peers_list = await self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-clear-alt", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alt) did not return the expected result",
        )

        self.info_mock.return_value = (
            "0,4333,[[BB9050011AC4202,peers-alt,[172.17.0.2]]]"
        )
        self.node.enable_tls = True
        expected = [(("172.17.0.2", 4333, "peers-alt"),)]

        peers_list = await self.node.info_peers_list()

        self.info_mock.assert_called_with("peers-tls-alt", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alt with tls enabled) did not return the expected result",
        )

        self.info_mock.reset_mock()
        self.node.enable_tls = False
        self.info_mock.side_effect = [
            "0,3000,[[BB9050011AC4202,,[172.17.0.3]]]",
            "0,3000,[[BB9050011AC4202,,[172.17.0.2]]]",
        ]
        self.node.use_services_alt = True
        self.node.consider_alumni = True
        expected = [(("172.17.0.3", 3000, None),), (("172.17.0.2", 3000, None),)]

        peers_list = await self.node.info_peers_list()

        self.assertEqual(self.info_mock.call_count, 2)
        self.info_mock.assert_any_call("alumni-clear-alt", "192.1.1.1")
        self.info_mock.assert_any_call("peers-clear-alt", "192.1.1.1")

        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alumni) did not return the expected result",
        )

        self.info_mock.reset_mock()
        self.info_mock.side_effect = [
            "0,4333,[[BB9050011AC4202,peers-alumni,[172.17.0.3]]]",
            "0,4333,[[BB9050011AC4202,peers-alt,[172.17.0.2]]]",
        ]
        self.node.enable_tls = True
        expected = [
            (("172.17.0.3", 4333, "peers-alumni"),),
            (("172.17.0.2", 4333, "peers-alt"),),
        ]

        peers_list = await self.node.info_peers_list()

        self.assertEqual(self.info_mock.call_count, 2)
        self.info_mock.assert_any_call("alumni-tls-alt", "192.1.1.1")
        self.info_mock.assert_any_call("peers-tls-alt", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alumni with tls enabled) did not return the expected result",
        )

        self.node.enable_tls = False
        self.node.consider_alumni = False

        self.info_mock.reset_mock()
        self.node.enable_tls = False
        self.info_mock.side_effect = [
            "0,3000,[[BB9050011AC4202,,[172.17.0.3]]]",
            "0,3000,[[BB9050011AC4202,,[172.17.0.2]]]",
        ]
        self.node.use_services_alt = False
        self.node.consider_alumni = True
        expected = [(("172.17.0.3", 3000, None),), (("172.17.0.2", 3000, None),)]

        peers_list = await self.node.info_peers_list()

        self.assertEqual(self.info_mock.call_count, 2)
        self.info_mock.assert_any_call("alumni-clear-std", "192.1.1.1")
        self.info_mock.assert_any_call("peers-clear-std", "192.1.1.1")

        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alumni with use_services_alt=False) did not return the expected result",
        )

    async def test_info_peers_admin_node_returns_empty_list(self):
        """
        Ensure that admin nodes always return empty lists for peer-related methods
        """
        # Mark node as admin node
        self.node.is_admin_node = True

        # Test info_peers returns empty list for admin node
        peers = await self.node.info_peers()
        self.assertEqual(peers, [], "Admin node info_peers should return empty list")

        # Test info_peers_alumni returns empty list for admin node
        alumni = await self.node.info_peers_alumni()
        self.assertEqual(
            alumni, [], "Admin node info_peers_alumni should return empty list"
        )

        # Test info_peers_alt returns empty list for admin node
        alt_peers = await self.node.info_peers_alt()
        self.assertEqual(
            alt_peers, [], "Admin node info_peers_alt should return empty list"
        )

        # Test info_peers_list returns empty list for admin node
        peers_list = await self.node.info_peers_list()
        self.assertEqual(
            peers_list, [], "Admin node info_peers_list should return empty list"
        )

        # Verify no info calls were made (peer discovery disabled)
        self.info_mock.assert_not_called()

    def test_is_admin_port_enabled(self):
        """
        Test the _is_admin_port_enabled method with various response types
        """
        # Test with admin=true in info response format
        self.assertTrue(self.node._is_admin_port_enabled("admin=true"))

        # Test with admin=false in info response format
        self.assertFalse(self.node._is_admin_port_enabled("admin=false"))

        # Test with admin=TRUE (case sensitive, should work)
        self.assertFalse(self.node._is_admin_port_enabled("admin=TRUE"))

        # Test with no admin key in response (should default to false)
        self.assertFalse(self.node._is_admin_port_enabled("other=value"))

        # Test with empty string (should be False)
        self.assertFalse(self.node._is_admin_port_enabled(""))

        # Test with None (should be False)
        self.assertFalse(self.node._is_admin_port_enabled(None))

        # Test with Exception (should be False)
        self.assertFalse(self.node._is_admin_port_enabled(Exception("test error")))

        # Test with malformed response (should be False)
        self.assertFalse(self.node._is_admin_port_enabled("malformed"))

        # Test with multiple key-value pairs including admin=true
        self.assertTrue(
            self.node._is_admin_port_enabled("version=1.0;admin=true;port=3000")
        )

        # Test with multiple key-value pairs including admin=false
        self.assertFalse(
            self.node._is_admin_port_enabled("version=1.0;admin=false;port=3000")
        )

    async def test_info_service_list(self):
        self.info_mock.return_value = "172.17.0.1:3000,172.17.1.1:3000"
        expected = [("172.17.0.1", 3000, None), ("172.17.1.1", 3000, None)]

        service_list = await self.node.info_service_list()

        self.info_mock.assert_called_with("service-clear-std", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service-clear) did not return the expected result",
        )

        self.info_mock.return_value = "172.17.0.1:4333,172.17.1.1:4333"
        self.node.enable_tls = True
        expected = [("172.17.0.1", 4333, None), ("172.17.1.1", 4333, None)]

        service_list = await self.node.info_service_list()

        self.info_mock.assert_called_with("service-tls-std", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service-tls) did not return the expected result",
        )

        self.node.enable_tls = False
        self.info_mock.return_value = "172.17.0.2:3000,172.17.1.2:3000"
        self.node.use_services_alt = True
        expected = [("172.17.0.2", 3000, None), ("172.17.1.2", 3000, None)]

        service_list = await self.node.info_service_list()

        self.info_mock.assert_called_with("service-clear-alt", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service-clear-alt) did not return the expected result",
        )

        self.node.enable_tls = True
        self.info_mock.return_value = "172.17.0.2:4333,172.17.1.2:4333"
        expected = [("172.17.0.2", 4333, None), ("172.17.1.2", 4333, None)]

        service_list = await self.node.info_service_list()

        self.info_mock.assert_called_with("service-tls-alt", "192.1.1.1")
        self.assertEqual(
            sorted(service_list),
            sorted(expected),
            "info_service_list(service-tls-alt) did not return the expected result",
        )

        self.node.enable_tls = False
        self.node.use_services_alt = False

    async def test_info_statistics(self):
        self.info_mock.return_value = "cs=2;ck=71;ci=false;o=5"
        expected = {"cs": "2", "ck": "71", "ci": "false", "o": "5"}

        stats = await self.node.info_statistics()

        self.info_mock.assert_called_with("statistics", self.ip)
        self.assertEqual(
            stats,
            expected,
            "info_statistics error:\n_expected:\t%s\n_found:\t%s" % (expected, stats),
        )

    async def test_info_namespaces(self):
        self.info_mock.return_value = "test;bar"
        expected = ["test", "bar"]

        namespaces = await self.node.info_namespaces()

        self.info_mock.assert_called_with("namespaces", self.ip)
        self.assertEqual(
            namespaces,
            expected,
            "info_namespaces error:\n_expected:\t%s\n_found:\t%s"
            % (expected, namespaces),
        )

    async def test_info_node(self):
        self.info_mock.return_value = "BB96DDF04CA0568"
        expected = "BB96DDF04CA0568"

        node = await self.node.info_node()

        self.info_mock.assert_called_with("node", self.ip)
        self.assertEqual(
            node,
            expected,
            "info_node error:\n_expected:\t%s\n_found:\t%s" % (expected, node),
        )

    async def test_info_namespace_statistics(self):
        self.info_mock.return_value = "asdf=1;b=b;c=!@#$%^&*()"
        expected = {"asdf": "1", "b": "b", "c": "!@#$%^&*()"}

        stats = await self.node.info_namespace_statistics("test")

        self.info_mock.assert_called_with("namespace/test", self.ip)
        self.assertEqual(
            stats,
            expected,
            "info_namespace_statistics error:\n_expected:\t%s\n_found:\t%s"
            % (expected, stats),
        )

    async def test_info_all_namespace_statistics(self):
        self.info_mock.side_effect = [
            "foo;bar",
            "asdf=1;b=b;c=!@#$%^&*()",
            "cdef=2;c=c;d=)(*&^%$#@!",
        ]
        expected = {
            "foo": {"asdf": "1", "b": "b", "c": "!@#$%^&*()"},
            "bar": {"cdef": "2", "c": "c", "d": ")(*&^%$#@!"},
        }

        actual = await self.node.info_all_namespace_statistics()

        self.assertEqual(self.info_mock.call_count, 3)
        self.info_mock.assert_any_call("namespaces", self.ip)
        self.info_mock.assert_any_call("namespace/foo", self.ip)
        self.info_mock.assert_any_call("namespace/bar", self.ip)
        self.assertEqual(actual, expected)

    async def info_all_namespace_statistics(self):
        self.info_mock.return_value = (
            "ns=test:set=jar-set:objects=1:tombstones=2:"
            "memory_data_bytes=3:device_data_bytes=4:truncate_lut=5:"
            "stop-writes-count=6:disable-eviction=false;ns=test:set=testset:"
            "objects=7:tombstones=8:memory_data_bytes=9:"
            "device_data_bytes=10:truncate_lut=11:stop-writes-count=12:"
            "disable-eviction=true;"
        )
        expected = {
            ("test", "jar-set"): {
                "object": "1",
                "tombstones": "2",
                "memory_data_bytes": "3",
                "device_data_bytes": "4",
                "truncate_lut": "5",
                "stop-writes-count": "6",
                "disable-eviction": "false",
            },
            ("test", "testset"): {
                "object": "7",
                "tombstones": "8",
                "memory_data_bytes": "9",
                "device_data_bytes": "10",
                "truncate_lut": "11",
                "stop-writes-count": "12",
                "disable-eviction": "true",
            },
        }

        actual = await self.node.info_all_set_statistics()

        self.info_mock.assert_called_with("sets")
        self.assertDictEqual(actual, expected)

    async def test_info_health_outliers(self):
        self.info_mock.return_value = (
            "id=bb9040011ac4202:confidence_pct=100:"
            "reason=fabric_connections_opened;id=bb9040011ac4203:"
            "confidence_pct=100:reason=proxies;id=bb9040011ac4204:"
            "confidence_pct=100:reason=node_arrivals"
        )
        expected = {
            "outlier0": {
                "id": "bb9040011ac4202",
                "confidence_pct": "100",
                "reason": "fabric_connections_opened",
            },
            "outlier1": {
                "id": "bb9040011ac4203",
                "confidence_pct": "100",
                "reason": "proxies",
            },
            "outlier2": {
                "id": "bb9040011ac4204",
                "confidence_pct": "100",
                "reason": "node_arrivals",
            },
        }

        actual = await self.node.info_health_outliers()

        self.info_mock.assert_called_with("health-outliers", self.ip)
        self.assertDictEqual(actual, expected)

    async def test_info_best_practices(self):
        self.info_mock.return_value = "failed_best_practices=none"
        expected = []

        actual = await self.node.info_best_practices()

        self.info_mock.assert_called_with("best-practices", self.ip)
        self.assertListEqual(actual, expected)

        self.info_mock.return_value = "failed_best_practices=foo,bar,jar"
        expected = ["foo", "bar", "jar"]

        actual = await self.node.info_best_practices()

        self.info_mock.assert_called_with("best-practices", self.ip)
        self.assertListEqual(actual, expected)

    async def test_info_bin_statistics_pre_7_0(self):
        """Test info_bin_statistics with server version < 7.0 - should call bins command"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.4.0.1"
        self.info_mock.return_value = (
            "test:bin_names=1,bin_names_quota=2,3,name,"
            "age;bar:bin_names=5,bin_names_quota=6,age;"
        )
        expected = {
            "test": {
                "bin_names": "1",
                "bin_names_quota": "2",
            },
            "bar": {
                "bin_names": "5",
                "bin_names_quota": "6",
            },
        }

        actual = await self.node.info_bin_statistics()

        self.info_mock.assert_called_with("bins", self.ip)
        self.assertDictEqual(actual, expected)

    async def test_info_bin_statistics_7_0_exact(self):
        """Test info_bin_statistics with server version exactly 7.0 - should return empty dict"""
        lib.live_cluster.client.node.Node.info_build.return_value = "7.0.0"

        actual = await self.node.info_bin_statistics()

        # Verify bins command was NOT called
        self.info_mock.assert_not_called()
        # Verify empty dict returned
        self.assertDictEqual(actual, {})

    async def test_info_bin_statistics_post_7_0(self):
        """Test info_bin_statistics with server version > 7.0 - should return empty dict"""
        lib.live_cluster.client.node.Node.info_build.return_value = "8.1.0.5"

        actual = await self.node.info_bin_statistics()

        # Verify bins command was NOT called
        self.info_mock.assert_not_called()
        # Verify empty dict returned
        self.assertDictEqual(actual, {})

    async def test_info_bin_statistics_info_build_exception(self):
        """Test info_bin_statistics when info_build() returns an exception"""
        expected_exception = Exception("Network error")
        lib.live_cluster.client.node.Node.info_build.return_value = expected_exception

        actual = await self.node.info_bin_statistics()

        # Verify the exception is returned
        self.assertEqual(actual, expected_exception)
        # Verify bins command was NOT called
        self.info_mock.assert_not_called()
        # Verify logger.error was called
        self.logger_mock.error.assert_called_once_with(expected_exception)

    async def test_info_bin_statistics_various_pre_7_0_versions(self):
        """Test info_bin_statistics with various server versions < 7.0"""
        test_versions = ["6.9.9", "6.4.0.1", "5.7.0.8", "4.9.0.1"]

        for version in test_versions:
            with self.subTest(version=version):
                # Reset mocks for each iteration
                self.info_mock.reset_mock()
                lib.live_cluster.client.node.Node.info_build.return_value = version
                self.info_mock.return_value = "test:bin_names=1;"

                actual = await self.node.info_bin_statistics()

                # Verify bins command was called
                self.info_mock.assert_called_with("bins", self.ip)
                # Verify result is processed (not empty)
                self.assertIsInstance(actual, dict)

    async def test_info_bin_statistics_various_post_7_0_versions(self):
        """Test info_bin_statistics with various server versions >= 7.0"""
        test_versions = ["7.0.0", "7.1.0", "8.0.0", "9.5.2.1"]

        for version in test_versions:
            with self.subTest(version=version):
                # Reset mocks for each iteration
                self.info_mock.reset_mock()
                lib.live_cluster.client.node.Node.info_build.return_value = version

                actual = await self.node.info_bin_statistics()

                # Verify bins command was NOT called
                self.info_mock.assert_not_called()
                # Verify empty dict returned
                self.assertDictEqual(actual, {})

    async def test_info_bin_statistics_empty_response_pre_7_0(self):
        """Test info_bin_statistics with empty response for pre-7.0 versions"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.4.0.1"
        self.info_mock.return_value = ""

        actual = await self.node.info_bin_statistics()

        self.info_mock.assert_called_with("bins", self.ip)
        self.assertDictEqual(actual, {})

    def test_server_bins_removed_version_constant(self):
        """Test that SERVER_INFO_BINS_REMOVAL_VERSION constant is properly defined"""
        self.assertEqual(constants.SERVER_INFO_BINS_REMOVAL_VERSION, "7.0")

    async def test_info_jobs_pre_6_3(self):
        """Test info_jobs with server version < 6.3 - should call jobs command"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.2.0"
        self.info_mock.return_value = "trid=123:module=scan;trid=456:module=query;"

        actual = await self.node.info_jobs("scan")

        self.info_mock.assert_called_with("jobs:module=scan", self.ip)
        self.assertIsInstance(actual, dict)

    async def test_info_jobs_6_3_and_later(self):
        """Test info_jobs with server version >= 6.3 - should return empty dict"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.3.0"

        actual = await self.node.info_jobs("scan")

        self.info_mock.assert_not_called()
        self.assertDictEqual(actual, {})

    async def test_info_scan_show_pre_6_3(self):
        """Test info_scan_show with server version < 6.3 - should use jobs command"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.2.0"
        self.info_mock.return_value = "trid=123:module=scan;"

        actual = await self.node.info_scan_show()

        self.info_mock.assert_called_with("jobs:module=scan", self.ip)
        self.assertIsInstance(actual, dict)

    async def test_info_scan_show_6_3_to_6_3(self):
        """Test info_scan_show with server version 6.3 - should use scan-show command"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.3.0"
        self.info_mock.return_value = "trid=123:status=running;"

        actual = await self.node.info_scan_show()

        self.info_mock.assert_called_with("scan-show", self.ip)
        self.assertIsInstance(actual, dict)

    async def test_info_scan_show_6_4_and_later(self):
        """Test info_scan_show with server version >= 6.4 - should return empty dict"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.4.0"

        actual = await self.node.info_scan_show()

        self.info_mock.assert_not_called()
        self.assertDictEqual(actual, {})

    async def test_info_query_show_pre_6_3(self):
        """Test info_query_show with server version < 6.3 - should use jobs command"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.2.0"
        self.info_mock.return_value = "trid=123:module=query;"

        actual = await self.node.info_query_show()

        self.info_mock.assert_called_with("jobs:module=query", self.ip)
        self.assertIsInstance(actual, dict)

    async def test_info_query_show_6_3_and_later(self):
        """Test info_query_show with server version >= 6.3 - should use query-show command"""
        lib.live_cluster.client.node.Node.info_build.return_value = "6.3.0"
        self.info_mock.return_value = "trid=123:status=running;"

        actual = await self.node.info_query_show()

        self.info_mock.assert_called_with("query-show", self.ip)
        self.assertIsInstance(actual, dict)

    async def test_info_jobs_info_build_exception(self):
        """Test info_jobs when info_build() returns an exception"""
        expected_exception = Exception("Network error")
        lib.live_cluster.client.node.Node.info_build.return_value = expected_exception

        actual = await self.node.info_jobs("scan")

        self.assertEqual(actual, expected_exception)
        self.info_mock.assert_not_called()

    def test_jobs_version_constants(self):
        """Test that job-related version constants are properly defined"""
        self.assertEqual(constants.SERVER_JOBS_REMOVAL_VERSION, "6.3")
        self.assertEqual(constants.SERVER_SCAN_SHOW_REMOVAL_VERSION, "6.4")

    async def test_info_XDR_statistics_with_server_pre_xdr5(self):
        self.info_mock.reset_mock()
        lib.live_cluster.client.node.Node.info_build.return_value = "2.5.6"
        self.info_mock.side_effect = ["a=b;c=1;2=z"]
        expected = {"a": "b", "c": "1", "2": "z"}

        actual = await self.node.info_XDR_statistics()

        self.assertEqual(self.info_mock.call_count, 1)
        self.info_mock.assert_any_call("statistics/xdr", self.ip)
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_all_dc_statistics")
    async def test_info_XDR_statistics_xdr5(self, info_all_dc_statistics_mock):
        lib.live_cluster.client.node.Node.info_build.return_value = "5.0.0.1"
        actual = await self.node.info_XDR_statistics()

        lib.live_cluster.client.node.Node.info_build.assert_called_once()
        self.assertEqual(actual, {})

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    async def test_info_set_config_xdr_create_dc_success(self, info_dcs_mock):
        info_dcs_mock.return_value = ["DC2", "DC3"]
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_create_dc("DC1")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;action=create", self.ip
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build.return_value = "4.9"
        info_dcs_mock.return_value = ["DC2", "DC3"]
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_create_dc("DC1")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;action=create", self.ip
        )
        self.assertEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    async def test_info_set_config_xdr_create_dc_fail(self, info_dcs_mock):
        info_dcs_mock.return_value = ["DC1", "DC2", "DC3"]

        actual = await self.node.info_set_config_xdr_create_dc("DC1")

        self.assertEqual(
            str(actual), "Failed to create XDR datacenter : DC already exists."
        )

        info_dcs_mock.return_value = ["DC2", "DC3"]
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_xdr_create_dc("DC1")

        self.assertEqual(
            str(actual), "Failed to create XDR datacenter : Unknown error occurred."
        )

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    async def test_info_set_config_xdr_delete_dc_success(self, info_dcs_mock):
        info_dcs_mock.return_value = ["DC1", "DC2"]
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_delete_dc("DC1")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;action=delete", self.ip
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build.return_value = "4.9"
        info_dcs_mock.return_value = ["DC1", "DC2"]
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_delete_dc("DC1")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;action=delete", self.ip
        )
        self.assertEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    async def test_info_set_config_xdr_delete_dc_fail(self, info_dcs_mock):
        info_dcs_mock.return_value = ["DC2", "DC3"]

        actual = await self.node.info_set_config_xdr_delete_dc("DC1")

        self.assertEqual(actual.message, "Failed to delete XDR datacenter")
        self.assertEqual(actual.response, "DC does not exist")

        info_dcs_mock.return_value = ["DC1", "DC2", "DC3"]
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_xdr_delete_dc("DC1")

        self.assertEqual(actual.message, "Failed to delete XDR datacenter")
        self.assertEqual(actual.response, "Unknown error occurred")

    async def test_info_set_config_xdr_add_namespace_success(self):
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_add_namespace("DC1", "ns")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;namespace=ns;action=add", self.ip
        )
        self.assertEqual(actual, expected)

        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_xdr_add_namespace(
            "DC1", "ns", rewind="12345"
        )

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;namespace=ns;action=add;rewind=12345",
            self.ip,
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build.return_value = "4.3.5.8"
        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_xdr_add_namespace(
            "DC1", "ns", rewind="12345"
        )

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;namespace=ns;action=add;rewind=12345",
            self.ip,
        )
        self.assertEqual(actual, expected)

    async def test_info_set_config_xdr_add_namespace_fail(self):
        actual = await self.node.info_set_config_xdr_add_namespace(
            "DC1", "ns", rewind="123aaa456"
        )

        self.assertEqual(actual.message, "Failed to add namespace to XDR datacenter")
        self.assertEqual(actual.response, 'Invalid rewind. Must be int or "all"')

        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_xdr_add_namespace(
            "DC1", "ns", rewind="all"
        )

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;namespace=ns;action=add;rewind=all",
            self.ip,
        )
        self.assertEqual(actual.message, "Failed to add namespace to XDR datacenter")
        self.assertEqual(actual.response, "Unknown error occurred")

    async def test_info_set_config_xdr_remove_namespace_success(self):
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_remove_namespace("DC1", "ns")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;namespace=ns;action=remove", self.ip
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build.return_value = "2.1.1.1"
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_remove_namespace("DC1", "ns")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;namespace=ns;action=remove", self.ip
        )
        self.assertEqual(actual, expected)

    async def test_info_set_config_xdr_remove_namespace_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_xdr_remove_namespace("DC1", "ns")

        self.assertEqual(
            actual.message, "Failed to remove namespace from XDR datacenter"
        )
        self.assertEqual(actual.response, "Unknown error occurred")

    async def test_info_set_config_xdr_add_node_success(self):
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_add_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;node-address-port=3.3.3.3:8000;action=add",
            self.ip,
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build.return_value = "4.5.6.9"
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_add_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;node-address-port=3.3.3.3:8000;action=add",
            self.ip,
        )
        self.assertEqual(actual, expected)

    async def test_info_set_config_xdr_add_node_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_xdr_add_node("DC1", "3.3.3.3:8000")

        self.assertEqual(actual.message, "Failed to add node to XDR datacenter")
        self.assertEqual(actual.response, "Unknown error occurred")

    async def test_info_set_config_xdr_remove_node_success(self):
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_remove_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;node-address-port=3.3.3.3:8000;action=remove",
            self.ip,
        )
        self.assertEqual(actual, expected)

        lib.live_cluster.client.node.Node.info_build.return_value = "4.9.9.9"
        self.info_mock.return_value = "ok"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_set_config_xdr_remove_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;datacenter=DC1;node-address-port=3.3.3.3:8000;action=remove",
            self.ip,
        )
        self.assertEqual(actual, expected)

    async def test_info_set_config_xdr_remove_node_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_xdr_remove_node("DC1", "3.3.3.3:8000")

        self.info_mock.assert_called_with(
            "set-config:context=xdr;dc=DC1;node-address-port=3.3.3.3:8000;action=remove",
            self.ip,
        )
        self.assertEqual(actual.message, "Failed to remove node from XDR datacenter")
        self.assertEqual(actual.response, "Unknown error occurred")

    async def test_info_set_config_xdr_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_xdr(
            "foo", "bar", dc="DC1", namespace="NS"
        )

        self.info_mock.assert_called_with(
            "set-config:context=xdr;foo=bar;dc=DC1;namespace=NS", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        lib.live_cluster.client.node.Node.info_build.return_value = "3.9"
        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_xdr(
            "foo", "bar", dc="DC1", namespace="NS"
        )

        self.info_mock.assert_called_with(
            "set-config:context=xdr;foo=bar;datacenter=DC1;namespace=NS", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_set_config_xdr_fail(self):
        actual = await self.node.info_set_config_xdr("foo", "bar", namespace="NS")

        self.assertIsInstance(actual, ArgumentError)
        self.assertEqual(str(actual), "Namespace must be accompanied by a dc.")

        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_xdr(
            "foo", "bar", dc="DC1", namespace="NS"
        )

        self.info_mock.assert_has_calls(
            [call("set-config:context=xdr;foo=bar;dc=DC1;namespace=NS", self.ip)]  # type: ignore
        )
        self.assertEqual(
            actual.message, "Failed to set XDR configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "DC does not exist")

    async def test_info_logs_ids(self):
        self.info_mock.return_value = "0:path0;1:path1;2:path2"
        expected = {"path0": "0", "path1": "1", "path2": "2"}

        actual = await self.node.info_logs_ids()

        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_logs_ids")
    async def test_info_logging_config(self, info_logs_mock):
        info_logs_mock.return_value = {"path0": "0", "path1": "1"}
        self.info_mock.side_effect = [
            "misc:INFO;alloc:WARNING;arenax:INFO;hardware:WARNING",
            "misc:WARNING;alloc:INFO;arenax:WARNING;hardware:INFO",
        ]
        expected = {
            "path0": {
                "misc": "INFO",
                "alloc": "WARNING",
                "arenax": "INFO",
                "hardware": "WARNING",
            },
            "path1": {
                "misc": "WARNING",
                "alloc": "INFO",
                "arenax": "WARNING",
                "hardware": "INFO",
            },
        }

        actual = await self.node.info_logging_config()

        info_logs_mock.assert_called_once()
        self.info_mock.assert_has_calls(
            [
                call("log/0", self.ip),
                call("log/1", self.ip),
            ]  # type: ignore
        )
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_logs_ids")
    async def test_info_set_config_logging_success(self, info_logs_mock):
        info_logs_mock.return_value = {"path0": "0", "path1": "1", "path2": "2"}
        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_logging("path1", "foo", "bar")

        self.info_mock.assert_called_with("log-set:id=1;foo=bar", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    @patch("lib.live_cluster.client.node.Node.info_logs_ids")
    async def test_info_set_config_logging_fail(self, info_logs_mock):
        info_logs_mock.return_value = {"path0": "0", "path1": "1", "path2": "2"}

        actual = await self.node.info_set_config_logging("path-DNE", "foo", "bar")

        self.assertIsInstance(actual, ASInfoResponseError)
        self.assertEqual(
            actual.message, "Failed to set logging configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "path-DNE does not exist")

        info_logs_mock.return_value = {"path0": "0", "path1": "1", "path2": "2"}
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_logging("path2", "foo", "bar")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set logging configuration parameter foo to bar"
        )

        self.assertEqual(actual.response, "Invalid subcontext logging")

    async def test_info_set_config_service_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_service("foo", "bar")

        self.info_mock.assert_called_with("set-config:context=service;foo=bar", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_set_config_service_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_service("foo", "bar")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set service configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "Invalid subcontext service")

    async def test_info_set_config_namespace_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_namespace("foo", "bar", "buff")

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_namespace(
            "foo", "bar", "buff", set_="test-set"
        )

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;foo=bar;set=test-set", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_namespace(
            "foo", "bar", "buff", subcontext="storage-engine"
        )

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_namespace(
            "foo", "bar", "buff", subcontext="geo2dsphere-within"
        )

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;geo2dsphere-within-foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        actual = await self.node.info_set_config_namespace(
            "mounts-size-limit", "50", "buff", subcontext="index-type"
        )

        self.info_mock.assert_called_with(
            "set-config:context=namespace;id=buff;mounts-size-limit=50", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_set_config_namespace_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_namespace("foo", "bar", "buff")

        self.assertIsInstance(actual, ASInfoResponseError)
        self.assertEqual(actual.message, "Failed to get namespaces")
        self.assertEqual(
            actual.response, "Unknown error occurred"
        )  # preserve the original error message

    async def test_info_set_config_network_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_network("foo", "bar", "sub-context")

        self.info_mock.assert_called_with(
            "set-config:context=network;sub-context.foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_set_config_network_fail(self):
        self.info_mock.return_value = "error"
        self.node.conf_schema_handler.get_subcontext.side_effect = [
            ["network"],
            ["not-sub"],
        ]

        actual = await self.node.info_set_config_network("foo", "bar", "sub")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set network configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "Invalid subcontext sub")

    async def test_info_set_config_security_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_security(
            "foo", "bar", subcontext="sub-context"
        )

        self.info_mock.assert_called_with(
            "set-config:context=security;sub-context.foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "ok"

        actual = await self.node.info_set_config_security("foo", "bar")

        self.info_mock.assert_called_with(
            "set-config:context=security;foo=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_set_config_security_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_set_config_security("foo", "bar", "sub")

        self.assertIsInstance(actual, ASInfoConfigError)
        self.assertEqual(
            actual.message, "Failed to set security configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "Invalid subcontext security")

    async def test_info_get_config_service(self):
        # todo call getconfig with various formats
        self.info_mock.return_value = "asdf=1;b=b;c=!@#$%^&*()"
        expected = {"asdf": "1", "b": "b", "c": "!@#$%^&*()"}

        config = await self.node.info_get_config("service")

        self.info_mock.assert_called_with("get-config:context=service", self.ip)
        self.assertEqual(
            config,
            expected,
            "info_namespace_statistics error:\n_expected:\t%s\n_found:\t%s"
            % (expected, config),
        )

    async def test_info_get_config_namespace_single(self):
        self.info_mock.side_effect = [
            "a=false;b=10000",
        ]
        expected = {"test": {"a": "false", "b": "10000"}}

        actual = await self.node.info_get_config("namespace", "test")
        self.info_mock.assert_called_with(
            "get-config:context=namespace;id=test", self.ip
        )
        self.assertDictEqual(expected, actual)

    @patch("lib.live_cluster.client.node.Node.info_namespaces")
    async def test_info_get_config_namespace_all(self, info_namespaces_mock: AsyncMock):
        self.info_mock.side_effect = [
            "a=false;b=10000",
            "c=true;d=10000",
        ]
        info_namespaces_mock.return_value = ["test", "bar"]
        expected = {
            "test": {"a": "false", "b": "10000"},
            "bar": {"c": "true", "b": "10000"},
        }

        await self.node.info_get_config("namespace")

        self.info_mock.assert_has_calls(
            [
                call("get-config:context=namespace;id=test", self.ip),
                call("get-config:context=namespace;id=bar", self.ip),
            ]  # type: ignore
        )

    async def test_info_get_config_xdr(self):
        def side_effect(req, ip):
            if req == "get-config:context=xdr":
                return "dcs=DC1,DC2;src-id=0;trace-sample=0"
            else:
                raise Exception("Unexpected info call: " + req)

        self.info_mock.side_effect = side_effect
        expected = {"dcs": "DC1,DC2", "src-id": "0", "trace-sample": "0"}

        actual = await self.node.info_get_config("xdr")

        self.info_mock.assert_any_call("get-config:context=xdr", self.ip)
        self.assertDictEqual(actual, expected)

    @patch("lib.utils.conf_parser.parse_file")
    async def test_info_get_originalconfig(self, parse_file_mock):
        self.assertDictEqual(await self.node.info_get_originalconfig(), {})

        self.node.localhost = True
        parse_file_mock.return_value = {
            "namespace": {
                "foo": {
                    "service": "config_data_1",
                },
                "bar": {
                    "service": "config_data_2",
                },
                "tar": {
                    "service": "config_data_3",
                },
            }
        }
        expected = {
            "foo": "config_data_1",
            "bar": "config_data_2",
            "tar": "config_data_3",
        }

        actual = await self.node.info_get_originalconfig("namespace")

        self.assertDictEqual(actual, expected)

        parse_file_mock.return_value = {
            "namespace": {
                "foo": {
                    "service": "config_data_1",
                },
                "bar": {
                    "service": "config_data_2",
                },
                "tar": {
                    "service": "config_data_3",
                },
            }
        }

        self.assertDictEqual(
            {}, await self.node.info_get_originalconfig(stanza="does-not-exist")
        )

    async def test_info_latency(self):
        self.info_mock.return_value = (
            "{ns}-read:23:53:38-GMT,ops/sec,>1ms,>8ms,>64ms;23:53:48,5234.4,0.54,0.02,0.00;"
            "{ns}-write:23:53:38-GMT,ops/sec,>1ms,>8ms,>64ms;"
            "23:53:48,354.7,2.34,0.77,0.00;error-no-data-yet-or-back-too-small;"
            "error-no-data-yet-or-back-too-small"
        )
        expected = {
            "read": {
                "total": {
                    "values": [["23:53:38->23:53:48", 5234.4, 0.54, 0.02, 0.0]],
                    "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                },
                "namespace": {
                    "ns": {
                        "values": [["23:53:38->23:53:48", 5234.4, 0.54, 0.02, 0.0]],
                        "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                    }
                },
            },
            "write": {
                "total": {
                    "values": [["23:53:38->23:53:48", 354.7, 2.34, 0.77, 0.0]],
                    "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                },
                "namespace": {
                    "ns": {
                        "values": [["23:53:38->23:53:48", 354.7, 2.34, 0.77, 0.0]],
                        "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                    }
                },
            },
        }

        latency_data = await self.node.info_latency()

        self.assertDictEqual(
            latency_data, expected, "info_latency did not return the expected result"
        )
        self.info_mock.assert_called_with("latency:", self.ip)

    async def test_info_latency_with_args(self):
        self.info_mock.return_value = (
            "{ns}-read:23:50:28-GMT,ops/sec,>1ms,>8ms,>64ms;23:50:58,0.0,0.00,0.00,0.00;"
            "23:51:28,0.0,0.00,0.00,0.00;23:51:58,0.0,0.00,0.00,0.00;"
            "23:52:28,0.0,0.00,0.00,0.00;3:52:58,0.0,0.00,0.00,0.00;"
            "23:53:28,0.0,0.00,0.00,0.00;23:53:58,0.0,0.00,0.00,0.00;"
            "23:54:28,0.0,0.00,0.00,0.00;23:54:58,0.0,0.00,0.00,0.00"
        )
        expected = {
            "read": {
                "total": {
                    "values": [
                        ["23:50:28->23:50:58", 0.0, 0.0, 0.0, 0.0],
                        ["23:50:58->23:51:28", 0.0, 0.0, 0.0, 0.0],
                        ["23:51:28->23:51:58", 0.0, 0.0, 0.0, 0.0],
                        ["23:51:58->23:52:28", 0.0, 0.0, 0.0, 0.0],
                        ["23:52:28->3:52:58", 0.0, 0.0, 0.0, 0.0],
                        ["3:52:58->23:53:28", 0.0, 0.0, 0.0, 0.0],
                        ["23:53:28->23:53:58", 0.0, 0.0, 0.0, 0.0],
                        ["23:53:58->23:54:28", 0.0, 0.0, 0.0, 0.0],
                        ["23:54:28->23:54:58", 0.0, 0.0, 0.0, 0.0],
                    ],
                    "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                },
                "namespace": {
                    "ns": {
                        "values": [
                            ["23:50:28->23:50:58", 0.0, 0.0, 0.0, 0.0],
                            ["23:50:58->23:51:28", 0.0, 0.0, 0.0, 0.0],
                            ["23:51:28->23:51:58", 0.0, 0.0, 0.0, 0.0],
                            ["23:51:58->23:52:28", 0.0, 0.0, 0.0, 0.0],
                            ["23:52:28->3:52:58", 0.0, 0.0, 0.0, 0.0],
                            ["3:52:58->23:53:28", 0.0, 0.0, 0.0, 0.0],
                            ["23:53:28->23:53:58", 0.0, 0.0, 0.0, 0.0],
                            ["23:53:58->23:54:28", 0.0, 0.0, 0.0, 0.0],
                            ["23:54:28->23:54:58", 0.0, 0.0, 0.0, 0.0],
                        ],
                        "columns": ["Time Span", "ops/sec", ">1ms", ">8ms", ">64ms"],
                    }
                },
            }
        }

        latency_actual = await self.node.info_latency(
            back=300, duration=120, slice_tm=30
        )

        self.assertDictEqual(
            latency_actual,
            expected,
            "info_latency with args did not return the expected result",
        )
        self.info_mock.assert_called_with(
            "latency:back=300;duration=120;slice=30;", self.ip
        )

    async def test_info_latencies_default(self):
        raw = """
        batch-index:;{test}-read:msec,1.0,2.00,3.00,4.00,5.00,6.00,7.00,8.00,
        9.00,10.00,11.00,12.00,13.00,14.00,15.00,16.00,17.00,18.00;{test}-write:msec,
        19.0,20.00,21.00,22.00,23.00,24.00,25.00,26.00,27.00,28.00,29.00,30.00,31.00,32.00,
        33.00,34.00,35.00,36.00;{test}-udf:;{test}-query:;{bar}-read:msec,37.0,38.00,39.00,40.00,41.00,42.00,43.00,44.00,
        45.00,46.00,47.00,48.00,49.00,50.00,51.00,52.00,53.00,54.00;{bar}-write:msec,
        55.0,56.00,57.00,58.00,59.00,60.00,61.00,62.00,63.00,64.00,65.00,66.00,67.00,68.00,
        69.00,70.00,71.00,72.00;
        {bar}-udf:;{bar}-query:"
        """
        self.info_mock.return_value = raw
        expected = {
            "read": {
                "namespace": {
                    "test": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                        "values": [[1.0, 2.0, 5.0, 8.0]],
                    },
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                        "values": [[37.0, 38.0, 41.0, 44.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                    "values": [[38.0, 37.05, 40.05, 43.05]],
                },
            },
            "write": {
                "namespace": {
                    "test": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                        "values": [[19.0, 20.0, 23.0, 26.0]],
                    },
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                        "values": [[55.0, 56.0, 59.0, 62.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">8ms", ">64ms"],
                    "values": [[74.0, 46.76, 49.76, 52.76]],
                },
            },
        }

        result = await self.node.info_latencies()
        self.assertDictEqual(result, expected)
        self.info_mock.assert_called_with("latencies:", self.ip)

    async def test_info_latencies_e2_b4(self):
        raw = """
        batch-index:;{test}-read:msec,1.0,2.00,3.00,4.00,5.00,6.00,7.00,8.00,
        9.00,10.00,11.00,12.00,13.00,14.00,15.00,16.00,17.00,18.00;{test}-write:msec,
        19.0,20.00,21.00,22.00,23.00,24.00,25.00,26.00,27.00,28.00,29.00,30.00,31.00,32.00,
        33.00,34.00,35.00,36.00;{test}-udf:;{test}-query:;{bar}-read:msec,37.0,38.00,39.00,40.00,41.00,42.00,43.00,44.00,
        45.00,46.00,47.00,48.00,49.00,50.00,51.00,52.00,53.00,54.00;{bar}-write:msec,
        55.0,56.00,57.00,58.00,59.00,60.00,61.00,62.00,63.00,64.00,65.00,66.00,67.00,68.00,
        69.00,70.00,71.00,72.00;
        {bar}-udf:;{bar}-query:"
        """
        self.info_mock.return_value = raw
        expected = {
            "read": {
                "namespace": {
                    "test": {
                        "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                        "values": [[1.0, 2.0, 4.0, 6.0, 8.0]],
                    },
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                        "values": [[37.0, 38.0, 40.0, 42.0, 44.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                    "values": [[38.0, 37.05, 39.05, 41.05, 43.05]],
                },
            },
            "write": {
                "namespace": {
                    "test": {
                        "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                        "values": [[19.0, 20.0, 22.0, 24.0, 26.0]],
                    },
                    "bar": {
                        "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                        "values": [[55.0, 56.0, 58.0, 60.0, 62.0]],
                    },
                },
                "total": {
                    "columns": ["ops/sec", ">1ms", ">4ms", ">16ms", ">64ms"],
                    "values": [[74.0, 46.76, 48.76, 50.76, 52.76]],
                },
            },
        }

        result = await self.node.info_latencies(buckets=4, exponent_increment=2)
        self.assertDictEqual(result, expected)
        self.info_mock.assert_called_with("latencies:", self.ip)

    async def test_info_latencies_verbose(self):
        raw = ""
        self.info_mock.side_effect = [
            "test",
            raw,
            raw,
            raw,
            raw,
            raw,
            raw,
            raw,
            raw,
            raw,
        ]

        _ = await self.node.info_latencies(verbose=True)

        self.assertEqual(self.info_mock.call_count, 10)
        self.info_mock.assert_any_call("latencies:", self.ip)
        self.info_mock.assert_any_call("latencies:hist={test}-proxy", self.ip)
        self.info_mock.assert_any_call("latencies:hist=benchmarks-fabric", self.ip)
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmarks-ops-sub", self.ip
        )
        self.info_mock.assert_any_call("latencies:hist={test}-benchmarks-read", self.ip)
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmarks-write", self.ip
        )
        self.info_mock.assert_any_call("latencies:hist={test}-benchmarks-udf", self.ip)
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmarks-udf-sub", self.ip
        )
        self.info_mock.assert_any_call(
            "latencies:hist={test}-benchmarks-batch-sub", self.ip
        )

    async def test_info_dcs(self):
        self.info_mock.return_value = "a=b;c=d;e=f;dcs=DC1,DC2,DC3"
        expected = ["DC1", "DC2", "DC3"]

        actual = await self.node.info_dcs()

        self.info_mock.assert_called_with("get-config:context=xdr", self.ip)
        self.assertListEqual(actual, expected)

        self.info_mock.return_value = "a=b;c=d;e=f;dcs=DC1,DC2,DC3"

        actual = await self.node.info_dcs()

        self.info_mock.assert_called_with("get-config:context=xdr", self.ip)
        self.assertListEqual(actual, expected)

        self.info_mock.return_value = "DC3;DC4;DC5"
        expected = ["DC3", "DC4", "DC5"]
        lib.live_cluster.client.node.Node.info_build.return_value = "4.9"

        actual = await self.node.info_dcs()

        self.info_mock.assert_called_with("dcs", self.ip)
        self.assertListEqual(actual, expected)

    async def test_info_dc_statistics_xdr5(self):
        lib.live_cluster.client.node.Node.info_build.return_value = "5.0"
        expected = {"a": "b", "c": "d", "e": "f"}
        dc = "foo"
        self.info_mock.return_value = "a=b;c=d;e=f"

        actual = await self.node.info_dc_statistics(dc=dc)

        self.info_mock.assert_called_with(
            "get-stats:context=xdr;dc={}".format(dc), self.ip
        )
        self.assertDictEqual(actual, expected)

    async def test_info_dc_statistics_pre_xdr5(self):
        lib.live_cluster.client.node.Node.info_build.return_value = "4.9"
        expected = {"a": "b", "c": "d", "e": "f"}
        dc = "foo"
        self.info_mock.return_value = "a=b;c=d;e=f"

        actual = await self.node.info_dc_statistics(dc=dc)

        self.info_mock.assert_called_with("dc/{}".format(dc), self.ip)
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_dc_statistics")
    @patch("lib.live_cluster.client.node.Node.info_dcs")
    async def test_info_all_dc_statistics_xdr5(
        self, info_dcs_mock: AsyncMock, info_dc_statistics_mock: AsyncMock
    ):
        info_dc_statistics_mock.side_effect = [
            {"a": "b", "c": "d", "e": "f"},
            {"g": "h", "i": "j", "k": "l"},
        ]
        expected = {
            "dc1": {"a": "b", "c": "d", "e": "f"},
            "dc2": {"g": "h", "i": "j", "k": "l"},
        }
        info_dcs_mock.return_value = ["dc1", "dc2"]

        actual = await self.node.info_all_dc_statistics()

        info_dc_statistics_mock.assert_has_calls([call("dc1"), call("dc2")])

        self.assertDictEqual(actual, expected)

    async def test_info_all_dc_statistics_pre_xdr5(self):
        lib.live_cluster.client.node.Node.info_build.return_value = "4.9"
        expected = {"a": "b", "c": "d", "e": "f"}
        dc = "foo"
        self.info_mock.return_value = "a=b;c=d;e=f"

        actual = await self.node.info_dc_statistics(dc=dc)

        self.info_mock.assert_called_with("dc/{}".format(dc), self.ip)
        self.assertDictEqual(actual, expected)

    async def test_info_xdr_dc_namespaces_statistics(
        self,
    ):
        self.info_mock.side_effect = [
            "a=b;c=d",
            "e=f;g=h",
        ]
        expected = {
            "test": {"a": "b", "c": "d"},
            "bar": {"e": "f", "g": "h"},
        }

        actual = await self.node.info_xdr_dc_namespaces_statistics(
            "dc1", ["test", "bar"]
        )
        self.info_mock.assert_has_calls(
            [
                call("get-stats:context=xdr;dc=dc1;namespace=test", self.ip),
                call("get-stats:context=xdr;dc=dc1;namespace=bar", self.ip),
            ]  # type: ignore
        )
        self.assertDictEqual(expected, actual)

    async def test_info_all_xdr_namespaces_statistics_pre_xdr5(self):
        lib.live_cluster.client.node.Node.info_build.return_value = "4.9"

        actual = await self.node.info_all_xdr_namespaces_statistics()
        self.assertDictEqual(actual, {})

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    @patch("lib.live_cluster.client.node.Node.info_xdr_dcs_config")
    @patch("lib.live_cluster.client.node.Node.info_xdr_dc_namespaces_statistics")
    async def test_info_all_xdr_namespaces_statistics_xdr5(
        self,
        info_xdr_dc_namespaces_statistics_mock: AsyncMock,
        info_xdr_dcs_config_mock: AsyncMock,
        info_dcs_mock: AsyncMock,
    ):
        lib.live_cluster.client.node.Node.info_build.return_value = "5.0"
        info_dcs_mock.return_value = ["dc1", "dc2"]
        info_xdr_dcs_config_mock.side_effect = [
            {"dc1": {"namespaces": "test,bar"}},
            {"dc2": {"namespaces": "zip,zow"}},
        ]
        info_xdr_dc_namespaces_statistics_mock.side_effect = [
            {"test": {"a": "b"}},
            {"zip": {"c": "d"}},
        ]
        expected = {"dc1": {"test": {"a": "b"}}, "dc2": {"zip": {"c": "d"}}}

        actual = await self.node.info_all_xdr_namespaces_statistics(
            namespaces=["test", "zip"]
        )
        self.assertDictEqual(actual, expected)

    async def test_info_udf_list(self):
        self.info_mock.return_value = "filename=basic_udf.lua,hash=706c57cb29e027221560a3cb4b693573ada98bf2,type=LUA;"
        expected = {
            "basic_udf.lua": {
                "filename": "basic_udf.lua",
                "hash": "706c57cb29e027221560a3cb4b693573ada98bf2",
                "type": "LUA",
            }
        }

        udf_actual = await self.node.info_udf_list()

        self.assertEqual(
            udf_actual, expected, "info_udf_list did not return the expected result"
        )
        self.info_mock.assert_called_with("udf-list", self.ip)

    async def test_info_udf_put_success(self):
        self.info_mock.return_value = ""
        udf_file_name = "test.lua"
        udf_str = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum"
        udf_type = "LUA"
        b64content = "TG9yZW0gSXBzdW0gaXMgc2ltcGx5IGR1bW15IHRleHQgb2YgdGhlIHByaW50aW5nIGFuZCB0eXBlc2V0dGluZyBpbmR1c3RyeS4gTG9yZW0gSXBzdW0gaGFzIGJlZW4gdGhlIGluZHVzdHJ5J3Mgc3RhbmRhcmQgZHVtbXkgdGV4dCBldmVyIHNpbmNlIHRoZSAxNTAwcywgd2hlbiBhbiB1bmtub3duIHByaW50ZXIgdG9vayBhIGdhbGxleSBvZiB0eXBlIGFuZCBzY3JhbWJsZWQgaXQgdG8gbWFrZSBhIHR5cGUgc3BlY2ltZW4gYm9vay4gSXQgaGFzIHN1cnZpdmVkIG5vdCBvbmx5IGZpdmUgY2VudHVyaWVzLCBidXQgYWxzbyB0aGUgbGVhcCBpbnRvIGVsZWN0cm9uaWMgdHlwZXNldHRpbmcsIHJlbWFpbmluZyBlc3NlbnRpYWxseSB1bmNoYW5nZWQuIEl0IHdhcyBwb3B1bGFyaXNlZCBpbiB0aGUgMTk2MHMgd2l0aCB0aGUgcmVsZWFzZSBvZiBMZXRyYXNldCBzaGVldHMgY29udGFpbmluZyBMb3JlbSBJcHN1bSBwYXNzYWdlcywgYW5kIG1vcmUgcmVjZW50bHkgd2l0aCBkZXNrdG9wIHB1Ymxpc2hpbmcgc29mdHdhcmUgbGlrZSBBbGR1cyBQYWdlTWFrZXIgaW5jbHVkaW5nIHZlcnNpb25zIG9mIExvcmVtIElwc3Vt"
        content_len = len(b64content)
        expected_call = (
            "udf-put:filename={};udf-type={};content-len={};content={}".format(
                udf_file_name, udf_type, content_len, b64content
            )
        )

        actual = await self.node.info_udf_put(udf_file_name, udf_str, udf_type)

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_udf_put_fail(self):
        self.info_mock.return_value = "error=invalid_base64_content"

        actual = await self.node.info_udf_put("udf_file_name", "udf_str", "udf_type")

        self.assertEqual(actual.message, "Failed to add UDF")
        self.assertEqual(actual.response, "invalid_base64_content")

    @patch("lib.live_cluster.client.node.Node.info_udf_list")
    async def test_info_udf_remove_success(self, info_udf_list_mock):
        info_udf_list_mock.return_value = {
            "file": {
                "filename": "bar.lua",
                "hash": "591d2536acb21a329040beabfd9bfaf110d35c18",
                "type": "LUA",
            }
        }
        self.info_mock.return_value = "OK"

        actual = await self.node.info_udf_remove("file")

        self.info_mock.assert_called_with("udf-remove:filename=file;", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    @patch("lib.live_cluster.client.node.Node.info_udf_list")
    async def test_info_udf_remove_fail(self, info_udf_list_mock):
        self.info_mock.return_value = "error=invalid_filename"
        info_udf_list_mock.return_value = {
            "file": {
                "filename": "bar.lua",
                "hash": "591d2536acb21a329040beabfd9bfaf110d35c18",
                "type": "LUA",
            }
        }

        actual = await self.node.info_udf_remove("file")

        self.assertEqual(actual.message, "Failed to remove UDF file")
        self.assertEqual(actual.response, "invalid_filename")

        info_udf_list_mock.return_value = {
            "NOT-file": {
                "filename": "bar.lua",
                "hash": "591d2536acb21a329040beabfd9bfaf110d35c18",
                "type": "LUA",
            }
        }

        actual = await self.node.info_udf_remove("file")

        self.assertEqual(actual.message, "Failed to remove UDF file")
        self.assertEqual(actual.response, "UDF does not exist")

    async def test_info_roster(self):
        self.info_mock.return_value = "ns=test:roster=null:pending_roster=null:observed_nodes=BB9070016AE4202,BB9060016AE4202,BB9050016AE4202,BB9040016AE4202,BB9020016AE4202"
        expected = {
            "test": {
                "observed_nodes": [
                    "BB9070016AE4202",
                    "BB9060016AE4202",
                    "BB9050016AE4202",
                    "BB9040016AE4202",
                    "BB9020016AE4202",
                ],
                "ns": "test",
                "pending_roster": ["null"],
                "roster": ["null"],
            }
        }

        roster_actual = await self.node.info_roster()

        self.assertDictEqual(
            roster_actual, expected, "info_roster did not return the expected result"
        )
        self.info_mock.assert_called_with("roster:", self.ip)

    async def test_info_roster_namespace(self):
        self.info_mock.return_value = "roster=null:pending_roster=null:observed_nodes=BB9070016AE4202,BB9060016AE4202,BB9050016AE4202,BB9040016AE4202,BB9020016AE4202"
        expected = {
            "observed_nodes": [
                "BB9070016AE4202",
                "BB9060016AE4202",
                "BB9050016AE4202",
                "BB9040016AE4202",
                "BB9020016AE4202",
            ],
            "pending_roster": [],
            "roster": [],
        }

        roster_actual = await self.node.info_roster_namespace("test")

        self.assertDictEqual(
            roster_actual, expected, "info_roster did not return the expected result"
        )
        self.info_mock.assert_called_with("roster:namespace=test", self.ip)

    async def test_info_cluster_stable(self):
        self.info_mock.return_value = "ABCDEFG"
        expected = "ABCDEFG"

        actual = await self.node.info_cluster_stable(
            cluster_size=3, namespace="bar", ignore_migrations=True
        )

        self.info_mock.assert_called_with(
            "cluster-stable:size=3;namespace=bar;ignore_migrations=true", self.ip
        )
        self.assertEqual(
            actual,
            expected,
            "info_cluster_stable did not return the expected result",
        )

    async def test_info_cluster_stable_with_errors(self):
        self.info_mock.return_value = "ERROR::foo"
        expected = ASInfoResponseError(
            ErrorsMsgs.INFO_SERVER_ERROR_RESPONSE, "ERROR::foo"
        )

        actual = await self.node.info_cluster_stable(namespace="bar")

        self.info_mock.assert_called_with("cluster-stable:namespace=bar", self.ip)
        self.assertEqual(
            actual,
            expected,
            "info_cluster_stable did not return the expected result",
        )

    async def test_info_racks(self):
        class TestCase:
            def __init__(self, return_val, expected):
                self.return_val = return_val
                self.expected = expected

        test_cases = [
            TestCase(
                "ns=test:rack_1=BCD10DFA9290C00,BB910DFA9290C00:rack_2=BD710DFA9290C00,BC310DFA9290C00",
                {
                    "test": {
                        "1": {
                            "rack-id": "1",
                            "nodes": ["BCD10DFA9290C00", "BB910DFA9290C00"],
                        },
                        "2": {
                            "rack-id": "2",
                            "nodes": ["BD710DFA9290C00", "BC310DFA9290C00"],
                        },
                    }
                },
            ),
            TestCase(
                "ns=test:roster_rack_1=BCD10DFA9290C00,BB910DFA9290C00:roster_rack_2=BD710DFA9290C00,BC310DFA9290C00",
                {
                    "test": {
                        "1": {
                            "rack-id": "1",
                            "nodes": ["BCD10DFA9290C00", "BB910DFA9290C00"],
                        },
                        "2": {
                            "rack-id": "2",
                            "nodes": ["BD710DFA9290C00", "BC310DFA9290C00"],
                        },
                    }
                },
            ),
            TestCase(
                "ns=test:roster_rack_1=BCD10DFA9290C00,BB910DFA9290C00:roster_rack_2=BD710DFA9290C00,BC310DFA9290C00:rack_1=BCD10DFA9290C00,BB910DFA9290C00:rack_2=BD710DFA9290C00,BC310DFA9290C00",
                {
                    "test": {
                        "1": {
                            "rack-id": "1",
                            "nodes": ["BCD10DFA9290C00", "BB910DFA9290C00"],
                        },
                        "2": {
                            "rack-id": "2",
                            "nodes": ["BD710DFA9290C00", "BC310DFA9290C00"],
                        },
                    }
                },
            ),
            TestCase(
                "ns=test:rack_1=BCD10DFA9290C00,BB910DFA9290C00:roster_rack_2=BD710DFA9290C00,BC310DFA9290C00;ns=bar:roster_rack_1=BCD10DFA9290C00,BB910DFA9290C00:rack_2=BD710DFA9290C00,BC310DFA9290C00",
                {
                    "test": {
                        "2": {
                            "rack-id": "2",
                            "nodes": ["BD710DFA9290C00", "BC310DFA9290C00"],
                        },
                    },
                    "bar": {
                        "1": {
                            "rack-id": "1",
                            "nodes": ["BCD10DFA9290C00", "BB910DFA9290C00"],
                        },
                    },
                },
            ),
        ]

        for tc in test_cases:
            with self.subTest(return_val=tc.return_val):
                self.info_mock.return_value = tc.return_val
                racks_actual = await self.node.info_racks()
                self.info_mock.assert_called_with("racks:", self.ip)
                self.assertDictEqual(
                    racks_actual,
                    tc.expected,
                    "info_racks did not return the expected result",
                )

    async def test_info_rack_ids(self):
        self.info_mock.return_value = "test:0;bar:1;foo:"
        expected = {
            "test": "0",
            "bar": "1",
        }

        racks_actual = await self.node.info_rack_ids()

        self.info_mock.assert_called_with("rack-ids", self.ip)
        self.assertEqual(
            racks_actual, expected, "info_rack_ids did not return the expected result"
        )

    @patch("lib.live_cluster.client.node.Node.info_build")
    @patch("lib.live_cluster.client.node.Node.info_dcs")
    async def test_info_xdr_dcs_config_pre_xdr5(
        self, info_dcs_mock: AsyncMock, info_build_mock: AsyncMock
    ):
        info_build_mock.return_value = "4.9.9.9"
        info_dcs_mock.return_value = ["REMOTE_DC"]
        self.info_mock.side_effect = [
            Exception("triggers the second call"),
            (
                "dc-name=REMOTE_DC:dc-type=aerospike:tls-name=:dc-security-config-file=/private/aerospike/security_credentials_REMOTE_DC.txt:"
                "nodes=192.168.100.140+3000,192.168.100.147+3000:int-ext-ipmap=:dc-connections=64:"
                "dc-connections-idle-ms=55000:dc-use-alternate-services=false:namespaces=test"
            ),
        ]
        expected = {
            "REMOTE_DC": {
                "dc-security-config-file": "/private/aerospike/security_credentials_REMOTE_DC.txt",
                "tls-name": "",
                "dc-name": "REMOTE_DC",
                "dc-connections-idle-ms": "55000",
                "dc-use-alternate-services": "false",
                "int-ext-ipmap": "",
                "dc-connections": "64",
                "namespaces": "test",
                "nodes": "192.168.100.140+3000,192.168.100.147+3000",
                "dc-type": "aerospike",
            }
        }

        xdr_dc_confg = await self.node.info_xdr_dcs_config()

        self.assertEqual(
            xdr_dc_confg,
            expected,
            "info_xdr_dcs_config with xdr feature did not return the expected result",
        )
        self.info_mock.assert_has_calls([call("get-dc-config", self.ip), call("get-dc-config:", self.ip)])  # type: ignore

    @patch("lib.live_cluster.client.node.Node.info_build")
    @patch("lib.live_cluster.client.node.Node.info_dcs")
    async def test_info_xdr_dcs_config_xdr5(
        self, info_dcs_mock: AsyncMock, info_build_mock: AsyncMock
    ):
        info_build_mock.return_value = "5.0.0.1"
        self.info_mock.side_effect = [
            "auth-mode=none;auth-password-file=null;auth-user=null"
        ]
        expected = {
            "REMOTE_DC": {
                "auth-mode": "none",
                "auth-password-file": "null",
                "auth-user": "null",
            }
        }

        xdr_dc_confg = await self.node.info_xdr_dcs_config(dcs=["REMOTE_DC"])

        self.assertEqual(
            xdr_dc_confg,
            expected,
            "info_xdr_dcs_config with xdr feature did not return the expected result",
        )
        self.info_mock.assert_has_calls([call("get-config:context=xdr;dc=REMOTE_DC", self.ip)])  # type: ignore
        info_dcs_mock.assert_not_called()

    async def test_info_xdr_dc_namespaces_config(
        self,
    ):
        self.info_mock.side_effect = [
            "a=b;c=d",
            "e=f;g=h",
        ]
        expected = {
            "test": {"a": "b", "c": "d"},
            "bar": {"e": "f", "g": "h"},
        }

        actual = await self.node.info_xdr_dc_namespaces_config("dc1", ["test", "bar"])
        self.assertDictEqual(expected, actual)

    async def test_info_all_xdr_namespaces_config_pre_xdr5(self):
        lib.live_cluster.client.node.Node.info_build.return_value = "4.9"

        actual = await self.node.info_xdr_namespaces_config()
        self.assertDictEqual(actual, {})

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    @patch("lib.live_cluster.client.node.Node.info_xdr_dcs_config")
    @patch("lib.live_cluster.client.node.Node.info_xdr_dc_namespaces_config")
    async def test_info_all_xdr_namespaces_config_xdr5(
        self,
        info_xdr_dc_namespaces_config: AsyncMock,
        info_xdr_dcs_config_mock: AsyncMock,
        info_dcs_mock: AsyncMock,
    ):
        lib.live_cluster.client.node.Node.info_build.return_value = "5.0"
        info_dcs_mock.return_value = ["dc1", "dc2"]
        info_xdr_dcs_config_mock.side_effect = [
            {"dc1": {"namespaces": "test,bar"}},
            {"dc2": {"namespaces": "zip,zow"}},
        ]
        info_xdr_dc_namespaces_config.side_effect = [
            {"test": {"a": "b"}},
            {"zip": {"c": "d"}},
        ]
        expected = {"dc1": {"test": {"a": "b"}}, "dc2": {"zip": {"c": "d"}}}

        actual = await self.node.info_xdr_namespaces_config(namespaces=["test", "zip"])
        self.assertDictEqual(actual, expected)

    async def test_info_xdr_config(self):
        self.info_mock.return_value = "a=1;b=2;c=3"
        expected = {
            "a": "1",
            "b": "2",
            "c": "3",
        }

        actual = await self.node.info_xdr_config()

        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_dcs")
    async def test_info_get_xdr_filter(self, info_dcs_mock: AsyncMock):
        info_dcs_mock.return_value = ["dc1", "dc2"]
        self.info_mock.side_effect = [
            "namespace=test:exp=1;namespace=bar:exp=2",
            "namespace=test:exp=3;namespace=bar:exp=4",
            "namespace=test:exp=5;namespace=bar:exp=6",
            "namespace=test:exp=7;namespace=bar:exp=8",
        ]
        expected = {
            "dc1": {
                "test": {"namespace": "test", "exp": "1", "b64-exp": "3"},
                "bar": {"namespace": "bar", "exp": "2", "b64-exp": "4"},
            },
            "dc2": {
                "test": {"namespace": "test", "exp": "5", "b64-exp": "7"},
                "bar": {"namespace": "bar", "exp": "6", "b64-exp": "8"},
            },
        }

        actual = await self.node.info_get_xdr_filter()

        self.assertDictEqual(actual, expected)

    async def test_info_histogram(self):
        raw = """
         units=bytes:hist-width=8388608:bucket-width=8192:buckets=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,505,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
         0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
        """

        # nraw, {'namespaces':'test'})
        self.info_mock.side_effect = ["test", raw]
        self.node.new_histogram_version = True
        expected = {
            "test": {
                # 'units': 'bytes',
                "width": 8192,
                "data": [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    505,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
                "histogram": "object-size-linear",
            }
        }

        histogram_actual = await self.node.info_histogram("objsz")

        self.assertEqual(
            histogram_actual,
            expected,
            "info_histogram did not return the expected result",
        )
        self.info_mock.assert_called_with(
            "histogram:namespace=test;type=object-size-linear", self.ip
        )

        self.info_mock.side_effect = ["test", raw]
        expected = {"test": raw}

        histogram_actual = await self.node.info_histogram(
            "objsz", logarithmic=True, raw_output=True
        )

        self.assertEqual(
            histogram_actual,
            expected,
            "info_histogram did not return the expected result",
        )

        self.info_mock.assert_called_with(
            "histogram:namespace=test;type=object-size", self.ip
        )
        self.info_mock.side_effect = ["test", raw]
        await self.node.info_histogram("ttl", logarithmic=True, raw_output=True)
        self.info_mock.assert_called_with("histogram:namespace=test;type=ttl", self.ip)

        self.node.new_histogram_version = False
        self.info_mock.side_effect = ["test", raw]
        await self.node.info_histogram("objsz", logarithmic=True, raw_output=True)
        self.info_mock.assert_called_with("hist-dump:ns=test;hist=objsz", self.ip)

    async def test_info_sindex(self):
        self.info_mock.return_value = "a=1:b=2:c=3:d=4:e=5;a=6:b=7:c=8:d=9:e=10;"
        expected = [
            {"a": "1", "b": "2", "c": "3", "d": "4", "e": "5"},
            {"a": "6", "b": "7", "c": "8", "d": "9", "e": "10"},
        ]

        actual = await self.node.info_sindex()

        self.info_mock.assert_called_with("sindex-list:", self.ip)
        self.assertListEqual(actual, expected)

    async def test_info_sindex_statistics(self):
        self.info_mock.return_value = "a=b;c=d;e=f"
        expected = {"a": "b", "c": "d", "e": "f"}

        actual = await self.node.info_sindex_statistics("foo", "bar")

        self.info_mock.assert_called_with(
            "sindex-stat:namespace={};indexname={}".format("foo", "bar"), self.ip
        )
        self.assertDictEqual(actual, expected)

    async def test_info_sindex_create_success(self):
        self.info_mock.return_value = "OK"
        expected_call = (
            "sindex-create:indexname=iname;ns=ns;indexdata=data1,data2".format()
        )

        actual = await self.node.info_sindex_create(
            "iname",
            "ns",
            "data1",
            "data2",
            feature_support={
                "namespace_query_selector_support": False,
                "expression_indexing": False,
            },
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "OK"
        expected_call = "sindex-create:indexname=iname;indextype=itype;ns=ns;set=set;context=khAB;indexdata=data1,data2"

        actual = await self.node.info_sindex_create(
            "iname",
            "ns",
            "data1",
            "data2",
            index_type="itype",
            set_="set",
            ctx=CDTContext([CTXItems.ListIndex(1)]),
            feature_support={
                "namespace_query_selector_support": False,
                "expression_indexing": False,
            },
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_sindex_create_fail(self):
        self.info_mock.return_value = "FAIL:4: Invalid indexdata"

        actual = await self.node.info_sindex_create(
            "iname",
            "ns",
            "data1",
            "data2",
            feature_support={
                "namespace_query_selector_support": False,
                "expression_indexing": False,
            },
        )

        self.assertEqual(actual.message, "Failed to create sindex iname")
        self.assertEqual(actual.response, "Invalid indexdata")

    async def test_info_sindex_create_with_ctx_base64(self):
        self.info_mock.return_value = "OK"
        expected_call = "sindex-create:indexname=ctx-idx;ns=test;context=dGVzdA==;indexdata=mybin,string"

        actual = await self.node.info_sindex_create(
            "ctx-idx",
            "test",
            "mybin",
            "string",
            cdt_ctx_base64="dGVzdA==",
            feature_support={
                "namespace_query_selector_support": False,
                "expression_indexing": False,
            },
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_sindex_create_with_exp_base64(self):
        self.info_mock.return_value = "OK"
        expected_call = (
            "sindex-create:indexname=exp-idx;ns=test;exp=dGVzdA==;type=string"
        )

        actual = await self.node.info_sindex_create(
            "exp-idx",
            "test",
            None,
            "string",
            exp_base64="dGVzdA==",
            feature_support={
                "namespace_query_selector_support": False,
                "expression_indexing": False,
            },
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_sindex_create_with_supports_sindex_type_syntax(self):
        self.info_mock.return_value = "OK"
        expected_call = "sindex-create:indexname=new-idx;ns=test;bin=mybin;type=string"

        actual = await self.node.info_sindex_create(
            "new-idx",
            "test",
            "mybin",
            "string",
            feature_support={
                "namespace_query_selector_support": False,
                "expression_indexing": True,
            },
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_sindex_create_with_all_new_params(self):
        self.info_mock.return_value = "OK"
        expected_call = "sindex-create:indexname=full-idx;indextype=mapkeys;ns=test;set=myset;context=dGVzdA==;bin=mybin;type=string"

        actual = await self.node.info_sindex_create(
            "full-idx",
            "test",
            "mybin",
            "string",
            index_type="mapkeys",
            set_="myset",
            cdt_ctx_base64="dGVzdA==",
            feature_support={
                "namespace_query_selector_support": False,
                "expression_indexing": True,
            },
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_sindex_delete_success(self):
        self.info_mock.return_value = "OK"
        expected_call = "sindex-delete:ns={};indexname={}".format(
            "ns",
            "iname",
        )

        actual = await self.node.info_sindex_delete(
            "iname", "ns", feature_support={"namespace_query_selector_support": False}
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "OK"
        expected_call = "sindex-delete:ns={};set={};indexname={}".format(
            "ns",
            "set",
            "iname",
        )

        actual = await self.node.info_sindex_delete(
            "iname",
            "ns",
            set_="set",
            feature_support={"namespace_query_selector_support": False},
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_sindex_delete_fail(self):
        self.info_mock.return_value = "FAIL:4: Invalid indexname"

        actual = await self.node.info_sindex_delete(
            "iname", "ns", feature_support={"namespace_query_selector_support": False}
        )

        self.assertEqual(actual.message, "Failed to delete sindex iname")
        self.assertEqual(actual.response, "Invalid indexname")

    async def test_use_new_truncate_command(self):
        input_output = [
            ("4.3.1.11", True),
            ("4.3.2.0", False),
            ("4.4.0.10", False),
            ("4.4.0.12", True),
            ("4.5.1.4", False),
            ("4.5.1.5", True),
            ("4.5.2.0", True),
        ]

        for input, output in input_output:
            lib.live_cluster.client.node.Node.info_build.return_value = input

            self.assertEqual(await self.node._use_new_truncate_command(), output)

    async def test_info_truncate_with_ns_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_truncate("test-ns")

        self.info_mock.assert_called_once_with(
            "truncate-namespace:namespace=test-ns", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    @patch("lib.live_cluster.client.node.Node._use_new_truncate_command")
    async def test_info_truncate_with_ns_and_older_command_success(
        self, use_new_truncate_command_mock
    ):
        self.info_mock.return_value = "ok"
        use_new_truncate_command_mock.return_value = False

        actual = await self.node.info_truncate("test-ns")

        self.info_mock.assert_called_once_with("truncate:namespace=test-ns", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_truncate_with_ns_and_lut_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_truncate("test-ns", lut="123456789")

        self.info_mock.assert_called_once_with(
            "truncate-namespace:namespace=test-ns;lut=123456789", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_truncate_with_set_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_truncate("test-ns", "bar")

        self.info_mock.assert_called_once_with(
            "truncate:namespace=test-ns;set=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_truncate_with_set_and_lut_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_truncate("test-ns", "bar", "123456789")

        self.info_mock.assert_called_once_with(
            "truncate:namespace=test-ns;set=bar;lut=123456789", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_truncate_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_truncate("test-ns", "bar", "123456789")

        self.info_mock.assert_called_once_with(
            "truncate:namespace=test-ns;set=bar;lut=123456789", self.ip
        )
        self.assertEqual(
            str(actual),
            "Failed to truncate namespace test-ns set bar : Unknown error occurred.",
        )

        self.info_mock.return_value = "error"

        actual = await self.node.info_truncate("test-ns")

        self.info_mock.assert_called_with(
            "truncate-namespace:namespace=test-ns", self.ip
        )
        self.assertEqual(
            str(actual),
            "Failed to truncate namespace test-ns : Unknown error occurred.",
        )

    async def test_info_truncate_undo_with_ns_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_truncate_undo("test-ns")

        self.info_mock.assert_called_once_with(
            "truncate-namespace-undo:namespace=test-ns", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    @patch("lib.live_cluster.client.node.Node._use_new_truncate_command")
    async def test_info_truncate_undo_with_ns_and_older_command_success(
        self, use_new_truncate_command_mock
    ):
        self.info_mock.return_value = "ok"
        use_new_truncate_command_mock.return_value = False

        actual = await self.node.info_truncate_undo("test-ns")

        self.info_mock.assert_called_once_with(
            "truncate-undo:namespace=test-ns", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_truncate_undo_with_ns_and_lut_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_truncate_undo("test-ns")

        self.info_mock.assert_called_once_with(
            "truncate-namespace-undo:namespace=test-ns", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_truncate_undo_with_set_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_truncate_undo("test-ns", "bar")

        self.info_mock.assert_called_once_with(
            "truncate-undo:namespace=test-ns;set=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_truncate_undo_with_set_and_lut_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_truncate_undo("test-ns", "bar")

        self.info_mock.assert_called_once_with(
            "truncate-undo:namespace=test-ns;set=bar", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_truncate_undo_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_truncate_undo("test-ns", "bar")

        self.info_mock.assert_called_once_with(
            "truncate-undo:namespace=test-ns;set=bar", self.ip
        )
        self.assertEqual(
            str(actual),
            "Failed to undo truncation of namespace test-ns set bar : Unknown error occurred.",
        )

        self.info_mock.return_value = "error"

        actual = await self.node.info_truncate_undo("test-ns")

        self.info_mock.assert_called_with(
            "truncate-namespace-undo:namespace=test-ns", self.ip
        )
        self.assertEqual(
            str(actual),
            "Failed to undo truncation of namespace test-ns : Unknown error occurred.",
        )

    async def test_info_recluster_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_recluster()

        self.info_mock.assert_called_once_with("recluster:", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_recluster_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_recluster()

        self.info_mock.assert_called_once_with("recluster:", self.ip)
        self.assertEqual(
            str(actual),
            "Failed to recluster : Unknown error occurred.",
        )

    async def test_info_quiesce_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_quiesce()

        self.info_mock.assert_called_once_with("quiesce:", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_quiesce_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_quiesce()

        self.info_mock.assert_called_once_with("quiesce:", self.ip)
        self.assertEqual(
            str(actual),
            "Failed to quiesce : Unknown error occurred.",
        )

    async def test_info_quiesce_undo_success(self):
        self.info_mock.return_value = "ok"

        actual = await self.node.info_quiesce_undo()

        self.info_mock.assert_called_once_with("quiesce-undo:", self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_quiesce_undo_fail(self):
        self.info_mock.return_value = "error"

        actual = await self.node.info_quiesce_undo()

        self.info_mock.assert_called_once_with("quiesce-undo:", self.ip)
        self.assertEqual(
            str(actual),
            "Failed to undo quiesce : Unknown error occurred.",
        )

    async def test_info_jobs(self):
        self.info_mock.return_value = (
            "module=scan:trid=123:ns=test;module=query:trid=456:ns=bar"
        )
        expected = {
            "123": {"trid": "123", "module": "scan", "ns": "test"},
            "456": {"trid": "456", "module": "query", "ns": "bar"},
        }

        actual = await self.node.info_jobs("scan")

        self.info_mock.assert_called_with("jobs:module=scan", self.ip)
        self.assertDictEqual(actual, expected)

    async def test_jobs_helper_uses_new(self):
        lib.live_cluster.client.node.Node.info_build.return_value = "6.3.0.0"
        self.info_mock.return_value = "foo"
        old = "old"
        new = "new"

        actual = await self.node._jobs_helper(old, new)

        self.info_mock.assert_called_with("new", self.ip)
        self.assertEqual(actual, "foo")

    async def test_jobs_helper_uses_old(self):
        lib.live_cluster.client.node.Node.info_build.return_value = (
            "5.0.0.11"  # Version < 6.3, should use old command
        )
        self.info_mock.return_value = "foo"
        old = "old"
        new = "new"

        actual = await self.node._jobs_helper(old, new)

        self.info_mock.assert_called_with("old", self.ip)
        self.assertEqual(actual, "foo")

    async def test_info_query_show(self):
        self.node._jobs_helper = AsyncMock()
        self.node._jobs_helper.return_value = (
            "module=query:trid=123:ns=test;module=query:trid=456:ns=bar"
        )
        expected = {
            "123": {"trid": "123", "module": "query", "ns": "test"},
            "456": {"trid": "456", "module": "query", "ns": "bar"},
        }

        actual = await self.node.info_query_show()

        self.node._jobs_helper.assert_called_with("jobs:module=query", "query-show")
        self.assertDictEqual(actual, expected)

    async def test_info_scan_show(self):
        self.node._jobs_helper = AsyncMock()
        self.node._jobs_helper.return_value = (
            "module=scan:trid=123:ns=test;module=scan:trid=456:ns=bar"
        )
        expected = {
            "123": {"trid": "123", "module": "scan", "ns": "test"},
            "456": {"trid": "456", "module": "scan", "ns": "bar"},
        }

        actual = await self.node.info_scan_show()

        self.node._jobs_helper.assert_called_with("jobs:module=scan", "scan-show")
        self.assertDictEqual(actual, expected)

    async def test_info_jobs_kill(self):
        self.info_mock.return_value = "OK"

        actual = await self.node.info_jobs_kill("foo", "123")

        self.info_mock.assert_called_with(
            "jobs:module=foo;cmd=kill-job;trid=123", self.ip
        )
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_jobs_kill_returns_error(self):
        self.info_mock.return_value = "not Ok"
        expected = ASInfoResponseError("Failed to kill job", "not Ok")

        actual = await self.node.info_jobs_kill("foo", "123")

        self.info_mock.assert_called_with(
            "jobs:module=foo;cmd=kill-job;trid=123", self.ip
        )
        self.assertEqual(actual, expected)

    async def test_info_scan_abort(self):
        self.node._jobs_helper = AsyncMock()
        self.node._jobs_helper.return_value = "OK"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_scan_abort("123")

        self.node._jobs_helper.assert_called_with(
            "jobs:module=scan;cmd=kill-job;trid=123", "scan-abort:trid=123"
        )
        self.assertEqual(actual, expected)

    async def test_info_scan_abort_returns_error(self):
        self.node._jobs_helper = AsyncMock()
        self.node._jobs_helper.return_value = "not Ok"
        expected = ASInfoResponseError("Failed to kill job", "not Ok")

        actual = await self.node.info_scan_abort("123")

        self.node._jobs_helper.assert_called_with(
            "jobs:module=scan;cmd=kill-job;trid=123", "scan-abort:trid=123"
        )
        self.assertEqual(actual, expected)

    async def test_info_query_abort(self):
        self.node._jobs_helper = AsyncMock()
        self.node._jobs_helper.return_value = "OK"
        expected = ASINFO_RESPONSE_OK

        actual = await self.node.info_query_abort("123")

        self.node._jobs_helper.assert_called_with(
            "jobs:module=query;cmd=kill-job;trid=123", "query-abort:trid=123"
        )
        self.assertEqual(actual, expected)

    async def test_info_query_abort_returns_error(self):
        self.node._jobs_helper = AsyncMock()
        self.node._jobs_helper.return_value = "not Ok"
        expected = ASInfoResponseError("Failed to kill job", "not Ok")

        actual = await self.node.info_query_abort("123")

        self.node._jobs_helper.assert_called_with(
            "jobs:module=query;cmd=kill-job;trid=123", "query-abort:trid=123"
        )
        self.assertEqual(actual, expected)

    async def test_info_scan_abort_all_with_feature_present(self):
        self.info_mock.return_value = "OK - number of scans killed: 7"
        expected = "ok - number of scans killed: 7"

        actual = await self.node.info_scan_abort_all()

        self.info_mock.assert_called_with("scan-abort-all:", self.ip)
        self.assertEqual(actual, expected)

    async def test_info_scan_abort_all_with_feature_present_and_error(self):
        self.info_mock.return_value = "error"
        expected = ASInfoResponseError("Failed to abort all scans", "error")

        actual = await self.node.info_scan_abort_all()

        self.assertEqual(actual, expected)

    async def test_info_query_abort_all(self):
        self.info_mock.return_value = "OK - number of queries killed: 7"
        expected = "ok - number of queries killed: 7"

        actual = await self.node.info_query_abort_all()

        self.info_mock.assert_called_with("query-abort-all:", self.ip)
        self.assertEqual(actual, expected)

    async def test_info_query_abort_all_with_error(self):
        self.info_mock.return_value = "error"
        expected = ASInfoResponseError("Failed to abort all queries", "error")

        actual = await self.node.info_query_abort_all()

        self.assertEqual(actual, expected)

    @patch("lib.live_cluster.client.assocket.ASSocket.create_user")
    @patch("lib.live_cluster.client.node.Node._get_connection")
    async def test_admin_cadmin(self, get_connection_mock, create_user_mock):
        get_connection_mock.return_value = ASSocket(
            self.node.ip,
            self.node.port,
            self.node.tls_name,
            self.node.user,
            self.node.password,
            self.node.auth_mode,
            self.node.ssl_context,
            timeout=self.node._timeout,
        )
        expected = 1
        create_user_mock.return_value = expected

        actual = await self.node._admin_cadmin(
            ASSocket.create_user, (1, 2, 3), self.node.ip, self.node.port
        )

        get_connection_mock.assert_called_with(self.node.ip, self.node.port)
        create_user_mock.assert_called_with(get_connection_mock.return_value, 1, 2, 3)
        self.assertEqual(actual, expected)

        get_connection_mock.return_value = None

        await util.assert_exception_async(
            self,
            OSError,
            "Could not connect to node 192.1.1.1",
            self.node._admin_cadmin,
            ASSocket.create_user,
            (1, 2, 3),
            self.node.ip,
            self.node.port,
        )

    async def test_admin_funcs(self):
        class TestCase:
            def __init__(self, node_func, assocket_func, args):
                self.node_func = node_func
                self.assocket_func = assocket_func
                self.args = args

        test_cases = [
            TestCase(
                self.node.admin_create_user,
                ASSocket.create_user,
                ("user", "pass", ["role1", "role2"]),
            ),
            TestCase(
                self.node.admin_delete_user,
                ASSocket.delete_user,
                ["user"],
            ),
            TestCase(
                self.node.admin_set_password,
                ASSocket.set_password,
                ("user", "pass"),
            ),
            TestCase(
                self.node.admin_change_password,
                ASSocket.change_password,
                ("user", "oldpass", "newpass"),
            ),
            TestCase(
                self.node.admin_grant_roles,
                ASSocket.grant_roles,
                ("user", ["role1", "role2"]),
            ),
            TestCase(
                self.node.admin_revoke_roles,
                ASSocket.revoke_roles,
                ("user", ["role1", "role2"]),
            ),
            TestCase(
                self.node.admin_query_users,
                ASSocket.query_users,
                (),
            ),
            TestCase(
                self.node.admin_query_user,
                ASSocket.query_user,
                ["user"],
            ),
            TestCase(
                self.node.admin_create_role,
                ASSocket.create_role,
                ("role", "privileges", "whitelist", "read_quota", "write_quota"),
            ),
            TestCase(
                self.node.admin_delete_role,
                ASSocket.delete_role,
                ["role"],
            ),
            TestCase(
                self.node.admin_add_privileges,
                ASSocket.add_privileges,
                ("role", ["priv1", "priv2"]),
            ),
            TestCase(
                self.node.admin_delete_privileges,
                ASSocket.delete_privileges,
                ("role", ["priv1", "priv2"]),
            ),
            TestCase(
                self.node.admin_set_whitelist,
                ASSocket.set_whitelist,
                ("role", "whitelist"),
            ),
            TestCase(
                self.node.admin_delete_whitelist,
                ASSocket.delete_whitelist,
                ["role"],
            ),
            TestCase(
                self.node.admin_set_quotas,
                ASSocket.set_quotas,
                ("role", "read-quota", "write-quota"),
            ),
            TestCase(
                self.node.admin_delete_quotas,
                ASSocket.delete_quotas,
                ("role", "read-quota", "write-quota"),
            ),
            TestCase(
                self.node.admin_query_roles,
                ASSocket.query_roles,
                (),
            ),
            TestCase(
                self.node.admin_query_role,
                ASSocket.query_role,
                ["role"],
            ),
        ]

        for tc in test_cases:
            admin_cadmin_mock = lib.live_cluster.client.node.Node._admin_cadmin = patch(
                "lib.live_cluster.client.node.Node._admin_cadmin", AsyncMock()
            ).start()
            admin_cadmin_mock.return_value = "foo"
            result = await tc.node_func(*tc.args)
            self.assertFalse(
                isinstance(result, Exception), msg="exception: {}".format(result)
            )
            self.assertEqual(result, "foo")
            admin_cadmin_mock.assert_called_with(
                tc.assocket_func, tc.args, self.node.ip
            )

    async def test_info_user_agents_success(self):
        """Test successful user agents retrieval"""
        # Mock response with base64 encoded user agents
        mock_response = "user-agent=dGVzdA==:count=5;user-agent=YXNhZG0=:count=3"
        self.info_mock.return_value = mock_response

        result = await self.node.info_user_agents()

        self.info_mock.assert_called_with("user-agents", self.ip)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["user-agent"], "dGVzdA==")
        self.assertEqual(result[0]["count"], "5")
        self.assertEqual(result[1]["user-agent"], "YXNhZG0=")
        self.assertEqual(result[1]["count"], "3")

    async def test_info_user_agents_empty(self):
        """Test when no user agents are present"""
        self.info_mock.return_value = ""

        result = await self.node.info_user_agents()

        self.info_mock.assert_called_with("user-agents", self.ip)
        self.assertEqual(result, [])

    async def test_info_user_agents_error(self):
        """Test error handling"""
        self.info_mock.return_value = ASInfoResponseError("error", "Test error")

        result = await self.node.info_user_agents()

        self.info_mock.assert_called_with("user-agents", self.ip)
        self.assertIsInstance(result, ASInfoResponseError)

    async def test_info_masking_add_rule_success(self):
        """Test successful masking rule addition"""
        self.info_mock.return_value = "ok"

        result = await self.node.info_masking_add_rule(
            "test",
            "demo",
            "ssn",
            "string",
            "redact",
            {"position": "0", "length": "4", "value": "*"},
        )

        expected_req = "masking:namespace=test;set=demo;bin=ssn;type=string;function=redact;position=0;length=4;value=*"
        self.info_mock.assert_called_with(expected_req, self.ip)
        self.assertEqual(result, ASINFO_RESPONSE_OK)

    async def test_info_masking_add_rule_error(self):
        """Test masking rule addition error"""
        self.info_mock.return_value = "error::invalid parameters"

        result = await self.node.info_masking_add_rule(
            "test", "demo", "ssn", "string", "redact", {"position": "0"}
        )

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to add masking rule")

    async def test_info_masking_remove_rule_success(self):
        """Test successful masking rule removal"""
        self.info_mock.return_value = "ok"

        result = await self.node.info_masking_remove_rule(
            "test", "demo", "ssn", "string"
        )

        expected_req = (
            "masking:namespace=test;set=demo;bin=ssn;type=string;function=remove"
        )
        self.info_mock.assert_called_with(expected_req, self.ip)
        self.assertEqual(result, ASINFO_RESPONSE_OK)

    async def test_info_masking_remove_rule_with_custom_type(self):
        """Test successful masking rule removal with custom type"""
        self.info_mock.return_value = "ok"

        result = await self.node.info_masking_remove_rule(
            "test", "demo", "ssn", "number"
        )

        expected_req = (
            "masking:namespace=test;set=demo;bin=ssn;type=number;function=remove"
        )
        self.info_mock.assert_called_with(expected_req, self.ip)
        self.assertEqual(result, ASINFO_RESPONSE_OK)

    async def test_info_masking_remove_rule_error(self):
        """Test masking rule removal error"""
        self.info_mock.return_value = "error::rule not found"

        result = await self.node.info_masking_remove_rule(
            "test", "demo", "ssn", "string"
        )

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to remove masking rule")

    async def test_info_masking_list_rules_success(self):
        """Test successful masking rules listing"""
        self.info_mock.return_value = "ns=test;set=demo;bin=ssn;type=string;function=redact;position=0;length=4;value=*:ns=test;set=demo;bin=email;type=string;function=constant;value=REDACTED"

        result = await self.node.info_masking_list_rules("test", "demo")

        expected_req = "masking-show:ns=test;set=demo;"
        self.info_mock.assert_called_with(expected_req, self.ip)

        expected = [
            {
                "ns": "test",
                "set": "demo",
                "bin": "ssn",
                "type": "string",
                "function": "redact",
                "position": "0",
                "length": "4",
                "value": "*",
            },
            {
                "ns": "test",
                "set": "demo",
                "bin": "email",
                "type": "string",
                "function": "constant",
                "value": "REDACTED",
            },
        ]
        self.assertEqual(result, expected)

    async def test_info_masking_list_rules_no_filters(self):
        """Test masking rules listing without filters"""
        self.info_mock.return_value = (
            "ns=test;set=demo;bin=ssn;type=string;function=redact"
        )

        result = await self.node.info_masking_list_rules()

        expected_req = "masking-show:"
        self.info_mock.assert_called_with(expected_req, self.ip)

        expected = [
            {
                "ns": "test",
                "set": "demo",
                "bin": "ssn",
                "type": "string",
                "function": "redact",
            }
        ]
        self.assertEqual(result, expected)

    async def test_info_masking_list_rules_empty_response(self):
        """Test masking rules listing with empty response"""
        self.info_mock.return_value = ""

        result = await self.node.info_masking_list_rules()

        self.assertEqual(result, [])

    async def test_info_masking_list_rules_error(self):
        """Test masking rules listing with ERROR response"""
        self.info_mock.return_value = "ERROR::masking not supported"

        result = await self.node.info_masking_list_rules()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to list masking rules")
        self.assertEqual(result.response, "masking not supported")


class SyscmdTest(unittest.TestCase):
    def setUp(self) -> None:
        def parse_func(input: str) -> dict[str, Any]:
            return {"key": "parsed"}

        self.parse_func = parse_func
        # self.sys_cmd = _SysCmd("name", False, ["cmd1", "cmd2", "cmd3"], parse_func)

    def test_init(self):
        _SysCmd.set_uid(-1)
        self.assertRaises(
            RuntimeError,
            lambda: _SysCmd("name", False, ["cmd1", "cmd2", "cmd3"], self.parse_func),
        )

        _SysCmd.set_uid(1)
        sys_cmd = _SysCmd("name", False, ["cmd1", "cmd2", "cmd3"], self.parse_func)

        self.assertEqual(sys_cmd.key, "name")
        self.assertEqual(sys_cmd.ignore_error, False)

    def test_iter_as_root(self):
        _SysCmd.set_uid(0)
        sys_cmd = _SysCmd(
            "name", False, ["sudo cmd1", "cmd2 sudo ", "cmd3"], self.parse_func
        )

        cmds = [cmd for cmd in sys_cmd]

        self.assertListEqual(["cmd1", "cmd2 ", "cmd3"], cmds)

    def test_iter_not_as_root(self):
        _SysCmd.set_uid(1)
        sys_cmd = _SysCmd(
            "name", False, ["sudo cmd1", "cmd2 sudo ", "cmd3"], self.parse_func
        )

        cmds = [cmd for cmd in sys_cmd]

        self.assertListEqual(["sudo cmd1", "cmd2 sudo ", "cmd3"], cmds)

    def test_parse(self):
        def parse_func(input: str) -> dict[str, Any]:
            return {
                "key1": {"key2": [{"key3": "n/e", "key4": None}]},
                "key.5": {
                    "ke y6": 2,
                    "key.7": "True",
                    "key8": "3.14",
                    "key9": "-5",
                    "key10": "-5.5",
                    "key11": "2",
                    "key12": True,
                    "key13": 3.14,
                },
                "key14": input,
            }

        expected = {
            "key1": {"key2": [{"key3": None, "key4": None}]},
            "key.5": {
                "ke_y6": 2,
                "key_7": True,
                "key8": 3.14,
                "key9": -5,
                "key10": -5.5,
                "key11": 2,
                "key12": True,
                "key13": 3.14,
            },
            "key14": "foo",
        }

        _SysCmd.set_uid(1)
        sys_cmd = _SysCmd(
            "name", False, ["sudo cmd1", "cmd2 sudo ", "cmd3"], parse_func
        )

        result = sys_cmd.parse("foo")

        self.assertDictEqual(expected, result)


class NeedsRefreshTest(asynctest.TestCase):
    """Test cases for the needs_refresh method"""

    async def setUp(self):
        self.ip = "192.1.1.1"
        self.port = 3000

        # Mock dependencies
        self.get_fully_qualified_domain_name = patch(
            "lib.live_cluster.client.node.get_fully_qualified_domain_name"
        ).start()
        self.async_shell_cmd_mock = patch(
            "lib.live_cluster.client.node.util.async_shell_command"
        ).start()
        getaddrinfo = patch("socket.getaddrinfo")
        self.addCleanup(patch.stopall)

        lib.live_cluster.client.node.Node.info_build = patch(
            "lib.live_cluster.client.node.Node.info_build", AsyncMock()
        ).start()
        socket.getaddrinfo = getaddrinfo.start()

        lib.live_cluster.client.node.Node.info_build.return_value = "5.0.0.11"
        self.get_fully_qualified_domain_name.return_value = "host.domain.local"
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.1.1.1", 3000))]

        # Mock _info_cinfo for Node initialization
        self.init_info_mock = patch.object(
            lib.live_cluster.client.node.Node, "_info_cinfo", new_callable=AsyncMock
        ).start()

        def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "features", "connection"]:
                return {
                    "node": "A00000000000000",
                    "features": "features",
                    "connection": "admin=false",
                }
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "192.1.1.1:3000",
                    "peers-clear-std": "2,3000,[[1A0,,[192.1.1.1]]]",
                }
            else:
                return "mock_response"

        self.init_info_mock.side_effect = info_side_effect

        # Create node
        self.node = await Node(self.ip, self.port)
        self.node._initialize_socket_pool()

        # Mock info methods
        self.info_mock = patch.object(
            self.node, "_info_cinfo", new_callable=AsyncMock
        ).start()
        self.get_connection_mock = patch.object(
            self.node, "_get_connection", new_callable=AsyncMock
        ).start()
        self.info_service_helper_mock = patch.object(
            self.node, "_info_service_helper"
        ).start()
        self.get_service_info_call_mock = patch.object(
            self.node, "_get_service_info_call"
        ).start()

    async def test_needs_refresh_node_not_alive(self):
        """Test that needs_refresh returns True when node is not alive"""
        self.node.alive = False

        result = await self.node.needs_refresh()

        self.assertTrue(result)

    async def test_needs_refresh_no_socket_pool(self):
        """Test that needs_refresh returns True when socket pool is None"""
        self.node.alive = True
        self.node.socket_pool = None

        result = await self.node.needs_refresh()

        self.assertTrue(result)

    async def test_needs_refresh_no_socket_pool_for_port(self):
        """Test that needs_refresh returns True when socket pool doesn't have the port"""
        self.node.alive = True
        self.node.socket_pool = {9999: deque()}  # Different port

        result = await self.node.needs_refresh()

        self.assertTrue(result)

    async def test_needs_refresh_no_connection_available(self):
        """Test that needs_refresh returns True when no socket connection is available"""
        self.node.alive = True
        self.get_connection_mock.return_value = None

        result = await self.node.needs_refresh()

        self.assertTrue(result)
        self.get_connection_mock.assert_called_once_with(self.ip, self.port)

    async def test_needs_refresh_service_addresses_changed(self):
        """Test that needs_refresh returns True when service addresses have changed"""
        self.node.alive = True
        self.node.service_addresses = [("192.1.1.1", 3000, None)]
        self.node.ip = "192.1.1.1"
        self.node.port = 3000
        self.node.tls_name = None

        # Mock successful connection
        mock_socket = AsyncMock()
        self.get_connection_mock.return_value = mock_socket

        # Mock service info calls
        self.get_service_info_call_mock.return_value = "service-clear-std"
        self.info_mock.return_value = {
            "node": "A00000000000000",
            "service-clear-std": "192.1.1.2:3000",
        }
        self.info_service_helper_mock.return_value = [
            ("192.1.1.2", 3000, None)
        ]  # Different address

        result = await self.node.needs_refresh()

        self.assertTrue(result)
        self.info_mock.assert_called_once_with(
            ["node", "service-clear-std"], self.ip, disable_cache=True
        )

    async def test_needs_refresh_service_addresses_compatible(self):
        """Test that needs_refresh returns False when service addresses are compatible"""
        self.node.alive = True
        self.node.ip = "192.1.1.1"
        self.node.port = 3000
        self.node.tls_name = None
        self.node.node_id = "A00000000000000"  # Set node ID to match
        self.node.service_addresses = [
            ("192.1.1.1", 3000, None),
            ("192.1.1.2", 3000, None),
        ]

        # Mock successful connection
        mock_socket = AsyncMock()
        self.get_connection_mock.return_value = mock_socket

        # Mock service info calls - current connection is in refreshed addresses
        self.get_service_info_call_mock.return_value = "service-clear-std"
        self.info_mock.return_value = {
            "node": "A00000000000000",
            "service-clear-std": "192.1.1.1:3000,192.1.1.2:3000",
        }
        self.info_service_helper_mock.return_value = [
            ("192.1.1.1", 3000, None),
            ("192.1.1.2", 3000, None),
        ]  # Same addresses including current connection

        result = await self.node.needs_refresh()

        self.assertFalse(result)

    async def test_needs_refresh_exception_handling(self):
        """Test that needs_refresh returns True when an exception occurs"""
        self.node.alive = True
        self.get_connection_mock.side_effect = Exception("Connection failed")

        result = await self.node.needs_refresh()

        self.assertTrue(result)

    async def test_service_addresses_compatible_same_addresses(self):
        """Test _service_addresses_compatible with identical addresses"""
        self.node.ip = "192.1.1.1"
        self.node.port = 3000
        self.node.tls_name = None
        refreshed = [("192.1.1.1", 3000, None)]

        result = self.node._service_addresses_compatible(refreshed, "service-clear-std")

        self.assertTrue(result)

    async def test_service_addresses_compatible_subset(self):
        """Test _service_addresses_compatible with current connection in refreshed addresses"""
        self.node.ip = "192.1.1.1"
        self.node.port = 3000
        self.node.tls_name = None
        refreshed = [("192.1.1.1", 3000, None), ("192.1.1.2", 3000, None)]

        result = self.node._service_addresses_compatible(refreshed, "service-clear-std")

        self.assertTrue(result)

    async def test_service_addresses_compatible_connection_not_in_current(self):
        """Test _service_addresses_compatible when connection address not in refreshed addresses"""
        self.node.ip = "192.1.1.1"
        self.node.port = 3000
        self.node.tls_name = None
        refreshed = [("192.1.1.2", 3000, None)]  # Different from connection

        result = self.node._service_addresses_compatible(refreshed, "service-clear-std")

        self.assertFalse(result)

    async def test_service_addresses_compatible_empty_current(self):
        """Test _service_addresses_compatible with empty refreshed addresses"""
        refreshed = []

        result = self.node._service_addresses_compatible(refreshed, "service-clear-std")

        self.assertFalse(result)  # Empty refreshed addresses should trigger refresh

    async def test_needs_refresh_load_balancer_scenario(self):
        """Test load balancer to direct connection optimization"""
        # Current connection via load balancer
        self.node.ip = "load-balancer.com"
        self.node.port = 3000
        self.node.tls_name = None
        self.node.alive = True

        mock_socket = AsyncMock()
        self.get_connection_mock.return_value = mock_socket

        # Mock service info calls
        self.get_service_info_call_mock.return_value = "service-clear-std"
        self.info_mock.return_value = {
            "node": "A00000000000000",
            "service-clear-std": "192.1.1.1:3000,192.1.1.2:3000",
        }

        # Service addresses from node (no LB)
        refreshed_addresses = [("192.1.1.1", 3000, None), ("192.1.1.2", 3000, None)]
        self.info_service_helper_mock.return_value = refreshed_addresses

        result = await self.node.needs_refresh()

        # Should trigger refresh to attempt direct connections
        self.assertTrue(result)

    async def test_service_addresses_compatible_load_balancer_not_in_refreshed(self):
        """Test load balancer scenario where LB is not in refreshed addresses"""
        self.node.ip = "load-balancer.com"
        self.node.port = 3000
        self.node.tls_name = None

        refreshed_addresses = [("192.1.1.1", 3000, None), ("192.1.1.2", 3000, None)]

        result = self.node._service_addresses_compatible(
            refreshed_addresses, "service-clear-std"
        )

        self.assertFalse(result)  # Should trigger refresh

    async def test_service_addresses_compatible_direct_connection_valid(self):
        """Test direct connection when it's in service addresses"""
        self.node.ip = "192.1.1.1"
        self.node.port = 3000
        self.node.tls_name = None

        refreshed_addresses = [("192.1.1.1", 3000, None), ("192.1.1.2", 3000, None)]

        result = self.node._service_addresses_compatible(
            refreshed_addresses, "service-clear-std"
        )

        self.assertTrue(result)  # No refresh needed

    async def test_needs_refresh_admin_node(self):
        """Test needs_refresh for admin nodes"""
        # Override admin node setting (it was set to False during initialization)
        self.node.is_admin_node = True
        self.node.alive = True
        self.node.ip = "192.1.1.1"
        self.node.port = 3000  # Keep original port for test consistency
        self.node.tls_name = None
        self.node.node_id = "A00000000000000"  # Set node ID to match

        mock_socket = AsyncMock()
        self.get_connection_mock.return_value = mock_socket

        # The needs_refresh method will call _get_admin_info_call internally
        # We need to mock the _get_admin_info_call method that exists on the node
        with patch.object(
            self.node, "_get_admin_info_call", return_value="admin-clear-std"
        ) as admin_call_mock:
            self.info_mock.return_value = {
                "node": "A00000000000000",
                "admin-clear-std": "192.1.1.1:3000",
            }
            self.info_service_helper_mock.return_value = [("192.1.1.1", 3000, None)]

            result = await self.node.needs_refresh()

            # The logic should work correctly for admin nodes
            # (admin call usage is tested implicitly through the mocked return)
            self.assertFalse(result)  # Should not need refresh if addresses match

    async def test_needs_refresh_node_id_changed(self):
        """Test needs_refresh when node ID changes"""
        self.node.alive = True
        self.node.node_id = "A00000000000000"

        mock_socket = AsyncMock()
        self.get_connection_mock.return_value = mock_socket

        # Mock different node ID returned
        self.get_service_info_call_mock.return_value = "service-clear-std"
        self.info_mock.return_value = {
            "node": "B11111111111111",  # Different node ID
            "service-clear-std": "192.1.1.1:3000",
        }

        result = await self.node.needs_refresh()

        self.assertTrue(result)  # Should refresh due to node ID change

    async def test_service_addresses_compatible_empty_refreshed_addresses(self):
        """Test handling of empty refreshed service addresses"""
        result = self.node._service_addresses_compatible([], "service-clear-std")

        self.assertFalse(result)  # Should trigger refresh

    async def test_needs_refresh_info_call_exception(self):
        """Test needs_refresh when info call fails"""
        self.node.alive = True
        mock_socket = AsyncMock()
        self.get_connection_mock.return_value = mock_socket

        # Mock info call failure
        self.info_mock.side_effect = Exception("Info call failed")

        result = await self.node.needs_refresh()

        self.assertTrue(result)  # Should refresh on error

    async def test_info_feature_key(self):
        """Test info_feature_key method parsing semicolon-separated response"""
        self.info_mock.return_value = "feature-key-version=2;serial-number=892960312;asdb-compression=true;asdb-encryption-at-rest=false;asdb-xdr=true"
        expected = {
            "feature-key-version": "2",
            "serial-number": "892960312",
            "asdb-compression": "true",
            "asdb-encryption-at-rest": "false",
            "asdb-xdr": "true",
        }

        feature_keys = await self.node.info_feature_key()

        self.info_mock.assert_called_with("feature-key", self.ip)
        self.assertEqual(
            feature_keys,
            expected,
            "info_feature_key error:\n_expected:\t%s\n_found:\t%s"
            % (expected, feature_keys),
        )

    async def test_info_feature_key_empty_response(self):
        """Test info_feature_key with empty response"""
        self.info_mock.return_value = ""
        expected = {}

        feature_keys = await self.node.info_feature_key()

        self.info_mock.assert_called_with("feature-key", self.ip)
        self.assertEqual(feature_keys, expected)

    async def test_info_feature_key_malformed_response(self):
        """Test info_feature_key with malformed response"""
        self.info_mock.return_value = "format=;missing=value;"
        expected = {"format": "", "missing": "value"}

        feature_keys = await self.node.info_feature_key()

        self.info_mock.assert_called_with("feature-key", self.ip)
        self.assertEqual(feature_keys, expected)

    async def test_info_feature_key_error_response(self):
        """Test info_feature_key with ERROR response returns exception due to @async_return_exceptions"""
        self.info_mock.return_value = "ERROR::invalid command"

        result = await self.node.info_feature_key()

        # Due to @async_return_exceptions decorator, exception is returned not raised
        self.assertIsInstance(result, ASInfoResponseError)
        self.info_mock.assert_called_with("feature-key", self.ip)

    async def test_info_feature_key_error_lowercase_response(self):
        """Test info_feature_key with error (lowercase) response returns exception due to @async_return_exceptions"""
        self.info_mock.return_value = "error: not available"

        result = await self.node.info_feature_key()

        # Due to @async_return_exceptions decorator, exception is returned not raised
        self.assertIsInstance(result, ASInfoResponseError)
        self.info_mock.assert_called_with("feature-key", self.ip)


class SocketPoolTest(asynctest.TestCase):
    """Test cases for socket pool FIFO behavior and edge cases"""

    async def setUp(self):
        self.ip = "192.1.1.1"
        self.port = 3000

        # Mock dependencies
        self.get_fully_qualified_domain_name = patch(
            "lib.live_cluster.client.node.get_fully_qualified_domain_name"
        ).start()
        self.async_shell_cmd_mock = patch(
            "lib.live_cluster.client.node.util.async_shell_command"
        ).start()
        getaddrinfo = patch("socket.getaddrinfo")
        self.addCleanup(patch.stopall)

        lib.live_cluster.client.node.Node.info_build = patch(
            "lib.live_cluster.client.node.Node.info_build", AsyncMock()
        ).start()
        socket.getaddrinfo = getaddrinfo.start()

        lib.live_cluster.client.node.Node.info_build.return_value = "5.0.0.11"
        self.get_fully_qualified_domain_name.return_value = "host.domain.local"
        socket.getaddrinfo.return_value = [(2, 1, 6, "", ("192.1.1.1", 3000))]

        # Mock _info_cinfo for Node initialization
        self.init_info_mock = patch.object(
            lib.live_cluster.client.node.Node, "_info_cinfo", new_callable=AsyncMock
        ).start()

        def info_side_effect(*args, **kwargs):
            cmd = args[0]
            if cmd == ["node", "features", "connection"]:
                return {
                    "node": "A00000000000000",
                    "features": "features",
                    "connection": "admin=false",
                }
            elif cmd == ["service-clear-std", "peers-clear-std"]:
                return {
                    "service-clear-std": "192.1.1.1:3000",
                    "peers-clear-std": "2,3000,[[1A0,,[192.1.1.1]]]",
                }
            else:
                return "mock_response"

        self.init_info_mock.side_effect = info_side_effect

        # Create node
        self.node = await Node(self.ip, self.port)
        self.node._initialize_socket_pool()

    async def test_socket_pool_maxlen_behavior(self):
        """Test that socket pool respects maxlen and FIFO behavior"""
        from lib.live_cluster.client.constants import MAX_SOCKET_POOL_SIZE

        # Fill socket pool to max capacity
        for i in range(MAX_SOCKET_POOL_SIZE + 5):  # Add more than max
            mock_sock = AsyncMock()
            mock_sock.name = f"sock_{i}"
            self.node.socket_pool[self.node.port].append(mock_sock)

        # Should only have MAX_SOCKET_POOL_SIZE sockets
        self.assertEqual(
            len(self.node.socket_pool[self.node.port]), MAX_SOCKET_POOL_SIZE
        )

        # Should be FIFO - last sockets should be in pool (oldest ones dropped)
        first_remaining_sock = self.node.socket_pool[self.node.port][0]
        self.assertEqual(first_remaining_sock.name, "sock_5")  # First 5 were dropped

        last_sock = self.node.socket_pool[self.node.port][-1]
        self.assertEqual(last_sock.name, f"sock_{MAX_SOCKET_POOL_SIZE + 4}")

    async def test_get_connection_fifo_order(self):
        """Test that _get_connection returns sockets in FIFO order"""
        # Add sockets in order
        sock1 = AsyncMock()
        sock1.is_connected.return_value = True
        sock1.name = "first"

        sock2 = AsyncMock()
        sock2.is_connected.return_value = True
        sock2.name = "second"

        self.node.socket_pool[self.node.port].append(sock1)
        self.node.socket_pool[self.node.port].append(sock2)

        # Should return first socket (FIFO)
        result = await self.node._get_connection(self.node.ip, self.node.port)
        self.assertEqual(result.name, "first")

    async def test_socket_pool_disconnected_socket_cleanup(self):
        """Test that disconnected sockets are cleaned up properly"""
        # Add disconnected socket first
        disconnected_sock = AsyncMock()
        disconnected_sock.is_connected.return_value = False
        disconnected_sock.name = "disconnected"

        # Add connected socket second
        connected_sock = AsyncMock()
        connected_sock.is_connected.return_value = True
        connected_sock.name = "connected"

        self.node.socket_pool[self.node.port].append(disconnected_sock)
        self.node.socket_pool[self.node.port].append(connected_sock)

        # Should skip disconnected socket and return connected one
        result = await self.node._get_connection(self.node.ip, self.node.port)

        # Disconnected socket should be closed
        disconnected_sock.close.assert_called_once()

        # Should return connected socket
        self.assertEqual(result.name, "connected")


class NodeErrorHandlingTest(asynctest.TestCase):
    """Test error handling for info functions"""

    async def setUp(self):
        self.maxDiff = None
        self.ip = "127.0.0.1"

        # Mock _info_cinfo to control responses
        self.info_mock = patch(
            "lib.live_cluster.client.node.Node._info_cinfo", AsyncMock()
        ).start()

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=RuntimeWarning)
            self.node: Node = await Node(self.ip, timeout=0)

    def tearDown(self):
        patch.stopall()

    # Core info function error tests
    async def test_info_statistics_error_response(self):
        """Test info_statistics handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::statistics not available"

        result = await self.node.info_statistics()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get statistics")
        self.assertEqual(result.raw_response, "ERROR::statistics not available")

    async def test_info_statistics_lowercase_error(self):
        """Test info_statistics handles lowercase error response"""
        self.info_mock.return_value = "error::permission denied"

        result = await self.node.info_statistics()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get statistics")

    async def test_info_namespaces_error_response(self):
        """Test info_namespaces handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::namespaces not accessible"

        result = await self.node.info_namespaces()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get namespaces")
        self.assertEqual(result.raw_response, "ERROR::namespaces not accessible")

    async def test_info_user_agents_error_response(self):
        """Test info_user_agents handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::user-agents not supported"

        result = await self.node.info_user_agents()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get user agents")

    async def test_info_namespace_statistics_error_response(self):
        """Test info_namespace_statistics handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::namespace test not found"

        result = await self.node.info_namespace_statistics("test")

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get namespace statistics for test")

    async def test_info_health_outliers_error_response(self):
        """Test info_health_outliers handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::health-outliers not available"

        result = await self.node.info_health_outliers()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get health outliers")

    async def test_info_best_practices_error_response(self):
        """Test info_best_practices handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::best-practices not supported"

        result = await self.node.info_best_practices()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get best practices")

    async def test_info_bin_statistics_error_response(self):
        """Test info_bin_statistics handles ERROR response correctly"""
        with patch.object(self.node, "info_build", AsyncMock()) as mock_build:
            mock_build.return_value = "6.4.0.1"  # Pre-7.0
            self.info_mock.return_value = "ERROR::bins not available"

            result = await self.node.info_bin_statistics()

            self.assertIsInstance(result, ASInfoResponseError)
            self.assertEqual(result.message, "Failed to get bin statistics")

    async def test_info_dc_statistics_error_response(self):
        """Test info_dc_statistics handles ERROR response correctly"""
        with patch.object(self.node, "info_build", AsyncMock()) as mock_build:
            mock_build.return_value = "6.4.0.1"  # Pre-XDR5
            self.info_mock.return_value = "ERROR::dc DC1 not found"

            result = await self.node.info_dc_statistics("DC1")

            self.assertIsInstance(result, ASInfoResponseError)
            self.assertEqual(result.message, "Failed to get DC statistics for DC1")

    async def test_info_xdr_statistics_error_response(self):
        """Test info_XDR_statistics handles ERROR response correctly"""
        with patch.object(self.node, "info_build", AsyncMock()) as mock_build:
            mock_build.return_value = "4.9.0.1"  # Pre-XDR5 (XDR5 is 5.0+)
            self.info_mock.return_value = "ERROR::XDR not enabled"

            result = await self.node.info_XDR_statistics()

            self.assertIsInstance(result, ASInfoResponseError)
            self.assertEqual(result.message, "Failed to get XDR statistics")

    async def test_info_logs_ids_error_response(self):
        """Test info_logs_ids handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::logs not accessible"

        result = await self.node.info_logs_ids()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get log IDs")

    async def test_info_xdr_config_error_response(self):
        """Test info_xdr_config handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::XDR config not available"

        result = await self.node.info_xdr_config()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get XDR config")

    async def test_info_sindex_list_error_response(self):
        """Test info_sindex handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::sindex not supported"

        result = await self.node.info_sindex()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get sindex list")

    async def test_info_all_set_statistics_error_response(self):
        """Test info_all_set_statistics handles ERROR response correctly"""
        self.info_mock.return_value = "ERROR::sets not available"

        result = await self.node.info_all_set_statistics()

        self.assertIsInstance(result, ASInfoResponseError)
        self.assertEqual(result.message, "Failed to get set statistics")

    # Edge case tests
    async def test_info_functions_with_empty_error_response(self):
        """Test functions handle empty ERROR responses"""
        self.info_mock.return_value = "ERROR"

        result = await self.node.info_statistics()

        self.assertIsInstance(result, ASInfoResponseError)

    async def test_info_functions_with_mixed_case_error(self):
        """Test functions don't trigger on mixed case like 'Error'"""
        self.info_mock.return_value = "Error: not an aerospike error format"

        result = await self.node.info_statistics()

        # Should NOT be treated as error since it's not ERROR or error
        self.assertIsInstance(result, dict)

    async def test_info_functions_with_error_in_middle(self):
        """Test functions don't trigger on ERROR in middle of response"""
        self.info_mock.return_value = "valid-data;ERROR=something;more-data"

        result = await self.node.info_statistics()

        # Should NOT be treated as error since ERROR is not at start
        self.assertIsInstance(result, dict)

    async def test_info_error_checking_performance_with_large_response(self):
        """Test error checking doesn't impact performance with large responses"""
        large_response = "data=" + "x" * 100000  # 100KB response
        self.info_mock.return_value = large_response

        import time

        start_time = time.time()
        result = await self.node.info_statistics()
        end_time = time.time()

        # Should be very fast since it only checks first characters
        self.assertLess(end_time - start_time, 0.1)  # Less than 100ms (generous for CI)
        self.assertIsInstance(result, dict)

    # Dependency error handling tests
    async def test_info_set_config_namespace_with_namespaces_error(self):
        """Test info_set_config_namespace when info_namespaces returns error"""
        # Mock info_namespaces to return an error
        with patch.object(self.node, "info_namespaces", AsyncMock()) as mock_namespaces:
            with patch.object(self.node, "info_build", AsyncMock()) as mock_build:
                mock_build.return_value = "6.4.0.1"
                mock_namespaces.return_value = ASInfoResponseError(
                    "Failed", "ERROR::no access"
                )
                self.info_mock.return_value = "error::config failed"

                result = await self.node.info_set_config_namespace(
                    "param", "value", "test-ns"
                )

                # Should handle the namespace error gracefully - in this case it returns ASInfoResponseError
                # because the namespace check fails (which is the expected behavior)
                self.assertIsInstance(result, ASInfoResponseError)
                self.assertEqual(
                    result.response, "no access"
                )  # preserve the original error message

    # Backward compatibility tests
    async def test_existing_error_handling_still_works(self):
        """Test that existing error handling patterns continue to work"""
        # Test functions that already had error checking
        self.info_mock.return_value = "ERROR::roster not available"

        result = await self.node.info_roster("test-ns")

        # Should still work as before
        self.assertIsInstance(result, ASInfoResponseError)

    async def test_async_return_exceptions_decorator_behavior(self):
        """Test that @async_return_exceptions decorator still works correctly"""
        self.info_mock.return_value = "ERROR::test error"

        # Should return exception object, not raise it
        result = await self.node.info_statistics()

        self.assertIsInstance(result, ASInfoResponseError)
        # Should not have raised an exception - if it did, test would fail

    async def test_successful_responses_still_work(self):
        """Test that successful responses continue to work normally"""
        self.info_mock.return_value = "cs=2;ck=71;ci=false"

        result = await self.node.info_statistics()

        self.assertIsInstance(result, dict)
        self.assertEqual(result["cs"], "2")
        self.assertEqual(result["ck"], "71")


if __name__ == "__main__":
    unittest.main()
