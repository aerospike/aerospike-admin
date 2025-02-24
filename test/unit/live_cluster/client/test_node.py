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
            if cmd == ["node", "service-clear-std", "features", "peers-clear-std"]:
                return {
                    "node": "A00000000000000",
                    "service-clear-std": "192.3.3.3:4567",
                    "peers-clear-std": "2,3000,[[1A0,,[3.126.208.136]]]",
                    "features": "features",
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
            if cmd == ["node", "service-clear-std", "features", "peers-clear-std"]:
                return {
                    "node": "A00000000000000",
                    "service-clear-std": "192.3.3.3:4567",
                    "peers-clear-std": "2,3000,[[1A0,,[3.126.208.136]]]",
                    "features": "features",
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
            if args[0] == ["node", "service-clear-std", "features", "peers-clear-std"]:
                return {
                    "node": "A0",
                    "service-clear-std": "1.1.1.1:3000;172.17.0.1:3000;172.17.1.1:3000",
                    "peers-clear-std": "10,3000,[[BB9050011AC4202,,[172.17.0.1]],[BB9070011AC4202,,[[2001:db8:85a3::8a2e]:6666]]]",
                    "features": "batch-index;blob-bits;cdt-list;cdt-map;cluster-stable;float;geo;",
                }

        as_socket_mock_used_for_login.info.side_effect = side_effect_info

        await Node("1.1.1.1", user="user")
        as_socket_mock_used_for_login.login.assert_called_once()
        # Login and the first info call used different sockets
        as_socket_mock_used_for_login.info.assert_has_calls(
            [
                call(
                    ["node", "service-clear-std", "features", "peers-clear-std"],
                )
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
        self.assertEqual(self.node.socket_pool, {self.node.port: set()})

        self.assertTrue(await self.node.login())

        as_socket_mock.close.assert_not_called()
        self.assertEqual(self.node.socket_pool, {self.node.port: set([as_socket_mock])})
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
        self.node.socket_pool[self.node.port].add(as_socket_mock2)
        self.node.socket_pool[self.node.port].add(as_socket_mock1)

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
        self.node.socket_pool[self.node.port].add(as_socket_in_pool)

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
        self.info_mock.assert_any_call("alumni-clear-std", "192.1.1.1")
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
        self.info_mock.assert_any_call("alumni-tls-std", "192.1.1.1")
        self.info_mock.assert_any_call("peers-tls-alt", "192.1.1.1")
        self.assertEqual(
            sorted(peers_list),
            sorted(expected),
            "info_peers_list(peers-alumni with tls enabled) did not return the expected result",
        )

        self.node.enable_tls = False
        self.node.consider_alumni = False

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

    async def test_info_bin_statistics(self):
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

    async def test_info_XDR_statistics_with_server_pre_xdr5(self):
        self.info_mock.reset_mock()
        lib.live_cluster.client.node.Node.info_build.return_value = "2.5.6"
        self.info_mock.side_effect = ["a=b;c=1;2=z"]
        self.node.features = "xdr"
        expected = {"a": "b", "c": "1", "2": "z"}

        actual = await self.node.info_XDR_statistics()

        self.assertEqual(self.info_mock.call_count, 1)
        self.info_mock.assert_any_call("statistics/xdr", self.ip)
        self.assertDictEqual(actual, expected)

    @patch("lib.live_cluster.client.node.Node.info_all_dc_statistics")
    async def test_info_XDR_statistics_xdr5(self, info_all_dc_statistics_mock):
        lib.live_cluster.client.node.Node.info_build.return_value = "5.0.0.1"
        actual = await self.node.info_XDR_statistics()

        self.assertEqual(lib.live_cluster.client.node.Node.info_build.call_count, 1)
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
        self.assertEqual(
            actual.message, "Failed to set namespace configuration parameter foo to bar"
        )
        self.assertEqual(actual.response, "Namespace does not exist")

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
        self.info_mock.assert_any_call(
            "latencies:hist=benchmarks-fabric", self.ip
        )
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
        self.node.features = "xdr"

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

        self.node.features = ["xdr"]

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

        self.info_mock.assert_called_with("sindex", self.ip)
        self.assertListEqual(actual, expected)

    async def test_info_sindex_statistics(self):
        self.info_mock.return_value = "a=b;c=d;e=f"
        expected = {"a": "b", "c": "d", "e": "f"}

        actual = await self.node.info_sindex_statistics("foo", "bar")

        self.info_mock.assert_called_with("sindex/{}/{}".format("foo", "bar"), self.ip)
        self.assertDictEqual(actual, expected)

    async def test_info_sindex_create_success(self):
        self.info_mock.return_value = "OK"
        expected_call = (
            "sindex-create:indexname=iname;ns=ns;indexdata=data1,data2".format()
        )

        actual = await self.node.info_sindex_create("iname", "ns", "data1", "data2")

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
        )

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_sindex_create_fail(self):
        self.info_mock.return_value = "FAIL:4: Invalid indexdata"

        actual = await self.node.info_sindex_create("iname", "ns", "data1", "data2")

        self.assertEqual(actual.message, "Failed to create sindex iname")
        self.assertEqual(actual.response, "Invalid indexdata")

    async def test_info_sindex_delete_success(self):
        self.info_mock.return_value = "OK"
        expected_call = "sindex-delete:ns={};indexname={}".format(
            "ns",
            "iname",
        )

        actual = await self.node.info_sindex_delete("iname", "ns")

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

        self.info_mock.return_value = "OK"
        expected_call = "sindex-delete:ns={};set={};indexname={}".format(
            "ns",
            "set",
            "iname",
        )

        actual = await self.node.info_sindex_delete("iname", "ns", set_="set")

        self.info_mock.assert_called_with(expected_call, self.ip)
        self.assertEqual(actual, ASINFO_RESPONSE_OK)

    async def test_info_sindex_delete_fail(self):
        self.info_mock.return_value = "FAIL:4: Invalid indexname"

        actual = await self.node.info_sindex_delete("iname", "ns")

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
        self.node.features = ["query-show"]
        self.info_mock.return_value = "foo"
        old = "old"
        new = "new"

        actual = await self.node._jobs_helper(old, new)

        self.info_mock.assert_called_with("new", self.ip)
        self.assertEqual(actual, "foo")

    async def test_jobs_helper_uses_old(self):
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
        self.node.features = ["query-show"]
        self.info_mock.return_value = "OK - number of scans killed: 7"
        expected = "ok - number of scans killed: 7"

        actual = await self.node.info_scan_abort_all()

        self.info_mock.assert_called_with("scan-abort-all:", self.ip)
        self.assertEqual(actual, expected)

    async def test_info_scan_abort_all_with_feature_present_and_error(self):
        self.node.features = ["query-show"]
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


if __name__ == "__main__":
    unittest.main()
