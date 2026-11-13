# Copyright 2026 Aerospike, Inc.
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
"""Client for the Aerospike Secret Agent.

Resolves secrets:[<resource>:]<key> references the way the Aerospike C tools
do. The package uses only the standard library and imports nothing else from
asadm, so moving it out only needs the lib.secret_agent import prefix renamed.

    from lib.secret_agent import SecretAgentClient, new_ssl_context

    client = SecretAgentClient(
        "127.0.0.1", 3005, ssl_context=new_ssl_context("/etc/aerospike/sa-ca.pem")
    )
    password = client.resolve("secrets:aerospike:password")
"""

from lib.secret_agent.address import (
    DEFAULT_HOST,
    DEFAULT_PORT,
    parse_address,
    parse_port,
)
from lib.secret_agent.client import DEFAULT_TIMEOUT, SecretAgentClient
from lib.secret_agent.errors import (
    InvalidConfigError,
    InvalidResponseError,
    RequestFailedError,
    SecretAgentError,
)
from lib.secret_agent.ref import SECRET_PREFIX, SecretRef, is_secret, parse_ref
from lib.secret_agent.tls import new_ssl_context

__all__ = [
    "DEFAULT_HOST",
    "DEFAULT_PORT",
    "DEFAULT_TIMEOUT",
    "SECRET_PREFIX",
    "InvalidConfigError",
    "InvalidResponseError",
    "RequestFailedError",
    "SecretAgentClient",
    "SecretAgentError",
    "SecretRef",
    "is_secret",
    "new_ssl_context",
    "parse_address",
    "parse_port",
    "parse_ref",
]
