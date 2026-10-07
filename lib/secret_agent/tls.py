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

import ssl

from lib.secret_agent.errors import InvalidConfigError


def new_ssl_context(ca_file: str) -> ssl.SSLContext:
    """Build a client SSLContext that verifies the agent against a CA, with
    TLS 1.2 or later.

    Args:
        ca_file: PEM CA file the agent certificate is verified against.

    Returns:
        The context, for SecretAgentClient's ssl_context.

    Raises:
        InvalidConfigError: ca_file cannot be loaded.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        ctx.load_verify_locations(cafile=ca_file)
    except (OSError, ValueError, ssl.SSLError) as e:
        reason = getattr(e, "strerror", None) or str(e)
        raise InvalidConfigError(
            "cannot load TLS CA file {}: {}".format(ca_file, reason)
        ) from e

    return ctx
