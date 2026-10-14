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
"""Exceptions raised by the Secret Agent client.

Every error is a SecretAgentError. Messages name the secret reference, never
the secret value.
"""


class SecretAgentError(Exception):
    """Base class for all Secret Agent client errors."""


class InvalidConfigError(SecretAgentError):
    """A client setting, TLS file or secret reference cannot be used."""


class RequestFailedError(SecretAgentError):
    """The agent could not be reached, the exchange failed or timed out, or the
    agent answered with an error."""


class InvalidResponseError(SecretAgentError):
    """The response breaks the agent protocol or holds an unusable secret."""
