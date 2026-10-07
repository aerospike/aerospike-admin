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

from dataclasses import dataclass

from lib.secret_agent.errors import InvalidConfigError

SECRET_PREFIX = "secrets:"


@dataclass(frozen=True)
class SecretRef:
    """A parsed secrets:[<resource>:]<key> reference."""

    resource: str
    key: str

    def __str__(self) -> str:
        if not self.resource:
            return SECRET_PREFIX + self.key

        return "{}{}:{}".format(SECRET_PREFIX, self.resource, self.key)


def is_secret(value: str) -> bool:
    """Report whether value is a secrets: reference rather than a literal.

    Args:
        value: An option value.

    Returns:
        True when value starts with secrets:.
    """
    return value.startswith(SECRET_PREFIX)


def parse_ref(value: str) -> SecretRef:
    """Parse secrets:[<resource>:]<key>.

    Like the Aerospike C tools, this splits on the last colon, so the resource
    may itself contain colons (an AWS ARN, for example).

    Args:
        value: The reference.

    Returns:
        The parsed reference. Its resource is empty when value has none.

    Raises:
        InvalidConfigError: value is not a reference or has an empty key.
    """
    if not is_secret(value):
        # Do not echo the value: it may be a literal password.
        raise InvalidConfigError(
            "not a secret reference, expected {}[<resource>:]<key>".format(
                SECRET_PREFIX
            )
        )

    resource, _, key = value[len(SECRET_PREFIX) :].rpartition(":")

    if not key:
        raise InvalidConfigError("secret reference {} has an empty key".format(value))

    return SecretRef(resource, key)
