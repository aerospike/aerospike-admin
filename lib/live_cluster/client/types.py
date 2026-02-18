# Copyright 2021-2025 Aerospike, Inc.
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

from enum import IntEnum, unique
import logging

logger = logging.getLogger(__name__)

Addr_Port_TLSName = tuple[str, int, str | None]


@unique
class ASCommand(IntEnum):
    AUTHENTICATE = 0
    CREATE_USER = 1
    DROP_USER = 2
    SET_PASSWORD = 3
    CHANGE_PASSWORD = 4
    GRANT_ROLES = 5
    REVOKE_ROLES = 6
    QUERY_USERS = 9
    CREATE_ROLE = 10
    DELETE_ROLE = 11
    ADD_PRIVLEGES = 12
    DELETE_PRIVLEGES = 13
    SET_WHITELIST = 14
    SET_RATE_QUOTAS = 15
    QUERY_ROLES = 16
    LOGIN = 20


@unique
class ASField(IntEnum):
    USER = 0
    PASSWORD = 1
    OLD_PASSWORD = 2
    CREDENTIAL = 3
    CLEAR_PASSWORD = 4
    SESSION_TOKEN = 5
    SESSION_TTL = 6
    AUTH_MODE = 7
    ROLES = 10
    ROLE = 11
    PRIVILEGES = 12
    WHITELIST = 13
    READ_QUOTA = 14
    WRITE_QUOTA = 15
    READ_INFO = 16
    WRITE_INFO = 17
    CONNECTIONS = 18


@unique
class ASPrivilege(IntEnum):
    USER_ADMIN = 0
    SYS_ADMIN = 1
    DATA_ADMIN = 2
    UDF_ADMIN = 3
    SINDEX_ADMIN = 4
    READ = 10
    READ_WRITE = 11
    READ_WRITE_UDF = 12
    WRITE = 13
    TRUNCATE = 14
    MASKING_ADMIN = 15
    READ_MASKED = 16
    WRITE_MASKED = 17
    ERROR = 255

    @classmethod
    def str_to_enum(cls, privilege_str):
        privilege_str = privilege_str.lower()
        privilege_str = privilege_str.replace("_", "-")

        str_to_enum_map = {
            "user-admin": cls.USER_ADMIN,
            "sys-admin": cls.SYS_ADMIN,
            "data-admin": cls.DATA_ADMIN,
            "udf-admin": cls.UDF_ADMIN,
            "sindex-admin": cls.SINDEX_ADMIN,
            "read": cls.READ,
            "read-write": cls.READ_WRITE,
            "read-write-udf": cls.READ_WRITE_UDF,
            "write": cls.WRITE,
            "truncate": cls.TRUNCATE,
            "masking-admin": cls.MASKING_ADMIN,
            "read-masked": cls.READ_MASKED,
            "write-masked": cls.WRITE_MASKED,
        }

        if privilege_str in str_to_enum_map:
            return str_to_enum_map[privilege_str]
        else:
            return cls.ERROR

    def is_global_only_scope(self):
        return (
            self == ASPrivilege.DATA_ADMIN
            or self == ASPrivilege.SYS_ADMIN
            or self == ASPrivilege.USER_ADMIN
            or self == ASPrivilege.UDF_ADMIN
            or self == ASPrivilege.SINDEX_ADMIN
        )

    def __str__(self):
        name = self.name.lower()
        name = name.replace("_", "-")
        return name


@unique
class ASResponse(IntEnum):
    _return_code_value: int | None
    ERROR_RESPONSE_CODE = -1
    OK = 0
    UNKNOWN_SERVER_ERROR = 1
    QUERY_END = 50  # Signal end of a query response. Is OK
    SECURITY_NOT_SUPPORTED = 51
    SECURITY_NOT_ENABLED = 52
    INVALID_COMMAND = 54
    UNRECOGNIZED_FIELD_ID = 55
    VALID_BUT_UNEXPECTED_COMMANDS = 56
    NO_USER_OR_UNRECOGNIZED_USER = 60
    USER_ALREADY_EXISTS = 61
    NO_PASSWORD_OR_BAD_PASSWORD = 62
    EXPIRED_PASSWORD = 63
    FORBIDDEN_PASSWORD = 64
    NO_CREDENTIAL_OR_BAD_CREDENTIAL = 65
    EXPIRED_SESSION = 66
    NO_ROLE_OR_INVALID_ROLE = 70
    ROLE_ALREADY_EXISTS = 71
    NO_PRIVILEGES_OR_UNRECOGNIZED_PRIVILEGES = 72
    BAD_WHITELIST = 73
    QUOTAS_NOT_ENABLED = 74
    BAD_RATE_QUOTA = 75
    NOT_AUTHENTICATED = 80
    ROLE_OR_PRIVILEGE_VIOLATION = 81
    NOT_WHITELISTED = 82
    RATE_QUOTA_EXCEEDED = 83
    ERROR_IN_LDAP_SETUP = 91  # 	Error in LDAP setup.	EE 4.1.0.1
    ERROR_IN_LDAP_TLS_SETUP = 92  # 	Error in LDAP TLS setup.	EE 4.1.0.1
    UNABLE_TO_AUTHENTICATE_LDAP_USER = 93  # 	Error authenticating LDAP user.	EE 4.1.0.1
    ERROR_QUERYING_LDAP_SERVER = 94  # 	Error querying LDAP server.

    @classmethod
    def _missing_(cls, value):
        if isinstance(value, int):
            asr = cls.ERROR_RESPONSE_CODE
            asr._return_code_value = value
            return asr

        return super()._missing_(value)

    def __str__(self):
        lower = self.name.lower().split("_")
        lower = " ".join(lower)
        lower = lower[0].upper() + lower[1:]

        if self.value == ASResponse.ERROR_RESPONSE_CODE:
            lower += " ({})".format(self._return_code_value)

        return lower


class ASProtocolError(Exception):
    def __init__(self, as_response, message):
        self.message = message + " : " + str(ASResponse(as_response)) + "."
        self.as_response = as_response
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message

    def __eq__(self, o: object) -> bool:
        if (
            isinstance(o, ASProtocolError)
            and self.message == o.message
            and self.as_response == o.as_response
        ):
            return True

        return False


class ASProtocolConnectionError(ASProtocolError):
    pass


class ASProtocolExcFactory:
    @staticmethod
    def create_exc(as_response, message):
        if as_response in {
            ASResponse.NO_USER_OR_UNRECOGNIZED_USER,
            ASResponse.EXPIRED_PASSWORD,
            ASResponse.NO_CREDENTIAL_OR_BAD_CREDENTIAL,
            ASResponse.NOT_AUTHENTICATED,
            ASResponse.NOT_WHITELISTED,
            ASResponse.EXPIRED_SESSION,
        }:
            return ASProtocolConnectionError(as_response, message)

        return ASProtocolError(as_response, message)


ASINFO_RESPONSE_OK = "ok"
GENERIC_ERROR_MSG = "Unknown error occurred"


class ASInfoError(Exception):
    def __init__(self, message: str, response: str | None = None):
        self.message = message
        self.response = response

    def __str__(self):
        if self.response:
            return "{} : {}.".format(self.message, self.response)
        else:
            return "{}.".format(self.message)

    def __eq__(self, o: object) -> bool:
        if (
            isinstance(o, ASInfoError)
            and self.message == o.message
            and self.response == o.response
        ):
            return True

        return False


class ASInfoResponseError(ASInfoError):
    def __init__(self, message: str, server_resp: str):
        self.raw_response = server_resp

        # Success can either be "ok", "OK", or "" :(
        if server_resp.lower() in {ASINFO_RESPONSE_OK, ""}:
            raise ValueError('info() returned value "ok" which is not an error.')

        try:
            # sometimes there is a message with 'error' and sometimes not. i.e. set-config, udf-put
            if server_resp.startswith("error") or server_resp.startswith("ERROR"):
                try:
                    server_resp = server_resp.split("=")[1]
                except IndexError:
                    server_resp = server_resp.split(":")[2]

            elif server_resp.startswith("fail") or server_resp.startswith("FAIL"):
                server_resp = server_resp.split(":")[2]

            clean_resp = server_resp.strip(" .")

        except IndexError:
            clean_resp = GENERIC_ERROR_MSG

        super().__init__(message, clean_resp)

    def __eq__(self, o: object) -> bool:
        if (
            isinstance(o, ASInfoResponseError)
            and self.raw_response == o.raw_response
            and super().__eq__(o)
        ):
            return True

        return False


class ASInfoConfigError(ASInfoResponseError):
    def __init__(self, message, resp, node, context, param, value):
        self.message = message
        self.response = GENERIC_ERROR_MSG

        is_valid_context, invalid_context = self._check_context(node, context[:])

        if not is_valid_context:
            self.response = "Invalid subcontext {}".format(invalid_context)
            return

        # Check if the server response contains a specific error first
        # This ensures actual server errors (like role violations) are shown
        # instead of being overridden by generic validation errors
        if resp and resp.lower() not in {ASINFO_RESPONSE_OK, ""}:
            # Use the parent class to process the server response
            super().__init__(message, resp)
            return

        config_type = node.config_type(context[:], param)

        logger.debug("Found config type %s for param %s", str(config_type), param)

        if config_type is None:
            self.response = "Invalid parameter"
            return

        if not config_type.dynamic:
            self.response = "Parameter is not dynamically configurable"
            return

        if not config_type.validate(value):
            self.response = "Invalid value for {}".format(str(config_type))
            return

        super().__init__(message, resp)

    def _check_context(self, node, subcontexts):
        current_context = []

        while subcontexts:
            next_subcontext = subcontexts.pop(0)

            valid_subcontexts = node.config_subcontext(current_context[:])

            if next_subcontext not in valid_subcontexts:
                return False, next_subcontext

            current_context.append(next_subcontext)

        return True, ""


class ASInfoNotAuthenticatedError(ASInfoResponseError):
    pass


class ASInfoClusterStableError(ASInfoResponseError):
    def __init__(self, server_resp: str):
        super().__init__("Cluster is unstable", server_resp)
