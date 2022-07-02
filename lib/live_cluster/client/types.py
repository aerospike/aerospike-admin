from enum import IntEnum, unique
import logging
from typing import Literal, Union

Addr_Port_TLSName = tuple[str, int, str]


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

    def __str__(self):
        lower = self.name.lower().split("_")
        lower = " ".join(lower)
        lower = lower[0].upper() + lower[1:]
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


ASINFO_RESPONSE_OK = "ok"


class ASInfoError(Exception):
    generic_error = "Unknown error occurred"

    def __init__(self, message, response):
        self.message = message
        self.raw_response = response

        # Success can either be "ok", "OK", or "" :(
        if response.lower() in {ASINFO_RESPONSE_OK, ""}:
            raise ValueError('info() returned value "ok" which is not an error.')

        try:
            # sometimes there is a message with 'error' and sometimes not. i.e. set-config, udf-put
            if response.startswith("error") or response.startswith("ERROR"):
                try:
                    response = response.split("=")[1]
                except IndexError:
                    response = response.split(":")[2]

            elif response.startswith("fail") or response.startswith("FAIL"):
                response = response.split(":")[2]

            self.response = response.strip(" .")

        except IndexError:
            self.response = self.generic_error

    def __str__(self):
        return "{} : {}.".format(self.message, self.response)

    def __eq__(self, o: object) -> bool:
        if (
            isinstance(o, ASInfoError)
            and self.message == o.message
            and self.response == o.response
            and self.raw_response == o.raw_response
        ):
            return True

        return False


class ASInfoConfigError(ASInfoError):
    def __init__(self, message, resp, node, context, param, value):
        self.message = message
        self.response = super().generic_error
        self.logger = logging.getLogger("asadm")

        is_valid_context, invalid_context = self._check_context(node, context[:])

        if not is_valid_context:
            self.response = "Invalid subcontext {}".format(invalid_context)
            return

        config_type = node.config_type(context[:], param)

        self.logger.debug("Found config type %s for param %s", str(config_type), param)

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


class ASInfoNotAuthenticatedError(ASInfoError):
    pass


class ASInfoClusterStableError(ASInfoError):
    pass


SIndexBinType = Union[Literal["NUMERIC"], Literal["GEO2DSPHERE"], Literal["STRING"]]
