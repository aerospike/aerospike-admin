# Copyright 2021-2023 Aerospike, Inc.
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

import logging
from distutils import debug
from enum import Enum
import traceback
from sys import exit
from typing import Optional


from lib.view import terminal

exit_code = 0


def get_exit_code():
    global exit_code
    return exit_code


def set_exit_code(code):
    global exit_code
    exit_code = code


class BaseLogger(logging.Logger, object):
    def _handle_exception(self, msg):
        if (
            isinstance(msg, Exception)
            and not isinstance(msg, ShellException)
            and not isinstance(msg, ASProtocolError)
            and not isinstance(msg, ASInfoError)
        ):
            traceback.print_exc()

    def debug(self, msg, *args, **kwargs):
        kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 1

        super().debug(msg, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        super().error(msg, *args, **kwargs)

        if self.level <= logging.ERROR:
            self._handle_exception(msg)
            set_exit_code(2)

    def critical(self, msg, *args, **kwargs):
        super().critical(msg, *args, **kwargs)

        if self.level <= logging.CRITICAL:
            self._handle_exception(msg)
            set_exit_code(1)


class _LogColors(Enum):
    red = "red"
    yellow = "yellow"


class LogFormatter(logging.Formatter):
    def __init__(self, fmt="%(levelno)s: %(msg)s"):
        super().__init__(fmt=fmt)

    def _format_message(self, msg, level, color: Optional[_LogColors], args):
        try:
            message = str(msg) % args
        except Exception:
            message = str(msg)

        message = level + ": " + message

        if color == _LogColors.red:
            message = terminal.fg_red() + message + terminal.fg_clear()

        if color == _LogColors.yellow:
            message = terminal.fg_yellow() + message + terminal.fg_clear()

        return message

    def format(self, record: logging.LogRecord):
        if record.levelno == logging.DEBUG:
            path_split = record.pathname.split("lib")

            if len(path_split) > 1:
                path = "lib" + record.pathname.split("lib")[1]
            else:
                path = record.filename

            msg = self._format_message(
                f"{{{path}:{record.lineno}}} - {record.msg}",
                "DEBUG",
                None,
                record.args,
            )

            if record.exc_info:
                exc = traceback.format_exception(*record.exc_info)
                for line in exc:
                    for subline in line.split("\n"):
                        if subline:
                            msg += "\n" + self._format_message(
                                f"{{{path}:{record.lineno}}} - {subline}",
                                "DEBUG",
                                None,
                                record.args,
                            )
                    msg += "\n" + self._format_message(
                        f"{{{path}:{record.lineno}}} -",
                        "DEBUG",
                        None,
                        record.args,
                    )

            return msg

        elif record.levelno == logging.INFO:
            return self._format_message(record.msg, "INFO", None, record.args)
        elif record.levelno == logging.WARNING:
            return self._format_message(
                record.msg, "WARNING", _LogColors.yellow, record.args
            )
        elif record.levelno == logging.ERROR:
            return self._format_message(
                record.msg, "ERROR", _LogColors.red, record.args
            )
        elif record.levelno == logging.CRITICAL:
            return self._format_message(
                record.msg, "ERROR", _LogColors.red, record.args
            )

        formatter = logging.Formatter(self._style._fmt)
        return formatter.format(record)


logging.setLoggerClass(BaseLogger)
logger = logging.getLogger("lib")
logger.propagate = False
logger.setLevel(
    logging.WARNING
)  # This only allows WARNING and above to be logged to handlers
stderr_log_handler = logging.StreamHandler()
stderr_log_handler.setLevel(
    logging.WARNING
)  # This only allows WARNING and above to be logged to stderr.
stderr_log_handler.setFormatter(LogFormatter())
logger.addHandler(stderr_log_handler)


# must be imported after logger instantiation
from lib.base_controller import (  # noqa: E402 - suppress flake warning
    ShellException,
)
from lib.live_cluster.client import (  # noqa: E402 - suppress flake warning
    ASProtocolError,
    ASInfoError,
)
