import logging
import traceback
from sys import exit


from lib.view import terminal


class BaseLogger(logging.Logger, object):
    execute_only_mode = False

    def __init__(self, name, level=logging.WARNING):
        return super().__init__(name, level=level)

    def _handle_exception(self, msg):
        if (
            isinstance(msg, Exception)
            and not isinstance(msg, ShellException)
            and not isinstance(msg, ASProtocolError)
            and not isinstance(msg, ASInfoError)
        ):
            traceback.print_exc()

    def error(self, msg, *args, **kwargs):
        super().error(msg, *args, **kwargs)

        if self.level <= logging.ERROR:
            self._handle_exception(msg)

            if self.execute_only_mode:
                exit(2)

    def critical(self, msg, *args, **kwargs):
        super().critical(msg, args, kwargs)

        if self.level <= logging.CRITICAL:
            self._handle_exception(msg)

        exit(1)


class LogFormatter(logging.Formatter):
    def __init__(self, fmt="%(levelno)s: %(msg)s"):
        super().__init__(fmt=fmt, datefmt=None, style="%")

    def _format_message(self, msg, level, color=None, *args):
        try:
            message = str(msg).format(*args)
        except Exception:
            message = str(msg)

        message = level + ": " + message

        if color == "red":
            message = terminal.fg_red() + message + terminal.fg_clear()

        if color == "yellow":
            message = terminal.fg_yellow() + message + terminal.fg_clear()

        return message

    def format(self, record: logging.LogRecord):
        if record.levelno == logging.DEBUG:
            return self._format_message(record.msg, "DEBUG", None, *record.args)
        elif record.levelno == logging.INFO:
            return self._format_message(record.msg, "INFO", None, *record.args)
        elif record.levelno == logging.WARNING:
            return self._format_message(record.msg, "WARNING", "yellow", *record.args)
        elif record.levelno == logging.ERROR:
            return self._format_message(record.msg, "ERROR", "red", *record.args)
        elif record.levelno == logging.CRITICAL:
            return self._format_message(record.msg, "ERROR", "red", *record.args)

        formatter = logging.Formatter(self._style._fmt)
        return formatter.format(record)


logging.setLoggerClass(BaseLogger)
logging.basicConfig()
logger = logging.getLogger("asadm")
logger.propagate = False
logger.setLevel(logging.DEBUG)
logging_handler = logging.StreamHandler()
logging_handler.setLevel(logging.INFO)
logging_handler.setFormatter(LogFormatter())
logger.addHandler(logging_handler)


class DebugFormatter(logging.Formatter):
    def __init__(self, fmt="%(levelno)s: %(msg)s"):
        super().__init__(fmt=fmt, datefmt=None, style="%")

    def format(self, record: logging.LogRecord):
        original_fmt = self._style._fmt
        result = None

        if record.levelno == logging.DEBUG:
            path_split = record.pathname.split("lib")

            if len(path_split) > 1:
                record.pathname = "lib" + record.pathname.split("lib")[1]
                self._style._fmt = (
                    "{%(pathname)s:%(lineno)d} %(levelname)s - %(message)s"
                )
            else:
                self._style._fmt = (
                    "{%(filename)s:%(lineno)d} %(levelname)s - %(message)s"
                )

        formatter = logging.Formatter(self._style._fmt)
        result = formatter.format(record)
        self._style._fmt = original_fmt

        return result


# must be imported after logger instantiation
from lib.base_controller import (  # noqa: E402 - suppress flake warning
    ShellException,
)
from lib.live_cluster.client import (  # noqa: E402 - suppress flake warning
    ASProtocolError,
    ASInfoError,
)
