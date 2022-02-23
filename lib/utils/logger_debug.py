import logging


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


def get_debug_logger(name, level=logging.DEBUG):
    logger = logging.getLogger(name)
    logger.propagate = False
    logger.setLevel(level)
    logger_handler = logging.StreamHandler()
    logger_handler.setFormatter(DebugFormatter())
    logger.addHandler(logger_handler)
    return logger
