# Copyright 2022-2023 Aerospike, Inc.
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
