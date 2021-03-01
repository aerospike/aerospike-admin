# Copyright 2013-2021 Aerospike, Inc.
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

import signal
import subprocess

DEFAULT_TIMEOUT = 5.0


class TimeoutException(Exception):

    """A timeout has occurred."""

    pass


class call_with_timeout:
    def __init__(self, function, timeout=DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.function = function

    def handler(self, signum, frame):
        raise TimeoutException()

    def __call__(self, *args):
        # get the old SIGALRM handler
        old = signal.signal(signal.SIGALRM, self.handler)
        # set the alarm
        signal.setitimer(signal.ITIMER_REAL, self.timeout)
        try:
            result = self.function(*args)
        finally:
            # restore existing SIGALRM handler
            signal.signal(signal.SIGALRM, old)
        signal.setitimer(signal.ITIMER_REAL, 0)
        return result


def timeout(timeout):
    """This decorator takes a timeout parameter in seconds."""

    def wrap_function(function):
        return call_with_timeout(function, timeout)

    return wrap_function


def default_timeout(function):
    """This simple decorator 'timesout' after DEFAULT_TIMEOUT seconds."""
    return call_with_timeout(function)


def getstatusoutput(command, timeout=DEFAULT_TIMEOUT):
    """This is a timeout wrapper around getstatusoutput."""
    _gso = call_with_timeout(subprocess.getstatusoutput, timeout)
    try:
        return _gso(command)
    except TimeoutException:
        return (-1, "The command '%s' timed-out after %i seconds." % (command, timeout))
