# Copyright 2025 Aerospike, Inc.
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
"""The process exit code asadm returns, in a module that imports nothing.

lib.utils.logger owns the usual way to set it - BaseLogger.error - but importing
that module pulls in lib.base_controller and lib.live_cluster.client, and with
them OpenSSL. Code that only needs to record a failure, such as the collectinfo
analyzer, imports this instead and stays cheap.
"""

exit_code = 0


def get_exit_code() -> int:
    return exit_code


def set_exit_code(code: int) -> None:
    global exit_code
    exit_code = code
