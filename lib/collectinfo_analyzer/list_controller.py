# Copyright 2022-2025 Aerospike, Inc.
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

from lib.view import terminal
from lib.base_controller import CommandHelp

from .collectinfo_command_controller import CollectinfoCommandController


@CommandHelp("Displays all added collectinfos files.")
class ListController(CollectinfoCommandController):
    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_all(self, line):
        cinfo_logs = self.log_handler.all_cinfo_logs
        for timestamp, snapshot in cinfo_logs.items():
            print(
                terminal.bold()
                + str(timestamp)
                + terminal.unbold()
                + ": "
                + str(snapshot.cinfo_file)
            )

    def _do_default(self, line):
        self._do_all(line)
