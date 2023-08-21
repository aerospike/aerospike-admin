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
from lib.view.view import CliView
from lib.base_controller import CommandHelp

from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp("Turn terminal pager on or off")
class PagerController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set()

    @CommandHelp(
        "Displays output with vertical and horizontal paging for each output table same as linux 'less' command. Use arrow keys to scroll output and 'q' to end page for table. All linux less commands can work in this pager option.",
        short_msg="Enables output paging. Similar to linux 'less'",
    )
    def do_on(self, line):
        CliView.pager = CliView.LESS

    @CommandHelp("Disables paging and prints output normally")
    def do_off(self, line):
        CliView.pager = CliView.NO_PAGER

    @CommandHelp("Display output in scrolling mode")
    def do_scroll(self, line):
        CliView.pager = CliView.SCROLL
