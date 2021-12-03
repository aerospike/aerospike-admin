from lib.view.view import CliView
from lib.base_controller import CommandHelp

from .live_cluster_command_controller import LiveClusterCommandController


@CommandHelp("Set pager for output")
class PagerController(LiveClusterCommandController):
    def __init__(self):
        self.modifiers = set()

    async def _do_default(self, line):
        self.execute_help(line)

    @CommandHelp(
        "Displays output with vertical and horizontal paging for each output table same as linux 'less'",
        "command.",
        "Use arrow keys to scroll output and 'q' to end page for table.",
        "All linux less commands can work in this pager option.",
    )
    async def do_on(self, line):
        CliView.pager = CliView.LESS

    @CommandHelp("Removes pager and prints output normally")
    async def do_off(self, line):
        CliView.pager = CliView.NO_PAGER

    @CommandHelp("Display output in scrolling mode")
    async def do_scroll(self, line):
        CliView.pager = CliView.SCROLL
