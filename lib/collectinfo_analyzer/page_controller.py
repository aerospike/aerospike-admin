from lib.base_controller import CommandHelp
from lib.view.view import CliView

from .collectinfo_command_controller import CollectinfoCommandController


@CommandHelp("Set pager for output")
class PagerController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set()

    def _do_default(self, line):
        self.execute_help(line)

    @CommandHelp(
        "Displays output with vertical and horizontal paging for each output table same as linux 'less' command.",
        "Use arrow keys to scroll output and 'q' to end page for table.",
        "All linux less commands can work in this pager option.",
    )
    def do_on(self, line):
        CliView.pager = CliView.LESS

    @CommandHelp("Removes pager and prints output normally")
    def do_off(self, line):
        CliView.pager = CliView.NO_PAGER

    @CommandHelp("Display output in scrolling mode")
    def do_scroll(self, line):
        CliView.pager = CliView.SCROLL
