from lib.view import terminal
from lib.base_controller import CommandHelp

from .collectinfo_command_controller import CollectinfoCommandController


class ListController(CollectinfoCommandController):
    def __init__(self):
        self.controller_map = {}
        self.modifiers = set()

    def _do_default(self, line):
        self.do_all(line)

    @CommandHelp("Displays list of all added collectinfos files.")
    def do_all(self, line):
        cinfo_logs = self.log_handler.all_cinfo_logs
        for timestamp, snapshot in cinfo_logs.items():
            print(
                terminal.bold()
                + str(timestamp)
                + terminal.unbold()
                + ": "
                + str(snapshot.cinfo_file)
            )
