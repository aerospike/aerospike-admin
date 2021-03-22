from lib.base_controller import CommandController


class CollectinfoCommandController(CommandController):

    log_handler = None

    def __init__(self, log_handler):
        CollectinfoCommandController.log_handler = log_handler
