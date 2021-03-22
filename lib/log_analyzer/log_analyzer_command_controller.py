from lib.base_controller import CommandController


class LogAnalyzerCommandController(CommandController):

    log_handler = None

    def __init__(self, log_handler):
        LogAnalyzerCommandController.log_handler = log_handler
