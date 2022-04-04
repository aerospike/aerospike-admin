from lib.base_controller import CommandController
from lib.log_analyzer.log_handler.log_handler import LogHandler


class LogAnalyzerCommandController(CommandController):

    log_handler = None

    def __init__(self, log_handler: LogHandler):
        LogAnalyzerCommandController.log_handler = log_handler
