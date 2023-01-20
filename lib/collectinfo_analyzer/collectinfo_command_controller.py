from lib.base_controller import CommandController
from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)


class CollectinfoCommandController(CommandController):
    def __init__(self, log_handler: CollectinfoLogHandler):
        CollectinfoCommandController.log_handler = log_handler
