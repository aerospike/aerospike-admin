from lib.base_controller import CommandController


class LiveClusterCommandController(CommandController):
    cluster = None

    def __init__(self, cluster):
        LiveClusterCommandController.cluster = cluster
