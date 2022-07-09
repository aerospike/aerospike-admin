from lib.base_controller import CommandController
from .client import Cluster


class LiveClusterCommandController(CommandController):
    cluster: Cluster = None

    def __init__(self, cluster: Cluster):
        LiveClusterCommandController.cluster = cluster
