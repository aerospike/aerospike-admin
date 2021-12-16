# # Copyright 2013-2021 Aerospike, Inc.
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# # http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.
# from io import StringIO
# from os import sys
# import asynctest
# from mock import patch
# from mock.mock import AsyncMock

# from lib.live_cluster.show_controller import (
#     ShowConfigController,
#     ShowDistributionController,
#     ShowLatenciesController,
#     ShowStatisticsController,
# )
# from lib.live_cluster.info_controller import InfoController, InfoNamespaceController
# from lib.live_cluster.client.node import Node
# from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController
# from lib.utils.lookup_dict import LookupDict
# from lib.utils import util

# real_stdout = sys.stdout


# def reset_stdout():
#     sys.stdout = real_stdout


# class ControllerTest(asynctest.TestCase):
#     async def setUp(self):
#         self.cluster_mock = patch(
#             "lib.live_cluster.live_cluster_root_controller.Cluster", AsyncMock()
#         ).start()
#         self.rc = await LiveClusterRootController()

#         sys.stdout = StringIO()

#         self.addCleanup(patch.stopall)
#         self.addCleanup(reset_stdout)

#         self.cluster_mock._crawl.side_effect = classmethod(lambda self: None)
#         self.cluster_mock._crawl.call_node_method = classmethod(
#             lambda self, nodes, method_name, *args, **kwargs: {
#                 "test": IOError("test error")
#             }
#         )

#         self.info_build_mock = patch(
#             "lib.live_cluster.client.node.Node.info_build"
#         ).start()
#         self.info_build_mock.return_value = "5.5.0.0"

#         n = Node("172.99.99.99")
#         self.cluster_mock._crawl.get_node = classmethod(lambda self, key: [n])

#         pd = LookupDict()
#         pd["test"] = "test"

#         self.cluster_mock._crawl.get_node_displaynames = classmethod(lambda self: pd)

#     async def test_info_controller(self):
#         ic = InfoController()

#         ic.pre_command([""])

#         await ic.do_network(["network"])  # TODO: view.info_network needs a "real" node
#         await ic.do_xdr(["xdr"])

#     async def test_info_namespace_controller(self):
#         inc = InfoNamespaceController()

#         inc.pre_command([""])

#         await inc.do_usage(["namespace usage"])
#         await inc.do_object(["namespace object"])

#     async def test_show_distribution_controller(self):
#         sdc = ShowDistributionController()

#         sdc.pre_command([""])
#         await sdc.do_time_to_live(["time_to_live"])
#         await sdc.do_object_size(["object_size"])
#         await sdc.do_object_size(["object_size", "-b"])

#     async def test_show_config_controller(self):
#         scc = ShowConfigController()

#         scc.pre_command([""])
#         await scc.do_service(["service"])
#         await scc.do_network(["network"])
#         await scc.do_namespace(["namespace"])
#         await scc.do_xdr(["xdr"])

#     async def test_show_latencies_controller(self):
#         slc = ShowLatenciesController()

#         slc.pre_command([""])
#         await util.capture_stdout_and_stderr_async(slc._do_default, ["latencies"])

#     async def test_ShowStatisticsController(self):
#         ssc = ShowStatisticsController()

#         ssc.pre_command([""])
#         await ssc.do_bins("bins")
#         await ssc.do_sets("sets")
#         await ssc.do_service("service")
#         await ssc.do_namespace("namespace")
#         await ssc.do_xdr("xdr")
