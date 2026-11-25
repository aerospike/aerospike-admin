# Copyright 2026 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
from unittest.mock import AsyncMock, MagicMock, create_autospec, patch

from lib.collectinfo_analyzer.collectinfo_handler.log_handler import (
    CollectinfoLogHandler,
)
from lib.collectinfo_analyzer.summary_controller import (
    SummaryController as CollectinfoSummaryController,
)
from lib.live_cluster.client.cluster import Cluster
from lib.live_cluster.summary_controller import (
    SummaryController as LiveSummaryController,
)
from lib.utils import constants

TIMESTAMP = "2026-11-24 10:00:00 UTC"
N1 = "1.1.1.1:3000"
N2 = "2.2.2.2:3000"

BUILDS = {N1: "8.1.2.1", N2: "8.2.1.0"}
EDITIONS = {N1: "Aerospike Enterprise Edition", N2: "Aerospike Enterprise Edition"}
CLUSTER_NAMES = {N1: "c1", N2: "c1"}
FEATURE_KEYS = {
    N1: {"asdb-compression": "true"},
    N2: {"asdb-compression": "true"},
}
SERVICE_STATS = {
    N1: {"uptime": "90000", "cluster_size": "2"},
    N2: {"uptime": "90000", "cluster_size": "2"},
}
NAMESPACE_STATS = {
    node: {
        "test": {
            "replication-factor": "2",
            "data_used_bytes": "8192",
            "data_compression_ratio": "0.400",
        },
        "bar": {
            "replication-factor": "2",
            "data_used_bytes": "8192",
            "data_compression_ratio": "0.512",
        },
    }
    for node in (N1, N2)
}
NAMESPACE_CONFIGS = {
    node: {
        "test": {"storage-engine": "device", "storage-engine.compression": "lz4"},
        "bar": {"storage-engine": "device", "storage-engine.compression": "none"},
    }
    for node in (N1, N2)
}
CONFIGS = {
    constants.CONFIG_SERVICE: {N1: {}, N2: {}},
    constants.CONFIG_NAMESPACE: NAMESPACE_CONFIGS,
    constants.CONFIG_SECURITY: {N1: {}, N2: {}},
}
STATS = {
    constants.STAT_SERVICE: SERVICE_STATS,
    constants.STAT_NAMESPACE: NAMESPACE_STATS,
    constants.STAT_XDR: {N1: {}, N2: {}},
}


class SummaryParityTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.view = patch("lib.base_controller.BaseController.view").start()
        self.addCleanup(patch.stopall)

    async def live_summary(self):
        controller = LiveSummaryController()
        cluster = controller.cluster = create_autospec(Cluster)
        info = {"build": BUILDS, "cluster-name": CLUSTER_NAMES}
        cluster.info = AsyncMock(side_effect=lambda cmd, nodes=None: info[cmd])
        cluster.info_version = AsyncMock(return_value=EDITIONS)
        cluster.info_system_statistics = AsyncMock(
            return_value={
                node: {
                    "lsb": {"description": "Ubuntu 24.04"},
                    "uname": {"kernel_release": "6.8.0"},
                }
                for node in (N1, N2)
            }
        )
        cluster.info_statistics = AsyncMock(return_value=SERVICE_STATS)
        cluster.info_all_namespace_statistics = AsyncMock(return_value=NAMESPACE_STATS)
        cluster.info_all_dc_statistics = AsyncMock(return_value={N1: {}, N2: {}})
        cluster.info_get_config = AsyncMock(
            side_effect=lambda nodes=None, stanza=None: CONFIGS[stanza]
        )
        cluster.info_feature_key = AsyncMock(return_value=FEATURE_KEYS)

        await controller.execute([])

        return self.view.print_summary.call_args.args[0]

    def collectinfo_summary(self):
        controller = CollectinfoSummaryController()
        handler = controller.log_handler = create_autospec(CollectinfoLogHandler)
        controller.mods = {}
        meta = {
            "asd_build": BUILDS,
            "edition": {N1: "Enterprise", N2: "Enterprise"},
            "feature-key": FEATURE_KEYS,
        }
        sys_data = {
            "lsb": {node: {"description": "Ubuntu 24.04"} for node in (N1, N2)},
            "uname": {node: {"kernel_release": "6.8.0"} for node in (N1, N2)},
        }
        handler.info_statistics.side_effect = lambda stanza: {TIMESTAMP: STATS[stanza]}
        handler.info_getconfig.side_effect = lambda stanza: {TIMESTAMP: CONFIGS[stanza]}
        handler.info_meta_data.side_effect = lambda stanza: {TIMESTAMP: meta[stanza]}
        handler.get_sys_data.side_effect = lambda stanza: {TIMESTAMP: sys_data[stanza]}
        cinfo_log = MagicMock()
        cinfo_log.get_cluster_name.return_value = CLUSTER_NAMES
        handler.get_cinfo_log_at.return_value = cinfo_log

        controller._do_default([])

        return self.view.print_summary.call_args.args[0]

    async def test_live_and_bundle_of_the_same_data_give_the_same_summary(self):
        live = await self.live_summary()
        bundle = self.collectinfo_summary()

        self.assertEqual(live, bundle)
        self.assertTrue(live["NAMESPACES"]["test"]["compression_enabled"])
        self.assertNotIn("compression_unverified", live["NAMESPACES"]["test"])
        self.assertTrue(live["NAMESPACES"]["bar"]["compression_enabled"])
        self.assertTrue(live["NAMESPACES"]["bar"]["compression_unverified"])
