from lib.collectinfo_analyzer.collectinfo_command_controller import (
    CollectinfoCommandController,
)
from lib.base_controller import CommandHelp
from lib.utils import constants, common


@CommandHelp("Displays features used in Aerospike cluster.")
class FeaturesController(CollectinfoCommandController):
    def __init__(self):
        self.modifiers = set(["like"])

    def _do_default(self, line):
        service_stats = self.log_handler.info_statistics(stanza=constants.STAT_SERVICE)
        namespace_stats = self.log_handler.info_statistics(
            stanza=constants.STAT_NAMESPACE
        )
        xdr_dc_stats = self.log_handler.info_statistics(stanza=constants.STAT_XDR)
        service_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_SERVICE
        )
        namespace_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_NAMESPACE
        )
        security_configs = self.log_handler.info_getconfig(
            stanza=constants.CONFIG_SECURITY
        )

        for timestamp in sorted(service_stats.keys()):
            features = {}
            s_stats = service_stats[timestamp]
            ns_stats = {}
            dc_stats = {}
            s_configs = {}
            ns_configs = {}
            sec_configs = {}

            if timestamp in service_configs:
                s_configs = service_configs[timestamp]

            if timestamp in namespace_stats:
                ns_stats = namespace_stats[timestamp]

            if timestamp in xdr_dc_stats:
                dc_stats = xdr_dc_stats[timestamp]

            if timestamp in namespace_configs:
                ns_configs = namespace_configs[timestamp]

            if timestamp in security_configs:
                sec_configs = security_configs[timestamp]

            features = common.find_nodewise_features(
                service_stats=s_stats,
                ns_stats=ns_stats,
                xdr_dc_stats=dc_stats,
                service_configs=s_configs,
                ns_configs=ns_configs,
                security_configs=sec_configs,
            )

            self.view.show_config(
                "Features",
                features,
                self.log_handler.get_cinfo_log_at(timestamp=timestamp),
                timestamp=timestamp,
                **self.mods
            )
