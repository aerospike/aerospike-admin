'''
Created on 07-Sep-2015

@author: Pavan Gupta
'''
import test_util
import unittest2 as unittest
import re
# from .. import *
import lib.util as util
import lib.controller as controller


# @unittest.skip("Skipping for testing purpose")   
class TestShowConfig(unittest.TestCase):
    output_list = list()
    service_config = ''
    network_config = ''
    test_namespace_config = ''
    bar_namespace_config = ''
    xdr_config = ''
    
    @classmethod
    def setUpClass(cls):
        rc = controller.RootController()
        actual_out = util.capture_stdout(rc.execute, ['show', 'config'])
        TestShowConfig.output_list = test_util.get_separate_output(actual_out, 'Configuration')
                          
        for item in TestShowConfig.output_list:
            if "~~Service Configuration~~" in item:
                TestShowConfig.service_config = item           
            elif "~~Network Configuration~~" in item:
                TestShowConfig.network_config = item           
            elif "~~test Namespace Configuration~~" in item:
                TestShowConfig.test_namespace_config = item               
            elif "~~bar Namespace Configuration~~" in item:
                TestShowConfig.bar_namespace_config = item              
            elif "~~XDR Configuration~~" in item:
                TestShowConfig.xdr_config = item
              
    @classmethod    
    def tearDownClass(self):
        self.rc = None
        
    def test_network(self):
        """
        This test will assert network output on heading, header, parameters.
        ToDo: test for values as well
        """
    
        exp_heading = "~~Network Configuration~~"
        exp_header = "NODE"
        exp_params = ['enable-fastpath', 
                    'fabric-keepalive-enabled', 
                    'fabric-keepalive-intvl', 
                    'fabric-keepalive-probes', 
                    'fabric-keepalive-time', 
                    'fabric-port', 
                    'heartbeat-address', 
                    'heartbeat-interval', 
                    'heartbeat-mode', 
                    'heartbeat-port', 
                    'heartbeat-protocol', 
                    'heartbeat-timeout', 
                    'network-info-port', 
                    'reuse-address', 
                    'service-address', 
                    'service-port']
        
        # mesh-seed-address-port :  additional parameter comes only with mesh setup.
        
#         actual_out = util.capture_stdout(self.rc.execute, ['show', 'config', 'network'])
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.network_config)
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params))
        pass
    
    
#     @unittest.skip("for time being")    
   
    def test_service(self):
        """
        Asserts service config output with heading, header & parameters.
        ToDo: test for values as well
        """
        
        exp_heading = "~~Service Configuration~~"
        exp_header = "NODE"
        exp_params = [  'allow-inline-transactions',
                        'auto-dun',
                        'auto-undun',
#                         'batch-index-threads',
#                         'batch-max-buffers-per-queue',
                        'batch-max-requests',
#                         'batch-max-unused-buffers',
                        'batch-priority',
                        'batch-threads',
                        'dump-message-above-size',
                        'fabric-workers',
                        'fb-health-bad-pct',
                        'fb-health-good-pct',
                        'fb-health-msg-per-burst',
                        'fb-health-msg-timeout',
                        'info-threads',
                        'ldt-benchmarks',
                        'max-msgs-per-type',
                        'memory-accounting',
                        'microbenchmarks',
                        'migrate-max-num-incoming',
                        'migrate-read-priority',
                        'migrate-read-sleep',
                        'migrate-rx-lifetime-ms',
                        'migrate-threads',
                        'migrate-xmit-hwm',
                        'migrate-xmit-lwm',
                        'migrate-xmit-priority',
                        'migrate-xmit-sleep',
                        'nsup-delete-sleep',
                        'nsup-period',
                        'nsup-startup-evict',
                        'paxos-max-cluster-size',
                        'paxos-protocol',
                        'paxos-recovery-policy',
                        'paxos-retransmit-period',
                        'paxos-single-replica-limit',
                        'pidfile',
#                         'pre-reserve-qnodes',
                        'prole-extra-ttl',
                        'proto-fd-idle-ms',
                        'proto-fd-max',
                        'proto-slow-netio-sleep-ms',
                        'query-batch-size',
                        'query-bufpool-size',
                        'query-in-transaction-thread',
                        'query-job-tracking',
                        'query-long-q-max-size',
                        'query-priority',
#                         'query-priority-sleep-us',
                        'query-rec-count-bound',
                        'query-req-in-query-thread',
                        'query-req-max-inflight',
                        'query-short-q-max-size',
                        'query-sleep',
                        'query-threads',
                        'query-threshold',
                        'query-untracked-time',
#                         'query-untracked-time-ms',
                        'query-worker-threads',
                        'replication-fire-and-forget',
                        'respond-client-on-master-completion',
#                         'scan-max-active',
#                         'scan-max-done',
#                         'scan-max-udf-transactions',
                        'scan-priority',
                        'scan-sleep',
#                         'scan-threads',
                        'service-threads',
#                         'sindex-builder-threads',
                        'sindex-data-max-memory',
                        'sindex-populator-scan-priority',
                        'snub-nodes',
                        'storage-benchmarks',
                        'ticker-interval',
                        'transaction-duplicate-threads',
                        'transaction-max-ms',
                        'transaction-pending-limit',
                        'transaction-queues',
                        'transaction-repeatable-read',
                        'transaction-retry-ms',
                        'transaction-threads-per-queue',
                        'udf-runtime-gmax-memory',
                        'udf-runtime-max-memory',
                        'use-queue-per-device',
                        'write-duplicate-resolution-disable',
                    ]

        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.service_config)        
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params))
      
#     @unittest.skip("for time being")
    
    def test_test_namespace(self):
        """
        Asserts namespace config output with heading, header & parameters.
        ToDo: test for values as well
        """
        
        exp_heading = "~~test Namespace Configuration~~"
        exp_header = "NODE"
        exp_params_test = [  'allow-nonxdr-writes',
                        'allow-xdr-writes',
                        'allow_versions',
                        'cold-start-evict-ttl',
                        'conflict-resolution-policy',
                        'default-ttl',
                        'disallow-null-setname',
                        'enable-xdr',
                        'evict-tenths-pct',
                        'high-water-disk-pct',
                        'high-water-memory-pct',
                        'ldt-enabled',
                        'ldt-page-size',
                        'max-ttl',
                        'memory-size',
                        'ns-forward-xdr-writes',
                        'read-consistency-level-override',
                        'repl-factor',
                        'sets-enable-xdr',
                        'single-bin',
                        'stop-writes-pct',
                        'total-bytes-memory',
                        'write-commit-level-override'
                      ] 
        
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.test_namespace_config)        
       
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params_test), set(actual_params)) 
    
#     @unittest.skip("for time being") 
    def test_bar_namespace(self):
        """
        Asserts namespace config output with heading, header & parameters.
        ToDo: test for values as well
        """
        
        exp_heading = "~~bar Namespace Configuration~~"
        exp_header = "NODE"
        exp_params_bar = [  'allow-nonxdr-writes',
                            'allow-xdr-writes',
                            'allow_versions',
                            'cold-start-evict-ttl',
                            'conflict-resolution-policy',
                            'default-ttl',
                            'disallow-null-setname',
                            'enable-xdr',
                            'evict-tenths-pct',
                            'high-water-disk-pct',
                            'high-water-memory-pct',
                            'ldt-enabled',
                            'ldt-page-size',
                            'max-ttl',
                            'memory-size',
                            'ns-forward-xdr-writes',
                            'read-consistency-level-override',
                            'repl-factor',
                            'sets-enable-xdr',
                            'single-bin',
                            'stop-writes-pct',
                            'total-bytes-memory',
                            'write-commit-level-override'
                        ] 
        
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.bar_namespace_config)        
       
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params_bar), set(actual_params)) 
    
#     @unittest.skip("Will enable once xdr is configuired")

    @unittest.skip("Will enable once xdr is configuired")   
    def test_xdr(self):
            """
            Asserts XDR config output with heading, header & parameters.
            ToDo: test for values as well
            """
            exp_heading = "~~XDR Configuration~~"
            exp_header = "NODE"
            exp_params = [  'enable-xdr',
                            'xdr-batch-num-retry',
                            'xdr-batch-retry-sleep',
                            'xdr-check-data-before-delete',
                            'xdr-compression-threshold',
                            'xdr-digestlog-size',
                            'xdr-forward-with-gencheck',
                            'xdr-hotkey-maxskip',
                            'xdr-info-timeout',
                            'xdr-local-port',
                            'xdr-max-recs-inflight',
                            'xdr-namedpipe-path',
                            'xdr-nw-timeout',
                            'xdr-read-batch-size',
                            'xdr-read-mode',
                            'xdr-read-threads',
                            'xdr-ship-delay',
                            'xdr-shipping-enabled',
                            'xdr-threads',
                            'xdr-timeout',
                            'xdr-write-batch-size'
                          ] 
            
            actual_heading, actual_header, actual_params = test_util.parse_output(TestShowConfig.xdr_config)        
           
            self.assertTrue(exp_heading in actual_heading)
            self.assertTrue(exp_header in actual_header)
            self.assertEqual(set(exp_params), set(actual_params)) 
    
class TestShowLatency(unittest.TestCase):
    # will remove this function once latency test is implemented without asinfo
    def parse_latency(tdata = ""):
            tdata = tdata.split(';')[:-1]
            data = {}
            while tdata != []:
                columns = tdata.pop(0)
                row = tdata.pop(0)
    
                hist_name, columns = columns.split(':', 1)
                columns = columns.split(',')
                row = row.split(',')
                start_time = columns.pop(0)
                end_time = row.pop(0)
                columns.insert(0, 'Time Span')
                row = [float(r) for r in row]
                row.insert(0, "%s->%s"%(start_time, end_time))
    
                data[hist_name] = (columns, row)
    
            return data
        
        
    @unittest.skip("need to implement without asinfo")
    def test_latency(self):        
        expected_out, err = util.shell_command(["asinfo", "-v", "latency:"])
        print expected_out, err
        self.assertTrue(True)
        
        rc = controller.RootController()
        actual_out = util.capture_stdout(rc.execute, ['show', 'latency'])
#         slc = controller.ShowLatencyController()
#         slc.nodes = "all"
#         slc._do_default([])
        print actual_out
        self.assertEqual(expected_out.strip(), actual_out.strip())

class TestShowDistribution(unittest.TestCase):
    output_list = list()
    test_ttl_distri = ''
    bar_ttl_distri = ''
    
    @classmethod
    def setUpClass(cls):
        rc = controller.RootController()
        actual_out = util.capture_stdout(rc.execute, ['show', 'distribution'])
        # use regex in get_separate_output(~.+Distribution.*~.+) 
        #if you are changing below Distribution keyword
        TestShowDistribution.output_list = test_util.get_separate_output(actual_out, 'Distribution in Seconds')
                          
        for item in TestShowDistribution.output_list:
            if "~~test - TTL Distribution in Seconds~~" in item:
                TestShowDistribution.test_ttl_distri = item           
            elif "~~bar - TTL Distribution in Seconds~~" in item:
                TestShowDistribution.bar_ttl_distri = item           
            elif "~~~~" in item:
                TestShowDistribution.test_namespace_config = item               
          
              
    @classmethod    
    def tearDownClass(self):
        self.rc = None
    
    @unittest.skip("need to implement without asinfo")
    def test_test_ttl(self):
        """
        Asserts TTL Distribution in Seconds for test namespace with heading, header & parameters.
        ToDo: test for values as well
        """
        exp_heading = "~~test - TTL Distribution in Seconds~~"
        exp_header = "NODE"
        exp_params = []
        
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowDistribution.test_ttl_distri)

    
    pass

# @unittest.skip("Skipping for testing purpose")  
class TestShowStatistics(unittest.TestCase):
    output_list = list()
    test_bin_stats = ''
    bar_bin_stats = ''
    service_stats = ''
    bar_namespace_stats = ''
    test_namespace_stats = ''
    xdr_stats = ''
    
    @classmethod
    def setUpClass(cls):
        rc = controller.RootController()
        actual_out = util.capture_stdout(rc.execute, ['show', 'statistics'])
        TestShowStatistics.output_list = test_util.get_separate_output(actual_out, 'Statistics')
                          
        for item in TestShowStatistics.output_list:
            if "~~test Bin Statistics~~" in item:
                TestShowStatistics.test_bin_stats = item           
            elif "~~bar Bin Statistics~~" in item:
                TestShowStatistics.bar_bin_stats = item           
            elif "~~Service Statistics~~" in item:
                TestShowStatistics.service_stats = item               
            elif "~~bar Namespace Statistics~~" in item:
                TestShowStatistics.bar_namespace_stats = item              
            elif "~~test Namespace Statistics~~" in item:
                TestShowStatistics.test_namespace_stats = item
            elif "~~XDR Statistics~~" in item:
                TestShowStatistics.xdr_stats = item
              
    @classmethod    
    def tearDownClass(self):
        self.rc = None
    
    def test_test_bin(self):
        """
        This test will assert <b> test Bin Statistics </b> output for heading, header and parameters.
        ToDo: test for values as well
        """
        exp_heading = "~test Bin Statistics~"
        exp_header = "NODE"
        exp_params = ['bin-names-quota', 'num-bin-names']
        
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.test_bin_stats)
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params))
        
    def test_bar_bin(self):
        """
        This test will assert <b> bar Bin Statistics </b> output for heading, header and parameters.
        ToDo: test for values as well
        """
        exp_heading = "~bar Bin Statistics~"
        exp_header = "NODE"
        exp_params = ['bin-names-quota', 'num-bin-names']
        
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.bar_bin_stats)
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params))  
          
    def test_service(self):
        """
        This test will assert <b> Service Statistics </b> output for heading, header and parameters.
        ToDo: test for values as well
        """
        exp_heading = "~Service Statistics~"
        exp_header = "NODE"
        exp_params = [  'batch_errors',
                        'batch_initiate',
                        'batch_queue',
                        'batch_timeout',
                        'batch_tree_count',
                        'client_connections',
                        'cluster_integrity',
                        'cluster_key',
                        'cluster_size',
                        'data-used-bytes-memory',
                        'delete_queue',
                        'err_duplicate_proxy_request',
                        'err_out_of_space',
                        'err_replica_non_null_node',
                        'err_replica_null_node',
                        'err_rw_cant_put_unique',
                        'err_rw_pending_limit',
                        'err_rw_request_not_found',
                        'err_storage_queue_full',
                        'err_sync_copy_null_master',
                        'err_sync_copy_null_node',
                        'err_tsvc_requests',
                        'err_write_fail_bin_exists',
                        'err_write_fail_bin_name',
                        'err_write_fail_bin_not_found',
                        'err_write_fail_forbidden',
                        'err_write_fail_generation',
                        'err_write_fail_generation_xdr',
                        'err_write_fail_incompatible_type',
                        'err_write_fail_key_exists',
                        'err_write_fail_key_mismatch',
                        'err_write_fail_not_found',
                        'err_write_fail_noxdr',
                        'err_write_fail_parameter',
                        'err_write_fail_prole_delete',
                        'err_write_fail_prole_generation',
                        'err_write_fail_prole_unknown',
                        'err_write_fail_record_too_big',
                        'err_write_fail_unknown',
                        'fabric_msgs_rcvd',
                        'fabric_msgs_sent',
                        'free-pct-disk',
                        'free-pct-memory',
                        'heartbeat_received_foreign',
                        'heartbeat_received_self',
                        'index-used-bytes-memory',
                        'info_queue',
                        'migrate_msgs_recv',
                        'migrate_msgs_sent',
                        'migrate_num_incoming_accepted',
                        'migrate_num_incoming_refused',
                        'migrate_progress_recv',
                        'migrate_progress_send',
                        'migrate_rx_objs',
                        'migrate_tx_objs',
                        'objects',
                        'ongoing_write_reqs',
                        'partition_absent',
                        'partition_actual',
                        'partition_desync',
                        'partition_object_count',
                        'partition_ref_count',
                        'partition_replica',
                        'paxos_principal',
                        'proxy_action',
                        'proxy_in_progress',
                        'proxy_initiate',
                        'proxy_retry',
                        'proxy_retry_new_dest',
                        'proxy_retry_q_full',
                        'proxy_retry_same_dest',
                        'proxy_unproxy',
                        'query_abort',
                        'query_agg',
                        'query_agg_abort',
                        'query_agg_avg_rec_count',
                        'query_agg_err',
                        'query_agg_success',
                        'query_avg_rec_count',
                        'query_fail',
                        'query_long_queue_full',
                        'query_long_queue_size',
                        'query_long_running',
                        'query_lookup_abort',
                        'query_lookup_avg_rec_count',
                        'query_lookup_err',
                        'query_lookup_success',
                        'query_lookups',
                        'query_reqs',
                        'query_short_queue_full',
                        'query_short_queue_size',
                        'query_short_running',
                        'query_success',
                        'query_tracked',
                        'queue',
                        'read_dup_prole',
                        'reaped_fds',
                        'record_locks',
                        'record_refs',
                        'rw_err_ack_badnode',
                        'rw_err_ack_internal',
                        'rw_err_ack_nomatch',
                        'rw_err_dup_cluster_key',
                        'rw_err_dup_internal',
                        'rw_err_dup_send',
                        'rw_err_write_cluster_key',
                        'rw_err_write_internal',
                        'rw_err_write_send',
                        'sindex-used-bytes-memory',
                        'sindex_gc_activity_dur',
                        'sindex_gc_garbage_cleaned',
                        'sindex_gc_garbage_found',
                        'sindex_gc_inactivity_dur',
                        'sindex_gc_list_creation_time',
                        'sindex_gc_list_deletion_time',
                        'sindex_gc_locktimedout',
                        'sindex_gc_objects_validated',
                        'sindex_ucgarbage_found',
                        'stat_cluster_key_err_ack_dup_trans_reenqueue',
                        'stat_cluster_key_err_ack_rw_trans_reenqueue',
                        'stat_cluster_key_partition_transaction_queue_count',
                        'stat_cluster_key_prole_retry',
                        'stat_cluster_key_regular_processed',
                        'stat_cluster_key_trans_to_proxy_retry',
                        'stat_cluster_key_transaction_reenqueue',
                        'stat_delete_success',
                        'stat_deleted_set_objects',
                        'stat_duplicate_operation',
                        'stat_evicted_objects',
                        'stat_evicted_objects_time',
                        'stat_evicted_set_objects',
                        'stat_expired_objects',
                        'stat_ldt_proxy',
                        'stat_nsup_deletes_not_shipped',
                        'stat_proxy_errs',
                        'stat_proxy_reqs',
                        'stat_proxy_reqs_xdr',
                        'stat_proxy_success',
                        'stat_read_errs_notfound',
                        'stat_read_errs_other',
                        'stat_read_reqs',
                        'stat_read_reqs_xdr',
                        'stat_read_success',
                        'stat_rw_timeout',
                        'stat_slow_trans_queue_batch_pop',
                        'stat_slow_trans_queue_pop',
                        'stat_slow_trans_queue_push',
                        'stat_write_errs',
                        'stat_write_errs_notfound',
                        'stat_write_errs_other',
                        'stat_write_reqs',
                        'stat_write_reqs_xdr',
                        'stat_write_success',
                        'stat_xdr_pipe_miss',
                        'stat_xdr_pipe_writes',
                        'stat_zero_bin_records',
                        'storage_defrag_corrupt_record',
                        'sub-records',
                        'system_free_mem_pct',
                        'system_swapping',
                        'total-bytes-disk',
                        'total-bytes-memory',
                        'transactions',
                        'tree_count',
                        'tscan_aborted',
                        'tscan_initiate',
                        'tscan_pending',
                        'tscan_succeeded',
                        'udf_delete_err_others',
                        'udf_delete_reqs',
                        'udf_delete_success',
                        'udf_lua_errs',
                        'udf_query_rec_reqs',
                        'udf_read_errs_other',
                        'udf_read_reqs',
                        'udf_read_success',
                        'udf_replica_writes',
                        'udf_scan_rec_reqs',
                        'udf_write_err_others',
                        'udf_write_reqs',
                        'udf_write_success',
                        'uptime',
                        'used-bytes-disk',
                        'used-bytes-memory',
                        'waiting_transactions',
                        'write_master',
                        'write_prole',  
                    ]
        
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.service_stats)
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params))   
                      
    def test_bar_namespace(self):
        """
        This test will assert <b> bar Namespace Statistics </b> output for heading, header and parameters.
        ToDo: test for values as well
        """
        exp_heading = "~bar Namespace Statistics~"
        exp_header = "NODE"
        exp_params = [  'allow-nonxdr-writes',
                        'allow-xdr-writes',
                        'allow_versions',
                        'available-bin-names',
                        'cold-start-evict-ttl',
                        'conflict-resolution-policy',
                        'current-time',
                        'data-used-bytes-memory',
                        'default-ttl',
                        'disallow-null-setname',
                        'enable-xdr',
                        'evict-tenths-pct',
                        'evicted-objects',
                        'expired-objects',
                        'free-pct-memory',
                        'high-water-disk-pct',
                        'high-water-memory-pct',
                        'hwm-breached',
                        'index-used-bytes-memory',
                        'ldt-enabled',
                        'ldt-page-size',
                        'master-objects',
                        'master-sub-objects',
                        'max-ttl',
                        'max-void-time',
                        'memory-size',
                        'non-expirable-objects',
                        'ns-forward-xdr-writes',
                        'nsup-cycle-duration',
                        'nsup-cycle-sleep-pct',
                        'objects',
                        'prole-objects',
                        'prole-sub-objects',
                        'read-consistency-level-override',
                        'repl-factor',
                        'set-deleted-objects',
                        'set-evicted-objects',
                        'sets-enable-xdr',
                        'sindex-used-bytes-memory',
                        'single-bin',
                        'stop-writes',
                        'stop-writes-pct',
                        'sub-objects',
                        'total-bytes-memory',
                        'type',
                        'used-bytes-memory',
                        'write-commit-level-override',
                    ]
        
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.bar_namespace_stats)
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params))  
        
    def test_test_namespace(self):
        """
        This test will assert <b> test Namespace Statistics </b> output for heading, header and parameters.
        ToDo: test for values as well
        """
        exp_heading = "~test Namespace Statistics~"
        exp_header = "NODE"
        exp_params = [  'allow-nonxdr-writes',
                        'allow-xdr-writes',
                        'allow_versions',
                        'available-bin-names',
                        'cold-start-evict-ttl',
                        'conflict-resolution-policy',
                        'current-time',
                        'data-used-bytes-memory',
                        'default-ttl',
                        'disallow-null-setname',
                        'enable-xdr',
                        'evict-tenths-pct',
                        'evicted-objects',
                        'expired-objects',
                        'free-pct-memory',
                        'high-water-disk-pct',
                        'high-water-memory-pct',
                        'hwm-breached',
                        'index-used-bytes-memory',
                        'ldt-enabled',
                        'ldt-page-size',
                        'master-objects',
                        'master-sub-objects',
                        'max-ttl',
                        'max-void-time',
                        'memory-size',
                        'non-expirable-objects',
                        'ns-forward-xdr-writes',
                        'nsup-cycle-duration',
                        'nsup-cycle-sleep-pct',
                        'objects',
                        'prole-objects',
                        'prole-sub-objects',
                        'read-consistency-level-override',
                        'repl-factor',
                        'set-deleted-objects',
                        'set-evicted-objects',
                        'sets-enable-xdr',
                        'sindex-used-bytes-memory',
                        'single-bin',
                        'stop-writes',
                        'stop-writes-pct',
                        'sub-objects',
                        'total-bytes-memory',
                        'type',
                        'used-bytes-memory',
                        'write-commit-level-override',
                    ]
        
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.test_namespace_stats)
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params)) 
    
    @unittest.skip("Will enable once xdr is configuired")
    def test_xdr(self):
        """
        This test will assert <b> test Namespace Statistics </b> output for heading, header and parameters.
        ToDo: test for values as well
        """
        exp_heading = "~~XDR Statistics~~"
        exp_header = "NODE"
        exp_params = [  'cur_throughput',
                        'err_ship_client',
                        'err_ship_conflicts',
                        'err_ship_server',
                        'esmt-bytes-shipped',
                        'esmt-bytes-shipped-compression',
                        'esmt-ship-compression',
                        'free-dlog-pct',
                        'latency_avg_dlogread',
                        'latency_avg_dlogwrite',
                        'latency_avg_ship',
                        'local_recs_fetch_avg_latency',
                        'local_recs_fetched',
                        'local_recs_migration_retry',
                        'local_recs_notfound',
                        'noship_recs_dup_intrabatch',
                        'noship_recs_expired',
                        'noship_recs_genmismatch',
                        'noship_recs_notmaster',
                        'noship_recs_unknown_namespace',
                        'perdc_timediff_lastship_cur_secs',
                        'stat_dlog_fread',
                        'stat_dlog_fseek',
                        'stat_dlog_fwrite',
                        'stat_dlog_read',
                        'stat_dlog_write',
                        'stat_pipe_reads_diginfo',
                        'stat_recs_dropped',
                        'stat_recs_localprocessed',
                        'stat_recs_logged',
                        'stat_recs_outstanding',
                        'stat_recs_relogged',
                        'stat_recs_replprocessed',
                        'stat_recs_shipped',
                        'stat_recs_shipping',
                        'timediff_lastship_cur_secs',
                        'total-recs-dlog',
                        'used-recs-dlog',
                        'xdr-uptime',
                        'xdr_deletes_canceled',
                        'xdr_deletes_relogged',
                        'xdr_deletes_shipped',
                    ]
        actual_heading, actual_header, actual_params = test_util.parse_output(TestShowStatistics.xdr_stats)
        
        self.assertTrue(exp_heading in actual_heading)
        self.assertTrue(exp_header in actual_header)
        self.assertEqual(set(exp_params), set(actual_params)) 


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']

    unittest.main()
    
    
    
    