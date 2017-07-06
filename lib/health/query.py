# Copyright 2013-2017 Aerospike, Inc.
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

QUERIES = '''
/***************************************************
* System Resource                                  *
****************************************************/
// SET CONSTRAINT VERSION <= 3.8.4;
// SET CONSTRAINT VERSION < 3.8.4;
// SET CONSTRAINT VERSION >= 3.8.4;
// SET CONSTRAINT VERSION > 3.8.4;
// SET CONSTRAINT VERSION = 3.8.4;
// SET CONSTRAINT VERSION 3.8.4;
// SET CONSTRAINT VERSION IN [3.8.4, 3.10.0];
SET CONSTRAINT VERSION ALL;

/* Disk */
s = select "%util" from SYSTEM.IOSTAT;
r = do s > 90;
ASSERT(r, False, "High system disk utilization.", "PERFORMANCE", CRITICAL,
				"Listed disks show higher than normal (> 90%) disk utilization at the time of sampling. Please run 'iostat' command to check disk utilization. Possible causes can be disk overload due to undersized cluster or some issue with disk hardware itself. If running on cloud, can be a problem with cloud instance itself.",
				"Disk utilization check.");
r1 = group by DEVICE do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed cluster disk utilization.", "ANOMALY", WARNING,
				"Listed disks show different disk utilization compared to other node[s]. Please run 'iostat' command on those node[s] to confirm such behavior. Possible causes can be skew in workload (e.g hotkey) and/or issue with disk on the specific node[s] which show anomalistic behavior.",
				 "Disk utilization Anomaly.");


avail=select like(".*available_pct") as "free_disk" from NAMESPACE.STATISTICS;
disk_free = select "device_free_pct" as "free_disk", "free-pct-disk" as "free_disk" from NAMESPACE.STATISTICS;
r = do disk_free - avail;
r = do r <= 30;
r = group by CLUSTER, NAMESPACE r;
ASSERT(r, True, "High (> 30%) fragmented blocks.", "PERFORMANCE", WARNING,
				"Listed namespace[s] have higher than normal (>30%) fragmented blocks at the time of sampling. Please run 'show config namespace like defrag' to check defrag configurations. Possible cause can be Aerospike disk defragmentation not keeping up with write rate and/or large record sizes causing fragmentation. Refer to knowledge base article discuss.aerospike.com/t/defragmentation for more details.",
				"Fragmented Blocks check.");


s = select "%iowait" from SYSTEM.IOSTAT;
r = do s > 10;
ASSERT(r, False, "High (> 10%) CPU IO wait time.", "PERFORMANCE", WARNING,
				"Listed nodes show higher than normal (> 10%) CPU spent in io wait. Please run 'iostat' command to check utilization. Possible cause can be slow disk or network leading to lot of CPU time spent waiting for IO.",
				"CPU IO wait time check.");
r1 = group by NODE do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed CPU IO wait time.", "ANOMALY", WARNING,
				"Listed nodes show skew in CPU IO wait time compared to other nodes in cluster. Please run 'iostat' command to check utilization. Possible cause can be skew in workload (e.g hotkey) and/or slow network/disk on the specific node[s] which show anomalistic behavior.",
				 "CPU IO wait time anomaly.");


s = select "await" from SYSTEM.IOSTAT;
r = do s > 4;
ASSERT(r, False, "High system disk average wait time.", "PERFORMANCE", WARNING,
				"Listed disks show higher than normal (> 4ms) disk average wait time. Please run 'iostat' command to check average wait time (await). Possible cause can be issue with disk hardware or VM instance in case you are running in cloud environment. This may also be caused by having storage over network like say SAN device or EBS.",
				"Disk average wait time check.");
r1 = group by DEVICE do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed cluster disk average wait time", "ANOMALY", WARNING,
				"Listed disks show different average wait time characteristic compared to other node[s]. Please run 'iostat' command on those node[s] to confirm such behavior. Possible can be skew in workload (e.g hotkey) and/or disk issue on the specific node[s] which should anomalistic behavior.",
				"Disk average wait time anomaly check.");


s = select "avgqu-sz" from SYSTEM.IOSTAT;
r = do s > 7;
ASSERT(r, False, "High disk average queue size.", "PERFORMANCE", INFO,
				"Listed disks show higher than normal (> 7) disk average queue size. This is not a issue if using NVME drives which support more queues. Please run 'iostat' command to check average wait time (avgqu-sz). Possible disk overload. This may be non-issue of disk has more than 7 queues. Please analyze this number in conjunction with utilization.",
				"Disk avg queue size check.");
r1 = group by DEVICE do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed cluster disk avg queue size.", "ANOMALY", WARNING,
				"Listed disks show different average queue size characteristic compared to other node[s]. Please run 'iostat' command on those node[s] to confirm such behavior. Possible issue can be differential load on these node[s] or issue with disk.",
				"Disk avg queue size anomaly check.");


s = select "id" as "cpu_use" from SYSTEM.TOP.CPU_UTILIZATION;
s = do 100 - s;
r = do s > 70;
ASSERT(r, False, "High system CPU utilization.", "PERFORMANCE", CRITICAL,
				"Listed node[s] are showing higher than normal (> 70%) CPU utilization. Please check top output. Possible system overload.",
				"CPU utilization check.");
r1 = group by CLUSTER, KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed cluster CPU utilization.", "ANOMALY", WARNING,
				"Listed node[s] show different CPU utilization characteristic compared to other node[s]. Please run top command on those node[s] to confirm such behavior. Possible skew in workload.",
				"CPU utilization anomaly check.");


s = select "resident_memory" from SYSTEM.TOP;
r = group by KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster resident memory utilization.", "ANOMALY", WARNING,
				"Listed node[s] show different resident memory usage compared to other node[s]. Please run top command on those node[s] to confirm such behavior. Possible skewed data distribution. This may be non-issue in case migrations are going on.",
				"Resident memory utilization anomaly.");


s = select "system_swapping" from SERVICE.STATISTICS;
r = do s == true;
ASSERT(r, False, "System memory swapping.", "LIMITS", INFO,
				"Listed node[s] are swapping. Please run 'show statistics service like system_swapping' to confirm such behaviour. Possible misconfiguration. This may be non-issue if amount of swap is small and good amount of memory available.",
				"System swap check.");

/* TODO - is it really actually an issue */
s = select "system_free_mem_pct";
r = do s < 20;
ASSERT(r, False, "Low system memory percentage.", "LIMITS", CRITICAL,
				"Listed node[s] have lower than normal (< 20%) system free memory percentage. Please run 'show statistics service like system_free_mem_pct' to get actual values. Possible misconfiguration.",
				"System memory percentage check.");

/* NB : ADD CHECKS IF NODES ARE NOT HOMOGENOUS MEM / NUM CPU etc */


s = select "available_bin_names", "available-bin-names" from NAMESPACE;
r = group by NAMESPACE do s > 3200;
ASSERT(r, True, "Low namespace available bin names.", "LIMITS", WARNING,
				"Listed node[s] have low available bin name (< 3200) for corresponding namespace[s]. Maximum unique bin names allowed per namespace are 32k. Please run 'show statistics namespace like available' to get actual values. Possible improperly modeled data.",
				"Namespace available bin names check.");


/* Holds only upto 4B key */
s = select "memory-size" from NAMESPACE;
r = group by NODE, NAMESPACE do SUM(s);
e = do r <= 274877906944;
ASSERT(e, True, "Namespace configured to use more than 256G.", "LIMITS", WARNING,
				"On list nodes namespace as mentioned have configured more than 256G of memory. Namespace with data not in memory can have max upto 4billion keys and can utilize only up to 256G. Please run 'show statistics namespace like memory-size' to check configured memory.",
				"Namespace per node memory limit check.");

/*
Following query selects assigned memory-size from namespace statistics and total ram size from system statistics.
group by for namespace stats sums all memory size and gives node level memory size.
group by for system stats helps to remove key, this is requirement for proper matching for simple operations.
*/
s = select "memory-size" from NAMESPACE;
n = group by NODE do SUM(s);
s = select "total" from SYSTEM.RAM;
m = group by NODE do SUM(s);
r = do n <= m on common;
ASSERT(r, True, "Namespace memory misconfiguration.", "LIMITS", WARNING,
				"Listed node[s] have more namespace memory configured than available physical memory. Please run 'show statistics namespace like memory-size' to check configured memory and check output of 'free' for system memory. Possible namespace misconfiguration.",
				"Namespace memory configuration check.");

r = do m - n on common;
r = do r >= 5368709120;
ASSERT(r, True, "Aerospike runtime memory configured < 5G.", "LIMITS", INFO,
				"Listed node[s] have less than 5G free memory available for Aerospike runtime. Please run 'show statistics namespace like memory-size' to check configured memory and check output of 'free' for system memory. Possible misconfiguration.",
				"Namespace memory configuration check.");


/*
Following query selects proto-fd-max from service config and client_connections from service statistics.
It uses as clause to get proper matching structure for simple operation.
*/
max = select "proto-fd-max" as "fd" from SERVICE.CONFIG;
conn = select "client_connections" as "fd" from SERVICE.STATISTICS;
bound = do 80 %% max;
r = do conn > bound;
ASSERT(r, False, "High system client connections.", "OPERATIONS", WARNING,
				"Listed node[s] show higher than normal (> 80%) client-connections of the max configured proto-fd-max. Please run 'show config like proto-fd-max' and 'show statistics like client_connections' for actual values. Possible can be network issue / improper client behavior / FD leak.",
				"Client connections check.");


s = select like(".*available_pct") from NAMESPACE.STATISTICS;
r = do s < 20;
ASSERT(r, False, "Low namespace disk available pct.", "OPERATIONS", WARNING,
				"Listed namespace[s] have lower than normal (< 20 %). Please run 'show statistics namespace like available_pct' to check available disk space. Probable cause - namespace size misconfiguration.",
				"Namespace disk available pct check.");


s = select * from SERVICE.CONFIG;
r = group by KEY do EQUAL(s);
ASSERT(r, True, "Different service configurations.", "OPERATIONS", WARNING,
				"Listed Service configuration[s] are different across multiple nodes in cluster. Please run 'show config service diff' to check different configuration values. Probable cause - config file misconfiguration.",
				"Service configurations difference check.");


s = select "migrate-threads", "migrate_threads" from SERVICE.CONFIG;
r = do s > 1;
ASSERT(r, False, "> 1 migrate thread configured.", "OPERATIONS", INFO,
				"Listed node[s] are running with higher than normal (> 1) migrate threads. Please run 'show config service like migrate-threads' to check migration configuration. Is a non-issue if requirement is to run migration aggressively. Otherwise possible operational misconfiguration.",
				"Migration thread configuration check.");


/* Device Configuration */
s = select "device_total_bytes", "device-total-bytes", "total-bytes-disk" from NAMESPACE.STATISTICS;
r = group by NAMESPACE do EQUAL(s);
ASSERT(r, True, "Different namespace device size configuration.", "OPERATIONS", WARNING,
				"Listed namespace[s] have difference in configured disk size. Please run 'show statistics namespace like bytes' to check total device size. Probable cause - config file misconfiguration.",
				"Namespace device size configuration difference check.");

hwm = select "high-water-disk-pct" from NAMESPACE.CONFIG;
hwm = group by CLUSTER, NAMESPACE hwm;
r = do hwm == 50;
ASSERT(r, True, "Non-default namespace device high water mark configuration.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-default high water mark configuration. Please run 'show config namespace like high-water-disk-pct' to check value. Probable cause - config file misconfiguration.",
				"Non-default namespace device high water mark check.");

hwm = select "high-water-disk-pct" as "defrag-lwm-pct" from NAMESPACE.CONFIG;
lwm = select like(".*defrag-lwm-pct") as "defrag-lwm-pct" from NAMESPACE.CONFIG;
r = do lwm < hwm on common;
r = group by CLUSTER, NAMESPACE r;
ASSERT(r, False, "Defrag low water mark misconfigured.", "OPERATIONS", WARNING,
				"Listed namespace[s] have defrag-lwm-pct lower than high-water-disk-pct. This might create situation like no block to write, no eviction and no defragmentation. Please run 'show config namespace like high-water-disk-pct defrag-lwm-pct' to check configured values. Probable cause - namespace watermark misconfiguration.",
				"Defrag low water mark misconfiguration check.");

/*
Following query collects used device space and total device space and computes available free space on each node per namespace per cluster (group by CLUSTER, NAMESPACE, NODE).
It collects cluster-size and uses it to find out expected data distribution for each node in case that node is down. It checks max of this computed value per namespace
with available space per node per namespace.
*/

t = select "device_total_bytes" as "disk_space", "device-total-bytes" as "disk_space", "total-bytes-disk" as "disk_space" from NAMESPACE.STATISTICS;
u = select "used-bytes-disk" as "disk_space", "device_used_bytes" as "disk_space" from NAMESPACE.STATISTICS;
/* Available extra space */
e = do t - u;
e = group by CLUSTER, NAMESPACE, NODE do SUM(e);
s = select "cluster_size" as "size" from SERVICE;
n = do AVG(s);
n = do n - 1;
/* Extra space need if 1 node goes down */
e1 = do u / n;
e1 = group by CLUSTER, NAMESPACE do MAX(e1);
r = do e > e1;
ASSERT(r, True, "Namespace under configured (disk) for single node failure.", "OPERATIONS", WARNING,
				"Listed namespace[s] does not have enough disk space configured to deal with increase in data per node in case of 1 node failure. Please run 'show statistics namespace like bytes' to check device space. It is non-issue if single replica limit is set to larger values, i.e if number of replica copies are reduced in case of node loss.",
				"Namespace single node failure disk config check.");

/*
Same as above query but for memory
*/
t = select "memory-size" as "mem" from NAMESPACE;
u = select "used-bytes-memory" as "mem", "memory_used_bytes" as "mem" from NAMESPACE.STATISTICS;
/* Available extra space */
e = do t - u;
e = group by CLUSTER, NAMESPACE, NODE do SUM(e);

s = select "cluster_size" as "size" from SERVICE;
n = do AVG(s);
n = do n - 1;
/* Extra space need if 1 node goes down */
e1 = do u / n;
e1 = group by CLUSTER, NAMESPACE do MAX(e1);
r = do e > e1;
ASSERT(r, True, "Namespace under configured (memory) for single node failure.", "OPERATIONS", WARNING,
				"Listed namespace[s] does not have enough memory space configured to deal with increase in data per node in case of 1 node failure. Please run 'show statistics namespace like bytes' to check memory space. It is non-issue if single replica limit is set to larger values, i.e number of replica copies reduce.",
				"Namespace single node failure memory config check.");


/* Namespace Configuration */

nsid = select "nsid" from NAMESPACE.CONFIG;
r = group by CLUSTER, NAMESPACE do EQUAL(nsid);
ASSERT(r, True, "Different namespace order in aerospike conf.", "OPERATIONS", CRITICAL,
				"Listed namespace[s] have different order on different nodes. Please check aerospike conf file on all nodes and change configuration to make namespace order same.",
				"Namespace order check.");

r = select "replication-factor", "repl-factor" from NAMESPACE.CONFIG;
r = group by CLUSTER, NAMESPACE r;
r = do r == 2;
ASSERT(r, True, "Non-default namespace replication-factor configuration.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-default replication-factor configuration. Please run 'show config namespace like repl' to check value. It may be non-issue in case namespace are configured for user requirement. Ignore those.",
				"Non-default namespace replication-factor check.");

s = select * from NAMESPACE.CONFIG;
r = group by NAMESPACE, KEY do EQUAL(s);
ASSERT(r, True, "Different namespace configurations.", "OPERATIONS", WARNING,
				"Listed namespace configuration[s] are different across multiple nodes in cluster. Please run 'show config namespace diff' to get actual difference. It may be non-issue in case namespace are configured with different device or file name etc. Ignore those.",
				"Namespace configurations difference check.");


s = select like(".*_err.*") from SERVICE.STATISTICS;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do SUM(u);
s = do s / u;
r = group by KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster service errors count.", "ANOMALY", WARNING,
				"Listed service errors[s] show skew in error count patterns (for listed node[s]). Please run 'show statistics service like err' for details.",
				"Service errors count anomaly check.");


s = select like(".*_error") from NAMESPACE.STATISTICS;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do MAX(u);
s = do s / u on common;
d = group by NAMESPACE, KEY do SUM(s);
e = do d == 0;
ASSERT(e, True, "Non-zero namespace errors count.", "OPERATIONS", WARNING,
				"Listed namespace error[s] show skew in count (for nodes). It may or may not be an issue depending on the error type. Please run 'show statistics namespace like error' for details.",
				"Namespace errors count check.");

/*
Following query collects master_objects, prole_objects and replication_factor, and computes proles for one replication (prole_objects/(replication_factor-1)).
After that it find out master and prole distribution is in correct range with each other or not,
this last result will 'AND' with replication_enabled and migration_in_progress bools to avoid wrong assert failure
*/

m = select "master_objects" as "cnt", "master-objects" as "cnt" from NAMESPACE.STATISTICS;
p = select "prole_objects" as "cnt", "prole-objects" as "cnt" from NAMESPACE.STATISTICS;
r = select "replication-factor", "repl-factor" from NAMESPACE.CONFIG;
m = select "migrate_rx_partitions_active", "migrate_progress_recv", "migrate-rx-partitions-active"  from NAMESPACE.STATISTICS;
mt = group by NAMESPACE do SUM(m);
pt = group by NAMESPACE do SUM(p);
r = group by NAMESPACE do MAX(r);
m = group by NAMESPACE do MAX(m);
migration_in_progress = do m > 0;
replication_enabled = do r > 1;
r = do r - 1;
pt = do pt / r;
discounted_pt = do 95 %% pt;
d = do discounted_pt > mt;
d = do d && replication_enabled;
d = do d && migration_in_progress;
ASSERT(d, False, "Skewed namespace data distribution, prole objects exceed master objects by > 5%.", "DATA", INFO,
				"Listed namespace[s] show abnormal object distribution. It may not be an issue if migrations are in progress. Please run 'show statistics namespace like object' for actual counts.",
				"Namespace data distribution check (prole objects exceed master objects by > 5%).");
discounted_mt = do 95 %% mt;
d = group by NAMESPACE do discounted_mt > pt;
d = do d && replication_enabled;
d = do d && migration_in_progress;
ASSERT(d, False, "Skewed namespace data distribution, master objects exceed prole objects by > 5%.", "DATA", INFO,
				"Listed namespace[s] show abnormal object distribution. It may not be an issue if migrations are in progress. Please run 'show statistics namespace like object' for actual counts.",
				"Namespace data distribution check (master objects exceed prole objects by > 5%).");


s = select "set-delete", "deleting" as "set-delete" from SET;
r = group by NAMESPACE, SET do EQUAL(s);
ASSERT(r, True, "Different set delete status.", "OPERATIONS", INFO,
				"Listed set[s] have different set delete status across multiple nodes in cluster. This is non-issue if set-delete is being performed. Nodes reset the status asynchronously. Please check if nsup is still delete data for the set.",
				"Set delete status check.");


s = select like ("disable-eviction") from SET;
r = group by NAMESPACE, SET do EQUAL(s);
ASSERT(r, True, "Different set eviction configuration.", "OPERATIONS", WARNING,
				"Listed set[s] have different eviction setting across multiple nodes in cluster. Please run 'show statistics set like disable-eviction' to check values. Possible operational misconfiguration.",
				"Set eviction configuration difference check.");


s = select like ("set-enable-xdr") from SET;
r = group by NAMESPACE, SET do EQUAL(s);
ASSERT(r, True, "Different set xdr configuration.", "OPERATIONS", WARNING,
				"Listed set[s] have different XDR replication setting across multiple nodes in cluster. Please run 'show statistics set like set-enable-xdr' to check values. Possible operational misconfiguration.",
				"Set xdr configuration difference check.");


s = select "n_objects", "objects" as "n_objects" from SET;
/* Should be Anomaly */
r = group by NAMESPACE, SET do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster set object count.", "ANOMALY", WARNING,
				"Listed set[s] have skewed object distribution. Please run 'show statistics set like object' to check counts. It may be non-issue if cluster is undergoing migrations.",
				"Set object count anomaly check.");

/* XDR */

s = select * from XDR.CONFIG;
r = GROUP by KEY do EQUAL(s);
ASSERT(r, True, "Different XDR configurations.", "OPERATIONS", WARNING,
				"Listed XDR configuration[s] are different across multiple nodes in cluster. Please run 'show config xdr diff' to get difference. Possible operational misconfiguration.",
				"XDR configurations difference check.");


s = select * from XDR.STATISTICS;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do SUM(u);
s = do s / u;
r = group by KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster XDR statistics.", "ANOMALY", WARNING,
				"Listed XDR statistic[s] show skew for the listed node[s]. It may or may not be an issue depending on the statistic type.",
				"XDR statistics anomaly check.");

s = select * from DC.STATISTICS;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do SUM(u);
s = do s / u on common;
r = group by DC, KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster remote DC statistics.", "ANOMALY", WARNING,
				"Listed DC statistic[s] show skew for the listed node[s]. Please run 'show statistics dc' to get all DC stats. May be non-issue if remote Data center connectivity behavior for nodes is not same.",
				"Remote DC statistics anomaly check.");

/*
Following xdr queries are example of assert level check condition. We are considering assert only if provided condition is true (at least for one key).
Also we use same condition variable to filter keys for output. So we are using group by (CLUSTER, NODE), it makes condition variable values matching with
assert input data structure, only exceptions are data which grouped by DC, in that case key filtration will not be possible.
*/
xdr_enabled = select "enable-xdr" from XDR.CONFIG;
xdr_enabled = group by CLUSTER, NODE do OR(xdr_enabled);

s = select "xdr-dc-state", "dc_state"  from DC.STATISTICS;
r = group by DC do EQUAL(s);
ASSERT(r, True, "Different remote DC states.", "OPERATIONS", WARNING,
				"Listed node[s] have a different remote DC visibility. Please run 'show statistics dc like state' to see DC state. Possible network issue between data centers.",
				"Remote DC state check.",
				xdr_enabled);

s = select "free-dlog-pct", "dlog_free_pct", "free_dlog_pct" from XDR;
r = do s < 95;
ASSERT(r, False, "Low XDR free digest log space.", "OPERATIONS", INFO,
				"Listed node[s] have lower than ideal (95%) free digest log space. Please run 'show statistics xdr like free' to see digest log space. Probable cause - low XDR throughput or a failed node processing in progress.",
				"XDR free digest log space check.",
				xdr_enabled);
r = group by CLUSTER, NODE do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster XDR free digest log space.", "ANOMALY", WARNING,
				"Listed node[s] have different digest log free size pattern. Please run 'show statistics xdr like free' to see digest log space. May not be an issue if the nodes are newly added or have been restarted with noresume or if remote Datacenter connectivity behavior differs for nodes.",
				"XDR free digest log space anomaly check.",
				xdr_enabled);


/* Needs normalization but not sure on what ?? */
s = select "timediff_lastship_cur_secs", "xdr_timelag" from XDR.STATISTICS;
r = do s > 10;
ASSERT(r, False, "High XDR shipping lag (> 10s).", "PERFORMANCE", WARNING,
				"Listed node[s] have higher than healthy ( > 10 sec) ship lag to remote data center. Please run 'show statistics xdr like time' to see shipping lag. Probable cause - connectivity issue to remote datacenter or spike in write throughput on the local cluster.",
				"XDR shipping lag check.",
				xdr_enabled);
r = group by CLUSTER, NODE do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Cluster XDR shipping lag skewed.", "ANOMALY", WARNING,
				"Listed node[s] have different ship lag patterns. Please run 'show statistics xdr like time' to see shipping lag. May not be an issue if the nodes are newly added or have been restarted with noresume or if remote Datacenter connectivity behavior differs for nodes.",
				"XDR shipping lag anomaly check.",
				xdr_enabled);


s = select "xdr-dc-timelag", "dc_timelag" from DC.STATISTICS;
r = group by DC do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster remote DC Lag.", "ANOMALY", WARNING,
				"Listed node[s] have different latency to remote data center. Please run 'show statistics dc like timelag' to see timelag. Possible Data center connectivity issue.",
				"Remote DC lag anomaly check.",
				xdr_enabled);


/* XDR xdr_read_latency_avg check */
s = select "xdr_read_latency_avg", "local_recs_fetch_avg_latency" from XDR.STATISTICS;
r = do s > 2;
ASSERT(r, False, "High XDR average read latency (>2 sec).", "PERFORMANCE", WARNING,
				"Listed node[s] have higher than normal (> 2sec) local read latencies. Please run 'show statistics xdr like latency' to see XDR read latency. Probable cause - system overload causing transaction queue to back up.",
				"XDR average read latency check.",
				xdr_enabled);


s = select "dc_open_conn" as "conn" from DC.STATISTICS;
ds = select "dc_size" as "conn" from DC.STATISTICS;
ds = do ds * 64;
r = do s > ds;
ASSERT(r, False, "High remote DC connections.", "LIMITS", WARNING,
				"Listed node[s] have higher than normal remote datacenter connections. Generally accepted number is (64*No of nodes in remote DC) per node. Please run 'show statistics dc like dc_open_conn dc_size' to see DC connection statistics. Ignore if XDR is not pipelined.",
				"Remote DC connections check.",
				xdr_enabled);


s = select "xdr_uninitialized_destination_error", "noship_recs_uninitialized_destination" from XDR.STATISTICS;
r = do s > 0;
ASSERT(r, False, "Uninitialized destination cluster.", "OPERATIONS", WARNING,
				"Listed node[s] have a non zero value for this uninitialized DC. Please check the configuration.",
				"Uninitialized destination cluster check.",
				xdr_enabled);


s = select "xdr_unknown_namespace_error", "noship_recs_unknown_namespace" from XDR.STATISTICS;
r = do s > 0;
ASSERT(r, False, "Missing namespace in remote data center.", "OPERATIONS", WARNING,
				"Certain namespace not found in remote DC. Please check the configuration to ascertain if remote DC has all the namespace being shipped.",
				"Remote DC namespace check.",
				xdr_enabled);

/* XDR failednode_sessions_pending check */
s = select "failednode_sessions_pending", "xdr_active_failed_node_sessions" from XDR.STATISTICS;
r = do s > 0;
ASSERT(r, False, "Active failed node sessions.", "OPERATIONS", INFO,
                "Listed node[s] have failed node sessions pending. Please check if there are any failed nodes on the source cluster.",
                "Active failed node sessions check.",
                xdr_enabled);

/* XDR linkdown_sessions_pending check */
s = select "linkdown_sessions_pending", "xdr_active_link_down_sessions" from XDR.STATISTICS;
r = do s > 0;
ASSERT(r, False, "Active linkdown sessions.", "OPERATIONS", INFO,
                "Listed node[s] have link down sessions pending. Please check the connectivity of remote datacenter.",
                "Active linkdown sessions check.",
                xdr_enabled);

/* XDR xdr_ship_outstanding_objects check */
s = select "xdr_ship_outstanding_objects", "stat_recs_outstanding" from XDR.STATISTICS;
r = do s > 10000;
ASSERT(r, False, "Too many outstanding objects (>10000) to ship !!.", "OPERATIONS", WARNING,
                "Listed node[s] have too many records outstanding. Please check relogging and error statistics.",
                "XDR outstanding objects check.",
                xdr_enabled);

/* XDR xdr_ship_inflight_objects check */
s = select "xdr_ship_inflight_objects", "stat_recs_inflight" from XDR.STATISTICS;
r = do s > 5000;
ASSERT(r, False, "Too many inflight objects (>5000).", "PERFORMANCE", WARNING,
                "Listed node[s] have too many objects inflight. This might lead to XDR throttling itself, consider tuning this parameter to a lower value.",
                "Crossing xdr-max-ship-throughput check.",
                xdr_enabled);

/* XDR xdr_ship_latency_avg check */
s = select "xdr_ship_latency_avg", "latency_avg_ship" from XDR.STATISTICS;
// Following value is not fixed yet
r = do s > 5;
ASSERT(r, False, "Record shipping takes too long (>5 sec).", "PERFORMANCE", WARNING,
				"Listed node[s] have more than normal (>5sec) average shipping latency to remote data center. Possible high connectivity latency or performance issue at the remote data center.",
				"XDR average ship latency check.",
				xdr_enabled);


/* CLUSTER STATE */

r = select "cluster_integrity" from SERVICE.STATISTICS;
r = do r == True;
ASSERT(r, True, "Cluster integrity fault.", "OPERATIONS", CRITICAL,
				"Listed node[s] have cluster integrity fault. This indicates cluster is not completely wellformed. Please check server logs for more information. Probable cause - issue with network.",
				"Cluster integrity fault check.");

r = select "cluster_key" from SERVICE.STATISTICS;
r = do EQUAL(r);
ASSERT(r, True, "Different Cluster Key.", "OPERATIONS", CRITICAL,
				"Listed cluster[s] have different cluster keys for nodes. This indicates cluster is not completely wellformed. Please check server logs for more information. Probable cause - issue with network.",
				"Cluster Key difference check.");

u = select "uptime" from SERVICE.STATISTICS;
total_nodes = group by CLUSTER do COUNT(u);
r = select "cluster_size" from SERVICE.STATISTICS;
r = do r == total_nodes;
ASSERT(r, True, "Unstable Cluster.", "OPERATIONS", CRITICAL,
				"Listed node[s] have cluster size not matching total number of available nodes. This indicates cluster is not completely wellformed. Please check server logs for more information. Probable cause - issue with network.",
				"Cluster stability check.");


/* UDF */

u = select * from UDF.METADATA;
r = group by FILENAME, KEY do EQUAL(u);
ASSERT(r, True, "UDF not in sync (file not matching).", "OPERATIONS", CRITICAL,
				"Listed UDF definitions do not match across the nodes. This may lead to incorrect UDF behavior. Run command 'asinfo -v udf-list' to see list of UDF. Re-register the latest version of the not in sync UDF[s].",
				"UDF sync (file not matching) check.");
total_nodes = group by CLUSTER do COUNT(u);
c = group by CLUSTER, FILENAME do COUNT(u);
r = do c == total_nodes;
ASSERT(r, True, "UDF not in sync (not available on all node).", "OPERATIONS", CRITICAL,
				"Listed UDF[s] are not available on all the nodes. This may lead to incorrect UDF behavior. Run command 'asinfo -v udf-list' to see list of UDF. Re-register missing UDF in cluster.",
				"UDF sync (availability on all node) check.");

/* SINDEX */

s = select "sync_state" from SINDEX.STATISTICS;
s = group by CLUSTER, NAMESPACE, SET, SINDEX s;
r = do s == "synced";
ASSERT(r, True, "SINDEX not in sync with primary.", "OPERATIONS", CRITICAL,
				"Listed sindex[es] are not in sync with primary. This can lead to wrong query results. Consider dropping and recreating secondary index[es].",
				"SINDEX sync state check.");
u = select "uptime" from SERVICE.STATISTICS;
total_nodes = group by CLUSTER do COUNT(u);
c = group by CLUSTER, NAMESPACE, SET, SINDEX do COUNT(s);
r = do c == total_nodes;
ASSERT(r, True, "SINDEX not in sync (not available on all node).", "OPERATIONS", CRITICAL,
				"Listed sindex[es] not available on all nodes. This can lead to wrong query results. Consider dropping and recreating missing secondary index[es].",
				"SINDEX metadata sync (availability on all node) check.");


/* LDT */

l = select like("ldt_.*");
r = do l > 0;
ASSERT(r, False, "Deprecated feature LDT in use.", "OPERATIONS", WARNING,
				"Listed nodes[s] have non-zero LDT statistics. This feature is deprecated. Please visit Aerospike Homepage for details.",
				"LDT statistics check.");

/*
	Different queries for different versions. All version constraint sections should be at the bottom of file, it will avoid extra version reset at the end.
*/

SET CONSTRAINT VERSION >= 3.9;

u = select "uptime" from SERVICE.STATISTICS;
u = GROUP BY CLUSTER, NODE do SUM(u);

e = select "client_write_error" from NAMESPACE.STATISTICS;
s = select "client_write_success" from NAMESPACE.STATISTICS;
s = GROUP BY CLUSTER, NODE, NAMESPACE do SUM(s);
r = do e / s;
r = do r/u on common;
r = do r == 0;
ASSERT(r, True, "Non-zero namespace write errors count", "OPERATIONS", INFO,
				"Listed namespace write error[s] show skew in count across nodes in cluster. It may or may not be an issue depending on the error type (e.g gen check errors may be expected if client is using check and set kind of operations). Please run 'show statistics namespace like client_write' to see values.",
				"Namespace write errors count check");

e = select "client_read_error" from NAMESPACE.STATISTICS;
s = select "client_read_success" from NAMESPACE.STATISTICS;
s = GROUP BY CLUSTER, NODE, NAMESPACE do SUM(s);
r = do e / s;
r = do r/u on common;
r = do r == 0;
ASSERT(r, True, "Non-zero namespace read errors count", "OPERATIONS", INFO,
				"Listed namespace read error[s] show skew in count across nodes in the cluster. It may or may not be an issue depending on the error type (e.g key not found may be expected). Please run 'show statistics namespace like client_read' to see values.",
				"Namespace read errors count check");

e = select "client_delete_error" from NAMESPACE.STATISTICS;
s = select "client_delete_success" from NAMESPACE.STATISTICS;
s = GROUP BY CLUSTER, NODE, NAMESPACE do SUM(s);
r = do e / s;
r = do r/u on common;
r = do r == 0;
ASSERT(r, True, "Non-zero namespace delete errors count", "OPERATIONS", INFO,
				"Listed namespace delete error[s] show skew in count across nodes in the cluster. It may or may not be an issue depending on the error type (e.g key not found). Please run 'show statistics namespace like client_delete' to see values.",
				"Namespace delete errors count check");

e = select "batch_sub_tsvc_timeout" from NAMESPACE.STATISTICS;
e = do e/u on common;
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero batch-index read sub-transaction timeouts.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero batch-index read sub-transaction timeouts across the nodes. Please run 'show statistics namespace like batch_sub_tsvc_timeout' to see the values.",
				"Namespace batch-index read sub-transaction timeout count check");

e = select "client_tsvc_timeout" from NAMESPACE.STATISTICS;
e = do e/u on common;
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero client transaction timeouts.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero client transaction timeouts (for nodes). Please run 'show statistics namespace like client_tsvc_timeout' to see values. Probable cause - congestion in the transaction queue (transaction threads not able to process efficiently enough), or it could also be that the timeout set by the client is too aggressive.",
				"Namespace client transaction timeout count check");

e = select "client_udf_error" from NAMESPACE.STATISTICS;
e = do e/u on common;
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero UDF transaction failure.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero UDF transaction failures (for nodes). Please run 'show statistics namespace like client_udf_error' to see values.",
				"Namespace UDF transaction failure check");

e = select "client_udf_timeout" from NAMESPACE.STATISTICS;
e = do e/u on common;
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero UDF transaction timeouts.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero UDF transaction timeouts (for nodes). Please run 'show statistics namespace like client_udf_timeout' to see values.",
				"Namespace UDF transaction timeout check");

e = select "udf_sub_udf_error" from NAMESPACE.STATISTICS;
e = do e/u on common;
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero UDF sub-transaction failures.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero UDF sub-transaction failures across nodes in cluster for scan/query background udf jobs. Please run 'show statistics namespace like udf_sub_udf_error udf_sub_lang_' to see details.",
				"Namespace UDF sub-transaction failure check");

e = select "client_write_timeout" from NAMESPACE.STATISTICS;
e = do e/u on common;
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero write transaction timeouts.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero write transaction timeouts (for nodes). Please run 'show statistics namespace like client_write_timeout' to see values.",
				"Namespace write transaction timeout check");

e = select "client_read_not_found" from NAMESPACE.STATISTICS;
e = group by CLUSTER, NAMESPACE e;
s = select "client_read_success" from NAMESPACE.STATISTICS;
s = group by CLUSTER, NAMESPACE, NODE do MAX(s);
s = do 50 %% s;
r = do e <= s;
ASSERT(r, True, "High read not found errors", "OPERATIONS", INFO,
				"Listed namespace[s] show higher than normal read not found errors (> 50% client read success). Please run 'show statistics namespace like client_read_not_found client_read_success' to see values.",
				"High read not found error check");

e = select "xdr_write_error" from NAMESPACE.STATISTICS;
e = do e/u on common;
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero XDR write errors count.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero XDR write transaction failures (for nodes). Please run 'show statistics namespace like xdr_write_error' to see values.",
				"Namespace XDR write failure check");

e = select "xdr_write_timeout" from NAMESPACE.STATISTICS;
e = do e/u on common;
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero XDR write timeouts.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero XDR write transaction timeouts (for nodes). Please run 'show statistics namespace like xdr_write_timeout' to see values.",
				"Namespace XDR write timeout check");

SET CONSTRAINT VERSION < 3.9;

e = select "stat_write_errs" from SERVICE.STATISTICS;
s = select "stat_write_success" from SERVICE.STATISTICS;
s = GROUP BY CLUSTER, NODE do SUM(s);
u = select "uptime" from SERVICE.STATISTICS;
u = GROUP BY CLUSTER, NODE do SUM(u);
r = do e / s;
r = do r/u on common;
r = do r == 0;
ASSERT(r, True, "Non-zero node write errors count", "OPERATIONS", INFO,
				"Listed write error[s] show skew in count (for nodes). It may or may not be an issue depending on the error type. Please run 'show statistics service like stat_write' to see values.",
				"Node write errors count check");

e = select "stat_read_errs_other" from SERVICE.STATISTICS;
s = select "stat_read_success" from SERVICE.STATISTICS;
s = GROUP BY CLUSTER, NODE do SUM(s);
u = select "uptime" from SERVICE.STATISTICS;
u = GROUP BY CLUSTER, NODE do SUM(u);
r = do e / s;
r = do r/u on common;
r = do r == 0;
ASSERT(r, True, "Non-zero node read errors count", "OPERATIONS", INFO,
				"Listed read error[s] show skew in count (for nodes). It may or may not be an issue depending on the error type. Please run 'show statistics service like stat_read' to see values.",
				"Node read errors count check");

SET CONSTRAINT VERSION >= 3.3.17;

defslp= select "storage-engine.defrag-sleep" from NAMESPACE.CONFIG;
r = do defslp == 1000;
ASSERT(r, True, "Non-default namespace defrag-sleep configuration.", "OPERATIONS",INFO,
				"Listed namespace[s] have non-default defrag-sleep configuration. Please run 'show config namespace like defrag' to check value. It may be a non-issue in case namespace are configureg for aggressive defrag. Ignore those.",
				"Non-default namespace defrag-sleep check.");



SET CONSTRAINT VERSION ALL;

'''
