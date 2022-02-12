# Copyright 2013-2021 Aerospike, Inc.
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

QUERIES = """
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

/* Variables */

error_pct_threshold = 1;

SET CONSTRAINT VERSION ALL;

/* System checks */

limit = select "Soft_Max_open_files" as "fd" from SYSTEM.LIMITS save;
limit = group by CLUSTER, NODE, KEY do SUM(limit);
config = select "proto-fd-max" as "fd" from SERVICE.CONFIG save;
r = do config < limit;
ASSERT(r, True, "File descriptor is configured higher than limit.", "LIMITS", INFO,
			    "Listed node[s] have proto-fd-limit set higher than system soft limit of Max open files. Aerospike process may run out of file descriptor, Possible misconfiguration.",
			    "System open file descriptor limit check.");

s = select * from SYSTEM.HDPARM save;
r = group by KEY do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different Disk Hardware in cluster.", "OPERATIONS", INFO,
                            "Different disk hardware configuration across multiple nodes in cluster.", "Disk hardware check.");

s = select "OOM" from SYSTEM.DMESG save;
ASSERT(s, False, "DMESG: Process Out of Memory kill.", "OPERATIONS", INFO,
                            "Certain process was killed due to Out Of Memory. Check dmesg or system log.",
                            "System OOM kill check.");

s = select "Blocked" from SYSTEM.DMESG save;
ASSERT(s, False, "DMESG: Process blocking.", "OPERATIONS", INFO,
                            "Certain process was blocked for more than 120sec. Check dmesg or system log.",
                            "System process blocking Check.");

s = select "OS" from SYSTEM.DMESG save;
r = group by NODE do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different OS version in cluster.", "OPERATIONS", INFO,
                            "Different version of OS running across multiple nodes in cluster.", "OS version check.");

s = select * from SYSTEM.LSCPU save;
r = group by KEY do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "CPU configuration mismatch.", "OPERATIONS", INFO,
                            "Listed node[s] in the cluster are running with different CPU or CPU setting, performance may be skewed. Please run 'lscpu' to check CPU configuration.",
                            "CPU config check.");

s = select "vm_drop_caches", "vm_nr_hugepages", "vm_nr_hugepages_policy", "vm_numa_zonelist_order", "vm_oom_dump_tasks", "vm_oom_kill_allocating_task", "vm_zone_reclaim_mode", "vm_swapiness",
            "vm_nr_overcommit_hugepages", "kernel_shmmax", "kernel_shmall", "kernel_version" from SYSTEM.SYSCTLALL save;
r = group by KEY do NO_MATCH(s, ==, MAJORITY);
ASSERT(r, False, "Sysctl configuration mismatch.", "OPERATIONS", INFO,
                            "Listed node[s] in the cluster are running with different Sysctl setting. Please run 'sysctl -a' to check CPU configuration.",
                            "Sysctl config check.");

s = select "has_firewall" from SYSTEM.IPTABLES;
ASSERT(s, False, "Node in cluster have firewall setting.", "OPERATIONS", INFO,
                                "Listed node[s] have firewall setting. Could cause cluster formation issue if misconfigured. Please run 'iptables -L' to check firewall rules.",
				"Firewall Check.");

s = select "AnonHugePages" from SYSTEM.MEMINFO save;
r = do s < 102400;
ASSERT(r, True, "THP may be enabled.", "OPERATIONS", WARNING,
						"Listed node[s] have AnonHugePages higher than 102400KiB. Node[s] may have THP enabled which may cause higher memory usage. See https://discuss.aerospike.com/t/disabling-transparent-huge-pages-thp-for-aerospike/5233 for more info.", 
						"System THP enabled check");


/* AWS */

l = select "os_age_months" from SYSTEM.LSB save;
r = do l > 12;
ASSERT(r, False, "Old Amazon Linux AMI.", "OPERATIONS", WARNING,
                            "Amazon Linux AMI is older than 12 months. It might causes periodic latency spikes probably due to a driver issue.",
                            "Amazon Linux AMI version check.");

s = select "ENA_enabled" from SYSTEM.DMESG;
aws_enabled = select "platform" from SYSTEM.ENVIRONMENT;
aws_enabled = do aws_enabled == "aws";
aws_enabled = group by CLUSTER, NODE do OR(aws_enabled);
ASSERT(s, True, "ENA not enabled.", "OPERATIONS", INFO,
                            "ENA is not enabled on AWS instance. Please check with Aerospike support team.",
                            "ENA enable check.", aws_enabled);

/* Disk */
s = select "%util" from SYSTEM.IOSTAT save;
r = do s > 90;
ASSERT(r, False, "High system disk utilization.", "PERFORMANCE", CRITICAL,
				"Listed disks show higher than normal (> 90%) disk utilization at the time of sampling. Please run 'iostat' command to check disk utilization. Possible causes can be disk overload due to undersized cluster or some issue with disk hardware itself. If running on cloud, can be a problem with cloud instance itself.",
				"Disk utilization check.");
r1 = group by DEVICE do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed cluster disk utilization.", "ANOMALY", WARNING,
				"Listed disks show different disk utilization compared to other node[s]. Please run 'iostat' command on those node[s] to confirm such behavior. Possible causes can be skew in workload (e.g hotkey) and/or issue with disk on the specific node[s] which show anomalistic behavior.",
				 "Disk utilization Anomaly.");


avail=select like(".*available_pct") as "free_disk" from NAMESPACE.STATISTICS save;
disk_free = select "device_free_pct" as "free_disk", "free-pct-disk" as "free_disk" from NAMESPACE.STATISTICS save;
r = do disk_free - avail save as "fragmented blocks pct";
r = do r <= 30;
r = group by CLUSTER, NAMESPACE r;
ASSERT(r, True, "High (> 30%) fragmented blocks.", "PERFORMANCE", WARNING,
				"Listed namespace[s] have higher than normal (>30%) fragmented blocks at the time of sampling. Please run 'show config namespace like defrag' to check defrag configurations. Possible cause can be Aerospike disk defragmentation not keeping up with write rate and/or large record sizes causing fragmentation. Refer to knowledge base article discuss.aerospike.com/t/defragmentation for more details.",
				"Fragmented Blocks check.");


s = select "%iowait" from SYSTEM.IOSTAT save;
r = do s > 10;
ASSERT(r, False, "High (> 10%) CPU IO wait time.", "PERFORMANCE", WARNING,
				"Listed nodes show higher than normal (> 10%) CPU spent in io wait. Please run 'iostat' command to check utilization. Possible cause can be slow disk or network leading to lot of CPU time spent waiting for IO.",
				"CPU IO wait time check.");
r1 = group by NODE do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed CPU IO wait time.", "ANOMALY", WARNING,
				"Listed nodes show skew in CPU IO wait time compared to other nodes in cluster. Please run 'iostat' command to check utilization. Possible cause can be skew in workload (e.g hotkey) and/or slow network/disk on the specific node[s] which show anomalistic behavior.",
				 "CPU IO wait time anomaly.");


s = select "await" from SYSTEM.IOSTAT save;
r = do s > 4;
ASSERT(r, False, "High system disk average wait time.", "PERFORMANCE", WARNING,
				"Listed disks show higher than normal (> 4ms) disk average wait time. Please run 'iostat' command to check average wait time (await). Possible cause can be issue with disk hardware or VM instance in case you are running in cloud environment. This may also be caused by having storage over network like say SAN device or EBS.",
				"Disk average wait time check.");
r1 = group by DEVICE do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed cluster disk average wait time", "ANOMALY", WARNING,
				"Listed disks show different average wait time characteristic compared to other node[s]. Please run 'iostat' command on those node[s] to confirm such behavior. Possible can be skew in workload (e.g hotkey) and/or disk issue on the specific node[s] which should anomalistic behavior.",
				"Disk average wait time anomaly check.");


s = select "avgqu-sz" from SYSTEM.IOSTAT save;
r = do s > 7;
ASSERT(r, False, "High disk average queue size.", "PERFORMANCE", INFO,
				"Listed disks show higher than normal (> 7) disk average queue size. This is not a issue if using NVME drives which support more queues. Please run 'iostat' command to check average wait time (avgqu-sz). Possible disk overload. This may be non-issue of disk has more than 7 queues. Please analyze this number in conjunction with utilization.",
				"Disk avg queue size check.");
r1 = group by DEVICE do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed cluster disk avg queue size.", "ANOMALY", WARNING,
				"Listed disks show different average queue size characteristic compared to other node[s]. Please run 'iostat' command on those node[s] to confirm such behavior. Possible issue can be differential load on these node[s] or issue with disk.",
				"Disk avg queue size anomaly check.");


s = select "id" as "cpu_use" from SYSTEM.TOP.CPU_UTILIZATION save as "cpu_idle_pct";
s = do 100 - s save as "cpu utilization pct";
r = do s > 70;
ASSERT(r, False, "High system CPU utilization.", "PERFORMANCE", CRITICAL,
				"Listed node[s] are showing higher than normal (> 70%) CPU utilization. Please check top output. Possible system overload.",
				"CPU utilization check.");
r1 = group by CLUSTER, KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r1, False, "Skewed cluster CPU utilization.", "ANOMALY", WARNING,
				"Listed node[s] show different CPU utilization characteristic compared to other node[s]. Please run top command on those node[s] to confirm such behavior. Possible skew in workload.",
				"CPU utilization anomaly check.");


s = select "resident_memory" from SYSTEM.TOP save;
r = group by KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster resident memory utilization.", "ANOMALY", WARNING,
				"Listed node[s] show different resident memory usage compared to other node[s]. Please run top command on those node[s] to confirm such behavior. Possible skewed data distribution. This may be non-issue in case migrations are going on.",
				"Resident memory utilization anomaly.");


s = select "system_swapping" from SERVICE.STATISTICS save;
r = do s == true;
ASSERT(r, False, "System memory swapping.", "LIMITS", INFO,
				"Listed node[s] are swapping. Please run 'show statistics service like system_swapping' to confirm such behaviour. Possible misconfiguration. This may be non-issue if amount of swap is small and good amount of memory available.",
				"System swap check.");

/* TODO - is it really actually an issue */
s = select "system_free_mem_pct" from SERVICE.STATISTICS save;
r = do s < 20;
ASSERT(r, False, "Low system memory percentage.", "LIMITS", CRITICAL,
				"Listed node[s] have lower than normal (< 20%) system free memory percentage. Please run 'show statistics service like system_free_mem_pct' to get actual values. Possible misconfiguration.",
				"System memory percentage check.");

f = select "memory_free_pct" as "stats", "free-pct-memory" as "stats" from NAMESPACE.STATISTICS save;
s = select "stop-writes-pct" as "stats" from NAMESPACE.CONFIG save;
u = do 100 - f save as "memory_used_pct";
r = do u <= s;
ASSERT(r, True, "Low namespace memory available pct (stop-write enabled).", "OPERATIONS", CRITICAL,
				"Listed namespace[s] have lower than normal (< (100 - memory_free_pct)) available memory space. Probable cause - namespace size misconfiguration.",
				"Critical Namespace memory available pct check.");

/* NB : ADD CHECKS IF NODES ARE NOT HOMOGENOUS MEM / NUM CPU etc */


s = select "available_bin_names", "available-bin-names" from NAMESPACE save;
r = group by NAMESPACE do s > 3200;
ASSERT(r, True, "Low namespace available bin names.", "LIMITS", WARNING,
				"Listed node[s] have low available bin name (< 3200) for corresponding namespace[s]. Maximum unique bin names allowed per namespace are 32k. Please run 'show statistics namespace like available' to get actual values. Possible improperly modeled data.",
				"Namespace available bin names check.");


/* Holds only upto 4B key */
SET CONSTRAINT VERSION < 3.12;
s = select "memory-size" from NAMESPACE.CONFIG save;
r = group by CLUSTER, NODE, NAMESPACE do SUM(s);
e = do r <= 274877906944;
ASSERT(e, True, "Namespace configured to use more than 256G.", "LIMITS", WARNING,
				"On listed nodes namespace as mentioned have configured more than 256G of memory. Namespace with data not in memory can have max upto 4 billion keys and can utilize only up to 256G. Please run 'show statistics namespace like memory-size' to check configured memory.",
				"Namespace per node memory limit check.");
SET CONSTRAINT VERSION ALL;

/*
Following query selects assigned memory-size from namespace config and total ram size from system statistics.
group by for namespace stats sums all memory size and gives node level memory size.
group by for system stats helps to remove key, this is requirement for proper matching for simple operations.
*/
s = select "memory-size" from NAMESPACE.CONFIG save;
n = group by NODE do SUM(s) save as "sum of memory-size";
s = select "total" from SYSTEM.FREE.MEM;
m = group by NODE do SUM(s) save as "total physical memory";
r = do n <= m on common;
ASSERT(r, True, "Namespace memory misconfiguration.", "LIMITS", WARNING,
				"Listed node[s] have more namespace memory configured than available physical memory. Please run 'show statistics namespace like memory-size' to check configured memory and check output of 'free' for system memory. Possible namespace misconfiguration.",
				"Namespace memory configuration check.");

r = do m - n on common save as "runtime memory";
r = do r >= 5368709120;
ASSERT(r, True, "Aerospike runtime memory configured < 5G.", "LIMITS", INFO,
				"Listed node[s] have less than 5G free memory available for Aerospike runtime. Please run 'show statistics namespace like memory-size' to check configured memory and check output of 'free' for system memory. Possible misconfiguration.",
				"Runtime memory configuration check.");


/*
Current configurations and config file values difference check
*/

oc = select * from SERVICE.ORIGINAL_CONFIG save;
c = select * from SERVICE.CONFIG save;
r = do oc == c on common;
ASSERT(r, True, "Service configurations different than config file values.", "OPERATIONS", INFO,
                 "Listed Service configuration[s] are different than actual initial value set in aerospike.conf file.",
                            "Service config runtime and conf file difference check.");

oc = select * from NETWORK.ORIGINAL_CONFIG save;
c = select * from NETWORK.CONFIG save;
r = do oc == c on common;
ASSERT(r, True, "Network configurations different than config file values.", "OPERATIONS", INFO,
                 "Listed Network configuration[s] are different than actual initial value set in aerospike.conf file.",
                            "Network config runtime and conf file difference check.");

oc = select * from NAMESPACE.ORIGINAL_CONFIG save;
c = select * from NAMESPACE.CONFIG save;
r = do oc == c on common;
ASSERT(r, True, "Namespace configurations different than config file values.", "OPERATIONS", INFO,
                 "Listed namespace configuration[s] are different than actual initial value set in aerospike.conf file.",
                            "Namespace config runtime and conf file difference check.");

oc = select * from XDR.ORIGINAL_CONFIG save;
c = select * from XDR.CONFIG save;
r = do oc == c on common;
ASSERT(r, True, "XDR configurations different than config file values.", "OPERATIONS", INFO,
                 "Listed XDR configuration[s] are different than actual initial value set in aerospike.conf file.",
                            "XDR config runtime and conf file difference check.");

oc = select * from DC.ORIGINAL_CONFIG save;
c = select * from DC.CONFIG save;
r = do oc == c on common;
ASSERT(r, True, "DC configurations different than config file values.", "OPERATIONS", INFO,
                 "Listed DC configuration[s] are different than actual initial value set in aerospike.conf file.",
                            "DC config runtime and conf file difference check.");


/*
Following query selects proto-fd-max from service config and client_connections from service statistics.
It uses as clause to get proper matching structure for simple operation.
*/
max = select "proto-fd-max" as "fd" from SERVICE.CONFIG save;
conn = select "client_connections" as "fd" from SERVICE.STATISTICS save;
bound = do 80 %% max;
r = do conn > bound;
ASSERT(r, False, "High system client connections.", "OPERATIONS", WARNING,
				"Listed node[s] show higher than normal client-connections (> 80% of the max configured proto-fd-max). Please run 'show config like proto-fd-max' and 'show statistics like client_connections' for actual values. Possible can be network issue / improper client behavior / FD leak.",
				"Client connections check.");

s = select like(".*available_pct") as "stats" from NAMESPACE.STATISTICS save;
m = select like(".*min-avail-pct") as "stats" from NAMESPACE.CONFIG save;
critical_check = do s >= m;
ASSERT(critical_check, True, "Low namespace disk available pct (stop-write enabled).", "OPERATIONS", CRITICAL,
				"Listed namespace[s] have lower than normal (< min-avail-pct) available disk space. Probable cause - namespace size misconfiguration.",
				"Critical Namespace disk available pct check.");

critical_check = do s < m;
r = do s >= 20;
r = do r || critical_check;
ASSERT(r, True, "Low namespace disk available pct.", "OPERATIONS", WARNING,
				"Listed namespace[s] have lower than normal (< 20 %) available disk space. Probable cause - namespace size misconfiguration.",
				"Namespace disk available pct check.");

s = select * from SERVICE.CONFIG ignore "heartbeat.mtu", "node-id-interface", "node-id", "pidfile", like(".*address"), like(".*port")  save;
r = group by CLUSTER, KEY do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different service configurations.", "OPERATIONS", WARNING,
				"Listed Service configuration[s] are different across multiple nodes in cluster. Please run 'show config service diff' to check different configuration values. Probable cause - config file misconfiguration.",
				"Service configurations difference check.");

multicast_mode_enabled = select like(".*mode") from NETWORK.CONFIG;
multicast_mode_enabled = do multicast_mode_enabled == "multicast";
multicast_mode_enabled = group by CLUSTER, NODE do OR(multicast_mode_enabled);
s = select like(".*mtu")  from NETWORK.CONFIG save;
r = group by CLUSTER do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different heartbeat.mtu.", "OPERATIONS", WARNING,
				"Listed node[s] have a different heartbeat.mtu configured. A multicast packet can only be as large as the interface mtu. Different mtu values might create cluster stability issue. Please contact Aerospike Support team.",
				"heartbeat.mtu check.",
				multicast_mode_enabled);

interval = select "heartbeat.interval" from NETWORK.CONFIG save;
r1 = do interval < 150;
r2 = do interval > 250;
r = do r1 || r2;
ASSERT(r, False, "Heartbeat interval is not in expected range (150 <= p <= 250)", "OPERATIONS", INFO,
        "Listed node(s) have heartbeat interval value not in expected range (150 <= p <= 250). New node might fail to join cluster.",
        "Heartbeat interval Check (150 <= p <= 250)");

timeout = select "heartbeat.timeout" from NETWORK.CONFIG save;
r1 = do timeout < 10;
r2 = do timeout > 15;
r = do r1 || r2;
ASSERT(r, False, "Heartbeat timeout is not in expected range (10 <= p <= 15)", "OPERATIONS", INFO,
        "Listed node(s) have heartbeat timeout value not in expected range (10 <= p <= 15). New node might fail to join cluster.",
        "Heartbeat timeout Check (10 <= p <= 15)");


s = select "migrate-threads", "migrate_threads" from SERVICE.CONFIG save;
r = do s > 1;
ASSERT(r, False, "> 1 migrate thread configured.", "OPERATIONS", INFO,
				"Listed node[s] are running with higher than normal (> 1) migrate threads. Please run 'show config service like migrate-threads' to check migration configuration. Is a non-issue if requirement is to run migration aggressively. Otherwise possible operational misconfiguration.",
				"Migration thread configuration check.");


/* Device Configuration */
s = select "scheduler" from SYSTEM.SCHEDULER save;
r = do s == "noop";
ASSERT(r, True, "Non-recommended IO scheduler.", "OPERATIONS", WARNING,
				"Listed device[s] have not configured with noop scheduler. This might create situation like slow data migrations. Please contact Aerospike Support team. Ignore if device is not used in any namespace.",
				"Device IO scheduler check.");

f = select "name" from SYSTEM.DF;
d = select like(".*device.*") from NAMESPACE.CONFIG save;
r = do APPLY_TO_ANY(d, IN, f);
ASSERT(r, False, "Device name misconfigured.", "OPERATIONS", WARNING,
				"Listed device[s] have partitions on same node. This might create situation like data corruption where data written to main drive gets overwritten/corrupted from data written to or deleted from the partition with the same name.",
				"Device name misconfiguration check.");

s = select "device_total_bytes", "device-total-bytes", "total-bytes-disk" from NAMESPACE.STATISTICS save;
r = group by CLUSTER, NAMESPACE do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different namespace device size configuration.", "OPERATIONS", WARNING,
				"Listed namespace[s] have difference in configured disk size. Please run 'show statistics namespace like bytes' to check total device size. Probable cause - config file misconfiguration.",
				"Namespace device size configuration difference check.");

hwm = select "high-water-disk-pct" from NAMESPACE.CONFIG save;
hwm = group by CLUSTER, NAMESPACE hwm;
r = do hwm == 50;
ASSERT(r, True, "Non-default namespace device high water mark configuration.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-default high water mark configuration. Please run 'show config namespace like high-water-disk-pct' to check value. Probable cause - config file misconfiguration.",
				"Non-default namespace device high water mark check.");

lwm = select like(".*defrag-lwm-pct") from NAMESPACE.CONFIG save;
lwm = group by CLUSTER, NAMESPACE lwm;
r = do lwm == 50;
ASSERT(r, True, "Non-default namespace device low water mark configuration.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-default low water mark configuration. Probable cause - config file misconfiguration.",
				"Non-default namespace device low water mark check.");

hwm = select "high-water-disk-pct" as "defrag-lwm-pct" from NAMESPACE.CONFIG save;
lwm = select like(".*defrag-lwm-pct") as "defrag-lwm-pct" from NAMESPACE.CONFIG save;
r = do lwm < hwm on common;
r = group by CLUSTER, NAMESPACE r;
ASSERT(r, False, "Defrag low water mark misconfigured.", "OPERATIONS", WARNING,
				"Listed namespace[s] have defrag-lwm-pct lower than high-water-disk-pct. This might create situation like no block to write, no eviction and no defragmentation. Please run 'show config namespace like high-water-disk-pct defrag-lwm-pct' to check configured values. Probable cause - namespace watermark misconfiguration.",
				"Defrag low water mark misconfiguration check.");

commit_to_device = select "storage-engine.commit-to-device" from NAMESPACE.CONFIG;
commit_to_device = group by CLUSTER, NAMESPACE commit_to_device;
ASSERT(commit_to_device, False, "Namespace has COMMIT-TO-DEVICE", "OPERATIONS" , INFO,
				"Listed namespace(s) have commit-to-device=true. Please run 'show config namespace like commit-to-device' for details.",
				"Namespace COMMIT-TO-DEVICE check.");

number_of_sets = select "set" from SET.STATISTICS;
number_of_sets = GROUP BY CLUSTER, NAMESPACE, NODE do COUNT_ALL(number_of_sets);
p = GROUP BY CLUSTER, NAMESPACE do MAX(number_of_sets) save as "sets_count";
warning_check = do p >= 1000;
ASSERT(warning_check, False, "High set count per namespace", "LIMITS", WARNING,
        "Listed namespace(s) have high number of set count (>=1000). Please run in AQL 'show sets' for details",
        "Critical Namespace Set Count Check (>=1000)");
correct_range_check = do p < 750;
r = do warning_check || correct_range_check;
ASSERT(r, True, "Number of Sets equal to or above 750", "LIMITS", INFO,
        "Listed namespace(s) have high number of set count (>=750). Please run in AQL 'show sets' for details",
        "Basic Set Count Check (750 <= p < 1000)");

stop_writes = select "stop_writes" from NAMESPACE.STATISTICS;
stop_writes = group by CLUSTER, NAMESPACE stop_writes;
ASSERT(stop_writes, False, "Namespace has hit stop-writes (stop_writes = true)", "OPERATIONS" , CRITICAL,
				"Listed namespace(s) have hit stop-write. Please run 'show statistics namespace like stop_writes' for details.",
				"Namespace stop-writes flag check.");

clock_skew_stop_writes = select "clock_skew_stop_writes" from NAMESPACE.STATISTICS;
clock_skew_stop_writes = group by CLUSTER, NAMESPACE clock_skew_stop_writes;
ASSERT(clock_skew_stop_writes, False, "Namespace has hit clock-skew-stop-writes (clock_skew_stop_writes = true)", "OPERATIONS" , CRITICAL,
				"Listed namespace(s) have hit clock-skew-stop-writes. Please run 'show statistics namespace like clock_skew_stop_writes' for details.",
				"Namespace clock-skew-stop-writes flag check.");

SET CONSTRAINT VERSION < 4.3;

device = select "file", "storage-engine.file" as "file", "device", "storage-engine.device" as "device" from NAMESPACE.CONFIG save;
device = do SPLIT(device);
r = do UNIQUE(device);
ASSERT(r, True, "Duplicate device/file configured.", "OPERATIONS", CRITICAL,
				"Listed namespace[s] have duplication in device/file configuration. This might corrupt data. Please configure device/file names carefully.",
				"Duplicate device/file check.");

SET CONSTRAINT VERSION ALL;

/*
Following query collects used device space and total device space and computes available free space on each node per namespace per cluster (group by CLUSTER, NAMESPACE, NODE).
It collects cluster-size and uses it to find out expected data distribution for each node in case that node is down. It checks max of this computed value per namespace
with available space per node per namespace.
*/

t = select "device_total_bytes" as "disk_space", "device-total-bytes" as "disk_space", "total-bytes-disk" as "disk_space" from NAMESPACE.STATISTICS;
u = select "used-bytes-disk" as "disk_space", "device_used_bytes" as "disk_space" from NAMESPACE.STATISTICS;
/* Available extra space */
e = do t - u;
e = group by CLUSTER, NAMESPACE, NODE do SUM(e) save as "available device space";
s = select "cluster_size" as "size" from SERVICE;
n = do MAX(s);
n = do n - 1;
/* Extra space need if 1 node goes down */
e1 = do u / n;
e1 = group by CLUSTER, NAMESPACE do MAX(e1) save as "distribution share of used device space per node";
r = do e > e1;
ASSERT(r, True, "Namespace under configured (disk) for single node failure.", "OPERATIONS", WARNING,
				"Listed namespace[s] does not have enough disk space configured to deal with increase in data per node in case of 1 node failure. Please run 'show statistics namespace like bytes' to check device space. It is non-issue if single replica limit is set to larger values, i.e if number of replica copies are reduced in case of node loss.",
				"Namespace single node failure disk config check.");

/*
Same as above query but for memory
*/
t = select "memory-size" as "mem" from NAMESPACE.CONFIG;
u = select "used-bytes-memory" as "mem", "memory_used_bytes" as "mem" from NAMESPACE.STATISTICS;
/* Available extra space */
e = do t - u;
e = group by CLUSTER, NAMESPACE, NODE do SUM(e) save as "available memory space";
s = select "cluster_size" as "size" from SERVICE;
n = do MAX(s);
n = do n - 1;
/* Extra space need if 1 node goes down */
e1 = do u / n;
e1 = group by CLUSTER, NAMESPACE do MAX(e1) save as "distribution share of used memory space per node";
r = do e > e1;
ASSERT(r, True, "Namespace under configured (memory) for single node failure.", "OPERATIONS", WARNING,
				"Listed namespace[s] does not have enough memory space configured to deal with increase in data per node in case of 1 node failure. Please run 'show statistics namespace like bytes' to check memory space. It is non-issue if single replica limit is set to larger values, i.e number of replica copies reduce.",
				"Namespace single node failure memory config check.");


/* Namespace Configuration */

SET CONSTRAINT VERSION < 3.13;

nsid = select "nsid" from NAMESPACE.CONFIG;
r = group by CLUSTER, NAMESPACE do NO_MATCH(nsid, ==, MAJORITY) save;
ASSERT(r, False, "Different namespace order in aerospike conf.", "OPERATIONS", CRITICAL,
				"Listed namespace[s] have different order on different nodes. Please check aerospike conf file on all nodes and change configuration to make namespace order same.",
				"Namespace order check.");

SET CONSTRAINT VERSION ALL;

repl = select "replication-factor", "repl-factor" from NAMESPACE.CONFIG;
repl = group by CLUSTER, NAMESPACE repl;
ns_count = group by CLUSTER do COUNT(repl) save as "total available namespaces for cluster";
ns_count_per_node = group by CLUSTER, NODE do COUNT(repl) save as "namespace count";
r = do ns_count_per_node == ns_count;
ASSERT(r, True, "Disparate namespaces.", "OPERATIONS", WARNING,
				"Listed node[s] do not have all namespaces configured. Please check aerospike conf file on all nodes and change namespace configuration as per requirement.",
				"Namespaces per node count check.");

r = select "replication-factor", "repl-factor" from NAMESPACE.CONFIG save;
r = group by CLUSTER, NAMESPACE r;
r = do r == 2;
ASSERT(r, True, "Non-default namespace replication-factor configuration.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-default replication-factor configuration. Please run 'show config namespace like repl' to check value. It may be non-issue in case namespace are configured for user requirement. Ignore those.",
				"Non-default namespace replication-factor check.");

s = select * from NAMESPACE.CONFIG ignore "rack-id", like(".*device"), like(".*file") save;
r = group by CLUSTER, NAMESPACE, KEY do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different namespace configurations.", "OPERATIONS", WARNING,
				"Listed namespace configuration[s] are different across multiple nodes in cluster. Please run 'show config namespace diff' to get actual difference. It may be non-issue in case namespace are configured with different device or file name etc. Ignore those.",
				"Namespace configurations difference check.");

/*  Errors */
s = select like(".*_err.*") from SERVICE.STATISTICS save;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do MAX(u);
s = do s / u;
r = group by KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster service errors count.", "ANOMALY", INFO,
				"Listed service errors[s] show skew in error count patterns (for listed node[s]). Please run 'show statistics service like err' for details.",
				"Service errors count anomaly check.");


e = select "hwm_breached", "hwm-breached" from NAMESPACE.STATISTICS;
e = group by CLUSTER, NAMESPACE e;
r = do e == False;
ASSERT(r, True, "Namespace HWM breached.", "OPERATIONS", WARNING,
				"Listed namespace[s] show HWM breached for memory or Disks.",
				"Namespace HWM breach check.");

/*
Following query collects master_objects, prole_objects and replication_factor, and computes proles for one replication (prole_objects/(replication_factor-1)).
After that it find out master and prole distribution is in correct range with each other or not,
this last result will 'AND' with replication_enabled and migration_in_progress bools to avoid wrong assert failure
*/

m = select "master_objects" as "cnt", "master-objects" as "cnt" from NAMESPACE.STATISTICS;
p = select "prole_objects" as "cnt", "prole-objects" as "cnt" from NAMESPACE.STATISTICS;
r = select "effective_replication_factor", "repl-factor" from NAMESPACE.STATISTICS;
mg = select "migrate_rx_partitions_active", "migrate_progress_recv", "migrate-rx-partitions-active"  from NAMESPACE.STATISTICS;
mt = group by NAMESPACE do SUM(m) save as "master_objects";
pt = group by NAMESPACE do SUM(p);
r = group by NAMESPACE do MAX(r);
mg = group by NAMESPACE do MAX(mg);
no_migration = do mg == 0;

replication_enabled = do r > 1;
r = do r - 1;
pt = do pt / r save as "unique prole_objects";
discounted_pt = do 95 %% pt save as "95% of unique prole_objects";
d = do discounted_pt > mt;
d = do d && replication_enabled;
d = do d && no_migration;
ASSERT(d, False, "Skewed namespace data distribution, prole objects exceed master objects by > 5%.", "DATA", INFO,
				"Listed namespace[s] show abnormal object distribution. It may not be an issue if migrations are in progress. Please run 'show statistics namespace like object' for actual counts.",
				"Namespace data distribution check (prole objects exceed master objects by > 5%).");
discounted_mt = do 95 %% mt save as "95% of master_objects";
d = group by NAMESPACE do discounted_mt > pt;
d = do d && replication_enabled;
d = do d && no_migration;
ASSERT(d, False, "Skewed namespace data distribution, master objects exceed prole objects by > 5%.", "DATA", INFO,
				"Listed namespace[s] show abnormal object distribution. It may not be an issue if migrations are in progress. Please run 'show statistics namespace like object' for actual counts.",
				"Namespace data distribution check (master objects exceed prole objects by > 5%).");


s = select "set-delete", "deleting" as "set-delete" from SET save;
r = group by CLUSTER, NAMESPACE, SET do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different set delete status.", "OPERATIONS", INFO,
				"Listed set[s] have different set delete status across multiple nodes in cluster. This is non-issue if set-delete is being performed. Nodes reset the status asynchronously. Please check if nsup is still delete data for the set.",
				"Set delete status check.");


s = select like ("disable-eviction") from SET save;
r = group by CLUSTER, NAMESPACE, SET do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different set eviction configuration.", "OPERATIONS", WARNING,
				"Listed set[s] have different eviction setting across multiple nodes in cluster. Please run 'show statistics set like disable-eviction' to check values. Possible operational misconfiguration.",
				"Set eviction configuration difference check.");




s = select "n_objects", "objects" from SET save;
r = group by CLUSTER, NAMESPACE, SET do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster set object count.", "ANOMALY", WARNING,
				"Listed set[s] have skewed object distribution. Please run 'show statistics set like object' to check counts. It may be non-issue if cluster is undergoing migrations.",
				"Set object count anomaly check.");

/* XDR < 5 */
SET CONSTRAINT VERSION < 5.0;

s = select like ("set-enable-xdr") from SET save;
r = group by CLUSTER, NAMESPACE, SET do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different set xdr configuration.", "OPERATIONS", WARNING,
				"Listed set[s] have different XDR replication setting across multiple nodes in cluster. Please run 'show statistics set like set-enable-xdr' to check values. Possible operational misconfiguration.",
				"Set xdr configuration difference check.");

s = select * from XDR.CONFIG save;
r = GROUP by CLUSTER, KEY do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different XDR configurations.", "OPERATIONS", WARNING,
				"Listed XDR configuration[s] are different across multiple nodes in cluster. Please run 'show config xdr diff' to get difference. Possible operational misconfiguration.",
				"XDR configurations difference check.");


s = select * from XDR.STATISTICS save;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do MAX(u);
s = do s / u;
r = group by CLUSTER, KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster XDR statistics.", "ANOMALY", WARNING,
				"Listed XDR statistic[s] show skew for the listed node[s]. It may or may not be an issue depending on the statistic type.",
				"XDR statistics anomaly check.");

s = select * from DC.STATISTICS ignore "dc_size", "dc_state" save;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do MAX(u);
s = do s / u on common;
r = group by CLUSTER, DC, KEY do SD_ANOMALY(s, ==, 3);
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
cluster_xdr_enabled = group by CLUSTER do OR(xdr_enabled);

s = select "xdr-dc-state", "dc_state"  from DC.STATISTICS save;
r = group by CLUSTER, DC do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different remote DC states.", "OPERATIONS", WARNING,
				"Listed DC[s] have a different remote DC visibility. Please run 'show statistics dc like state' to see DC state. Possible network issue between data centers.",
				"Remote DC state check.",
				xdr_enabled);

s = select "dc_size"  from DC.STATISTICS save;
r = group by CLUSTER, DC do NO_MATCH(s, ==, MAJORITY) save;
ASSERT(r, False, "Different remote DC sizes.", "OPERATIONS", WARNING,
				"Listed DC[s] have a different remote DC size. Please run 'show statistics dc like size' to see DC size. Possible network issue between data centers.",
				"Remote DC size check.");

s = select "free-dlog-pct", "dlog_free_pct", "free_dlog_pct" from XDR save;
r = do s < 95;
ASSERT(r, False, "Low XDR free digest log space.", "OPERATIONS", INFO,
				"Listed node[s] have lower than ideal (95%) free digest log space. Please run 'show statistics xdr like free' to see digest log space. Probable cause - low XDR throughput or a failed node processing in progress.",
				"XDR free digest log space check.",
				xdr_enabled);
r = group by CLUSTER do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster XDR free digest log space.", "ANOMALY", WARNING,
				"Listed node[s] have different digest log free size pattern. Please run 'show statistics xdr like free' to see digest log space. May not be an issue if the nodes are newly added or have been restarted with noresume or if remote Datacenter connectivity behavior differs for nodes.",
				"XDR free digest log space anomaly check.",
				cluster_xdr_enabled);


/* Needs normalization but not sure on what ?? */
s = select "timediff_lastship_cur_secs", "xdr_timelag" from XDR.STATISTICS save;
r = do s > 10;
ASSERT(r, False, "High XDR shipping lag (> 10s).", "PERFORMANCE", WARNING,
				"Listed node[s] have higher than healthy ( > 10 sec) ship lag to remote data center. Please run 'show statistics xdr like time' to see shipping lag. Probable cause - connectivity issue to remote datacenter or spike in write throughput on the local cluster.",
				"XDR shipping lag check.",
				xdr_enabled);
r = group by CLUSTER do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Cluster XDR shipping lag skewed.", "ANOMALY", WARNING,
				"Listed node[s] have different ship lag patterns. Please run 'show statistics xdr like time' to see shipping lag. May not be an issue if the nodes are newly added or have been restarted with noresume or if remote Datacenter connectivity behavior differs for nodes.",
				"XDR shipping lag anomaly check.",
				cluster_xdr_enabled);


s = select "xdr-dc-timelag", "dc_timelag" from DC.STATISTICS save;
r = group by CLUSTER, DC do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed cluster remote DC Lag.", "ANOMALY", WARNING,
				"Listed node[s] have different latency to remote data center. Please run 'show statistics dc like timelag' to see timelag. Possible Data center connectivity issue.",
				"Remote DC lag anomaly check.",
				cluster_xdr_enabled);


/* XDR xdr_read_latency_avg check */
s = select "xdr_read_latency_avg", "local_recs_fetch_avg_latency" from XDR.STATISTICS save;
r = do s > 2;
ASSERT(r, False, "High XDR average read latency (>2 sec).", "PERFORMANCE", WARNING,
				"Listed node[s] have higher than normal (> 2sec) local read latencies. Please run 'show statistics xdr like latency' to see XDR read latency. Probable cause - system overload causing transaction queue to back up.",
				"XDR average read latency check.",
				xdr_enabled);


s = select "dc_open_conn" as "conn" from DC.STATISTICS save;
ds = select "dc_size" as "conn" from DC.STATISTICS save;
ds = do ds * 64 save as "max expected dc connections";
r = do s > ds;
ASSERT(r, False, "High remote DC connections.", "LIMITS", WARNING,
				"Listed node[s] have higher than normal remote datacenter connections. Generally accepted number is (64*No of nodes in remote DC) per node. Please run 'show statistics dc like dc_open_conn dc_size' to see DC connection statistics. Ignore if XDR is not pipelined.",
				"Remote DC connections check.",
				xdr_enabled);


s = select "xdr_uninitialized_destination_error", "noship_recs_uninitialized_destination" from XDR.STATISTICS save;
r = do s > 0;
ASSERT(r, False, "Uninitialized destination cluster.", "OPERATIONS", WARNING,
				"Listed node[s] have a non zero value for this uninitialized DC. Please check the configuration.",
				"Uninitialized destination cluster check.",
				xdr_enabled);


s = select "xdr_unknown_namespace_error", "noship_recs_unknown_namespace" from XDR.STATISTICS save;
r = do s > 0;
ASSERT(r, False, "Missing namespace in remote data center.", "OPERATIONS", WARNING,
				"Certain namespace not found in remote DC. Please check the configuration to ascertain if remote DC has all the namespace being shipped.",
				"Remote DC namespace check.",
				xdr_enabled);

/* XDR failednode_sessions_pending check */
s = select "failednode_sessions_pending", "xdr_active_failed_node_sessions" from XDR.STATISTICS save;
r = do s > 0;
ASSERT(r, False, "Active failed node sessions.", "OPERATIONS", INFO,
                "Listed node[s] have failed node sessions pending. Please check if there are any failed nodes on the source cluster.",
                "Active failed node sessions check.",
                xdr_enabled);

/* XDR linkdown_sessions_pending check */
s = select "linkdown_sessions_pending", "xdr_active_link_down_sessions" from XDR.STATISTICS save;
r = do s > 0;
ASSERT(r, False, "Active linkdown sessions.", "OPERATIONS", INFO,
                "Listed node[s] have link down sessions pending. Please check the connectivity of remote datacenter.",
                "Active linkdown sessions check.",
                xdr_enabled);

/* XDR xdr_ship_outstanding_objects check */
s = select "xdr_ship_outstanding_objects", "stat_recs_outstanding" from XDR.STATISTICS save;
r = do s > 10000;
ASSERT(r, False, "Too many outstanding objects (>10000) to ship !!.", "OPERATIONS", WARNING,
                "Listed node[s] have too many records outstanding. Please check relogging and error statistics.",
                "XDR outstanding objects check.",
                xdr_enabled);

/* XDR xdr_ship_inflight_objects check */
s = select "xdr_ship_inflight_objects", "stat_recs_inflight" from XDR.STATISTICS save;
r = do s > 5000;
ASSERT(r, False, "Too many inflight objects (>5000).", "PERFORMANCE", WARNING,
                "Listed node[s] have too many objects inflight. This might lead to XDR throttling itself, consider tuning this parameter to a lower value.",
                "Crossing xdr-max-ship-throughput check.",
                xdr_enabled);

/* XDR xdr_ship_latency_avg check */
s = select "xdr_ship_latency_avg", "latency_avg_ship" from XDR.STATISTICS save;
// Following value is not fixed yet
r = do s > 5000;
ASSERT(r, False, "Record shipping takes too long (>5 sec).", "PERFORMANCE", WARNING,
				"Listed node[s] have more than normal (>5sec) average shipping latency to remote data center. Possible high connectivity latency or performance issue at the remote data center.",
				"XDR average ship latency check.",
				xdr_enabled);

/* XDR dlog_overwritten_error check */
s = select "dlog_overwritten_error" from XDR.STATISTICS save;
r = do s > 0;
ASSERT(r, False, "XDR digest log entries got overwritten.", "PERFORMANCE", WARNING,
				"Listed node[s] have a non zero value for XDR digest log entries that got overwritten.",
				"XDR dlog overwritten error check.",
				xdr_enabled);

/* XDR xdr_queue_overflow_error check */
s = select "xdr_queue_overflow_error" from XDR.STATISTICS save;
r = do s > 0;
ASSERT(r, False, "XDR queue overflows.", "PERFORMANCE", WARNING,
				"Listed node[s] have a non zero value for XDR queue overflow errors. Typically happens when there are no physical space available on the storage holding the digest log, or if the writes are happening at such a rate that elements are not written fast enough to the digest log. The number of entries this queue can hold is 1 million.",
				"XDR queue overflow error check.",
				xdr_enabled);

/* XDR > 5 */

SET CONSTRAINT VERSION ALL;
/* CLUSTER STATE */

r = select "cluster_integrity" from SERVICE.STATISTICS save;
r = do r == True;
ASSERT(r, True, "Cluster integrity fault.", "OPERATIONS", CRITICAL,
				"Listed node[s] have cluster integrity fault. This indicates cluster is not completely wellformed. Please check server logs for more information. Probable cause - issue with network.",
				"Cluster integrity fault check.");

r = select "cluster_key" from SERVICE.STATISTICS;
r = do NO_MATCH(r, ==, MAJORITY) save;
ASSERT(r, False, "Different Cluster Key.", "OPERATIONS", CRITICAL,
				"Listed cluster[s] have different cluster keys for nodes. This indicates cluster is not completely wellformed. Please check server logs for more information. Probable cause - issue with network.",
				"Cluster Key difference check.");

u = select "uptime" from SERVICE.STATISTICS;
total_nodes = group by CLUSTER do COUNT(u) save as "total nodes";
r = select "cluster_size" from SERVICE.STATISTICS save;
r = do r == total_nodes;
ASSERT(r, True, "Unstable Cluster.", "OPERATIONS", CRITICAL,
				"Listed node[s] have cluster size not matching total number of available nodes. This indicates cluster is not completely wellformed. Please check server logs for more information. Probable cause - issue with network.",
				"Cluster stability check.");

paxos_replica_limit = select "paxos-single-replica-limit" from SERVICE.CONFIG save as "paxos-single-replica-limit";
paxos_replica_limit = group by CLUSTER paxos_replica_limit;

cluster_size = select "cluster_size" from SERVICE.STATISTICS;
cluster_size = group by CLUSTER do MAX(cluster_size);

replication_factor_check = select "replication-factor", "repl-factor" from NAMESPACE.CONFIG;
replication_factor_check = group by CLUSTER, NODE do MAX(replication_factor_check);
replication_factor_check = do replication_factor_check >=2;

r = do cluster_size <= paxos_replica_limit;
r = do r && replication_factor_check;

ASSERT(r, False, "Critical Cluster State - Only one copy of data exists", "OPERATIONS", CRITICAL,
				"Listed node[s] have cluster size less than or equal to paxos-single-replica-limit. Only one copy of the data (no replicas) will be kept in the cluster",
				"Paxos single replica limit check");


/* UDF */

u = select * from UDF.METADATA;
r = group by FILENAME, KEY do NO_MATCH(u, ==, MAJORITY) save;
ASSERT(r, False, "UDF not in sync (file not matching).", "OPERATIONS", CRITICAL,
				"Listed UDF definitions do not match across the nodes. This may lead to incorrect UDF behavior. Run command 'asinfo -v udf-list' to see list of UDF. Re-register the latest version of the not in sync UDF[s].",
				"UDF sync (file not matching) check.");
total_nodes = group by CLUSTER do COUNT(u) save as "expected node count";
c = group by CLUSTER, FILENAME do COUNT(u) save as "node count";
r = do c == total_nodes;
ASSERT(r, True, "UDF not in sync (not available on all node).", "OPERATIONS", CRITICAL,
				"Listed UDF[s] are not available on all the nodes. This may lead to incorrect UDF behavior. Run command 'asinfo -v udf-list' to see list of UDF. Re-register missing UDF in cluster.",
				"UDF sync (availability on all node) check.");

/* SINDEX */

s = select "sync_state" as "val", "state" as "val" from SINDEX.STATISTICS save;
s = group by CLUSTER, NAMESPACE, SET, SINDEX s;
r1 = do s == "synced";
r2 = do s == "RW";
r = do r1 || r2;
ASSERT(r, True, "SINDEX not in sync with primary.", "OPERATIONS", CRITICAL,
				"Listed sindex[es] are not in sync with primary. This can lead to wrong query results. Consider dropping and recreating secondary index[es].",
				"SINDEX sync state check.");
u = select "uptime" from SERVICE.STATISTICS;
total_nodes = group by CLUSTER do COUNT(u) save as "cluster node count";
c = group by CLUSTER, NAMESPACE, SET, SINDEX do COUNT(s) save as "nodes with SINDEX";
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


/* ENDPOINTS */

service = select "endpoints" as "e" from METADATA.ENDPOINTS;
services = select "services" as "e" from METADATA.SERVICES;
all_endpoints = do service + services;

r = group by CLUSTER do EQUAL(all_endpoints);
ASSERT(r, True, "Services list discrepancy.", "OPERATIONS", WARNING,
				"Listed Cluster[s] shows different services list for different nodes. Please run 'asinfo -v services' to get all services.",
				"Services list discrepancy test.");


/* RACKS */

rackid = select "rack-id" from NAMESPACE.CONFIG;
r = group by CLUSTER, NAMESPACE do VALUE_UNIFORM(rackid);
ASSERT(r, True, "Wrong rack-id distribution.", "OPERATIONS", WARNING,
				"Listed namespace[s] does not have uniform rack distribution. It might cause extra traffic on c with less nodes assigned. Please set rack-id properly.",
				"Roster misconfiguration test.");

node_rackid = select "rack-id" from NAMESPACE.CONFIG;
node_rackid = group by CLUSTER, NODE, NAMESPACE do FIRST(node_rackid);

node_id = select "node-id" from METADATA;
node_id = group by CLUSTER, NODE do FIRST(node_id);

rack_rackid = select "rack-id" from RACKS.CONFIG;
rack_rackid = group by CLUSTER, NODE, NAMESPACE, RACKS do FIRST(rack_rackid);

rack_nodes = select "nodes" from RACKS.CONFIG;
rack_nodes = group by CLUSTER, NODE, NAMESPACE, RACKS do FIRST(rack_nodes);

r1 = do node_rackid == rack_rackid;
r2 = do node_id IN rack_nodes;
r = do r1 && r2;
r = group by CLUSTER, NODE, NAMESPACE do OR(r);

ASSERT(r, True, "Node is not part of configured rack.", "OPERATIONS", WARNING,
				"Listed node[s] is not part of configured rack. Probable cause - missed to re-cluster after changing rack-id.",
				"Node rack membership check");

rack_nodes = select "nodes" from RACKS.CONFIG;
r = group by CLUSTER, NAMESPACE, RACKS do EQUAL(rack_nodes);
ASSERT(r, True, "Rack configuration mismatch.", "OPERATIONS", WARNING,
				"Listed namespace[s] having different rack configurations across multiple nodes in cluster. Please check rack configurations.",
				"Rack configuration check");

/*
	Different queries for different versions. All version constraint sections should be at the bottom of file, it will avoid extra version reset at the end.
*/

SET CONSTRAINT VERSION >= 3.9;
// Uptime

u = select "uptime" from SERVICE.STATISTICS;
u = GROUP BY CLUSTER, NODE do MAX(u);


// Read statistics

nf = select "client_read_not_found" as "cnt" from NAMESPACE.STATISTICS;
s = select "client_read_success" as "cnt" from NAMESPACE.STATISTICS;
t = select "client_read_timeout" as "cnt" from NAMESPACE.STATISTICS;
e = select "client_read_error" as "cnt" from NAMESPACE.STATISTICS;
total_reads = do s + nf;
total_reads = do total_reads + t;
total_reads = do total_reads + e save as "total client reads";
total_reads_per_sec = do total_reads/u;
total_reads = group by CLUSTER, NAMESPACE, NODE do MAX(total_reads);
total_reads_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_reads_per_sec);

e = select "client_read_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_reads_per_sec;
p = do p * 100 save as "client_read_error % of total reads";
r = do p <= 5;
ASSERT(r, True, "High client read errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal read errors (> 5% client reads). Please run 'show statistics namespace like client_read' to see values.",
				"High read error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero client read errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero read errors. Please run 'show statistics namespace like client_read' to see values.",
				"Non-zero read error check");

t = select "client_read_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_reads;
r = do r * 100 save as "client_read_timeout % of total reads";
r = do r <= 5;
ASSERT(r, True, "High client read timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal read timeouts (> 5% client reads). Please run 'show statistics namespace like client_read' to see values.",
				"High read timeouts check");

c = select "client_read_not_found" from NAMESPACE.STATISTICS save;
c = group by CLUSTER, NAMESPACE c;

r = do c / total_reads;
r = do r * 100 save as "client_read_not_found % of total reads";
r = do r <= 20;
ASSERT(r, True, "High read not found errors", "OPERATIONS", INFO,
				"Listed namespace[s] show higher than normal read not found errors (> 20% client reads). Please run 'show statistics namespace like client_read' to see values.",
				"High read not found error check");


// Delete statistics

nf = select "client_delete_not_found" as "cnt" from NAMESPACE.STATISTICS;
s = select "client_delete_success" as "cnt" from NAMESPACE.STATISTICS;
t = select "client_delete_timeout" as "cnt" from NAMESPACE.STATISTICS;
e = select "client_delete_error" as "cnt" from NAMESPACE.STATISTICS;
total_deletes = do s + nf;
total_deletes = do total_deletes + t;
total_deletes = do total_deletes + e save as "total client deletes";
total_deletes_per_sec = do total_deletes/u;
total_deletes = group by CLUSTER, NAMESPACE, NODE do MAX(total_deletes);
total_deletes_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_deletes_per_sec);

e = select "client_delete_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_deletes_per_sec;
p = do p * 100 save as "client_delete_error % of total deletes";
r = do p <= 5;
ASSERT(r, True, "High client delete errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal delete errors (> 5% client deletes). Please run 'show statistics namespace like client_delete' to see values.",
				"High delete error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero client delete errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero delete errors. Please run 'show statistics namespace like client_delete' to see values.",
				"Non-zero delete error check");

t = select "client_delete_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_deletes;
r = do r * 100 save as "client_delete_timeout % of total deletes";
r = do r <= 5;
ASSERT(r, True, "High client delete timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal delete timeouts (> 5% client deletes). Please run 'show statistics namespace like client_delete' to see values.",
				"High delete timeouts check");

c = select "client_delete_not_found" from NAMESPACE.STATISTICS save;
c = group by CLUSTER, NAMESPACE c;
r = do c / total_deletes;
r = do r * 100 save as "client_delete_not_found % of total deletes";
r = do r <= 20;
ASSERT(r, True, "High delete not found errors", "OPERATIONS", INFO,
				"Listed namespace[s] show higher than normal delete not found errors (> 20% client deletes). Please run 'show statistics namespace like client_delete' to see values.",
				"High delete not found error check");


// Write statistics

s = select "client_write_success" as "cnt" from NAMESPACE.STATISTICS;
t = select "client_write_timeout" as "cnt" from NAMESPACE.STATISTICS;
e = select "client_write_error" as "cnt" from NAMESPACE.STATISTICS;
total_writes = do s + t;
total_writes = do total_writes + e save as "total client writes";
total_writes_per_sec = do total_writes/u;
total_writes = group by CLUSTER, NAMESPACE, NODE do MAX(total_writes);
total_writes_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_writes_per_sec);

e = select "client_write_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_writes_per_sec;
p = do p * 100 save as "client_write_error % of total writes";
r = do p <= 5;
ASSERT(r, True, "High client write errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal write errors (> 5% client writes). Please run 'show statistics namespace like client_write' to see values.",
				"High write error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero client write errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero write errors. Please run 'show statistics namespace like client_write' to see values.",
				"Non-zero write error check");

t = select "client_write_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_writes;
r = do r * 100 save as "client_write_timeout % of total writes";
r = do r <= 5;
ASSERT(r, True, "High client write timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal write timeouts (> 5% client writes). Please run 'show statistics namespace like client_write' to see values.",
				"High write timeouts check");


// Client Proxy transaction statistics

s = select "client_proxy_complete" as "cnt" from NAMESPACE.STATISTICS;
t = select "client_proxy_timeout" as "cnt" from NAMESPACE.STATISTICS;
e = select "client_proxy_error" as "cnt" from NAMESPACE.STATISTICS;
total_client_proxy = do s + t;
total_client_proxy = do total_client_proxy + e save as "total client proxy transactions";
total_client_proxy_per_sec = do total_client_proxy/u;
total_client_proxy = group by CLUSTER, NAMESPACE, NODE do MAX(total_client_proxy);
total_client_proxy_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_client_proxy_per_sec);

e = select "client_proxy_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_client_proxy_per_sec;
p = do p * 100 save as "client_proxy_error % of total proxy transactions";
r = do p <= 5;
ASSERT(r, True, "High client proxy transaction errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal proxy transaction errors (> 5% client proxy transactions). Please run 'show statistics namespace like client_proxy' to see values.",
				"High proxy transaction error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero client proxy transaction errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero proxy transaction errors. Please run 'show statistics namespace like client_proxy' to see values.",
				"Non-zero proxy transaction error check");


t = select "client_proxy_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_client_proxy;
r = do r * 100 save as "client_proxy_timeout % of total proxy transactions";
r = do r <= 5;
ASSERT(r, True, "High client proxy transaction timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal proxy transaction timeouts (> 5% client proxy transactions). Please run 'show statistics namespace like client_proxy' to see values.",
				"High proxy transaction timeouts check");


// UDF Transaction statistics

s = select "client_udf_complete" as "cnt" from NAMESPACE.STATISTICS;
t = select "client_udf_timeout" as "cnt" from NAMESPACE.STATISTICS;
e = select "client_udf_error" as "cnt" from NAMESPACE.STATISTICS;
total_udf_transactions = do s + t;
total_udf_transactions = do total_udf_transactions + e save as "total udf transactions";
total_udf_transactions_per_sec = do total_udf_transactions/u;
total_udf_transactions = group by CLUSTER, NAMESPACE, NODE do MAX(total_udf_transactions);
total_udf_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_udf_transactions_per_sec);

e = select "client_udf_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_udf_transactions_per_sec;
p = do p * 100 save as "client_udf_error % of total udf transactions";
r = do p <= 5;
ASSERT(r, True, "High udf transaction errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal udf transaction errors (> 5% udf transactions). Please run 'show statistics namespace like client_udf' to see values.",
				"High udf transaction error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero udf transaction errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero udf transaction errors. Please run 'show statistics namespace like client_udf' to see values.",
				"Non-zero udf transaction error check");

t = select "client_udf_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_udf_transactions;
r = do r * 100 save as "client_udf_timeout % of total udf transactions";
r = do r <= 5;
ASSERT(r, True, "High udf transaction timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal udf transaction timeouts (> 5% udf transaction). Please run 'show statistics namespace like client_udf' to see values.",
				"High udf transaction timeouts check");


// UDF Sub-Transaction statistics

s = select "udf_sub_udf_complete" as "cnt" from NAMESPACE.STATISTICS;
t = select "udf_sub_udf_timeout" as "cnt" from NAMESPACE.STATISTICS;
e = select "udf_sub_udf_error" as "cnt" from NAMESPACE.STATISTICS;
total_udf_sub_transactions = do s + t;
total_udf_sub_transactions = do total_udf_sub_transactions + e save as "total udf sub-transactions";
total_udf_sub_transactions_per_sec = do total_udf_sub_transactions/u;
total_udf_sub_transactions = group by CLUSTER, NAMESPACE, NODE do MAX(total_udf_sub_transactions);
total_udf_sub_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_udf_sub_transactions_per_sec);

e = select "udf_sub_udf_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_udf_sub_transactions_per_sec;
p = do p * 100 save as "udf_sub_udf_error % of total udf sub-transactions";
r = do p <= 5;
ASSERT(r, True, "High udf sub-transaction errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal udf sub-transaction errors (> 5% udf sub-transactions). Please run 'show statistics namespace like udf_sub_udf' to see values.",
				"High udf sub-transaction error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero udf sub-transaction errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero udf sub-transaction errors. Please run 'show statistics namespace like udf_sub_udf' to see values.",
				"Non-zero udf sub-transaction error check");

t = select "udf_sub_udf_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_udf_sub_transactions;
r = do r * 100 save as "udf_sub_udf_timeout % of total udf sub-transactions";
r = do r <= 5;
ASSERT(r, True, "High udf sub-transaction timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal udf sub-transaction timeouts (> 5% udf sub-transaction). Please run 'show statistics namespace like udf_sub_udf' to see values.",
				"High udf sub-transaction timeouts check");


// Proxied Batch-index Sub-Transaction statistics

s = select "batch_sub_proxy_complete" as "cnt" from NAMESPACE.STATISTICS;
t = select "batch_sub_proxy_error" as "cnt" from NAMESPACE.STATISTICS;
e = select "batch_sub_proxy_timeout" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + t;
total_transactions = do total_transactions + e save as "total batch-index sub-transactions";
total_transactions_per_sec = do total_transactions/u;
total_transactions = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions);
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "batch_sub_proxy_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "batch_sub_proxy_error % of total batch-index sub-transactions";
r = do p <= 5;
ASSERT(r, True, "High batch-index sub-transaction errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal batch-index sub-transaction errors (> 5% batch-index sub-transactions). Please run 'show statistics namespace like batch_sub_proxy' to see values.",
				"High batch-index sub-transaction error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero batch-index sub-transaction errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero batch-index sub-transaction errors. Please run 'show statistics namespace like batch_sub_proxy' to see values.",
				"Non-zero batch-index sub-transaction error check");

t = select "batch_sub_proxy_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_transactions;
r = do r * 100 save as "batch_sub_proxy_timeout % of total batch-index sub-transactions";
r = do r <= 5;
ASSERT(r, True, "High batch-index sub-transaction timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal batch-index sub-transaction timeouts (> 5% batch-index sub-transaction). Please run 'show statistics namespace like batch_sub_proxy' to see values.",
				"High batch-index sub-transaction timeouts check");


// Batch-index read Sub-Transaction statistics

nf = select "batch_sub_read_not_found" as "cnt" from NAMESPACE.STATISTICS;
s = select "batch_sub_read_success" as "cnt" from NAMESPACE.STATISTICS;
t = select "batch_sub_read_timeout" as "cnt" from NAMESPACE.STATISTICS;
e = select "batch_sub_read_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + nf;
total_transactions = do total_transactions + t;
total_transactions = do total_transactions + e save as "total batch-index read sub-transactions";
total_transactions_per_sec = do total_transactions/u;
total_transactions = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions);
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "batch_sub_read_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "batch_sub_read_error % of total reads";
r = do p <= 5;
ASSERT(r, True, "High batch-index read sub-transaction errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal batch-index read sub-transaction errors (> 5% batch-index read sub-transactions). Please run 'show statistics namespace like batch_sub_read' to see values.",
				"High batch-index read sub-transaction error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero batch-index read sub-transaction errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero batch-index read sub-transaction errors. Please run 'show statistics namespace like batch_sub_read' to see values.",
				"Non-zero batch-index read sub-transaction error check");

t = select "batch_sub_read_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_transactions;
r = do r * 100 save as "batch_sub_read_timeout % of total batch-index read sub-transactions";
r = do r <= 5;
ASSERT(r, True, "High batch-index read sub-transaction timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal batch-index read sub-transaction timeouts (> 5% batch-index read sub-transactions). Please run 'show statistics namespace like batch_sub_read' to see values.",
				"High batch-index read sub-transaction timeouts check");

c = select "batch_sub_read_not_found" from NAMESPACE.STATISTICS save;
c = group by CLUSTER, NAMESPACE c;
r = do c / total_transactions;
r = do r * 100 save as "batch_sub_read_not_found % of total batch-index read sub-transactions";
r = do r <= 20;
ASSERT(r, True, "High batch-index read sub-transaction not found errors", "OPERATIONS", INFO,
				"Listed namespace[s] show higher than normal batch-index read sub-transaction not found errors (> 20% batch-index read sub-transactions). Please run 'show statistics namespace like batch_sub_read' to see values.",
				"High batch-index read sub-transaction not found error check");


// Client UDF Transaction statistics

rs = select "client_lang_read_success" as "cnt" from NAMESPACE.STATISTICS;
ds = select "client_lang_delete_success" as "cnt" from NAMESPACE.STATISTICS;
ws = select "client_lang_write_success" as "cnt" from NAMESPACE.STATISTICS;
e = select "client_lang_error" as "cnt" from NAMESPACE.STATISTICS;
total_client_udf_transactions = do rs + ds;
total_client_udf_transactions = do total_client_udf_transactions + ws;
total_client_udf_transactions = do total_client_udf_transactions + e save as "total client_lang";
total_client_udf_transactions_per_sec = do total_client_udf_transactions/u;
total_client_udf_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_client_udf_transactions_per_sec);

e = select "client_lang_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_client_udf_transactions_per_sec;
p = do p * 100 save as "client_lang_error % of total client_lang";
r = do p <= 5;
ASSERT(r, True, "High client initiated udf transactions errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal client initiated udf transactions errors (> 5% client initiated udf transactions). Please run 'show statistics namespace like client_lang' to see values.",
				"High client initiated udf transactions error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero client initiated udf transaction errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero client initiated udf transaction errors. Please run 'show statistics namespace like client_lang' to see values.",
				"Non-zero client initiated udf transaction error check");


// UDF Sub-Transaction statistics

rs = select "udf_sub_lang_read_success" as "cnt" from NAMESPACE.STATISTICS;
ds = select "udf_sub_lang_delete_success" as "cnt" from NAMESPACE.STATISTICS;
ws = select "udf_sub_lang_write_success" as "cnt" from NAMESPACE.STATISTICS;
e = select "udf_sub_lang_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do rs + ds;
total_transactions = do total_transactions + ws;
total_transactions = do total_transactions + e save as "total udf_sub_lang";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "udf_sub_lang_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "udf_sub_lang_error % of total udf_sub_lang";
r = do p <= 5;
ASSERT(r, True, "High udf sub-transaction errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal udf sub-transaction errors (> 5% udf sub-transactions). Please run 'show statistics namespace like udf_sub_lang' to see values.",
				"High udf sub-transaction error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero udf sub-transaction errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero udf sub-transaction errors. Please run 'show statistics namespace like udf_sub_lang' to see values.",
				"Non-zero udf sub-transaction error check");


SET CONSTRAINT VERSION >= 6.0;

u = select "uptime" from SERVICE.STATISTICS;
u = GROUP BY CLUSTER, NODE do MAX(u);

// Primary Index Basic Long Query, previously basic scan
s = select "pi_query_long_basic_complete" as "cnt" from NAMESPACE.STATISTICS;
e = select "pi_query_long_basic_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + e save as "total pindex long queries";
total_transactions_per_sec = do total_transactions / u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "pi_query_long_basic_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "pi_query_long_basic_error % of total pindex long queries";
r = do p <= 5;
ASSERT(r, True, "High basic primary index long query errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal basic primary index long query errors (> 5% total). Please run 'show statistics namespace like pi_query_long_basic' to see values.",
				"High basic primary index long query errors check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero basic primary index long query errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero basic primary index long query errors. Please run 'show statistics namespace like pi_query_long_basic' to see values.",
				"Non-zero basic primary index long query errors check");

// Primary Index Basic Short Query, previously basic scan
s = select "pi_query_short_basic_complete" as "cnt" from NAMESPACE.STATISTICS;
e = select "pi_query_short_basic_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + e save as "total pindex short queries";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "pi_query_short_basic_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "pi_query_short_basic_error % of total pindex short queries";
r = do p <= 5;
ASSERT(r, True, "High basic primary index short query errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal basic primary index short query errors (> 5% total). Please run 'show statistics namespace like pi_query_short_basic' to see values.",
				"High basic primary index short query errors check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero basic primary index short query errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero basic primary index short query errors. Please run 'show statistics namespace like pi_query_short_basic' to see values.",
				"Non-zero basic primary index short query errors check");
    
// Primary Index Aggregation query statistics, formally aggregation scans.
s = select "pi_query_aggr_complete" as "cnt" from NAMESPACE.STATISTICS;
e = select "pi_query_aggr_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + e save as "total pindex query aggregations";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "pi_query_aggr_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "pi_query_aggr_error % of total pindex query aggregations";
r = do p <= 5;
ASSERT(r, True, "High primary index aggregation query errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal primary index aggregation query errors (> 5% total). Please run 'show statistics namespace like pi_query_aggr' to see values.",
				"High primary index aggregation query error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero primary index aggregation query errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero primary index aggregation query errors. Please run 'show statistics namespace like pi_query_aggr' to see values.",
				"Non-zero primary index aggregation query error check");


// Primary Index Background UDF queries statistics, formally background udf scans.
s = select "pi_query_udf_bg_complete" as "cnt" from NAMESPACE.STATISTICS;
e = select "pi_query_udf_bg_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + e save as "total pindex background udf queries";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "pi_query_udf_bg_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "pi_query_udf_bg_error % of total pindex background udf queries";
r = do p <= 5;
ASSERT(r, True, "High primary index background udf queries errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal primary index background udf queries errors (> 5% total). Please run 'show statistics namespace like pi_query_udf_bg' to see values.",
				"High primary index background udf queries error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero primary index background udf queries errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero primary index background udf queries errors. Please run 'show statistics namespace like pi_query_udf_bg' to see values.",
				"Non-zero primary index background udf queries error check");

// Secondary Index Basic Long Query Statistics, formally Query Lookup statistics
c = select "si_query_long_basic_complete" as "val" from NAMESPACE.STATISTICS save;
e = select "si_query_long_basic_error" as "val" from NAMESPACE.STATISTICS save;
total_transactions = do c + e save as "total sindex long queries";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "si_query_long_basic_error % of total basic queries";
r = do p <= 5;
ASSERT(r, True, "High secondary index basic long query errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal sindex basic long query errors (> 5% total). Please run 'show statistics namespace like si_query_long_basic' to see values.",
				"High sindex basic long query error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero sindex basic long query errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero sindex basic query errors. Please run 'show statistics namespace like si_query_long_basic' to see values.",
				"Non-zero sindex basic long query error check");
    
    
// Secondary Index Basic Short Query Statistics, formally Query Lookup statistics
c = select "si_query_short_basic_complete" as "val" from NAMESPACE.STATISTICS save;
e = select "si_query_short_basic_error" as "val" from NAMESPACE.STATISTICS save;
total_transactions = do c + e save as "total sindex short basic queries";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "si_query_short_basic_error % of total sindex short basic queries";
r = do p <= 5;
ASSERT(r, True, "High sindex basic short query errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal sindex basic short query errors (> 5% total). Please run 'show statistics namespace like si_query_short_basic' to see values.",
				"High sindex basic short query error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero sindex basic short query errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero sindex basic query errors. Please run 'show statistics namespace like si_query_short_basic' to see values.",
				"Non-zero sindex basic short query error check");
    
    
// Secondary Index Aggregation Query Statistics, fromally Query Agg statistics
s = select "si_query_aggr_complete" as "val" from NAMESPACE.STATISTICS save;
e = select "si_query_aggr_error" as "val" from NAMESPACE.STATISTICS save;
total_transactions = do s + e; 
total_transaction = do total_transactions + a save as "total sindex query aggregations";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "si_query_aggr_error % of total query aggregations";
r = do p <= 5;
ASSERT(r, True, "High sindex query aggregation errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal sindex query aggregation errors (> 5% total). Please run 'show statistics namespace like si_query_aggr' to see values.",
				"High sindex query aggregation error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero sindex query aggregation errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero sindex query aggregation errors. Please run 'show statistics namespace like si_query_aggr' to see values.",
				"Non-zero sindex query aggregation error check");
    
// Secondary Index Background UDF Query Statistics
c = select "si_query_udf_bg_complete" as "val" from NAMESPACE.STATISTICS save;
e = select "si_query_udf_bg_error" as "val" from NAMESPACE.STATISTICS save;
total_transactions = do c + e save as "total sindex query background udf";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "si_query_udf_bg_error % of total basic queries";
r = do p <= 5;
ASSERT(r, True, "High sindex UDF background query errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal sindex UDF background query errors (> 5% total). Please run 'show statistics namespace like si_query_udf_bg' to see values.",
				"High sindex UDF background query error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero sindex UDF background query errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero sindex UDF background query errors. Please run 'show statistics namespace like si_query_udf_bg' to see values.",
				"Non-zero sindex UDF background query error check");
    
// Secondary Index Background Ops Query Statistics
c = select "si_query_ops_bg_complete" as "val" from NAMESPACE.STATISTICS save;
e = select "si_query_ops_bg_error" as "val" from NAMESPACE.STATISTICS save;
total_transactions = do c + e save as "total sindex background ops queries";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "si_query_ops_bg_error % of total sindex background ops queries";
r = do p <= 5;
ASSERT(r, True, "High sindex background ops query errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal sindex background ops query errors (> 5% total). Please run 'show statistics namespace like si_query_ops_bg' to see values.",
				"High sindex background ops query error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero sindex background ops query errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero sindex background ops query errors. Please run 'show statistics namespace like si_query_ops_bg' to see values.",
				"Non-zero sindex background ops query error check");

// Should be constrained to just 5.7
SET CONSTRAINT VERSION < 6.0

// Scan Background OPS statistics
s = select "scan_ops_bg_complete" as "cnt" from NAMESPACE.STATISTICS;
e = select "scan_ops_bg_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + e save as "total background ops scans";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "scan_ops_bg_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "scan_ops_bg_error % of total background ops scans";
r = do p <= 5;
ASSERT(r, True, "High background ops scans errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal background ops scan errors (> 5% scan background ops). Please run 'show statistics namespace like scan_ops_bg' to see values.",
				"High scan background ops error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero scan background ops errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero scan background ops errors. Please run 'show statistics namespace like scan_ops_bg' to see values.",
				"Non-zero scan background ops error check");

SET CONSTRAINT VERSION > 3.9

// Scan Agg statistics
s = select "scan_aggr_complete" as "cnt" from NAMESPACE.STATISTICS;
e = select "scan_aggr_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + e save as "total scan aggregations";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "scan_aggr_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "scan_aggr_error % of total scan aggregations";
r = do p <= 5;
ASSERT(r, True, "High scan aggregation errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal scan aggregation errors (> 5% scan aggregations). Please run 'show statistics namespace like scan_agg' to see values.",
				"High scan aggregation error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero scan aggregation errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero scan aggregation errors. Please run 'show statistics namespace like scan_agg' to see values.",
				"Non-zero scan aggregation error check");
    
// Scan Basic statistics
s = select "scan_basic_complete" as "cnt" from NAMESPACE.STATISTICS;
e = select "scan_basic_error", as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + e save as "total basic scans";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "scan_basic_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "scan_basic_error % of total basic scans";
r = do p <= 5;
ASSERT(r, True, "High basic scan errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal basic scan errors (> 5% basic scans). Please run 'show statistics namespace like scan_basic' to see values.",
				"High basic scan error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero basic scan errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero basic scan errors. Please run 'show statistics namespace like scan_basic' to see values.",
				"Non-zero basic scan error check");


// Scan Background UDF statistics
s = select "scan_udf_bg_complete" as "cnt" from NAMESPACE.STATISTICS;
e = select "scan_udf_bg_error" as "cnt" from NAMESPACE.STATISTICS;
total_transactions = do s + e save as "total scan background udf";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = select "scan_udf_bg_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "scan_udf_bg_error % of total scan background udf";
r = do p <= 5;
ASSERT(r, True, "High scan background udf errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal scan background udf errors (> 5% scan background udf). Please run 'show statistics namespace like scan_udf_bg' to see values.",
				"High scan background udf error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero scan background udf errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero scan background udf errors. Please run 'show statistics namespace like scan_udf_bg' to see values.",
				"Non-zero scan background udf error check");
    
// Query Agg statistics
s = select "query_aggr_complete" as "val", "query_agg_success" as "val" from NAMESPACE.STATISTICS save;
e = select "query_aggr_error" as "val", "query_agg_error" as "val" from NAMESPACE.STATISTICS save;
total_transaction = do s + e save as "total query aggregations";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "query_aggr_error % of total query aggregations";
r = do p <= 5;
ASSERT(r, True, "High query aggregation errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal query aggregation errors (> 5% query aggregations). Please run 'show statistics namespace like query_agg' to see values.",
				"High query aggregation error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero query aggregation errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero query aggregation errors. Please run 'show statistics namespace like query_agg' to see values.",
				"Non-zero query aggregation error check");

// Query Lookup statistics
c = select "query_basic_complete" as "val", "query_lookup_success" as "val" from NAMESPACE.STATISTICS save;
e = select "query_basic_error" as "val", "query_lookup_error" as "val" from NAMESPACE.STATISTICS save;
total_transactions = do c + e save as "total query lookups";
total_transactions_per_sec = do total_transactions/u;
total_transactions_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_transactions_per_sec);

e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_transactions_per_sec;
p = do p * 100 save as "query_basic_error % of total query lookups";
r = do p <= 5;
ASSERT(r, True, "High query lookup errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal query lookup errors (> 5% query lookups). Please run 'show statistics namespace like query_basic' (=> 5.7) or 'show statistics namespace like query_lookup' (< 5.7) to see values.",
				"High query lookup error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero query lookup errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero query lookup errors. Please run 'show statistics namespace like query_basic' (=> 5.7) or 'show statistics namespace like query_lookup' (< 5.7) to see values.",
				"Non-zero query lookup error check");


// Client transaction statistics

e = select "client_tsvc_error" from NAMESPACE.STATISTICS save;
e = do e/u on common save as "errors per second";
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero client transaction error.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero client transaction errors (for nodes). Please run 'show statistics namespace like client_tsvc_error' to see values. Probable cause - protocol errors or security permission mismatch.",
				"Namespace client transaction error count check");


// UDF Sub-Transactions (transaction service) statistics

e = select "udf_sub_tsvc_error" from NAMESPACE.STATISTICS save;
e = do e/u on common save as "errors per second";
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero udf sub-transaction error in the transaction service.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero udf sub-transaction errors in the transaction service (for nodes). Probable cause - protocol errors or security permission mismatch.",
				"Namespace udf sub-transaction transaction service error count check");


// Batch-index read Sub-Transaction (transaction service) statistics

e = select "batch_sub_tsvc_error" from NAMESPACE.STATISTICS save;
e = do e/u on common save as "errors per second";
e = group by CLUSTER, NAMESPACE e;
r = do e > 0;
ASSERT(r, False, "Non-zero batch-index read sub-transaction errors in the transaction service.", "OPERATIONS", INFO,
				"Listed namespace[s] have non-zero batch-index read sub-transaction errors in the transaction service across the nodes. Please run 'show statistics namespace like batch_sub_tsvc_error' to see the values.",
				"Namespace batch-index read sub-transaction transaction service error count check");


/*  Key busy error */
s = select "fail_key_busy" from NAMESPACE.STATISTICS save;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do MAX(u);
s = do s / u;
r = group by KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed Fail Key Busy count.", "ANOMALY", INFO,
				"fail_key_busy show skew count patterns (for listed node[s]). Please run 'show statistics namespace like fail_key_busy' for details.",
				"Key Busy  errors count anomaly check.");

// XDR Write statistics

SET CONSTRAINT VERSION < 4.5.1

s = select "xdr_write_success" as "cnt", "xdr_client_write_success" as "cnt" from NAMESPACE.STATISTICS;
t = select "xdr_write_timeout" as "cnt" from NAMESPACE.STATISTICS;
e = select "xdr_write_error" as "cnt" from NAMESPACE.STATISTICS;
total_xdr_writes = do s + t;
total_xdr_writes = do total_xdr_writes + e save as "total xdr writes";
total_xdr_writes_per_sec = do total_xdr_writes/u;
total_xdr_writes = group by CLUSTER, NAMESPACE, NODE do MAX(total_xdr_writes);
total_xdr_writes_per_sec = group by CLUSTER, NAMESPACE, NODE do MAX(total_xdr_writes_per_sec);

e = select "xdr_write_error" from NAMESPACE.STATISTICS save;
e = do e/u save as "errors per second (by using uptime)";
e = group by CLUSTER, NAMESPACE e;
p = do e/total_xdr_writes_per_sec;
p = do p * 100 save as "xdr_write_error % of total xdr writes";
r = do p <= 5;
ASSERT(r, True, "High xdr write errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal xdr write errors (> 5% xdr writes). Please run 'show statistics namespace like xdr_write' to see values.",
				"High xdr write error check");
warning_breached = do p > 5;
r = do p <= error_pct_threshold;
r = do r || warning_breached;
ASSERT(r, True, "Non-zero xdr write errors", "OPERATIONS", INFO,
				"Listed namespace[s] show non-zero xdr write errors. Please run 'show statistics namespace like xdr_write' to see values.",
				"Non-zero xdr write error check");

t = select "xdr_write_timeout" from NAMESPACE.STATISTICS save;
t = group by CLUSTER, NAMESPACE t;
r = do t/total_xdr_writes;
r = do r * 100 save as "xdr_write_timeout % of total xdr writes";
r = do r <= 5;
ASSERT(r, True, "High xdr write timeouts", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal xdr write timeouts (> 5% xdr writes). Please run 'show statistics namespace like xdr_write' to see values.",
				"High xdr write timeouts check");

SET CONSTRAINT VERSION < 3.14;
/* CLUSTER STATE */

hp = select "heartbeat.protocol", "heartbeat-protocol" from NETWORK.CONFIG;
heartbeat_proto_v2 = do hp == "v2";
heartbeat_proto_v2 = group by CLUSTER, NODE do OR(heartbeat_proto_v2);
cs = select "cluster_size" from SERVICE.STATISTICS save;
mcs = select "paxos-max-cluster-size" as "cluster_size" from SERVICE.CONFIG save;
cs_without_saved_value = select "cluster_size" from SERVICE.STATISTICS;
mcs_without_saved_value = select "paxos-max-cluster-size" as "cluster_size" from SERVICE.CONFIG;
r = do cs < mcs;
ASSERT(r, True, "Critical cluster size.", "OPERATIONS", CRITICAL,
				"Listed node[s] have cluster size higher than configured paxos-max-cluster-size. Please run 'show config service like paxos-max-cluster-size' to check configured max cluster size.",
				"Critical cluster size check.",
				heartbeat_proto_v2);

small_max_configured = do mcs_without_saved_value < 20;
critical_size = do cs >= mcs;
correct_size = do mcs_without_saved_value - 10;
correct_size = do cs_without_saved_value <= correct_size;
r = do small_max_configured || critical_size;
r = do r || correct_size;
ASSERT(r, True, "Cluster size is near the max configured cluster size.", "OPERATIONS", WARNING,
				"Listed node[s] have cluster size near the configured paxos-max-cluster-size. Please run 'show config service like paxos-max-cluster-size' to check configured max cluster size.",
				"Cluster size check.",
				heartbeat_proto_v2);

SET CONSTRAINT VERSION < 3.9;

/*  Key busy error */
s = select "err_rw_pending_limit" from SERVICE.STATISTICS save;
u = select "uptime" from SERVICE.STATISTICS;
u = group by CLUSTER, NODE do MAX(u);
s = do s / u;
r = group by KEY do SD_ANOMALY(s, ==, 3);
ASSERT(r, False, "Skewed Fail Key Busy count.", "ANOMALY", INFO,
				"err_rw_pending_limit show skew count patterns (for listed node[s]). Please run 'show statistics like err_rw_pending_limit' for details.",
				"Key Busy  errors count anomaly check.");


// Read statistics

t = select "stat_read_reqs" as "cnt" from SERVICE.STATISTICS save;

e = select "stat_read_errs_other" from SERVICE.STATISTICS save;
r = do e/t;
r = do r * 100 save as "stat_read_errs_other % of total reads";
r = do r <= 5;
ASSERT(r, True, "High read errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal read errors (> 5% reads). Please run 'show statistics service like stat_read' to see values.",
				"High read error check");

nf = select "stat_read_errs_notfound" from SERVICE.STATISTICS save;
r = do nf/t;
r = do r * 100 save as "stat_read_errs_notfound % of total reads";
r = do r <= 20;
ASSERT(r, True, "High read not found errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal read not found errors (> 20% reads). Please run 'show statistics service like stat_read' to see values.",
				"High read not found error check");


// Write statistics

t = select "stat_write_reqs" as "cnt" from SERVICE.STATISTICS save;

e = select "stat_write_errs" from SERVICE.STATISTICS save;
r = do e/t;
r = do r * 100 save as "stat_write_errs % of total writes";
r = do r <= 5;
ASSERT(r, True, "High write errors", "OPERATIONS", WARNING,
				"Listed namespace[s] show higher than normal write errors (> 5% writes). Please run 'show statistics service like stat_write' to see values.",
				"High write error check");


e = select "stat_read_errs_other" from SERVICE.STATISTICS save;
s = select "stat_read_success" from SERVICE.STATISTICS;
s = GROUP BY CLUSTER, NODE do SUM(s);
r = do e / s;
r = do r/u on common;
r = do r == 0;
ASSERT(r, True, "Non-zero node read errors count", "OPERATIONS", INFO,
				"Listed read error[s] show skew in count (for nodes). It may or may not be an issue depending on the error type. Please run 'show statistics service like stat_read' to see values.",
				"Node read errors count check");


SET CONSTRAINT VERSION >= 3.3.17;

defslp= select "defrag-sleep", "storage-engine.defrag-sleep" from NAMESPACE.CONFIG save;
defslp = group by CLUSTER, NAMESPACE defslp;
r = do defslp == 1000;
ASSERT(r, True, "Non-default namespace defrag-sleep configuration.", "OPERATIONS",INFO,
                "Listed namespace[s] have non-default defrag-sleep configuration. Please run 'show config namespace like defrag' to check value. It may be a non-issue in case namespaces are configured for aggressive defrag. Ignore those.",
                "Non-default namespace defrag-sleep check.");

SET CONSTRAINT VERSION ALL;


/*
Queries Requested by SA Team (Ronen)
*/

SET CONSTRAINT VERSION >= 3.9;

crp = select "cache_read_pct" as "post-write-queue", "cache-read-pct" as "post-write-queue" from NAMESPACE.STATISTICS save;
pwq = select "post-write-queue", "storage-engine.post-write-queue" as "post-write-queue"  from NAMESPACE.CONFIG save;
crp = do crp >= 10;
pwq = do pwq == 256;
r = do crp && pwq;
r = group by CLUSTER, NAMESPACE, NODE r;
ASSERT(r, False, "Sub-optimal post-write-queue", "OPERATIONS", INFO,
				"Listed namespace[s] show high cache hit rate (> 10%) but post-write-queue value is default. It might be sub-optimal. Please contact Aerospike support team or SA team.",
				"Namespace post-write-queue check");


SET CONSTRAINT VERSION < 4.2;

ptl = select "partition-tree-locks" from NAMESPACE.CONFIG save;
cs = select "cluster_size" from SERVICE.STATISTICS;
cs = group by CLUSTER do MAX(cs) save as "cluster_size";
r = do cs/ptl;
r = group by CLUSTER, NAMESPACE, NODE r;
r = do r < 2;

ASSERT(r, True, "Non-recommended partition-tree-locks", "OPERATIONS", WARNING,
				"Listed namespace[s] show low value for partition-tree-locks with respect to cluster size. It should be 8 for cluster-size < 16, 16 for cluster sizes 16 to 31, 32 for cluster sizes 32 to 63, etc. Please contact Aerospike support team or SA team.",
				"Namespace partition-tree-locks check");

m = select "memory-size" as "cnt" from NAMESPACE.CONFIG;
s = select "stop-writes-pct" as "cnt"  from NAMESPACE.CONFIG;
s = do 100 - s;
s = do s/100;
extra_space = do m * s save as "breathing space (over stop-write)";
extra_space = group by CLUSTER, NODE, NAMESPACE do SUM(extra_space);

p = select "partition-tree-sprigs" as "cnt" from NAMESPACE.CONFIG save as "partition-tree-sprigs";
p = do p/16;

// sprig overhead: 1M per 16 partition-tree-sprigs
sprig_overhead = do 1024 * 1024;
all_sprig_overhead = do p * sprig_overhead;

// lock overhead: 320K per partition-tree-locks
lock_overhead = do 320 * 1024;
all_lock_overhead = do ptl * lock_overhead;

// base overhead
base_overhead = do 64 * 1024;

total_overhead = do base_overhead + all_sprig_overhead;
total_overhead = do total_overhead + all_lock_overhead save as "partition-tree-sprigs overhead";

r = do total_overhead < extra_space;
e = select "edition" from METADATA;
e = do e == "Community";
e = group by CLUSTER, NODE do OR(e);
ASSERT(r, False, "Non-recommended partition-tree-sprigs for Community edition", "OPERATIONS", INFO,
				"Listed namespace[s] show low value for partition-tree-sprigs with respect to memory-size. partition-tree-sprigs overhead is less than (100 - stop-write-pct) % memory-size. It should be increased. Please contact Aerospike support team or SA team.",
				"Namespace partition-tree-sprigs check for Community edition",
				e);

SET CONSTRAINT VERSION >= 4.2;

cs = select "cluster_size" from SERVICE.STATISTICS;
cs = group by CLUSTER do MAX(cs);
repl = select "effective_replication_factor" as "cnt" from NAMESPACE.STATISTICS;

m = select "memory-size" as "cnt" from NAMESPACE.CONFIG;
s = select "stop-writes-pct" as "cnt"  from NAMESPACE.CONFIG;
s = do 100 - s;
s = do s/100;
extra_space = do m * s save as "breathing space (over stop-write)";
extra_space = group by CLUSTER, NODE, NAMESPACE do SUM(extra_space);

// sprig overhead: 8bytes per partition-tree-sprigs
sprigs = select "partition-tree-sprigs" as "cnt" from NAMESPACE.CONFIG save as "partition-tree-sprigs";
sprig_overhead = do 8 * sprigs;
all_sprig_overhead = do sprig_overhead * 4096;
all_sprig_overhead = do all_sprig_overhead / cs;
all_sprig_overhead = do all_sprig_overhead * repl;

// lock overhead: 8bytes per partition-tree-locks
ptl = 256;
lock_overhead = do 8 * 256;
all_lock_overhead = do lock_overhead * 4096;
all_lock_overhead = do all_lock_overhead / cs;
all_lock_overhead = do all_lock_overhead * repl;

// base overhead
base_overhead = do 64 * 1024;
total_overhead = do base_overhead + all_sprig_overhead;
total_overhead = do total_overhead + all_lock_overhead save as "partition-tree-sprigs overhead";

r = do total_overhead < extra_space;
e = select "edition" from METADATA;
e = do e == "Community";
e = group by CLUSTER, NODE do OR(e);
ASSERT(r, False, "Non-recommended partition-tree-sprigs for Community edition", "OPERATIONS", INFO,
				"Listed namespace[s] show low value for partition-tree-sprigs with respect to memory-size. partition-tree-sprigs overhead is less than (100 - stop-write-pct) % memory-size. It should be increased. Please contact Aerospike support team or SA team.",
				"Namespace partition-tree-sprigs check for Community edition",
				e);

SET CONSTRAINT VERSION >= 4.3.0.2;
// sprig mounts-size-limit checks

// critical case
cluster_size = select "cluster_size" as "sprig_limit_critical" from SERVICE.STATISTICS;
cluster_size = group by CLUSTER do MAX(cluster_size) save as "cluster-size";
repl = select "effective_replication_factor" as "sprig_limit_critical" from NAMESPACE.STATISTICS save as "effective_repl_factor";
pts = select "partition-tree-sprigs" as "sprig_limit_critical" from NAMESPACE.CONFIG save as "partition-tree-sprigs";
size_limit = select "index-type.mounts-size-limit" as "sprig_limit_critical" from NAMESPACE.CONFIG;
// below statement adds thousand delimiter to mounts-size-limiter when it prints
size_limit = do size_limit * 1 save as "mounts-size-limit";

// check for enterprise edition
edition = select "edition" from METADATA;
is_enterprise = do edition == "Enterprise";
is_enterprise = group by CLUSTER, NODE do OR(is_enterprise);

// check for all flash
index_type = select "index-type" from NAMESPACE.STATISTICS;
is_flash = do index_type == "flash";

// combine enterprise and all flash conditions
dont_skip = do is_enterprise && is_flash;
dont_skip = group by CLUSTER, NODE, NAMESPACE do OR(dont_skip);

// calculate sprig overhead
num_partitions = do 4096 * repl;
partitions_per_node = do num_partitions/cluster_size;
pts_per_node = do partitions_per_node * pts;
total_pts = do pts_per_node * 4096 save as "Minimum space required";
result = do total_pts > size_limit;

ASSERT(result, False, "ALL FLASH - Too many sprigs per partition for current available index mounted space. Some records are likely failing to be created.", "OPERATIONS", CRITICAL,
				"Minimum space required for sprig overhead at current cluster size exceeds mounts-size-limit.
				 See: https://www.aerospike.com/docs/operations/configure/namespace/index/#flash-index and https://www.aerospike.com/docs/operations/plan/capacity/#aerospike-all-flash",
				"Check for too many sprigs for current cluster size.",
				dont_skip);


// warning case
mcs = select "min-cluster-size" as "sprig_limit_warning" from SERVICE;
mcs = group by CLUSTER do MAX(mcs) save as "min-cluster-size";
repl = select "replication-factor" as "sprig_limit_warning" from NAMESPACE.STATISTICS;
pts = select "partition-tree-sprigs" as "sprig_limit_warning" from NAMESPACE.CONFIG;
msl = select "index-type.mounts-size-limit" as "sprig_limit_warning" from NAMESPACE.CONFIG;
// below statement adds thousand delimiter to mounts-size-limiter when it prints
msl = do msl * 1 save as "mounts-size-limit";

// calculate sprig overhead
// The replication factor should be min(repl, mcs)
r1 = do 4096 * repl;
r1 = do r1/mcs;
r1 = do r1 * pts;
r1 = do r1 * 4096 save as "Minimum space required";
r1 = do r1 > msl;

repl_smaller = do repl < mcs;
e1 = do repl_smaller && dont_skip;

ASSERT(r1, False, "ALL FLASH - Too many sprigs per partition for configured min-cluster-size.", "OPERATIONS", WARNING,
				"Minimum space required for sprig overhead at min-cluster-size exceeds mounts-size-limit. 
				 See: https://www.aerospike.com/docs/operations/configure/namespace/index/#flash-index and https://www.aerospike.com/docs/operations/plan/capacity/#aerospike-all-flash",
				"Check for too many sprigs for minimum cluster size.",
				e1);

// same as calculation above but with min-cluster-size
// Only is asserted if min-cluster-size is smaller than replication-factor.
// r2 = do 4096 * mcs;
// r2 = do r2/mcs;
r2 = 4096;
r2 = do r2 * pts;
r2 = do r2 * 4096 save as "Minimum space required";
r2 = do r2 > msl;

mcs_smaller = do mcs <= repl;
e2 = do mcs_smaller && dont_skip;

ASSERT(r2, False, "ALL FLASH - Too many sprigs per partition for configured min-cluster-size.", "OPERATIONS", WARNING,
				"Minimum space required for sprig overhead at min-cluster-size exceeds mounts-size-limit. 
				 See: https://www.aerospike.com/docs/operations/configure/namespace/index/#flash-index and https://www.aerospike.com/docs/operations/plan/capacity/#aerospike-all-flash",
				"Check for too many sprigs for minimum cluster size.",
				e2);

SET CONSTRAINT VERSION >= 4.0.0.1;
// SC mode rules

s = select "strong-consistency" from NAMESPACE.CONFIG;
// Find out atleast one namespace in SC mode
s = group by CLUSTER do OR(s);

r = select "clock_skew_stop_writes" from NAMESPACE.STATISTICS;
ASSERT(r, False, "Wrong clock skew for SC mode", "OPERATIONS", WARNING,
				"For listed namespace[s], clock skew is outside of tolerance for strong-consistency. So writes are not allowed.",
				"Namespace clock_skew_stop_writes check",
				s);

r = select "dead_partitions" from NAMESPACE.STATISTICS save;
ASSERT(r, 0, "Non-zero dead partitions", "OPERATIONS", WARNING,
				"Listed namespace[s] shows non-zero dead partitions. This is the number of partitions that are unavailable when all roster nodes are present. Will require the use of the revive command to make them available again.",
				"Namespace dead partitions check",
				s);

r = select "unavailable_partitions" from NAMESPACE.STATISTICS save;
ASSERT(r, 0, "Non-zero unavailable partitions", "OPERATIONS", WARNING,
				"Listed namespace[s] shows non-zero unavailable partitions. This is the number of partitions that are unavailable when roster nodes are missing. Will turn into dead_partitions if still unavailable when all roster nodes are present. Probable cause - nodes more than or equal to replication-factor are either 'untrusted' or out of the cluster.",
				"Namespace unavailable partitions check",
				s);

csw = select "cluster_clock_skew_stop_writes_sec" as "skew_val" from SERVICE.STATISTICS save;
// convert to milliseconds
csw = do csw * 1000;
cs_warning = do 0.75 * csw;
cs = select "cluster_clock_skew_ms" as "skew_val", "cluster_clock_skew" as "skew_val" from SERVICE.STATISTICS save;
r = do cs > cs_warning;
ASSERT(r, False, "Cluster clock_skew breached warning level", "OPERATIONS", WARNING,
				"Listed cluster[s] shows clock_skew more than 3/4th of cluster_clock_skew_stop_writes_sec. If it crossed cluster_clock_skew_stop_writes_sec then cluster will stop accepting writes.",
				"Cluster clock_skew check",
				s);

size = select "cluster_size" from SERVICE.STATISTICS;
p = group by CLUSTER do MAX(size) save as "cluster_size";
repl = select "replication-factor", "repl-factor" from NAMESPACE.CONFIG save as "replication_factor";
r = do p == repl;
ASSERT(r, False, "Nodes equal to replication factor.", "OPERATIONS", WARNING,
                                "Number of nodes is equal to replication factor, rolling restart not possible",
                                "Node / replication factor check", s);

sc_check = select "strong-consistency" from NAMESPACE.CONFIG;
sc_check = group by CLUSTER, NAMESPACE do OR(sc_check);

roster = select "roster", "observed_nodes" from ROSTER.CONFIG;
r = group by CLUSTER, NAMESPACE, NODE do EQUAL(roster);
ASSERT(r, True, "Roster misconfigured.", "OPERATIONS", WARNING,
				"Listed namespace[s] shows difference between set roster nodes and observe nodes. Please set roster properly.",
				"Roster misconfiguration check.", sc_check);

roster_null_check = select "roster" from ROSTER.CONFIG;
roster_null_check = group by CLUSTER, NAMESPACE, NODE roster_null_check;
roster_null_check = do "null" IN roster_null_check;

r = do roster_null_check && sc_check;

ASSERT(r, False, "Roster is null or NOT set.", "OPERATIONS", CRITICAL,
				"Listed namespace[s] shows ROSTER as NULL or NOT SET. Please check and set roster properly.",
				"Roster null check.");

SET CONSTRAINT VERSION ALL;

/*
Server Health Check
*/

SET CONSTRAINT VERSION >= 4.3.1;

m = select * from METADATA.HEALTH save;
ASSERT(m, False, "Outlier[s] detected by the server health check.", "OPERATIONS", WARNING,
			    "Listed outlier[s] have been reported by the server health check and they might be misbehaving.",
			    "Server health check outlier detection. Run command 'asinfo -v health-outliers' to see list of outliers");

SET CONSTRAINT VERSION ALL;

"""
