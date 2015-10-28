__author__ = 'aerospike'

import os, glob, re
import time, datetime
from lib.util import shell_command
import copy

DT_FMT = "%b %d %Y %H:%M:%S"
DT_TO_MINUTE_FMT = "%b %d %Y %H:%M"
DT_TIME_FMT = "%H:%M:%S"
DATE_SEG = 0
DATE_SEPARATOR = "-"
YEAR = 0
MONTH = 1
DATE = 2

TIME_SEG = 1
TIME_SEPARATOR = ":"
HH = 0
MM = 1
SS = 2

class LogReader(object):
    ascollectinfoExt = "/ascollectinfo.log"
    serverLogExt = "/aerospike.log"
    networkStartPattern = 'Network Information'
    serviceStartPattern = 'Service Configuration'
    networkEndPattern = 'Number of rows'
    sectionSeparator="(=+)ASCOLLECTINFO(=+)"
    statsPattern="\[\'statistics\'\]"
    configPattern="\[\'config\'\]"
    distributionPattern="\[\'distribution\'\]"

    def __init__(self, log_path):
        self.log_path = log_path
        self.selected_dirs = self.get_dirs()
        self.initial_cluster_files = {}
        for file in self.getFiles(True, log_path):
            timestamp = self.get_timestamp(file)
            if "===ASCOLLECTINFO===" == timestamp:
                print "\n>>> Cannot add collectinfo file from asmonitor. Use the one from asadm ignoring " + file + " <<<\n"
            else:
                self.initial_cluster_files[self.get_timestamp(file)] = file
        self.all_cluster_files = copy.deepcopy(self.initial_cluster_files)
        self.selected_cluster_files = copy.deepcopy(self.initial_cluster_files)
        self.added_cluster_files = {}

        self.added_server_files = {}
        self.selected_server_files = {}

    def get_timestamp(self, file):
        file_id = open(file,"r")
        file_id.seek(0,0)
        line = file_id.readline()
        return line.strip().strip("\n")

    def get_dirs(self, path=""):
        try:
            if not path:
                path = self.log_path
            return [name for name in os.listdir(path)
                if os.path.isdir(os.path.join(path, name))]
        except:
            return []

    def get_current_dirs(self, path=""):
        return filter(lambda dir: dir in self.selected_dirs,self.get_dirs(self.log_path))

    def checkTime(self, val, date_string, segment, index=""):
        try:
            if segment == DATE_SEG:
                if val.__contains__("-"):
                    for v in range(int(val.split("-")[0]),int(val.split("-")[1])+1):
                        if(int(date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[index]) == v):
                            return True

                elif val.__contains__(","):
                    for v in val.split(","):
                        if(int(date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[index]) == int(v)):
                            return True

                else:
                    if(int(date_string.split(" ")[DATE_SEG].split(DATE_SEPARATOR)[index]) == int(val)):
                        return True
            elif segment == TIME_SEG:
                if val.__contains__("-"):
                    for v in range(int(val.split("-")[0]),int(val.split("-")[1])+1):
                        if(int(date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[index]) == v):
                            return True

                elif val.__contains__(","):
                    for v in val.split(","):
                        if(int(date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[index]) == int(v)):
                            return True

                else:
                    if(int(date_string.split(" ")[TIME_SEG].split(TIME_SEPARATOR)[index]) == int(val)):
                        return True
        except:
            pass

        return False

    def select_dirs(self, year="", month="", date="", hr="", minutes="", sec=""):
        dirs = self.get_dirs()
        if(year):
            dirs = filter(lambda dir : self.checkTime(year, self.getTime(dir), DATE_SEG, YEAR), dirs)
        if(month):
            dirs = filter(lambda dir : self.checkTime(month, self.getTime(dir), DATE_SEG, MONTH), dirs)
        if(date):
            dirs = filter(lambda dir : self.checkTime(date, self.getTime(dir), DATE_SEG, DATE), dirs)
        if(hr):
            dirs = filter(lambda dir : self.checkTime(hr, self.getTime(dir), TIME_SEG, HH), dirs)
        if(minutes):
            dirs = filter(lambda dir : self.checkTime(minutes, self.getTime(dir), TIME_SEG, MM), dirs)
        if(sec):
            dirs = filter(lambda dir : self.checkTime(sec, self.getTime(dir), TIME_SEG, SS), dirs)

        self.selected_dirs = copy.deepcopy(dirs)

    def select_cluster_snapshots(self, year="", month="", date="", hr="", minutes="", sec=""):
        snapshots = self.all_cluster_files.keys()

        if(year):
            snapshots = filter(lambda timestamp : self.checkTime(year, self.getTime(timestamp), DATE_SEG, YEAR), snapshots)
        if(month):
            snapshots = filter(lambda timestamp : self.checkTime(month, self.getTime(timestamp), DATE_SEG, MONTH), snapshots)
        if(date):
            snapshots = filter(lambda timestamp : self.checkTime(date, self.getTime(timestamp), DATE_SEG, DATE), snapshots)
        if(hr):
            snapshots = filter(lambda timestamp : self.checkTime(hr, self.getTime(timestamp), TIME_SEG, HH), snapshots)
        if(minutes):
            snapshots = filter(lambda timestamp : self.checkTime(minutes, self.getTime(timestamp), TIME_SEG, MM), snapshots)
        if(sec):
            snapshots = filter(lambda timestamp : self.checkTime(sec, self.getTime(timestamp), TIME_SEG, SS), snapshots)

        self.selected_cluster_files.clear()
        for snapshot in snapshots:
            self.selected_cluster_files[snapshot] = self.all_cluster_files[snapshot]

    def select_servers(self, indices):
        nodes = sorted(self.added_server_files.keys())
        self.selected_server_files.clear()
        for index in indices:
            try:
                self.selected_server_files[nodes[int(index)-1]] = self.added_server_files[nodes[int(index)-1]]
            except:
                continue

    def getFiles(self, clusterMode, dir_path=""):
        try:
            if not dir_path:
                dir_path = self.log_path
            ext = self.ascollectinfoExt
            if not clusterMode:
                ext = self.serverLogExt
            dirs = [a[0] for a in os.walk(dir_path)]
            f_filter = [d+ext for d in dirs]
            return [f for files in [glob.iglob(files) for files in f_filter] for f in files]
        except:
            return []

    def getFilesFromCurrentList(self, clusterMode, indices=[]):
        if clusterMode:
            files = {}
            if indices:
                timestamps = sorted(self.all_cluster_files.keys())
                for index in indices:
                    try:
                        files[timestamps[index-1]] = [self.all_cluster_files[timestamps[index-1]]]
                    except:
                        continue
            else:
                for timestamp in self.selected_cluster_files:
                    files[timestamp] = [self.selected_cluster_files[timestamp]]
            return files
        else :
            files = []
            if indices:
                nodes = sorted(self.added_server_files.keys())
                for index in indices:
                    try:
                        files.append(self.added_server_files[nodes[index-1]])
                    except:
                        continue
            else:
                for node, file in self.selected_server_files.iteritems():
                    files.append(file)
            return {"cluster":files}

    def getNode(self, path):
        for node,fpath in self.selected_server_files.iteritems():
            if path == fpath:
                return node
        return path

    def getTime(self, path):
        try:
            filename = re.split("/", path)[-2]
        except:
            filename = path
        try:
            return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(re.split('_', filename)[2])))
        except:
            return filename

    def getNodes(self, path):
        nodes = []
        lines = open(path,'r').readlines()
        line = lines.pop(0)
        while(line):
            if(re.search( self.networkStartPattern, line )):
                line = lines.pop(2)
                while(not (re.search( self.networkEndPattern, line ))):
                    nodes.append(line.split()[3])
                    line = lines.pop(2)
                break
            if lines:
                line = lines.pop(0)
            else:
                break
        return nodes

    @staticmethod
    def getPrefixes(path):
        nodePrefixes = []
        lines = open(path,'r').readlines()
        line = lines.pop(0)
        while(line):
            if(re.search( LogReader.serviceStartPattern, line )):
                line = lines.pop(0)
                nodes = line.split()
                nodePrefixes = nodes[2:len(nodes)]
                break
            line = lines.pop(0)
        return nodePrefixes

    def read(self, path):
        logInfo = {}
        logInfo["statistics"]={}
        logInfo["config"]={}
        logInfo["distribution"]={}

        file_id = open(path,"r")
        line = file_id.readline()

        while(line):
            sr1 = re.search( self.configPattern, line )
            sr2 = re.search( self.distributionPattern, line )
            sr3 = re.search( self.statsPattern, line )
            if(sr1):
                logInfo["config"] = self.readConfig(file_id)
        #    elif(sr2):
        #        logInfo["distribution"] = self.readDistribution(file_id)
            elif(sr3):
                logInfo["statistics"] = self.readStats(file_id)
                break

            try:
                line = file_id.readline()
            except IndexError:
                break;

        return logInfo

    def htableToDic(self,file_id):
        currentLine = 0
        nodes = []
        resDir = {}
        line = file_id.readline()
        while(line.strip().__len__()!=0 and not line.startswith('~')):
            if currentLine==0:
                tempNodes = line.split()
                nodes = tempNodes[2:len(tempNodes)]
            else:
                tempList = line.split()
                currentNode = 0
                dirEmpty = 0
                if len(resDir)== 0:
                    dirEmpty = 1
                beg = 2
                if(tempList[1]!=":"):
                    beg=1
                    tempList[0]=tempList[0][0:len(tempList[0])-1]
                for tempVal in tempList[beg:len(tempList)]:
                    tempDir = {}
                    if(not dirEmpty):
                        tempDir = resDir[nodes[currentNode]]
                    tempDir[tempList[0]] = tempVal
                    resDir[nodes[currentNode]] = tempDir
                    currentNode += 1

            currentLine += 1
            line = file_id.readline()
        return resDir

    def readStats(self, file_id):
        statDic = {}
        statDic["bins"] = {}
        statDic["sets"] = {}
        statDic["stats"] = {}
        statDic["namespace"] = {}

        binPattern = '~([^~]+) Bin Statistics'
        setPattern = '~([^~]+) Set Statistics'
        statPattern = 'Service Statistics'
        nsPattern = '~([^~]+) Namespace Statistics'

        line = file_id.readline()
        while(line.strip().__len__()!=0 and not re.search( self.sectionSeparator, line)):
            m1 = re.search( binPattern, line )
            m2 = re.search( setPattern, line )
            m3 = re.search( statPattern, line )
            m4 = re.search( nsPattern, line )
            dic = {}
            key = "key"
            if(m1):
                dic = statDic["bins"]
                key = m1.group(1)
            elif(m2):
                dic = statDic["sets"]
                key = m2.group(1)
            elif(m3):
                dic = statDic["stats"]
                key = "service"
            elif(m4):
                dic = statDic["namespace"]
                key = m4.group(1)

            dic[key]=self.htableToDic(file_id)
            try:
                line = file_id.readline()
            except IndexError:
                break

        return statDic

    def readConfig(self, file_id):
        configDic = {}
        configDic["service"] = {}
        configDic["network"] = {}
        configDic["namespace"] = {}

        servicePattern = '(~+)Service Configuration(~+)'
        netPattern = '(~+)Network Configuration(~+)'
        nsPattern = '~([^~]+)Namespace Configuration(~+)'

        line = file_id.readline()

        while(line.strip().__len__()!=0 and not re.search( self.sectionSeparator, line)):
            m1 = re.search( servicePattern, line )
            m2 = re.search( netPattern, line )
            m3 = re.search( nsPattern, line )
            dic = {}
            key = "key"
            if(m1):
                dic = configDic
                key = "service"
            elif(m2):
                dic = configDic
                key = "network"
            elif(m3):
                dic = configDic["namespace"]
                key = m3.group(1).strip()

            dic[key]=self.htableToDic(file_id)
            try:
                line = file_id.readline()
            except IndexError:
                break

        return configDic

    def readDistribution(self, file_id):
        configDic = {}
        configDic["ttl"] = {}
        configDic["evict"] = {}
        configDic["objsz"] = {}

        ttlPattern = '~([^~]+) - TTL Distribution in Seconds(~+)'
        evictPattern = '~([^~]+) - Eviction Distribution in Seconds(~+)'
        objszPattern = '~([^~]+) - Object Size Distribution in Seconds(~+)'

        line = file_id.readline()

        while(line.strip().__len__()!=0 and not re.search( self.sectionSeparator, line)):
            m1 = re.search( ttlPattern, line )
            m2 = re.search( evictPattern, line )
            m3 = re.search( objszPattern, line )
            dic = {}
            key = "key"
            if(m1):
                dic = configDic["ttl"]
                key = m1.group(1).strip()
            elif(m2):
                dic = configDic["evict"]
                key = m2.group(1).strip()
            elif(m3):
                dic = configDic["objsz"]
                key = m3.group(1).strip()

            dic[key]=self.distTableToDic(file_id)
            try:
                line = file_id.readline()
            except IndexError:
                break

        return configDic

    def distTableToDic(self, file_id):
        result = {}
        line = file_id.readline()
        while(line.strip().__len__()!=0 and (line.split()[0].strip()!="Node" or not line.strip().startswith("Number of rows"))):
            line = file_id.readline()

        if(line.strip().__len__()==0 or line.strip().startswith("Number of rows")):
            return result

        line = file_id.readline()
        while not line.strip().startswith("Number of rows"):
            vals = line.split()
            result[vals[0]] = vals[1:len(vals)]
            line = file_id.readline()

        file_id.seek(1,1)
        return result

    def grep(self, str, file):
        out, err = shell_command(['grep','\"'+str+'\"', file])
        return out

    def grepCount(self, str, file):
        out, err = shell_command(['grep', '-o', '\"'+str+'\"', file, '|' 'wc -l'])
        return out

    def parse_timedelta(self, arg):
        toks = arg.split(":")
        num_toks = len(toks)
        if num_toks > 3:
            return 0
        toks.reverse()
        try:
            arg_seconds = long(toks[0].strip())
            if num_toks > 1:
                arg_seconds = arg_seconds + (60 * long(toks[1].strip()))
            if num_toks > 2:
                arg_seconds = arg_seconds + (3600 * long(toks[2].strip()))
        except:
            return 0
        return datetime.timedelta(seconds = arg_seconds)

    def parse_init_dt(self, arg_from, tail_dt):
        if arg_from.startswith("-"):
            # Relative start time:
            try:
                init_dt = tail_dt - self.parse_timedelta(arg_from.strip("- "))
            except:
                print "can't parse relative start time " + arg_from
                return 0
        else:
            # Absolute start time:
            try:
                init_dt = datetime.datetime(\
                    *(time.strptime(arg_from, DT_FMT)[0:6]))
            except:
                print "can't parse absolute start time " + arg_from
                return 0
        return init_dt

    def get_dt(self, line):
        return line[0: line.find(" GMT:")]

    def parse_dt(self, line):
        prefix = line[0: line.find(" GMT:")].split(",")[0]
        return datetime.datetime(*(time.strptime(prefix, DT_FMT)[0:6]))

    def grepDiff(self, grep_str, file, start_tm="head", duration="", slice_tm="10", global_start_tm="", limit=""):
        latencyPattern1 = '%s (\d+)'
        latencyPattern2 = '%s \(([0-9,\s]+)\)'
        latencyPattern3 = '(\d+)\((\d+)\) %s'
        latencyPattern4 = '%s \((\d+)'
        result = {"value":{},"diff":{}}

        lines = self.grep(grep_str, file).strip().split('\n')
        if not lines or lines == ['']:
            return global_start_tm,result
        line = lines.pop(0)
        try:
            tail_line = lines[-1]
        except:
            tail_line = line
        tail_tm = self.parse_dt(tail_line)
        if global_start_tm:
            start_tm = global_start_tm
        else:
            if start_tm == "head":
                start_tm = self.parse_dt(line)
            else:
                start_tm = self.parse_init_dt(start_tm, tail_tm)
                if start_tm>tail_tm:
                    #print "Wrong start time"
                    return global_start_tm,result

        while(self.parse_dt(line)<start_tm):
                try:
                    line = lines.pop(0)
                except:
                    #print "Wrong start time"
                    return global_start_tm,result

        if duration:
            duration_tm = self.parse_timedelta(duration)
            end_tm = start_tm + duration_tm
        else:
            end_tm = tail_tm + self.parse_timedelta("10")


        slice_size = self.parse_timedelta(slice_tm)

        m1 = re.search( latencyPattern1%(grep_str), line )
        m2 = re.search( latencyPattern2%(grep_str), line )
        m3 = re.search( latencyPattern3%(grep_str), line )
        m4 = re.search( latencyPattern4%(grep_str), line )
        while(not m1 and not m2 and not m3 and not m4):
            try:
                line = lines.pop(0)
                if self.parse_dt(line)>=end_tm:
                    return global_start_tm,result
            except:
                return global_start_tm,result
            m1 = re.search( latencyPattern1%(grep_str), line )
            m2 = re.search( latencyPattern2%(grep_str), line )
            m3 = re.search( latencyPattern3%(grep_str), line )
            m4 = re.search( latencyPattern4%(grep_str), line )

        value = {}
        diff = {}

        slice_start = start_tm
        slice_end = slice_start + slice_size
        while(self.parse_dt(line)>=slice_end):
            #value[slice_start.strftime(DT_FMT)] = []
            #diff[slice_start.strftime(DT_FMT)] = []
            slice_start = slice_end
            slice_end = slice_start + slice_size

        if slice_end > end_tm:
                slice_end = end_tm

        pattern = ""
        prev = []
        slice_val = []
        pattern_type = 0

        #print str(m1) + " : " + str(m2) + " " + str(m3) + " " +str(m4)
        if(m1):
            pattern = latencyPattern1%(grep_str)
            slice_val.append(int(m1.group(1)))
        elif(m2):
            pattern = latencyPattern2%(grep_str)
            slice_val = map(lambda x: int(x), m2.group(1).split(","))
            pattern_type = 1
        elif(m3):
            pattern = latencyPattern3%(grep_str)
            slice_val = map(lambda x: int(x), list(m3.groups()))
            pattern_type = 2
        elif(m4):
            pattern = latencyPattern4%(grep_str)
            slice_val.append(int(m4.group(1)))
            pattern_type = 3
        else:
            print "no match"
            return global_start_tm,result

        for line in lines:
            #print line
            if self.parse_dt(line) >= end_tm:
                under_limit = True
                if limit:
                    under_limit = False
                if prev :
                    if limit:
                        temp = ([b-a for b,a in zip(slice_val,prev)])
                        if any(i >= limit for i in temp):
                            diff[slice_start.strftime(DT_FMT)] = ([b for b in temp])
                            under_limit = True
                        temp = []
                    else:
                        diff[slice_start.strftime(DT_FMT)] = ([b-a for b,a in zip(slice_val,prev)])
                else:
                    if not limit or any(i >= limit for i in slice_val):
                        diff[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                        under_limit = True

                if under_limit:
                    value[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                slice_val = []
                break

            if self.parse_dt(line)>=slice_end:
                under_limit = True
                if limit:
                    under_limit = False
                if prev :
                    if limit:
                        temp = ([b-a for b,a in zip(slice_val,prev)])
                        if any(i >= limit for i in temp):
                            diff[slice_start.strftime(DT_FMT)] = ([b for b in temp])
                            under_limit = True
                        temp = []
                    else:
                        diff[slice_start.strftime(DT_FMT)] = ([b-a for b,a in zip(slice_val,prev)])
                else:
                    if not limit or any(i >= limit for i in slice_val):
                        diff[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                        under_limit = True

                if under_limit:
                    value[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                prev = slice_val
                slice_start = slice_end
                slice_end = slice_start + slice_size
                slice_val = []
                if slice_end > end_tm:
                    slice_end = end_tm

            m = re.search( pattern, line )
            if(m):
                tm = self.get_dt(line)
                current = None
                if pattern_type == 2:
                    current = map(lambda x: int(x), list(m.groups()))
                else:
                    current = map(lambda x: int(x),m.group(1).split(","))
                if(slice_val):
                    slice_val = ([b+a for b,a in zip(current,slice_val)])
                else:
                    slice_val = ([b for b in current])

        if slice_val:
            under_limit = True
            if limit:
                under_limit = False
            if prev :
                if limit:
                    temp = ([b-a for b,a in zip(slice_val,prev)])
                    if any(i >= limit for i in temp):
                        diff[slice_start.strftime(DT_FMT)] = ([b for b in temp])
                        under_limit = True
                    temp = []
                else:
                    diff[slice_start.strftime(DT_FMT)] = ([b-a for b,a in zip(slice_val,prev)])
            else:
                if not limit or any(i >= limit for i in slice_val):
                    diff[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                    under_limit = True

            if under_limit:
                value[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])

        result["value"] = value
        result["diff"] = diff

        return start_tm, result
#l = LogReader("/var/log/aerospike/asla/as_log_1444289465.19")
#print l.getPrefixes("/var/log/aerospike/asla/as_log_1444289465.19/ascollectinfo.log")

