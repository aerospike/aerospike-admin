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

    def __init__(self, log_path):
        self.log_path = log_path
        self.selected_dirs = self.get_dirs()

    def get_dirs(self, path=""):
        if not path:
            path = self.log_path
        return [name for name in os.listdir(path)
            if os.path.isdir(os.path.join(path, name))]

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

    def getFiles(self, clusterMode, dir_path=""):
        if not dir_path:
            dir_path = self.log_path
        ext = self.ascollectinfoExt
        if not clusterMode:
            ext = self.serverLogExt
        dirs = [a[0] for a in os.walk(dir_path)]
        f_filter = [d+ext for d in dirs]
        return [f for files in [glob.iglob(files) for files in f_filter] for f in files]

    def getFilesFromCurrentList(self, clusterMode):
        ext = self.ascollectinfoExt
        if not clusterMode:
            ext = self.serverLogExt
        dirs = self.get_current_dirs()
        f_filter = [d+ext for d in dirs]
        return [f for files in [glob.iglob(files) for files in f_filter] for f in files]

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
            line = lines.pop(0)
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

        lines = open(path,"r").readlines()
        line = lines.pop(0)

        while(line):
            sr1 = re.search( self.statsPattern, line )
            sr2 = re.search( self.configPattern, line )
            key = ""
            method = self.readStats
            collectLines = 0
            if(sr1):
                key = "statistics"
                method = self.readStats
                collectLines = 1
                line = lines.pop(0)
            elif(sr2):
                key = "config"
                method = self.readConfig
                collectLines = 1
                line = lines.pop(0)

            tempLines = []
            while(collectLines and (not re.search( self.sectionSeparator, line) )):
                tempLines.append(line)
                line = lines.pop(0)

            if(len(tempLines)>0):
                logInfo[key]=method(tempLines)

            try:
                line = lines.pop(0)
            except IndexError:
                break;

        return logInfo

    def htableToDic(self,rows):
        currentLine = 0
        nodes = []
        resDir = {}
        for line in rows:
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
        return resDir

    def readStats(self, lines):
        statDic = {}
        statDic["bins"] = {}
        statDic["sets"] = {}
        statDic["stats"] = {}
        statDic["namespace"] = {}

        binPattern = '~([^~]+) Bin Statistics'
        setPattern = '~([^~]+) Set Statistics'
        statPattern = 'Service Statistics'
        nsPattern = '~([^~]+) Namespace Statistics'

        line = lines.pop(0)

        while(line.strip().__len__()!=0):
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

            line = lines.pop(0)
            tempLines = []
            while(line.strip().__len__()!=0 and not line.startswith('~')):
                tempLines.append(line)
                line = lines.pop(0)
            dic[key]=self.htableToDic(tempLines)
            try:
                line = lines.pop(0)
            except IndexError:
                break

        return statDic

    def readConfig(self, lines):
        configDic = {}
        configDic["service"] = {}
        configDic["network"] = {}
        configDic["namespace"] = {}

        servicePattern = '(~+)Service Configuration(~+)'
        netPattern = '(~+)Network Configuration(~+)'
        nsPattern = '~([^~]+)Namespace Configuration(~+)'

        line = lines.pop(0)

        while(line.strip().__len__()!=0):
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

            line = lines.pop(0)
            tempLines = []
            while(line.strip().__len__()!=0 and not line.startswith('~')):
                tempLines.append(line)
                line = lines.pop(0)
            dic[key]=self.htableToDic(tempLines)
            try:
                line = lines.pop(0)
            except IndexError:
                break

        return configDic

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

    def grepDiff(self, str, file, start_tm="head", duration="", slice_tm="10", global_start_tm=""):
        latencyPattern1 = '%s (\d+)'
        latencyPattern2 = '%s \(([0-9,\s]+)\)'
        result = {"value":{},"diff":{}}

        lines = self.grep(str, file).strip().split('\n')
        if not lines:
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

        m1 = re.search( latencyPattern1%(str), line )
        m2 = re.search( latencyPattern2%(str), line )
        while(not m1 and not m2):
            try:
                line = lines.pop(0)
                if self.parse_dt(line)>=end_tm:
                    return global_start_tm,result
            except:
                return global_start_tm,result
            m1 = re.search( latencyPattern1%(str), line )
            m2 = re.search( latencyPattern2%(str), line )

        value = {}
        diff = {}

        slice_start = start_tm
        slice_end = slice_start + slice_size
        while(self.parse_dt(line)>=slice_end):
            value[slice_start.strftime(DT_FMT)] = []
            diff[slice_start.strftime(DT_FMT)] = []
            slice_start = slice_end
            slice_end = slice_start + slice_size

        if slice_end > end_tm:
                slice_end = end_tm

        pattern = ""
        prev = []
        slice_val = []

        if(m1):
            pattern = latencyPattern1%(str)
            slice_val.append(int(m1.group(1)))
        elif(m2):
            pattern = latencyPattern2%(str)
            slice_val = map(lambda x: int(x), m2.group(1).split(","))
        else:
            return global_start_tm,result

        for line in lines:
            #print line
            if self.parse_dt(line)>=end_tm:
                value[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                if prev :
                    diff[slice_start.strftime(DT_FMT)] = ([b-a for b,a in zip(slice_val,prev)])
                else:
                    diff[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                slice_val = []
                break

            if self.parse_dt(line)>=slice_end:
                value[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                if prev :
                    diff[slice_start.strftime(DT_FMT)] = ([b-a for b,a in zip(slice_val,prev)])
                else:
                    diff[slice_start.strftime(DT_FMT)] = ([b for b in slice_val])
                prev = slice_val
                slice_start = slice_end
                slice_end = slice_start + slice_size
                slice_val = []
                if slice_end > end_tm:
                    slice_end = end_tm

            m = re.search( pattern, line )
            if(m):
                tm = self.get_dt(line)
                current = map(lambda x: int(x),m.group(1).split(","))
                if(slice_val):
                    slice_val = ([b+a for b,a in zip(current,slice_val)])
                else:
                    slice_val = ([b for b in current])

        if slice_val:
            value[slice_start.strftime(DT_FMT)] = slice_val
            if prev :
                diff[slice_start.strftime(DT_FMT)] = ([b-a for b,a in zip(slice_val,prev)])
            else:
                diff[slice_start.strftime(DT_FMT)] = slice_val

        result["value"] = value
        result["diff"] = diff

        return start_tm, result
#l = LogReader("/var/log/aerospike/asla/as_log_1444289465.19")
#print l.getPrefixes("/var/log/aerospike/asla/as_log_1444289465.19/ascollectinfo.log")

