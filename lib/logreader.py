__author__ = 'aerospike'

import os, glob, re
import time
from lib.util import shell_command

class LogReader(object):
    ascollectinfoExt = "/ascollectinfo.log"
    serverLogExt = "/aerospike.log"
    networkStartPattern = 'Network Information'
    serviceStartPattern = 'Service Configuration'
    networkEndPattern = 'Number of rows'
    sectionSeparator="(=+)ASCOLLECTINFO(=+)"
    statsPattern="\[\'statistics\'\]"
    configPattern="\[\'config\'\]"

    def __init__(self,log_path):
        self.log_path = log_path

    def getFiles(self, clusterMode):
        ext = self.ascollectinfoExt
        if not clusterMode:
            ext = self.serverLogExt
        dirs = [a[0] for a in os.walk(self.log_path)]
        f_filter = [d+ext for d in dirs]
        return [f for files in [glob.iglob(files) for files in f_filter] for f in files]

    def getTime(self, path):
        filename = re.split("/", path)[-2]
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(re.split('_', filename)[2])))

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

    def grepLatency(self, str, file):
        latencyPattern1 = '%s (\d+)'
        latencyPattern2 = '%s \(([0-9,\s]+)\)'
        result = []
        lines = self.grep(str, file).strip().split('\n')
        line = lines.pop(0)
        m1 = re.search( latencyPattern1%(str), line )
        m2 = re.search( latencyPattern2%(str), line )
        while(not m1 and not m2 and len(lines)>0):
            line = lines.pop(0)
            m1 = re.search( latencyPattern1%(str), line )
            m2 = re.search( latencyPattern2%(str), line )

        pattern = ""
        prev = []
        if(m1):
            pattern = latencyPattern1%(str)
            prev.append(int(m1.group(1)))
        elif(m2):
            pattern = latencyPattern2%(str)
            prev = map(lambda x: int(x), m2.group(1).split(","))

        for line in lines:
            #print line
            m = re.search( pattern, line )
            if(m):
                current = map(lambda x: int(x),m.group(1).split(","))
                result.append([b-a for b,a in zip(current,prev)])
                prev = current

        return result
#l = LogReader("/var/log/aerospike/asla/as_log_1444289465.19")
#print l.getPrefixes("/var/log/aerospike/asla/as_log_1444289465.19/ascollectinfo.log")

