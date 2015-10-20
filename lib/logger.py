import copy
import ntpath

__author__ = 'aerospike'

from lib.logreader import LogReader
class Logger(object):
    logInfo = {}

    def __init__(self, log_path):
        self.log_path = log_path
        self.log_reader = LogReader(log_path)

    def __str__(self):
        files = self.log_reader.getFiles(True);
        retval =""

        i = 1
        for file in sorted(files):
            nodes = self.log_reader.getNodes(file)
            retval += "\n "+str(i)+": "
            retval += ntpath.basename(file)
            retval += " (" 
            retval += self.log_reader.getTime(file)
            retval += ")" 
            retval += "\n\tFound %s nodes"%(len(nodes))
            retval += "\n\tOnline:  %s"%(", ".join(nodes))
            retval += "\n"
            i  = i + 1

        return retval

    def infoGetConfig(self, stanza = ""):
        resDic = {}
        files = self.log_reader.getFiles(True);

        for file in sorted(files):
            if(not self.logInfo.has_key(file)):
                self.logInfo[file] = self.log_reader.read(file)

            if (stanza == "service"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["config"]["service"])
            elif (stanza == "network"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["config"]["network"])
            elif (stanza == "namespace"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["config"]["namespace"])

        return resDic

    def infoStatistics(self, stanza = ""):
        resDic = {}
        files = self.log_reader.getFiles(True);

        for file in sorted(files):
            if(not self.logInfo.has_key(file)):
                self.logInfo[file] = self.log_reader.read(file)

            if (stanza == "service"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["statistics"]["stats"]["service"])
            elif (stanza == "sets"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["statistics"]["sets"])
            elif (stanza == "bins"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["statistics"]["bins"])
            elif (stanza == "namespace"):
                resDic[file] = copy.deepcopy(self.logInfo[file]["statistics"]["namespace"])

        return resDic

    def grep(self,search_str, grep_cluster_logs):
        files = []
        if(grep_cluster_logs):
            files = self.log_reader.getFiles(True);
        else:
            files = self.log_reader.getFiles(False);

        grepRes = {}

        for file in files:
            grepRes[file] = self.log_reader.grep(search_str, file)

        return grepRes

    def grepCount(self,search_str, grep_cluster_logs):
        files = []
        if(grep_cluster_logs):
            files = self.log_reader.getFiles(True);
        else:
            files = self.log_reader.getFiles(False);

        grepRes = {}

        for file in files:
            grepRes[file] = self.log_reader.grepCount(search_str, file)

        return grepRes

    def grepLatency(self,search_str, grep_cluster_logs):
        files = []
        if(grep_cluster_logs):
            files = self.log_reader.getFiles(True);
        else:
            files = self.log_reader.getFiles(False);

        grepRes = {}

        for file in files:
            grepRes[file] = self.log_reader.grepLatency(search_str, file)

        return grepRes


