__author__ = 'aerospike'

from lib.logreader import LogReader
class LogHelper(object):
    prefixes = {}
    def __init__(self, path):
        self.path = path

    def getPrefixes(self):
        if(self.prefixes.has_key(self.path)):
            return self.prefixes[self.path]
        else:
            prefixes = LogReader.getPrefixes(self.path)
            prefixMap = {}
            for prefix in prefixes:
                prefixMap[prefix] = prefix
            self.prefixes[self.path] = prefixMap
            return prefixMap

#l1 = LogHelper("/var/log/aerospike/asla/as_log_1444289465.19/ascollectinfo.log")
#print l1.getPrefixes()
