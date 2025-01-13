class ErrorsMsgs:
    NS_DNE = "Namespace does not exist"
    DC_DNE = "DC does not exist"
    UDF_DNE = "UDF does not exist"
    DC_EXISTS = "DC already exists"
    UDF_UPLOAD_FAIL = "Failed to add UDF"
    ROSTER_READ_FAIL = "Could not retrieve roster for namespace"
    DC_CREATE_FAIL = "Failed to create XDR datacenter"
    DC_DELETE_FAIL = "Failed to delete XDR datacenter"
    DC_NS_ADD_FAIL = "Failed to add namespace to XDR datacenter"
    DC_NS_REMOVE_FAIL = "Failed to remove namespace from XDR datacenter"
    DC_NODE_ADD_FAIL = "Failed to add node to XDR datacenter"
    DC_NODE_REMOVE_FAIL = "Failed to remove node from XDR datacenter"
    INVALID_REWIND = 'Invalid rewind. Must be int or "all"'
    INFO_SERVER_ERROR_RESPONSE = 'Failed to execute info command - server error'


DEFAULT_CONFIG_PATH = "/etc/aerospike/aerospike.conf"
