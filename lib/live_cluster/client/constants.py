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
    INFO_SERVER_ERROR_RESPONSE = "Server returned an error response for info command"
    CHECKPOINT_SAVE_FAIL = "Failed to start checkpoint save"
    CHECKPOINT_STATUS_FAIL = "Failed to get checkpoint status"
    INVALID_CHECKPOINT_TIMEOUT = "Invalid timeout. Must be an int between 1 and 3600"


DEFAULT_CONFIG_PATH = "/etc/aerospike/aerospike.conf"
MAX_SOCKET_POOL_SIZE = 16

# A node parked by checkpoint-save refuses every info command except checkpoint-status
# and a re-issued checkpoint-save. The error code is not a discriminator - the server
# uses AS_ERR_FORBIDDEN (22) for its pre-startup refusal too - so match the message.
CHECKPOINT_PARKED_RESPONSE = "checkpoint-save in progress"
CHECKPOINT_SAVE_IN_PROGRESS = "checkpoint-save already in progress"
CHECKPOINT_SAVE_COMPLETE = "checkpoint-save already complete"
CHECKPOINT_TIMEOUT_MIN = 1
CHECKPOINT_TIMEOUT_MAX = 3600
CHECKPOINT_TIMEOUT_DEFAULT = 300
