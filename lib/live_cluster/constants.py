from lib.base_controller import ModifierHelp


SSH_MODIFIER_USAGE = "--enable-ssh [--ssh-user <user>] [--ssh-pwd <pwd>] [--ssh-port <port>] [--ssh-key <key>] [--ssh-key-pwd]"
SSH_MODIFIER_HELP = (
    ModifierHelp(
        "--enable-ssh",
        "Enables the collection of system statistics from a remote server via SSH using configuration loaded from '.ssh/config' by default.",
    ),
    ModifierHelp(
        "--ssh-user",
        "User ID to use when logging into remote servers via SSH. If not provided and no matching config file entry is found the current user ID is used.",
        default="current user",
    ),
    ModifierHelp(
        "--ssh-pwd",
        "User password used for logging into the remote servers via SSH.",
    ),
    ModifierHelp(
        "--ssh-key",
        "SSH key file path to send to the remote servers for authentication. If not provided and no config file entry is found then the keys in the .ssh directory are used.",
    ),
    ModifierHelp(
        "--ssh-port",
        "SSH port to use when logging into the remote servers.",
        default="22",
    ),
)
