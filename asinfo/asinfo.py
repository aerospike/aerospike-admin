#!/usr/bin/env python3

# Copyright 2008-2025 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License")
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
####
#
# A short utility program which pings a given host and requests the 'info' about
# either all names or a certain name
#
#

import os
import shlex
import sys
from subprocess import Popen, PIPE
import argparse

__version__ = "$$__version__$$"

DEFAULTPASSWORD = "SomeRandomDefaultPassword"


def bytes_to_str(data):
    try:
        return data.decode("utf-8")
    except Exception:
        pass

    return data


def print_config_help():
    print("\n")
    print("Usage: asinfo [OPTIONS]")
    print(
        "---------------------------------------------------------------------------------------\n"
    )

    print(" -V --version         Show the version of asinfo and exit")
    print(" -E --help            Show program usage.")
    print(" -v --value           Fetch single value (Default: all).")
    print(" -l --line-separator  Print in separate lines (Default: False).")
    print(
        " --timeout=value      Set timeout value in seconds. \n"
        "                      TLS connection does not support timeout. Default: 5 seconds"
    )

    print_config_file_option()
    config_file_help()


def print_config_file_option():
    print("\n")
    print("Configuration File Allowed Options")
    print("----------------------------------\n")
    print("[cluster]")
    print(
        " -h HOST, --host=HOST\n"
        '                      HOST is "<host1>[:<tlsname1>][:<port1>],..." \n'
        "                      Server seed hostnames or IP addresses. The tlsname is \n"
        "                      only used when connecting with a secure TLS enabled \n"
        "                      server. Default: localhost:3000\n"
        "                      Examples:\n"
        "                        host1\n"
        "                        host1:3000,host2:3000\n"
        "                        192.168.1.10:cert1:3000,192.168.1.20:cert2:3000"
    )
    print(
        " -p PORT, --port=PORT \n"
        "                      Server default port. Default: 3000"
    )
    print(
        " -U USER, --user=USER \n"
        "                      User name used to authenticate with cluster. Default: none"
    )
    print(
        " -P, --password\n"
        "                      Password used to authenticate with cluster. Default: none\n"
        "                      User will be prompted on command line if -P specified and no\n"
        "                      password is given."
    )
    print(
        " --auth=AUTHENTICATION_MODE \n"
        "                      Authentication mode. Values: ['EXTERNAL', 'EXTERNAL_INSECURE', 'INTERNAL', 'PKI'].\n"
        "                      Default: INTERNAL"
    )
    print(
        " --tls-enable \n"
        "                      Enable TLS on connections. By default TLS is disabled."
    )
    # Deprecated
    # print(" --tls-encrypt-only   Disable TLS certificate verification.\n")
    print(
        " -t TLS_NAME, --tls-name=TLS_NAME \n"
        "                      Specify host tlsname."
    )
    print(
        " --tls-cafile=TLS_CAFILE <path>\n"
        "                      Path to a trusted CA certificate file."
    )
    print(
        " --tls-capath=TLS_CAPATH <path>\n"
        "                      Path to a directory of trusted CA certificates."
    )
    print(
        " --tls-protocols=TLS_PROTOCOLS\n"
        "                      Set the TLS protocol selection criteria. This format\n"
        "                      is the same as Apache's SSLProtocol documented at http\n"
        "                      s://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl\n"
        "                      protocol . If not specified the asinfo will use '-all\n"
        "                      +TLSv1.2' if has support for TLSv1.2,otherwise it will\n"
        "                      be '-all +TLSv1'."
    )
    print(
        " --tls-cipher-suite=TLS_CIPHER_SUITE\n"
        "                      Set the TLS cipher selection criteria. The format is\n"
        "                      the same as Open_sSL's Cipher List Format documented\n"
        "                      at https://www.openssl.org/docs/man1.0.1/apps/ciphers.\n"
        "                      html"
    )
    print(
        " --tls-keyfile=TLS_KEYFILE <path>\n"
        "                      Path to the key for mutual authentication (if\n"
        "                      Aerospike Cluster is supporting it)."
    )
    print(
        " --tls-keyfile-password=password\n"
        "                      Password to load protected tls-keyfile.\n"
        "                      It can be one of the following:\n"
        "                      1) Environment variable: 'env:<VAR>'\n"
        "                      2) File: 'file:<PATH>'\n"
        "                      3) String: 'PASSWORD'\n"
        "                      Default: none\n"
        "                      User will be prompted on command line if --tls-keyfile-password specified and no\n"
        "                      password is given."
    )
    print(
        " --tls-certfile=TLS_CERTFILE <path>\n"
        "                      Path to the chain file for mutual authentication (if\n"
        "                      Aerospike Cluster is supporting it)."
    )
    print(
        " --tls-cert-blacklist <path>\n"
        "                      Path to a certificate blacklist file. The file should\n"
        "                      contain one line for each blacklisted certificate.\n"
        "                      Each line starts with the certificate serial number\n"
        "                      expressed in hex. Each entry may optionally specify\n"
        "                      the issuer name of the certificate (serial numbers are\n"
        "                      only required to be unique per issuer).Example:\n"
        "                      867EC87482B2\n"
        "                      /C=US/ST=CA/O=Acme/OU=Engineering/CN=TestChainCA"
    )

    print(
        " --tls-crl-check      Enable CRL checking for leaf certificate. An error\n"
        "                      occurs if a valid CRL files cannot be found in\n"
        "                      tls_capath."
    )
    print(
        " --tls-crl-check-all  Enable CRL checking for entire certificate chain. An\n"
        "                      error occurs if a valid CRL files cannot be found in\n"
        "                      tls_capath."
    )
    print("")


def config_file_help():
    print("\n\n")
    print(
        "Default configuration files are read from the following files in the given order:\n"
        "/etc/aerospike/astools.conf ~/.aerospike/astools.conf\n"
        "The following sections are read: (cluster include)\n"
        "The following options effect configuration file behavior\n"
    )
    print(
        " --no-config-file\n"
        "                      Do not read any config file. Default: disabled"
    )
    print(
        " --instance <name>\n"
        "                      Section with these instance is read. e.g in case instance \n"
        "                      `a` is specified section cluster_a is read."
    )
    print(
        " --config-file <path>\n"
        "                      Read this file after default configuration file."
    )
    print(
        " --only-config-file <path>\n"
        "                      Read only this configuration file."
    )
    print("\n")


def get_cli_args():
    parser = argparse.ArgumentParser(add_help=False, conflict_handler="resolve")
    add_fn = parser.add_argument

    add_fn("-V", "--version", action="store_true")
    add_fn("-E", "--help", action="store_true")
    add_fn("-v", "--value")
    add_fn("-l", "--line-separator", dest="line-separator", action="store_true")

    add_fn("-h", "--host")
    add_fn("-p", "--port", type=int)
    add_fn("-U", "--user")
    add_fn("-P", "--password", nargs="?")

    add_fn("--auth")
    add_fn("-t", "--tls-name")
    add_fn("--tls-enable", dest="tls-enable", action="store_true")
    add_fn("--tls-cafile", dest="tls-cafile")
    add_fn("--tls-capath", dest="tls-capath")
    add_fn("--tls-protocols", dest="tls-protocols")
    add_fn("--tls-cipher-suite", dest="tls-cipher-suite")
    add_fn("--tls-keyfile", dest="tls-keyfile")
    add_fn(
        "--tls-keyfile-password",
        nargs="?",
        dest="tls-keyfile-password",
        const=DEFAULTPASSWORD,
    )
    add_fn("--tls-certfile", dest="tls-certfile")
    add_fn("--tls-cert-blacklist", dest="tls-cert-blacklist")
    add_fn("--tls-crl-check", dest="tls-crl-check", action="store_true")
    add_fn("--tls-crl-check-all", dest="tls-crl-check-all", action="store_true")

    add_fn("--config-file", dest="config-file")
    add_fn("--instance")
    add_fn("--no-config-file", dest="no-config-file", action="store_true")
    add_fn("--only-config-file", dest="only-config-file")

    # Old style parameter with underscore
    # Todo: deprecate old style parameters
    add_fn("--tls_name")
    add_fn("--tls_enable", action="store_true")
    add_fn("--tls_cafile")
    add_fn("--tls_capath")
    add_fn("--tls_protocols")
    add_fn("--tls_cipher_suite")
    add_fn("--tls_keyfile")
    add_fn("--tls_certfile")
    add_fn("--tls_cert_blacklist")
    add_fn("--tls_crl_check", action="store_true")
    add_fn("--tls_crl_check_all", action="store_true")

    add_fn("--timeout", type=float)

    return parser.parse_args()


args = get_cli_args()

if args.help:
    print_config_help()
    sys.exit(0)

if args.version:
    sVersion = __version__.split("-")

    version = sVersion[0]
    build = sVersion[-1] if len(sVersion) > 1 else ""

    print("Aerospike Information Tool")
    print("Version " + version)
    print("Build " + build)

    sys.exit(0)

if args.value == "stats":
    args.value = "statistics"

os.environ["PATH"] = (
    os.path.dirname(os.path.realpath(sys.argv[0])) + ":" + os.getenv("PATH")
)

# asadm ( >= 0.1.22)
cmd = ["asadm", "--asinfo-mode"]
asinfo_cmd = ""

# default password in asadm is DEFAULTPASSWORD, so no need to pass default
# tls-keyfile-password is by default None in asadm, so need to pass its default
pwd_args = ["password"]

for arg, val in vars(args).items():
    if arg == "value":
        if val:
            asinfo_cmd += "'%s'" % (str(val))
    else:
        if (
            val is not None
            and val is not False
            and (arg not in pwd_args or val != DEFAULTPASSWORD)
        ):
            # If not a default values then only pass to asadm.
            cmd.append("--%s" % (str(arg)))
            if val is not True:
                # If not enable/disable argument then pass value also.
                # Some values may have space in it, to make it correct we need quotes.
                cmd.append("%s" % (val))

# asinfo works with only single node (seed node)

# final asadm command
if asinfo_cmd:
    cmd.extend(["-e", asinfo_cmd])

p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=False)
out, err = p.communicate()
out = bytes_to_str(out)
err = bytes_to_str(err)

if err:
    if out:
        print(out)

    print(str(err))
    sys.exit(1)

elif out:
    out = str(out).strip()

    connection_errors = ["Not able to connect any cluster", "Could not connect to node"]
    if any(ce in out for ce in connection_errors):
        # print "request to ",args.host,":",args.port," returned error"
        print(out)
        sys.exit(1)

    if "error:" in out.lower():
        print(str(out))
        sys.exit(1)

    if p.returncode:
        print("request to ", args.host, ":", args.port, " returned error")
        if out:
            print(out)
        sys.exit(1)

    print(out.strip())
