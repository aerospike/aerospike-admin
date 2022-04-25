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

import collections
import json
import os
import re

try:
    import toml

    HAVE_TOML = True
except ImportError:
    HAVE_TOML = False

try:
    from jsonschema import validate

    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

from lib.utils.constants import ADMIN_HOME, AuthMode

DEFAULTPASSWORD = "SomeRandomDefaultPassword"


class _Namespace(object):
    def __init__(self, adict):
        self.__dict__.update(adict)


# Default is local host without security / tls
# with timeout value of 1ms
_confdefault = {
    "cluster": {
        "host": "127.0.0.1",
        "services-alternate": False,
        "port": 3000,
        "user": None,
        "password": DEFAULTPASSWORD,
        "auth": AuthMode.INTERNAL,
        "tls-enable": False,
        "tls-name": "",
        "tls-cafile": "",
        "tls-capath": "",
        "tls-cert-blacklist": "",
        "tls-certfile": "",
        "tls-cipher-suite": "",
        "tls-crl-check": False,
        "tls-crl-check-all": False,
        "tls-keyfile": "",
        "tls-keyfile-password": None,
        "tls-protocols": "",
    },
    "asadm": {
        "services-alumni": False,
        "timeout": 1,
        "line-separator": False,
        "no-color": False,
        "out-file": "",
        "profile": False,
        "single-node": False,
        "json": False,
        "help": False,
        "version": False,
        "asinfo-mode": False,
        "collectinfo": False,
        "execute": False,
        "enable": False,
        "log-analyser": False,
        "log-path": "",
        "pmap": False,
    },
}

_confspec = """{
    "$schema": "http://json-schema.org/draft-04/schema#",
    "tile" : "toolsconf",
    "type" : "object",
    "additionalProperties" : true,
    "properties": {
       "cluster" : { "$ref" : "#/definitions/instance" },
       "asadm" : { "$ref" : "#/definitions/asadm" },
       "include" : {
            "type" : "object",
            "additionalProperties" : false,
            "properties" : {
                "file" : { "type" : "string" },
                "directory" : { "type": "string"}
           }
       }
    },
    "patternProperties": {
        "^cluster_.*$" : { "$ref" : "#/definitions/instance" },
        "^asadm_.*$" : { "$ref" : "#/definitions/asadm" }
    },
    "definitions" : {
        "asadm" : {
            "type" : "object",
            "properties" : {
                "services-alumni" : { "type" : "boolean" },
                "timeout" : { "type" : "integer" },

                "line-separator": { "type" : "boolean" },
                "no-color": { "type" : "boolean" },
                "out-file": { "type" : "string" },
                "profile": { "type" : "boolean" },
                "single-node": { "type" : "boolean" },

                "help": { "type" : "boolean" },
                "version": { "type" : "boolean" },
                "asinfo-mode": { "type" : "boolean" },
                "collectinfo": { "type" : "boolean" },
                "execute": { "type" : "boolean" },
                "enable": { "type" : "boolean" },
                "log-analyser": { "type" : "boolean" },
                "log-path" : { "type" : "string" }
            },
            "additionalProperties" : false
        },
        "instance" : {
            "type" : "object",
            "additionalProperties" : false,
            "properties" : {
                "host" : {"type" : "string"},
                "services-alternate" : { "type" : "boolean" },
                "port" : {"type" : "integer"},
                "user" : { "type" : "string" },
                "password" : { "type" : "string" },
                "auth" : { "type" : "string" },
                "tls-enable" : { "type" : "boolean" },
                "tls-name": { "type" : "string" },
                "tls-cipher-suite" : { "type" : "string" },
                "tls-crl-check" : { "type" : "boolean" },
                "tls-crl-check-all" : { "type" : "boolean" },
                "tls-keyfile" : { "type" : "string" },
                "tls-keyfile-password" : { "type" : "string" },
                "tls-cafile" : { "type" : "string" },
                "tls-capath" : { "type" : "string" },
                "tls-certfile" : { "type" : "string" },
                "tls-cert-blacklist" : { "type" : "string" },
                "tls-protocols" : {"type" : "string" }
            }
        }
    }
}"""


def _getdefault(logger):
    import copy

    return copy.deepcopy(_confdefault)


def _loadfile(fname, logger):
    conf_dict = {}

    if os.path.exists(fname):
        # file exists
        if HAVE_TOML:
            conf_dict = toml.loads(open(fname).read())
        else:
            raise ImportError("No module named toml")

        include_files = []
        if "include" in conf_dict.keys():
            if "file" in conf_dict["include"].keys():
                f = conf_dict["include"]["file"]
                include_files.append(os.path.expanduser(f))

            if "directory" in conf_dict["include"].keys():
                d = conf_dict["include"]["directory"]
                include_files = include_files + sorted(
                    [
                        os.path.join(dp, f)
                        for dp, dn, fn in os.walk(os.path.expanduser(d))
                        for f in fn
                    ]
                )

        for f in include_files:
            try:
                _merge(conf_dict, _loadfile(f, logger))
            except Exception as e:
                logger.error(
                    "Config file parse error: " + str(f) + " " + str(e).split("\n")[0]
                )

        if HAVE_JSONSCHEMA:
            validate(conf_dict, json.loads(_confspec))
        else:
            raise ImportError("No module named jsonschema")

    return conf_dict


def decode(v):
    if isinstance(v, str):
        if len(v) == 0:
            return None
        return v
    else:
        return v


def _flatten(conf_dict, instance=None):
    # _flatten global and asadm specific property
    # change all string key and value into utf-8

    asadm_conf = {}

    sections = []

    if instance is None:
        sections.append("asadm")
        sections.append("cluster")
    else:
        sections.append("cluster_" + str(instance))
        i = "asadm_" + str(instance)
        if i in conf_dict:
            sections.append(i)
        else:
            sections.append("asadm")

    for section in sections:
        if section in conf_dict.keys():
            for k, v in conf_dict[section].items():
                # Empty passwords are allowed do not interpret
                # it as None
                if k == "password":
                    asadm_conf[decode(k.replace("-", "_"))] = str(v)
                else:
                    asadm_conf[decode(k.replace("-", "_"))] = decode(v)

    return asadm_conf


def _merge(dct, merge_dct, ignore_false=False):
    for k, v in merge_dct.items():
        if (
            k in dct
            and isinstance(dct[k], dict)
            and isinstance(merge_dct[k], collections.Mapping)
        ):
            _merge(dct[k], merge_dct[k], ignore_false=ignore_false)
        else:
            if merge_dct[k] is not None and (
                not ignore_false or merge_dct[k] is not False
            ):
                dct[k] = merge_dct[k]


def _getseeds(conf):

    re_ipv6host = re.compile(r"^(\[.*\])$")
    re_ipv6hostport = re.compile(r"^(\[.*\]):(.*)$")
    re_ipv6hostnameport = re.compile(r"^(\[.*\]):(.*):(.*)$")
    re_ipv4hostport = re.compile(r"^(.*):(.*)$")
    re_ipv4hostnameport = re.compile(r"^(.*):(.*):(.*)$")

    # Set up default port and tls-name if not specified in
    # host string
    port = 3000
    if "port" in conf.keys() and conf["port"] is not None:
        port = conf["port"]

    tls_name = None
    if (
        "tls_name" in conf.keys()
        and conf["tls_name"] is not None
        and "tls_enable" in conf
        and conf["tls_enable"]
    ):
        tls_name = conf["tls_name"]

    if "host" in conf.keys() and conf["host"] is not None:
        seeds = []
        hosts = conf["host"].split(",")

        for host in hosts:
            try:
                m = re_ipv6hostnameport.match(host)
                if m and len(m.groups()) == 3:
                    g = m.groups()
                    seeds.append(
                        (
                            str(g[0]).strip("[]"),
                            int(g[2]),
                            tls_name if (tls_name is not None) else str(g[1]),
                        )
                    )
                    continue

                m = re_ipv6hostport.match(host)
                if m and len(m.groups()) == 2:
                    g = m.groups()
                    seeds.append((str(g[0]).strip("[]"), int(g[1]), tls_name))
                    continue

                m = re_ipv6host.match(host)
                if m and len(m.groups()) == 1:
                    g = m.groups()
                    seeds.append((str(g[0]).strip("[]"), port, tls_name))
                    continue

                m = re_ipv4hostnameport.match(host)
                if m and len(m.groups()) == 3:
                    g = m.groups()
                    seeds.append(
                        (
                            str(g[0]).strip("[]"),
                            int(g[2]),
                            tls_name if (tls_name is not None) else str(g[1]),
                        )
                    )
                    continue

                m = re_ipv4hostport.match(host)
                if m and len(m.groups()) == 2:
                    g = m.groups()
                    seeds.append((str(g[0]).strip("[]"), int(g[1]), tls_name))
                    continue

                # ipv4 host only
                seeds.append((str(host), port, tls_name))

            except Exception as e:
                print("host parse error " + str(e) + " " + str(hosts))

        return seeds
    else:
        return []


def loadconfig(cli_args, logger):
    # order of loading is
    #
    # Default
    default_conf_dict = _getdefault(logger)

    if cli_args.no_config_file and cli_args.only_config_file:
        print(
            "--no-config-file and only-config-file are mutually exclusive option. Please enable only one."
        )
        exit(1)

    conf_dict = {}
    conffiles = []

    if cli_args.only_config_file is not None or not cli_args.no_config_file:
        # need to load config file

        if not HAVE_TOML:
            logger.warning("No module named toml. Skipping Config file read.")

        elif not HAVE_JSONSCHEMA:
            logger.warning("No module named jsonschema. Skipping Config file read.")

        elif cli_args.only_config_file is not None:
            # Load only config file.
            f = cli_args.only_config_file

            if os.path.exists(f):
                try:
                    _merge(conf_dict, _loadfile(f, logger))
                    conffiles.append(f)
                except Exception as e:
                    # Bail out of the primary file has parsing error.
                    logger.critical(
                        "Config file parse error: "
                        + str(f)
                        + " "
                        + str(e).split("\n")[0]
                    )
            else:
                logger.warning(
                    "Config file read error : " + str(f) + " " + "No such file"
                )

        elif not cli_args.no_config_file:
            # Read config file if no-config-file is not specified
            # -> /etc/aerospike/astools.conf
            # -> ./aerospike/astools.conf
            # -> user specified conf file
            conffiles = ["/etc/aerospike/astools.conf", ADMIN_HOME + "astools.conf"]
            if cli_args.config_file:
                if os.path.exists(cli_args.config_file):
                    conffiles.append(cli_args.config_file)
                else:
                    logger.warning(
                        "Config file read error : "
                        + str(cli_args.config_file)
                        + " "
                        + "No such file"
                    )

            for f in conffiles:
                try:
                    _merge(conf_dict, _loadfile(f, logger))
                except Exception as e:
                    # Bail out of the primary file has parsing error.
                    logger.critical(
                        "Config file parse error: "
                        + str(f)
                        + " "
                        + str(e).split("\n")[0]
                    )

    asadm_dict = _flatten(default_conf_dict)
    _merge(asadm_dict, _flatten(conf_dict, cli_args.instance))

    # -> Command line
    cli_dict = vars(cli_args)

    # For boolean arguments, false is default value... so ignore it
    _merge(asadm_dict, cli_dict, ignore_false=True)

    try:
        asadm_dict["auth"] = AuthMode[asadm_dict["auth"].upper()]
    except Exception:
        logger.critical("Wrong authentication mode: " + str(asadm_dict["auth"]))

    # Find seed nods
    seeds = _getseeds(asadm_dict)
    args = _Namespace(asadm_dict)

    # debug
    # print json.dumps(vars(args), indent=4)
    # print seeds

    if not cli_args.asinfo_mode:
        if cli_args.instance:
            print("Instance:    " + cli_args.instance)

        if not cli_args.collectinfo:
            print("Seed:        " + str(seeds))

        if cli_args.no_config_file or not conffiles:
            print("Config_file: None")
        else:
            print("Config_file: " + ", ".join(reversed(conffiles)))

    return args, seeds


def print_config_help():
    print("\n")
    print("Usage: asadm [OPTIONS]")
    print(
        "---------------------------------------------------------------------------------------\n"
    )

    print(" -V --version         Show the version of asadm and exit")
    print(" -E --help            Show program usage.")
    print(
        " -e --execute         Execute a single or multiple asadm commands and exit. \n"
        "                      The input value is either string of ';' separated asadm \n"
        "                      commands or path of file which has asadm commands (ends with ';')."
    )
    print(
        " --enable             Run commands in privileged mode.  Must be used with the\n"
        "                      --execute option. Not allowed in interactive mode."
    )
    print(" -o --out-file        Path of file to write output of -e command[s].")
    print(" --no-color           Disable colored output.")
    print(
        " --single-node        Enable asadm mode to connect only seed node. \n"
        "                      By default asadm connects to all nodes in cluster."
    )
    print(" --collectinfo        Start asadm to run against offline collectinfo files.")
    print(" --pmap               Include partition map analysis in collectinfo files.")
    print(
        " --log-analyser       Start asadm in log-analyser mode and analyse data from log files."
    )
    print(
        " -f --log-path=path   Path of cluster collectinfo file or directory \n"
        "                      containing collectinfo and system info files."
    )
    print(" -j --json            Output as JSON (experimental).")

    print_config_file_option()
    config_file_help()


def print_config_file_option():
    print("\n")
    print("Configuration File Allowed Options")
    print("----------------------------------\n")
    print("[cluster]")
    print(
        ' -h, --host=HOST      HOST is "<host1>[:<tlsname1>][:<port1>],..." \n'
        "                      Server seed hostnames or IP addresses. The tlsname is \n"
        "                      only used when connecting with a secure TLS enabled \n"
        "                      server. Default: localhost:3000\n"
        "                      Examples:\n"
        "                        host1\n"
        "                        host1:3000,host2:3000\n"
        "                        192.168.1.10:cert1:3000,192.168.1.20:cert2:3000"
    )
    print(
        " --services-alternate Enable use of services-alternate instead of services in\n"
        "                      info request during cluster tending"
    )
    print(" -p, --port=PORT      Server default port. Default: 3000")
    print(
        " -U, --user=USER      User name used to authenticate with cluster. Default: none"
    )
    print(
        " -P, --password       Password used to authenticate with cluster. Default: none\n"
        "                      User will be prompted on command line if -P specified and no\n"
        "                      password is given."
    )
    print(
        " --auth=AUTHENTICATION_MODE\n"
        "                      Authentication mode. Values: "
        + str(list(AuthMode))
        + ".\n"
        "                      Default: " + str(AuthMode.INTERNAL)
    )
    print(
        " --tls-enable         Enable TLS on connections. By default TLS is disabled."
    )
    print(
        " -t --tls-name=name   Default TLS name of host to verify for TLS connection,\n"
        "                      if not specified in host string. It is required if tls-enable\n"
        "                      is set."
    )
    print(" --tls-cafile=path    Path to a trusted CA certificate file.")
    print(" --tls-capath=path    Path to a directory of trusted CA certificates.")
    print(
        " --tls-protocols=TLS_PROTOCOLS\n"
        "                      Set the TLS protocol selection criteria. This format\n"
        "                      is the same as Apache's SSLProtocol documented at http\n"
        "                      s://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl\n"
        "                      protocol . If not specified the asadm will use ' -all\n"
        "                      +TLSv1.2' if has support for TLSv1.2,otherwise it will\n"
        "                      be ' -all +TLSv1'."
    )
    print(
        " --tls-cipher-suite=TLS_CIPHER_SUITE\n"
        "                      Set the TLS cipher selection criteria. The format is\n"
        "                      the same as Open_sSL's Cipher List Format documented\n"
        "                      at https://www.openssl.org/docs/man1.0.1/apps/ciphers.\n"
        "                      html"
    )
    print(
        " --tls-keyfile=path   Path to the key for mutual authentication (if Aerospike\n"
        "                      Cluster is supporting it)."
    )
    print(
        " --tls-keyfile-password=password\n"
        "                      Password to load protected tls-keyfile.\n"
        "                      It can be one of the following:\n"
        "                      1) Environment varaible: 'env:<VAR>'\n"
        "                      2) File: 'file:<PATH>'\n"
        "                      3) String: 'PASSWORD'\n"
        "                      Default: none\n"
        "                      User will be prompted on command line if --tls-keyfile-password specified and no\n"
        "                      password is given."
    )
    print(
        " --tls-certfile=path  Path to the chain file for mutual authentication (if\n"
        "                      Aerospike Cluster is supporting it)."
    )
    print(
        " --tls-cert-blacklist=path\n"
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
    print("[asadm]")
    print(
        " -s --services-alumni\n"
        "                      Enable use of services-alumni-list instead of services-list"
    )
    print(
        " --timeout=value      Set timeout value in seconds for node level operations. \n"
        "                      TLS connection does not support timeout. Default: 1 seconds"
    )
    print(
        " --enable             Run commands in privileged mode.  Must be used with the\n"
        "                      --execute option. Not allowed in interactive mode."
    )


def config_file_help():
    print("\n\n")
    print(
        "Default configuration files are read from the following files in the given order:\n"
        "/etc/aerospike/astools.conf ~/.aerospike/astools.conf\n"
        "The following sections are read: (cluster asadm include)\n"
        "The following options effect configuration file behavior\n"
    )
    print(
        " --no-config-file\n"
        "                      Do not read any config file. Default: disabled"
    )
    print(
        " --instance=name\n"
        "                      Section with these instance is read. e.g in case instance \n"
        "                      `a` is specified sections cluster_a, asadm_a is read."
    )
    print(
        " --config-file=path\n"
        "                      Read this file after default configuration file."
    )
    print(
        " --only-config-file=path\n"
        "                      Read only this configuration file."
    )
    print("\n")


def get_cli_args():
    have_argparse = True
    try:
        import argparse

        parser = argparse.ArgumentParser(add_help=False, conflict_handler="resolve")
        add_fn = parser.add_argument
    except Exception:
        import optparse

        have_argparse = False
        usage = "usage: %prog [options]"
        parser = optparse.OptionParser(usage, add_help_option=False)
        add_fn = parser.add_option

    add_fn("-V", "--version", action="store_true")
    add_fn("-E", "--help", action="store_true")
    add_fn("-e", "--execute")
    add_fn("--enable", action="store_true")
    add_fn("-o", "--out-file")
    add_fn("-c", "--collectinfo", action="store_true")
    add_fn("-l", "--log-analyser", action="store_true")
    add_fn("-f", "--log-path")
    add_fn("-j", "--json", action="store_true")
    add_fn("--no-color", action="store_true")
    add_fn("--debug", action="store_true")
    add_fn("--profile", action="store_true")
    add_fn("--single-node", action="store_true")
    add_fn("--line-separator", action="store_true")

    add_fn("-h", "--host")
    add_fn("-a", "--services-alternate", action="store_true")
    add_fn("-p", "--port", type=int)
    add_fn("-U", "--user")
    if have_argparse:
        add_fn("-P", "--password", nargs="?", const=DEFAULTPASSWORD)
    else:
        parser.add_option(
            "-P",
            "--password",
            dest="password",
            action="store_const",
            const=DEFAULTPASSWORD,
        )

    add_fn("--auth")
    add_fn("--tls-enable", action="store_true")
    add_fn("--tls-cafile")
    add_fn("--tls-capath")
    add_fn("--tls-protocols")
    add_fn("--tls-cipher-suite")
    add_fn("--tls-keyfile")
    if have_argparse:
        add_fn("--tls-keyfile-password", nargs="?", const=DEFAULTPASSWORD)
    else:
        parser.add_option(
            "--tls-keyfile-password",
            dest="tls-keyfile-password",
            action="store_const",
            const=DEFAULTPASSWORD,
        )
    add_fn("--tls-certfile")
    add_fn("--tls-cert-blacklist")
    add_fn("--tls-crl-check", action="store_true")
    add_fn("--tls-crl-check-all", action="store_true")

    add_fn("-t", "--tls-name")
    add_fn("-s", "--services-alumni", action="store_true")
    add_fn("--timeout", type=float)

    add_fn("--config-file")
    add_fn("--instance")
    add_fn("--no-config-file", action="store_true")
    add_fn("--only-config-file")

    # Old style parameter with underscore
    # And parameters which needs to be passed through
    # asinfo (they come with underscore).
    add_fn("--line_separator", action="store_true")
    add_fn("--log_analyser", action="store_true")
    add_fn("--file_path", dest="log_path")
    add_fn("--asinfo_mode", action="store_true")
    add_fn("--asinfo-mode", action="store_true")
    add_fn("--out_file")
    add_fn("--no_color", action="store_true")
    add_fn("--services_alumni", action="store_true")
    add_fn("--services_alternate", action="store_true")
    add_fn("--single_node_cluster", dest="single_node", action="store_true")
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

    ### collectinfo options ###
    # include pmap analysis in collect info file.
    # Usage, `asadm collectinfo --pmap`
    add_fn("--pmap", action="store_true")

    if have_argparse:
        return parser.parse_args()

    (cli_args, args) = parser.parse_args()
    return cli_args
