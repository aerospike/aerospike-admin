# Copyright 2018 Aerospike, Inc.
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

import toml
import json
import os
import re

import collections

from jsonschema import validate

from lib.utils.constants import ADMIN_HOME

class _Namespace(object):
  def __init__(self, adict):
    self.__dict__.update(adict)

# Default is local host without security / tls
# with timeout value of 5ms
_confdefault = '''
    [cluster]

    host = "127.0.0.1:3000"
    port = 3000

    user = ""
    password = "prompt"

    tls-enable =  false
    tls-cafile = ""
    tls-capath = ""
    tls-cert-blacklist = ""
    tls-certfile = ""
    tls-cipher-suite = ""
    tls-crl-check = false
    tls-crl-check-all = false
    tls-keyfile =  ""
    tls-protocols = ""

    [asadm]

    services-alumni = false
    services-alternate = false
    timeout = 5

    line-separator = false
    no-color = false
    out-file = ""
    profile = false
    single-node = false

    help = false
    version = false
    asinfo-mode = false
    collectinfo = false
    execute = false
    log-analyser = false
    log-path = ""

}'''

_confspec = '''{
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
                "services-alternate" : { "type" : "boolean" },
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
                "port" : {"type" : "integer"},
                "user" : { "type" : "string" },
                "password" : { "type" : "string" },
                "tls-enable" : { "type" : "boolean" },
                "tls-cipher-suite" : { "type" : "string" },
                "tls-crl-check" : { "type" : "boolean" },
                "tls-crl-check-all" : { "type" : "boolean" },

                "tls-keyfile" : { "type" : "string" },
                "tls-cafile" : { "type" : "string" },
                "tls-capath" : { "type" : "string" },
                "tls-certfile" : { "type" : "string" },
                "tls-cert-blacklist" : { "type" : "string" },
                "tls-protocols" : {"type" : "string" }
            }
        }
    }
}'''

def _getdefault(logger):
    conf_dict = toml.loads(_confdefault)
    validate(conf_dict, json.loads(_confspec))
    return conf_dict

def _loadfile(fname, logger):
    conf_dict = {}
    if os.path.exists(fname):
        # file exists
        conf_dict = toml.loads(open(fname).read())

        include_files = []
        if "include" in conf_dict.keys():
            if "file" in conf_dict["include"].keys():
                f = conf_dict["include"]["file"]
                include_files.append(os.path.expanduser(f))

            if "directory" in conf_dict["include"].keys():
                d = conf_dict["include"]["directory"]
                include_files = include_files + sorted([os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.expanduser(d)) for f in fn])

        for f in include_files:
            try:
                _merge(conf_dict, _loadfile(f, logger))
            except Exception as e:
                logger.error("Config file parse error: " + str(f) + " " + str(e).split("\n")[0])

    validate(conf_dict, json.loads(_confspec))
    return conf_dict

def decode(v):
    if isinstance(v, basestring):
        if len(v) == 0:
            return None
        return str(v)
    else:
        return v

def _flatten(conf_dict, instance):
    # _flatten global and asadm specific property
    # change all string key and value into utf-8

    # fill with default
    asadm_conf = {}
    for k,v in conf_dict["asadm"].iteritems():
        asadm_conf[decode(k.replace("-", "_"))] = decode(v)
    for k,v in conf_dict["cluster"].iteritems():
        asadm_conf[decode(k.replace("-", "_"))] = decode(v)

    if instance is None:
        return asadm_conf

    # Overlay instance setion
    sections = []

    sections.append("cluster_"+str(instance))

    mymod = "asadm_"+str(instance)
    if mymod in conf_dict.keys():
       sections.append(mymod)

    for section in sections:
        if section in conf_dict.keys():
            for k,v in conf_dict[section].iteritems():
                asadm_conf[decode(k.replace("-", "_"))] = decode(v)
    return asadm_conf


def _merge(dct, merge_dct):
    for k, v in merge_dct.iteritems():
        if (k in dct and isinstance(dct[k], dict)
                and isinstance(merge_dct[k], collections.Mapping)):
            _merge(dct[k], merge_dct[k])
        else:
            if merge_dct[k] is not None:
                dct[k] = merge_dct[k]


def _getseeds(conf):

    re_ipv6host = re.compile("^(\[.*\])$")
    re_ipv6hostport = re.compile("^(\[.*\]):(.*)$")
    re_ipv6hostnameport = re.compile("^(\[.*\]):(.*):(.*)$")
    re_ipv4hostport = re.compile("^(.*):(.*)$")
    re_ipv4hostnameport = re.compile("^(.*):(.*):(.*)$")

    # Set up default port and tls-name if not specified in
    # host string
    port = 3000
    if "port" in conf.keys() and conf["port"] is not None:
        port = conf["port"]

    tls_name = None
    if "tls_name" in conf.keys() and conf["tls_name"] is not None:
        tls_name = conf["tls_name"]


    if "host" in conf.keys() and conf["host"] is not None:
        seeds = []
        hosts = conf["host"].split(",")

        for host in hosts:
            try:
                m = re_ipv6hostnameport.match(host)
                if (m and len(m.groups()) == 3):
                    g = m.groups()
                    seeds.append((str(g[0]).strip("[]"), str(g[2]),
                        tls_name if (tls_name is not None) else str(g[1])))
                    continue

                m = re_ipv6hostport.match(host)
                if (m and len(m.groups()) == 2):
                    g = m.groups()
                    seeds.append((str(g[0]).strip("[]"), str(g[1]), tls_name))
                    continue

                m = re_ipv6host.match(host)
                if m and len(m.groups()) == 1:
                    g = m.groups()
                    seeds.append((str(g[0]).strip("[]"), port, tls_name))
                    continue

                m = re_ipv4hostnameport.match(host)
                if (m and len(m.groups()) == 3):
                    g = m.groups()
                    seeds.append((str(g[0]).strip("[]"), str(g[2]),
                        tls_name if (tls_name is not None) else str(g[1])))
                    continue

                m = re_ipv4hostport.match(host)
                if (m and len(m.groups()) == 2):
                    g = m.groups()
                    seeds.append((str(g[0]).strip("[]"), str(g[1]), tls_name))
                    continue

                # ipv4 host only
                seeds.append((str(host), port, tls_name))

            except Exception as e:
                print "host parse error " + str(e) +  " " + str(hosts)

        return seeds
    else:
        return []


def loadconfig(cli_args, logger):

    #print json.dumps(vars(cli_args), indent=4)

    # order of loading is
    #
    # Default
    conf_dict = _getdefault(logger)

    if cli_args.no_config_file and cli_args.only_config_file:
        print "--no-config-file and only-config-file are mutually exclusive option. Please enable only one."
        exit(1)

    # Load only config file.
    if cli_args.only_config_file is not None:
        f = cli_args.only_config_file
        conffiles = [f]
        try:
            _merge(conf_dict, _loadfile(f, logger))
        except Exception as e:
            # Bail out of the primary file has parsing error.
            logger.error("Config file parse error: " + str(f) + " " + str(e).split("\n")[0])
            exit(-1)

    # Read config file if no-config-file is not specified
    # is specified
    elif not cli_args.no_config_file:
       # -> /etc/aerospike/astools.conf
        # -> ./aerospike/astools.conf
        # -> user specified conf file
        conffiles = ["/etc/aerospike/astools.conf", ADMIN_HOME + "astools.conf"]
        if cli_args.config_file:
            conffiles.append(cli_args.config_file)

        for f in conffiles:
            try:
                _merge(conf_dict, _loadfile(f, logger))
            except Exception as e:
                # Bail out of the primary file has parsing error.
                logger.error("Config file parse error: " + str(f) + " " + str(e).split("\n")[0])
                exit(-1)

    asadm_dict = _flatten(conf_dict, cli_args.instance)

    # -> Command line
    cli_dict = vars(cli_args)
    _merge(asadm_dict, cli_dict)

    # Find seed nods
    seeds = _getseeds(asadm_dict)
    args = _Namespace(asadm_dict)

    # debug
    #print json.dumps(vars(args), indent=4)
    #print seeds

    # print
    if not cli_args.asinfo_mode:
        if cli_args.instance:
            print("Instance:    " + cli_args.instance )
        print("Seed:        " + str(seeds))

        if cli_args.no_config_file:
            print("Config_file: None")
        else:
            print("Config_file: " + ", ".join(reversed(conffiles)))

    return args, seeds


def print_config_help():
    print ("\n")
    print ("Usage: asadm [OPTIONS]")
    print ("---------------------------------------------------------------------------------------\n")

    print (" -V --version         Show the version of asadm and exit")
    print (" -E --help            Show program usage.")
    print (" -e --execute         Execute a single or multiple asadm commands and exit. \n"
           "                      The input value is either string of ';' separated asadm \n"
           "                      commands or path of file which has asadm commands (ends with ';').")
    print (" -o --out-file        Path of file to write output of -e command[s].")
    print (" --no-color           Disable colored output.")
    print (" --single-node        Enable asadm mode to connect only seed node. \n"
           "                      By default asadm connects to all nodes in cluster.")
    print (" --collectinfo        Start asadm to run against offline collectinfo files.")
    print (" --log-analyser       Start asadm in log-analyser mode and analyse data from log files.")
    print (" -f --log-path        Path of cluster collectinfo file or directory \n"
           "                      containing collectinfo and system info files.")

    print_config_file_option()
    config_file_help()

def print_config_file_option():
    print ("\n")
    print ("Configuration File Allowed Options")
    print ("----------------------------------\n")
    print ("[cluster]")
    print (" -h HOST, --host=HOST\n"
           "                      HOST is \"<host1>[:<tlsname1>][:<port1>],...\" \n"
           "                      Server seed hostnames or IP addresses. The tlsname is \n"
           "                      only used when connecting with a secure TLS enabled \n"
           "                      server. Default: localhost:3000\n"
           "                      Examples:\n"
           "                        host1\n"
           "                        host1:3000,host2:3000\n"
           "                        192.168.1.10:cert1:3000,192.168.1.20:cert2:3000")
    print (" -p PORT, --port=PORT \n"
           "                      Server default port. Default: 3000")
    print (" -U USER, --user=USER \n"
           "                      User name used to authenticate with cluster. Default: none")
    print (" -P, --password\n"
           "                      Password used to authenticate with cluster. Default: none\n"
           "                      User will be prompted on command line if -P specified and no\n"
           "                      password is given.")
    print (" --tls-enable         Enable TLS on connections. By default TLS is disabled.")
    # Deprecated
    # print(" --tls-encrypt-only   Disable TLS certificate verification.\n")
    print (" --tls-cafile=TLS_CAFILE\n"
           "                      Path to a trusted CA certificate file.")
    print (" --tls-capath=TLS_CAPATH.\n"
           "                      Path to a directory of trusted CA certificates.")
    print (" --tls-protocols=TLS_PROTOCOLS\n"
           "                      Set the TLS protocol selection criteria. This format\n"
           "                      is the same as Apache's SSLProtocol documented at http\n"
           "                      s://httpd.apache.org/docs/current/mod/mod_ssl.html#ssl\n"
           "                      protocol . If not specified the asadm will use '-all\n"
           "                      +TLSv1.2' if has support for TLSv1.2,otherwise it will\n"
           "                      be '-all +TLSv1'.")
    print (" --tls-cipher-suite=TLS_CIPHER_SUITE\n"
           "                      Set the TLS cipher selection criteria. The format is\n"
           "                      the same as Open_sSL's Cipher List Format documented\n"
           "                      at https://www.openssl.org/docs/man1.0.1/apps/ciphers.\n"
           "                      html")
    print (" --tls-keyfile=TLS_KEYFILE\n"
           "                      Path to the key for mutual authentication (if\n"
           "                      Aerospike Cluster is supporting it).")
    print (" --tls-certfile=TLS_CERTFILE <path>\n"
           "                      Path to the chain file for mutual authentication (if\n"
           "                      Aerospike Cluster is supporting it).")
    print (" --tls-cert-blacklist <path>\n"
           "                      Path to a certificate blacklist file. The file should\n"
           "                      contain one line for each blacklisted certificate.\n"
           "                      Each line starts with the certificate serial number\n"
           "                      expressed in hex. Each entry may optionally specify\n"
           "                      the issuer name of the certificate (serial numbers are\n"
           "                      only required to be unique per issuer).Example:\n"
           "                      867EC87482B2\n"
           "                      /C=US/ST=CA/O=Acme/OU=Engineering/CN=TestChainCA")

    print (" --tls-crl-check      Enable CRL checking for leaf certificate. An error\n"
           "                      occurs if a valid CRL files cannot be found in\n"
           "                      tls_capath.")
    print (" --tls-crl-checkall   Enable CRL checking for entire certificate chain. An\n"
           "                      error occurs if a valid CRL files cannot be found in\n"
           "                      tls_capath.")
    print ("")
    print ("[asadm]")
    print (" -t --tls-name        Default TLS name of host to verify for TLS connection,\n"
           "                      if not specified in host string. It is required if tls-enable\n"
           "                      is set.")
    print (" -s --services-alumni\n"
           "                      Enable use of services-alumni-list instead of services-list")
    print (" -a --services-alternate \n"
           "                      Enable use of services-alternate instead of services in\n"
           "                      info request during cluster tending")
    print (" --timeout            Set timeout value in seconds to node level operations. \n"
           "                      TLS connection does not support timeout. Default: 5 seconds")

def config_file_help():
    print "\n\n"
    print ("Default configuration files are read from the following files in the given order:\n"
          "/etc/aerospike/astools.conf ~/.aerospike/astools.conf\n"
          "The following sections are read: (cluster aql include)\n"
          "The following options effect configuration file behavior\n")
    print (" --no-config-file\n"
           "                      Do not read any config file. Default: disabled")
    print (" --instance <name>\n"
           "                      Section with these instance is read. e.g in case instance \n"
           "                      `a` is specified sections cluster_a, aql_a is read.")
    print (" --config-file <path>\n"
           "                      Read this file after default configuration file.")
    print (" --only-config-file <path>\n"
           "                      Read only this configuration file.")
    print ("\n")


def add_options(add_fn):
    add_fn("-V", "--version", action="store_true")
    add_fn("-E", "--help", action="store_true")
    add_fn("-e", "--execute")
    add_fn("-o", "--out-file")
    add_fn("-c", "--collectinfo",  action="store_true")
    add_fn("-l", "--log-analyser",  action="store_true")
    add_fn("-f", "--log-path")
    add_fn("--no-color", action="store_true")
    add_fn("--profile",  action="store_true")
    add_fn("--single-node", action="store_true")
    add_fn("--line-separator",  action="store_true")

    add_fn("-h", "--host")
    add_fn("-p", "--port", type=int)
    add_fn("-U", "--user")
    add_fn("-P", "--password",  action="store_const")
    add_fn("--tls-enable", action="store_true")
    add_fn("--tls-cafile")
    add_fn("--tls-capath")
    add_fn("--tls-protocols")
    add_fn("--tls-cipher-suite")
    add_fn("--tls-keyfile")
    add_fn("--tls-certfile")
    add_fn("--tls-cert-blacklist")
    add_fn("--tls-crl-check", action="store_true")
    add_fn("--tls-crl-check-all",  action="store_true")

    add_fn("-t", "--tls-name")
    add_fn("-s", "--services-alumni", action="store_true")
    add_fn("-a", "--services-alternate", action="store_true")
    add_fn("--timeout", type=float, default=5)

    add_fn("--config-file")
    add_fn("--instance")
    add_fn("--no-config-file", action="store_true")
    add_fn("--only-config-file")

    # Old style parameter with underscore
    # And parameters which needs to be passed through
    # asinfo (they come with underscore).
    add_fn("--line_separator",  action="store_true")
    add_fn("--log_analyser", action="store_true")
    add_fn("--file_path", dest="log_path")
    add_fn("--asinfo_mode", action="store_true")
    add_fn("--asinfo-mode", action="store_true")
    add_fn("--out_file")
    add_fn("--no_color")
    add_fn("--services_alumni")
    add_fn("--services_alternate")
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
    add_fn("--tls_crl_check",  action="store_true")
    add_fn("--tls_crl_check_all", action="store_true")
