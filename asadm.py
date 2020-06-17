#!/bin/sh
""":"
for interp in python python3 ; do
   command -v > /dev/null "$interp" && exec "$interp" "$0" "$@"
done
echo >&2 "No Python interpreter found!"
exit 1
":"""

# Copyright 2013-2020 Aerospike, Inc.
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

from __future__ import print_function
from __future__ import absolute_import
from future import standard_library
standard_library.install_aliases()
from builtins import filter
from builtins import map
from builtins import str

import cmd
import copy
import getpass
import os
import re
import shlex
import sys
import logging
import traceback

if sys.version_info[0] < 3:
    raise Exception("Asadm requires Python 3. Use tools package <= 3.27.x for Python 2 support.")

if '-e' not in sys.argv and '--asinfo' not in sys.argv:
    # asinfo mode or non-interactive mode does not need readline
    # if we import readline then it adds escape character, which breaks some of asinfo use-cases.
    import readline
    if 'libedit' in readline.__doc__:
        # BSD libedit style tab completion for OS X
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")

# Setup logger before anything


class BaseLogger(logging.Logger, object):

    def __init__(self, name, level=logging.WARNING):
        return super(BaseLogger, self).__init__(name, level=level)

    def _handle_exception(self, msg):
        if isinstance(msg, Exception) and not isinstance(msg, ShellException):
            traceback.print_exc()

    def _print_message(self, msg, level, red_color=False, *args, **kwargs):
        try:
            message = str(msg).format(*args, **kwargs)
        except Exception:
            message = str(msg)

        message = level + ": " + message

        if red_color:
            message = terminal.fg_red() + message + terminal.fg_clear()

        print(message)

    def debug(self, msg, *args, **kwargs):
        if self.level <= logging.DEBUG:
            self._print_message(msg=msg, level="DEBUG", red_color=False, *args, **kwargs)

    def info(self, msg, *args, **kwargs):
        if self.level <= logging.INFO:
            self._print_message(msg=msg, level="INFO", red_color=False, *args, **kwargs)

    def warning(self, msg, *args, **kwargs):
        if self.level <= logging.WARNING:
            self._print_message(msg=msg, level="WARNING", red_color=True, *args, **kwargs)

    def error(self, msg, *args, **kwargs):
        if self.level <= logging.ERROR:
            self._print_message(msg=msg, level="ERROR", red_color=True, *args, **kwargs)
            self._handle_exception(msg)

    def critical(self, msg, *args, **kwargs):
        if self.level <= logging.CRITICAL:
            self._print_message(msg=msg, level="ERROR", red_color=True, *args, **kwargs)
            self._handle_exception(msg)
        exit(1)

logging.setLoggerClass(BaseLogger)
logging.basicConfig(level=logging.WARNING)

logger = logging.getLogger('asadm')
logger.setLevel(logging.INFO)

from lib.controllerlib import ShellException
from lib.basiccontroller import BasicRootController
from lib.client import info
from lib.client.assocket import ASSocket
from lib.client.ssl_context import SSLContext
from lib.collectinfocontroller import CollectinfoRootController
from lib.logcontroller import LogRootController
from lib.utils import common, util, conf
from lib.utils.constants import ADMIN_HOME, AdminMode, AuthMode
from lib.view import terminal, view

__version__ = '$$__version__$$'
CMD_FILE_SINGLE_LINE_COMMENT_START = "//"
CMD_FILE_MULTI_LINE_COMMENT_START = "/*"
CMD_FILE_MULTI_LINE_COMMENT_END = "*/"

MULTILEVEL_COMMANDS = ["show", "info"]


class AerospikeShell(cmd.Cmd):
    def __init__(self, admin_version, seeds, user=None, password=None, auth_mode=AuthMode.INTERNAL,
                 use_services_alumni=False, use_services_alt=False, log_path="", mode=AdminMode.LIVE_CLUSTER,
                 ssl_context=None, only_connect_seed=False, execute_only_mode=False, timeout=5):

        # indicates shell created successfully and connected to cluster/collectinfo/logfile
        self.connected  = True
        self.admin_history = ADMIN_HOME + 'admin_' + str(mode).lower() + "_history"
        self.execute_only_mode = execute_only_mode

        if mode == AdminMode.LOG_ANALYZER:
            self.name = 'Aerospike Log Analyzer Shell'
        elif mode == AdminMode.COLLECTINFO_ANALYZER:
            self.name = 'Aerospike Collectinfo Shell'
        else:
            self.name = 'Aerospike Interactive Shell'

        if not execute_only_mode:
            print(terminal.bold() + self.name + ', version ' +\
                admin_version + terminal.reset() + "\n")

        cmd.Cmd.__init__(self)

        try:
            if mode == AdminMode.LOG_ANALYZER:
                if not log_path:
                    log_path = " "

                self.ctrl = LogRootController(admin_version, log_path)
                self.prompt = "Log-analyzer> "

            elif mode == AdminMode.COLLECTINFO_ANALYZER:
                if not log_path:
                    logger.error(
                        "You have not specified any collectinfo path. Usage: asadm -c -f <collectinfopath>")
                    self.do_exit('')
                    exit(1)

                self.ctrl = CollectinfoRootController(admin_version,
                                                      clinfo_path=log_path)
                self.prompt = "Collectinfo-analyzer> "
                if not execute_only_mode:
                    self.intro = str(self.ctrl.loghdlr)

            else:
                if user is not None:
                    if password == conf.DEFAULTPASSWORD:
                        if sys.stdin.isatty():
                            password = getpass.getpass("Enter Password:")
                        else:
                            password = sys.stdin.readline().strip()

                    if not info.hasbcrypt:
                        self.do_exit('')
                        logger.critical("Authentication failed: bcrypt not installed.")

                self.ctrl = BasicRootController(seed_nodes=seeds, user=user, password=password, auth_mode=auth_mode,
                                                use_services_alumni=use_services_alumni, use_services_alt=use_services_alt,
                                                ssl_context=ssl_context, asadm_version=admin_version,
                                                only_connect_seed=only_connect_seed, timeout=timeout)

                if not self.ctrl.cluster.get_live_nodes():
                    self.do_exit('')
                    if self.execute_only_mode:
                        logger.error("Not able to connect any cluster with " + str(seeds) + ".")
                        self.connected = False
                        return
                    else:
                        logger.critical("Not able to connect any cluster with " + str(seeds) + ".")

                self.prompt = "Admin> "
                self.intro = ""
                if not execute_only_mode:
                    self.intro += str(self.ctrl.cluster) + "\n"
                    cluster_visibility_error_nodes = self.ctrl.cluster.get_visibility_error_nodes()

                    if cluster_visibility_error_nodes:
                        self.intro += terminal.fg_red() + "Cluster Visibility error (Please check services list): %s" % (
                            ", ".join(cluster_visibility_error_nodes)) + terminal.fg_clear() + "\n"

                    cluster_down_nodes = self.ctrl.cluster.get_down_nodes()

                    if cluster_down_nodes:
                        self.intro += terminal.fg_red() + "Extra nodes in alumni list: %s" % (
                            ", ".join(cluster_down_nodes)) + terminal.fg_clear() + "\n"

            if self.use_rawinput:
                self.prompt = "\001" + terminal.bold() + terminal.fg_red() + "\002" +\
                              self.prompt + "\001" +\
                              terminal.unbold() + terminal.fg_clear() + "\002"
        except Exception as e:
            self.do_exit('')
            logger.critical(str(e))

        if not execute_only_mode:

            try:
                readline.read_history_file(self.admin_history)
            except Exception:
                readline.write_history_file(self.admin_history)

        self.commands = set()

        regex = re.compile("^do_(.*)$")
        commands = [regex.match(v).groups()[0] for v in filter(regex.search, dir(self))]

        for command in commands:
            if command != 'help':
                self.commands.add(command)

    def clean_line(self, line):
        # get rid of extra whitespace
        lexer = shlex.shlex(line)
        # TODO: shlex is not working with 'with' ip addresses. Need to write a
        #       new parser or correct shlex behavior.
        commands = []

        command = []
        build_token = ''
        lexer.wordchars += ".-:/_{}"
        for token in lexer:
            build_token += token
            if token == '-':
                continue

            if token == ';':
                if command:
                    commands.append(command)
                    command = []
            else:
                command.append(build_token)
            build_token = ''
        else:
            if build_token:
                command.append(build_token)
            if command:
                commands.append(command)

        return commands

    def precmd(self, line, max_commands_to_print_header=1,
               command_index_to_print_from=1):

        lines = None

        try:
            lines = self.clean_line(line)

            if not lines:  # allow empty lines
                return ""
        except Exception as e:
            logger.error(e)
            return ""

        for line in lines:
            if line[0] in self.commands:
                return " ".join(line)

            if len(lines) > max_commands_to_print_header:
                if len(line) > 1 and any(cmd.startswith(line[0]) for cmd in MULTILEVEL_COMMANDS):
                    index = command_index_to_print_from
                else:
                    # If single level command then print from first index. For example: health, features, grep etc.
                    index = 0

                print("\n~~~ %s%s%s ~~~" % (
                    terminal.bold(), ' '.join(line[index:]), terminal.reset()))

            sys.stdout.write(terminal.reset())
            try:
                response = self.ctrl.execute(line)
                if response == "EXIT":
                    return "exit"
            except Exception as e:
                logger.error(e)
        return ""  # line was handled by execute

    def _listdir(self, root):
        "List directory 'root' appending the path separator to subdirs."
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        "Perform completion of filesystem path."
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
               for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_path(self, args):
        "Completions for the 'extra' command."
        if not args:
            return []

        if args[-1].startswith("\'"):
            names = ["\'" + v for v in self._complete_path(args[-1].split("\'")[-1])]
            return names
        if args[-1].startswith("\""):
            names = ["\"" + v for v in self._complete_path(args[-1].split("\"")[-1])]
            return names

        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def completenames(self, text, line, begidx, endidx):
        try:
            origline = line

            if isinstance(origline, str):
                line = origline.split(" ")
                line = [v for v in map(str.strip, line) if v]
                if origline and origline[-1] == ' ':
                    line.append('')

            if len(line) > 0:
                self.ctrl._init_commands()  # dirty
                cmds = self.ctrl.commands.get_key(line[0])
            else:
                cmds = []

            watch = False
            if len(cmds) == 1:
                cmd = cmds[0]
                if cmd == 'help':
                    line.pop(0)
                if cmd == 'watch':
                    watch = True
                    line.pop(0)
                    try:
                        for _ in (1, 2):
                            int(line[0])
                            line.pop(0)
                    except Exception:
                        pass
            line_copy = copy.deepcopy(line)
            names = self.ctrl.complete(line)
            if watch:
                try:
                    names.remove('watch')
                except Exception:
                    pass
            if not names:
                names = self.complete_path(line_copy) + [None]
                return names

        except Exception:
            return []
        return ["%s " % n for n in names]

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        try:
            if state >= 0:
                origline = readline.get_line_buffer()
                line = origline.lstrip()
                stripped = len(origline) - len(line)
                begidx = readline.get_begidx() - stripped
                endidx = readline.get_endidx() - stripped
                compfunc = self.completenames
                self.completion_matches = compfunc(text, line, begidx, endidx)
        except Exception:
            pass

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def emptyline(self):
        # do nothing
        return

    def close(self):
        try:
            self.ctrl.close()
        except Exception:
            pass

    # Other
    def do_exit(self, line):
        self.close()
        if not self.execute_only_mode and readline.get_current_history_length() > 0:
            readline.write_history_file(self.admin_history)

        return True

    def do_EOF(self, line):
        return self.do_exit(line)

    def do_cake(self, line):
        msg = """
                           *             *
                                                     *
      *                                                               *
               *               (             )
                              (*)           (*)
                       )       |             |       (
              *       (*)     |~|           |~|     (*)
                       |      |S|           |A|      |          *
                      |~|     |P|           |D|     |~|
                      |A|     |I|           |M|     |U|
                     ,|E|a@@@@|K|@@@@@@@@@@@|I|@@@@a|T|.
                .,a@@@|R|@@@@@|E|@@@@@@@@@@@|N|@@@@@|I|@@@@a,.
              ,a@@@@@@|O|@@@@@@@@@@@@.@@@@@@@@@@@@@@|L|@@@@@@@a,
             a@@@@@@@@@@@@@@@@@@@@@\' . `@@@@@@@@@@@@@@@@@@@@@@@@a
             ;`@@@@@@@@@@@@@@@@@@\'   .   `@@@@@@@@@@@@@@@@@@@@@\';
             ;@@@`@@@@@@@@@@@@@\'     .     `@@@@@@@@@@@@@@@@\'@@@;
             ;@@@;,.aaaaaaaaaa       .       aaaaa,,aaaaaaa,;@@@;
             ;;@;;;;@@@@@@@@;@      @.@      ;@@@;;;@@@@@@;;;;@@;
             ;;;;;;;@@@@;@@;;@    @@ . @@    ;;@;;;;@@;@@@;;;;;;;
             ;;;;;;;;@@;;;;;;;  @@   .   @@  ;;;;;;;;;;;@@;;;;@;;
             ;;;;;;;;;;;;;;;;;@@     .     @@;;;;;;;;;;;;;;;;@@@;
         ,%%%;;;;;;;;@;;;;;;;;       .       ;;;;;;;;;;;;;;;;@@;;%%%,
      .%%%%%%;;;;;;;@@;;;;;;;;     ,%%%,     ;;;;;;;;;;;;;;;;;;;;%%%%%%,
     .%%%%%%%;;;;;;;@@;;;;;;;;   ,%%%%%%%,   ;;;;;;;;;;;;;;;;;;;;%%%%%%%,
     %%%%%%%%`;;;;;;;;;;;;;;;;  %%%%%%%%%%%  ;;;;;;;;;;;;;;;;;;;\'%%%%%%%%
     %%%%%%%%%%%%`;;;;;;;;;;;;,%%%%%%%%%%%%%,;;;;;;;;;;;;;;;\'%%%%%%%%%%%%
     `%%%%%%%%%%%%%%%%%,,,,,,,%%%%%%%%%%%%%%%,,,,,,,%%%%%%%%%%%%%%%%%%%%\'
       `%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\'
           `%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\'
"""
        from time import sleep
        s = 0.5
        for line in msg.split('\n'):
            print(line)
            sleep(s)
            s = s / 1.2
        print(terminal.bold() + \
            "Let there be CAKE!".center(80) + \
            terminal.reset())


def do_ctrl_c(*args, **kwargs):
    print("Please press ctrl+d or type exit")


def parse_tls_input(cli_args):
    if cli_args.collectinfo:
        return None

    try:
        keyfile_password = cli_args.tls_keyfile_password

        if cli_args.tls_enable and cli_args.tls_keyfile and cli_args.tls_keyfile_password == conf.DEFAULTPASSWORD:

            if sys.stdin.isatty():
                keyfile_password = getpass.getpass("Enter TLS-Keyfile Password:")
            else:
                keyfile_password = sys.stdin.readline().strip()

        return SSLContext(enable_tls=cli_args.tls_enable, encrypt_only=None,
                          cafile=cli_args.tls_cafile, capath=cli_args.tls_capath,
                          keyfile=cli_args.tls_keyfile, keyfile_password=keyfile_password,
                          certfile=cli_args.tls_certfile, protocols=cli_args.tls_protocols,
                          cipher_suite=cli_args.tls_cipher_suite,
                          cert_blacklist=cli_args.tls_cert_blacklist,
                          crl_check=cli_args.tls_crl_check,
                          crl_check_all=cli_args.tls_crl_check_all).ctx

    except Exception as e:
        logger.error("SSLContext creation Exception: " + str(e))
        exit(1)


def execute_asinfo_commands(commands_arg, seed, user=None, password=None, auth_mode=AuthMode.INTERNAL, ssl_context=None, line_separator=False):
    cmds = [None]

    if commands_arg:
        asinfo_command_pattern = re.compile(r'''((?:[^;"'\n]|"[^"]*"|'[^']*')+)''')

        cmds = asinfo_command_pattern.split(commands_arg)[1::2]
        if not cmds:
            return

    if user is not None:
        if password == conf.DEFAULTPASSWORD:
            if sys.stdin.isatty():
                password = getpass.getpass("Enter Password:")
            else:
                password = sys.stdin.readline().strip()

        if not info.hasbcrypt:
            logger.critical("Authentication failed: bcrypt not installed.")

    assock = ASSocket(seed[0], seed[1], seed[2], user, password, auth_mode, ssl_context)
    if not assock.connect():
        logger.critical("Not able to connect any cluster with " + str(seed) + ".")
        return

    if user is not None:
        if not assock.login():
            logger.critical("Not able to login and authenticate any cluster with " + str(seed) + ".")
            return

    node_name = "%s:%s" % (seed[0], seed[1])

    for command in cmds:
        if command:
            command = util.strip_string(command)

        result = assock.execute(command)

        if result == -1 or result is None:
            result = IOError("Error: Invalid command '%s'" % command)

        view.CliView.asinfo({node_name: result}, line_separator, False, None)

    return


def main():
    cli_args = conf.get_cli_args()

    admin_version = get_version()

    if cli_args.help:
        conf.print_config_help()
        exit(0)

    if cli_args.version:
        print("Aerospike Administration Shell")
        print("Version " + str(admin_version))
        exit(0)

    if cli_args.no_color:
        disable_coloring()

    mode = AdminMode.LIVE_CLUSTER
    if cli_args.collectinfo:
        mode = AdminMode.COLLECTINFO_ANALYZER

    if cli_args.log_analyser:
        if cli_args.collectinfo:
            logger.critical("collectinfo-analyser and log-analyser are mutually exclusive options. Please enable only one.")
        mode = AdminMode.LOG_ANALYZER

    if not os.path.isdir(ADMIN_HOME):
        os.makedirs(ADMIN_HOME)

    execute_only_mode = False
    if cli_args.execute:
        execute_only_mode = True

    cli_args, seeds = conf.loadconfig(cli_args, logger)

    if cli_args.services_alumni and cli_args.services_alternate:
        logger.critical("Aerospike does not support alternate address for alumni services. Please enable only one of services_alumni or services_alternate.")

    if cli_args.auth == AuthMode.EXTERNAL and not cli_args.tls_enable:
        logger.critical("TLS is required for authentication mode: EXTERNAL")

    ssl_context = parse_tls_input(cli_args)

    if cli_args.asinfo_mode:

        if mode == AdminMode.COLLECTINFO_ANALYZER or mode == AdminMode.LOG_ANALYZER:
            logger.critical("asinfo mode can not work with Collectinfo-analyser or Log-analyser mode.")

        commands_arg = cli_args.execute
        if commands_arg and os.path.isfile(commands_arg):
            commands_arg = parse_commands(commands_arg)

        try:
            execute_asinfo_commands(commands_arg, seeds[0], user=cli_args.user,
                                    password=cli_args.password, auth_mode=cli_args.auth,
                                    ssl_context=ssl_context, line_separator=cli_args.line_separator)
            exit(0)
        except Exception as e:
            logger.error(e)
            exit(1)

    if not execute_only_mode:
        readline.set_completer_delims(' \t\n;')

    shell = AerospikeShell(admin_version, seeds, user=cli_args.user,
                           password=cli_args.password,
                           auth_mode=cli_args.auth,
                           use_services_alumni=cli_args.services_alumni,
                           use_services_alt=cli_args.services_alternate,
                           log_path=cli_args.log_path,
                           mode=mode,
                           ssl_context=ssl_context,
                           only_connect_seed=cli_args.single_node,
                           execute_only_mode=execute_only_mode, timeout=cli_args.timeout)

    use_yappi = False
    if cli_args.profile:
        try:
            import yappi
            use_yappi = True
        except Exception as a:
            print("Unable to load profiler")
            print("Yappi Exception:")
            print(str(a))
            exit(1)

    func = None
    args = ()
    single_command = True
    real_stdout = sys.stdout
    if not execute_only_mode:
        if not shell.connected:
            exit(1)

        func = shell.cmdloop
        single_command = False

    else:
        commands_arg = cli_args.execute
        max_commands_to_print_header = 1
        command_index_to_print_from = 1
        if os.path.isfile(commands_arg):
            commands_arg = parse_commands(commands_arg)
            max_commands_to_print_header = 0
            command_index_to_print_from = 0

        if cli_args.out_file:
            try:
                f = open(str(cli_args.out_file), "w")
                sys.stdout = f
                disable_coloring()
                max_commands_to_print_header = 0
                command_index_to_print_from = 0
            except Exception as e:
                print(e)

        if shell.connected:
            line = shell.precmd(commands_arg,
                                max_commands_to_print_header=max_commands_to_print_header,
                                command_index_to_print_from=command_index_to_print_from)

            shell.onecmd(line)
            func = shell.onecmd
            args = (line,)

        else:
            if "collectinfo" in commands_arg:
                logger.info("Collecting only System data")
                func = common.collect_sys_info(port=cli_args.port)

            exit(1)

    cmdloop(shell, func, args, use_yappi, single_command)
    shell.close()
    try:
        sys.stdout = real_stdout
        if f:
            f.close()
    except Exception:
        pass


def disable_coloring():
    from .lib.view import terminal
    terminal.enable_color(False)


def cmdloop(shell, func, args, use_yappi, single_command):
    try:
        if use_yappi:
            import yappi
            yappi.start()
            func(*args)
            yappi.get_func_stats().print_all()
        else:
            func(*args)
    except (KeyboardInterrupt, SystemExit):
        if not single_command:
            shell.intro = terminal.fg_red() + \
                "\nTo exit asadm utility please run exit command." + \
                terminal.fg_clear()
        cmdloop(shell, func, args, use_yappi, single_command)


def parse_commands(file):
    commands = ""
    commented = False
    for line in open(file, 'r').readlines():
        if not line or not line.strip():
            continue
        if commented:
            if line.strip().endswith(CMD_FILE_MULTI_LINE_COMMENT_END):
                commented = False
            continue
        if line.strip().startswith(CMD_FILE_SINGLE_LINE_COMMENT_START):
            continue
        if line.strip().startswith(CMD_FILE_MULTI_LINE_COMMENT_START):
            if not line.strip().endswith(CMD_FILE_MULTI_LINE_COMMENT_END):
                commented = True
            continue
        try:
            commands = commands + line
        except Exception:
            commands = line
    return commands

def get_version():
    if __version__.startswith('$$'):
        import string
        path = sys.argv[0].split('/')[:-1]
        path.append("version.txt")
        vfile = '/'.join(path)
        f = open(vfile)
        version = f.readline()
        f.close()
        return str(version)
    else:
        return __version__

if __name__ == '__main__':
    main()
