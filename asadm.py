#!/usr/bin/env python3

# Copyright 2013-2021 Aerospike, Inc.
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

import inspect
import cmd
import getpass
import logging

import os
import re
import shlex
import sys
import asyncio
import readline
from lib.live_cluster.client.msgpack import ASPacker
from lib.utils.async_object import AsyncObject


if "libedit" in readline.__doc__:
    # BSD libedit style tab completion for OS X
    readline.parse_and_bind("bind ^I rl_complete")
else:
    readline.parse_and_bind("tab: complete")

# Setup logger before anything

from lib.utils.logger import logger
from lib.collectinfo_analyzer.collectinfo_root_controller import (
    CollectinfoRootController,
)
from lib.live_cluster.live_cluster_root_controller import LiveClusterRootController
from lib.live_cluster.client import info
from lib.live_cluster.client.assocket import ASSocket
from lib.live_cluster.client.ssl_context import SSLContext
from lib.log_analyzer.log_analyzer_root_controller import LogAnalyzerRootController
from lib.live_cluster.collectinfo_controller import CollectinfoController
from lib.utils import common, util, conf
from lib.utils.constants import ADMIN_HOME, AdminMode, AuthMode
from lib.view import terminal, view, sheet
from time import sleep
import yappi  # noqa F401

# Do not remove this line.  It mitigates a race condition that occurs when using
# pyinstaller and socket.getaddrinfo.  For some reason the idna codec is not registered
# causing a lookup error to occur. Adding this line here makes sure that the proper
# codec is registered well before it is used in getaddrinfo.
# see https://bugs.python.org/issue29288, https://github.com/aws/aws-cli/blob/1.16.277/awscli/clidriver.py#L55,
# and https://github.com/pyinstaller/pyinstaller/issues/1113 for more info :)
"".encode("idna")

# Do not remove this line.  It mitigates a race condition that occurs when using
# pyinstaller and socket.getaddrinfo.  For some reason the idna codec is not registered
# causing a lookup error to occur. Adding this line here makes sure that the proper
# codec is registered well before it is used in getaddrinfo.
# see https://bugs.python.org/issue29288, https://github.com/aws/aws-cli/blob/1.16.277/awscli/clidriver.py#L55,
# and https://github.com/pyinstaller/pyinstaller/issues/1113 for more info :)
"".encode("idna")

__version__ = "$$__version__$$"
CMD_FILE_SINGLE_LINE_COMMENT_START = "//"
CMD_FILE_MULTI_LINE_COMMENT_START = "/*"
CMD_FILE_MULTI_LINE_COMMENT_END = "*/"

MULTILEVEL_COMMANDS = ["show", "info", "manage"]

DEFAULT_PROMPT = "Admin> "
PRIVILEGED_PROMPT = "Admin+> "


packer = ASPacker()


class AerospikeShell(cmd.Cmd, AsyncObject):
    async def __init__(
        self,
        admin_version,
        seeds,
        user=None,
        password=None,
        auth_mode=AuthMode.INTERNAL,
        use_services_alumni=False,
        use_services_alt=False,
        log_path="",
        mode=AdminMode.LIVE_CLUSTER,
        ssl_context=None,
        only_connect_seed=False,
        execute_only_mode=False,
        privileged_mode=False,
        timeout=1,
    ):
        # indicates shell created successfully and connected to cluster/collectinfo/logfile
        self.connected = True
        self.admin_history = ADMIN_HOME + "admin_" + str(mode).lower() + "_history"
        self.execute_only_mode = execute_only_mode
        self.privileged_mode = False
        if mode == AdminMode.LOG_ANALYZER:
            self.name = "Aerospike Log Analyzer Shell"
        elif mode == AdminMode.COLLECTINFO_ANALYZER:
            self.name = "Aerospike Collectinfo Shell"
        else:
            self.name = "Aerospike Interactive Shell"

        if not execute_only_mode:
            print(
                terminal.bold()
                + self.name
                + ", version "
                + admin_version
                + terminal.reset()
                + "\n"
            )

        cmd.Cmd.__init__(self)

        try:
            if mode == AdminMode.LOG_ANALYZER:
                if not log_path:
                    log_path = " "

                self.ctrl = LogAnalyzerRootController(admin_version, log_path)
                self.prompt = "Log-analyzer> "

            elif mode == AdminMode.COLLECTINFO_ANALYZER:
                if not log_path:
                    logger.error(
                        "You have not specified any collectinfo path. Usage: asadm -c -f <collectinfopath>"
                    )
                    await self.do_exit("")
                    sys.exit(1)

                self.ctrl = CollectinfoRootController(
                    admin_version, clinfo_path=log_path
                )
                self.prompt = "Collectinfo-analyzer> "
                if not execute_only_mode:
                    self.intro = str(self.ctrl.log_handler)

            else:
                if user is not None:
                    if password == conf.DEFAULTPASSWORD:
                        if sys.stdin.isatty():
                            password = getpass.getpass("Enter Password:")
                        else:
                            password = sys.stdin.readline().strip()

                    if not info.hasbcrypt:
                        await self.do_exit("")
                        logger.critical("Authentication failed: bcrypt not installed.")

                self.ctrl = await LiveClusterRootController(
                    seeds,
                    user,
                    password,
                    auth_mode,
                    use_services_alumni,
                    use_services_alt,
                    ssl_context,
                    only_connect_seed,
                    timeout=timeout,
                    asadm_version=admin_version,
                )

                if not self.ctrl.cluster.get_live_nodes():
                    await self.do_exit("")
                    if self.execute_only_mode:
                        self.connected = False
                        return
                    else:
                        logger.critical(
                            "Not able to connect any cluster with " + str(seeds) + "."
                        )

                self.set_default_prompt()
                self.intro = ""
                if execute_only_mode:
                    if privileged_mode:
                        self.ctrl.do_enable([])
                else:
                    self.intro += str(self.ctrl.cluster) + "\n"
                    cluster_visibility_error_nodes = (
                        self.ctrl.cluster.get_visibility_error_nodes()
                    )

                    if cluster_visibility_error_nodes:
                        self.intro += (
                            terminal.fg_red()
                            + "Cluster Visibility error (Please check services list): %s"
                            % (", ".join(cluster_visibility_error_nodes))
                            + terminal.fg_clear()
                            + "\n"
                        )

                    cluster_down_nodes = await self.ctrl.cluster.get_down_nodes()

                    if cluster_down_nodes:
                        self.intro += (
                            terminal.fg_red()
                            + "Extra nodes in alumni list: %s"
                            % (", ".join(cluster_down_nodes))
                            + terminal.fg_clear()
                            + "\n"
                        )

        except Exception as e:
            await self.do_exit("")
            logger.critical(e)

        if not execute_only_mode:

            try:
                readline.read_history_file(self.admin_history)
            except Exception:
                readline.write_history_file(self.admin_history)

        self.commands = set()

        regex = re.compile("^do_(.*)$")
        commands = [regex.match(v).groups()[0] for v in filter(regex.search, dir(self))]

        for command in commands:
            if command != "help":
                self.commands.add(command)

    def set_prompt(self, prompt, color="green"):
        self.prompt = prompt

        if self.use_rawinput:
            if color == "green":
                color_func = terminal.fg_green
            elif color == "red":
                color_func = terminal.fg_red
            else:

                def color_func():
                    return ""

            self.prompt = (
                "\001"
                + terminal.bold()
                + color_func()
                + "\002"
                + self.prompt
                + "\001"
                + terminal.unbold()
                + terminal.fg_clear()
                + "\002"
            )

    def set_default_prompt(self):
        self.set_prompt(DEFAULT_PROMPT, "green")

    def set_privaliged_prompt(self):
        self.set_prompt(PRIVILEGED_PROMPT, "red")

    def clean_line(self, line):
        # get rid of extra whitespace
        lexer = shlex.shlex(line)
        # TODO: shlex is not working with 'with' ip addresses. Need to write a
        #       new parser or correct shlex behavior.
        commands = []

        command = []
        build_token = ""
        lexer.wordchars += r"`~!@#$%^&*()_-+={}[]|\:''\"<>,./?"
        for token in lexer:
            build_token += token
            if token == "-":
                continue

            if token == ";":
                if command:
                    commands.append(command)
                    command = []
            else:
                command.append(build_token)
            build_token = ""
        else:
            if build_token:
                command.append(build_token)
            if command:
                commands.append(command)

        return commands

    # This was copied from the base class then turned async.
    async def cmdloop(self, intro=None):
        """Repeatedly issue a prompt, accept input, parse an initial prefix
        off the received input, and dispatch to action methods, passing them
        the remainder of the line as argument.

        """

        self.preloop()
        if self.use_rawinput and self.completekey:
            self.old_completer = readline.get_completer()
            readline.set_completer(self.complete)
            readline.parse_and_bind(self.completekey + ": complete")

        try:
            if intro is not None:
                self.intro = intro
            if self.intro:
                self.stdout.write(str(self.intro) + "\n")
            stop = None
            while not stop:
                if self.cmdqueue:
                    line = self.cmdqueue.pop(0)
                else:
                    if self.use_rawinput:
                        try:
                            line = input(self.prompt)
                        except EOFError:
                            line = "EOF"
                    else:
                        self.stdout.write(self.prompt)
                        self.stdout.flush()
                        line = self.stdin.readline()
                        if not len(line):
                            line = "EOF"
                        else:
                            line = line.rstrip("\r\n")
                line = await self.precmd(line)
                stop = await self.onecmd(line)
                stop = self.postcmd(stop, line)
            self.postloop()
        finally:
            if self.use_rawinput and self.completekey:
                try:
                    readline.set_completer(self.old_completer)
                except ImportError:
                    pass

    async def precmd(
        self, line, max_commands_to_print_header=1, command_index_to_print_from=1
    ):
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

                if len(line) > 1 and any(
                    cmd.startswith(line[0]) for cmd in MULTILEVEL_COMMANDS
                ):
                    index = command_index_to_print_from
                else:
                    # If single level command then print from first index. For example: health, features, grep etc.
                    index = 0

                print(
                    "\n~~~ %s%s%s ~~~"
                    % (terminal.bold(), " ".join(line[index:]), terminal.reset())
                )

            sys.stdout.write(terminal.reset())

            try:
                response = await self.ctrl.execute(line)

                if response == "EXIT":
                    return "exit"

                elif response == "ENABLE":
                    self.set_privaliged_prompt()

                elif response == "DISABLE":
                    self.set_default_prompt()

            except Exception as e:
                logger.error(e)
        return ""  # line was handled by execute

    # overloaded to support async
    async def onecmd(self, line):
        result = super().onecmd(line)

        if inspect.iscoroutine(result):
            result = await result

        return result

    def completenames(self, text, line, begidx, endidx):
        origline = line

        if isinstance(origline, str):
            line = origline.split(" ")
            line = [v for v in map(str.strip, line) if v]
            if origline and origline[-1] == " ":
                line.append("")

        if len(line) > 0:
            self.ctrl._init_commands()  # dirty
            cmds = self.ctrl.commands.get_key(line[0])
        else:
            cmds = []

        if len(cmds) == 1:
            cmd = cmds[0]
            if cmd == "help":
                line.pop(0)
            if cmd == "watch":
                line.pop(0)
                try:
                    for _ in (1, 2):
                        int(line[0])
                        line.pop(0)
                except Exception:
                    pass

        names = self.ctrl.complete(line)

        return ["%s " % n for n in names]

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """

        if state <= 0:
            origline = readline.get_line_buffer()
            line = origline.lstrip()
            stripped = len(origline) - len(line)
            begidx = readline.get_begidx() - stripped
            endidx = readline.get_endidx() - stripped
            compfunc = self.completenames
            self.completion_matches = compfunc(text, line, begidx, endidx)

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def emptyline(self):
        # do nothing
        return

    async def close(self):
        try:
            await self.ctrl.close()
        except Exception:
            pass

    # Other
    async def do_exit(self, line):
        await self.close()
        if not self.execute_only_mode and readline.get_current_history_length() > 0:
            readline.write_history_file(self.admin_history)

        return True

    async def do_EOF(self, line):
        return await self.do_exit(line)

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

        s = 0.5
        for line in msg.split("\n"):
            print(line)
            sleep(s)
            s = s / 1.2
        print(terminal.bold() + "Let there be CAKE!".center(80) + terminal.reset())


def do_ctrl_c(*args, **kwargs):
    print("Please press ctrl+d or type exit")


def parse_tls_input(cli_args):
    if cli_args.collectinfo:
        return None

    try:
        keyfile_password = cli_args.tls_keyfile_password

        if (
            cli_args.tls_enable
            and cli_args.tls_keyfile
            and cli_args.tls_keyfile_password == conf.DEFAULTPASSWORD
        ):

            if sys.stdin.isatty():
                keyfile_password = getpass.getpass("Enter TLS-Keyfile Password:")
            else:
                keyfile_password = sys.stdin.readline().strip()

        return SSLContext(
            enable_tls=cli_args.tls_enable,
            encrypt_only=None,
            cafile=cli_args.tls_cafile,
            capath=cli_args.tls_capath,
            keyfile=cli_args.tls_keyfile,
            keyfile_password=keyfile_password,
            certfile=cli_args.tls_certfile,
            protocols=cli_args.tls_protocols,
            cipher_suite=cli_args.tls_cipher_suite,
            cert_blacklist=cli_args.tls_cert_blacklist,
            crl_check=cli_args.tls_crl_check,
            crl_check_all=cli_args.tls_crl_check_all,
        ).ctx

    except Exception as e:
        logger.error("SSLContext creation Exception: " + str(e))
        sys.exit(1)


async def execute_asinfo_commands(
    commands_arg,
    seed,
    user=None,
    password=None,
    auth_mode=AuthMode.INTERNAL,
    ssl_context=None,
    line_separator=False,
):
    cmds = [None]

    if commands_arg:
        asinfo_command_pattern = re.compile(r"""((?:[^;"'\n]|"[^"]*"|'[^']*')+)""")

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
    if not await assock.connect():
        logger.critical("Not able to connect any cluster with " + str(seed) + ".")
        return

    if not await assock.login():
        logger.critical(
            "Not able to login and authenticate any cluster with " + str(seed) + "."
        )
        return

    node_name = "%s:%s" % (seed[0], seed[1])

    for command in cmds:
        if command:
            command = util.strip_string(command)

        result = await assock.info(command)

        if result == -1 or result is None:
            result = IOError("Error: Invalid command '%s'" % command)

        view.CliView.asinfo({node_name: result}, line_separator, False, None)

    return


async def main():
    loop = asyncio.get_event_loop()

    if get_version == "development":
        loop.set_debug(True)
    else:
        # Do nothing in production. It is likely that another error occurred too that will be displayed.
        loop.set_exception_handler(lambda loop, context: None)

    cli_args = conf.get_cli_args()

    admin_version = get_version()

    if cli_args.debug:
        logger.setLevel(logging.DEBUG)

    if cli_args.help:
        conf.print_config_help()
        sys.exit(0)

    if cli_args.version:
        print("Aerospike Administration Shell")
        print("Version " + str(admin_version))
        sys.exit(0)

    if cli_args.no_color:
        disable_coloring()

    if cli_args.pmap:
        CollectinfoController.get_pmap = True

    mode = AdminMode.LIVE_CLUSTER
    if cli_args.collectinfo:
        mode = AdminMode.COLLECTINFO_ANALYZER

    if cli_args.log_analyser:
        if cli_args.collectinfo:
            logger.critical(
                "collectinfo-analyser and log-analyser are mutually exclusive options. Please enable only one."
            )
        mode = AdminMode.LOG_ANALYZER

    if cli_args.json:
        output_json()

    if not os.path.isdir(ADMIN_HOME):
        os.makedirs(ADMIN_HOME)

    execute_only_mode = False

    if cli_args.execute is not None:
        execute_only_mode = True
        logger.execute_only_mode = True

    cli_args, seeds = conf.loadconfig(cli_args)

    if cli_args.services_alumni and cli_args.services_alternate:
        logger.critical(
            "Aerospike does not support alternate address for alumni services. Please enable only one of services_alumni or services_alternate."
        )

    if not cli_args.tls_enable and (
        cli_args.auth == AuthMode.EXTERNAL or cli_args.auth == AuthMode.PKI
    ):
        logger.critical("TLS is required for authentication mode: " + cli_args.auth)

    ssl_context = parse_tls_input(cli_args)

    if cli_args.asinfo_mode:

        if mode == AdminMode.COLLECTINFO_ANALYZER or mode == AdminMode.LOG_ANALYZER:
            logger.critical(
                "asinfo mode cannot work with Collectinfo-analyser or Log-analyser mode."
            )

        commands_arg = cli_args.execute
        if commands_arg and os.path.isfile(commands_arg):
            commands_arg = parse_commands(commands_arg)

        try:
            await execute_asinfo_commands(
                commands_arg,
                seeds[0],
                user=cli_args.user,
                password=cli_args.password,
                auth_mode=cli_args.auth,
                ssl_context=ssl_context,
                line_separator=cli_args.line_separator,
            )
            sys.exit(0)
        except Exception as e:
            logger.error(e)
            sys.exit(1)

    if not execute_only_mode:
        readline.set_completer_delims(" \t\n;")
    shell = await AerospikeShell(
        admin_version,
        seeds,
        user=cli_args.user,
        password=cli_args.password,
        auth_mode=cli_args.auth,
        use_services_alumni=cli_args.services_alumni,
        use_services_alt=cli_args.services_alternate,
        log_path=cli_args.log_path,
        mode=mode,
        ssl_context=ssl_context,
        only_connect_seed=cli_args.single_node,
        execute_only_mode=execute_only_mode,
        privileged_mode=cli_args.enable,
        timeout=cli_args.timeout,
    )  # type: ignore

    use_yappi = False
    if cli_args.profile:
        try:
            use_yappi = True
        except Exception as a:
            print("Unable to load profiler")
            print("Yappi Exception:")
            print(str(a))
            sys.exit(1)

    func = None
    args = ()
    single_command = True
    real_stdout = sys.stdout
    if not execute_only_mode:
        if not shell.connected:
            sys.exit(1)

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

        def cleanup():
            try:
                sys.stdout = real_stdout
                if f:
                    f.close()
            except Exception:
                pass

        if shell.connected:
            line = await shell.precmd(
                commands_arg,
                max_commands_to_print_header=max_commands_to_print_header,
                command_index_to_print_from=command_index_to_print_from,
            )

            await shell.onecmd(line)
            func = shell.onecmd
            args = (line,)

        else:
            if "collectinfo" in commands_arg:
                logger.warning(
                    "Collecting only System data. Not able to connect any cluster with "
                    + str(seeds)
                    + "."
                )

                func = common.collect_sys_info(port=cli_args.port)

                cleanup()
                sys.exit(1)

            cleanup()
            logger.critical("Not able to connect any cluster with " + str(seeds) + ".")

    await cmdloop(shell, func, args, use_yappi, single_command)
    await shell.close()

    try:
        sys.stdout = real_stdout
        if f:
            f.close()
    except Exception:
        pass


def disable_coloring():
    terminal.enable_color(False)


def output_json():
    sheet.set_style_json()


async def cmdloop(shell, func, args, use_yappi, single_command):
    try:
        if use_yappi:
            yappi.start()
            func(*args)
            yappi.get_func_stats().print_all()
        else:
            await func(*args)
    except (KeyboardInterrupt, SystemExit):
        if not single_command:
            shell.intro = (
                terminal.fg_red()
                + "\nTo exit asadm utility please run exit command."
                + terminal.fg_clear()
            )
        await cmdloop(shell, func, args, use_yappi, single_command)


def parse_commands(file):
    commands = ""
    commented = False
    for line in open(file, "r").readlines():
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
    if __version__.startswith("$$"):
        return "development"

    return __version__


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        pass
