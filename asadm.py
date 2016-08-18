#!/usr/bin/env python

# Copyright 2013-2016 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import copy
import glob

import readline
import cmd
import getpass
import shlex
from lib import citrusleaf
from lib.controller import *
from lib.logcontroller import *
from lib import terminal

__version__ = '$$__version__$$'
CMD_FILE_SINGLE_LINE_COMMENT_START = "//"
CMD_FILE_MULTI_LINE_COMMENT_START = "/*"
CMD_FILE_MULTI_LINE_COMMENT_END = "*/"

class AerospikeShell(cmd.Cmd):
    def __init__(self, seed, telnet, user=None, password=None, use_services=False, log_path="", log_analyser=False):

        cmd.Cmd.__init__(self)

        if log_analyser:
            if not log_path:
                log_path = " "
            self.ctrl = LogRootController(seed_nodes=[seed]
                                   , use_telnet=telnet
                                   , user=user
                                   , password=password, log_path=log_path)
        else:
            self.ctrl = RootController(seed_nodes=[seed]
                                   , use_telnet=telnet
                                   , user=user
                                   , password=password, use_services=use_services, asadm_version=__version__)

        try:
            readline.read_history_file(ADMINHIST)
        except Exception:
            readline.write_history_file(ADMINHIST)

        self.prompt = "Admin> "
        if self.use_rawinput:
            self.prompt = "\001" + terminal.bold() + terminal.fg_red() + "\002" +\
                          self.prompt + "\001" +\
                          terminal.unbold() + terminal.fg_clear() + "\002"

        self.name = 'Aerospike Interactive Shell'
        self.intro = terminal.bold() + self.name + ', version ' +\
                     __version__ + terminal.reset() + "\n"

        if log_analyser:
            self.intro += terminal.fg_red() + ">>>>> Working on log files <<<<<<\n" + terminal.fg_clear()
            self.intro += str(self.ctrl.logger) + "\n"
        else:
            if log_path:
                self.intro += terminal.fg_red() + ">>>>> -l not specified -f ignored. Running in normal asadm mode. Use -l for log analyser mode !! <<<<< \n" + terminal.fg_clear()
                log_path = ""
            self.intro += str(self.ctrl.cluster) + "\n"
            cluster_visibility_error_nodes = self.ctrl.cluster.getClusterVisibilityErrorNodes()
            if cluster_visibility_error_nodes:
                self.intro += terminal.fg_red() + "Cluster Visibility error (Please check services list): %s"%(", ".join(cluster_visibility_error_nodes)) + terminal.fg_clear() + "\n"


            if not self.ctrl.cluster.getLiveNodes():
                print self.intro
                print terminal.fg_red() + "Not able to connect any cluster." + terminal.fg_clear()
                self.do_exit('')
                exit(0)
        self.commands = set()

        regex = re.compile("^do_(.*)$")
        commands = map(lambda v: regex.match(v).groups()[0], filter(regex.search, dir(self)))
        for command in commands:
            if command != 'help':
                self.commands.add(command)

    def cleanLine(self, line):
        # get rid of extra whitespace
        lexer = shlex.shlex(line)
        # TODO: shlex is not working with 'with' ip addresses. Need to write a
        #       new parser or correct shlex behavior.
        commands = []

        command = []
        build_token = ''
        lexer.wordchars+=".-:/_"
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

    def precmd(self, line, max_commands_to_print_header=1, command_index_to_print_from=1):
        lines = None
        try:
            lines = self.cleanLine(line)

            if not lines: # allow empty lines
                return ""
        except Exception as e:
            print "%sERR: %s%s"%(terminal.fg_red(), e, terminal.fg_clear())
            return ""

        for line in lines:
            if line[0] in self.commands:
                return " ".join(line)

            if len(lines) > max_commands_to_print_header:
                print "~~~ %s%s%s ~~~"%(terminal.bold()
                                        , ' '.join(line[command_index_to_print_from:])
                                        , terminal.reset())

            sys.stdout.write(terminal.reset())
            try:
                response = self.ctrl.execute(line)
                if response == "EXIT":
                    return "exit"
            except Exception as e:
                print "%sERR: %s%s"%(terminal.fg_red(), e, terminal.fg_clear())
        return "" # line was handled by execute

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
            names = map( lambda v : "\'"+v, self._complete_path(args[-1].split("\'")[-1]))
            return names
        if args[-1].startswith("\""):
            names = map( lambda v : "\""+v, self._complete_path(args[-1].split("\"")[-1]))
            return names
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def completenames(self, text, line, begidx, endidx):
        try:
            origline = line

            if isinstance(origline, str):
                line = origline.split(" ")
                line = filter(lambda v: v, map(str.strip, line))
                if origline and origline[-1] == ' ':
                    line.append('')

            if len(line) > 0:
                self.ctrl._initCommands() # dirty
                cmds = self.ctrl.commands.getKey(line[0])
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
                        for _ in (1,2):
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
                names = self.complete_path(line_copy)+[None]
                return names

        except Exception as e:
            return []
        return map(lambda n: "%s "%n, names)

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        try:
            if state >= 0:
                import readline
                origline = readline.get_line_buffer()
                line = origline.lstrip()
                stripped = len(origline) - len(line)
                begidx = readline.get_begidx() - stripped
                endidx = readline.get_endidx() - stripped
                compfunc = self.completenames
                self.completion_matches = compfunc(text, line, begidx, endidx)
        except Exception as e:
            pass

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def emptyline(self):
        # do nothing
        return

    # Other
    def do_exit(self, line):
        readline.write_history_file(ADMINHIST)
        print "\nConfig files location: " + str(ADMINHOME)
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
            print line
            sleep(s)
            s = s / 1.2
        print terminal.bold() + \
            "Let there be CAKE!".center(80) + \
            terminal.reset()

def do_ctrl_c(*args, **kwargs):
    print "Please press ctrl+d or type exit"

def main():
    try:
        import argparse
        parser = argparse.ArgumentParser(add_help=False, conflict_handler='resolve')
        parser.add_argument("-h"
                            , "--host"
                            , dest="host"
                            , default="127.0.0.1"
                            , help="Address (ip/fqdn) of a host in an " + \
                                   "Aerospike cluster")
        parser.add_argument("-p", "--port"
                            , dest="port"
                            , type=int
                            , default=3000
                            , help="Aerospike service port used by the host.")
        parser.add_argument("-U"
                            , "--user"
                            , dest="user"
                            , help="user name")
        parser.add_argument("-P"
                            , "--password"
                            , dest="password"
                            , nargs="?"
                            , const="prompt"
                            , help="password")
        parser.add_argument("-e"
                            , "--execute"
                            , dest="execute"
                            , help="Execute a single or multiple asadm commands and exit. The input value is either string of ';' separated asadm commands or path of file which has asadm commands (ends with ';')")
        parser.add_argument("-o"
                            , "--out_file"
                            , dest="out_file"
                            , help="Path of file to write output of -e command/s")
        parser.add_argument("--no-color"
                            , dest="no_color"
                            , action="store_true"
                            , help="Disable colored output")
        parser.add_argument("--profile"
                            , dest="profile"
                            , action="store_true"
                            #, help="Profile Aerospike Admin for performance issues"
                            , help=argparse.SUPPRESS)
        parser.add_argument("-u"
                            , "--help"
                            , dest="help"
                            , action="store_true"
                            , help="show program usage")
        parser.add_argument("--version"
                            , dest="show_version"
                            , action="store_true"
                            , help="Show the version of asadm and exit")
        parser.add_argument("-s"
                            , "--services"
                            , dest="use_services"
                            , action="store_true"
                            , help="Enable use of services-list instead of services-alumni-list")
        parser.add_argument("-l"
                            , "--log_analyser"
                            , dest="log_analyser"
                            , action="store_true"
                            , help="Start asadm in log-analyser mode and analyse data from log files")
        parser.add_argument("-f"
                            , "--file-path"
                            , dest="log_path"
                            , help="Path of cluster collectinfo file or directory containing collectinfo files.")

        cli_args = parser.parse_args()
    except Exception:
        import optparse
        usage = "usage: %prog [options]"
        parser = optparse.OptionParser(usage, add_help_option=False)
        parser.add_option("-h"
                            , "--host"
                            , dest="host"
                            , default="127.0.0.1"
                            , help="Address (ip/fqdn) of a host in an " + \
                                   "Aerospike cluster")
        parser.add_option("-p", "--port"
                            , dest="port"
                            , type=int
                            , default=3000
                            , help="Aerospike service port used by the host.")
        parser.add_option("-U"
                            , "--user"
                            , dest="user"
                            , help="user name")
        parser.add_option("-P"
                            , "--password"
                            , dest="password"
                            , action="store_const"
                            #, nargs="?"
                            , const="prompt"
                            , help="password")
        parser.add_option("-e"
                            , "--execute"
                            , dest="execute"
                            , help="Execute a single or multiple asadm commands and exit. The input value is either string of ';' separated asadm commands or path of file which has asadm commands (ends with ';')")
        parser.add_option("-o"
                            , "--out_file"
                            , dest="out_file"
                            , help="Path of file to write output of -e command/s")
        parser.add_option("--no-color"
                            , dest="no_color"
                            , action="store_true"
                            , help="Disable colored output")
        parser.add_option("--profile"
                            , dest="profile"
                            , action="store_true"
                            #, help="Profile Aerospike Admin for performance issues"
                            , help=optparse.SUPPRESS_USAGE)
        parser.add_option("-u"
                            , "--help"
                            , dest="help"
                            , action="store_true"
                            , help="show program usage")
        parser.add_option("--version"
                            , dest="show_version"
                            , action="store_true"
                            , help="Show the version of asadm and exit")
        parser.add_option("-s"
                            , "--services"
                            , dest="use_services"
                            , action="store_true"
                            , help="Enable use of services-list instead of services-alumni-list")
        parser.add_option("-l"
                            , "--log_analyser"
                            , dest="log_analyser"
                            , action="store_true"
                            , help="Start asadm in log-analyser mode and analyse data from log files")
        parser.add_option("-f"
                            , "--file-path"
                            , dest="log_path"
                            , help="Path of cluster collectinfo file or directory containing collectinfo files.")

        (cli_args, args) = parser.parse_args()

    if cli_args.help:
        parser.print_help()
        exit(0)

    if cli_args.show_version:
        print __version__
        exit(0)

    if cli_args.no_color:
        disable_coloring()

    user = None
    password = None
    if cli_args.user != None:
        user = cli_args.user
        if cli_args.password == "prompt":
            cli_args.password = getpass.getpass("Enter Password:")
        password = citrusleaf.hashpassword(cli_args.password)


    global ADMINHOME, ADMINHIST
    ADMINHOME = os.path.expanduser('~') + '/.aerospike/'
    ADMINHIST = ADMINHOME + 'admin_hist'

    if not os.path.isdir(ADMINHOME):
        os.makedirs(ADMINHOME)

    seed = (cli_args.host, cli_args.port)
    telnet = False # telnet currently not working, hardcoding to off

    use_services = False
    if cli_args.use_services:
        use_services = True

    log_path = ""
    log_analyser = False;
    if cli_args.log_analyser:
        log_analyser = True
    if cli_args.log_path:
        log_path = cli_args.log_path
        if log_analyser:
            if os.path.isdir(log_path):
                os.chdir(log_path)
            elif os.path.isfile(log_path):
                os.chdir(os.path.dirname(log_path))


    readline.set_completer_delims(' \t\n;')
    shell = AerospikeShell(seed, telnet, user=user, password=password, use_services=use_services, log_path=log_path, log_analyser=log_analyser)

    use_yappi = False
    if cli_args.profile:
        try:
            import yappi
            use_yappi = True

        except Exception as a:
            print "Unable to load profiler"
            print "Yappi Exception:"
            print str(a)
            exit(1)

    func = None
    args = ()
    single_command = True
    real_stdout = sys.stdout
    if not cli_args.execute:
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
                print e
        line = shell.precmd(commands_arg, max_commands_to_print_header=max_commands_to_print_header, command_index_to_print_from=command_index_to_print_from)
        shell.onecmd(line)
        func = shell.onecmd
        args = (line,)

    cmdloop(shell, func, args, use_yappi, single_command)
    try:
        sys.stdout = real_stdout
        if f:
            f.close()
    except Exception:
        pass

def disable_coloring():
    from lib import terminal
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
            shell.intro = terminal.fg_red() + "\nTo exit asadm utility please run exit command" + terminal.fg_clear()
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

if __name__ == '__main__':
    main()
