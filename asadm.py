#!/usr/bin/env python

# Copyright 2013-2014 Aerospike, Inc.
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

import readline
import cmd
import sys
import os
import re
import optparse
import getpass
import shlex
from lib import citrusleaf
from lib.controller import *
from lib.logcontroller import *
from lib import terminal

__version__ = '$$__version__$$'

class AerospikeShell(cmd.Cmd):
    def __init__(self, seed, telnet, user=None, password=None, log_path="", log_analyser=False):
        cmd.Cmd.__init__(self)

        if log_path and log_analyser:
            self.ctrl = LogRootController(seed_nodes=[seed]
                                   , use_telnet=telnet
                                   , user=user
                                   , password=password, log_path=log_path)
        else:
            self.ctrl = RootController(seed_nodes=[seed]
                                   , use_telnet=telnet
                                   , user=user
                                   , password=password)

        try:
            readline.read_history_file(ADMINHIST)
        except Exception, i:
            readline.write_history_file(ADMINHIST)

        self.prompt = "Admin> "
        if self.use_rawinput:
            self.prompt = "\001" + terminal.bold() + terminal.fg_red() + "\002" +\
                          self.prompt + "\001" +\
                          terminal.unbold() + terminal.fg_clear() + "\002"

        self.name = 'Aerospike Interactive Shell'
        self.intro = terminal.bold() + self.name + ', version ' +\
                     __version__ + terminal.reset() + "\n"

        if not log_analyser:
            log_path = ""
            self.intro += terminal.fg_red() + ">>>>> -f not specified -l ignored. Running in normal asadm mode. Use -f for log analyser mode !! <<<<< \n" + terminal.fg_clear()

        if log_path:
            self.intro += terminal.fg_red() + ">>>>> Working on log files <<<<<<\n" + terminal.fg_clear()
            self.intro += str(self.ctrl.logger) + "\n"
        else:
            self.intro += str(self.ctrl.cluster) + "\n"
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

    def precmd(self, line):
        try:
            lines = self.cleanLine(line)
        except:
            return ""

        if not lines: # allow empty lines
            return ""

        for line in lines:
            if line[0] in self.commands:
                return " ".join(line)

            if len(lines) > 1:
                print "~~~ %s%s%s ~~~"%(terminal.bold()
                                        , ' '.join(line[1:])
                                        , terminal.reset())

            sys.stdout.write(terminal.reset())
            try:
                response = self.ctrl.execute(line)
                if response == "EXIT":
                    return "exit"
            except ShellException as e:
                print "%sERR: %s%s"%(terminal.fg_red(), e, terminal.fg_clear())
        return "" # line was handled by execute

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
                    except:
                        pass

            names = self.ctrl.complete(line)
            if watch:
                try:
                    names.remove('watch')
                except:
                    pass

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
        # do onthing
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
                        # , nargs="?"
                        , const="prompt"
                        , help="password")
    parser.add_option("-e"
                        , "--execute"
                        , dest="execute"
                        , help="Execute a single asadmin command and exit")
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
    parser.add_option("-f"
                        , "--file"
                        , dest="log_analyser"
                        , action="store_true"
                        , help="Fetch data from log files")
    parser.add_option("-l"
                        , "--log-path"
                        , dest="log_path"
                        , help="Path of ascollectinfo log files.")



    (cli_args, args) = parser.parse_args()
    if cli_args.help:
        parser.print_help()
        exit(0)

    if cli_args.show_version:
        print __version__
        exit(0)

    if cli_args.no_color:
        from lib import terminal
        terminal.enable_color(False)

    user = None
    password = None
    if cli_args.user != None:
        user = cli_args.user
        if cli_args.password == "prompt":
            cli_args.password = getpass.getpass("Enter Password:")
        password = citrusleaf.hashpassword(cli_args.password)

    global ADMINHOME, ADMINHIST
    ADMINHOME = os.environ['HOME'] + '/.aerospike/'
    ADMINHIST = ADMINHOME + 'admin_hist'

    if not os.path.isdir(ADMINHOME):
        os.makedirs(ADMINHOME)

    seed = (cli_args.host, cli_args.port)
    telnet = False # telnet currently not working, hardcoding to off
    log_path = " "
    if cli_args.log_path:
        log_path = cli_args.log_path
        os.chdir(log_path)

    log_analyser = False;
    if cli_args.log_analyser:
        log_analyser = True

    shell = AerospikeShell(seed, telnet, user=user, password=password, log_path=log_path, log_analyser=log_analyser)

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
    if not cli_args.execute:
        func = shell.cmdloop
    else:
        line = shell.precmd(cli_args.execute)
        shell.onecmd(line)
        func = shell.onecmd
        args = (line,)

    try:
        if use_yappi:
            yappi.start()
            func(*args)
            yappi.get_func_stats().print_all()
        else:
            func(*args)
    except (KeyboardInterrupt, SystemExit):
        shell.do_exit('')
        exit(0)

if __name__ == '__main__':
    main()
