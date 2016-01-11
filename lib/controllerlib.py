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

from lib import view, terminal
from lib.cluster import Cluster
from lib.prefixdict import PrefixDict
from lib import util
import inspect
import re

DEFAULT = "_do_default"

class CommandHelp(object):
    def __init__(self, *message):
        self.message = list(message)

    def __call__(self, func):
        try:
            if func.__name__ == DEFAULT:
                self.message[0] = "%sDefault%s: %s"%(terminal.underline()
                                                     , terminal.reset()
                                                     , self.message[0])
        except:
            pass

        func._command_help = self.message

        return func

    @staticmethod
    def hasHelp(func):
        try:
            _ = func._command_help
            return True
        except Exception as e:
            return False

    @staticmethod
    def display(func, indent = 0):
        indent = "  " * indent
        try:
            print "\n".join(map(lambda l: indent+l, func._command_help))
        except:
            pass

    @staticmethod
    def printText(message, indent = 0):
        indent = "  " * indent
        print "%s%s"%(indent, message)
            

class ShellException(Exception):
    def __call__(self, *ignore):
        # act as a callable and raise self
        raise self

class BaseController(object):
    view = None
    cluster = None

    def __init__(self, seed_nodes=[('127.0.0.1',3000)]
                 , use_telnet=False, user=None, password=None, use_services=False):

        cls = BaseController
        cls.view = view.CliView()
        cls.cluster = Cluster(seed_nodes, use_telnet, user, password, use_services)

        # instance vars
        self.modifiers = set()

    def _initCommands(self):
        command_re = re.compile("^(do_(.*))$")
        commands = map(lambda v:
                       command_re.match(v).groups()
                       , filter(command_re.search, dir(self)))
        self.commands = PrefixDict()

        for command in commands:
            self.commands.add(command[1], getattr(self, command[0]))

        for command, controller in self.controller_map.items():
            try:
                controller = controller()
            except:
                pass

            self.commands.add(command, controller)

    def complete(self, line):
        self._init()

        command = line.pop(0) if line else ''

        commands = self.commands.getKey(command)

        if command != commands[0] and len(line) == 0:
            # if user has full command name and is hitting tab,
            # the user probably wants the next level
            return sorted(commands)

        try:
            return self.controller_map[commands[0]]().complete(line)
        except:
            # The line contains an ambiguous entry
            # or exact match
            return []

    def __call__(self, line):
        return self.execute(line)

    def _initControllerMap(self):
        try: # define controller map if not defined
            if self.controller_map:
                pass
        except:
            self.controller_map = {}

    def _init(self):
        self._initControllerMap()
        self._initCommands()

    def _findMethod(self, line):
        method = None
        try:
            command = line.pop(0)
        except IndexError:
            # Popped last element use default
            method = getattr(self, DEFAULT)

        if method is None:
            try:
                method = self.commands[command]
                if len(method) > 1:
                    # handle ambiguos commands
                    commands = sorted(self.commands.getKey(command))
                    commands[-1] = "or %s"%(commands[-1])
                    if len(commands) > 2:
                        commands = ', '.join(commands)
                    else:
                        commands = ' '.join(commands)
                    raise ShellException(
                        "Ambiguous command: '%s' may be %s."%(command
                                                              , commands))
                else:
                    method = method[0]
            except KeyError:
                line.insert(0, command)

                # Maybe the controller understands the command from here
                # Have to forward it to the controller since some commands
                # may have strange options like asinfo
                method = getattr(self, DEFAULT)

        return method

    def _run_results(self, results):
        rv = []
        for result in results:
            if isinstance(result, util.Future):
                result.start()
                rv.append(result.result())
            elif isinstance(result, list) or isinstance(result, tuple):
                rv.append(self._run_results(result))
            else:
                rv.append(result)
        return rv

    def execute(self, line):
        self._init()

        method = self._findMethod(line)

        if method:
            try:
                if inspect.ismethod(method):
                    self.preCommand(line[:])
                results = method(line)
                if not isinstance(results, list) and not isinstance(results, tuple):
                    if isinstance(results, util.Future):
                        results = (results,)
                    else:
                        return results

                return self._run_results(results)

            except IOError as e:
                raise ShellException(str(e))
        else:
            raise ShellException(
                "Method was not set? %s"%(line))

    def executeHelp(self, line, indent=0):
        self._init()

        method = self._findMethod(line)
        if method:
            try:
                try:
                    method_name = method.__name__
                except:
                    #method_name = method.__class__.__name__
                    method_name = None

                if method_name == DEFAULT: # Print controller help
                    CommandHelp.display(self, indent=indent)
                    if self.modifiers:
                        CommandHelp.printText(
                            "%sModifiers%s: %s"%(terminal.underline()
                                                 , terminal.reset()
                                                 , ", ".join(
                                                     sorted(self.modifiers)))
                            , indent=indent)
                    if CommandHelp.hasHelp(method):
                        CommandHelp.display(method, indent=indent)

                    indent += 2
                    for command in sorted(self.commands.keys()):
                        CommandHelp.printText("- %s%s%s:"%(terminal.bold()
                                                           , command
                                                           , terminal.reset())
                                              , indent=indent-1)
                        self.executeHelp([command], indent=indent)
                    return
                elif isinstance(method, ShellException):
                    # Method not implemented
                    pass
                elif method_name is None: # Nothing to print yet
                    method.executeHelp(line, indent=indent)
                else: # Print help for a command
                    CommandHelp.display(method, indent=indent)
                    return
            except IOError as e: 
                raise ShellException(str(e))
        else:
            raise ShellException(
                "Method was not set? %s"%(line))

    def _do_default(self, line):
        # Override method to provide default command behavior
        raise ShellException("Do not understand '%s'"%(" ".join(line)))

    def preCommand(self, line):
        pass # Hook to be defined by subclasses

class CommandController(BaseController):
    def __init__(self):
        # Root controller configs class vars
        self.modifiers = set()

    def parseModifiers(self, line):
        mods = self.modifiers

        groups = {}

        for mod in mods:
            if mod in mods:
                groups[mod] = []

        mod = 'line'
        groups[mod] = []

        while line:
            word = line.pop(0)
            if word in self.modifiers:
                mod = word
                if mod == 'diff':      # Special case for handling diff modifier of show config
                    groups[mod].append(True)
            else:
                if word not in groups[mod]:
                    groups[mod].append(word)

        if 'with' in mods and 'all' in groups['with']:
            groups['with'] = 'all'

        return groups

    def preCommand(self, line):
        try:
            if self.nodes:
                return
        except:
            self.mods = self.parseModifiers(line)

            if not self.modifiers:
                return

            try:
                if 'with' in self.modifiers:
                    if len(self.mods['with']) > 0:
                        self.nodes = self.mods['with']
                    else:
                        self.nodes = self.default_nodes
                else:
                    self.nodes = self.default_nodes
            except:
                self.nodes = 'all' # default not set use all

