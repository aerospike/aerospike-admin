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

import inspect
import re
import logging

from lib.health.healthchecker import HealthChecker
from lib.utils import util
from lib.utils.lookupdict import PrefixDict
from lib.view import view, terminal

DEFAULT = "_do_default"


class CommandHelp(object):

    '''
    hide - If True then the help info of command and its children will not be
           displayed unless it is explicitly called on the command.

    If no help info is defined but succeeding help should still be shown you 
    must define CommandHelp with an empty message i.e. ''
    '''
    def __init__(self, *message, hide=False):
        self.message = list(message)
        self.hide = hide

    def __call__(self, func):
        try:
            if func.__name__ == DEFAULT:
                self.message[0] = "%sDefault%s: %s" % (
                    terminal.underline(), terminal.reset(), self.message[0])
        except Exception:
            pass

        func._command_help = self.message
        func._hide = self.hide

        return func

    @staticmethod
    def has_help(func):
        try:
            func._command_help
            return True
        except Exception:
            return False

    @staticmethod
    def display(func, indent=0):
        indent = "  " * indent
        try:
            if func._command_help == ['']:
                return

            print("\n".join([indent + l for l in func._command_help]))
        except Exception:
            pass

    @staticmethod
    def print_text(message, indent=0):
        indent = "  " * indent
        print("%s%s" % (indent, message))

    @staticmethod
    def is_hidden(func):
        try:
            return func._hide
        except:
            return False


class DisableAutoComplete():
    '''Decorator to disable tab completion and auto completion. e.g. if ShowController
    was decoracted it would not allow 'sho' **enter** to resolve to 'show'.
    '''
    def __init__(self, disable=True):
        self.disable_auto_complete = disable

    def __call__(self, func):
        func.disable_auto_complete = self.disable_auto_complete
        return func

    @staticmethod
    def has_auto_complete(func):
        try:
            if func.disable_auto_complete:
                return False
            return True
        except:
            # Default to enable auto complete to not require decorator
            return True

class ShellException(Exception):

    def __call__(self, *ignore):
        # act as a callable and raise self
        raise self


class BaseController(object):
    view = None
    health_checker = None
    asadm_version = ''
    logger = None

    # Here so each command controller does not need to define them
    modifiers = set()
    required_modifiers = set()

    def __init__(self, asadm_version=''):
        # Create static instances of view / health_checker / asadm_version /
        # logger
        BaseController.view = view.CliView()
        BaseController.health_checker = HealthChecker()
        BaseController.asadm_version = asadm_version
        BaseController.logger = logging.getLogger("asadm")


    def _init_commands(self):
        command_re = re.compile("^(do_(.*))$")
        commands = [command_re.match(v).groups() for v in filter(command_re.search, dir(self))]

        self.commands = PrefixDict()

        for command in commands:
            self.commands.add(command[1], getattr(self, command[0]))

        for command, controller in self.controller_map.items():
            try:
                controller = controller()
            except Exception:
                pass

            self.commands.add(command, controller)

    def complete(self, line):
        self._init()

        command = line.pop(0) if line else ''

        commands = self.commands.get_key(command)

        try:
            if not DisableAutoComplete.has_auto_complete(self.commands[commands[0]][0]):
                return []
        except:
            import traceback
            traceback.print_exc()

        if command != commands[0] and len(line) == 0:
            # if user has full command name and is hitting tab,
            # the user probably wants the next level
            return sorted(commands)

        try:
            return self.controller_map[commands[0]]().complete(line)
        except Exception:
            # The line contains an ambiguous entry
            # or exact match
            return []

    def __call__(self, line):
        return self.execute(line)

    def _init_controller_map(self):
        try:  # define controller map if not defined
            if self.controller_map:
                pass
        except Exception:
            self.controller_map = {}

    def _init(self):
        self._init_controller_map()
        self._init_commands()

    def _find_method(self, line):
        method = None
        command = None

        try:
            command = line.pop(0)
        except IndexError:
            # Popped last element use default
            method = getattr(self, DEFAULT)

        if method is not None:
            return method

        try:
            method = self.commands[command]

            if len(method) > 1:
                # handle ambiguos commands
                commands = sorted(self.commands.get_key(command))
                commands[-1] = "or %s" % (commands[-1])
                if len(commands) > 2:
                    commands = ', '.join(commands)
                else:
                    commands = ' '.join(commands)
                raise ShellException(
                    "Ambiguous command: '%s' may be %s." % (command, commands))
            else:
                method = method[0]
                
                # If auto complete is diabled check to see if command entered
                # is prefix or entire command.
                if not DisableAutoComplete.has_auto_complete(method):
                    is_full_cmd = command in self.commands.keys()

                    if not is_full_cmd:
                        return getattr(self, DEFAULT)

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
        # Init all command controller objects
        self._init()
        method = self._find_method(line)

        if method:
            try:
                if inspect.ismethod(method):
                    self.pre_command(line[:])

                results = method(line)

                if (not isinstance(results, list)
                        and not isinstance(results, tuple)):

                    if isinstance(results, util.Future):
                        results = (results,)
                    else:
                        return results

                return self._run_results(results)

            except IOError as e:
                raise ShellException(str(e))
        else:
            raise ShellException("Method was not set? %s" % (line))

    def execute_help(self, line, indent=0, method=None):
        self._init()

        # Removes the need to call _find_method twice since it also happens
        # in parent call.
        if method == None:
            method = self._find_method(line)

        if method:
            try:
                try:
                    method_name = method.__name__
                except Exception:
                    method_name = None

                if method_name == DEFAULT:  # Print controller help
                    CommandHelp.display(self, indent=indent)
                    required_mods = list(filter(lambda mod: mod != 'line', self.required_modifiers))
                    if required_mods:
                        CommandHelp.print_text(
                            "%sRequired%s: %s" % (terminal.underline(),
                                                    terminal.reset(), ", ".join(
                                sorted(required_mods))), indent=indent)
                    if self.modifiers:
                        CommandHelp.print_text(
                            "%sModifiers%s: %s" % (terminal.underline(),
                                                    terminal.reset(), ", ".join(
                                sorted(self.modifiers))), indent=indent)

                    if CommandHelp.has_help(method):
                        CommandHelp.display(method, indent=indent)

                    indent += 2
                    for command in self.commands.keys():
                        command_method = self._find_method([command])

                        if CommandHelp.has_help(command_method) and not CommandHelp.is_hidden(command_method):
                            CommandHelp.print_text(
                                "- %s%s%s:" % (terminal.bold(), command,
                                            terminal.reset()), indent=indent - 1)

                            self.execute_help([command], indent=indent, method=command_method)
                    return

                elif isinstance(method, ShellException):
                    # Method not implemented
                    pass

                elif method_name is None:  # Nothing to print yet
                    method.execute_help(line, indent=indent)

                else:  # Print help for a command
                    CommandHelp.display(method, indent=indent)
                    return

            except IOError as e:
                raise ShellException(str(e))
        else:
            raise ShellException(
                "Method was not set? %s" % (line))

    def _do_default(self, line):
        # Override method to provide default command behavior
        raise ShellException("%s: command not found." % (" ".join(line)))

    # Hook to be defined by subclasses
    def pre_command(self, line):
        pass


class CommandController(BaseController):

    def parse_modifiers(self, line, duplicates_in_line_allowed=False):
        mods = self.modifiers | self.required_modifiers

        groups = {}

        for mod in mods:
            if mod in mods:
                groups[mod] = []

        mod = 'line'
        groups[mod] = []

        while line:
            word = line.pop(0)

            # Remove ',' from input since it can cause it needs to be filtered
            # out in many cases.
            if word == ',':
                continue

            if word in mods:
                mod = word
                # Special case for handling diff modifier of show config
                if mod == 'diff':
                    groups[mod].append(True)

            else:
                if duplicates_in_line_allowed or word not in groups[mod]:
                    groups[mod].append(word)

        if 'with' in mods and 'all' in groups['with']:
            groups['with'] = 'all'

        for mod in self.required_modifiers:
            if not len(groups[mod]):
                self.execute_help(line)
                if mod == 'line':
                    raise IOError('Missing required argument'.format(mod))

                raise IOError('{} is required'.format(mod))

        return groups

    def pre_command(self, line):
        try:
            if self.nodes:
                return
        except Exception:
            self.mods = self.parse_modifiers(line)
            if not self.modifiers:
                self.nodes = 'all'
                return

            try:
                if 'with' in self.modifiers:
                    if len(self.mods['with']) > 0:
                        self.nodes = self.mods['with']
                    else:
                        self.nodes = self.default_nodes
                else:
                    self.nodes = self.default_nodes
            except Exception:
                self.nodes = 'all'  # default not set use all

class BasicCommandController(CommandController):
    cluster = None

    def __init__(self, cluster):
        BasicCommandController.cluster = cluster


def create_disabled_controller(controller, command_):
    '''Required to keep control logic in the controllers and out of asadm.py.  This
    also allows us to keep the controller from being executed while still displaying
    help info.
    '''

    class DisableController(controller):

        # override
        def execute(self, line):
            self.logger.error('User must be in privileged mode to issue "{}" commands.\n' \
                        '       Type "enable" to enter privileged mode.'.format(command_))

    return DisableController