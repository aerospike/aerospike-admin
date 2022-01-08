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

from lib.health.health_checker import HealthChecker
from lib.utils import util
from lib.utils.lookup_dict import PrefixDict
from lib.view import view, terminal

DEFAULT = "_do_default"

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


class CommandHelp:

    """
    hide - If True then the help info of command and its children will not be
           displayed unless it is explicitly called on the command.

    If no help info is defined but succeeding help should still be shown you
    must define CommandHelp with an empty message i.e. ''
    """

    def __init__(self, *message, hide=False):
        self.message = list(message)
        self.hide = hide

    def __call__(self, func):
        try:
            if func.__name__ == DEFAULT:
                self.message[0] = "%sDefault%s: %s" % (
                    terminal.underline(),
                    terminal.reset(),
                    self.message[0],
                )
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
            if func._command_help == [""]:
                return

            print("\n".join([indent + line for line in func._command_help]))
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
        except Exception:
            return False


class CommandName:
    def __init__(self, name):
        self._assigned_name = name

    def __call__(self, func):
        func._assigned_name = self._assigned_name
        return func

    @staticmethod
    def name(func):
        return func._assigned_name

    @staticmethod
    def has_name(func):
        try:
            if func._assigned_name:
                return True
            return False
        except Exception:
            return False


class DisableAutoComplete:
    """Decorator to disable tab completion and auto completion. e.g. if ShowController
    was decoracted it would not allow 'sho' **enter** to resolve to 'show'.
    """

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
        except Exception:
            # Default to enable auto complete to not require decorator
            return True


def create_disabled_controller(controller, command_):
    """Required to keep control logic in the controllers and out of asadm.py.  This
    also allows us to keep the controller from being executed while still displaying
    help info.
    """

    class DisableController(controller):

        # override
        async def execute(self, line):
            self.logger.error(
                'User must be in privileged mode to issue "{}" commands.\n'
                '       Type "enable" to enter privileged mode.'.format(command_)
            )

    return DisableController


class ShellException(Exception):
    def __call__(self, *ignore):
        # act as a callable and raise self
        raise self


class BaseController(object):
    view = None
    health_checker = None
    asadm_version = ""
    logger = None

    # Here so each command controller does not need to define them
    modifiers = set()
    required_modifiers = set()
    mods = {}
    context = None

    """
        For when a parent controller takes an argument that needs parsing
        before sending argument to child controllers
    """
    controller_arg = None

    def __init__(self, asadm_version=""):
        # Create static instances of view / health_checker / asadm_version /
        # logger
        BaseController.view = view.CliView()
        BaseController.health_checker = HealthChecker()
        BaseController.asadm_version = asadm_version
        BaseController.logger = logging.getLogger("asadm")

    def _init_commands(self):
        command_re = re.compile("^(do_(.*))$")
        commands = [
            command_re.match(v).groups() for v in filter(command_re.search, dir(self))
        ]

        self.commands = PrefixDict()

        for command in commands:
            func = getattr(self, command[0])
            if CommandName.has_name(func):
                self.commands.add(CommandName.name(func), func)
            else:
                self.commands.add(command[1], func)

        for command, controller in self.controller_map.items():
            if self.context:
                context_cpy = list(self.context) + [command]
            else:
                context_cpy = [command]

            try:
                controller = controller()
                controller.context = context_cpy
            except Exception as e:
                print(e)

            self.commands.add(command, controller)

    def complete(self, line):
        self._init()
        command = line.pop(0) if line else ""
        commands = self.commands.get_key(command)

        logger.debug("Auto-complete: command {}".format(command))

        if not DisableAutoComplete.has_auto_complete(self.commands[commands[0]][0]):
            return []

        if command != commands[0] and len(line) == 0:
            # if user has full command name and is hitting tab,
            # the user probably wants the next level
            logger.debug("Auto-complete: results {}".format(commands))
            return sorted(commands)

        try:
            logger.debug(
                "Auto-complete: going to next controller {}".format(commands[0])
            )
            return self.commands.get(commands[0])[0].complete(line)
        except Exception as e:
            logger.debug(
                "Auto-complete: command is ambiguous or exact match {}, error: {}".format(
                    commands[0], e
                )
            )

            # TODO: Make modifiers auto-completable?
            # if self.required_modifiers | self.modifiers:
            #     return list(self.required_modifiers | self.modifiers)

            # The line contains an ambiguous entry
            # or exact match
            return []

    async def __call__(self, line):
        return await self.execute(line)

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
            logger.debug("Looking for {} in command_map".format(command))
            method = self.commands[command]
            logger.debug("Found method {} in command_map".format(method))

            if len(method) > 1:
                # handle ambiguos commands
                commands = sorted(self.commands.get_key(command))
                commands[-1] = "or %s" % (commands[-1])
                if len(commands) > 2:
                    commands = ", ".join(commands)
                else:
                    commands = " ".join(commands)
                raise ShellException(
                    "Ambiguous command: '%s' may be %s." % (command, commands)
                )
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
            if inspect.isfunction(result):
                rv.append(result())
            elif isinstance(result, list) or isinstance(result, tuple):
                rv.append(self._run_results(result))
            else:
                rv.append(result)
        return rv

    async def execute(self, line):
        # Init all command controller objects
        self._init()

        if self.controller_arg is not None:
            self.pre_controller(line)

        method = self._find_method(line)

        if method:
            try:
                if inspect.ismethod(method):
                    self.pre_command(line[:])

                results = method(line)

                if inspect.iscoroutine(results):
                    results = await results

                if not isinstance(results, list) and not isinstance(results, tuple):
                    """
                    returning view functions wrapped in coroutines to display allows
                    multiple do_* func to run concurrently but display deterministicely.
                    """
                    if inspect.isfunction(results):
                        results = (results,)
                    else:
                        return results

                # results is a tuple or list of coroutines
                return self._run_results(results)

            except IOError as e:
                raise ShellException(str(e))
        else:
            raise ShellException("Method was not set? %s" % (line))

    def execute_help(self, line, indent=0, method=None, print_modifiers=True):
        self._init()

        # Removes the need to call _find_method twice since it also happens
        # in parent call.
        if method is None:
            method = self._find_method(line)

        if method:
            try:
                try:
                    method_name = method.__name__
                except Exception:
                    method_name = None

                if method_name == DEFAULT:  # Print controller help
                    CommandHelp.display(self, indent=indent)

                    if print_modifiers:
                        required_mods = [
                            mod for mod in self.required_modifiers if mod != "line"
                        ]
                        if required_mods:
                            CommandHelp.print_text(
                                "%sRequired%s: %s"
                                % (
                                    terminal.underline(),
                                    terminal.reset(),
                                    ", ".join(sorted(required_mods)),
                                ),
                                indent=indent,
                            )
                        if self.modifiers:
                            CommandHelp.print_text(
                                "%sModifiers%s: %s"
                                % (
                                    terminal.underline(),
                                    terminal.reset(),
                                    ", ".join(sorted(self.modifiers)),
                                ),
                                indent=indent,
                            )

                    if CommandHelp.has_help(method):
                        CommandHelp.display(method, indent=indent)

                    indent += 2
                    for command in self.commands.keys():
                        command_method = self._find_method([command])

                        if CommandHelp.has_help(
                            command_method
                        ) and not CommandHelp.is_hidden(command_method):
                            arg = ""

                            if (
                                inspect.isclass(command_method)
                                and command_method.controller_arg is not None
                            ):
                                arg = " <{}>".format(command_method.controller_arg)

                            CommandHelp.print_text(
                                "- %s%s%s%s:"
                                % (terminal.bold(), command, arg, terminal.reset()),
                                indent=indent - 1,
                            )

                            self.execute_help(
                                [command], indent=indent, method=command_method
                            )
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
            raise ShellException("Method was not set? %s" % (line))

    async def _do_default(self, line):
        # Override method to provide default command behavior
        raise ShellException("%s: command not found." % (" ".join(line)))

    # Hook to be defined by subclasses
    def pre_command(self, line):
        pass

    def pre_controller(self, line):
        pass


class CommandController(BaseController):
    def parse_modifiers(self, line, duplicates_in_line_allowed=False):
        mods = self.modifiers | self.required_modifiers
        groups = {}

        for mod in mods:
            if mod in mods:
                groups[mod] = []

        mod = "line"
        groups[mod] = []

        while line:
            word = line.pop(0)

            # Remove ',' from input since it needs to be filtered
            # out in many cases.
            if word == ",":
                continue

            if word in mods:
                mod = word
                # Special case for handling diff modifier of show config
                if mod == "diff":
                    groups[mod].append(True)

            else:
                if duplicates_in_line_allowed or word not in groups[mod]:
                    groups[mod].append(word)

        if "with" in mods and "all" in groups["with"]:
            groups["with"] = "all"

        return groups

    def _check_required_modifiers(self, line):
        for mod in self.required_modifiers:
            if not self.mods[mod]:
                self.execute_help(line)
                if mod == "line":
                    raise IOError("Missing required argument")

                raise IOError("{} is required".format(mod))

    def pre_command(self, line):
        mods = self.modifiers | self.required_modifiers
        try:
            if self.nodes:
                return
        except Exception:
            self.mods.update(self.parse_modifiers(line))
            self._check_required_modifiers(line)

            if not mods:
                self.nodes = "all"
                return

            try:
                if "with" in mods:
                    if len(self.mods["with"]) > 0:
                        self.nodes = self.mods["with"]
                    else:
                        self.nodes = self.default_nodes
                else:
                    self.nodes = self.default_nodes
            except Exception:
                self.nodes = "all"  # default not set use all

    def pre_controller(self, line):
        if self.controller_arg is None:
            return

        mod = self.context[-1]

        if mod not in self.mods:
            self.mods[mod] = {}

        # Used as the key to reference arg, normally the controllers "command".
        try:
            arg = line.pop(0)
        except IndexError:
            raise IOError("{} is required".format(mod))

        if arg not in self.modifiers | self.required_modifiers:

            if mod not in self.mods[mod]:
                self.mods[mod] = []

            self.mods[mod].append(arg)

            return

        raise IOError("{} is required".format(mod))
