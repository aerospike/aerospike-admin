# Copyright 2013-2023 Aerospike, Inc.
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

from __future__ import annotations

import inspect
import re
import logging
import string
from typing import Any, Callable, Union

from lib.health.health_checker import HealthChecker
from lib.utils.lookup_dict import PrefixDict
from lib.view import view, terminal

DEFAULT = "_do_default"

logger = logging.getLogger(__name__)
logger.setLevel(logging.CRITICAL)


class ModifierHelp:
    def __init__(self, name: str, msg: str, default: str | None = None):
        self.name = name
        self.msg = msg
        self.default = default


class CommandHelp:
    _MAX_SHORT_MSG = 120
    _MAX_LONG_MSG_LEN = 100
    DEFAULT_USAGE = "COMMAND"

    """
    hide - If True then the help info of command and its children will not be
           displayed unless it is explicitly called on the command.
    """

    def __init__(
        self,
        *long_msg: str,
        short_msg: str | None = None,
        usage=None,
        hide=False,
        modifiers: tuple[ModifierHelp, ...] | None = None,
    ):
        self._usage = usage
        self._short_msg = short_msg
        self._hide = hide
        self._modifiers = modifiers

        long_msg_str = " ".join(list(long_msg))

        if not long_msg_str.endswith("."):
            long_msg_str = long_msg_str + "."

        self._long_msg = self.split_str_by_space(long_msg_str, self._MAX_LONG_MSG_LEN)

        # Add period to end of long_msg
        if not self._short_msg:
            self._short_msg = " ".join(long_msg)

            if len(self._short_msg) > self._MAX_SHORT_MSG:
                logger.fatal(
                    f"long_msg should be no longer than {self._MAX_SHORT_MSG} when no short_msg is supplied",
                    stack_info=True,
                )

        # Remove period from end of short_msg
        if self._short_msg and self._short_msg.endswith("."):
            self._short_msg = self._short_msg[:-1]

        if short_msg and len(short_msg) > self._MAX_SHORT_MSG:
            logger.fatal(
                f"short_msg should be no longer than {self._MAX_SHORT_MSG}",
                stack_info=True,
            )

    def __call__(self, func):
        func._long_msg = self._long_msg
        func._hide = self._hide
        func._short_msg = self._short_msg
        func._usage = self._usage
        func._modifiers = self._modifiers

        return func

    @staticmethod
    def split_str_by_space(string: str, length: int) -> list[str]:
        result = []
        line_start = 0
        last_space = 0

        for char_idx, char in enumerate(string):
            if char_idx - line_start > length and line_start - 1 != last_space:
                result.append(string[line_start:last_space])
                line_start = last_space + 1

            if char == " ":
                last_space = char_idx

        result.append(string[line_start:])
        return result

    @staticmethod
    def has_help(func):
        try:
            func._long_msg
            return True
        except Exception:
            return False

    @staticmethod
    def display_long(func):
        try:
            print("\n".join([line for line in CommandHelp.long_message(func)]))
        except Exception:
            pass

    @staticmethod
    def display_modifiers(func, indent=0):
        indent = "  " * indent
        try:
            if func._modifiers:
                max_length = max(len(mod.name) for mod in func._modifiers) + 5
                CommandHelp.print_text("")
                for mod in func._modifiers:
                    ljust = mod.name.ljust(max_length)
                    msg = CommandHelp.split_str_by_space(mod.msg, 50)
                    print(f"{indent}{ljust}- {msg[0]}")

                    for m in msg[1:]:
                        print(f"{indent}  {' ' * max_length}{m}")

                    if mod.default:
                        print(f"{indent}  {' ' * max_length}Default: {mod.default}")

        except Exception:
            pass

    @staticmethod
    def long_message(func):
        try:
            return func._long_msg
        except Exception:
            return ""

    @staticmethod
    def short_message(func):
        try:
            return func._short_msg
        except Exception:
            return ""

    @staticmethod
    def usage(func):
        try:
            if not func._usage:
                return ""

            return func._usage
        except Exception:
            return ""

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


# TODO: CommandName should be used for context, not do_*
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
    # Create static instances of view / health_checker / asadm_version / logger
    view = view.CliView()
    health_checker = HealthChecker()
    logger = logging.getLogger("asadm")
    asadm_version: str | None

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
            self.commands.add(command, controller())

    def _set_command_contexts(self):
        for command in self.controller_map:
            controller: BaseController = self.commands[command][0]
            context_cpy = list(self._context)
            context_cpy.append(command)
            controller.set_context(context_cpy)

    def set_context(self, context):
        """
        Called by the parent controller to set the context of the current controller
        before use.
        """
        self._context = context

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

            # The line contains an ambiguous entry
            # or exact match
            return []

    async def __call__(self, line):
        return await self.execute(line)

    def _init_controller_map(self):
        """
        Define controller_map if not defined. This way, not all sub-commands need to
        define it or call super()
        """
        try:
            if self.controller_map:
                pass
        except Exception:
            self.controller_map: dict[str, type[BaseController]] = {}

    def _init_modifiers(self):
        """
        Define modifiers, required_modifiers, and mods if not defined. This way,
        not all sub-commands need to define it or call super()
        """
        try:
            if self.modifiers:
                pass
        except Exception:
            self.modifiers = set()

        try:
            if self.required_modifiers:
                pass
        except Exception:
            self.required_modifiers = set()

        try:
            if self.mods:
                pass
        except Exception:
            self.mods = {}

    def _init_context(self):
        try:
            if self._context:
                pass
        except Exception:
            self._context = []

    def _init(self):
        self._init_modifiers()
        self._init_controller_map()
        self._init_context()
        self._init_commands()
        self._set_command_contexts()

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

    async def execute(self, line: list[str]) -> Union[None, str, list[None]]:
        # Init all command controller objects and modifiers.
        self._init()

        self.pre_controller(line)
        method = self._find_method(line)

        results = None

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

        raise ShellException("Method was not set? %s" % (line))

    def _print_usage(
        self, method: Callable[[Any], Any], context: list[str], is_method: bool
    ):
        context_str = " ".join(context)
        if self.commands and not is_method:
            if CommandHelp.usage(method):
                usage = [
                    f"Usage:  {context_str} {terminal.bold()}{CommandHelp.DEFAULT_USAGE}{terminal.reset()}",
                    f"Usage:  {context_str} {CommandHelp.usage(method)}",
                ]
            else:
                usage = [f"Usage:  {context_str} {CommandHelp.DEFAULT_USAGE}"]
        else:
            usage = [f"Usage:  {context_str} {CommandHelp.usage(method)}"]

        CommandHelp.print_text("\n" + "\n        or\n".join(usage))

    def _print_help_helper(self, method, context, is_method):
        CommandHelp.print_text("")
        CommandHelp.display_long(method)

        self._print_usage(method, context, is_method)

        CommandHelp.display_modifiers(method, indent=4)
        CommandHelp.print_text("")

    def _print_help(self):
        self._print_help_helper(self, self._context, False)

    def _print_method_help(self, method):
        context = self._context[:]
        method_name = method.__name__
        context.append(method_name[3:])
        self._print_help_helper(method, context, True)

    def _get_max_command_len(self, default_defined):
        max_len_help_msg = 0

        if default_defined:
            max_len_help_msg = len(DEFAULT)

        for command in self.commands.keys():
            command_method = self._find_method([command])

            if CommandHelp.has_help(command_method) and not CommandHelp.is_hidden(
                command_method
            ):
                max_len_help_msg = max(max_len_help_msg, len(command))

        return max_len_help_msg

    def _print_sub_commands_help(self):
        default_method = self._find_method([DEFAULT])
        max_len_help_msg = self._get_max_command_len(default_method) + 5
        indent = 2

        if self.commands:
            CommandHelp.print_text(("Commands:\n"))

            # Print default command first if defined
            if default_method:
                command = "Default"
                fmt_command = f"{terminal.bold()}{terminal.underline()}{command}{terminal.reset()}"
                fmt_command = fmt_command.ljust(
                    max_len_help_msg + (len(fmt_command) - len(command))
                )
                CommandHelp.print_text(
                    f"{fmt_command}{CommandHelp.short_message(default_method)}",
                    indent=indent - 1,
                )

        # Now print all possible subcommands
        for command in sorted(self.commands.keys()):
            default_method = self._find_method([command])

            if CommandHelp.has_help(default_method) and not CommandHelp.is_hidden(
                default_method
            ):
                command = command.ljust(max_len_help_msg)
                CommandHelp.print_text(
                    f"{terminal.bold()}{command}{terminal.reset()}{CommandHelp.short_message(default_method)}",
                    indent=indent - 1,
                )

        CommandHelp.print_text("")

    def execute_help(self, line, method=None):
        """ """
        self._init()

        # Removes the need to call _find_method twice since it also happens
        # in parent call.
        if method is None:
            method = self._find_method(line)

        if method:
            try:
                method_name: str | None = None

                try:
                    # Method name only exists on functions,
                    method_name = method.__name__
                except Exception:
                    pass

                if method_name is None:
                    # This is the top of the recursive calls meaning self = a root controller
                    method.execute_help(line)

                elif method_name == DEFAULT:
                    # Print controller help
                    self._print_help()
                    self._print_sub_commands_help()

                    if self.commands:
                        if self._context:
                            context_str = " ".join(self._context)
                            CommandHelp.print_text(
                                f"\nRun 'help {context_str} {CommandHelp.DEFAULT_USAGE}' for more information on a command.\n"
                            )
                        else:
                            CommandHelp.print_text(
                                f"\nRun 'help {CommandHelp.DEFAULT_USAGE}' for more information on a command.\n"
                            )
                    return

                elif isinstance(method, ShellException):
                    # Method not implemented
                    pass
                else:
                    # Print help for a method i.e. do_watch or do_show but not _do_default
                    self._print_method_help(method)
                    return

            except IOError as e:
                raise ShellException(str(e))
        else:
            raise ShellException("Method was not set? %s" % (line))

    @CommandHelp("Print this help message")
    async def _do_default(self, line):
        # Override method to provide default command behavior
        self.execute_help(line)
        self.logger.error("%s: command not found." % (" ".join(line)))

    def pre_command(self, line):
        """
        Called once before the command executes. Optionally, defined in subclass
        """
        pass

    def pre_controller(self, line):
        """
        Called before each new controller is called. Optionally, defined in subclass.
        """
        pass


class CommandController(BaseController):
    default_nodes = "all"

    def parse_modifiers(self, line, duplicates_in_line_allowed=False):
        mods = self.modifiers | self.required_modifiers
        groups: dict[str, list[Any]] = {}

        for mod in mods:
            if mod in mods:
                groups[mod] = []

        mod = "line"
        groups[mod] = []

        while line:
            word = line.pop(0)

            if word in mods:
                mod = word
                # Special case for handling diff modifier of show config
                if mod == "diff":
                    groups[mod].append(True)

            else:
                if duplicates_in_line_allowed or word not in groups[mod]:
                    groups[mod].append(word)

        # Remove trailing ',' from input since it needs to be filtered
        # out in many cases.
        for mod in groups:
            if len(groups[mod]) > 1:
                for idx, val in enumerate(groups[mod]):
                    if isinstance(val, str) and val.endswith(","):
                        groups[mod][idx] = val[:-1]

        if "with" in mods and "all" in groups["with"]:
            groups["with"] = "all"  # type: ignore
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
