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

import sys
from typing import Union

_add_it = None
_remove_it = None
_reset = None

sclear = None
sbold = None
sdim = None
snormal = None
sunderline = None
sinverse = None
siclear = None

fgblack = None
fgred = None
fggreen = None
fgyellow = None
fgblue = None
fgmagenta = None
fgcyan = None
fgwhite = None

bgblack = None
bgred = None
bggreen = None
bgyellow = None
bgblue = None
bgmagenta = None
bgcyan = None
bgwhite = None

esc = None
term = None

sclear_code = None
cur_format: Union[list[str], set[str], None] = None


def enable_color(is_enable):
    global _add_it, _remove_it, _reset
    global sclear, sbold, sdim, snormal, sunderline, sinverse, siclear
    global fgblack, fgred, fggreen, fgyellow, fgblue, fgmagenta, fgcyan, fgwhite
    global bgblack, bgred, bggreen, bgyellow, bgblue, bgmagenta, bgcyan, bgwhite
    global esc, term
    global sclear_code, cur_format
    global color_enabled

    color_enabled = is_enable

    if is_enable:
        sclear = "0"
        sbold = "1"
        sdim = "2"
        snormal = "22"
        sunderline = "4"
        sinverse = "7"
        siclear = "27"

        fgblack = "30;90"
        fgred = "31;91"
        fggreen = "32;92"
        fgyellow = "33;93"
        fgblue = "34;94"
        fgmagenta = "35;95"
        fgcyan = "36;96"
        fgwhite = "37;97"

        bgblack = "40;100"
        bgred = "41;101"
        bggreen = "42;102"
        bgyellow = "43;103"
        bgblue = "44;104"
        bgmagenta = "45;105"
        bgcyan = "46;106"
        bgwhite = "47;107"

        esc = "\033["
        term = "m"

        sclear_code = esc + sclear + term
        cur_format = set()

        def _add_it(decoration):
            if decoration in cur_format:
                return ""  # nothing to do
            else:
                cur_format.add(decoration)
                return esc + ";".join(cur_format) + term

        def _remove_it(decoration, decoration_clear=""):
            if decoration in cur_format:
                cur_format.remove(decoration)
                if decoration_clear:
                    return esc + decoration_clear + term
                else:
                    return esc + sclear + ";" + ";".join(cur_format) + term
            else:
                return ""  # nothing to do

        def _reset():
            cur_format.clear()
            return esc + sclear + term

    else:
        sclear = ""
        sbold = ""
        sdim = ""
        snormal = ""
        sunderline = ""
        sinverse = ""
        siclear = ""

        fgblack = ""
        fgred = ""
        fggreen = ""
        fgyellow = ""
        fgblue = ""
        fgmagenta = ""
        fgcyan = ""
        fgwhite = ""

        bgblack = ""
        bgred = ""
        bggreen = ""
        bgyellow = ""
        bgblue = ""
        bgmagenta = ""
        bgcyan = ""
        bgwhite = ""

        sclear_code = ""
        cur_format = list()

        def _add_it(decoration) -> str:
            if decoration in cur_format:
                return ""  # nothing to do
            else:
                cur_format.append(decoration)
                return decoration

        def _remove_it(decoration, decoration_clear="") -> str:
            if decoration in cur_format:
                cur_format.remove(decoration)
                return decoration
            else:
                return ""  # nothing to do

        def _reset():
            cur_format.reverse()
            retval = "".join(cur_format)
            del cur_format[:]
            return retval


# Real terminal?
isatty = sys.stdout.isatty()
color_enabled = isatty
enable_color(isatty)


def bold():
    return _add_it(sbold)


def unbold():
    return _remove_it(sbold)


def dim():
    return _add_it(sdim)


def undim():
    return _remove_it(sdim)


def underline():
    return _add_it(sunderline)


def ununderline():
    return _remove_it(sunderline)


def inverse():
    return _add_it(sinverse)


def uninverse():
    return _remove_it(sinverse, siclear)


def reset():
    return _reset()


def fg_black():
    return _add_it(fgblack)


def fg_red():
    return _add_it(fgred)


def fg_not_red():
    return _remove_it(fgred)


def fg_green():
    return _add_it(fggreen)


def fg_not_green():
    return _remove_it(fggreen)


def fg_yellow():
    return _add_it(fgyellow)


def fg_not_yellow():
    return _remove_it(fgyellow)


def fg_blue():
    return _add_it(fgblue)


def fg_not_blue():
    return _remove_it(fgblue)


def fg_magenta():
    return _add_it(fgmagenta)


def fg_not_magenta():
    return _remove_it(fgmagenta)


def fg_cyan():
    return _add_it(fgcyan)


def fg_not_cyan():
    return _remove_it(fgcyan)


def fg_white():
    return _add_it(fgwhite)


def fg_clear():
    _remove_it(fgblack)
    _remove_it(fgred)
    _remove_it(fggreen)
    _remove_it(fgyellow)
    _remove_it(fgblue)
    _remove_it(fgmagenta)
    _remove_it(fgcyan)
    return sclear_code + _remove_it(fgwhite)


def bg_black():
    return _add_it(bgblack)


def bg_red():
    return _add_it(bgred)


def bg_green():
    return _add_it(bggreen)


def bg_yellow():
    return _add_it(bgyellow)


def bg_blue():
    return _add_it(bgblue)


def bg_magenta():
    return _add_it(bgmagenta)


def bg_cyan():
    return _add_it(bgcyan)


def bg_white():
    return _add_it(bgwhite)


def bg_clear():
    _remove_it(bgblack)
    _remove_it(bgred)
    _remove_it(bggreen)
    _remove_it(bgyellow)
    _remove_it(bgblue)
    _remove_it(bgmagenta)
    _remove_it(bgcyan)
    return sclear_code + _remove_it(bgwhite)


def style(*functions):
    if not functions:
        return ""

    for function in functions[:-1]:
        function()

    return functions[-1]()
