#!/usr/bin/env python3
"""Usage: lock_requirements.py <Pipfile.lock> [name...]. Prints hashed pip
requirements: the named packages (develop, else default), or all of default."""

import json
import sys


def requirement(name, spec):
    line = name + spec["version"]
    if spec.get("markers"):
        line += "; " + spec["markers"]
    return line + "".join(" --hash=" + h for h in spec["hashes"])


def requirements(lock_path, names=()):
    with open(lock_path) as f:
        lock = json.load(f)

    if names:
        specs = [(n, lock["develop"].get(n) or lock["default"][n]) for n in names]
    else:
        specs = sorted(lock["default"].items())

    return "".join(requirement(name, spec) + "\n" for name, spec in specs)


if __name__ == "__main__":
    sys.stdout.write(requirements(sys.argv[1], sys.argv[2:]))
