#!/usr/bin/env bash
set -xeuo pipefail

DISTRO="$1"
env
cd local
#if [ "$(git rev-parse --is-shallow-repository 2>/dev/null)" = "true" ]; then
#git fetch --unshallow --tags --no-recurse-submodules
#fi
#git submodule update --init
ls -laht
git branch -v
git describe

.github/packaging/common/entrypoint.sh -c -d "$DISTRO"
.github/packaging/common/entrypoint.sh -e -d "$DISTRO"

ls -laht ../dist
