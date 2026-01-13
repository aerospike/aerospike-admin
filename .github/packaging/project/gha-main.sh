#!/usr/bin/env bash
set -xeuo pipefail

DISTRO="$1"
env
cd local
git fetch --unshallow --tags --force 2>/dev/null || git fetch --tags --force
ls -laht
git branch -v

.github/packaging/common/entrypoint.sh -c -d "$DISTRO"
.github/packaging/common/entrypoint.sh -e -d "$DISTRO"

ls -laht ../dist
