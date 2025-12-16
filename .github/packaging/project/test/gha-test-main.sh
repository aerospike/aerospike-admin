#!/usr/bin/env bash
set -xeuo pipefail
DISTRO="$1"
REPO_NAME="$2"
PKG_VERSION="$3"
env
git fetch --unshallow --tags --no-recurse-submodules
.github/packaging/common/example-test.sh "$DISTRO" "$REPO_NAME" "$PKG_VERSION"
