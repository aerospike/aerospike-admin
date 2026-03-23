#!/usr/bin/env bash
set -xeuo pipefail

DISTRO="$1"
REPO_NAME="$2"
PKG_VERSION="$3"
PACKAGE_NAME="$4"
export PKG_VERSION PACKAGE_NAME

git fetch --unshallow --tags --no-recurse-submodules 2>/dev/null || git fetch --tags --no-recurse-submodules

ROOT="$(git rev-parse --show-toplevel)"
"${ROOT}/.github/bin/test/install_from_jfrog.sh"
"${ROOT}/.github/bin/test/test_execute.sh"
