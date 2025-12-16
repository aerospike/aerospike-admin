#!/usr/bin/env bash
set -xeuo pipefail

DISTRO="$1"
env
cd local
git fetch --unshallow --tags --no-recurse-submodules
git submodule update --init
ls -laht
git branch -v

if [ "${GITHUB_ACTIONS:-}" = "true" ] && [ "${USE_REMOTE_BUILDER_IMAGES:-false}" = "true" ]; then
  # CI + remote images: don't build, just execute (will pull in execute_build_image)
  .github/packaging/common/entrypoint.sh -e -d "$DISTRO"
else
  # Local or non-remote mode: build image then run it (existing behavior)
  .github/packaging/common/entrypoint.sh -c -d "$DISTRO"
  .github/packaging/common/entrypoint.sh -e -d "$DISTRO"
fi

ls -laht ../dist

