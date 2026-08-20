#!/usr/bin/env bash
# shellcheck disable=SC1091
# ------------------------------------------------------------------------------
# Copyright 2012-2023 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at http://www.apache.org/licenses/LICENSE-2.0
# ------------------------------------------------------------------------------
#
# Emit a short OS identifier used by pkg/Makefile (e.g. "el9", "ubuntu24",
# "macos15"). Pass -long for the verbose form ("rhel9", "ubuntu24", "macos15").
#
# On Linux this reads /etc/os-release. Every distro in the CI matrix and every
# supported local-dev distro has this file; the legacy /etc/issue fallback was
# removed along with the tools-packaging-common submodule.
#
# On macOS it emits "macos<major>" from the product version (26.0 -> macos26).
# No longer part of any artifact name -- .pkg files are named per arch, not per
# macOS generation (see MAC_PKG in pkg/Makefile). Kept for callers that want the
# build host's generation.

set -euo pipefail

OPT_LONG=0
[[ "${1:-}" = "-long" ]] && OPT_LONG=1

kernel="$(uname -s)"

if [[ "$kernel" = "Darwin" ]]; then
    # Identifies the build host's generation only. Not part of any artifact
    # name, and not a minimum the artifact supports -- see MACOS_MIN_VERSION.
    mac_version="$(sw_vers -productVersion)"
    # `set -e` above already catches an sw_vers that exits non-zero. This
    # guard is for the case it cannot see: exiting 0 having printed nothing,
    # which would emit the bare token "macos" -- non-empty, so pkg/Makefile's
    # prep-mac guard would wave it through and the release would ship
    # aerospike-asadm-<version>-macos-<arch>.pkg.
    if [[ -z "$mac_version" ]]; then
        echo "error: sw_vers -productVersion returned nothing." >&2
        exit 1
    fi
    echo "macos${mac_version%%.*}"
    exit 0
fi

if [[ "$kernel" != "Linux" ]]; then
    echo "error: ${kernel} is not supported." >&2
    exit 1
fi

if [[ ! -f /etc/os-release ]]; then
    echo "error: /etc/os-release not found." >&2
    exit 1
fi

. /etc/os-release

distro_id="${ID,,}"
distro_version="${VERSION_ID%%.*}"

case "$distro_id" in
    rhel|redhat)
        short="el${distro_version}"
        long="${distro_id}${distro_version}"
        ;;
    fedora)
        short="fc${distro_version}"
        long="${distro_id}${distro_version}"
        ;;
    *)
        short="${distro_id}${distro_version}"
        long="$short"
        ;;
esac

if [[ "$OPT_LONG" = "1" ]]; then
    echo "$long"
else
    echo "$short"
fi
