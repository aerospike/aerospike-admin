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
# Emit a short distro identifier used by pkg/Makefile (e.g. "el9", "ubuntu24").
# Pass -long for the verbose form ("rhel9", "ubuntu24").
#
# Reads /etc/os-release. Every distro in the CI matrix and every supported
# local-dev distro has this file; the legacy /etc/issue fallback was removed
# along with the tools-packaging-common submodule.

set -euo pipefail

OPT_LONG=0
[[ "${1:-}" = "-long" ]] && OPT_LONG=1

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: $(uname -s) is not supported." >&2
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
