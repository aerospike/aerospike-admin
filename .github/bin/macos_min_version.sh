#!/usr/bin/env bash
# Print the macOS support floor (MACOS_MIN_VERSION) from pkg/Makefile.
#
# The floor is both the deployment target the Intel cryptography build compiles
# against and the bar check_min_os.sh holds the shipping bundle to, so it is
# read here rather than repeated in each workflow. The sed prints whatever
# follows the "=", so the result is shape-checked: a trailing inline comment or
# stray whitespace would otherwise sail through into a deployment target and a
# cache key.
#
# Usage: macos_min_version.sh [<makefile>]
set -euo pipefail

makefile="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/pkg/Makefile}"
if [[ ! -f "$makefile" ]]; then
	echo "error: no makefile at $makefile" >&2
	exit 1
fi

min_os=$(sed -n 's/^MACOS_MIN_VERSION[[:space:]]*=[[:space:]]*//p' "$makefile")
if [[ ! "$min_os" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
	echo "error: MACOS_MIN_VERSION malformed in $makefile: '$min_os'" >&2
	exit 1
fi

printf '%s\n' "$min_os"
