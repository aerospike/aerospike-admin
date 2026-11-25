#!/usr/bin/env bash
# Print the OpenSSL floor (OPENSSL_FLOOR) from pkg/Makefile, shape-checked as in
# macos_min_version.sh. With -minor, print only its minor version (2 for 3.2.2).
#
# Usage: openssl_floor.sh [-minor] [<makefile>]
set -euo pipefail

part=full
if [[ "${1:-}" == -minor ]]; then
	part=minor
	shift
fi
makefile="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/pkg/Makefile}"
if [[ ! -f "$makefile" ]]; then
	echo "error: no makefile at $makefile" >&2
	exit 1
fi

floor=$(sed -n 's/^OPENSSL_FLOOR[[:space:]]*=[[:space:]]*//p' "$makefile")
if [[ ! "$floor" =~ ^3\.([0-9]+)\.[0-9]+$ ]]; then
	echo "error: OPENSSL_FLOOR malformed in $makefile: '$floor'" >&2
	exit 1
fi

if [[ "$part" == minor ]]; then
	printf '%s\n' "${BASH_REMATCH[1]}"
else
	printf '%s\n' "$floor"
fi
