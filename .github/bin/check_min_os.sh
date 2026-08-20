#!/usr/bin/env bash
# Fail if any Mach-O in a macOS payload declares a minos above our floor; dyld
# refuses such a binary on that release, with no override. Catches an unpinned
# compile inheriting the runner's SDK, and prebuilt files vendored off the runner
# that no compile flag reaches.
#
# Usage: check_min_os.sh <floor> <path>...
set -euo pipefail

floor="${1:-}"
shift || true
if [[ -z "$floor" || $# -eq 0 ]]; then
	echo "usage: $(basename "$0") <floor> <path>..." >&2
	exit 1
fi
if [[ ! "$floor" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
	echo "error: floor '$floor' is not a macOS version" >&2
	exit 1
fi

# sort -V, so 14.8 ranks above 14.0 and 9.0 below 10.0.
version_le() {
	[[ "$1" == "$2" ]] || [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]
}

# Every floor in the file, one per line: LC_BUILD_VERSION on current objects,
# LC_VERSION_MIN_MACOSX on older ones. A universal binary carries one set of
# load commands per slice, and `otool -l` prints them in slice order, so
# stopping at the first would let a later slice's higher floor through.
read_minos() {
	otool -l "$1" 2>/dev/null | awk '
		/^Load command/      { bv = 0; vm = 0; next }
		/LC_BUILD_VERSION/   { bv = 1; next }
		/LC_VERSION_MIN_MAC/ { vm = 1; next }
		bv && $1 == "minos"   { print $2; bv = 0 }
		vm && $1 == "version" { print $2; vm = 0 }
	'
}

scanned=0
violations=0
while IFS= read -r f; do
	# Filter on type, not the +x bit: dylibs and .so are not executable.
	case "$(file -b "$f" 2>/dev/null)" in
	*Mach-O*) ;;
	*) continue ;;
	esac
	scanned=$((scanned + 1))
	# Report the highest offending slice. A file with no load command at all
	# has no floor to violate.
	worst=""
	while IFS= read -r minos; do
		version_le "$minos" "$floor" && continue
		if [[ -z "$worst" ]] || ! version_le "$minos" "$worst"; then
			worst="$minos"
		fi
	done < <(read_minos "$f")
	if [[ -n "$worst" ]]; then
		echo "  $worst  $f" >&2
		violations=$((violations + 1))
	fi
done < <(find "$@" -type f)

if ((violations > 0)); then
	{
		echo "error: $violations of $scanned Mach-O file(s) above the macOS $floor floor (listed above)."
		echo "Build against MACOSX_DEPLOYMENT_TARGET=$floor, or stop vendoring the offending file."
	} >&2
	exit 1
fi

if ((scanned == 0)); then
	echo "error: no Mach-O files found under: $*" >&2
	exit 1
fi

echo "==> $scanned Mach-O file(s) all run on macOS $floor or later"
