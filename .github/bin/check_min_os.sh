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

# LC_BUILD_VERSION on current objects, LC_VERSION_MIN_MACOSX on older ones.
read_minos() {
	otool -l "$1" 2>/dev/null | awk '
		/LC_BUILD_VERSION/  { in_bv = 1; next }
		/LC_VERSION_MIN_MAC/ { in_vm = 1; next }
		in_bv && $1 == "minos"   { print $2; exit }
		in_vm && $1 == "version" { print $2; exit }
		/^Load command/ { in_bv = 0; in_vm = 0 }
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
	minos=$(read_minos "$f")
	# No load command means no floor to violate.
	[[ -n "$minos" ]] || continue
	if ! version_le "$minos" "$floor"; then
		echo "  $minos  $f" >&2
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
