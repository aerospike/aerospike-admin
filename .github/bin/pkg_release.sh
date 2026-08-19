#!/usr/bin/env bash
# Split a version into the package version and the package release iteration.
#
# A release-candidate tag must not leak into package file names or image tags.
# The "rcN" pre-release identifier becomes the package iteration instead (rpm
# Release / deb revision), which is what distro tooling already uses to order
# rebuilds of the same upstream version:
#
#   5.0.3-rc2                -> version 5.0.3                 iteration 2
#   5.0.3-rc2-master.abc123  -> version 5.0.3-master.abc123   iteration 2
#   5.0.3                    -> version 5.0.3                 iteration 1
#   5.0.3-beta1              -> version 5.0.3-beta1           iteration 1
#
# Only "rcN" is folded; any other pre-release identifier is left in the version
# so two different pre-releases can never collapse onto the same package name.
# A version that would still carry an rc identifier after the fold (bare "-rc",
# more than 4 rc digits, a second rc identifier) is rejected rather than shipped
# under a name the standard forbids.
#
# This file is shared verbatim across the tools repos and the bundle; keep the
# copies byte-identical and the shared cases in pkg_release.bats in step.
#
# Usage: pkg_release.sh <version> [version|iteration|release|all]
#   version    package version, rcN stripped
#   iteration  rpm Release / deb revision number
#   release    "<version>-<iteration>", for names with no iteration field of
#              their own (macOS .pkg, .tar, docker tags)
#   all        the three values as KEY=value lines (default)
set -euo pipefail

version="${1:-}"
if [[ -z "$version" ]]; then
	echo "usage: $(basename "$0") <version> [version|iteration|release|all]" >&2
	exit 1
fi

# The rcN token must be a WHOLE pre-release identifier, not a prefix of one:
# an unanchored match would strip "rc2" out of the middle of "rc2x" and glue the
# remainder onto the core, yielding a package version the binary is not stamped
# with. "rc" is matched case-insensitively so an uppercase RC2 cannot leak into
# a file name or image tag, the digit run is bounded so it cannot overflow
# bash's signed-64-bit arithmetic and wrap onto another iteration, and leading
# zeros are folded (rc01 == rc1) so one rc can never yield two differently
# named packages that dpkg/rpm would compare as equal.
if [[ "$version" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-[Rr][Cc]0*([0-9]{1,4})(-(.*))?$ ]]; then
	pkg_version="${BASH_REMATCH[1]}${BASH_REMATCH[3]:+-${BASH_REMATCH[4]}}"
	iteration="${BASH_REMATCH[2]}"
	if ((iteration < 1)); then
		echo "rc numbering starts at rc1; '$version' would package as iteration 0, which dpkg/rpm sort below every other build of $pkg_version" >&2
		exit 1
	fi
elif [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.]+)*$ ]]; then
	# Not an rc: the identifier stays in the version, iteration 1.
	pkg_version="$version"
	iteration=1
else
	echo "unparseable version '$version' (expected MAJOR.MINOR.PATCH with an optional pre-release identifier)" >&2
	exit 1
fi

# Catches what the fold cannot absorb: a bare "-rc", an rc digit run past the
# bound, and an rc smuggled in behind the folded one ("5.0.3-rc2-rc3").
if [[ "$pkg_version" =~ (^|[-.])[Rr][Cc][0-9]*([-.]|$) ]]; then
	echo "'$version' would leave an rc identifier in the package version '$pkg_version'; rc folds into the iteration and must be rc1..rc9999, the first pre-release identifier" >&2
	exit 1
fi

case "${2:-all}" in
version) printf '%s\n' "$pkg_version" ;;
iteration) printf '%s\n' "$iteration" ;;
release) printf '%s-%s\n' "$pkg_version" "$iteration" ;;
all) printf 'PKG_VERSION=%s\nITERATION=%s\nRELEASE=%s-%s\n' \
	"$pkg_version" "$iteration" "$pkg_version" "$iteration" ;;
*)
	echo "unknown field '$2' (want: version|iteration|release|all)" >&2
	exit 1
	;;
esac
