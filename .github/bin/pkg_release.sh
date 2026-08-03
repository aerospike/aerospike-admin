#!/usr/bin/env bash
# Split a version into the package version and the package release iteration.
#
# A release-candidate tag must not leak into package file names or image tags.
# The "rcN" pre-release identifier becomes the package iteration instead (rpm
# Release / deb revision), which is what distro tooling already uses to order
# rebuilds of the same upstream version:
#
#   5.0.3-rc2                -> version 5.0.3                iteration 2
#   5.0.3-rc2-master.abc123  -> version 5.0.3-master.abc123   iteration 2
#   5.0.3                    -> version 5.0.3                iteration 1
#   5.0.3-beta1              -> version 5.0.3-beta1           iteration 1
#
# Only "rcN" is folded; any other pre-release identifier is left in the version
# so two different pre-releases can never collapse onto the same package name.
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

pkg_version=$(printf '%s' "$version" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+)-rc[0-9]+/\1/')
iteration=$(printf '%s' "$version" | sed -nE 's/^[0-9]+\.[0-9]+\.[0-9]+-rc([0-9]+).*$/\1/p')
# Base 10 so rc01 and rc1 cannot yield two differently named packages that
# dpkg/rpm would then compare as equal.
iteration=$((10#${iteration:-1}))

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
