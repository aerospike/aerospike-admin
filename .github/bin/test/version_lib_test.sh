#!/usr/bin/env bash
# Unit tests for version_lib.sh -- the assertions the post-install smoke tests
# are built from. They run against strings, not an installed binary, so they need
# no package and no bats: `bash .github/bin/test/version_lib_test.sh`.
#
# The smoke tests themselves only run in build-and-release.yml, which is
# workflow_dispatch-only, and mac-artifact.yml never invokes `make -C pkg
# osx-pkg`. Without this file a regression in the assertions -- one that lets a
# mis-stamped binary through -- would first be observed during a release. These
# cases are the ones that regression would break.
#
# Mirrors the helper asconfig and asbench ship; keep the shared cases in step.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.github/bin/test/version_lib.sh
. "$SCRIPT_DIR/version_lib.sh"

failures=0

# What `asadm --version` / `asinfo --version` print for a given embedded string:
# both split on "-", the core on a Version line and the last field, when there is
# one, on a Build line (asadm.py's get_version, asinfo.py's --version branch).
report() {
	printf 'Aerospike Administration Shell\nVersion %s\n' "${1%%-*}"
	[ "$1" = "${1%%-*}" ] || printf 'Build %s\n' "${1##*-}"
}

check() {
	local want="$1" desc="$2" got=0
	shift 2
	"$@" >/dev/null 2>&1 || got=1
	if [ "$got" != "$want" ]; then
		echo "FAIL: $desc (wanted exit $want, got $got)" >&2
		failures=$((failures + 1))
	else
		echo "ok: $desc"
	fi
}

expect_eq() {
	local desc="$1" want="$2" got="$3"
	if [ "$got" = "$want" ]; then
		echo "ok: $desc"
	else
		echo "FAIL: $desc (wanted '$want', got '$got')" >&2
		failures=$((failures + 1))
	fi
}

# --- expected_version_lines: the shape of the expected output ---
expect_eq "rc version yields both lines" \
	"$(printf 'Version 5.0.3\nBuild rc3')" "$(expected_version_lines 5.0.3-rc3)"
expect_eq "bare version yields no Build line" \
	"Version 5.0.3" "$(expected_version_lines 5.0.3)"
expect_eq "dev version builds from the sha" \
	"$(printf 'Version 5.0.3\nBuild abc123def')" "$(expected_version_lines 5.0.3-abc123def)"
check 1 "unparseable core is rejected" expected_version_lines garbage
check 1 "a v prefix is rejected" expected_version_lines v5.0.3-rc3
# Emitting the literal "Build " would blame the binary for a malformed
# expectation -- asadm prints no Build line for an empty trailing field.
check 1 "an empty trailing field is rejected" expected_version_lines 5.0.3-

# --- assert_version_output: what the binary actually printed ---
check 0 "matching rc stamp passes" assert_version_output "$(report 5.0.3-rc3)" 5.0.3-rc3
check 0 "matching bare stamp passes" assert_version_output "$(report 5.0.3)" 5.0.3
check 0 "matching dev stamp passes" assert_version_output "$(report 5.0.3-abc123def)" 5.0.3-abc123def
# The case rcN-as-iteration created: two packages that differ by nothing else.
check 1 "a stale rc2 binary fails an rc3 package" assert_version_output "$(report 5.0.3-rc2)" 5.0.3-rc3
check 1 "a bare binary fails an rc package" assert_version_output "$(report 5.0.3)" 5.0.3-rc3
# How a binary that fell back to `git describe` gives itself away. Unreachable
# from either get-version path, so this file is the only place it is exercised.
check 1 "a git-describe binary fails a bare version" assert_version_output "$(report 5.0.3-15-gabc123def)" 5.0.3
check 1 "wrong core fails" assert_version_output "$(report 5.0.4-rc3)" 5.0.3-rc3
check 1 "a longer core is not a match" assert_version_output "$(report 5.0.30-rc3)" 5.0.3-rc3
check 1 "empty output fails" assert_version_output "" 5.0.3-rc3

# --- expected_version: which string to expect ---
version_file="$(mktemp)"
printf '5.0.3-rc3\n' >"$version_file"

expect_eq "falls back to the VERSION file" \
	"5.0.3-rc3" "$(unset EXPECTED_VERSION; expected_version "$version_file")"
expect_eq "EXPECTED_VERSION wins for a dev build" \
	"5.0.3-abc123def" "$(EXPECTED_VERSION=5.0.3-abc123def expected_version "$version_file")"
check 1 "a disagreeing core fails" \
	env EXPECTED_VERSION=5.1.0-rc3 bash -c ". '$SCRIPT_DIR/version_lib.sh'; expected_version '$version_file'"
# rcN is the only field distinguishing two artifacts of one release, so a
# core-only comparison here would validate against the wrong claim and pass.
check 1 "a same-core different-rcN fails" \
	env EXPECTED_VERSION=5.0.3-rc9 bash -c ". '$SCRIPT_DIR/version_lib.sh'; expected_version '$version_file'"
# An unresolved needs.<job>.outputs.<name> arrives as set-but-empty, and on a
# master release the VERSION file equals BUILD_VERSION -- so falling back here
# would hide the one wiring mistake this check exists to catch.
check 1 "an empty EXPECTED_VERSION fails rather than falling back" \
	env EXPECTED_VERSION= bash -c ". '$SCRIPT_DIR/version_lib.sh'; expected_version '$version_file'"
check 1 "no file and no EXPECTED_VERSION fails" \
	env -u EXPECTED_VERSION bash -c ". '$SCRIPT_DIR/version_lib.sh'; expected_version /nonexistent/VERSION"

rm -f "$version_file"

if [ "$failures" -ne 0 ]; then
	echo "$failures version_lib.sh assertion(s) behaved wrongly" >&2
	exit 1
fi
echo "all version_lib.sh assertions behave as documented"
