#!/usr/bin/env bash
# Version assertions shared by test_execute.bats and test_execute.sh, so the
# two cannot drift.

# Resolve the version the installed binary is expected to report:
# EXPECTED_VERSION when set, otherwise the VERSION file. When both are present
# their MAJOR.MINOR.PATCH cores must agree -- a mismatch means CI handed the
# tests the wrong workflow output, not that the binary is wrong.
expected_version() {
	local version_file="$1" file_version="" expected
	if [ -f "$version_file" ]; then
		file_version="$(tr -d '[:space:]' <"$version_file")"
	fi
	# Set-but-empty is a broken wiring, not a request for the default: it is
	# what a workflow output that never got produced looks like. Falling back
	# to the VERSION file there would quietly test the binary against the
	# checkout instead of against the build, which is the one thing
	# EXPECTED_VERSION exists to prevent.
	if [ -n "${EXPECTED_VERSION+set}" ] && [ -z "$EXPECTED_VERSION" ]; then
		echo "EXPECTED_VERSION is set but empty -- the step that supplies it produced nothing" >&2
		return 1
	fi
	expected="${EXPECTED_VERSION:-$file_version}"
	if [ -z "$expected" ]; then
		echo "no VERSION file at $version_file and no EXPECTED_VERSION set" >&2
		return 1
	fi
	if [ -n "${EXPECTED_VERSION:-}" ] && [ -n "$file_version" ] &&
		[ "${EXPECTED_VERSION%%-*}" != "${file_version%%-*}" ]; then
		echo "EXPECTED_VERSION '$EXPECTED_VERSION' and VERSION file '$file_version' disagree" >&2
		return 1
	fi
	printf '%s\n' "$expected"
}

# The lines `asadm --version` / `asinfo --version` must print for that string.
# Both split the embedded version on "-": the core goes on the Version line and
# the last field, if any, on a Build line.
#
#   5.0.3-rc3        Version 5.0.3 / Build rc3
#   5.0.3-abc123def  Version 5.0.3 / Build abc123def
#   5.0.3            Version 5.0.3
expected_version_lines() {
	local expected="$1" core
	core="${expected%%-*}"
	if ! printf '%s' "$core" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
		echo "cannot parse a MAJOR.MINOR.PATCH core out of '$expected'" >&2
		return 1
	fi
	printf 'Version %s\n' "$core"
	if [ "$expected" != "$core" ]; then
		printf 'Build %s\n' "${expected##*-}"
	fi
}

assert_version_output() {
	local output="$1" expected="$2" lines line
	lines="$(expected_version_lines "$expected")" || return 1

	while IFS= read -r line; do
		if ! printf '%s\n' "$output" | grep -qxF "$line"; then
			echo "expected '$line' (from $expected) in --version output:" >&2
			printf '%s\n' "$output" >&2
			return 1
		fi
	done <<<"$lines"

	# A stale binary stamped from `git describe` reports a Build line where the
	# release version has none, which the checks above cannot see.
	if [ "$expected" = "${expected%%-*}" ] && printf '%s\n' "$output" | grep -q '^Build '; then
		echo "unexpected Build line for version '$expected':" >&2
		printf '%s\n' "$output" >&2
		return 1
	fi
}
