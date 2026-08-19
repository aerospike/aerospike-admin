#!/usr/bin/env bash
# Same post-install checks as test_execute.bats, for hosts without bats.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
# shellcheck source=.github/bin/test/version_lib.sh
. "$SCRIPT_DIR/version_lib.sh"

expected="$(expected_version "$REPO_ROOT/VERSION")"

for tool in asadm asinfo; do
	"$tool" --help >/dev/null
	out="$("$tool" --version 2>&1)"
	assert_version_output "$out" "$expected"
	echo "$tool reports $(expected_version_lines "$expected" | tr '\n' ' ')(from $expected)"
done
