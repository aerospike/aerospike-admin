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
	if [[ "$out" == *"legacy provider failed to load"* ]]; then
		echo "error: $tool: OpenSSL's legacy provider failed to load" >&2
		exit 1
	fi
	assert_version_output "$out" "$expected"
	echo "$tool reports $(expected_version_lines "$expected" | tr '\n' ' ')(from $expected)"
done

if [ "$(uname)" = Linux ]; then
	bundle="$(dirname "$(readlink -f "$(command -v asadm)")")"
	bundled="$(find "$bundle" \( -name 'libssl.so*' -o -name 'libcrypto.so*' -o -path '*/ossl-modules/*' \))"
	if [ -n "$bundled" ]; then
		echo "error: asadm ships its own OpenSSL: $bundled" >&2
		exit 1
	fi
fi

if command -v openssl >/dev/null &&
	OPENSSL_FORCE_FIPS_MODE=1 openssl sha256 /dev/null >/dev/null 2>&1 &&
	! OPENSSL_FORCE_FIPS_MODE=1 openssl md5 /dev/null >/dev/null 2>&1; then
	for tool in asadm asinfo; do
		OPENSSL_FORCE_FIPS_MODE=1 "$tool" --version >/dev/null
		echo "$tool starts with OpenSSL in FIPS mode"
	done
fi
