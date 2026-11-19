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

	if command -v rpm >/dev/null && rpm -q aerospike-asadm >/dev/null 2>&1; then
		if ! command -v objdump >/dev/null; then
			echo "error: objdump (binutils) is needed to read the OpenSSL symbol versions the bundle imports" >&2
			exit 1
		fi
		needed="$({ find "$bundle" -name '*.so*' -type f -exec objdump -T {} + 2>/dev/null || true; } |
			sed -nE 's/.*OPENSSL_3\.([0-9]+).*/\1/p' | sort -n | tail -1)"
		if [ "${needed:-0}" -gt 0 ]; then
			requires="$(rpm -q --requires aerospike-asadm)"
			declared="$(sed -nE 's/^openssl-libs >= 1:3\.([0-9]+).*/\1/p' <<< "$requires")"
			if [ -z "$declared" ] || [ "$declared" -lt "$needed" ]; then
				echo "error: the bundle imports OPENSSL_3.$needed symbols but the rpm requires: $(grep '^openssl' <<< "$requires")" >&2
				exit 1
			fi
			echo "the rpm requires openssl-libs >= 1:3.$declared for the bundle's OPENSSL_3.$needed symbols"
		fi
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
