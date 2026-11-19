#!/usr/bin/env bats
#
# Post-install smoke tests, run against INSTALLED asadm and asinfo.
# Version assertions and EXPECTED_VERSION: see version_lib.sh.

setup() {
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
  VERSION_FILE="$REPO_ROOT/VERSION"
  load "$BATS_TEST_DIRNAME/version_lib.sh"
}

@test "can run asadm" {
  run asadm --help
  [ "$status" -eq 0 ]
}

@test "asadm reports the version from the VERSION file" {
  local expected
  expected="$(expected_version "$VERSION_FILE")"

  run asadm --version
  [ "$status" -eq 0 ]
  echo "expected (from $expected):"
  expected_version_lines "$expected"
  echo "reported:"
  echo "$output"
  assert_version_output "$output" "$expected"
}

@test "asadm starts without OpenSSL's legacy provider failing to load" {
  # The Intel macOS bundle links its own OpenSSL. A legacy provider built as
  # a module sits at a build-time path, loads on the build runner, and warns on
  # every start anywhere else, so this only proves anything on a clean host.
  run asadm --version
  [ "$status" -eq 0 ]
  [[ "$output" != *"legacy provider failed to load"* ]]
}

@test "can run asinfo" {
  run asinfo --help
  [ "$status" -eq 0 ]
}

@test "asinfo reports the version from the VERSION file" {
  local expected
  expected="$(expected_version "$VERSION_FILE")"

  run asinfo --version
  [ "$status" -eq 0 ]
  echo "expected (from $expected):"
  expected_version_lines "$expected"
  echo "reported:"
  echo "$output"
  assert_version_output "$output" "$expected"
}

@test "asadm ships no OpenSSL of its own on Linux" {
  [ "$(uname)" = Linux ] || skip "macOS has no host OpenSSL to load"
  local bundle
  bundle="$(dirname "$(readlink -f "$(command -v asadm)")")"

  run find "$bundle" \( -name 'libssl.so*' -o -name 'libcrypto.so*' -o -path '*/ossl-modules/*' \)
  [ "$status" -eq 0 ]
  echo "bundled OpenSSL: $output"
  [ -z "$output" ]
}

@test "the rpm requires the OpenSSL its bundle links against" {
  command -v rpm >/dev/null && rpm -q aerospike-asadm >/dev/null 2>&1 \
    || skip "asadm was not installed from an rpm"
  command -v objdump >/dev/null || {
    echo "objdump (binutils) is needed to read the OpenSSL symbol versions the bundle imports"
    return 1
  }
  local bundle needed declared
  bundle="$(dirname "$(readlink -f "$(command -v asadm)")")"
  needed="$(find "$bundle" -name '*.so*' -type f -exec objdump -T {} + |
    sed -nE 's/.*OPENSSL_3\.([0-9]+).*/\1/p' | sort -n | tail -1)"
  [ "${needed:-0}" -gt 0 ] || skip "the bundle imports nothing newer than OPENSSL_3.0"

  run rpm -q --requires aerospike-asadm
  [ "$status" -eq 0 ]
  echo "the bundle imports OPENSSL_3.$needed symbols; the rpm requires:"
  echo "$output"
  declared="$(sed -nE 's/^openssl-libs >= 1:3\.([0-9]+).*/\1/p' <<< "$output")"
  [ -n "$declared" ]
  [ "$declared" -ge "$needed" ]
}

@test "asadm and asinfo start when the host's OpenSSL is in FIPS mode" {
  command -v openssl >/dev/null || skip "no openssl CLI to confirm FIPS mode can be forced"
  OPENSSL_FORCE_FIPS_MODE=1 openssl sha256 /dev/null >/dev/null 2>&1 \
    || skip "this host has no OpenSSL FIPS provider"
  if OPENSSL_FORCE_FIPS_MODE=1 openssl md5 /dev/null >/dev/null 2>&1; then
    skip "this host's OpenSSL ignores OPENSSL_FORCE_FIPS_MODE"
  fi

  run env OPENSSL_FORCE_FIPS_MODE=1 asadm --version
  echo "$output"
  [ "$status" -eq 0 ]

  run env OPENSSL_FORCE_FIPS_MODE=1 asinfo --version
  echo "$output"
  [ "$status" -eq 0 ]
}
