#!/usr/bin/env bats
#
# Table test for openssl_floor.sh, the single read of the OpenSSL floor behind
# the rpm's openssl-libs requirement, assert_system_openssl and
# hold_el_openssl.sh.

setup() {
  OPENSSL_FLOOR_SH="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/openssl_floor.sh"
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
  MAKEFILE="$BATS_TEST_TMPDIR/Makefile"
}

# assert_floor <makefile line> <expected full> <expected minor>
assert_floor() {
  printf '%s\n' "$1" >"$MAKEFILE"
  run "$OPENSSL_FLOOR_SH" "$MAKEFILE"
  [ "$status" -eq 0 ]
  [ "$output" = "$2" ]
  run "$OPENSSL_FLOOR_SH" -minor "$MAKEFILE"
  [ "$status" -eq 0 ]
  [ "$output" = "$3" ]
}

# assert_malformed <makefile contents>
assert_malformed() {
  printf '%s\n' "$1" >"$MAKEFILE"
  run "$OPENSSL_FLOOR_SH" "$MAKEFILE"
  [ "$status" -eq 1 ]
  [[ "$output" == *"OPENSSL_FLOOR malformed"* ]]
}

@test "a floor is read back exactly, with its minor" {
  assert_floor "OPENSSL_FLOOR = 3.2.2" "3.2.2" "2"
  assert_floor "OPENSSL_FLOOR=3.10.1" "3.10.1" "10"
}

@test "a missing, empty or malformed floor fails" {
  assert_malformed "ARCH = arm64"
  assert_malformed "OPENSSL_FLOOR ="
  assert_malformed "OPENSSL_FLOOR = 3.2"
  assert_malformed "OPENSSL_FLOOR = 3.2.2 # comment"
  assert_malformed "OPENSSL_FLOOR := 3.2.2"
  assert_malformed $'OPENSSL_FLOOR = 3.2.2\r'
}

@test "the repo's pkg/Makefile has a well-formed floor" {
  run "$OPENSSL_FLOOR_SH"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^3\.[0-9]+\.[0-9]+$ ]]
}
