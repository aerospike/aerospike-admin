#!/usr/bin/env bats
#
# Table test for macos_min_version.sh, the single read of the macOS support
# floor behind the Intel deployment target, the OpenSSL cache key and the
# bundle floor check. Like pkg_release.bats these need no installed binary and
# no packaging, so they run on every pull request.

setup() {
  MACOS_MIN_VERSION_SH="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/macos_min_version.sh"
  REPO_ROOT="$(cd "$BATS_TEST_DIRNAME/../../.." && pwd)"
  MAKEFILE="$BATS_TEST_TMPDIR/Makefile"
}

# assert_floor <makefile line> <expected>
assert_floor() {
  printf '%s\n' "$1" >"$MAKEFILE"
  run "$MACOS_MIN_VERSION_SH" "$MAKEFILE"
  [ "$status" -eq 0 ]
  [ "$output" = "$2" ]
}

# assert_malformed <makefile contents>
assert_malformed() {
  printf '%s\n' "$1" >"$MAKEFILE"
  run "$MACOS_MIN_VERSION_SH" "$MAKEFILE"
  [ "$status" -eq 1 ]
  [[ "$output" == *"MACOS_MIN_VERSION malformed"* ]]
}

@test "a plain floor is read back exactly" {
  assert_floor "MACOS_MIN_VERSION = 14.0" "14.0"
}

@test "spacing around the assignment does not change the value" {
  assert_floor "MACOS_MIN_VERSION=14.0" "14.0"
  assert_floor "MACOS_MIN_VERSION	=	14.0" "14.0"
}

@test "a floor with one or three components is accepted" {
  assert_floor "MACOS_MIN_VERSION = 14" "14"
  assert_floor "MACOS_MIN_VERSION = 14.0.1" "14.0.1"
}

@test "surrounding lines do not leak into the value" {
  printf '%s\n' "# Support floor, asserted by check_min_os.sh." \
    "MACOS_MIN_VERSION = 14.0" \
    "ARCH = \$(shell uname -m)" >"$MAKEFILE"
  run "$MACOS_MIN_VERSION_SH" "$MAKEFILE"
  [ "$status" -eq 0 ]
  [ "$output" = "14.0" ]
}

@test "a trailing inline comment is rejected, not passed through" {
  assert_malformed "MACOS_MIN_VERSION = 14.0 # oldest supported"
}

@test "trailing whitespace is rejected" {
  assert_malformed "MACOS_MIN_VERSION = 14.0   "
}

@test "an empty assignment is rejected" {
  assert_malformed "MACOS_MIN_VERSION ="
}

@test "a missing assignment is rejected" {
  assert_malformed "ARCH = x86_64"
}

@test "two assignments are rejected rather than concatenated" {
  printf '%s\n' "MACOS_MIN_VERSION = 14.0" "MACOS_MIN_VERSION = 15.0" >"$MAKEFILE"
  run "$MACOS_MIN_VERSION_SH" "$MAKEFILE"
  [ "$status" -eq 1 ]
  [[ "$output" == *"MACOS_MIN_VERSION malformed"* ]]
}

@test "a longer variable name is not mistaken for the floor" {
  assert_malformed "MACOS_MIN_VERSION_OVERRIDE = 15.0"
}

@test "a non-numeric floor is rejected" {
  assert_malformed "MACOS_MIN_VERSION = sonoma"
}

@test "a missing makefile is an error, not an empty floor" {
  run "$MACOS_MIN_VERSION_SH" "$BATS_TEST_TMPDIR/does-not-exist"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no makefile at"* ]]
}

@test "the repo's own pkg/Makefile parses" {
  run "$MACOS_MIN_VERSION_SH"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^[0-9]+(\.[0-9]+)*$ ]]

  # Defaulting to the repo's pkg/Makefile must agree with naming it.
  run "$MACOS_MIN_VERSION_SH" "$REPO_ROOT/pkg/Makefile"
  [ "$status" -eq 0 ]
  [[ "$output" =~ ^[0-9]+(\.[0-9]+)*$ ]]
}
