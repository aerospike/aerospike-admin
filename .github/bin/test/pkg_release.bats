#!/usr/bin/env bats
#
# Table test for pkg_release.sh -- the single computation behind every .deb,
# .rpm, .tar and .pkg file name and every docker image tag in this repo.
#
# Unlike test_execute.bats these tests need no installed binary and no
# packaging, so they run on every pull request. The script and this file are
# shared verbatim across the tools repos; keep the copies byte-identical.

setup() {
  PKG_RELEASE="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/pkg_release.sh"
}

# assert_release <input> <pkg_version> <iteration>
assert_release() {
  local input="$1" want_version="$2" want_iteration="$3"
  local want_release="${want_version}-${want_iteration}"

  run "$PKG_RELEASE" "$input" version
  [ "$status" -eq 0 ]
  [ "$output" = "$want_version" ]

  run "$PKG_RELEASE" "$input" iteration
  [ "$status" -eq 0 ]
  [ "$output" = "$want_iteration" ]

  run "$PKG_RELEASE" "$input" release
  [ "$status" -eq 0 ]
  [ "$output" = "$want_release" ]

  run "$PKG_RELEASE" "$input" all
  [ "$status" -eq 0 ]
  [ "$output" = "PKG_VERSION=${want_version}
ITERATION=${want_iteration}
RELEASE=${want_release}" ]
}

# assert_rc_rejected <input>
assert_rc_rejected() {
  run "$PKG_RELEASE" "$1" all
  [ "$status" -eq 1 ]
  [[ "$output" == *"rc folds into the iteration"* ]]
}

@test "GA version packages as iteration 1" {
  assert_release "2.2.10" "2.2.10" "1"
}

@test "rcN folds into the iteration and leaves the version bare" {
  assert_release "2.2.10-rc2" "2.2.10" "2"
  assert_release "2.2.10-rc10" "2.2.10" "10"
}

@test "rcN is folded case-insensitively so 'rc' never reaches a name" {
  assert_release "2.2.10-RC2" "2.2.10" "2"
}

@test "a trailing identifier survives the rc fold" {
  assert_release "5.0.3-rc2-master.abc123" "5.0.3-master.abc123" "2"
}

@test "a non-rc pre-release identifier stays in the version" {
  assert_release "2.2.10-beta1" "2.2.10-beta1" "1"
  assert_release "2.2.10-abc123def" "2.2.10-abc123def" "1"
}

@test "rc must be a whole identifier, not a prefix of one" {
  # 2.2.10-rc2x is not rcN, so it must NOT be folded to 2.2.10x.
  assert_release "2.2.10-rc2x" "2.2.10-rc2x" "1"
  assert_release "2.2.10-rc2rc3" "2.2.10-rc2rc3" "1"
}

@test "git describe output is passed through untouched" {
  assert_release "2.2.9-15-gabcdef123" "2.2.9-15-gabcdef123" "1"
}

@test "rc0 is rejected: iteration 0 sorts below every other build" {
  run "$PKG_RELEASE" "2.2.10-rc0" all
  [ "$status" -eq 1 ]
  [[ "$output" == *"rc numbering starts at rc1"* ]]
}

@test "a bare -rc is rejected, not shipped in a name" {
  assert_rc_rejected "2.2.10-rc"
}

@test "an rc digit run past the bound is rejected, not passed through" {
  assert_rc_rejected "2.2.10-rc12345"
  # Must not wrap via 64-bit arithmetic onto a small iteration either.
  assert_rc_rejected "2.2.10-rc18446744073709551617"
}

@test "a second rc identifier cannot ride the trailing group into the name" {
  assert_rc_rejected "5.0.3-rc2-rc3"
  assert_rc_rejected "5.0.3-rc2-master.rc4"
}

@test "an empty version is a usage error" {
  run "$PKG_RELEASE" ""
  [ "$status" -eq 1 ]
  [[ "$output" == *"usage:"* ]]

  run "$PKG_RELEASE"
  [ "$status" -eq 1 ]
  [[ "$output" == *"usage:"* ]]
}

@test "an unparseable version is rejected, not mangled" {
  run "$PKG_RELEASE" "not-a-version" all
  [ "$status" -eq 1 ]
  [[ "$output" == *"unparseable version"* ]]
}

@test "an unknown field is rejected" {
  run "$PKG_RELEASE" "2.2.10" bogus
  [ "$status" -eq 1 ]
  [[ "$output" == *"unknown field"* ]]
}

@test "rc01 and rc1 agree, so one rc cannot name two packages" {
  a="$("$PKG_RELEASE" "2.2.10-rc1" release)"
  # rc01 is rejected upstream by validate-inputs, but the fold must still be
  # base-10 rather than octal if one ever reaches here.
  b="$("$PKG_RELEASE" "2.2.10-rc01" release)"
  [ "$a" = "$b" ]
}
