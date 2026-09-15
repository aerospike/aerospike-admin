#!/usr/bin/env bats
#
# Failure-path tests for check_crypto_static_openssl.sh. `otool` is stubbed on
# PATH, so these run on any OS and on every pull request. The guard has already
# regressed to fail-open once: piped into grep under pipefail, "otool could not
# read it" and "it has no OpenSSL dylib" were indistinguishable.

setup() {
  CHECK_CRYPTO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/check_crypto_static_openssl.sh"
  STUB_DIR="$BATS_TEST_TMPDIR/bin"
  BUNDLE="$BATS_TEST_TMPDIR/bundle"
  EXTENSION="$BUNDLE/_internal/cryptography/hazmat/bindings/_rust.abi3.so"
  mkdir -p "$STUB_DIR" "$(dirname "$EXTENSION")"
  : >"$EXTENSION"

  cat >"$STUB_DIR/otool" <<'STUB'
#!/usr/bin/env bash
if [[ -n "${STUB_OTOOL_FAIL:-}" ]]; then
  echo "otool: can't map file: $*" >&2
  exit 1
fi
printf '%s\n' "${STUB_OTOOL_OUT:-}"
STUB

  chmod +x "$STUB_DIR/otool"
  PATH="$STUB_DIR:$PATH"

  unset STUB_OTOOL_FAIL
  export STUB_OTOOL_OUT="	/usr/lib/libiconv.2.dylib (compatibility version 7.0.0, current version 7.0.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)"
}

@test "a statically linked extension passes" {
  run "$CHECK_CRYPTO" "$BUNDLE"
  [ "$status" -eq 0 ]
  [[ "$output" == *"links OpenSSL statically (1 extension(s) checked)"* ]]
}

@test "a libssl dependency fails and the offending line is shown" {
  export STUB_OTOOL_OUT="	@rpath/libssl.3.dylib (compatibility version 3.0.0, current version 3.0.0)
	/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)"
  run "$CHECK_CRYPTO" "$BUNDLE"
  [ "$status" -eq 1 ]
  [[ "$output" == *"links OpenSSL dynamically"* ]]
  [[ "$output" == *"libssl.3.dylib"* ]]
  [[ "$output" == *"OPENSSL_STATIC=1"* ]]
}

@test "a libcrypto dependency fails too" {
  export STUB_OTOOL_OUT="	@rpath/libcrypto.3.dylib (compatibility version 3.0.0, current version 3.0.0)"
  run "$CHECK_CRYPTO" "$BUNDLE"
  [ "$status" -eq 1 ]
  [[ "$output" == *"links OpenSSL dynamically"* ]]
}

@test "an otool failure fails loudly instead of passing uninspected" {
  export STUB_OTOOL_FAIL=1
  run "$CHECK_CRYPTO" "$BUNDLE"
  [ "$status" -eq 1 ]
  [[ "$output" == *"otool failed on"* ]]
  [[ "$output" == *"can't map file"* ]]
  [[ "$output" != *"links OpenSSL statically"* ]]
}

@test "a bundle with no cryptography extension is an error, not a pass" {
  mkdir -p "$BATS_TEST_TMPDIR/empty"
  run "$CHECK_CRYPTO" "$BATS_TEST_TMPDIR/empty"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no cryptography _rust.abi3.so found"* ]]
}

@test "one bad extension among several still fails" {
  local second="$BUNDLE/_internal/other/_rust.abi3.so"
  mkdir -p "$(dirname "$second")"
  : >"$second"
  export STUB_OTOOL_OUT="	@rpath/libssl.3.dylib (compatibility version 3.0.0, current version 3.0.0)"
  run "$CHECK_CRYPTO" "$BUNDLE"
  [ "$status" -eq 1 ]
  [[ "$output" == *"links OpenSSL dynamically"* ]]
}

@test "several clean extensions are all counted" {
  local second="$BUNDLE/_internal/other/_rust.abi3.so"
  mkdir -p "$(dirname "$second")"
  : >"$second"
  run "$CHECK_CRYPTO" "$BUNDLE"
  [ "$status" -eq 0 ]
  [[ "$output" == *"2 extension(s) checked"* ]]
}

@test "no arguments is a usage error" {
  run "$CHECK_CRYPTO"
  [ "$status" -eq 1 ]
  [[ "$output" == *"usage:"* ]]
}
