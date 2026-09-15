#!/usr/bin/env bats
#
# Failure-path tests for check_min_os.sh, the scan that decides whether a
# macOS payload can run on the support floor. `file` and `otool` are stubbed on
# PATH, so these run on any OS and on every pull request.
#
# The fail-open cases matter most: this scan is the only thing that ever sees
# the static OpenSSL archive members (member minos is unrecoverable once they
# are linked in), and its verdict is then cached.

setup() {
  CHECK_MIN_OS="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/check_min_os.sh"
  STUB_DIR="$BATS_TEST_TMPDIR/bin"
  PAYLOAD="$BATS_TEST_TMPDIR/payload"
  mkdir -p "$STUB_DIR" "$PAYLOAD"
  : >"$PAYLOAD/one.o"

  cat >"$STUB_DIR/file" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "${STUB_FILE_OUT:-Mach-O 64-bit object x86_64}"
STUB

  cat >"$STUB_DIR/otool" <<'STUB'
#!/usr/bin/env bash
if [[ -n "${STUB_OTOOL_FAIL:-}" ]]; then
  echo "otool: can't map file: $*" >&2
  exit 1
fi
printf '%s\n' "${STUB_OTOOL_OUT:-}"
STUB

  chmod +x "$STUB_DIR/file" "$STUB_DIR/otool"
  PATH="$STUB_DIR:$PATH"

  unset STUB_FILE_OUT STUB_OTOOL_FAIL
  export STUB_OTOOL_OUT=""
}

build_version() {
  printf 'Load command 8\n      cmd LC_BUILD_VERSION\n  cmdsize 32\n platform 1\n    minos %s\n      sdk 15.5\n' "$1"
}

version_min() {
  printf 'Load command 8\n      cmd LC_VERSION_MIN_MACOSX\n  cmdsize 16\n  version %s\n      sdk 10.9\n' "$1"
}

@test "a floor-matching object passes" {
  STUB_OTOOL_OUT="$(build_version 14.0)"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 0 ]
  [[ "$output" == *"1 Mach-O file(s) all run on macOS 14.0 or later"* ]]
}

@test "an object below the floor passes: it runs on more releases, not fewer" {
  STUB_OTOOL_OUT="$(build_version 11.0)"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 0 ]
}

@test "an object above the floor fails and is named" {
  STUB_OTOOL_OUT="$(build_version 26.0)"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 1 ]
  [[ "$output" == *"26.0"* ]]
  [[ "$output" == *"one.o"* ]]
  [[ "$output" == *"above the macOS 14.0 floor"* ]]
}

@test "the older LC_VERSION_MIN_MACOSX load command is read too" {
  STUB_OTOOL_OUT="$(version_min 26.0)"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 1 ]
  [[ "$output" == *"26.0"* ]]
}

@test "a later slice's higher floor is not hidden by an earlier compliant one" {
  STUB_OTOOL_OUT="$(build_version 14.0)
$(build_version 26.0)"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 1 ]
  [[ "$output" == *"26.0"* ]]
}

@test "the highest offending slice is the one reported" {
  STUB_OTOOL_OUT="$(build_version 26.0)
$(build_version 15.0)"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 1 ]
  [[ "$output" == *"26.0"* ]]
  [[ "$output" != *"15.0"* ]]
}

@test "version comparison is numeric, so 14.8 does not rank below 14.10" {
  STUB_OTOOL_OUT="$(build_version 14.10)"
  run "$CHECK_MIN_OS" 14.8 "$PAYLOAD"
  [ "$status" -eq 1 ]

  STUB_OTOOL_OUT="$(build_version 14.8)"
  run "$CHECK_MIN_OS" 14.10 "$PAYLOAD"
  [ "$status" -eq 0 ]
}

@test "an object with no build-version load command has no floor to violate" {
  STUB_OTOOL_OUT="Load command 0
      cmd LC_SEGMENT_64
  cmdsize 232"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 0 ]
}

@test "an otool failure fails loudly instead of counting as clean" {
  # Discarding otool's status reported an uninspected file as compliant, which
  # for the OpenSSL archive members would be the only scan they ever get.
  export STUB_OTOOL_FAIL=1
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 1 ]
  [[ "$output" == *"otool failed on"* ]]
  [[ "$output" == *"can't map file"* ]]
  [[ "$output" != *"all run on macOS"* ]]
}

@test "non-Mach-O files are skipped, and a payload of only those is an error" {
  export STUB_FILE_OUT="ASCII text"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no Mach-O files found"* ]]
}

@test "an empty payload is an error, not a pass" {
  mkdir -p "$BATS_TEST_TMPDIR/empty"
  run "$CHECK_MIN_OS" 14.0 "$BATS_TEST_TMPDIR/empty"
  [ "$status" -eq 1 ]
  [[ "$output" == *"no Mach-O files found"* ]]
}

@test "a malformed floor is rejected before anything is scanned" {
  run "$CHECK_MIN_OS" "14.0 # oldest" "$PAYLOAD"
  [ "$status" -eq 1 ]
  [[ "$output" == *"is not a macOS version"* ]]
}

@test "a missing floor or path is a usage error" {
  run "$CHECK_MIN_OS"
  [ "$status" -eq 1 ]
  [[ "$output" == *"usage:"* ]]

  run "$CHECK_MIN_OS" 14.0
  [ "$status" -eq 1 ]
  [[ "$output" == *"usage:"* ]]
}

@test "every file is scanned, not just the first" {
  : >"$PAYLOAD/two.o"
  STUB_OTOOL_OUT="$(build_version 14.0)"
  run "$CHECK_MIN_OS" 14.0 "$PAYLOAD"
  [ "$status" -eq 0 ]
  [[ "$output" == *"2 Mach-O file(s)"* ]]
}
