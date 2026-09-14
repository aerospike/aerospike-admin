#!/usr/bin/env bats
#
# Unit tests for docker/docker-entrypoint.sh, the tools image's help entrypoint
# (TOOLS-4360). AEROSPIKE_METADATA_DIR points the script at a fixture, so none
# of this needs a built image; the release workflow's docker smoke test runs
# the same contract against the real one.
#
# The script is invoked as `sh <path>` rather than executed: /bin/sh is dash on
# the ubuntu runner, so this catches bashisms, and it keeps the test independent
# of the file's exec bit (the Dockerfile pins that with COPY --chmod).
#
# Contract pinned here:
#   no arguments                 -> usage on stdout, exit 0
#   first argument starts "-"    -> error + usage on stderr, stdout empty, exit 127
#   first argument not runnable  -> error + usage on stderr, stdout empty, exit 127
#   anything else                -> exec'd as given (passthrough), status propagated
# The tool list and image-info only feed the usage text; exec never reads them.
#
# Shared verbatim across the tools repos; keep the copies byte-identical.

bats_require_minimum_version 1.5.0

setup() {
    ENTRY="${BATS_TEST_DIRNAME}/../../../docker/docker-entrypoint.sh"
    export AEROSPIKE_METADATA_DIR="${BATS_TEST_TMPDIR}/md"
    mkdir -p "${AEROSPIKE_METADATA_DIR}"
    printf 'asadm\nasinfo\n' > "${AEROSPIKE_METADATA_DIR}/tools"
    printf 'Aerospike tools image (aerospike-tools 0.0.0)\n' \
        > "${AEROSPIKE_METADATA_DIR}/image-info"

    # A stand-in tool: prints its arguments one per line and exits 42, so both
    # argument passing and exit-status propagation are observable.
    FAKE_BIN="${BATS_TEST_TMPDIR}/bin"
    mkdir -p "${FAKE_BIN}"
    printf '#!/bin/sh\nprintf "%%s\\n" "$@"\nexit 42\n' > "${FAKE_BIN}/faketool"
    chmod +x "${FAKE_BIN}/faketool"
}

# usage_lists <text> <tool>: the per-tool line, anchored, so a name that merely
# appears in prose does not pass.
usage_lists() {
    grep -qE "^  docker run --rm <image> $2( |\$)" <<<"$1"
}

@test "no args: usage on stdout, exit 0, title first, every tool listed, shell hint" {
    run -0 --separate-stderr sh "${ENTRY}"
    [ -z "${stderr}" ]
    [ "${lines[0]}" = "Aerospike tools image (aerospike-tools 0.0.0)" ]
    usage_lists "${output}" asadm
    usage_lists "${output}" asinfo
    [[ "${output}" == *"--entrypoint bash"* ]]
}

@test "several tools: the lede says to name one" {
    run -0 sh "${ENTRY}"
    [[ "${output}" == *"This image ships more than one tool, so name the one you want:"* ]]
}

@test "one tool: singular lede, and that tool in the examples" {
    printf 'asadm\n' > "${AEROSPIKE_METADATA_DIR}/tools"
    run -0 sh "${ENTRY}"
    [[ "${output}" == *"Name the tool to run:"* ]]
    [[ "${output}" != *"more than one tool"* ]]
    [[ "${output}" == *"docker run --rm <image> asadm --help"* ]]
}

@test "CRLF and blank lines in the tool list are tolerated" {
    printf 'asadm\r\n\r\nasinfo\n\n' > "${AEROSPIKE_METADATA_DIR}/tools"
    run -0 sh "${ENTRY}"
    [[ "${output}" == *"more than one tool"* ]]
    usage_lists "${output}" asadm
    usage_lists "${output}" asinfo
}

@test "first argument starting with '-': exit 127, error and usage on stderr, stdout empty" {
    run -127 --separate-stderr sh "${ENTRY}" --version
    [ -z "${output}" ]
    [[ "${stderr}" == *"Error: '--version' is an option, not a binary. Name the binary first: docker run --rm <image> <binary> --version"* ]]
    usage_lists "${stderr}" asadm

    run -127 --separate-stderr sh "${ENTRY}" -h
    [ -z "${output}" ]
    [[ "${stderr}" == *"Error: '-h' is an option, not a binary."* ]]

    run -127 --separate-stderr sh "${ENTRY}" --
    [ -z "${output}" ]
    [[ "${stderr}" == *"Error: '--' is an option, not a binary."* ]]
}

@test "empty first argument: exit 127, error and usage on stderr" {
    run -127 --separate-stderr sh "${ENTRY}" ""
    [ -z "${output}" ]
    [[ "${stderr}" == *"Error: the first argument is empty; name the binary to run."* ]]
    usage_lists "${stderr}" asadm
}

@test "first argument that is not an executable: exit 127, error and usage on stderr, stdout empty" {
    run -127 --separate-stderr sh "${ENTRY}" no-such-tool --version
    [ -z "${output}" ]
    [[ "${stderr}" == *"Error: 'no-such-tool' is not an executable in this image."* ]]
    usage_lists "${stderr}" asinfo
}

@test "a listed tool is exec'd with its arguments intact and its exit status propagated" {
    printf 'faketool\n' > "${AEROSPIKE_METADATA_DIR}/tools"
    PATH="${FAKE_BIN}:${PATH}" run -42 --separate-stderr sh "${ENTRY}" faketool -a "b c"
    [ -z "${stderr}" ]
    [ "${#lines[@]}" -eq 2 ]
    [ "${lines[0]}" = "-a" ]
    [ "${lines[1]}" = "b c" ]
}

@test "passthrough: an executable not in the tool list is exec'd as given" {
    run -3 --separate-stderr sh "${ENTRY}" sh -c 'exit 3'
    [ -z "${output}" ]
    [ -z "${stderr}" ]

    run -0 sh "${ENTRY}" env FOO=bar sh -c 'printf %s "$FOO"'
    [ "${output}" = "bar" ]
}

@test "passthrough: an absolute path is exec'd, not matched by basename" {
    run -42 sh "${ENTRY}" "${FAKE_BIN}/faketool" x
    [ "${lines[0]}" = "x" ]
}

@test "missing tool list: generic usage, exit 0, and exec is unaffected" {
    rm -f "${AEROSPIKE_METADATA_DIR}/tools"
    run -0 --separate-stderr sh "${ENTRY}"
    [ "${lines[0]}" = "Aerospike tools image (aerospike-tools 0.0.0)" ]
    [[ "${output}" == *"Name the tool to run:"* ]]
    usage_lists "${output}" '<binary>'
    [[ "${output}" == *"--entrypoint bash"* ]]
    [[ "${output}" != *"docker run --rm <image> asadm"* ]]

    run -3 sh "${ENTRY}" sh -c 'exit 3'
}

@test "missing image-info: usage renders under the generic title" {
    rm -f "${AEROSPIKE_METADATA_DIR}/image-info"
    run -0 sh "${ENTRY}"
    [ "${lines[0]}" = "Aerospike tools image" ]
}
