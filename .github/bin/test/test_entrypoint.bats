#!/usr/bin/env bats
#
# Unit tests for docker/docker-entrypoint.sh. AEROSPIKE_METADATA_DIR points the
# script at a fixture, so none of this needs a built image.

bats_require_minimum_version 1.5.0

setup() {
    ENTRY="${BATS_TEST_DIRNAME}/../../../docker/docker-entrypoint.sh"
    export AEROSPIKE_METADATA_DIR="${BATS_TEST_TMPDIR}/md"
    mkdir -p "${AEROSPIKE_METADATA_DIR}"
    printf 'asadm\nasinfo\n' > "${AEROSPIKE_METADATA_DIR}/tools"
    printf 'Aerospike tools image (aerospike-tools 0.0.0)\n' \
        > "${AEROSPIKE_METADATA_DIR}/image-info"
}

@test "no args: usage on stdout, exit 0" {
    run -0 sh "${ENTRY}"
    [[ "${output}" == *"docker run --rm <image> asadm"* ]]
    [[ "${output}" == *"docker run --rm <image> asinfo"* ]]
    [[ "${output}" == *"Aerospike tools image (aerospike-tools 0.0.0)"* ]]
}

@test "several tools: usage says to name one" {
    run -0 sh "${ENTRY}"
    [[ "${output}" == *"ships more than one tool"* ]]
}

@test "one tool: singular lede, and that tool in the examples" {
    printf 'asadm\n' > "${AEROSPIKE_METADATA_DIR}/tools"
    run -0 sh "${ENTRY}"
    [[ "${output}" == *"Name the tool to run:"* ]]
    [[ "${output}" == *"docker run --rm <image> asadm --help"* ]]
}

@test "unknown first argument: exit 127, message on stderr, nothing on stdout" {
    run -127 --separate-stderr sh "${ENTRY}" --version
    [ -z "${output}" ]
    [[ "${stderr}" == *"is not a tool shipped in this image"* ]]
}

@test "a listed tool is exec'd with its arguments intact" {
    printf 'faketool\n' > "${AEROSPIKE_METADATA_DIR}/tools"
    mkdir -p "${BATS_TEST_TMPDIR}/bin"
    printf '#!/bin/sh\nprintf "%%s\\n" "$@"\nexit 42\n' \
        > "${BATS_TEST_TMPDIR}/bin/faketool"
    chmod +x "${BATS_TEST_TMPDIR}/bin/faketool"
    PATH="${BATS_TEST_TMPDIR}/bin:${PATH}" run -42 sh "${ENTRY}" faketool -a "b c"
    [ "${lines[1]}" = "b c" ]
}

@test "missing tool list: fails loudly and names the file" {
    rm -f "${AEROSPIKE_METADATA_DIR}/tools"
    run -1 --separate-stderr sh "${ENTRY}" asadm
    [[ "${stderr}" == *"tools is missing or unreadable"* ]]
}

@test "missing image-info: usage still renders under the generic title" {
    rm -f "${AEROSPIKE_METADATA_DIR}/image-info"
    run -0 sh "${ENTRY}"
    [[ "${output}" == *"Aerospike tools image"* ]]
}
