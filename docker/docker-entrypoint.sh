#!/bin/sh
#
# Entrypoint for the Aerospike tools images.
#
# The convention across every tools image is:
#
#   docker run --rm <image> <binary> [args]
#
# because several images ship more than one binary (asadm + asinfo,
# asbackup + asrestore, and all seven in the bundle), so no single default
# is correct. Without this script, forgetting the binary name produces a
# runc error that explains nothing:
#
#   exec: "--version": executable file not found in $PATH
#
# This script turns that into usage listing the binaries the image actually
# ships. The list is generated at build time into ${TOOLS_FILE} from the
# installed package, so it stays right as the packages change.
#
set -eu

METADATA_DIR="${AEROSPIKE_METADATA_DIR:-/usr/local/share/aerospike}"
TOOLS_FILE="${METADATA_DIR}/tools"
IMAGE_INFO_FILE="${METADATA_DIR}/image-info"

# One-line description per binary. A binary with no entry here still lists,
# just without the trailing description, so a new tool never breaks usage.
describe() {
    case "$1" in
    asadm)    echo "Aerospike Admin" ;;
    asinfo)   echo "Aerospike info command-line tool" ;;
    aql)      echo "Aerospike Query Language shell" ;;
    asbackup) echo "Back up an Aerospike namespace or cluster" ;;
    asrestore) echo "Restore an Aerospike backup" ;;
    asbench)  echo "Benchmark an Aerospike cluster" ;;
    asconfig) echo "Manage Aerospike configuration files" ;;
    *)        echo "" ;;
    esac
}

tools() {
    [ -r "${TOOLS_FILE}" ] || return 0
    cat "${TOOLS_FILE}"
}

tool_count() {
    tools | grep -c . || true
}

is_tool() {
    tools | grep -qxF -- "$1"
}

usage() {
    if [ -r "${IMAGE_INFO_FILE}" ]; then
        cat "${IMAGE_INFO_FILE}"
    else
        echo "Aerospike tools image"
    fi
    echo

    if [ "$(tool_count)" -gt 1 ]; then
        echo "This image ships more than one tool, so name the one you want:"
    else
        echo "Name the tool to run:"
    fi
    echo

    width=$(tools | awk '{ if (length($0) > n) n = length($0) } END { print n + 0 }')
    first=""
    for tool in $(tools); do
        [ -n "${first}" ] || first="${tool}"
        description=$(describe "${tool}")
        if [ -n "${description}" ]; then
            printf '  docker run --rm <image> %-*s [args]   %s\n' \
                "${width}" "${tool}" "${description}"
        else
            printf '  docker run --rm <image> %-*s [args]\n' "${width}" "${tool}"
        fi
    done
    [ -n "${first}" ] || first="<binary>"

    echo
    echo "Examples:"
    echo "  docker run --rm <image> ${first} --help"
    echo "  docker run --rm -ti <image> ${first} [args]   (add -ti for interactive tools)"
    echo
    echo "For a shell inside the image:"
    echo "  docker run --rm -ti --entrypoint bash <image>"
}

if [ "$#" -eq 0 ]; then
    usage
    exit 0
fi

if is_tool "$1"; then
    exec "$@"
fi

{
    echo "Error: '$1' is not a tool shipped in this image."
    echo
    usage
} >&2
exit 127
