#!/bin/sh
#
# Entrypoint for the Aerospike tools images (identical in every tools repo).
#
# Convention:   docker run --rm <image> <binary> [args]
#
# Several images ship more than one binary (asadm + asinfo, asbackup +
# asrestore, all seven in the bundle), so there is no default binary and no
# CMD. This script only fixes the failure mode: without it, forgetting the
# binary name yields a runc error that explains nothing --
#   exec: "--version": executable file not found in $PATH
#
# Rules (postgres / docker:cli style helper that ends in a passthrough):
#   no arguments                     usage on stdout, exit 0
#   first argument empty or "-..."   error + usage on stderr, exit 127
#   first argument not resolvable    error + usage on stderr, exit 127
#   anything else                    exec "$@"   (the tool becomes PID 1)
#
# It is a passthrough, not an allow-list: `docker run <image> bash` works, as
# does anything on PATH or any path. 127 is what runc returned before, so
# scripts that checked for it keep working.
#
# The usage text lists the binaries recorded at build time in
#   ${AEROSPIKE_METADATA_DIR:-/usr/local/share/aerospike}/tools   (one per line)
# under the title in .../image-info. Those files only feed the usage text:
# they never gate execution, and usage still prints if they are missing.
# AEROSPIKE_METADATA_DIR exists so the bats tests can point the script at a
# fixture; it is internal, not a supported interface of the image.
#
set -eu

METADATA_DIR="${AEROSPIKE_METADATA_DIR:-/usr/local/share/aerospike}"
TOOLS_FILE="${METADATA_DIR}/tools"
IMAGE_INFO_FILE="${METADATA_DIR}/image-info"

# One-line description per binary. A binary with no entry still lists, just
# without the trailing description, so a new tool never breaks usage.
describe() {
    case "$1" in
    asadm)     echo "Aerospike Admin" ;;
    asinfo)    echo "Aerospike info command-line tool" ;;
    aql)       echo "Aerospike Query Language shell" ;;
    asbackup)  echo "Back up an Aerospike namespace or cluster" ;;
    asrestore) echo "Restore an Aerospike backup" ;;
    asbench)   echo "Benchmark an Aerospike cluster" ;;
    asconfig)  echo "Manage Aerospike configuration files" ;;
    *)         echo "" ;;
    esac
}

# Recorded tool names, one per line; tolerates CRLF and blank lines and
# prints nothing when the file is missing or empty.
tools() {
    [ -r "${TOOLS_FILE}" ] || return 0
    tr -d '\r' < "${TOOLS_FILE}" | grep . || true
}

usage() {
    if [ -r "${IMAGE_INFO_FILE}" ]; then
        cat "${IMAGE_INFO_FILE}"
    else
        echo "Aerospike tools image"
    fi
    echo

    # Positional parameters are local to a function in POSIX sh, so this
    # does not disturb the caller's "$@".
    # shellcheck disable=SC2046
    set -- $(tools)
    if [ "$#" -gt 1 ]; then
        echo "This image ships more than one tool, so name the one you want:"
    else
        echo "Name the tool to run:"
    fi
    echo
    [ "$#" -gt 0 ] || set -- '<binary>'

    width=0
    for tool in "$@"; do
        [ "${#tool}" -le "${width}" ] || width="${#tool}"
    done
    for tool in "$@"; do
        description="$(describe "${tool}")"
        if [ -n "${description}" ]; then
            printf '  docker run --rm <image> %-*s [args]   %s\n' \
                "${width}" "${tool}" "${description}"
        else
            printf '  docker run --rm <image> %-*s [args]\n' "${width}" "${tool}"
        fi
    done

    echo
    echo "Examples:"
    echo "  docker run --rm <image> $1 --help"
    echo "  docker run --rm -ti <image> $1 [args]   (add -ti for interactive tools)"
    echo
    echo "For a shell inside the image:"
    echo "  docker run --rm -ti --entrypoint bash <image>"
}

fail() {
    {
        echo "Error: $1"
        echo
        usage
    } >&2
    exit 127
}

if [ "$#" -eq 0 ]; then
    usage
    exit 0
fi

# This guard must run before command -v: in dash `command -v --` succeeds
# with no output and `command -v -h` is a usage error, so an option in $1
# must never reach it.
case "$1" in
-*) fail "'$1' is an option, not a binary. Name the binary first: docker run --rm <image> <binary> $1" ;;
"") fail "the first argument is empty; name the binary to run." ;;
esac

command -v "$1" > /dev/null 2>&1 \
    || fail "'$1' is not an executable in this image."

exec "$@"
