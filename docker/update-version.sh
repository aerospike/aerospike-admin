#!/usr/bin/env bash
#
# update-version.sh
#
# Updates the version, download URLs, and SHA256 checksums in the asadm Dockerfiles.
#
# JFrog URL structure:
#   DEB: {deb-base}/pool/{ubuntu-codename}/aerospike-asadm/{filename}
#        e.g. .../pool/noble/aerospike-asadm/aerospike-asadm_5.0.0-rc1_ubuntu24.04_x86_64.deb
#   RPM: {rpm-base}/{el-version}/{arch}/{filename}
#        e.g. .../el10/aarch64/aerospike-asadm-5.0.0_rc1.el10.aarch64.rpm
#
# Usage:
#   ./docker/update-version.sh --version VERSION [OPTIONS]
#
# Required:
#   --version VERSION       asadm version, e.g. 5.0.0 or 5.0.0-rc1
#
# Source options:
#   --packages-dir DIR      Local directory to search for built packages.
#                           Packages are discovered by name pattern (version + OS + arch).
#                           SHA256 is computed automatically from the found files.
#                           Use --deb-base-url / --rpm-base-url to set the URLs written
#                           into Dockerfiles (pointing to where packages will be hosted).
#
#   --compute-sha           Download each package from the resolved URL and compute
#                           its SHA256 checksum (only used without --packages-dir).
#
# URL override options:
#   --deb-base-url URL      Base URL for DEB packages.
#                           Default: https://aerospike.jfrog.io/artifactory/database-deb-dev-local
#                           Full URL: {deb-base}/pool/{codename}/aerospike-asadm/{filename}
#
#   --rpm-base-url URL      Base URL for RPM packages.
#                           Default: https://aerospike.jfrog.io/artifactory/database-rpm-dev-local
#                           Full URL: {rpm-base}/{el-version}/{arch}/{filename}
#
# Other options:
#   --dry-run               Print resolved values without modifying any Dockerfile.
#   -h, --help              Show this help message.
#
# Examples:
#   # Local packages dir → auto-discover files, compute SHA256, write JFrog dev URLs:
#   ./docker/update-version.sh --version 5.0.0-rc1 --packages-dir /path/to/pkgs
#
#   # Local dir with custom JFrog repo (e.g. staging):
#   ./docker/update-version.sh --version 5.0.0-rc1 \
#       --packages-dir /path/to/pkgs \
#       --deb-base-url https://aerospike.jfrog.io/artifactory/database-deb-staging-local \
#       --rpm-base-url https://aerospike.jfrog.io/artifactory/database-rpm-staging-local
#
#   # Remote URL, no SHA256 (fastest):
#   ./docker/update-version.sh --version 5.0.0-rc1
#
#   # Remote URL + download to compute SHA256:
#   ./docker/update-version.sh --version 5.0.0-rc1 --compute-sha
#
#   # Preview without modifying files:
#   ./docker/update-version.sh --version 5.0.0-rc1 --packages-dir /path/to/pkgs --dry-run

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
VERSION=""
PACKAGES_DIR=""
COMPUTE_SHA=false
DRY_RUN=false

DEB_BASE_URL="https://aerospike.jfrog.io/artifactory/database-deb-dev-local"
RPM_BASE_URL="https://aerospike.jfrog.io/artifactory/database-rpm-dev-local"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)       VERSION="$2";       shift 2 ;;
        --packages-dir)  PACKAGES_DIR="$2";  shift 2 ;;
        --deb-base-url)  DEB_BASE_URL="$2";  shift 2 ;;
        --rpm-base-url)  RPM_BASE_URL="$2";  shift 2 ;;
        --compute-sha)   COMPUTE_SHA=true;   shift ;;
        --dry-run)       DRY_RUN=true;       shift ;;
        -h|--help)
            grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1" >&2
            echo "Run with --help for usage." >&2
            exit 1
            ;;
    esac
done

[[ -n "${VERSION}" ]] || { echo "ERROR: --version is required." >&2; exit 1; }

# RPM versions replace hyphens with underscores (5.0.0-rc1 → 5.0.0_rc1)
RPM_VERSION="${VERSION//-/_}"

# Ubuntu 24.04 codename (for DEB pool path)
UBUNTU2404_CODENAME="noble"

# ---------------------------------------------------------------------------
# Package filenames
# ---------------------------------------------------------------------------
PKG_UBUNTU2404_AMD64="aerospike-asadm_${VERSION}_ubuntu24.04_x86_64.deb"
PKG_UBUNTU2404_ARM64="aerospike-asadm_${VERSION}_ubuntu24.04_aarch64.deb"
PKG_EL10_AMD64="aerospike-asadm-${RPM_VERSION}.el10.x86_64.rpm"
PKG_EL10_ARM64="aerospike-asadm-${RPM_VERSION}.el10.aarch64.rpm"

# ---------------------------------------------------------------------------
# Construct download URLs
# ---------------------------------------------------------------------------
DEB_POOL="${DEB_BASE_URL}/pool/${UBUNTU2404_CODENAME}/aerospike-asadm"

URL_UBUNTU2404_AMD64="${DEB_POOL}/${PKG_UBUNTU2404_AMD64}"
URL_UBUNTU2404_ARM64="${DEB_POOL}/${PKG_UBUNTU2404_ARM64}"
URL_EL10_AMD64="${RPM_BASE_URL}/el10/x86_64/${PKG_EL10_AMD64}"
URL_EL10_ARM64="${RPM_BASE_URL}/el10/aarch64/${PKG_EL10_ARM64}"

# ---------------------------------------------------------------------------
# Helper: find a package file in a directory (resolves symlinks like /tmp → /private/tmp)
# ---------------------------------------------------------------------------
find_package() {
    local dir="$1" filename="$2"
    local real_dir
    real_dir=$(cd "${dir}" && pwd -P)
    find -L "${real_dir}" -maxdepth 3 -name "${filename}" -type f 2>/dev/null | head -1
}

# ---------------------------------------------------------------------------
# Helper: SHA256 of a local file
# ---------------------------------------------------------------------------
sha256_of() {
    if command -v sha256sum &>/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

# ---------------------------------------------------------------------------
# Helper: download a URL to a temp file and return its SHA256
# ---------------------------------------------------------------------------
sha256_of_url() {
    local url="$1"
    local tmp
    tmp=$(mktemp)
    echo "  Downloading for SHA256: $(basename "${url}")" >&2
    if ! curl -fsSL --retry 3 --retry-delay 3 "${url}" -o "${tmp}" 2>/dev/null; then
        echo "  WARNING: Download failed — SHA256 set to PLACEHOLDER" >&2
        rm -f "${tmp}"
        echo "PLACEHOLDER"
        return
    fi
    local sha
    sha=$(sha256_of "${tmp}")
    rm -f "${tmp}"
    echo "${sha}"
}

# ---------------------------------------------------------------------------
# Resolve SHA256 values
# ---------------------------------------------------------------------------
resolve_sha() {
    local pkg_name="$1" url="$2"

    if [[ -n "${PACKAGES_DIR}" ]]; then
        local filepath
        filepath=$(find_package "${PACKAGES_DIR}" "${pkg_name}")
        if [[ -z "${filepath}" ]]; then
            echo "  WARNING: Not found in '${PACKAGES_DIR}': ${pkg_name}" >&2
            echo "PLACEHOLDER"
        else
            echo "  Found: ${filepath}" >&2
            sha256_of "${filepath}"
        fi
    elif [[ "${COMPUTE_SHA}" == true ]]; then
        sha256_of_url "${url}"
    else
        echo "PLACEHOLDER"
    fi
}

# ---------------------------------------------------------------------------
# Helper: update one Dockerfile in-place
# ---------------------------------------------------------------------------
update_dockerfile() {
    local file="$1"
    local amd64_url="$2" amd64_sha="$3"
    local arm64_url="$4" arm64_sha="$5"

    [[ -f "${file}" ]] || { echo "ERROR: Dockerfile not found: ${file}" >&2; exit 1; }

    if [[ "${DRY_RUN}" == true ]]; then
        printf "  [dry-run] %s\n" "${file}"
        printf "    AMD64  URL: %s\n" "${amd64_url}"
        printf "    AMD64  SHA: %s\n" "${amd64_sha}"
        printf "    ARM64  URL: %s\n" "${arm64_url}"
        printf "    ARM64  SHA: %s\n" "${arm64_sha}"
        return
    fi

    sed -i.bak \
        -e "s|^ARG ASADM_AMD64_URL=.*|ARG ASADM_AMD64_URL=\"${amd64_url}\"|" \
        -e "s|^ARG ASADM_AMD64_SHA256=.*|ARG ASADM_AMD64_SHA256=\"${amd64_sha}\"|" \
        -e "s|^ARG ASADM_ARM64_URL=.*|ARG ASADM_ARM64_URL=\"${arm64_url}\"|" \
        -e "s|^ARG ASADM_ARM64_SHA256=.*|ARG ASADM_ARM64_SHA256=\"${arm64_sha}\"|" \
        "${file}"
    rm -f "${file}.bak"
    echo "  Updated: ${file}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
echo "Version:      ${VERSION}"
echo "DEB base URL: ${DEB_BASE_URL}"
echo "RPM base URL: ${RPM_BASE_URL}"
[[ -n "${PACKAGES_DIR}" ]] && echo "Packages dir: ${PACKAGES_DIR}"
[[ "${COMPUTE_SHA}" == true ]] && echo "(will download packages to compute SHA256)"
echo ""

# Resolve SHAs
SHA_UBUNTU2404_AMD64=$(resolve_sha "${PKG_UBUNTU2404_AMD64}" "${URL_UBUNTU2404_AMD64}")
SHA_UBUNTU2404_ARM64=$(resolve_sha "${PKG_UBUNTU2404_ARM64}" "${URL_UBUNTU2404_ARM64}")
SHA_EL10_AMD64=$(resolve_sha "${PKG_EL10_AMD64}" "${URL_EL10_AMD64}")
SHA_EL10_ARM64=$(resolve_sha "${PKG_EL10_ARM64}" "${URL_EL10_ARM64}")

echo ""
echo "Ubuntu 24.04 Dockerfile:"
update_dockerfile \
    "${SCRIPT_DIR}/ubuntu24.04/Dockerfile" \
    "${URL_UBUNTU2404_AMD64}" "${SHA_UBUNTU2404_AMD64}" \
    "${URL_UBUNTU2404_ARM64}" "${SHA_UBUNTU2404_ARM64}"

echo ""
echo "UBI 10 Dockerfile:"
update_dockerfile \
    "${SCRIPT_DIR}/ubi10/Dockerfile" \
    "${URL_EL10_AMD64}" "${SHA_EL10_AMD64}" \
    "${URL_EL10_ARM64}" "${SHA_EL10_ARM64}"

echo ""
if [[ "${DRY_RUN}" == true ]]; then
    echo "Dry run complete. No files were modified."
else
    if [[ "${SHA_UBUNTU2404_AMD64}" == "PLACEHOLDER" || \
          "${SHA_UBUNTU2404_ARM64}" == "PLACEHOLDER" || \
          "${SHA_EL10_AMD64}"       == "PLACEHOLDER" || \
          "${SHA_EL10_ARM64}"       == "PLACEHOLDER" ]]; then
        echo "NOTE: One or more SHA256 checksums are PLACEHOLDER."
        echo "      SHA256 verification will be skipped at Docker build time."
        echo "      Use --packages-dir <dir> or --compute-sha to enable verification."
        echo ""
    fi
    echo "Done."
fi
