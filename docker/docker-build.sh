#!/usr/bin/env bash
#
# docker/docker-build.sh
#
# Build multi-architecture Docker images for Aerospike asadm.
#
# Flow:
#   1. Resolve .deb URLs and SHA256s for VERSION (local dir or remote URL).
#   2. Generate docker-bake.hcl with test and push targets that pass those
#      URLs/SHAs as build args.
#   3. Build with docker buildx bake.
#
# Modes:
#   -t   Test: build and load locally (one image per arch, --load compatible)
#   -p   Push: build and push to registry (multi-arch, or single-arch when -a selects one arch)
#   -M   Manifest: stitch per-arch tags into a multi-arch manifest (buildx imagetools create; pushes by default)
#

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BAKE_FILE="docker-bake.hcl"

DEFAULT_DEB_BASE_URL="https://aerospike.jfrog.io/artifactory/database-deb-dev-local"
UBUNTU_CODENAME="noble"

# ---------------------------------------------------------------------------
# Logging — all to stderr so functions called as $(...) can return stdout cleanly
# ---------------------------------------------------------------------------
log_info()    { printf '\e[36m[INFO]\e[0m  %s\n' "$*" >&2; }
log_success() { printf '\e[32m[OK]\e[0m    %s\n' "$*" >&2; }
log_warn()    { printf '\e[33m[WARN]\e[0m  %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
function usage() {
  cat <<'EOF'
Usage: docker/docker-build.sh -t|-p|-M -v VERSION [OPTIONS]

Build the Aerospike asadm distroless Docker image (single recipe; multi-arch).

MODES (one required):
    -t               Test mode: build and load locally (one image per arch)
    -p               Push mode: build and push images (see -a below)
    -M, --manifest   Create/push multi-arch manifest from existing per-arch tags (imagetools)

REQUIRED:
    -v, --version VERSION   asadm version, e.g. 5.0.0 or 5.0.0-rc1

OPTIONS:
    -r, --registry REG      Registry prefix for image tags (default: aerospike)
                            Repeat for multiple registries: -r reg1 -r reg2
                            Example: -r artifact.aerospike.io/database-docker-dev-local
    -a, --arch ARCH         Filter arch; repeat for multiple (default: all)
                            Values: amd64, arm64
                            Test (-t): limits test bake targets.
                            Push (-p): if exactly one arch is selected, pushes a single-platform
                            image tagged <version>-<arch> (native CI matrix + -M).
                            If both arches (default), push uses one multi-platform target.
    -u, --packages-url URL_OR_PATH
                            Package source — local dir or JFrog base URL:
                              Local:  -u /path/to/dist  (sets --packages-dir)
                              Remote: -u https://aerospike.jfrog.io/artifactory/database-deb-dev-local
                                      (sets --deb-base-url)
    --packages-dir DIR      Explicit local packages dir. .deb is copied into the build
                            context and SHA256 is computed from the local file.
    --deb-base-url URL      Explicit DEB base URL (default: JFrog dev repo).
    -T, --timestamp TS      Override the timestamp appended to push tags (default: current UTC time,
                            format YYYYMMDDHHmmSS, e.g. 20260421153000)
    -s, --compute-sha       Download each .deb from the resolved URL to compute SHA256
                            (only meaningful without --packages-dir; otherwise SHA is
                            computed from the local file).
    -n, --no-cache          Disable Docker build cache
    -N, --dry-run           Resolve URLs/SHAs and print, then exit (no bake, no build).
    -h, --help              Show this help message

TAGS PRODUCED:
  Test mode (loaded locally):
    <reg>/aerospike-asadm:<version>-<arch>
    e.g. aerospike/aerospike-asadm:5.0.0-amd64

  Push mode — multi-arch (default, both arches):
    <reg>/aerospike-asadm:<version>
    <reg>/aerospike-asadm:<version>-<timestamp>   (when -T is set)

  Push mode — single arch (-a once): per-arch tag (native CI matrix):
    <reg>/aerospike-asadm:<version>-<arch>

EXAMPLES:
    # Build + load using local packages dir
    docker/docker-build.sh -t -v 5.0.0-rc1 -u /path/to/dist

    # Build + load from JFrog dev (single -u sets the DEB base URL)
    docker/docker-build.sh -t -v 5.0.0-rc1 \
        -u https://aerospike.jfrog.io/artifactory/database-deb-dev-local

    # Build + load, download package to compute SHA256
    docker/docker-build.sh -t -v 5.0.0 -s

    # Build + push to default registry (docker.io/aerospike/aerospike-asadm)
    docker/docker-build.sh -p -v 5.0.0

    # Build + push to JFrog dev registry with dev package source
    docker/docker-build.sh -p -v 5.0.0 \
        -r artifact.aerospike.io/database-docker-dev-local \
        -u https://aerospike.jfrog.io/artifactory/database-deb-dev-local

    # Push to multiple registries simultaneously
    docker/docker-build.sh -p -v 5.0.0 \
        -r aerospike \
        -r artifact.aerospike.io/database-docker-dev-local

    # Build + test only amd64
    docker/docker-build.sh -t -v 5.0.0 -a amd64

    # Stitch manifest after native per-arch pushes
    docker/docker-build.sh -M -v 5.0.0 \
        -r artifact.aerospike.io/database-docker-dev-local

OUTPUT:
    docker/docker-bake.hcl   Generated bake file (gitignored, not committed)
EOF
}

# ---------------------------------------------------------------------------
# SHA256 helpers
# ---------------------------------------------------------------------------
sha256_of_file() {
  if command -v sha256sum &>/dev/null; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha256_of_url() {
  local url="$1"
  local tmp
  tmp=$(mktemp)
  log_info "  Downloading for SHA256: $(basename "${url}")"
  if ! curl -fsSL --retry 3 --retry-delay 3 "${url}" -o "${tmp}" 2>/dev/null; then
    log_warn "  Download failed — SHA256 set to PLACEHOLDER"
    rm -f "${tmp}"
    printf 'PLACEHOLDER'
    return
  fi
  sha256_of_file "${tmp}"
  rm -f "${tmp}"
}

find_package() {
  local dir="$1" filename="$2"
  local real_dir
  real_dir=$(cd "${dir}" && pwd -P)
  find -L "${real_dir}" -maxdepth 3 -name "${filename}" -type f 2>/dev/null | head -1
}

# ---------------------------------------------------------------------------
# Bake file emitters — write to stdout; caller redirects to BAKE_FILE
# ---------------------------------------------------------------------------

# _emit_args: print an `args = { ... }` block for a target. Args are passed
# as alternating KEY VALUE; values are skipped when empty so we don't emit
# stale ARGs into the bake file.
function _emit_args() {
  local pairs=("$@")
  local i n=${#pairs[@]}
  local emitted=()
  for ((i = 0; i < n; i += 2)); do
    local key="${pairs[$i]}" val="${pairs[$((i + 1))]}"
    [[ -z "${val}" ]] && continue
    emitted+=("${key}" "${val}")
  done
  [[ ${#emitted[@]} -eq 0 ]] && return
  echo "  args = {"
  local m=${#emitted[@]}
  for ((i = 0; i < m; i += 2)); do
    echo "    ${emitted[$i]} = \"${emitted[$((i + 1))]}\""
  done
  echo "  }"
}

# _emit_tags TAG [TAG ...]
function _emit_tags() {
  local tags=("$@")
  local n=${#tags[@]}
  echo "  tags = ["
  for ((i = 0; i < n; i++)); do
    if [[ $i -lt $((n - 1)) ]]; then
      echo "    \"${tags[$i]}\","
    else
      echo "    \"${tags[$i]}\""
    fi
  done
  echo "  ]"
}

# _emit_test_target NAME ARCH LOCAL_PKG TAGS...
# Single-arch test target. URL/SHA args are passed for the active arch.
function _emit_test_target() {
  local name="$1" arch="$2" local_pkg="$3"
  shift 3
  local tags=("$@")
  echo "target \"${name}\" {"
  echo "  context    = \".\""
  echo "  dockerfile = \"Dockerfile\""
  echo "  platforms  = [\"linux/${arch}\"]"
  if [[ "${arch}" == "amd64" ]]; then
    _emit_args \
      ASADM_AMD64_URL "${ASADM_AMD64_URL}" \
      ASADM_AMD64_SHA256 "${ASADM_AMD64_SHA256}" \
      ASADM_LOCAL_PKG "${local_pkg}"
  else
    _emit_args \
      ASADM_ARM64_URL "${ASADM_ARM64_URL}" \
      ASADM_ARM64_SHA256 "${ASADM_ARM64_SHA256}" \
      ASADM_LOCAL_PKG "${local_pkg}"
  fi
  _emit_tags "${tags[@]}"
  echo "}"
  echo ""
}

# _emit_push_target NAME LOCAL_PKG_AMD64 LOCAL_PKG_ARM64 TAGS...
# Multi-arch push target (always linux/amd64 + linux/arm64).
function _emit_push_target() {
  local name="$1" local_pkg_amd64="$2" local_pkg_arm64="$3"
  shift 3
  local tags=("$@")
  echo "target \"${name}\" {"
  echo "  context    = \".\""
  echo "  dockerfile = \"Dockerfile\""
  echo "  platforms  = [\"linux/amd64\", \"linux/arm64\"]"
  _emit_args \
    ASADM_AMD64_URL "${ASADM_AMD64_URL}" \
    ASADM_AMD64_SHA256 "${ASADM_AMD64_SHA256}" \
    ASADM_ARM64_URL "${ASADM_ARM64_URL}" \
    ASADM_ARM64_SHA256 "${ASADM_ARM64_SHA256}" \
    ASADM_LOCAL_PKG_AMD64 "${local_pkg_amd64}" \
    ASADM_LOCAL_PKG_ARM64 "${local_pkg_arm64}"
  _emit_tags "${tags[@]}"
  echo "}"
  echo ""
}

# _emit_single_arch_push_target NAME ARCH LOCAL_PKG TAGS...
# Single-arch push target (native CI matrix; tag includes arch).
function _emit_single_arch_push_target() {
  local name="$1" arch="$2" local_pkg="$3"
  shift 3
  local tags=("$@")
  echo "target \"${name}\" {"
  echo "  context    = \".\""
  echo "  dockerfile = \"Dockerfile\""
  echo "  platforms  = [\"linux/${arch}\"]"
  if [[ "${arch}" == "amd64" ]]; then
    _emit_args \
      ASADM_AMD64_URL "${ASADM_AMD64_URL}" \
      ASADM_AMD64_SHA256 "${ASADM_AMD64_SHA256}" \
      ASADM_LOCAL_PKG_AMD64 "${local_pkg}"
  else
    _emit_args \
      ASADM_ARM64_URL "${ASADM_ARM64_URL}" \
      ASADM_ARM64_SHA256 "${ASADM_ARM64_SHA256}" \
      ASADM_LOCAL_PKG_ARM64 "${local_pkg}"
  fi
  _emit_tags "${tags[@]}"
  echo "}"
  echo ""
}

# _emit_group NAME TARGET [TARGET ...]
function _emit_group() {
  local name="$1"
  shift
  local targets=("$@")
  local list
  list=$(printf '"%s", ' "${targets[@]}")
  list="${list%, }"
  echo "group \"${name}\" { targets = [${list}] }"
  echo ""
}

# ---------------------------------------------------------------------------
# run_manifest_mode: stitch per-arch tags into multi-arch manifest(s)
# Requires global VERSION, REGISTRY_PREFIXES
# ---------------------------------------------------------------------------
function run_manifest_mode() {
  log_info "=== Creating multi-arch manifest (imagetools) ==="
  for reg in "${REGISTRY_PREFIXES[@]}"; do
    local src_amd64 src_arm64 target_tag
    src_amd64="${reg}/aerospike-asadm:${VERSION}-amd64"
    src_arm64="${reg}/aerospike-asadm:${VERSION}-arm64"
    target_tag="${reg}/aerospike-asadm:${VERSION}"
    log_info "imagetools create ${target_tag}"
    docker buildx imagetools create \
      -t "${target_tag}" \
      "${src_amd64}" \
      "${src_arm64}"
    docker buildx imagetools inspect "${target_tag}"
  done
  log_success "Manifest(s) pushed."
}

# ---------------------------------------------------------------------------
# generate_bake: write docker-bake.hcl
# Reads globals: VERSION, REGISTRY_PREFIXES, ACTIVE_ARCHES, PUSH_SINGLE_ARCH,
#                ASADM_*_URL, ASADM_*_SHA256, LOCAL_PKG_*
# ---------------------------------------------------------------------------
function generate_bake() {
  log_info "Generating ${BAKE_FILE}..."

  local test_target_names=()
  local push_target_names=()

  {
    echo "# Generated by docker/docker-build.sh — do not edit by hand."
    echo ""
    echo "variable \"VERSION\" { default = \"${VERSION}\" }"
    echo ""

    # ---- Test targets (single-arch, --load compatible) ----
    for arch in "${ACTIVE_ARCHES[@]}"; do
      local local_pkg=""
      if [[ "${arch}" == "amd64" ]]; then local_pkg="${LOCAL_PKG_AMD64}"; fi
      if [[ "${arch}" == "arm64" ]]; then local_pkg="${LOCAL_PKG_ARM64}"; fi
      local tags=()
      for reg in "${REGISTRY_PREFIXES[@]}"; do
        tags+=("${reg}/aerospike-asadm:${VERSION}-${arch}")
      done
      _emit_test_target "test-${arch}" "${arch}" "${local_pkg}" "${tags[@]}"
      test_target_names+=("test-${arch}")
    done

    # ---- Push targets ----
    if [[ "${PUSH_SINGLE_ARCH:-false}" == true ]]; then
      local arch="${ACTIVE_ARCHES[0]}"
      local push_pkg=""
      if [[ "${arch}" == "amd64" ]]; then push_pkg="${LOCAL_PKG_AMD64}"; fi
      if [[ "${arch}" == "arm64" ]]; then push_pkg="${LOCAL_PKG_ARM64}"; fi
      local tags=()
      for reg in "${REGISTRY_PREFIXES[@]}"; do
        tags+=("${reg}/aerospike-asadm:${VERSION}-${arch}")
      done
      _emit_single_arch_push_target "push-${arch}" "${arch}" "${push_pkg}" "${tags[@]}"
      push_target_names+=("push-${arch}")
    else
      local tags=()
      for reg in "${REGISTRY_PREFIXES[@]}"; do
        tags+=("${reg}/aerospike-asadm:${VERSION}")
        if [[ -n "${TIMESTAMP}" ]]; then
          tags+=("${reg}/aerospike-asadm:${VERSION}-${TIMESTAMP}")
        fi
      done
      _emit_push_target "push" "${LOCAL_PKG_AMD64}" "${LOCAL_PKG_ARM64}" "${tags[@]}"
      push_target_names+=("push")
    fi

    # ---- Groups ----
    if [[ ${#test_target_names[@]} -gt 0 ]]; then _emit_group "test" "${test_target_names[@]}"; fi
    if [[ ${#push_target_names[@]} -gt 0 ]]; then _emit_group "push" "${push_target_names[@]}"; fi

  } >"${BAKE_FILE}"

  log_success "Generated ${BAKE_FILE}"
}

# ---------------------------------------------------------------------------
# resolve_packages: compute URLs, SHA256s, and (optionally) copy local .debs
# into the build context. Populates globals:
#   ASADM_{AMD64,ARM64}_URL
#   ASADM_{AMD64,ARM64}_SHA256
#   LOCAL_PKG_{AMD64,ARM64}     (set only when --packages-dir is used)
#   LOCAL_PKGS_COPIED           (paths to clean up on EXIT)
# ---------------------------------------------------------------------------
function resolve_packages() {
  local pkg_amd64="aerospike-asadm_${VERSION}_ubuntu24.04_x86_64.deb"
  local pkg_arm64="aerospike-asadm_${VERSION}_ubuntu24.04_aarch64.deb"
  local pool="${DEB_BASE_URL}/pool/${UBUNTU_CODENAME}/aerospike-asadm"

  ASADM_AMD64_URL="${pool}/${pkg_amd64}"
  ASADM_ARM64_URL="${pool}/${pkg_arm64}"

  log_info "=== Resolving packages ==="
  log_info "  Version:      ${VERSION}"
  log_info "  DEB base URL: ${DEB_BASE_URL}"
  [[ -n "${PACKAGES_DIR}" ]] && log_info "  Packages dir: ${PACKAGES_DIR}"

  local need_amd64=false need_arm64=false
  for a in "${ACTIVE_ARCHES[@]}"; do
    [[ "${a}" == "amd64" ]] && need_amd64=true
    [[ "${a}" == "arm64" ]] && need_arm64=true
  done

  if [[ -n "${PACKAGES_DIR}" ]]; then
    local real_dir
    real_dir=$(cd "${PACKAGES_DIR}" && pwd -P)
    if [[ "${need_amd64}" == true ]]; then
      local path
      path=$(find_package "${real_dir}" "${pkg_amd64}")
      if [[ -n "${path}" ]]; then
        log_info "  Found:  ${path}"
        ASADM_AMD64_SHA256=$(sha256_of_file "${path}")
        cp "${path}" "${SCRIPT_DIR}/${pkg_amd64}"
        LOCAL_PKG_AMD64="${pkg_amd64}"
        LOCAL_PKGS_COPIED+=("${SCRIPT_DIR}/${pkg_amd64}")
      else
        log_warn "  ${pkg_amd64} not found in ${PACKAGES_DIR} — will fall back to URL"
        ASADM_AMD64_SHA256="PLACEHOLDER"
      fi
    fi
    if [[ "${need_arm64}" == true ]]; then
      local path
      path=$(find_package "${real_dir}" "${pkg_arm64}")
      if [[ -n "${path}" ]]; then
        log_info "  Found:  ${path}"
        ASADM_ARM64_SHA256=$(sha256_of_file "${path}")
        cp "${path}" "${SCRIPT_DIR}/${pkg_arm64}"
        LOCAL_PKG_ARM64="${pkg_arm64}"
        LOCAL_PKGS_COPIED+=("${SCRIPT_DIR}/${pkg_arm64}")
      else
        log_warn "  ${pkg_arm64} not found in ${PACKAGES_DIR} — will fall back to URL"
        ASADM_ARM64_SHA256="PLACEHOLDER"
      fi
    fi
  elif [[ "${COMPUTE_SHA}" == true ]]; then
    [[ "${need_amd64}" == true ]] && ASADM_AMD64_SHA256=$(sha256_of_url "${ASADM_AMD64_URL}")
    [[ "${need_arm64}" == true ]] && ASADM_ARM64_SHA256=$(sha256_of_url "${ASADM_ARM64_URL}")
  else
    ASADM_AMD64_SHA256="PLACEHOLDER"
    ASADM_ARM64_SHA256="PLACEHOLDER"
  fi

  echo ""
  log_info "  AMD64 URL: ${ASADM_AMD64_URL}"
  log_info "  AMD64 SHA: ${ASADM_AMD64_SHA256}"
  log_info "  ARM64 URL: ${ASADM_ARM64_URL}"
  log_info "  ARM64 SHA: ${ASADM_ARM64_SHA256}"
  if [[ "${ASADM_AMD64_SHA256}" == "PLACEHOLDER" || "${ASADM_ARM64_SHA256}" == "PLACEHOLDER" ]]; then
    log_warn "  One or more SHA256 checksums are PLACEHOLDER — SHA256 verification will be skipped at build time."
  fi
  echo ""
}

function _cleanup_local_pkgs() {
  for f in "${LOCAL_PKGS_COPIED[@]+"${LOCAL_PKGS_COPIED[@]}"}"; do
    if [[ -f "${f}" ]]; then rm -f "${f}"; fi
  done
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Script-level state
VERSION=""
TIMESTAMP="$(date -u +%Y%m%d%H%M%S)"
REGISTRY_PREFIXES=()
ACTIVE_ARCHES=()
PUSH_SINGLE_ARCH=false

PACKAGES_DIR=""
DEB_BASE_URL="${DEFAULT_DEB_BASE_URL}"
COMPUTE_SHA=false

ASADM_AMD64_URL=""
ASADM_AMD64_SHA256=""
ASADM_ARM64_URL=""
ASADM_ARM64_SHA256=""

LOCAL_PKG_AMD64=""
LOCAL_PKG_ARM64=""
LOCAL_PKGS_COPIED=()

function main() {
  local mode=""
  local dry_run=false
  local no_cache=false
  local arch_filters=()
  local pkg_url=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
    -t) mode="test" ; shift ;;
    -p) mode="push" ; shift ;;
    -M | --manifest) mode="manifest" ; shift ;;
    -v | --version)       VERSION="$2"             ; shift 2 ;;
    -r | --registry)      REGISTRY_PREFIXES+=("$2") ; shift 2 ;;
    -a | --arch)          arch_filters+=("$2")     ; shift 2 ;;
    -u | --packages-url)  pkg_url="$2"             ; shift 2 ;;
    --packages-dir)       PACKAGES_DIR="$2"        ; shift 2 ;;
    --deb-base-url)       DEB_BASE_URL="$2"        ; shift 2 ;;
    -T | --timestamp)     TIMESTAMP="$2"           ; shift 2 ;;
    -s | --compute-sha)   COMPUTE_SHA=true         ; shift ;;
    -n | --no-cache)      no_cache=true            ; shift ;;
    -N | --dry-run)       dry_run=true             ; shift ;;
    -h | --help)      usage ; exit 0 ;;
    *) log_warn "Unknown option: $1" ; usage ; exit 1 ;;
    esac
  done

  if [[ -z "${mode}" ]]; then
    log_warn "A mode (-t, -p, or -M) is required."
    usage
    exit 1
  fi

  if [[ -z "${VERSION}" ]]; then
    log_warn "--version is required."
    usage
    exit 1
  fi

  # Default registry
  if [[ ${#REGISTRY_PREFIXES[@]} -eq 0 ]]; then REGISTRY_PREFIXES=("aerospike"); fi

  # Resolve active arches
  local all_arches=("amd64" "arm64")
  if [[ ${#arch_filters[@]} -eq 0 ]]; then
    ACTIVE_ARCHES=("${all_arches[@]}")
  else
    for a in "${arch_filters[@]}"; do
      case "${a}" in
      amd64 | x86_64)  ACTIVE_ARCHES+=("amd64") ;;
      arm64 | aarch64) ACTIVE_ARCHES+=("arm64") ;;
      *) log_warn "Unknown arch '${a}' (valid: amd64, arm64)" ;;
      esac
    done
  fi

  # Deduplicate ACTIVE_ARCHES (preserve order)
  if [[ ${#ACTIVE_ARCHES[@]} -gt 0 ]]; then
    local __deduped=()
    local __a __dup __b
    for __a in "${ACTIVE_ARCHES[@]}"; do
      __dup=false
      for __b in "${__deduped[@]+"${__deduped[@]}"}"; do
        if [[ "${__a}" == "${__b}" ]]; then __dup=true; break; fi
      done
      if [[ "${__dup}" == false ]]; then __deduped+=("${__a}"); fi
    done
    ACTIVE_ARCHES=("${__deduped[@]}")
  fi

  if [[ ${#ACTIVE_ARCHES[@]} -eq 0 ]]; then
    log_warn "No valid arches after filtering."
    exit 1
  fi

  if [[ "${mode}" == "manifest" ]]; then
    run_manifest_mode
    exit 0
  fi

  # Push with exactly one arch: single-platform target (native CI matrix)
  if [[ "${mode}" == "push" && ${#ACTIVE_ARCHES[@]} -eq 1 ]]; then
    PUSH_SINGLE_ARCH=true
  fi

  # Resolve -u / --packages-url: local dir or remote JFrog base URL
  if [[ -n "${pkg_url}" ]]; then
    if [[ "${pkg_url}" == http://* || "${pkg_url}" == https://* ]]; then
      DEB_BASE_URL="${pkg_url}"
    else
      PACKAGES_DIR="${pkg_url}"
    fi
  fi

  # ---- Step 1: Resolve URLs + SHAs (and copy local .debs into context if any) ----
  resolve_packages
  if [[ ${#LOCAL_PKGS_COPIED[@]} -gt 0 ]]; then
    trap '_cleanup_local_pkgs' EXIT
  fi

  if [[ "${dry_run}" == true ]]; then
    log_info "Dry run: skipping bake generation and Docker build."
    exit 0
  fi

  # ---- Step 2: Generate bake file ----
  log_info "=== Generating Bake File ==="
  generate_bake

  # ---- Step 3: Build ----
  echo ""
  log_info "=== Building Images ==="
  local bake_args=("-f" "${BAKE_FILE}")
  if [[ "${no_cache}" == true ]]; then bake_args+=("--no-cache"); fi

  case "${mode}" in
  test)
    log_info "Building and loading locally..."
    docker buildx bake "${bake_args[@]}" test --progress plain --load
    ;;
  push)
    log_info "Building and pushing to: ${REGISTRY_PREFIXES[*]}..."
    docker buildx bake "${bake_args[@]}" push --progress plain --push
    ;;
  esac

  echo ""
  log_success "Done!"
}

main "$@"
