#!/usr/bin/env bash
#
# docker/docker-build.sh
#
# Build multi-architecture Docker images for Aerospike asadm.
#
# Flow:
#   1. Call ./update-version.sh to patch Dockerfile ARGs (URLs + SHA256)
#   2. Generate docker-bake.hcl with test and push targets
#   3. Build with docker buildx bake
#
# Modes:
#   -t   Test: build and load locally (one image per distro×arch, --load compatible)
#   -p   Push: build and push multi-arch manifests to registry
#   -g   Update Dockerfiles only (no bake / no build)
#

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

BAKE_FILE="docker-bake.hcl"

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log_info()    { printf '\e[36m[INFO]\e[0m  %s\n' "$*"; }
log_success() { printf '\e[32m[OK]\e[0m    %s\n' "$*"; }
log_warn()    { printf '\e[33m[WARN]\e[0m  %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
function usage() {
  cat <<'EOF'
Usage: docker/docker-build.sh -t|-p|-g --version VERSION [OPTIONS]

Build Docker images for Aerospike asadm (Ubuntu 24.04 and UBI 10).

MODES (one required):
    -t               Test mode: build and load locally (single platform per arch)
    -p               Push mode: build and push multi-arch manifests to registry
    -g, --generate   Update Dockerfiles only, no build

REQUIRED:
    --version VERSION       asadm version, e.g. 5.0.0 or 5.0.0-rc1
                            Required unless --skip-update is set.

OPTIONS:
    -r, --registry REG      Registry prefix for image tags (default: aerospike)
                            Repeat for multiple registries: -r reg1 -r reg2
                            Example: -r artifact.aerospike.io/database-docker-dev-local
    --distro DISTRO         Filter distro; repeat for multiple (default: all)
                            Values: ubuntu24.04, ubi10
    --arch ARCH             Filter arch for test targets; repeat for multiple (default: all)
                            Values: amd64, arm64
                            Push always builds both arches regardless of this flag.
    -u, --packages-url URL_OR_PATH
                            Package source — local dir or JFrog base URL:
                              Local:  -u /path/to/dist  (sets --packages-dir)
                              Remote: -u https://aerospike.jfrog.io/artifactory/database-deb-dev-local
                                      (sets both --deb-base-url and --rpm-base-url)
    --packages-dir DIR      Explicit local packages dir (forwarded to update-version.sh)
    --deb-base-url URL      Explicit DEB base URL (forwarded to update-version.sh)
    --rpm-base-url URL      Explicit RPM base URL (forwarded to update-version.sh)
    --compute-sha           Forwarded to update-version.sh (download packages to compute SHA256)
    --skip-update           Skip calling update-version.sh (use current Dockerfile ARGs as-is)
    --no-cache              Disable Docker build cache
    --dry-run               Dry run: forward to update-version.sh; skip Docker steps
    -h, --help              Show this help message

DISTROS AND BASE IMAGES:
    ubuntu24.04    Ubuntu 24.04, installs asadm .deb   (linux/amd64 + linux/arm64)
    ubi10          Red Hat UBI 10, installs asadm .rpm  (linux/amd64 + linux/arm64)

TAGS PRODUCED:
  Test mode (loaded locally):
    <reg>/aerospike-asadm:<version>-<distro>-<arch>
    e.g. aerospike/aerospike-asadm:5.0.0-ubuntu24.04-amd64

  Push mode (multi-arch manifests):
    <reg>/aerospike-asadm:<version>-ubuntu24.04   (linux/amd64 + linux/arm64)
    <reg>/aerospike-asadm:<version>               (canonical alias → ubuntu24.04)
    <reg>/aerospike-asadm:<version>-ubi10         (linux/amd64 + linux/arm64)

EXAMPLES:
    # Build + load using local packages dir
    docker/docker-build.sh -t --version 5.0.0-rc1 -u /path/to/dist

    # Build + load from JFrog dev (single -u sets both DEB and RPM URLs)
    docker/docker-build.sh -t --version 5.0.0-rc1 \
        -u https://aerospike.jfrog.io/artifactory/database-dev-local

    # Build + load, download packages to compute SHA256
    docker/docker-build.sh -t --version 5.0.0 --compute-sha

    # Build + push to default registry (docker.io/aerospike/aerospike-asadm)
    docker/docker-build.sh -p --version 5.0.0

    # Build + push to JFrog dev registry with dev package source
    docker/docker-build.sh -p --version 5.0.0 \
        -r artifact.aerospike.io/database-docker-dev-local \
        -u https://aerospike.jfrog.io/artifactory/database-dev-local

    # Push to multiple registries simultaneously
    docker/docker-build.sh -p --version 5.0.0 \
        -r aerospike \
        -r artifact.aerospike.io/database-docker-dev-local

    # Update Dockerfiles only (no build)
    docker/docker-build.sh -g --version 5.0.0 --compute-sha

    # Build + test only ubuntu24.04 amd64
    docker/docker-build.sh -t --version 5.0.0 --distro ubuntu24.04 --arch amd64

    # Build without updating Dockerfiles
    docker/docker-build.sh -t --version 5.0.0 --skip-update

OUTPUT:
    docker/docker-bake.hcl   Generated bake file (gitignored, not committed)
EOF
}

# ---------------------------------------------------------------------------
# Bake file emitters — write to stdout; caller redirects to BAKE_FILE
# ---------------------------------------------------------------------------

# Emit a single-arch test target block.
# _emit_test_target NAME CTX ARCH TAG [TAG ...]
function _emit_test_target() {
  local name="$1" ctx="$2" arch="$3"
  shift 3
  local tags=("$@")
  local n=${#tags[@]}
  echo "target \"${name}\" {"
  echo "  context    = \"${ctx}\""
  echo "  dockerfile = \"Dockerfile\""
  echo "  platforms  = [\"linux/${arch}\"]"
  echo "  tags = ["
  for ((i = 0; i < n; i++)); do
    if [[ $i -lt $((n - 1)) ]]; then
      echo "    \"${tags[$i]}\","
    else
      echo "    \"${tags[$i]}\""
    fi
  done
  echo "  ]"
  echo "}"
  echo ""
}

# Emit a multi-arch push target block (always linux/amd64 + linux/arm64).
# _emit_push_target NAME CTX TAG [TAG ...]
function _emit_push_target() {
  local name="$1" ctx="$2"
  shift 2
  local tags=("$@")
  local n=${#tags[@]}
  echo "target \"${name}\" {"
  echo "  context    = \"${ctx}\""
  echo "  dockerfile = \"Dockerfile\""
  echo "  platforms  = [\"linux/amd64\", \"linux/arm64\"]"
  echo "  tags = ["
  for ((i = 0; i < n; i++)); do
    if [[ $i -lt $((n - 1)) ]]; then
      echo "    \"${tags[$i]}\","
    else
      echo "    \"${tags[$i]}\""
    fi
  done
  echo "  ]"
  echo "}"
  echo ""
}

# Emit a named bake group.
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
# generate_bake: write docker-bake.hcl
# Reads globals: VERSION, REGISTRY_PREFIXES, ACTIVE_DISTROS, ACTIVE_ARCHES
# ---------------------------------------------------------------------------
function generate_bake() {
  log_info "Generating ${BAKE_FILE}..."

  declare -A distro_ctx=(
    [ubuntu24.04]="ubuntu24.04"
    [ubi10]="ubi10"
  )

  local test_target_names=()
  local push_target_names=()

  {
    echo "# Generated by docker/docker-build.sh — do not edit by hand."
    echo ""
    echo "variable \"VERSION\" { default = \"${VERSION}\" }"
    echo ""

    # ---- Test targets (single-arch, --load compatible) ----
    for distro in "${ACTIVE_DISTROS[@]}"; do
      local ctx="${distro_ctx[${distro}]}"
      local slug="${distro//\./-}"
      for arch in "${ACTIVE_ARCHES[@]}"; do
        local tags=()
        for reg in "${REGISTRY_PREFIXES[@]}"; do
          tags+=("${reg}/aerospike-asadm:${VERSION}-${distro}-${arch}")
        done
        _emit_test_target "${slug}-${arch}" "${ctx}" "${arch}" "${tags[@]}"
        test_target_names+=("${slug}-${arch}")
      done
    done

    # ---- Push targets (multi-arch manifests) ----
    for distro in "${ACTIVE_DISTROS[@]}"; do
      local ctx="${distro_ctx[${distro}]}"
      local slug="${distro//\./-}"
      local tags=()
      for reg in "${REGISTRY_PREFIXES[@]}"; do
        tags+=("${reg}/aerospike-asadm:${VERSION}-${distro}")
        # ubuntu24.04 also gets the canonical version-only tag
        [[ "${distro}" == "ubuntu24.04" ]] && tags+=("${reg}/aerospike-asadm:${VERSION}")
      done
      _emit_push_target "${slug}" "${ctx}" "${tags[@]}"
      push_target_names+=("${slug}")
    done

    # ---- Groups ----
    [[ ${#test_target_names[@]} -gt 0 ]] && _emit_group "test" "${test_target_names[@]}"
    [[ ${#push_target_names[@]} -gt 0 ]] && _emit_group "push" "${push_target_names[@]}"

  } >"${BAKE_FILE}"

  log_success "Generated ${BAKE_FILE}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Script-level state: populated in main(), read by generate_bake()
VERSION=""
REGISTRY_PREFIXES=()
ACTIVE_DISTROS=()
ACTIVE_ARCHES=()

function main() {
  local mode=""
  local skip_update=false
  local dry_run=false
  local no_cache=false
  local full_generate=false
  local generate_only=false
  local distro_filters=()
  local arch_filters=()
  local pkg_url="" packages_dir="" deb_base_url="" rpm_base_url=""
  local compute_sha=false

  while [[ $# -gt 0 ]]; do
    case "$1" in
    -t) mode="test" ; shift ;;
    -p) mode="push" ; shift ;;
    -g | --generate)  full_generate=true       ; shift ;;
    --version)        VERSION="$2"             ; shift 2 ;;
    -r | --registry)  REGISTRY_PREFIXES+=("$2") ; shift 2 ;;
    --distro)         distro_filters+=("$2")   ; shift 2 ;;
    --arch)           arch_filters+=("$2")     ; shift 2 ;;
    -u | --packages-url) pkg_url="$2"           ; shift 2 ;;
    --packages-dir)   packages_dir="$2"        ; shift 2 ;;
    --deb-base-url)   deb_base_url="$2"        ; shift 2 ;;
    --rpm-base-url)   rpm_base_url="$2"        ; shift 2 ;;
    --compute-sha)    compute_sha=true         ; shift ;;
    --skip-update)    skip_update=true         ; shift ;;
    --no-cache)       no_cache=true            ; shift ;;
    --dry-run)        dry_run=true             ; shift ;;
    -h | --help)      usage ; exit 0 ;;
    *) log_warn "Unknown option: $1" ; usage ; exit 1 ;;
    esac
  done

  # Resolve mode
  if [[ "${full_generate}" == true && -z "${mode}" ]]; then
    generate_only=true
  fi
  if [[ "${full_generate}" == false && -z "${mode}" ]]; then
    log_warn "A mode (-t, -p, or -g) is required."
    usage
    exit 1
  fi

  # --version required unless --skip-update
  if [[ -z "${VERSION}" && "${skip_update}" == false ]]; then
    log_warn "--version is required (or use --skip-update to skip Dockerfile update)."
    usage
    exit 1
  fi

  # Default registry
  [[ ${#REGISTRY_PREFIXES[@]} -eq 0 ]] && REGISTRY_PREFIXES=("aerospike")

  # Resolve active distros
  local all_distros=("ubuntu24.04" "ubi10")
  if [[ ${#distro_filters[@]} -eq 0 ]]; then
    ACTIVE_DISTROS=("${all_distros[@]}")
  else
    for d in "${distro_filters[@]}"; do
      local valid=false
      for ad in "${all_distros[@]}"; do
        [[ "${ad}" == "${d}" ]] && { ACTIVE_DISTROS+=("${d}") ; valid=true ; break ; }
      done
      [[ "${valid}" == false ]] && log_warn "Unknown distro '${d}' (valid: ${all_distros[*]})"
    done
  fi

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

  if [[ ${#ACTIVE_DISTROS[@]} -eq 0 ]]; then
    log_warn "No valid distros after filtering."
    exit 1
  fi
  if [[ ${#ACTIVE_ARCHES[@]} -eq 0 ]]; then
    log_warn "No valid arches after filtering."
    exit 1
  fi

  # Resolve -u / --packages-url: local dir or remote JFrog base URL
  if [[ -n "${pkg_url}" ]]; then
    if [[ "${pkg_url}" == http://* || "${pkg_url}" == https://* ]]; then
      deb_base_url="${pkg_url}"
      rpm_base_url="${pkg_url}"
    else
      packages_dir="${pkg_url}"
    fi
  fi

  # ---- Step 1: Update Dockerfiles ----
  if [[ "${skip_update}" == false ]]; then
    log_info "=== Updating Dockerfiles ==="
    local update_args=("--version" "${VERSION}")
    [[ -n "${packages_dir}" ]]     && update_args+=("--packages-dir" "${packages_dir}")
    [[ -n "${deb_base_url}" ]]     && update_args+=("--deb-base-url" "${deb_base_url}")
    [[ -n "${rpm_base_url}" ]]     && update_args+=("--rpm-base-url" "${rpm_base_url}")
    [[ "${compute_sha}" == true ]] && update_args+=("--compute-sha")
    [[ "${dry_run}"     == true ]] && update_args+=("--dry-run")
    ./update-version.sh "${update_args[@]}"
    echo ""
  fi

  if [[ "${generate_only}" == true ]]; then
    log_success "Dockerfiles updated. (-g only: skipping bake and build)"
    exit 0
  fi

  if [[ "${dry_run}" == true ]]; then
    log_info "Dry run: skipping bake generation and Docker build."
    exit 0
  fi

  # ---- Step 2: Generate bake file ----
  echo ""
  log_info "=== Generating Bake File ==="
  generate_bake

  # ---- Step 3: Build ----
  echo ""
  log_info "=== Building Images ==="
  local bake_args=("-f" "${BAKE_FILE}")
  [[ "${no_cache}" == true ]] && bake_args+=("--no-cache")

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
