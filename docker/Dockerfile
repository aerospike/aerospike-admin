#
# Aerospike asadm - Docker image.
#
# https://github.com/aerospike/aerospike-admin
#
# Supports linux/amd64 and linux/arm64.
# Driven by docker/docker-build.sh, which passes the version-specific URLs +
# SHA256s as build args (and optionally an in-context .deb via ASADM_LOCAL_PKG*).
# Build directly only if you set those args yourself; otherwise use the script.
#
# Base: debian:trixie-slim. The .deb is built on Ubuntu 24.04 (glibc 2.39)
# and its bundled libpython needs GLIBC_2.38; Trixie ships glibc 2.41,
# Bookworm only 2.36 which is too old. Trixie-slim also ships the common
# C libs the PyInstaller bundle dynamically links to (zlib1g, libcrypt1,
# etc.) so no extra package curation is needed — apt installs the .deb and
# anything it (transitively) needs.
#

ARG ASADM_AMD64_URL=""
ARG ASADM_AMD64_SHA256=""
ARG ASADM_ARM64_URL=""
ARG ASADM_ARM64_SHA256=""

FROM debian:trixie-slim@sha256:b6e2a152f22a40ff69d92cb397223c906017e1391a73c952b588e51af8883bf8

ARG ASADM_AMD64_URL
ARG ASADM_AMD64_SHA256
ARG ASADM_ARM64_URL
ARG ASADM_ARM64_SHA256
# When set to a filename, the package is copied from the build context instead
# of downloaded from ASADM_*_URL. Set by docker/docker-build.sh -u <local-dir>.
ARG ASADM_LOCAL_PKG=""
ARG ASADM_LOCAL_PKG_AMD64=""
ARG ASADM_LOCAL_PKG_ARM64=""

LABEL org.opencontainers.image.title="Aerospike asadm" \
      org.opencontainers.image.description="asadm and asinfo, tools for managing Aerospike database." \
      org.opencontainers.image.source="https://github.com/aerospike/aerospike-admin" \
      org.opencontainers.image.base.name="docker.io/library/debian:trixie-slim" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aerospike"

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

# Fetch (or copy) → verify SHA → apt-install the .deb. apt resolves any
# transitive Depends from the .deb (currently none declared) and the .deb's
# PyInstaller bundle relies only on libs already present in trixie-slim.
# curl is installed only when we need to download, then purged.
# hadolint ignore=DL3008
RUN --mount=type=bind,source=.,target=/build-ctx \
    export DEBIAN_FRONTEND=noninteractive && \
    ARCH="$(dpkg --print-architecture)" && \
    if [ "${ARCH}" = "amd64" ]; then \
        PKG_URL="${ASADM_AMD64_URL}"; PKG_SHA="${ASADM_AMD64_SHA256}"; \
        LOCAL_PKG="${ASADM_LOCAL_PKG_AMD64:-${ASADM_LOCAL_PKG}}"; \
    else \
        PKG_URL="${ASADM_ARM64_URL}"; PKG_SHA="${ASADM_ARM64_SHA256}"; \
        LOCAL_PKG="${ASADM_LOCAL_PKG_ARM64:-${ASADM_LOCAL_PKG}}"; \
    fi && \
    apt-get update -y && \
    if [ -n "${LOCAL_PKG}" ] && [ -f "/build-ctx/${LOCAL_PKG}" ]; then \
        cp "/build-ctx/${LOCAL_PKG}" /tmp/asadm.deb; \
    else \
        apt-get install -y --no-install-recommends curl ca-certificates && \
        curl -fsSL --retry 3 --retry-delay 3 "${PKG_URL}" -o /tmp/asadm.deb && \
        apt-get purge -y --auto-remove curl; \
    fi && \
    if [ -n "${PKG_SHA}" ] && [ "${PKG_SHA}" != "PLACEHOLDER" ]; then \
        echo "${PKG_SHA}  /tmp/asadm.deb" | sha256sum -c -; \
    fi && \
    apt-get install -y --no-install-recommends ca-certificates tini /tmp/asadm.deb && \
    PKG_NAME="$(dpkg-deb -f /tmp/asadm.deb Package)" && \
    PKG_VERSION="$(dpkg-query -W -f='${Version}' "${PKG_NAME}")" && \
    mkdir -p /usr/local/share/aerospike && \
    dpkg-query -L "${PKG_NAME}" \
      | { grep -E '^/usr/(local/)?bin/.' || true; } \
      | while read -r f; do \
            if [ -f "${f}" ] && [ -x "${f}" ]; then basename "${f}"; fi; \
        done \
      | sort -u > /usr/local/share/aerospike/tools && \
    if [ ! -s /usr/local/share/aerospike/tools ]; then \
        echo "no tool binaries found in ${PKG_NAME}" >&2; exit 1; \
    fi && \
    printf '%s image (%s %s)\n' "${PKG_NAME}" "${PKG_NAME}" "${PKG_VERSION}" \
      > /usr/local/share/aerospike/image-info && \
    groupadd --system --gid 10001 aerospike && \
    useradd --system --uid 10001 --gid 10001 --create-home \
      --home-dir /home/aerospike --shell /bin/bash aerospike && \
    rm -f /tmp/asadm.deb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# .deb installs /usr/bin/asadm and /usr/bin/asinfo symlinks → the bundle.
# Both are on PATH; default to asadm, swap with `docker run IMAGE asinfo …`.

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# tini is PID 1 so the tool runs as a child, where the kernel's default signal
# dispositions apply: `docker stop` on a tool that installs no SIGTERM handler
# (asbench, aql, asadm) exits at once instead of waiting out the timeout and
# being SIGKILLed. It also reaps orphans.
#
# The entrypoint script is the help entrypoint: it runs the binary named as the
# first argument, and prints usage listing the binaries this image ships when
# the caller names none or names something else. `--entrypoint bash` still gives
# a shell. No CMD: a default binary would hide the usage message, and images
# that ship several binaries have no correct default.
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/docker-entrypoint.sh"]

# The image runs as root so writes into bind-mounted directories keep working.
# An unprivileged `aerospike` user (uid/gid 10001) is present for callers that
# need one: `docker run --user 10001:10001 ...`, or runAsUser in a pod spec.

# Dynamic labels last: they change every build, so anything after them would
# have to rebuild with them.
ARG IMAGE_VERSION=""
ARG IMAGE_REVISION=""
ARG IMAGE_CREATED=""

LABEL org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.created="${IMAGE_CREATED}"
