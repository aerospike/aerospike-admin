#
# Aerospike asadm - distroless CLI image.
#
# https://github.com/aerospike/aerospike-admin
#
# Supports linux/amd64 and linux/arm64.
# Driven by docker/docker-build.sh, which passes the version-specific URLs +
# SHA256s as build args (and optionally an in-context .deb via ASADM_LOCAL_PKG*).
# Build directly only if you set those args yourself; otherwise use the script.
#
# The .deb produced by pkg/Makefile is fully self-contained: a PyInstaller
# one-dir bundle at /opt/aerospike/bin/asadm/ plus two symlinks at
# /usr/bin/{asadm,asinfo}, and declares no Depends:. We therefore unpack
# the .deb in a builder stage and copy just the payload into a distroless
# runtime stage — no apt, no dpkg, no shell in the shipped image.
#

# Empty defaults so the in-stage RUN (which uses `set -u`) sees them as
# defined-but-empty when only one arch's ARGs are passed (single-arch builds).
# docker-build.sh injects real values via bake `args = {}`.
ARG ASADM_AMD64_URL=""
ARG ASADM_AMD64_SHA256=""
ARG ASADM_ARM64_URL=""
ARG ASADM_ARM64_SHA256=""

# ---------------------------------------------------------------------------
# Builder: fetch + verify + extract the .deb. Discarded after stage 2.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS builder

ARG ASADM_AMD64_URL
ARG ASADM_AMD64_SHA256
ARG ASADM_ARM64_URL
ARG ASADM_ARM64_SHA256
# When set to a filename, the package is copied from the build context instead
# of downloaded from ASADM_*_URL. Set by docker/docker-build.sh -u <local-dir>.
# ASADM_LOCAL_PKG        - single-arch test builds (legacy).
# ASADM_LOCAL_PKG_AMD64  - multi-arch builds, amd64.
# ASADM_LOCAL_PKG_ARM64  - multi-arch builds, arm64.
ARG ASADM_LOCAL_PKG=""
ARG ASADM_LOCAL_PKG_AMD64=""
ARG ASADM_LOCAL_PKG_ARM64=""

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

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
    if [ -n "${LOCAL_PKG}" ] && [ -f "/build-ctx/${LOCAL_PKG}" ]; then \
        cp "/build-ctx/${LOCAL_PKG}" /tmp/asadm.deb; \
    else \
        apt-get update -y && \
        apt-get install -y --no-install-recommends curl ca-certificates && \
        curl -fsSL --retry 3 --retry-delay 3 "${PKG_URL}" -o /tmp/asadm.deb; \
    fi && \
    if [ -n "${PKG_SHA}" ] && [ "${PKG_SHA}" != "PLACEHOLDER" ]; then \
        echo "${PKG_SHA}  /tmp/asadm.deb" | sha256sum -c -; \
    fi && \
    mkdir -p /stage && \
    dpkg-deb -x /tmp/asadm.deb /stage

# ---------------------------------------------------------------------------
# Runtime: distroless/cc supplies glibc + libstdc++ + libgcc + ca-certificates.
# No shell, no package manager, no curl.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12

LABEL org.opencontainers.image.title="Aerospike asadm" \
      org.opencontainers.image.description="asadm and asinfo, tools for managing Aerospike database." \
      org.opencontainers.image.source="https://github.com/aerospike/aerospike-admin" \
      org.opencontainers.image.base.name="gcr.io/distroless/cc-debian12" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aerospike"

COPY --from=builder /stage/opt/aerospike /opt/aerospike
COPY --from=builder /stage/usr/bin/asadm /usr/bin/asadm
COPY --from=builder /stage/usr/bin/asinfo /usr/bin/asinfo

ENTRYPOINT ["/usr/bin/asadm"]
