#
# Aerospike asadm - Ubuntu 24.04
#
# https://github.com/aerospike/aerospike-admin
#
# Supports amd64 and arm64.
# Update version-specific ARGs with: docker/update-version.sh
#

ARG ASADM_AMD64_URL="https://aerospike.jfrog.io/artifactory/database-deb-dev-local/pool/noble/aerospike-asadm/aerospike-asadm_5.0.0-rc1_ubuntu24.04_x86_64.deb"
ARG ASADM_AMD64_SHA256="PLACEHOLDER"
ARG ASADM_ARM64_URL="https://aerospike.jfrog.io/artifactory/database-deb-dev-local/pool/noble/aerospike-asadm/aerospike-asadm_5.0.0-rc1_ubuntu24.04_aarch64.deb"
ARG ASADM_ARM64_SHA256="PLACEHOLDER"

FROM ubuntu:24.04

LABEL org.opencontainers.image.title="Aerospike asadm" \
      org.opencontainers.image.description="asadm and asinfo, tools for managing Aerospike database." \
      org.opencontainers.image.source="https://github.com/aerospike/aerospike-admin" \
      org.opencontainers.image.base.name="docker.io/library/ubuntu:24.04" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aerospike"

ARG ASADM_AMD64_URL
ARG ASADM_AMD64_SHA256
ARG ASADM_ARM64_URL
ARG ASADM_ARM64_SHA256
# When set to a filename, the package is copied from the build context instead
# of downloaded from ASADM_*_URL. Set by docker/docker-build.sh -u <local-dir>.
# ASADM_LOCAL_PKG        - used by single-arch test builds (legacy).
# ASADM_LOCAL_PKG_AMD64  - used by multi-arch push builds for amd64.
# ASADM_LOCAL_PKG_ARM64  - used by multi-arch push builds for arm64.
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
    apt-get update -y && \
    apt-get install -y --no-install-recommends ca-certificates && \
    if [ -n "${LOCAL_PKG}" ] && [ -f "/build-ctx/${LOCAL_PKG}" ]; then \
        cp "/build-ctx/${LOCAL_PKG}" /tmp/asadm.deb; \
    else \
        apt-get install -y --no-install-recommends curl && \
        curl -fsSL --retry 3 --retry-delay 3 "${PKG_URL}" -o /tmp/asadm.deb && \
        apt-get purge -y --auto-remove curl; \
    fi && \
    if [ "${PKG_SHA}" != "PLACEHOLDER" ]; then \
        echo "${PKG_SHA}  /tmp/asadm.deb" | sha256sum -c -; \
    fi && \
    dpkg -i /tmp/asadm.deb && \
    rm -f /tmp/asadm.deb && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["asadm"]
