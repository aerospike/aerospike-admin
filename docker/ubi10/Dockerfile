#
# Aerospike asadm - Red Hat UBI 10
#
# https://github.com/aerospike/aerospike-admin
#
# Supports amd64 (x86_64) and arm64 (aarch64).
# Update version-specific ARGs with: docker/update-version.sh
#

ARG ASADM_AMD64_URL="https://aerospike.jfrog.io/artifactory/database-rpm-dev-local/el10/x86_64/aerospike-asadm-5.0.0_rc1.el10.x86_64.rpm"
ARG ASADM_AMD64_SHA256="PLACEHOLDER"
ARG ASADM_ARM64_URL="https://aerospike.jfrog.io/artifactory/database-rpm-dev-local/el10/aarch64/aerospike-asadm-5.0.0_rc1.el10.aarch64.rpm"
ARG ASADM_ARM64_SHA256="PLACEHOLDER"

FROM redhat/ubi10:latest

LABEL org.opencontainers.image.title="Aerospike asadm" \
      org.opencontainers.image.description="asadm and asinfo, tools for managing Aerospike database." \
      org.opencontainers.image.source="https://github.com/aerospike/aerospike-admin" \
      org.opencontainers.image.base.name="registry.access.redhat.com/ubi10/ubi:latest" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aerospike"

ARG ASADM_AMD64_URL
ARG ASADM_AMD64_SHA256
ARG ASADM_ARM64_URL
ARG ASADM_ARM64_SHA256

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

RUN ARCH="$(uname -m)" && \
    if [ "${ARCH}" = "x86_64" ]; then \
        PKG_URL="${ASADM_AMD64_URL}"; PKG_SHA="${ASADM_AMD64_SHA256}"; \
    else \
        PKG_URL="${ASADM_ARM64_URL}"; PKG_SHA="${ASADM_ARM64_SHA256}"; \
    fi && \
    dnf install -y curl ca-certificates && \
    curl -fsSL --retry 3 --retry-delay 3 "${PKG_URL}" -o /tmp/asadm.rpm && \
    if [ "${PKG_SHA}" != "PLACEHOLDER" ]; then \
        echo "${PKG_SHA}  /tmp/asadm.rpm" | sha256sum -c -; \
    fi && \
    rpm -i /tmp/asadm.rpm && \
    rm -f /tmp/asadm.rpm && \
    dnf remove -y curl && \
    dnf clean all

ENTRYPOINT ["asadm"]
