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

FROM redhat/ubi10:10.0

LABEL org.opencontainers.image.title="Aerospike asadm" \
      org.opencontainers.image.description="asadm and asinfo, tools for managing Aerospike database." \
      org.opencontainers.image.source="https://github.com/aerospike/aerospike-admin" \
      org.opencontainers.image.base.name="registry.access.redhat.com/ubi10/ubi:10.0" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aerospike"

ARG ASADM_AMD64_URL
ARG ASADM_AMD64_SHA256
ARG ASADM_ARM64_URL
ARG ASADM_ARM64_SHA256
# When set to a filename, the package is copied from the build context instead
# of downloaded from ASADM_*_URL. Set by docker/docker-build.sh -u <local-dir>.
ARG ASADM_LOCAL_PKG=""
ARG ASADM_LOCAL_PKG_AMD64=""
ARG ASADM_LOCAL_PKG_ARM64=""

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

RUN --mount=type=bind,source=.,target=/build-ctx \
    --mount=type=secret,id=jfrog_token,required=false \
    ARCH="$(uname -m)" && \
    if [ "${ARCH}" = "x86_64" ]; then \
        PKG_URL="${ASADM_AMD64_URL}"; PKG_SHA="${ASADM_AMD64_SHA256}"; \
        LOCAL_PKG="${ASADM_LOCAL_PKG_AMD64:-${ASADM_LOCAL_PKG}}"; \
    else \
        PKG_URL="${ASADM_ARM64_URL}"; PKG_SHA="${ASADM_ARM64_SHA256}"; \
        LOCAL_PKG="${ASADM_LOCAL_PKG_ARM64:-${ASADM_LOCAL_PKG}}"; \
    fi && \
    if [ -n "${LOCAL_PKG}" ] && [ -f "/build-ctx/${LOCAL_PKG}" ]; then \
        cp "/build-ctx/${LOCAL_PKG}" /tmp/asadm.rpm; \
    else \
        JFROG_TOKEN="$(cat /run/secrets/jfrog_token 2>/dev/null || true)" && \
        dnf install -y curl ca-certificates && \
        if [ -n "${JFROG_TOKEN}" ]; then \
            curl -fsSL --retry 3 --retry-delay 3 \
                -H "Authorization: Bearer ${JFROG_TOKEN}" \
                "${PKG_URL}" -o /tmp/asadm.rpm; \
        else \
            curl -fsSL --retry 3 --retry-delay 3 "${PKG_URL}" -o /tmp/asadm.rpm; \
        fi && \
        dnf remove -y curl; \
    fi && \
    if [ "${PKG_SHA}" != "PLACEHOLDER" ]; then \
        echo "${PKG_SHA}  /tmp/asadm.rpm" | sha256sum -c -; \
    fi && \
    rpm -i /tmp/asadm.rpm && \
    rm -f /tmp/asadm.rpm && \
    dnf clean all

ENTRYPOINT ["asadm"]
