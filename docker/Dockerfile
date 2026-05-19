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
# /usr/bin/{asadm,asinfo}, and declares no Depends:. We unpack the .deb in a
# builder stage and copy just the payload into a distroless runtime stage —
# no apt, no dpkg, no shell in the shipped image.
#
# Runtime base is gcr.io/distroless/python3-debian12: it ships the C libs
# Python bundles typically link against (zlib, libffi, libsqlite3, libcrypt,
# libreadline, libuuid, libbz2, liblzma, …), which our PyInstaller bundle
# excludes from itself (see pyinstaller-build.spec excludes_binaries). We
# don't use the bundled /usr/bin/python3 — our PyInstaller binary brings its
# own — but the lib set is exactly what we need, maintained by Google.
#

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
ARG ASADM_LOCAL_PKG=""
ARG ASADM_LOCAL_PKG_AMD64=""
ARG ASADM_LOCAL_PKG_ARM64=""

SHELL ["/bin/bash", "-Eeuo", "pipefail", "-c"]

# Extract to / so the .deb's absolute symlinks at /usr/bin/{asadm,asinfo}
# → /opt/aerospike/bin/asadm/{asadm,asinfo} resolve correctly when the final
# stage COPYs from /opt/aerospike. Extracting under /stage would leave
# dangling symlinks (BuildKit resolves them against the builder root).
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
    dpkg-deb -x /tmp/asadm.deb / && \
    mkdir -p /shim/usr/local/bin && \
    ln -sf /opt/aerospike/bin/asadm/asadm  /shim/usr/local/bin/asadm && \
    ln -sf /opt/aerospike/bin/asadm/asinfo /shim/usr/local/bin/asinfo

# ---------------------------------------------------------------------------
# Runtime. distroless/python3 ships the C libs Python apps need; we don't use
# its bundled python3 binary (PyInstaller embeds its own). No shell, no apt.
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/python3-debian12

LABEL org.opencontainers.image.title="Aerospike asadm" \
      org.opencontainers.image.description="asadm and asinfo, tools for managing Aerospike database." \
      org.opencontainers.image.source="https://github.com/aerospike/aerospike-admin" \
      org.opencontainers.image.base.name="gcr.io/distroless/python3-debian12" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="Aerospike"

COPY --from=builder /opt/aerospike /opt/aerospike

# Symlinks created in the builder at /shim/usr/local/bin/{asadm,asinfo} →
# /opt/aerospike/bin/asadm/{asadm,asinfo}. COPY of a *directory* preserves
# symlinks (single-file COPY dereferences them — which would break
# PyInstaller's /proc/self/exe → dirname → _internal/ resolution).
# Placing the symlinks on PATH lets users invoke either binary by name:
#   docker run IMAGE                  → asadm   (default via CMD)
#   docker run IMAGE asadm  --help    → asadm
#   docker run IMAGE asinfo --help    → asinfo
COPY --from=builder /shim/usr/local/bin/ /usr/local/bin/

# Reset the inherited `python3` entrypoint from distroless/python3-debian12;
# our CMD becomes the full command. runc resolves bare names via PATH, so
# users can invoke either tool by name.
ENTRYPOINT []
CMD ["asadm"]
