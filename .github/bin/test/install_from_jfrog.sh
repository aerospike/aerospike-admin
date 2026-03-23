#!/usr/bin/env bash
set -euo pipefail

: "${JF_USERNAME:?JF_USERNAME is required}"
: "${JF_TOKEN:?JF_TOKEN is required}"
: "${PKG_VERSION:?PKG_VERSION is required}"
: "${PACKAGE_NAME:?PACKAGE_NAME is required}"

JFROG_URL="https://artifact.aerospike.io/artifactory"
JFROG_KEY_URL="https://aerospike.jfrog.io/artifactory/api/security/keypair/aerospike/public"
RETRY_TIMEOUT=300
RETRY_INTERVAL=10

install_deb() {
  export DEBIAN_FRONTEND=noninteractive
  install -m 600 /dev/null /etc/apt/auth.conf.d/aerospike.conf
  printf "machine artifact.aerospike.io\nlogin %s\npassword %s\n" "$JF_USERNAME" "$JF_TOKEN" \
    > /etc/apt/auth.conf.d/aerospike.conf

  local codename arch keyring
  codename=$(lsb_release -sc)
  arch=$(dpkg --print-architecture)
  keyring=/usr/share/keyrings/aerospike.gpg

  wget -qO - "$JFROG_KEY_URL" | gpg --batch --no-tty --dearmor -o "$keyring"
  echo "deb [arch=$arch signed-by=$keyring] ${JFROG_URL}/database-deb-dev-local $codename main" \
    > /etc/apt/sources.list.d/aerospike.list
  apt-get update

  local end=$((SECONDS + RETRY_TIMEOUT))
  while [ $SECONDS -lt $end ]; do
    if apt -y install "aerospike-${PACKAGE_NAME}=${PKG_VERSION}"; then return 0; fi
    echo "Retrying in ${RETRY_INTERVAL}s..."
    apt-get update || true
    sleep "$RETRY_INTERVAL"
  done
  echo "ERROR: deb install failed after ${RETRY_TIMEOUT}s" >&2
  exit 1
}

install_rpm() {
  . /etc/os-release
  local dist arch
  case "$ID" in
    rhel|centos|almalinux|rocky) dist="el${VERSION_ID%%.*}" ;;
    amzn) dist="amzn2023" ;;
    *) echo "ERROR: unsupported distro: $ID" >&2; exit 1 ;;
  esac
  arch=$(uname -m)

  printf '%s\n' \
    "[aerospike-dev]" \
    "name=Aerospike RPM DEV" \
    "baseurl=${JFROG_URL}/database-rpm-dev-local/${dist}/${arch}/" \
    "username=${JF_USERNAME}" \
    "password=${JF_TOKEN}" \
    "enabled=1" \
    "gpgcheck=1" \
    "gpgkey=${JFROG_KEY_URL}" \
    > /etc/yum.repos.d/aerospike.repo

  local rpm_version end
  rpm_version=$(echo "$PKG_VERSION" | tr '-' '_')
  end=$((SECONDS + RETRY_TIMEOUT))
  while [ $SECONDS -lt $end ]; do
    if dnf install -y "aerospike-${PACKAGE_NAME}-${rpm_version}-1.${arch}"; then return 0; fi
    echo "Retrying in ${RETRY_INTERVAL}s..."
    dnf makecache --refresh || true
    sleep "$RETRY_INTERVAL"
  done
  echo "ERROR: rpm install failed after ${RETRY_TIMEOUT}s" >&2
  exit 1
}

if [ -f /etc/debian_version ]; then
  install_deb
else
  install_rpm
fi
