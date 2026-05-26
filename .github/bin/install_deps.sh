#!/usr/bin/env bash
#
# Install build dependencies for the asadm CI matrix.
#
# Usage:
#   source .github/bin/install_deps.sh
#   install_deps <distro>     # e.g. install_deps ubuntu24.04
#
# Supported distros: debian11, debian12, debian13,
#                    ubuntu20.04, ubuntu22.04, ubuntu24.04, ubuntu26.04,
#                    el8, el9, el10, amzn2023
#
# Set DEBUG=1 to enable bash trace mode.
#

set -euo pipefail
[[ -n "${DEBUG:-}" ]] && set -x

export PYTHON_VERSION="${PYTHON_VERSION:-3.12.11}"
export ASDF_VERSION="${ASDF_VERSION:-v0.18.0}"
export GOLANG_VERSION="${GOLANG_VERSION:-1.24.6}"

export CURL_RETRY_OPTS=(--retry 5 --retry-delay 5)

DEBIAN_11_DEPS='ca-certificates curl git rsync make gcc g++ build-essential xz-utils liblzma-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev libffi-dev libncursesw5-dev uuid-dev tk-dev libssl1.1 libssl-dev ruby-rubygems rpm less'
DEBIAN_12_DEPS="libreadline8 libreadline-dev ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma lzma-dev libffi-dev build-essential gcc g++ less"
DEBIAN_13_DEPS="libreadline8 libreadline-dev ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma liblzma-dev libffi-dev libsqlite3-dev build-essential gcc g++ zlib1g-dev libbz2-dev libreadline-dev libncursesw5-dev libnss3-dev uuid-dev tk-dev xz-utils less"
UBUNTU_2004_DEPS="libreadline8 libreadline-dev ruby make rpm git snapd curl binutils rsync libssl1.1 libssl-dev lzma lzma-dev libffi-dev build-essential gcc g++ less"
UBUNTU_2204_DEPS="libreadline8 libreadline-dev ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma lzma-dev libffi-dev build-essential gcc g++ less"
UBUNTU_2404_DEPS="libreadline8 libreadline-dev ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma lzma-dev libffi-dev build-essential gcc g++ less"
# Ubuntu 26.04 (resolute): lzma-dev was dropped — use liblzma-dev. Do not pin libreadline8
# (t64 / readline major varies); libreadline-dev pulls the correct runtime (see aerospike/aql#70).
# Extra pyenv-style -dev packages keep CPython stdlib modules complete; ensurepip workaround below.
UBUNTU_2604_DEPS="${UBUNTU_2404_DEPS/lzma-dev/liblzma-dev} zlib1g-dev libbz2-dev libsqlite3-dev libncursesw5-dev xz-utils tk-dev uuid-dev"
UBUNTU_2604_DEPS="${UBUNTU_2604_DEPS/libreadline8 /}"
EL8_DEPS="ruby rubygems redhat-rpm-config rpm-build make git rsync gcc gcc-c++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs sqlite sqlite-devel sqlite-libs less"
EL9_DEPS="ruby rpmdevtools make git rsync gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs sqlite sqlite-devel sqlite-libs less"
EL10_DEPS="ruby rpmdevtools make git rsync gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs sqlite sqlite-devel sqlite-libs less"
AMZN2023_DEPS="readline-devel ruby rpmdevtools make git rsync gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs sqlite sqlite-devel sqlite-libs less"

_pkg_list_for() {
  case "$1" in
    debian11)    echo "$DEBIAN_11_DEPS" ;;
    debian12)    echo "$DEBIAN_12_DEPS" ;;
    debian13)    echo "$DEBIAN_13_DEPS" ;;
    ubuntu20.04) echo "$UBUNTU_2004_DEPS" ;;
    ubuntu22.04) echo "$UBUNTU_2204_DEPS" ;;
    ubuntu24.04) echo "$UBUNTU_2404_DEPS" ;;
    ubuntu26.04) echo "$UBUNTU_2604_DEPS" ;;
    el8)         echo "$EL8_DEPS" ;;
    el9)         echo "$EL9_DEPS" ;;
    el10)        echo "$EL10_DEPS" ;;
    amzn2023)    echo "$AMZN2023_DEPS" ;;
    *)           echo "ERROR: unknown distro: $1" >&2; return 1 ;;
  esac
}

# readline-devel isn't in UBI base repos; pull from Rocky vault.
_readline_url_for() {
  local arch
  arch=$(uname -m)
  case "$1" in
    el8)  echo "https://download.rockylinux.org/pub/rocky/8.10/Devel/${arch}/os/Packages/r/readline-devel-7.0-10.el8.${arch}.rpm" ;;
    el9)  echo "https://dl.rockylinux.org/vault/rocky/9.6/devel/${arch}/os/Packages/r/readline-devel-8.1-4.el9.${arch}.rpm" ;;
    el10) echo "https://dl.rockylinux.org/vault/rocky/10.0/devel/${arch}/os/Packages/r/readline-devel-8.2-11.el10.${arch}.rpm" ;;
    *)    echo "" ;;
  esac
}

# PEP 668: newer distros need --break-system-packages for pip.
_pip_flags_for() {
  case "$1" in
    debian*|ubuntu24.04|ubuntu26.04|el9|el10|amzn2023) echo "--break-system-packages" ;;
    *) echo "" ;;
  esac
}

_install_distro_packages() {
  local distro="$1"
  local deps; deps=$(_pkg_list_for "$distro")

  case "$distro" in
    ubuntu*|debian*)
      rm -rf /var/lib/apt/lists/*
      apt-get clean
      apt-get update -o Acquire::Retries=5
      # shellcheck disable=SC2086 # intentional word-split on package list
      apt-get install -y --no-install-recommends $deps
      ;;
    el8)
      dnf -y update
      dnf module enable -y ruby:2.7
      yum install -y "$(_readline_url_for el8)"
      # shellcheck disable=SC2086
      dnf -y install $deps
      ;;
    el9|el10)
      dnf -y update
      yum install -y "$(_readline_url_for "$distro")"
      # shellcheck disable=SC2086
      dnf -y install $deps
      ;;
    amzn2023)
      dnf -y update
      # shellcheck disable=SC2086
      dnf -y install $deps
      ;;
  esac
}

_install_go() {
  local arch_label
  case "$(uname -m)" in
    x86_64)  arch_label="amd64" ;;
    aarch64) arch_label="arm64" ;;
    *)       echo "unknown arch $(uname -m)" >&2; return 1 ;;
  esac
  local tarball="go${GOLANG_VERSION}.linux-${arch_label}.tar.gz"
  curl -L "${CURL_RETRY_OPTS[@]}" "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  mkdir -p /opt/golang
  tar -zxf "/tmp/${tarball}" -C /opt/golang
}

_install_python_via_asdf_and_fpm() {
  local pip_flags="$1"  # "" or "--break-system-packages"
  local distro="${2:-}"

  /opt/golang/go/bin/go install "github.com/asdf-vm/asdf/cmd/asdf@${ASDF_VERSION}"
  install "$HOME/go/bin/asdf" /usr/local/bin/asdf
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  # Ubuntu 26.04 (resolute): ensurepip during "make install" can fail (pip bootstrap to --root /).
  # Build without bundled pip and install pip explicitly afterward.
  if [[ "$distro" == "ubuntu26.04" ]]; then
    export PYTHON_CONFIGURE_OPTS="--with-ensurepip=no"
  fi
  asdf install python "$PYTHON_VERSION"
  if [[ "$distro" == "ubuntu26.04" ]]; then
    unset PYTHON_CONFIGURE_OPTS
    curl -L "${CURL_RETRY_OPTS[@]}" https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
    "$HOME/.asdf/installs/python/$PYTHON_VERSION/bin/python" /tmp/get-pip.py --no-warn-script-location
    rm -f /tmp/get-pip.py
  fi
  asdf set python "$PYTHON_VERSION"
  echo "python $PYTHON_VERSION" > /.tool-versions
  echo "python $PYTHON_VERSION" > "$HOME/.tool-versions"

  # shellcheck disable=SC2086 # intentional word-split on pip flags
  asdf exec python -m pip install $pip_flags pipenv

  local asdf_bin="$HOME/.asdf/installs/python/$PYTHON_VERSION/bin"
  install "$asdf_bin/python" /usr/bin/python
  install "$asdf_bin/python" /usr/bin/python3
  install "$asdf_bin/pipenv" /usr/bin/pipenv
  install "$asdf_bin/pip"    /usr/bin/pip
  install "$asdf_bin/pip3"   /usr/bin/pip3

  gem install fpm -v 1.17.0
}

_post_install_cleanup() {
  case "$1" in
    ubuntu*|debian*) rm -rf /var/lib/apt/lists/* ;;
  esac
}

install_deps() {
  local distro="${1:?install_deps requires a distro argument (e.g. ubuntu24.04)}"

  _install_distro_packages "$distro"

  # debian11 ships stale CA bundle; refresh before Go/asdf curl calls.
  if [[ "$distro" == "debian11" ]]; then
    update-ca-certificates
  fi

  _install_go
  _install_python_via_asdf_and_fpm "$(_pip_flags_for "$distro")" "$distro"
  _post_install_cleanup "$distro"
}
