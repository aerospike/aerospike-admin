#!/usr/bin/env bash
set -x

# Install Rust for building cryptography from source
function install_rust() {
  echo "=== Installing Rust for cryptography build ==="
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
  export PATH="$HOME/.cargo/bin:$PATH"
}

DEBIAN_12_DEPS="libreadline8 libreadline-dev ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma lzma-dev libffi-dev build-essential gcc g++"
DEBIAN_13_DEPS="libreadline8 libreadline-dev ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma liblzma-dev libffi-dev libsqlite3-dev build-essential gcc g++ zlib1g-dev libbz2-dev libreadline-dev libncursesw5-dev libnss3-dev uuid-dev tk-dev xz-utils"
UBUNTU_2004_DEPS="libreadline8 libreadline-dev ruby make rpm git snapd curl binutils rsync libssl1.1 libssl-dev lzma lzma-dev libffi-dev build-essential gcc g++"
UBUNTU_2204_DEPS="libreadline8 libreadline-dev ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma lzma-dev libffi-dev build-essential gcc g++"
UBUNTU_2404_DEPS="libreadline8 libreadline-dev ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma lzma-dev libffi-dev build-essential gcc g++"
EL8_DEPS="ruby rubygems redhat-rpm-config  rpm-build make git rsync gcc gcc-c++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs sqlite sqlite-devel sqlite-libs"
EL9_DEPS="ruby rpmdevtools make git rsync gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs sqlite sqlite-devel sqlite-libs pkg-config"
EL10_DEPS="ruby rpmdevtools make git rsync gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs sqlite sqlite-devel sqlite-libs pkg-config"
AMZN2023_DEPS="readline-devel ruby rpmdevtools make git rsync gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs sqlite sqlite-devel sqlite-libs pkg-config"
function install_deps_debian12() {
  apt -y install $DEBIAN_12_DEPS
  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install --break-system-packages pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3
  gem install fpm -v 1.17.0
}

function install_deps_debian13() {
  apt -y install $DEBIAN_13_DEPS
  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install --break-system-packages pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3


  gem install fpm -v 1.17.0
}

function install_deps_ubuntu20.04() {
  apt -y install $UBUNTU_2004_DEPS
  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3
  gem install fpm -v 1.17.0
}

function install_deps_ubuntu22.04() {
  apt -y install $UBUNTU_2204_DEPS
  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3
  gem install fpm -v 1.17.0
}

function install_deps_ubuntu24.04() {
  apt -y install $UBUNTU_2404_DEPS
  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi

  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install --break-system-packages pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3
  gem install fpm -v 1.17.0
}
function install_deps_el8() {
  dnf module enable -y ruby:2.7
  yum install -y "https://download.rockylinux.org/pub/rocky/8.10/Devel/$(uname -m)/os/Packages/r/readline-devel-7.0-10.el8.$(uname -m).rpm"
  dnf -y install $EL8_DEPS
  gem install --no-document fpm 
  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3

  gem install fpm -v 1.17.0
}

function install_deps_el9() {
  yum install -y "https://download.rockylinux.org/pub/rocky/9.6/devel/$(uname -m)/os/Packages/r/readline-devel-8.1-4.el9.$(uname -m).rpm"
  dnf -y install $EL9_DEPS

  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install --break-system-packages pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3
  gem install fpm -v 1.17.0
}

function install_deps_el10() {
  yum install -y "https://download.rockylinux.org/pub/rocky/10.0/devel/$(uname -m)/os/Packages/r/readline-devel-8.2-11.el10.$(uname -m).rpm"
  dnf -y install $EL10_DEPS
  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install --break-system-packages pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3
  gem install fpm
}

function install_deps_amzn2023() {
  dnf -y install $AMZN2023_DEPS
  if [ "$(uname -m)" = "x86_64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  elif [ "$(uname -m)" = "aarch64" ]; then
      curl -L https://go.dev/dl/go1.24.6.linux-arm64.tar.gz -o /tmp/go1.24.6.linux-arm64.tar.gz
      mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-arm64.tar.gz -C /opt/golang
  else
      echo "unknown arch $(uname -m)"
      exit 1
  fi
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  install_rust
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec python -m pip install --break-system-packages pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3
  gem install fpm -v 1.17.0
}
