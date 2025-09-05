#!/usr/bin/env bash
VERSION=$(git rev-parse HEAD | cut -c -8)
function install_deps_debian11() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync libssl1.1 libssl-dev lzma \
                 lzma-dev  libffi-dev
  curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
  mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  /root/.asdf/installs/python/3.10.18/bin/python3 -m pip install pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/local/bin/pipenv
  gem install fpm
}

function install_deps_debian12() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync libssl3 libssl-dev lzma \
                 lzma-dev libffi-dev
  curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
  mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install --break-system-packages pipenv
  gem install fpm
}

function install_deps_ubuntu20.04() {
  apt -y install ruby make rpm git snapd curl binutils python3 python3-pip rsync libssl1.1 libssl-dev \
                 lzma lzma-dev libffi-dev
  curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
  mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install pipenv
  gem install fpm
}

function install_deps_ubuntu22.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync libssl3 libssl-dev \
               lzma lzma-dev libffi-dev
  curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
  mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install pipenv
  gem install fpm
}

function install_deps_ubuntu24.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync libssl3 libssl-dev \
               lzma lzma-dev libffi-dev
  curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
  mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install --break-system-packages pipenv
  gem install fpm
}

function install_deps_redhat-ubi9() {
  microdnf -y install ruby rpmdevtools make git python3 python3-pip rsync
  curl -L https://go.dev/dl/go1.24.6.linux-amd64.tar.gz -o /tmp/go1.24.6.linux-amd64.tar.gz
  mkdir -p /opt/golang && tar -zxvf /tmp/go1.24.6.linux-amd64.tar.gz -C /opt/golang
  /opt/golang/go/bin/go install github.com/asdf-vm/asdf/cmd/asdf@v0.18.0
  install /root/go/bin/asdf /usr/local/bin/asdf
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  microdnf install -y gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs \
                      sqlite sqlite-devel sqlite-libs
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install --break-system-packages pipenv
  gem install fpm
}
