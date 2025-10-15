#!/usr/bin/env bash
set -x
function install_deps_debian11() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync libssl1.1 libssl-dev lzma \
                 lzma-dev  libffi-dev
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
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install --break-system-packages pipenv
  gem install fpm
}

function install_deps_debian13() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils rsync libssl3 libssl-dev lzma \
                 liblzma-dev libffi-dev libsqlite3-dev build-essential zlib1g-dev libbz2-dev libreadline-dev libncursesw5-dev libnss3-dev uuid-dev tk-dev xz-utils
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

function install_deps_ubuntu20.04() {
  apt -y install ruby make rpm git snapd curl binutils python3 python3-pip rsync libssl1.1 libssl-dev \
                 lzma lzma-dev libffi-dev
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
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install pipenv
  gem install fpm
}

function install_deps_ubuntu22.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync libssl3 libssl-dev \
               lzma lzma-dev libffi-dev
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
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install pipenv
  gem install fpm
}

function install_deps_ubuntu24.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync libssl3 libssl-dev \
               lzma lzma-dev libffi-dev
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
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install --break-system-packages pipenv
  gem install fpm
}
function install_deps_redhat-el8() {
  dnf -y install ruby rpm-build make git python3 python3-pip rsync gcc gcc-c++ \
                 make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs \
                 sqlite sqlite-devel sqlite-libs epel-release fpm 
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

  gem install fpm
}

function install_deps_redhat-el9() {
  dnf -y install ruby rpmdevtools make git python3 python3-pip rsync
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
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  dnf install -y gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs \
                      sqlite sqlite-devel sqlite-libs
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install pipenv
  gem install fpm
}

function install_deps_redhat-el10() {
  dnf -y install ruby rpmdevtools make git python3 python3-pip rsync
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
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  dnf install -y gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs \
                      sqlite sqlite-devel sqlite-libs
  asdf install python 3.10.18
  asdf set python 3.10.18
  asdf exec pip install pipenv
  gem install fpm
}

function install_deps_amazon-2023() {
  dnf -y install ruby rpmdevtools make git python3 python3-pip rsync
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
  asdf plugin add python https://github.com/asdf-community/asdf-python.git
  dnf install -y gcc g++ make automake zlib zlib-devel libffi-devel openssl-devel bzip2-devel xz-devel xz xz-libs \
                      sqlite sqlite-devel sqlite-libs
  asdf install python 3.10.18
  asdf set python 3.10.18
  echo "python 3.10.18" > /.tool-versions
  echo "python 3.10.18" > /root/.tool-versions
  asdf exec pip install pipenv
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python
  install /root/.asdf/installs/python/3.10.18/bin/python /usr/bin/python3
  install /root/.asdf/installs/python/3.10.18/bin/pipenv /usr/bin/pipenv
  install /root/.asdf/installs/python/3.10.18/bin/pip /usr/bin/pip
  install /root/.asdf/installs/python/3.10.18/bin/pip3 /usr/bin/pip3
  gem install fpm
}
