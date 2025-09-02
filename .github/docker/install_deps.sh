#!/usr/bin/env bash

function install_deps_debian12() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync
  pip3 install pipenv
  gem install fpm
}


function install_deps_debian11() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync
  pip3 install pipenv
  gem install fpm
}


function install_deps_ubuntu20.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync
  pip3 install pipenv
  gem install fpm
}

function install_deps_ubuntu22.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync
  pip3 install pipenv
  gem install fpm
}

function install_deps_ubuntu24.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils python3 python3-pip rsync
  pip3 install pipenv
  gem install fpm
}

function install_deps_ubi9() {
  microdnf -y install ruby rpmdevtools make git python3 python3-pip rsync
  gem install fpm
}
