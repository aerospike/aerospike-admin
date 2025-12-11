#!/usr/bin/env bash
set -xeuo pipefail

# Required functions:
# install_deps_debian11
# install_deps_debian12
# install_deps_debian13
# install_deps_ubuntu20.04
# install_deps_ubuntu22.04
# install_deps_ubuntu24.04
# install_deps_el8
# install_deps_el9
# install_deps_el10
# install_deps_amzn2023

function install_fpm() {
  gem install fpm -v 1.17.0
}

function install_deps_debian11() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils
  #Install your dependencies
  install_fpm
}

function install_deps_debian12() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils
  #Install your dependencies
  install_fpm
}

function install_deps_debian13() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils
  #Install your dependencies
  install_fpm
}

function install_deps_ubuntu20.04() {
  apt -y install ruby make rpm git snapd curl binutils
  #Install your dependencies
  install_fpm
}

function install_deps_ubuntu22.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils
  #Install your dependencies
  install_fpm
}

function install_deps_ubuntu24.04() {
  apt -y install ruby-rubygems make rpm git snapd curl binutils
  #Install your dependencies
  install_fpm
}

function install_deps_el8() {
  dnf module enable -y ruby:2.7
  dnf -y install ruby ruby-devel redhat-rpm-config rubygems rpm-build make git
  #Install your dependencies
  install_fpm
}

function install_deps_el9() {
  dnf -y install ruby rpmdevtools make git
  #Install your dependencies
  install_fpm
}

function install_deps_el10() {
  dnf -y install ruby rpmdevtools make git
  #Install your dependencies
  install_fpm
}

function install_deps_amzn2023() {
  dnf -y install ruby rpmdevtools make git
  #Install your dependencies
  install_fpm
}