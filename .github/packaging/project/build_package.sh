#!/usr/bin/env bash
set -xeuo pipefail

function build_packages(){
  if [ "$ENV_DISTRO" = "" ]; then
    echo "ENV_DISTRO is not set"
    return
  fi
  export PATH=$PATH:/opt/golang/go/bin
  GIT_DIR=$(git rev-parse --show-toplevel)

  # build
  cd "$GIT_DIR" || exit 1
  make clean
  make

  echo "build_package.sh version: $(git describe --tags --always --abbrev=7)"
  VERSION=$(git describe --tags --always --abbrev=7)
  export VERSION

  # package
  cd "$GIT_DIR"/pkg || exit 1
  make clean
  echo "building package for $BUILD_DISTRO"

  if [[ "$ENV_DISTRO" == *"ubuntu"* ]]; then
    make deb
  elif [[ "$ENV_DISTRO" == *"debian"* ]]; then
    make deb
  elif [[ "$ENV_DISTRO" == *"el"* ]]; then
    make rpm
  elif [[ "$ENV_DISTRO" == *"amzn"* ]]; then
    make rpm
  else
    make tar
  fi

  mkdir -p /tmp/output/"$ENV_DISTRO"
  cp -a "$GIT_DIR"/pkg/target/* /tmp/output/"$ENV_DISTRO"
}
