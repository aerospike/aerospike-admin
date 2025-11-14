#!/usr/bin/env bash
set -xeuo pipefail

function build_packages(){
  if [ "$ENV_DISTRO" = "" ]; then
    echo "ENV_DISTRO is not set"
    return
  fi
  chown -R root:root .
  GIT_DIR=$(git rev-parse --show-toplevel)
  cd "$GIT_DIR"
  make one-file
  cd $GIT_DIR/pkg
  echo "building package for $BUILD_DISTRO"

  if [[ $ENV_DISTRO == *"ubuntu"* ]]; then
    make deb
  elif [[ $ENV_DISTRO == *"debian"* ]]; then
    make deb
  elif [[ $ENV_DISTRO == *"el"* ]]; then
    make rpm
  elif [[ $ENV_DISTRO == *"amzn"* ]]; then
    make rpm
  else
    make tar
  fi

  mkdir -p /tmp/output/$ENV_DISTRO
  cp -a $GIT_DIR/pkg/target/* /tmp/output/$ENV_DISTRO
}