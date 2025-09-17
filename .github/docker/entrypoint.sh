#!/usr/bin/env bash
set -xeuo pipefail
env


SCRIPT_DIR="$(dirname "$(realpath "$0")")"



source $SCRIPT_DIR/build_package.sh

if [ -d ".git" ]; then
    GIT_DIR=$(pwd)
    PKG_DIR=$GIT_DIR/pkg
fi



function build_container() {
  docker build --progress=plain -t asbackup-pkg-builder-"$1"-"$(git rev-parse HEAD | cut -c -8)" -f .github/docker/Dockerfile-"$1" .
}


function execute_build_image() {
  export BUILD_DISTRO="$1"
  docker run -e BUILD_DISTRO -v $(realpath ../dist):/tmp/output asbackup-pkg-builder-"$BUILD_DISTRO"-"$(git rev-parse HEAD | cut -c -8)"
  ls -laht ../dist
}

INSTALL=false
BUILD_INTERNAL=false
BUILD_CONTAINERS=false
EXECUTE_BUILD=false
BUILD_DISTRO=${BUILD_DISTRO:-"all"}

while getopts "ibced:" opt; do
    case ${opt} in
        i )
            INSTALL=true
            ;;
        b )
            BUILD_INTERNAL=true
            ;;
        c )
            BUILD_CONTAINERS=true
            ;;
        e )
            EXECUTE_BUILD=true
            ;;
        d )
            BUILD_DISTRO="$OPTARG"
            ;;
    esac
done

shift $((OPTIND -1))

if [ "$INSTALL" = false ] && [ "$BUILD_INTERNAL" = false ] && [ "$BUILD_CONTAINERS" = false ] && [ "$EXECUTE_BUILD" = false ];
then
    echo """Error: Options:
    -i ( install )
    -b ( build internal )
    -c ( build containers )
    -e ( execute docker package build )
    -d [ redhat | ubuntu | debian ]""" 1>&2
    exit 1
fi

if grep -q 20.04 /etc/os-release; then
  ENV_DISTRO="ubuntu20.04"
elif grep -q 22.04 /etc/os-release; then
  ENV_DISTRO="ubuntu22.04"
elif grep -q 24.04 /etc/os-release; then
  ENV_DISTRO="ubuntu24.04"
elif grep -q "platform:el8" /etc/os-release; then
  ENV_DISTRO="redhat-el8"
elif grep -q "platform:el9" /etc/os-release; then
  ENV_DISTRO="redhat-el9"
elif grep -q "amazon_linux:2023" /etc/os-release; then
  ENV_DISTRO="amazon-2023"
elif grep -q "bullseye" /etc/os-release; then
  ENV_DISTRO="debian11"
elif grep -q "bookworm" /etc/os-release; then
  ENV_DISTRO="debian12"
elif grep -q "trixie" /etc/os-release; then
  ENV_DISTRO="debian13"
else
  cat /etc/os-release
  echo "os not supported"
fi


if [ "$INSTALL" = "true" ]; then
  if [ "$ENV_DISTRO" = "ubuntu20.04" ]; then
      echo "installing dependencies for Ubuntu 20.04"
      install_deps_ubuntu20.04
  elif [ "$ENV_DISTRO" = "ubuntu22.04" ]; then
      echo "installing dependencies for Ubuntu 22.04"
      install_deps_ubuntu22.04
  elif [ "$ENV_DISTRO" = "ubuntu24.04" ]; then
      echo "installing dependencies for Ubuntu 24.04"
      install_deps_ubuntu24.04
  elif [ "$ENV_DISTRO" = "redhat-el8" ]; then
      echo "installing dependencies for RedHat el8"
      install_deps_redhat-el8
  elif [ "$ENV_DISTRO" = "redhat-el9" ]; then
      echo "installing dependencies for RedHat el9"
      install_deps_redhat-el9
  elif [ "$ENV_DISTRO" = "amazon-2023" ]; then
      echo "installing dependencies for Amazon 2023"
      install_deps_redhat-amazon-2023
  elif [ "$ENV_DISTRO" = "debian11" ]; then
      echo "installing dependencies for Debian 11"
      install_deps_debian11
  elif [ "$ENV_DISTRO" = "debian12" ]; then
      echo "installing dependencies for Debian 12"
      install_deps_debian12
  elif [ "$ENV_DISTRO" = "debian13" ]; then
      echo "installing dependencies for Debian 13"
      install_deps_debian13
  else
      cat /etc/os-release
      echo "distro not supported"
  fi
elif [ "$BUILD_INTERNAL" = "true" ]; then
  build_packages
elif [ "$BUILD_CONTAINERS" = "true" ]; then
  if  [ "$BUILD_DISTRO" = "all" ]; then
    build_container debian11
    build_container debian12
    build_container debian13
    build_container ubuntu20.04
    build_container ubuntu22.04
    build_container ubuntu24.04
    build_container redhat-el8
    build_container redhat-el9
    build_container amazon-2023
  else
    build_container $BUILD_DISTRO
  fi
fi

if [ "$EXECUTE_BUILD" = "true" ]; then
   if [ "$BUILD_DISTRO" = "all" ]; then
        echo "building package for Debian 11"
        execute_build_image debian11
        echo "building package for Debian 12"
        execute_build_image debian12
        echo "building package for Debian 13"
        execute_build_image debian13
        echo "building package for Ubuntu 20.04"
        execute_build_image ubuntu20.04
        echo "building package for Ubuntu 22.04"
        execute_build_image ubuntu22.04
        echo "building package for Ubuntu 24.04"
        execute_build_image ubuntu24.04
        echo "building package for RedHat el8"
        execute_build_image redhat-el8
        echo "building package for RedHat el9"
        execute_build_image redhat-el9
        echo "building package for Amazon 2023"
        execute_build_image amazon-2023
    else
        echo "building package for $BUILD_DISTRO"
        execute_build_image $BUILD_DISTRO
    fi
fi