#!/usr/bin/env bash
set -xeuo pipefail
env


SCRIPT_DIR="$(dirname "$(realpath "$0")")"



if [ -d ".git" ]; then
    GIT_DIR=$(pwd)
    PKG_DIR=$GIT_DIR/pkg
fi



function build_container() {
  PKG_VERSION=${PKG_VERSION:-$(git describe --tags --always)}
  docker build --build-arg=PKG_VERSION="$PKG_VERSION" --build-arg=JF_USERNAME="$JF_USERNAME" --build-arg=JF_TOKEN="$JF_TOKEN" --progress=plain -t asadm-pkg-tester-"$1":"$PKG_VERSION" -f .github/docker/test/Dockerfile-"$1" .
  docker tag asadm-pkg-tester-"$1":"$PKG_VERSION" asadm-pkg-tester-"$1":"latest"
}


function execute_build_image() {
  export BUILD_DISTRO="$1"
  docker run -e BUILD_DISTRO -v $(realpath ../dist):/tmp/output asadm-pkg-tester-"$BUILD_DISTRO"-"$(git rev-parse HEAD | cut -c -8)"
}
RUN_TESTS=false
INSTALL=false
BUILD_INTERNAL=false
BUILD_CONTAINERS=false
EXECUTE_BUILD=false
BUILD_DISTRO=${BUILD_DISTRO:-"all"}


while getopts "tibced:" opt; do
    case ${opt} in
        t )
            RUN_TESTS=true
            ;;
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

if [ "$INSTALL" = false ] && [ "$BUILD_INTERNAL" = false ] && [ "$BUILD_CONTAINERS" = false ] && [ "$EXECUTE_BUILD" = false ] && [ "$RUN_TESTS" = false ];
then
    echo """Error: Options:
    -t ( test )
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
  ENV_DISTRO="el8"
elif grep -q "platform:el9" /etc/os-release; then
  ENV_DISTRO="el9"
elif grep -q "platform:el10" /etc/os-release; then
  ENV_DISTRO="el10"
elif grep -q "amazon_linux:2023" /etc/os-release; then
  ENV_DISTRO="amzn2023"
elif grep -q "bookworm" /etc/os-release; then
  ENV_DISTRO="debian12"
elif grep -q "trixie" /etc/os-release; then
  ENV_DISTRO="debian13"
else
  cat /etc/os-release
  echo "os not supported"
fi

if [ "$RUN_TESTS" = "true" ]; then
  bats .github/docker/test/test_execute.bats
  exit $?
elif [ "$INSTALL" = "true" ]; then
  if [ "$ENV_DISTRO" = "ubuntu20.04" ]; then
      echo "installing dependencies for Ubuntu 20.04"
      install_test_deps_ubuntu20.04
  elif [ "$ENV_DISTRO" = "ubuntu22.04" ]; then
      echo "installing dependencies for Ubuntu 22.04"
      install_test_deps_ubuntu22.04
  elif [ "$ENV_DISTRO" = "ubuntu24.04" ]; then
      echo "installing dependencies for Ubuntu 24.04"
      install_test_deps_ubuntu24.04
  elif [ "$ENV_DISTRO" = "el8" ]; then
      echo "installing dependencies for RedHat el8"
      install_test_deps_el8
  elif [ "$ENV_DISTRO" = "el9" ]; then
      echo "installing dependencies for RedHat el9"
      install_test_deps_el9
  elif [ "$ENV_DISTRO" = "el10" ]; then
      echo "installing dependencies for RedHat el10"
      install_test_deps_el10
  elif [ "$ENV_DISTRO" = "amzn2023" ]; then
      echo "installing dependencies for Amazon 2023"
      install_test_deps_redhat-amzn2023
  elif [ "$ENV_DISTRO" = "debian12" ]; then
      echo "installing dependencies for Debian 12"
      install_test_deps_debian12
  elif [ "$ENV_DISTRO" = "debian13" ]; then
      echo "installing dependencies for Debian 13"
      install_test_deps_debian13
  else
      cat /etc/os-release
      echo "distro not supported"
  fi
elif [ "$BUILD_INTERNAL" = "true" ]; then
  test_packages
elif [ "$BUILD_CONTAINERS" = "true" ]; then
  if  [ "$BUILD_DISTRO" = "all" ]; then
    build_container debian12
    build_container debian13
    build_container ubuntu20.04
    build_container ubuntu22.04
    build_container ubuntu24.04
    build_container el8
    build_container el9
    build_container el10
    build_container amzn2023
  else
    build_container $BUILD_DISTRO
  fi
fi

if [ "$EXECUTE_BUILD" = "true" ]; then
   if [ "$BUILD_DISTRO" = "all" ]; then
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
        execute_build_image el8
        echo "building package for RedHat el9"
        execute_build_image el9
        echo "building package for RedHat el10"
        execute_build_image el10
        echo "building package for Amazon 2023"
        execute_build_image amzn2023
    else
        echo "building package for $BUILD_DISTRO"
        execute_build_image $BUILD_DISTRO
    fi
fi