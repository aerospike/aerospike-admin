#!/usr/bin/env bats
VERSION=$(git rev-parse HEAD | cut -c -8)

@test "build debian11" {
  .github/docker/entrypoint.sh -c -d debian11
  [ "$?" -eq 0 ]
}

@test "build debian11 package" {
  TEMP_DIR=$(mktemp -d)
  docker run -e BUILD_DISTRO="debian11" -v $TEMP_DIR:/tmp/output "asadmin-pkg-builder-debian11-$VERSION"
  [ $? -eq 0 ] && [ -f $TEMP_DIR/debian11/*.deb ]
}

@test "build debian12" {
  .github/docker/entrypoint.sh -c -d debian12
  [ "$?" -eq 0 ]
}

@test "build debian12 package" {
  TEMP_DIR=$(mktemp -d)
  docker run -e BUILD_DISTRO="debian12" -v $TEMP_DIR:/tmp/output "asadmin-pkg-builder-debian12-$VERSION"
  [ $? -eq 0 ] && [ -f $TEMP_DIR/debian12/*.deb ]
}

@test "build ubuntu20.04" {
  .github/docker/entrypoint.sh -c -d ubuntu20.04
  [ "$?" -eq 0 ]
}

@test "build ubuntu20.04 package" {
  TEMP_DIR=$(mktemp -d)
  docker run -e BUILD_DISTRO="ubuntu20.04" -v $TEMP_DIR:/tmp/output "asadmin-pkg-builder-ubuntu20.04-$VERSION"
  [ $? -eq 0 ] && [ -f $TEMP_DIR/ubuntu20.04/*.deb ]
}


@test "build ubuntu22.04" {
  .github/docker/entrypoint.sh -c -d ubuntu22.04
  [ "$?" -eq 0 ]
}

@test "build ubuntu22.04 package" {
  TEMP_DIR=$(mktemp -d)
  docker run -e BUILD_DISTRO="ubuntu22.04" -v $TEMP_DIR:/tmp/output "asadmin-pkg-builder-ubuntu22.04-$VERSION"
  [ $? -eq 0 ] && [ -f $TEMP_DIR/ubuntu22.04/*.deb ]
}

@test "build ubuntu24.04" {
  .github/docker/entrypoint.sh -c -d ubuntu24.04
  [ "$?" -eq 0 ]
}

@test "build ubuntu24.04 package" {
  TEMP_DIR=$(mktemp -d)
  docker run -e BUILD_DISTRO="ubuntu24.04" -v $TEMP_DIR:/tmp/output "asadmin-pkg-builder-ubuntu24.04-$VERSION"
  [ $? -eq 0 ] && [ -f $TEMP_DIR/ubuntu24.04/*.deb ]
}

@test "build redhat ubi9" {
  .github/docker/entrypoint.sh -c -d redhat-ubi9
  [ "$?" -eq 0 ]
}

@test "build redhat ubi9 package" {
  TEMP_DIR=$(mktemp -d)
  docker run -e BUILD_DISTRO="redhat-ubi9" -v $TEMP_DIR:/tmp/output "asadmin-pkg-builder-redhat-ubi9-$VERSION"
  [ $? -eq 0 ] && [ -f $TEMP_DIR/redhat-ubi9/*.deb ]
}