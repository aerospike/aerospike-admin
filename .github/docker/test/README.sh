#!/usr/bin/env bash
#You can execute this README by replacing the following with your email and your JFrog token:
# JF_USERNAME='ghaywood@aerospike.com' JF_TOKEN='xxxxxxxxxxxxxxxxxx' .github/docker/test/README.sh


#Testing a package is available from the repository and can be executed:
JF_USERNAME=${JF_USERNAME:-"You must provide your JFrog username"}
JF_TOKEN=${JF_TOKEN:-"You must provide your JFrog token"}

#This commit should have already been pushed, so the action has built it and uploaded it to JFrog
PKG_VERSION=$(git describe --tags --always)

#Build the test container and install the current version of asadm from JFrog
# -d specifies the distro to test
.github/docker/test/entrypoint.sh -c -d ubuntu24.04
#...

#Execute the test runner
docker run -t -i asadm-pkg-tester-ubuntu24.04:$(git describe --tags --always)

#...
#test_execute.bats
# ✓ can run asadm
#
#1 test, 0 failures

