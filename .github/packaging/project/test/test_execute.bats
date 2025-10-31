#!/usr/bin/env bats

@test "can run asadm" {
  asadm --help
  [ "$?" -eq 0 ]
}