#!/usr/bin/env bats

@test "can run asadm" {
  asadm --help
  [ "$?" -eq 0 ]
}

@test "can run asinfo" {
  asinfo --help
  [ "$?" -eq 0 ]
}
