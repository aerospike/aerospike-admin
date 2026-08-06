#!/usr/bin/env bats

# `run` captures status and output instead of relying on errexit. The previous
# form (`asadm --help` followed by `[ "$?" -eq 0 ]`) could not fail: a non-zero
# exit aborted the body at the first line under errexit, so the check only ever
# ran when $? was already 0. That matters now that build-and-release.yml runs
# this file AFTER the astools.conf reinstall cycle, making it the pipeline's last
# word on whether asadm starts.
@test "can run asadm" {
  run asadm --help
  [ "$status" -eq 0 ]
  [ -n "$output" ]
}

@test "can run asinfo" {
  run asinfo --help
  [ "$status" -eq 0 ]
  [ -n "$output" ]
}
