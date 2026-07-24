#!/usr/bin/env bats
#
# Config-file lifecycle tests. Run ONLY from the linux-install and mac-install
# jobs (never the docker smoke job, which shims tool binaries onto the host).
# Requires two env vars exported by the install step:
#   ASTOOLS_SAMPLE    - absolute path to the packaged astools.conf.sample
#   ASTOOLS_REINSTALL - command that reinstalls the package from its local file

setup() {
  CONF=/etc/aerospike/astools.conf
  SAMPLE="${ASTOOLS_SAMPLE}"
  if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi
}

@test "astools.conf is created on install and matches the sample" {
  [ -f "$CONF" ]
  [ "$(cat "$CONF")" = "$(cat "$SAMPLE")" ]
}

@test "astools.conf is recreated after removal + reinstall (after-upgrade wiring)" {
  $SUDO rm -f "$CONF"
  [ ! -e "$CONF" ]
  eval "${ASTOOLS_REINSTALL}"
  [ -f "$CONF" ]
  [ "$(cat "$CONF")" = "$(cat "$SAMPLE")" ]
}

@test "user edits survive reinstall" {
  echo "# user edit marker" | $SUDO tee -a "$CONF" >/dev/null
  eval "${ASTOOLS_REINSTALL}"
  grep -q "# user edit marker" "$CONF"
}
