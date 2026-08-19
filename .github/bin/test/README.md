# Post-install smoke tests

`test_execute.bats` is the canonical smoke test for an installed asadm package. It runs in
CI against every Linux distro and macOS runner after the .deb/.rpm/.pkg built *in that
workflow run* is installed (never a JFrog pull, which would only prove JFrog returned a
file). `test_execute.sh` is the same checks without bats.

Both share the assertions in `version_lib.sh`, which documents the version contract and
`EXPECTED_VERSION`.

```sh
bats .github/bin/test/test_execute.bats
EXPECTED_VERSION=5.0.3-rc3 .github/bin/test/test_execute.sh
```

`test_astools_conf.bats` covers the packaged `astools.conf` handling.
