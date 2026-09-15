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

# macOS build guards

`check_crypto_static_openssl.bats`, `check_min_os.bats` and `macos_min_version.bats` cover the
scripts that gate a macOS bundle: cryptography must link OpenSSL statically, nothing in the
payload may declare a floor above `MACOS_MIN_VERSION`, and that floor must be read from
`pkg/Makefile` without picking up anything else on the line. `otool` and `file` are stubbed on
`PATH`, so these need no macOS runner and no built bundle, and they run on every pull request.

```sh
bats .github/bin/test/check_crypto_static_openssl.bats .github/bin/test/check_min_os.bats .github/bin/test/macos_min_version.bats
```
