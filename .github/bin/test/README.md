# Post-install smoke tests

`test_execute.bats` is the canonical smoke test for an installed asadm package.
It runs in CI against every Linux distro and macOS runner after the .deb/.rpm/.pkg
is installed, and can be run locally the same way:

```sh
bats .github/bin/test/test_execute.bats
```

`install_from_jfrog.sh` installs the published package from Artifactory
(used for ad-hoc verification of a release; not wired into CI today).
