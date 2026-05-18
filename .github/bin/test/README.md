# Post-install smoke tests

`test_execute.bats` is the canonical smoke test for an installed asadm package.
It runs in CI against every Linux distro and macOS runner after the .deb/.rpm/.pkg
built in this workflow is installed locally, and can be run locally the same way:

```sh
bats .github/bin/test/test_execute.bats
```

The CI test phase deliberately installs packages built *in this workflow run* —
it does **not** pull from JFrog. Pulling from JFrog at test time would only
verify that JFrog returned a file, not that our built artifact is correct.
