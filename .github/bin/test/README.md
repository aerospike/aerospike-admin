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

## Version checks

Beyond running, the tests assert that **the version asadm and asinfo report matches
the repo's `VERSION` file**, so a package labelled with one version but carrying a
binary stamped with another fails here instead of downstream in the aerospike-tools
bundle.

Both printed lines are compared. asadm and asinfo split the embedded version on `-`,
so `5.0.3-rc3` reports `Version 5.0.3` / `Build rc3` and a bare `5.0.3` reports no
`Build` line at all. Asserting the `Build` line is what catches a stale rc binary
inside a later rc's package, where the two differ only by the iteration.

`test_execute.sh` is the same checks without bats; both share the assertions in
`version_lib.sh`.

Both accept `EXPECTED_VERSION` to verify a package built from a revision other than
the checkout you run them from. CI sets it to the workflow's `BUILD_VERSION`, which
on a dev build carries the commit sha instead of the `rcN` in the file. It still has
to agree with the VERSION file on `MAJOR.MINOR.PATCH`, so a run wired to the wrong
workflow output fails rather than testing against whatever it was handed.

```sh
EXPECTED_VERSION=5.0.3-rc3 .github/bin/test/test_execute.sh
```

`test_astools_conf.bats` covers the packaged `astools.conf` handling.
