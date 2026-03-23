# Post-install smoke tests

`test_execute.sh` is a plain Bash script (not Bats): a single smoke check does not need a test framework, avoids installing `bats` on runners, and matches the pattern used in other tools repos.

`install_from_jfrog.sh` installs the published package from Artifactory; `test_execute.sh` verifies the CLI is on `PATH` and responds to `--help`.

Legacy flows that invoked `bats .github/packaging/project/test/test_execute.bats` must be updated to run `test_execute.sh` (or call `.github/packaging/project/test/gha-test-main.sh`, which uses the scripts under `.github/bin/test/`).
