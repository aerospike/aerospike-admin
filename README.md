# Aerospike Admin

## Description
Aerospike Admin provides an interface for Aerospike users to view the stat
of their Aerospike Cluster by fetching information from a running cluster (Cluster mode) 
a collectinfo file (Collectinfo-Analyzer), or logs (Log-analyser mode).
To get started run `asadm` and issue the `help` command. The
full documentation can be found [here](https://docs.aerospike.com/tools/asadm).

## Asinfo
The Aerospike Admin repo now contains asinfo. Asinfo has been a long time member of the
Aerospike Tools package but is now build together with asadm. Asinfo provides a raw
interface to Aerospike info protocol and is useful for debugging and development. The
full documentation can be found [here](https://docs.aerospike.com/tools/asinfo).

## Build and Install Aerospike Admin
### Runtime Dependencies
There are no runtime dependencies.  This is because the python interpreter is now 
bundled with asadm version 2.6 and later.

### Build Dependencies
- python 3.9
- pipenv

### Build and Install Asadm
1. Install python 3.9
2. Install [pipenv](https://pypi.org/project/pipenv/)
3. Build Asadm
    There are two ways asadm can be bundled: one-file and one-dir. Both, are related to
    pyinstaller's two methods of bundling. The one-file build is great if you want a single 
    executable artifact. The downside of one-file is that it must decompress into a /tmp
    directory in order to execute.  This causes a number of problems.  On macOS, the startup
    time is drastically increased because of the codesigning mechanism. The /tmp directory
    must be mounted with the the exec option. If the above scenarios describe your environment
    then use the one-dir build.
    * one-dir (default)
        ```
        make one-dir
        ```
    * one-file
        ```
        make one-file
        ```
4. Install asadm
    ```
    sudo make install
    ```

## Running Aerospike Admin in Live Cluster Mode.
```
asadm -h <Aerospike Server Address\>
Admin> help
```

## Running Aerospike Admin in Log-analyser Mode.
```
asadm -l [-f <location of logs\>]
Admin> help
```

## Running Aerospike Admin in Collectinfo Mode.
```
asadm -c [-f <location of collectinfo\>]
Admin> help
```


## Tests

### Setting Test Environment
asadm has unit and e2e tests. To setup environment for e2e tests, execute following steps:
- Enable security in the aerospike.conf file.
- Verify that the default user `admin` exists and that is has the default roles: `sys-admin`, `user-admin`, and `read-write`. 
- Start Aerospike cluster: Test machine should be part of this cluster with 3000 as asinfo port.
- Write a few records to cluster `asbenchmark -h <host> -Uadmin -Padmin`
- Wait for a few seconds so cluster can return histogram output properly.

### Running Tests
```
pipenv
./run_tests.sh
```

## Profiling
### Dependencies
- yappi: 0.92

### Run Profiler
asadm --profile
Do not exit with 'ctrl+c' exit with the *exit* command
