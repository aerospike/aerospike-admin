# Aerospike Admin
## Description
Aerospike Admin provides an interface for Aerospike users to view the stat
of their Aerospike Cluster by fetching information from a running cluster (Cluster mode) 
a collectinfo file (Collectinfo-Analyzer), or logs (Log-analyser mode).
Start the tool with *asadm* and run the *help* command to get started.

## Installing Aerospike Admin
### Runtime Dependencies
There are no runtime dependencies.  This is because the python interpreter is now 
bundled with asadm version 2.6 and later.

### Build Dependencies
- python 3.9
- pipenv

### Build and Install Asadm
1. Install python 3.9
2. Install [pipenv](https://pypi.org/project/pipenv/)
3. Run
```
sudo make
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


### Python Modules
#### Runtime
- bcrypt = "==3.1.4"
- cryptography = "==3.4.7"
- distro = "==1.5.0"
- jsonschema = "==2.5.1"
- pexpect = "==4.4.0"
- ply = "==3.11"
- pyasn1 = "==0.4.2"
- toml = "==0.9.4"
- yappi = "==0.98"
- pyOpenSSL = "==18.0.0"
- setuptools = "*"
- aiohttp = "==3.8.1"


#### Build
- pyinstaller = "==4.7"
- macholib = * **for mac build only**

#### Test
- pytest = "*"
- unittest2 = "*"
- mock = "*"
- asynctest = "*"

#### Dev
black = "*"
flake8 = "*"

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
