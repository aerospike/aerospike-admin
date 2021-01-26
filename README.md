# Aerospike Admin
## Description
Aerospike Admin provides an interface for Aerospike users to view the stat
of their Aerospike Cluster by fetching information from a running cluster (Cluster mode) 
a collectinfo file (Collectinfo-Analyzer), or logs (Log-analyser mode).
Start the tool with *asadm* and run the *help* command to get started.

## Installing Aerospike Admin

### Build Dependencies

- pip >= 9.0.3
- pex == 1.6.1
- requests == 2.18.4

### Install asadm as PEX
```
sudo make
sudo make install
```

### Install asadm without PEX
```
sudo pip install -r requirements.txt
sudo make no_pex
sudo make install
```

## Running Aerospike Admin in Live Cluster Mode.
asadm -h <Aerospike Server Address\>
Admin> help

## Running Aerospike Admin in Log-analyser Mode.
asadm -l [-f <location of logs\>]
Admin> help

## Running Aerospike Admin in Collectinfo Mode.
asadm -c [-f <location of collectinfo\>]
Admin> help


## Dependencies
- python 3.4+

### Python Modules
- bcrypt == 3.1.4
- cryptography >= 2.4.2
- jsonschema >= 2.5.1
- pexpect: >= 3.0
- ply: >= 3.4
- pyOpenSSL: >= 18.0.0
- pyasn1: >= 0.3.1
- toml


### Mac OSX
Requires Python 3.5+
Run following command to ensure asadm history works properly:
```
sudo easy_install -a readline
```

## Tests
### Dependencies
- unittest2: 0.5.1
- Mock: 1.0.1

### Setting Test Environment
asadm has unit and e2e tests. To setup environment for e2e tests, execute following steps:
- Enable security in the aerospike.conf file.
- Verify that the default user `admin` exists and that is has the default roles: `sys-admin`, `user-admin`, and `read-write`. 
- Start Aerospike cluster: Test machine should be part of this cluster with 3000 as asinfo port.
- Write few records to cluster `asbenchmark -h <host> -Uadmin -Padmin`
- Wait for few seconds so cluster can return histogram output properly.

### Running Tests
- pip install -r requirements.txt
- ./run_tests.sh

## Profiling
### Dependencies
- yappi: 0.92

### Run Profiler
asadm --profile
Do not exit with 'ctrl+c' exit with the *exit* command
