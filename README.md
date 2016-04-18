# Aerospike Admin
## Description
Aerospike Admin provides and interface for Aerospike users to view the current
stat of their Aerospike Cluster. Start the tool with *python asadmin.py* and
run the *help* command to get started.

## Installing Aerospike Admin
```
make
sudo make install
```

## Running Aerospike Admin Against Cluster
asadm -h <Aerospike Server Address>
Admin> help

## Running Aerospike Admin for logs
asadm -f [-l <location of logs>]
Admin> help

## Dependencies
- python 2.6+

## Tests
### Dependencies
- unittest2: 0.5.1
- Mock: 1.0.1

### Running Tests
./run_tests.sh or unit2 discover

## Profiling
### Dependencies
- yappi: 0.92

### Run Profiler
python asadmin.py --profile
Do not exit with 'ctrl+c' exit with the *exit* command
