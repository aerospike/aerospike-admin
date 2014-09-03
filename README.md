# AeroSpike ADMIN
## Description
AeroSpike ADMIN provides and interface for Aerospike users to view the current
stat of their Aerospike Cluster. Start the tool with *python asadmin.py* and
run the *help* command to get started.

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
