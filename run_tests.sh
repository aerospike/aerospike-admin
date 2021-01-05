#!/usr/bin/env sh

# Copyright 2013-2021 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Used for testing "show latencies -v" to get micro benchmarks
echo "Configuring additional write & read benchmarks for server 5.1+"
asinfo -v 'set-config:context=namespace;id=test;enable-benchmarks-write=true'
asinfo -v 'set-config:context=namespace;id=test;enable-benchmarks-read=true'

echo "Running unit test cases :"
# Forced to run with python3 because some tests were not running correctly 
python3 -m unittest2 discover -s test/unit -t .

echo
echo "Running e2e test cases :"
python3 -m unittest2 discover -s test/e2e -t .

echo
echo "Running asinfo test cases :"
./test/test_asinfo.sh
