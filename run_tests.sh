#!/usr/bin/env sh

# Copyright 2013-2019 Aerospike, Inc.
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

echo "Running unit test cases :"
unit2 discover -s test/unit -t .

echo
echo "Running e2e test cases :"
unit2 discover -s test/e2e -t .

echo
echo "Running asinfo test cases :"
./test/test_asinfo.sh
