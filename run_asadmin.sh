#!/usr/bin/env sh

# Copyright 2013-2014 Aerospike, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

BASEDIR=$(dirname $0)

pyz_file=$BASEDIR/asadmin
py_file=$BASEDIR/asadmin.py

if [ -e "$pyz_file" ]
then
    use_file=$pyz_file
elif [ -e "$py_file" ]
then
    use_file=$py_file
fi

python $use_file "$@"
