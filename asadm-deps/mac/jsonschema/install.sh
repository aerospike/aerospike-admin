#!/usr/bin/env bash

# Copyright 2018 Aerospike, Inc.
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

################################################################################

PYMODULE=jsonschema

################################################################################

command_exists () {
    type "$1" &> /dev/null ;
}

################################################################################

if [ $EUID -ne 0 ]; then
	echo "This script requires root or sudo privileges."
	exit 1
fi

if ! command_exists pip ; then
    echo Installing pip
	easy_install pip

	if ! command_exists pip ; then
		echo "Error while installing pip. Please install pip and run this installation again."
		exit 1
	fi
fi
echo Installing ${PYMODULE}
pip install ${PYMODULE} --upgrade
