#!/usr/bin/env bash

# Copyright 2013-2017 Aerospike, Inc.
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

if [ $EUID -ne 0 ]; then
        echo "This script requires root or sudo privileges."
        exit 1
fi

lowercase(){
    echo "$1" | sed "y/ABCDEFGHIJKLMNOPQRSTUVWXYZ/abcdefghijklmnopqrstuvwxyz/"
}

OS=`lowercase \`uname\``
DISTRO="UNKNOWN"

if [ "$OS" == "darwin" ]; then
    DISTRO="mac"
elif [ "$OS" == "linux" ]; then
    if [ -f /etc/redhat-release ] ; then
        DISTRO="rpm"
    elif [ -f /etc/debian_version ] ; then
        DISTRO="deb"
    elif [ -f /etc/system-release ] ; then
        DISTRO="rpm"
    fi
else
    echo "No support to OS {$OS}"
    exit 1
fi

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

for dep in $(cd ${DIR}/${DISTRO} && ls | grep -v install.sh); do
        if [ -x ${DIR}/${DISTRO}/${dep}/install.sh ]; then
                ${DIR}/${DISTRO}/${dep}/install.sh
        fi
done