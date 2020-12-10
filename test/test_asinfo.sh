#!/usr/bin/env bash

# Copyright 2013-2020 Aerospike, Inc.
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

run_test(){
    unknown_option_error="Do not understand"
    asinfo_cmd_str="'$1' "
#    echo ${asinfo_cmd_str}
    cmd_out=`./asadm.py --asinfo-mode --no-config-file -e "${asinfo_cmd_str}" -Uadmin -Padmin`
    cmd_status="$?"
#    echo ${cmd_out}
    if [ "$cmd_status" -ne 0 ]; then
    #    echo
       return 1
    fi
    if [[ $cmd_out == *"${unknown_option_error}"* ]]; then
    #    echo
       return 1
    fi
    if [[ $cmd_out != *"$2"* ]];then
    #    echo
       return 1
    fi
    echo -n "."
}

asinfo_cmd="bins"
output_substring="bin"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="bins/test"
output_substring="bin"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="get-config:context=namespace;id=test"
output_substring="default-ttl"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

# Deprecated with server 5.0, replaced with get-config below
# asinfo_cmd="get-dc-config"
# output_substring1="dc-name"
# output_substring2="DC_Name"
# if ( ! run_test ${asinfo_cmd} ${output_substring1} ) && ( ! run_test ${asinfo_cmd} ${output_substring2} ) ; then
# 	echo "Error while running asinfo command: ${asinfo_cmd}"
# 	exit 1
# fi

asinfo_cmd="get-config:context=xdr"
output_substring1="dcs"
if ( ! run_test ${asinfo_cmd} ${output_substring1} ) ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="hist-dump:ns=test;hist=ttl"
output_substring="test:ttl"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	asinfo_cmd="histogram:namespace=test;type=ttl"
	output_substring="units=seconds:"
	if ! run_test ${asinfo_cmd} ${output_substring} ; then
		echo "Error while running asinfo command: ${asinfo_cmd}"
		exit 1
	fi
fi

asinfo_cmd="latencies:"
output_substring="test"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="log/0"
output_substring="fabric:INFO"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="namespace/test"
output_substring="prole"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="get-config:context=network"
output_substring="address"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="STATUS"
output_substring="OK"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

# Test for invisible escape characters which can get added due to any python library like readline

asinfo_cmd_str="\"STATUS\" "

cmd_out=`./asadm.py -Uadmin -Padmin --asinfo-mode --no-config-file -e "${asinfo_cmd_str}" | tr -dc '[:alnum:]\n\r'`
cmd_status="$?"

if [ "$cmd_status" -ne 0 ]; then
    echo "Error: translate command over asinfo output failed"
    exit 1
fi
if [[ $cmd_out != "OK" ]];then
    echo "Error: extra characters in asinfo output. Expected OK but output is ${cmd_out}"
    exit 1
fi

cmd_out=`./asadm.py -Uadmin -Padmin --asinfo-mode --no-config-file -e "${asinfo_cmd_str}" | hexdump`
cmd_status="$?"
expected_output=`echo "OK" | hexdump`

if [ "$cmd_status" -ne 0 ]; then
    echo "Error: hexdump command over asinfo output failed"
    exit 1
fi
if [[ $cmd_out != $expected_output ]];then
    echo "Error: hexdump command over asinfo output failed"
    exit 1
fi

echo
echo "OK"
exit 0
