#!/usr/bin/env bash

run_test(){
    unknown_option_error="Do not understand"
    cmd_out=`./asinfo.py -v "$1"`
    cmd_status="$?"
#    echo ${cmd_out}
    if [ "$cmd_status" -ne 0 ]; then
       return 1
    fi
    if [[ $cmd_out == *"${unknown_option_error}"* ]]; then
       return 1
    fi
    if [[ $cmd_out != *"$2"* ]];then
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

asinfo_cmd="get-dc-config"
output_substring1="dc-name"
output_substring2="DC_Name"
if ( ! run_test ${asinfo_cmd} ${output_substring1} ) && ( ! run_test ${asinfo_cmd} ${output_substring2} ) ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="hist-dump:ns=test;hist=ttl"
output_substring="test:ttl"
if ! run_test ${asinfo_cmd} ${output_substring} ; then
	echo "Error while running asinfo command: ${asinfo_cmd}"
	exit 1
fi

asinfo_cmd="latency:"
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

# Test cases for invisible escape characters which can get added due to any python library like readline

cmd_out=`./asinfo.py -v "STATUS" | tr -dc '[:alnum:]\n\r'`
cmd_status="$?"

if [ "$cmd_status" -ne 0 ]; then
    echo "Error: translate command over asinfo output failed"
    exit 1
fi
if [[ $cmd_out != "OK" ]];then
    echo "Error: extra characters in asinfo output. Expected OK but output is ${cmd_out}"
    exit 1
fi

cmd_out=`./asinfo.py -v "STATUS" | hexdump`
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

# Test cases for asadm error handling

## Wrong Host
expected_error_msg="request to  WrongHost : 3000  returned error"
cmd_out=`./asinfo.py -h "WrongHost"`
cmd_status="$?"

if [ "$cmd_status" -ne 1 ]; then
    echo "Error: asinfo with wrong Host failed"
    exit 1
fi
#if [[ $cmd_out != $expected_error_msg ]];then
#    echo "Error: asinfo with wrong Host failed. Expected '${expected_error_msg}' but output is '${cmd_out}'"
#    exit 1
#fi

# Wrong Port
expected_error_msg="request to  127.0.0.1 : 98989898  returned error"
cmd_out=`./asinfo.py -h "localhost" -p 98989898`
cmd_status="$?"

if [ "$cmd_status" -ne 1 ]; then
    echo "Error: asinfo with wrong Port failed"
    exit 1
fi
#if [[ $cmd_out != $expected_error_msg ]];then
#    echo "Error: asinfo with wrong Port failed. Expected '${expected_error_msg}' but output is '${cmd_out}'"
#    exit 1
#fi

# Wrong command value
expected_error_msg="Error: Invalid command 'WrongCommand'"
cmd_out=`./asinfo.py -v "WrongCommand"`
cmd_status="$?"

if [ "$cmd_status" -ne 1 ]; then
    echo "Error: asinfo with wrong Command Value failed"
    exit 1
fi
if [[ $cmd_out != $expected_error_msg ]];then
    echo "Error: asinfo with wrong Command Value failed. Expected '${expected_error_msg}' but output is '${cmd_out}'"
    exit 1
fi

echo
echo "All asinfo Test passed Successfully"
exit 0