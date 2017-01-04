#!/usr/bin/env bash
################################################################################

command_exists () {
    type "$1" &> /dev/null ;
}

################################################################################

if [ $EUID -ne 0 ]; then
	echo "This script requires root or sudo privileges."
	exit 1
fi

if ! command_exists zip ; then
    echo Installing zip
	yum install zip

	if ! command_exists zip ; then
		echo "Error while installing zip. Please install zip and run this installation again."
		exit 1
	fi
fi
