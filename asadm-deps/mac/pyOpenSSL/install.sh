#!/usr/bin/env bash
################################################################################

PYMODULE=pyOpenSSL

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