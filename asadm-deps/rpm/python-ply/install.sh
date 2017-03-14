#!/usr/bin/env bash
################################################################################

PYMODULE=ply

################################################################################

command_exists () {
    type "$1" &> /dev/null ;
}

################################################################################

if [ $EUID -ne 0 ]; then
	echo "This script requires root or sudo privileges."
	exit 1
fi

python <<EOF
try:
	import ${PYMODULE}
	print "ply already installed on this machine"
	import sys
	sys.exit(0)
except Exception as e:
	import sys
	sys.exit(1)
EOF
has_pymodule=$?

if [ $has_pymodule -eq 0 ]; then
	exit 0
fi

pip_command="pip"
if ! command_exists ${pip_command} ; then
    echo Installing epel-release
	yum install epel-release

	echo Installing pip
	yum install -y python-pip

	if ! command_exists ${pip_command} ; then
		if command_exists pip-python ; then
			pip_command="pip-python"
		elif command_exists python-pip ; then
			pip_command="python-pip"
		fi
	fi
	if ! command_exists ${pip_command} ; then
		echo "Error while installing pip. Please install pip and run this installation again."
		exit 1
	fi
fi
echo Installing ${PYMODULE}
${pip_command} install ${PYMODULE}
