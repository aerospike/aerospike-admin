#!/usr/bin/env bash
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