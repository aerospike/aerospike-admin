#!/bin/bash
# This script requires the pex utility to be installed:
#   pip install pex
#

# Create the asadm wheel
pip wheel -w . .

# Create the pex executable using the asadm wheel and the dependencies from requirements.txt
pex -v -f . -r requirements.txt --disable-cache asadm -c asadm.py -o asadm.pex

# Wheels no longer needed, remove them
rm *.whl
