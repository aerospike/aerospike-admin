#!/bin/bash
# This script requires the pex utility to be installed:
#   pip install pex
#

# Create the asadm wheel
pip wheel -w . .

# Create the pex executable using the asadm wheel and the dependencies from requirements.txt
pex -v -f . --disable-cache asadm -r requirements.txt -c asadm.py -o asadm.pex

# Wheel no longer needed, remove it
rm *.whl
