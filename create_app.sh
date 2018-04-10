#!/bin/bash
# This script requires the pex utility to be installed:
#   pip install pex
#

# Create the asadm wheel
pip wheel -w . . -r requirements.txt

# Create the pex executable using the asadm wheel and the dependencies from requirements.txt
pex -v -f . --disable-cache asadm jsonschema lib pexpect pyasn1 pyOpenSSL python_bcrypt mock ply toml unittest2 yappi -c asadm.py -o asadm.pex

# Wheels no longer needed, remove them
rm *.whl
