#!/bin/bash
set -e

BUILD_ROOT="./build/"
REQUIREMENT_FILE="./requirements.txt"
PEX_PYTHONS=""
SHEBANG="/usr/bin/env python"

IFS=',' read -ra ADDR <<< "$PYTHONS"
for i in "${ADDR[@]}"; do
        "$i"/pip wheel -w "$BUILD_ROOT"tmp/asadm "$BUILD_ROOT"tmp/asadm
        "$i"/pip wheel --no-cache-dir --wheel-dir="$BUILD_ROOT"tmp/wheels -r $REQUIREMENT_FILE
        PEX_PYTHONS="$PEX_PYTHONS --python=$i/python "
done
cp "$BUILD_ROOT"tmp/asadm/*.whl "$BUILD_ROOT"tmp/wheels

if [ -x "$(command -v auditwheel)" ]; then
        mkdir -p "$BUILD_ROOT"tmp/audit/wheels
        for whl in "$BUILD_ROOT"tmp/wheels/*.whl; do
                auditwheel repair "$whl" --plat manylinux2010_x86_64 -w "$BUILD_ROOT"tmp/audit/wheels
        done
        cp "$BUILD_ROOT"tmp/audit/wheels/*.whl "$BUILD_ROOT"tmp/wheels
        rm "$BUILD_ROOT"tmp/audit/wheels/*.whl
fi

pex -v -r $REQUIREMENT_FILE $PEX_PYTHONS --python-shebang="$SHEBANG" --repo="$BUILD_ROOT"tmp/wheels --no-pypi --no-build --disable-cache asadm -c asadm.py -o "$BUILD_ROOT"tmp/asadm/asadm.pex
