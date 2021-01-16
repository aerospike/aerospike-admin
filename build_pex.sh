#!/bin/bash
set -e

BUILD_ROOT="./build/"
REQUIREMENT_FILE="./requirements.txt"
PEX_PYTHONS=""
SHEBANG=`cat pex_shebang.txt`

IFS=',' read -ra ADDR <<< "$PYTHONS"
for i in "${ADDR[@]}"; do
        "$i"/pip wheel -w "$BUILD_ROOT"tmp/asadm "$BUILD_ROOT"tmp/asadm
        "$i"/pip wheel --no-cache-dir --wheel-dir="$BUILD_ROOT"tmp/wheels -r $REQUIREMENT_FILE
        PEX_PYTHONS="$PEX_PYTHONS --python=$i/python "
done

if [[ -z "${CODESIGNMAC}" ]]; then
        echo "codesign environment variable not set.  Skipping codesign of .so in wheels"
else
        echo "codesign environment variable is set.  Running codesign of .so in wheels"
        pip install wheel
        export PATH="/Library/Frameworks/Python.framework/Versions/2.7/bin:$PATH"
        ls -lat "$BUILD_ROOT"tmp/wheels
		for WHEEL_PATH in "$BUILD_ROOT"tmp/wheels/* ; do
			wheel unpack "$WHEEL_PATH"
			PACKAGE_WHEEL=$(basename "$WHEEL_PATH")
			PACKAGE=$(echo $PACKAGE_WHEEL| cut -d'-' -f 1,2)
			find "$PACKAGE" -type f -name "*.so" -print0 | xargs -0 echo
			find "$PACKAGE" -type f -name "*.so" -print0 | xargs -0 codesign --force --options runtime --sign "Developer ID Application: Aerospike, Inc." ; \
			wheel pack "$PACKAGE"
			rm -rf "$PACKAGE"
			rename s/cffi-1.14.3/cffi-1.14.3-2/ cffi-*.whl
			mv "$PACKAGE_WHEEL" "$BUILD_ROOT"tmp/wheels/
		done
        ls -lat "$BUILD_ROOT"tmp/wheels
fi

cp "$BUILD_ROOT"tmp/asadm/*.whl "$BUILD_ROOT"tmp/wheels

if [ -x "$(command -v auditwheel)" ]; then
        mkdir -p "$BUILD_ROOT"tmp/audit/wheels
        for whl in "$BUILD_ROOT"tmp/wheels/*.whl; do
                auditwheel repair "$whl" --plat manylinux2010_x86_64 -w "$BUILD_ROOT"tmp/audit/wheels
        done
        cp "$BUILD_ROOT"tmp/audit/wheels/*.whl "$BUILD_ROOT"tmp/wheels
        rm "$BUILD_ROOT"tmp/audit/wheels/*.whl
fi

pip install pex
pex -v -r $REQUIREMENT_FILE $PEX_PYTHONS --python-shebang="$SHEBANG" --repo="$BUILD_ROOT"tmp/wheels --no-pypi --no-build --disable-cache asadm -c asadm.py -o "$BUILD_ROOT"tmp/asadm/asadm.pex
