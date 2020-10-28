#!/bin/bash

BUILD_ROOT="./build/"

for WHEEL_PATH in "$BUILD_ROOT"tmp/wheels/* ; do
    wheel unpack "$WHEEL_PATH"
    PACKAGE_WHEEL=$(basename "$WHEEL_PATH")
    PACKAGE=$(echo $PACKAGE_WHEEL| cut -d'-' -f 1,2)
    find "$PACKAGE" -type f -name "*.so" -print0 | xargs -0 echo
    find "$PACKAGE" -type f -name "*.so" -print0 | xargs -0 codesign --force --options runtime --sign "Developer ID Application: Aerospike, Inc." ; \
    wheel pack "$PACKAGE"
    rm -rf "$PACKAGE"
    mv "$PACKAGE_WHEEL" "$BUILD_ROOT"tmp/wheels/
done

