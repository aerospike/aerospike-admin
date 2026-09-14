#!/usr/bin/env bash
# Fail if cryptography's compiled extension links OpenSSL dynamically.
#
# PyInstaller flattens every vendored dylib into one directory, keyed by base
# name. Python's own _ssl and _hashlib bring a libssl.3.dylib/libcrypto.3.dylib
# along, so a cryptography that also links OpenSSL dynamically collides with
# them: one copy wins, and if it is not the one cryptography was compiled
# against, the binary dies at startup on a missing symbol.
#
# cryptography publishes arm64-only macOS wheels from 49.0.0 on, so the Intel
# leg compiles from the sdist and has to link OpenSSL statically to stay out of
# that collision. The published wheels are already statically linked, so this
# holds on every platform.
#
# Usage: check_crypto_static_openssl.sh <path>...
set -euo pipefail

if [[ $# -eq 0 ]]; then
	echo "usage: $(basename "$0") <path>..." >&2
	exit 1
fi

checked=0
violations=0
while IFS= read -r f; do
	# Keep "otool could not read it" apart from "it has no OpenSSL dylib".
	# Piped straight into grep, pipefail makes both look identical, and this
	# guard would then report success on a build it never actually inspected.
	if ! out=$(otool -L "$f" 2>&1); then
		echo "error: otool failed on $f" >&2
		printf '%s\n' "$out" >&2
		exit 1
	fi
	checked=$((checked + 1))
	if deps=$(printf '%s\n' "$out" | grep -E 'libssl|libcrypto'); then
		echo "  $f" >&2
		echo "$deps" | sed 's/^/    /' >&2
		violations=$((violations + 1))
	fi
done < <(find "$@" -type f -name '_rust.abi3.so')

if ((violations > 0)); then
	{
		echo "error: cryptography links OpenSSL dynamically (listed above)."
		echo "Build it against a static OpenSSL: set OPENSSL_DIR and OPENSSL_STATIC=1."
	} >&2
	exit 1
fi

if ((checked == 0)); then
	echo "error: no cryptography _rust.abi3.so found under: $*" >&2
	exit 1
fi

echo "==> cryptography links OpenSSL statically ($checked extension(s) checked)"
