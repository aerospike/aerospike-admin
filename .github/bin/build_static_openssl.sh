#!/usr/bin/env bash
# Build a static-only OpenSSL pinned to our macOS support floor.
#
# Homebrew bottles carry the building runner's minos in their libcrypto.a and
# libssl.a members. Linked into cryptography's _rust.abi3.so, the final Mach-O
# is stamped with MACOSX_DEPLOYMENT_TARGET while the code inside was compiled
# for a later release, and check_min_os.sh reads only the final object.
#
# Usage: build_static_openssl.sh <prefix> <min_macos>
set -euo pipefail

# NOTHING UPDATES THIS PIN FOR US. Dependabot watches pip, github-actions and
# docker, not a version string in a shell script. The arm64 bundle picks up
# OpenSSL fixes from cryptography's own wheels; the Intel bundle ships whatever
# is pinned here, with every CI gate green. Bump both lines on any 3.6.x
# security release, and move off 3.6 when it goes end-of-support -- not an LTS
# line. Checksums: https://github.com/openssl/openssl/releases
VERSION="3.6.4"
SHA256="9bffaa1ad1e07b354c21bd3324ec02fa15579f45a7d0494b3e74bc449b7333ef"
URL="https://github.com/openssl/openssl/releases/download/openssl-${VERSION}/openssl-${VERSION}.tar.gz"

prefix="${1:-}"
min_os="${2:-}"
if [[ -z "$prefix" || -z "$min_os" ]]; then
	echo "usage: $(basename "$0") <prefix> <min_macos>" >&2
	exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$(uname -m)" in
x86_64) target="darwin64-x86_64-cc" ;;
arm64) target="darwin64-arm64-cc" ;;
*)
	echo "error: unsupported architecture $(uname -m)" >&2
	exit 1
	;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> fetching OpenSSL ${VERSION}"
curl -fsSL --retry 3 -o "$work/openssl.tar.gz" "$URL"

echo "==> verifying checksum"
echo "${SHA256}  $work/openssl.tar.gz" | shasum -a 256 -c -

tar -xzf "$work/openssl.tar.gz" -C "$work"
cd "$work/openssl-${VERSION}"

# no-shared so nothing dynamic can be vendored into the bundle later. no-module
# builds the legacy provider into libcrypto: left as a module it is a separate
# legacy.dylib under MODULESDIR, a build-time path that does not exist on a
# user's machine, so every asadm run warns that legacy failed to load.
echo "==> configuring $target for macOS $min_os"
MACOSX_DEPLOYMENT_TARGET="$min_os" \
	./Configure "$target" no-shared no-module no-tests no-docs --prefix="$prefix" --libdir=lib

echo "==> building"
MACOSX_DEPLOYMENT_TARGET="$min_os" make -j"$(sysctl -n hw.ncpu)" >/dev/null
MACOSX_DEPLOYMENT_TARGET="$min_os" make install_sw >/dev/null

# A legacy provider left outside the archive loads fine here, off the prefix we
# just installed, and fails only once the bundle is on a machine without it.
# Not grep -q: under pipefail an early exit leaves nm dying of SIGPIPE, and a
# symbol that is present reads as absent.
echo "==> checking the legacy provider is in libcrypto, not a module"
if ! nm -g "$prefix/lib/libcrypto.a" | grep ossl_legacy_provider_init >/dev/null; then
	echo "error: libcrypto.a has no built-in legacy provider; configure with no-module" >&2
	exit 1
fi

# Prove the floor rather than trusting the flag. Once these are linked in,
# member minos is unrecoverable, so this is the only scan they get.
echo "==> checking archive members against the macOS $min_os floor"
members="$work/members"
mkdir -p "$members"
for lib in libcrypto libssl; do
	(cd "$members" && ar x "$prefix/lib/${lib}.a")
done
"$here/check_min_os.sh" "$min_os" "$members"

echo "==> static OpenSSL ${VERSION} installed at $prefix"
