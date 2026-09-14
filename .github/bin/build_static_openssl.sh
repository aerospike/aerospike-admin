#!/usr/bin/env bash
# Build a static-only OpenSSL pinned to our macOS support floor.
#
# Homebrew builds each bottle on its own macOS, so its libcrypto.a/libssl.a
# members carry that runner's minos. Linking those into cryptography's
# _rust.abi3.so leaves the final Mach-O stamped with MACOSX_DEPLOYMENT_TARGET
# while the code inside it was compiled for a later release -- and
# check_min_os.sh reads only the final object, so the mismatch is invisible to
# it. Compiling OpenSSL ourselves against the floor is what makes the floor the
# binary claims actually true.
#
# Usage: build_static_openssl.sh <prefix> <min_macos>
set -euo pipefail

# THIS OPENSSL SHIPS INSIDE THE INTEL macOS asadm, AND NOTHING UPDATES IT FOR US.
#
# Dependabot covers pip, github-actions and docker; no ecosystem watches a
# version string in a shell script. The asymmetry is what makes it easy to
# miss: on an OpenSSL security release the arm64 bundle picks up the fix by
# itself, because cryptography's own wheels vendor a current OpenSSL, while
# the Intel bundle keeps linking whatever is pinned here -- with every CI gate
# green. On any OpenSSL 3.6.x security release, bump both lines below. The
# cache keys hash this file, so a bump invalidates the OpenSSL and bundle
# caches on its own. Checksums: https://github.com/openssl/openssl/releases
#
# 3.6 is not an LTS line. When it goes end-of-support, move to a supported
# branch here rather than letting the pin outlive it.
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

# no-shared so nothing dynamic can be vendored into the bundle later; no-tests
# and no-docs keep a build we only ever link against from taking minutes we
# do not need to spend.
echo "==> configuring $target for macOS $min_os"
MACOSX_DEPLOYMENT_TARGET="$min_os" \
	./Configure "$target" no-shared no-tests no-docs --prefix="$prefix" --libdir=lib

echo "==> building"
MACOSX_DEPLOYMENT_TARGET="$min_os" make -j"$(sysctl -n hw.ncpu)" >/dev/null
MACOSX_DEPLOYMENT_TARGET="$min_os" make install_sw >/dev/null

# Prove the floor rather than trusting the flag: unpack the archives and reuse
# the same scanner the shipping bundle is held to.
echo "==> checking archive members against the macOS $min_os floor"
members="$work/members"
mkdir -p "$members"
for lib in libcrypto libssl; do
	(cd "$members" && ar x "$prefix/lib/${lib}.a")
done
"$here/check_min_os.sh" "$min_os" "$members"

echo "==> static OpenSSL ${VERSION} installed at $prefix"
