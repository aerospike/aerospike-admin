#!/usr/bin/env bash
# Install the Rust toolchain cryptography builds with, from a rustup-init pinned
# by version and sha256. Used by install_deps.sh and the FIPS e2e client image.
set -euo pipefail

RUSTUP_VERSION="1.29.3"
RUST_VERSION="${RUST_VERSION:-1.95.0}"

case "$(uname -m)" in
x86_64) sha256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55 ;;
aarch64) sha256=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282 ;;
*)
	echo "no pinned rustup-init for $(uname -m)" >&2
	exit 1
	;;
esac

# rustup-init picks its behaviour from its own file name, so keep that name.
dir="$(mktemp -d)"
rustup_init="$dir/rustup-init"
curl -fL --retry 5 --retry-delay 5 "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/$(uname -m)-unknown-linux-gnu/rustup-init" -o "$rustup_init"
echo "${sha256}  ${rustup_init}" | sha256sum -c -
chmod +x "$rustup_init"
"$rustup_init" -y --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION"
rm -rf "$dir"
