#!/usr/bin/env bash
#
# Strip foreign code signatures from a staged macOS install root.
#
# The shared mac signer (aerospike/shared-workflows sign-mac-artifacts) codesigns
# every embedded Mach-O, but HARD-ERRORS on any binary already signed by an
# identity other than ours:
#
#     ERROR: <path> is signed with a different identity: Software Signing
#
# asadm's PyInstaller tree bundles Apple's /usr/bin/less
# (pyinstaller-build.spec: `binaries = [('/usr/bin/less','.')]`), which carries
# Apple's "Software Signing" authority, so the signing job fails on it. Removing
# the foreign signature makes the signer treat the binary as unsigned and sign it
# with our Developer ID -- exactly what the legacy pkg/Makefile.mac path did, via
# `codesign --force` over every executable in the tree.
#
# Only foreign signatures are stripped; anything already signed by Aerospike is
# left alone so the signer's "already signed with correct identity" fast path
# still applies.
#
# NOTE: a stripped binary will not execute on arm64 until it is re-signed. That
# is a transient state inside the build root -- the signing job re-signs it
# before the pkg ships, and the post-install check asserts nothing unsigned made
# it into the installed tree.
set -euo pipefail

root="${1:?usage: strip-foreign-signatures.sh <staged-root>}"

echo "Stripping foreign code signatures under ${root}:"
found=0
while IFS= read -r bin; do
    file "$bin" | grep -q "Mach-O" || continue
    auth=$(codesign -dvv "$bin" 2>&1 | sed -n 's/^Authority=//p' | head -1 || true)
    [[ -n "$auth" ]] || continue                # unsigned: the signer will sign it
    [[ "$auth" == *"Aerospike"* ]] && continue  # ours: the signer skips it
    echo "  ${bin#"$root"/} (was: $auth)"
    codesign --remove-signature "$bin"
    found=$((found + 1))
done < <(find "$root" -type f -perm +111)
echo "Stripped ${found} foreign-signed binary(ies)."
