#!/usr/bin/env bash
# Holds OpenSSL at the EL9/EL10 base image's version, so host-linked extensions
# import no OpenSSL symbols newer than OPENSSL_FLOOR (pkg/Makefile), while every
# other package still updates from UBI. UBI keeps only each package's newest
# build, so the Rocky vault for the base image's release is added beside it, for
# `dnf --nobest` to fall back to and for the named packages (default:
# openssl-devel) at exactly the held version.
#
# Usage: hold_el_openssl.sh <distro> [package...]. A no-op on other distros.
set -euo pipefail

distro="${1:-${ENV_DISTRO:-}}"
shift || true
case "$distro" in
el9) rel=9.6 ;;
el10) rel=10.0 ;;
*)
	echo "hold_el_openssl: nothing to hold for '${distro:-<unset>}'"
	exit 0
	;;
esac

# The hold stops dnf from ever updating OpenSSL, which only a throwaway build
# or test container can afford.
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && [ -z "${CI:-}" ]; then
	echo "hold_el_openssl: refusing to run outside a container or CI: it stops dnf from updating OpenSSL on this host. Build ${distro} in its UBI image." >&2
	exit 1
fi

floor="$("$(dirname "${BASH_SOURCE[0]}")/openssl_floor.sh")"
floor_minor="$("$(dirname "${BASH_SOURCE[0]}")/openssl_floor.sh" -minor)"

ver="$(rpm -q --qf '%{VERSION}' openssl-libs)"
case "$ver" in
3.*)
	minor="${ver#3.}"
	minor="${minor%%.*}"
	;;
*)
	echo "hold_el_openssl: unexpected openssl-libs version '${ver}'" >&2
	exit 1
	;;
esac
lowest="$(printf '%s\n' "$floor" "$ver" | sort -V | head -1)"
if [ "$minor" -gt "$floor_minor" ] || [ "$lowest" != "$floor" ]; then
	echo "hold_el_openssl: openssl-libs ${ver} is not on the 3.${floor_minor} line at or above ${floor} (OPENSSL_FLOOR in pkg/Makefile). Build ${distro} in the base image the workflows name, or move the floor." >&2
	exit 1
fi

grep -qx 'excludepkgs=openssl\*' /etc/dnf/dnf.conf || printf 'excludepkgs=openssl*\n' >>/etc/dnf/dnf.conf

# UBI images lack Rocky's keyring, so dnf imports it over HTTPS on first use.
# cost= takes a build both repos carry from UBI; priority= would instead hide
# the older vault builds --nobest falls back to.
vault="https://dl.rockylinux.org/vault/rocky/${rel}"
: >/etc/yum.repos.d/rocky-vault.repo
for repo in BaseOS AppStream CRB devel; do
	{
		printf '[rocky-vault-%s]\n' "$(tr '[:upper:]' '[:lower:]' <<<"$repo")"
		printf 'name=Rocky Linux %s - %s (vault)\n' "$rel" "$repo"
		printf 'baseurl=%s/%s/%s/os/\n' "$vault" "$repo" "$(uname -m)"
		printf 'gpgcheck=1\n'
		printf 'cost=2000\n'
		printf 'gpgkey=https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-%s\n' "${rel%%.*}"
		printf 'enabled=1\n\n'
	} >>/etc/yum.repos.d/rocky-vault.repo
done

evr="$(rpm -q --qf '%{VERSION}-%{RELEASE}' openssl-libs)"
specs=()
for pkg in "${@:-openssl-devel}"; do
	specs+=("${pkg}-${evr}")
done
dnf -y --disableexcludes=main install "${specs[@]}"

held="$(rpm -q --qf '%{VERSION}-%{RELEASE}' openssl-libs)"
if [ "$held" != "$evr" ]; then
	echo "hold_el_openssl: openssl-libs moved from ${evr} to ${held}" >&2
	exit 1
fi
echo "hold_el_openssl: ${distro} holds openssl-libs ${evr} (floor ${floor}); installed ${specs[*]}"
