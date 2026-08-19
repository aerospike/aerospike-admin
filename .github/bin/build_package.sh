#!/usr/bin/env bash
set -euo pipefail
[[ -n "${DEBUG:-}" ]] && set -x

function assert_dynamic_deps() {
	local bundle="$GIT_DIR/build/bin/asadm"
	local allowed="libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1
		libgcc_s.so.1 libstdc++.so.6 libz.so.1 libcrypt.so.1
		ld-linux-x86-64.so.2 ld-linux-aarch64.so.1"
	local provided
	provided=$(find "$bundle" -name 'lib*.so*' -printf '%f\n')

	local elf lib needed fail=0
	while IFS= read -r elf; do
		needed=$(readelf -d "$elf" 2>/dev/null | awk '/\(NEEDED\)/ { gsub(/[][]/, "", $NF); print $NF }') || true
		[ -z "$needed" ] && continue
		for lib in $needed; do
			if printf '%s\n' "$provided" | grep -qxF "$lib"; then
				continue
			fi
			if ! printf '%s\n' $allowed | grep -qxF "$lib"; then
				echo "${elf#"$bundle"/} has unexpected dynamic dependency $lib; bundle it or add it to the allowlist and the package depends" >&2
				fail=1
			fi
		done
	done < <(find "$bundle" -type f)

	if [ "$fail" -eq 0 ]; then
		echo "assert_dynamic_deps: all host-loaded DT_NEEDED entries within allowlist"
	fi
	return $fail
}

function deb_relations() {
	dpkg-deb -f "$1" "$2" | tr ',' '\n' \
		| sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/[[:space:]][[:space:]]*/ /g'
}

function tools_split_version() {
	sed -n 's/^TOOLS_SPLIT_VERSION[[:space:]]*=[[:space:]]*//p' "$GIT_DIR/pkg/Makefile" | head -1
}

# Print one relation name per line for an rpm array tag. %{TAG} outside a [...]
# iteration block formats only the FIRST element, and rpm normalizes dependency
# arrays into sorted order -- so which entry is visible depends on alphabetical
# luck against `aerospike-tools`, not on what the spec declared. That made the
# Obsoletes check below fail OPEN: verified on ubi9 that a package declaring both
# `Obsoletes: aaa-other` and `Obsoletes: aerospike-tools` reports only
# `aaa-other`, so an rpm that erases the bundle passed the guard. The [...] form
# emits every entry, and emits nothing (not "(none)") for an absent tag, so the
# positive checks still fail correctly on a missing field.
function rpm_relations() {
	rpm -qp --qf "[%{$2}\n]" "$1" | awk '{print $1}'
}

# Assert the aerospike-tools relations actually reached the package metadata.
# Building only proves fpm accepted the flag; these fields are what make the
# bundle overlap installable, and their absence produces no output anywhere.
# The negative checks matter as much as the positive ones: `Conflicts:
# aerospike-tools` on the deb would make plain `dpkg -i` hard-fail, and fpm's
# --replaces maps to rpm Obsoletes, which would erase the whole bundle instead of
# taking over files.
#
# Takes the package format as $1 rather than re-deriving it from $ENV_DISTRO.
# Deriving it twice meant this guard could disagree with the dispatcher that
# actually chose the format -- the dispatcher matches substrings (*el*) while a
# case glob matches prefixes (el*), so `rhel9` built an rpm and then hit a
# default branch that returned 0 while reporting a tar. A gate whose default is
# success is not a gate.
function assert_pkg_relations() {
	local fmt="${1:-}" pkg split
	split=$(tools_split_version)
	if [ -z "$split" ]; then
		echo "assert_pkg_relations: TOOLS_SPLIT_VERSION not found in pkg/Makefile" >&2
		return 1
	fi
	case "$fmt" in
		deb)
			pkg=$(find "$GIT_DIR/pkg/target" -name '*.deb' -print -quit)
			if [ -z "$pkg" ]; then
				echo "assert_pkg_relations: no .deb found under pkg/target" >&2
				return 1
			fi
			if ! deb_relations "$pkg" Replaces | grep -qxF "aerospike-tools (<< $split)"; then
				echo "deb is missing 'Replaces: aerospike-tools (<< $split)'" >&2
				return 1
			fi
			if ! deb_relations "$pkg" Breaks | grep -qxF "aerospike-tools (<< $split)"; then
				echo "deb is missing 'Breaks: aerospike-tools (<< $split)'" >&2
				return 1
			fi
			if deb_relations "$pkg" Replaces | grep -qx 'aerospike-tools' \
				|| deb_relations "$pkg" Breaks | grep -qx 'aerospike-tools'; then
				echo "deb carries an UNVERSIONED aerospike-tools relation; it must be bounded (<< $split) or it hits the metapackage too" >&2
				return 1
			fi
			if deb_relations "$pkg" Conflicts | grep -q 'aerospike-tools'; then
				echo "deb must not Conflict with aerospike-tools (Breaks+Replaces is the split handoff)" >&2
				return 1
			fi
			;;
		rpm)
			pkg=$(find "$GIT_DIR/pkg/target" -name '*.rpm' -print -quit)
			if [ -z "$pkg" ]; then
				echo "assert_pkg_relations: no .rpm found under pkg/target" >&2
				return 1
			fi
			if ! rpm -qp --conflicts "$pkg" | sed 's/[[:space:]][[:space:]]*/ /g' \
				| grep -qxF "aerospike-tools < $split"; then
				echo "rpm is missing 'Conflicts: aerospike-tools < $split'" >&2
				return 1
			fi
			if rpm -qp --conflicts "$pkg" | grep -qx 'aerospike-tools'; then
				echo "rpm carries an UNVERSIONED Conflicts: aerospike-tools; it must be bounded (< $split) or the metapackage becomes unsatisfiable" >&2
				return 1
			fi
			if rpm_relations "$pkg" OBSOLETES | grep -qx 'aerospike-tools'; then
				echo "rpm must not Obsolete aerospike-tools (that erases the bundle)" >&2
				return 1
			fi
			;;
		tar)
			echo "assert_pkg_relations: no relations declared for the tar target; skipping"
			return 0
			;;
		*)
			echo "assert_pkg_relations: unknown package format '$fmt'" >&2
			return 1
			;;
	esac
	echo "assert_pkg_relations: versioned aerospike-tools split relations present and correct ($fmt)"
	return 0
}

# Exercise the bundle overlap as a real package-manager transaction. Metadata
# presence (assert_pkg_relations) proves fpm emitted the field; it does NOT prove
# dpkg resolves the overlap or that dnf names the conflict, which is what the
# original bug report was about:
#
#   dpkg: error processing archive aerospike-asadm_...deb (--install):
#    trying to overwrite '/opt/aerospike/bin/asadm/asadm', which is also in
#    package aerospike-tools
#
# The real bundle is not reachable from CI, so stand in a stub that ships the one
# path the report names, built with the fpm that just built the real package. That
# validates the resolver semantics -- the part in doubt -- rather than the real
# bundle's file list, which is not.
#
# Wrapper so the stub is always removed, including on the failure paths -- leaving
# a fake aerospike-tools installed would poison anything that ran afterwards.
function assert_bundle_overlap() {
	local fmt="$1" rc=0
	_bundle_overlap_cleanup "$fmt"
	_bundle_overlap_check "$fmt" || rc=$?
	_bundle_overlap_cleanup "$fmt"
	return "$rc"
}

# Remove BOTH packages, real one first. The real package has to go too: on the
# Obsoletes mutation dnf erases the stub and leaves aerospike-asadm installed,
# which then blocks the stub from installing on any later call. Removing only the
# stub left the check non-repeatable.
function _bundle_overlap_cleanup() {
	case "$1" in
		deb)
			dpkg --purge aerospike-asadm >/dev/null 2>&1 || true
			dpkg --purge aerospike-tools >/dev/null 2>&1 || true
			;;
		rpm)
			rpm -e aerospike-asadm >/dev/null 2>&1 || true
			rpm -e aerospike-tools >/dev/null 2>&1 || true
			;;
	esac
	return 0
}

function _bundle_overlap_check() {
	local fmt="$1" stub_root old_pkg meta_pkg real_pkg rc out split
	split=$(tools_split_version)
	[ -n "$split" ] || { echo "assert_bundle_overlap: TOOLS_SPLIT_VERSION not found in pkg/Makefile" >&2; return 1; }
	stub_root=$(mktemp -d)
	mkdir -p "$stub_root/root/opt/aerospike/bin/asadm"
	echo "stub bundle payload" > "$stub_root/root/opt/aerospike/bin/asadm/asadm"

	case "$fmt" in
		deb)
			real_pkg=$(find "$GIT_DIR/pkg/target" -name '*.deb' -print -quit)
			( cd "$stub_root" && fpm --force -s dir -t deb -n aerospike-tools -v 12.0.0 \
				-C "$stub_root/root" --package "$stub_root/old.deb" . >/dev/null )
			( cd "$stub_root" && fpm --force -s empty -t deb -n aerospike-tools -v "$split" \
				--package "$stub_root/meta.deb" >/dev/null )
			old_pkg="$stub_root/old.deb"
			meta_pkg="$stub_root/meta.deb"

			dpkg -i "$old_pkg" >/dev/null || { echo "assert_bundle_overlap: stub old bundle would not install" >&2; return 1; }

			rc=0
			out=$(dpkg -i "$real_pkg" 2>&1) || rc=$?
			if [ "$rc" -eq 0 ]; then
				echo "assert_bundle_overlap: dpkg -i SUCCEEDED over the old bundle -- Breaks (<< $split) did not take effect" >&2
				return 1
			fi
			if printf '%s\n' "$out" | grep -qi 'trying to overwrite'; then
				echo "assert_bundle_overlap: dpkg died on a raw file overwrite, not a named break -- the versioned relations did not take effect" >&2
				printf '%s\n' "$out" >&2
				return 1
			fi
			if ! printf '%s\n' "$out" | grep -qi 'breaks aerospike-tools'; then
				echo "assert_bundle_overlap: dpkg failed but not with a named break on aerospike-tools; not actionable" >&2
				printf '%s\n' "$out" >&2
				return 1
			fi

			if ! out=$(dpkg -i "$meta_pkg" "$real_pkg" 2>&1); then
				echo "assert_bundle_overlap: one-shot migration (metapackage + this package in a single dpkg run) FAILED" >&2
				printf '%s\n' "$out" >&2
				return 1
			fi
			if ! dpkg -S /opt/aerospike/bin/asadm/asadm 2>/dev/null | grep -q 'aerospike-asadm'; then
				echo "assert_bundle_overlap: /opt/aerospike/bin/asadm/asadm is not owned by aerospike-asadm after migration" >&2
				dpkg -S /opt/aerospike/bin/asadm/asadm >&2 || true
				return 1
			fi
			if ! dpkg-query -W -f='${Status} ${Version}' aerospike-tools 2>/dev/null | grep -q "install ok installed $split"; then
				echo "assert_bundle_overlap: aerospike-tools is not installed at the metapackage version $split after migration" >&2
				dpkg-query -W aerospike-tools >&2 || true
				return 1
			fi
			echo "assert_bundle_overlap: deb refuses the old bundle with a named break and migrates cleanly through the $split metapackage"
			;;
		rpm)
			real_pkg=$(find "$GIT_DIR/pkg/target" -name '*.rpm' -print -quit)
			( cd "$stub_root" && fpm --force -s dir -t rpm -n aerospike-tools -v 12.0.0 \
				-C "$stub_root/root" --package "$stub_root/old.rpm" . >/dev/null )
			( cd "$stub_root" && fpm --force -s empty -t rpm -n aerospike-tools -v "$split" \
				--package "$stub_root/meta.rpm" >/dev/null )
			old_pkg="$stub_root/old.rpm"
			meta_pkg="$stub_root/meta.rpm"

			rpm -i "$old_pkg" >/dev/null || { echo "assert_bundle_overlap: stub old bundle would not install" >&2; return 1; }

			# Uses rpm directly rather than dnf: dnf is a Python program, and by this
			# point in the build install_deps has put an asdf-managed Python ahead of
			# the system one on PATH, so `dnf` dies with "ModuleNotFoundError: No
			# module named 'dnf'". rpm is a compiled binary and unaffected. Testing at
			# the rpm layer still proves the Conflicts is enforced and names the
			# package, which is the substance of the promise.
			rc=0
			out=$(rpm -i "$real_pkg" 2>&1) || rc=$?
			if [ "$rc" -eq 0 ]; then
				echo "assert_bundle_overlap: rpm install SUCCEEDED over the old bundle -- Conflicts (< $split) did not take effect" >&2
				return 1
			fi
			if printf '%s\n' "$out" | grep -qi 'conflicts with file from'; then
				echo "assert_bundle_overlap: rpm died on a raw FILE collision, not a named package conflict -- Conflicts did not take effect" >&2
				printf '%s\n' "$out" >&2
				return 1
			fi
			if printf '%s\n' "$out" | grep -qi 'obsoleted by'; then
				echo "assert_bundle_overlap: rpm reports aerospike-tools as OBSOLETED, not conflicting -- that erases the bundle instead of refusing" >&2
				printf '%s\n' "$out" >&2
				return 1
			fi
			if ! printf '%s\n' "$out" | grep -qi 'conflicts with'; then
				echo "assert_bundle_overlap: rpm failed but not with a named aerospike-tools conflict; not actionable" >&2
				printf '%s\n' "$out" >&2
				return 1
			fi

			if ! out=$(rpm -U "$meta_pkg" "$real_pkg" 2>&1); then
				echo "assert_bundle_overlap: one-shot migration (metapackage + this package in a single rpm transaction) FAILED" >&2
				printf '%s\n' "$out" >&2
				return 1
			fi
			if ! rpm -qf /opt/aerospike/bin/asadm/asadm 2>/dev/null | grep -q 'aerospike-asadm'; then
				echo "assert_bundle_overlap: /opt/aerospike/bin/asadm/asadm is not owned by aerospike-asadm after migration" >&2
				rpm -qf /opt/aerospike/bin/asadm/asadm >&2 || true
				return 1
			fi
			if ! rpm -q --qf '%{VERSION}\n' aerospike-tools 2>/dev/null | grep -qxF "$split"; then
				echo "assert_bundle_overlap: aerospike-tools is not installed at the metapackage version $split after migration" >&2
				rpm -q aerospike-tools >&2 || true
				return 1
			fi
			echo "assert_bundle_overlap: rpm refuses the old bundle with a named conflict and migrates cleanly through the $split metapackage"
			;;
		tar)
			echo "assert_bundle_overlap: no relations declared for the tar target; skipping"
			;;
		*)
			echo "assert_bundle_overlap: unknown package format '$fmt'" >&2
			return 1
			;;
	esac
	rm -rf "$stub_root"
	return 0
}

function build_packages() {
	if [ "${ENV_DISTRO:-}" = "" ]; then
		echo "ENV_DISTRO is not set" >&2
		return 1
	fi
	export PATH=$PATH:/opt/golang/go/bin
	GIT_DIR=$(git rev-parse --show-toplevel)

	# Source of truth for the version, in precedence order:
	#   1. $PKG_VERSION env (CI sets this from VERSION file)
	#   2. VERSION file at repo root
	#   3. git describe (legacy clones without VERSION file)
	if [[ -n "${PKG_VERSION:-}" ]]; then
		VERSION="$PKG_VERSION"
	elif [[ -f "$GIT_DIR/VERSION" ]]; then
		VERSION=$(tr -d '[:space:]' < "$GIT_DIR/VERSION")
	else
		VERSION=$(git describe --tags --always --abbrev=9)
	fi
	export VERSION
	echo "build_package.sh version: $VERSION"

	# build
	cd "$GIT_DIR" || exit 1
	make clean
	make

	assert_dynamic_deps

	# package
	cd "$GIT_DIR"/pkg || exit 1
	make clean
	echo "building package for $BUILD_DISTRO"

	# Single source of truth for the package format: chosen once here, then handed
	# to assert_pkg_relations so the guard cannot disagree with what was built.
	local pkg_fmt
	if [[ $ENV_DISTRO == *"ubuntu"* || $ENV_DISTRO == *"debian"* ]]; then
		pkg_fmt=deb
	elif [[ $ENV_DISTRO == *"el"* || $ENV_DISTRO == *"amzn"* ]]; then
		pkg_fmt=rpm
	else
		pkg_fmt=tar
	fi
	make "$pkg_fmt"

	assert_pkg_relations "$pkg_fmt"
	assert_bundle_overlap "$pkg_fmt"
}
