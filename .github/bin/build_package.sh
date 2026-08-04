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

# Assert the aerospike-tools relations actually reached the package metadata.
# Building only proves fpm accepted the flag; these fields are what make the
# bundle overlap installable, and their absence produces no output anywhere.
# The negative checks matter as much as the positive ones: a Conflicts on the deb
# would make plain `dpkg -i` hard-fail, and fpm's --replaces maps to rpm
# Obsoletes, which would erase the whole bundle instead of taking over files.
function assert_pkg_relations() {
	local pkg
	case "$ENV_DISTRO" in
		ubuntu*|debian*)
			pkg=$(find "$GIT_DIR/pkg/target" -name '*.deb' -print -quit)
			if [ -z "$pkg" ]; then
				echo "assert_pkg_relations: no .deb found under pkg/target" >&2
				return 1
			fi
			if ! dpkg-deb -f "$pkg" Replaces | grep -qx 'aerospike-tools'; then
				echo "deb is missing 'Replaces: aerospike-tools'" >&2
				return 1
			fi
			if [ -n "$(dpkg-deb -f "$pkg" Conflicts)" ]; then
				echo "deb must not declare Conflicts: $(dpkg-deb -f "$pkg" Conflicts)" >&2
				return 1
			fi
			;;
		el*|amzn*)
			pkg=$(find "$GIT_DIR/pkg/target" -name '*.rpm' -print -quit)
			if [ -z "$pkg" ]; then
				echo "assert_pkg_relations: no .rpm found under pkg/target" >&2
				return 1
			fi
			if ! rpm -qp --qf '%{CONFLICTS}\n' "$pkg" | grep -qx 'aerospike-tools'; then
				echo "rpm is missing 'Conflicts: aerospike-tools'" >&2
				return 1
			fi
			if rpm -qp --qf '%{OBSOLETES}\n' "$pkg" | grep -qx 'aerospike-tools'; then
				echo "rpm must not Obsolete aerospike-tools (that erases the bundle)" >&2
				return 1
			fi
			;;
		*)
			echo "assert_pkg_relations: no relations declared for $ENV_DISTRO (tar); skipping"
			return 0
			;;
	esac
	echo "assert_pkg_relations: aerospike-tools relations present and correct"
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

	if [[ $ENV_DISTRO == *"ubuntu"* ]]; then
		make deb
	elif [[ $ENV_DISTRO == *"debian"* ]]; then
		make deb
	elif [[ $ENV_DISTRO == *"el"* ]]; then
		make rpm
	elif [[ $ENV_DISTRO == *"amzn"* ]]; then
		make rpm
	else
		make tar
	fi

	assert_pkg_relations
}
