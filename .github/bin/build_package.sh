#!/usr/bin/env bash
set -euo pipefail
[[ -n "${DEBUG:-}" ]] && set -x

function assert_dynamic_deps() {
	local bundle="$GIT_DIR/build/bin/asadm"
	local allowed="libc.so.6 libm.so.6 libpthread.so.0 libdl.so.2 librt.so.1 libutil.so.1
		libgcc_s.so.1 libstdc++.so.6 libz.so.1 libcrypt.so.1
		libssl.so.3 libcrypto.so.3 libssl.so.1.1 libcrypto.so.1.1
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

function assert_system_openssl() {
	local bundle="$GIT_DIR/build/bin/asadm"
	local fail=0

	local bundled
	bundled=$(find "$bundle" \( -name 'libssl*.so*' -o -name 'libcrypto*.so*' -o -path '*/ossl-modules/*' \) -printf '%P\n')
	if [ -n "$bundled" ]; then
		echo "the bundle ships its own OpenSSL ($(tr '\n' ' ' <<< "$bundled")); asadm must load the host's" >&2
		fail=1
	fi

	if builds_cryptography_from_source "$ENV_DISTRO"; then
		local rust_ext
		rust_ext=$(find "$bundle" -path '*/cryptography/*' -name '_rust*.so' | head -1)
		if [ -z "$rust_ext" ]; then
			echo "no cryptography extension found under $bundle" >&2
			fail=1
		elif ! readelf -d "$rust_ext" | grep -q 'NEEDED.*\[libcrypto\.so'; then
			echo "${rust_ext#"$bundle"/} carries its own OpenSSL; build cryptography from source against the host's" >&2
			fail=1
		fi
	fi

	case "$ENV_DISTRO" in
	el9 | el10 | amzn2023)
		if ! command -v objdump >/dev/null; then
			echo "objdump (binutils) is needed to read the OpenSSL symbol versions the bundle imports" >&2
			return 1
		fi
		local floor floor_minor above_floor
		floor="$("$GIT_DIR/.github/bin/openssl_floor.sh")"
		floor_minor="$("$GIT_DIR/.github/bin/openssl_floor.sh" -minor)"
		above_floor=$({ find "$bundle" -name '*.so*' -type f -exec objdump -T {} + 2>/dev/null || true; } |
			{ grep -oE 'OPENSSL_3\.[0-9]+' || true; } | sort -u | awk -F. -v floor="$floor_minor" '$2 > floor' | tr '\n' ' ')
		if [ -n "$above_floor" ]; then
			echo "the bundle needs OpenSSL symbols above 3.$floor_minor ($above_floor), but the rpm requires only openssl-libs >= 1:$floor. Build against OpenSSL 3.$floor_minor (install_deps holds el9 and el10 at their UBI base image's OpenSSL), or raise OPENSSL_FLOOR in pkg/Makefile" >&2
			fail=1
		fi
		;;
	esac

	if [ "$fail" -eq 0 ]; then
		echo "assert_system_openssl: asadm loads the host's OpenSSL"
	fi
	return $fail
}

# Runs before `make`, whose pipenv install then finds the locked version present.
# No build isolation: pip would fetch the build tools unpinned, so they come
# hash-checked from Pipfile.lock, and maturin from the venv's bin on PATH.
# --force-reinstall replaces a PyPI wheel an earlier build left in the venv.
function install_cryptography_from_source() {
	pipenv --venv >/dev/null 2>&1 || pipenv --python 3.12
	local lock_reqs="$GIT_DIR/.github/bin/lock_requirements.py" reqs
	reqs=$(mktemp)
	python3 -I "$lock_reqs" "$GIT_DIR/Pipfile.lock" maturin setuptools cffi pycparser >"$reqs"
	pipenv run python -m pip install --no-deps --require-hashes -r "$reqs"
	python3 -I "$lock_reqs" "$GIT_DIR/Pipfile.lock" cryptography >"$reqs"
	PATH="$(pipenv --venv)/bin:$PATH" pipenv run python -m pip install --no-deps --require-hashes \
		--no-build-isolation --no-binary cryptography --force-reinstall -r "$reqs"
	rm -f "$reqs"
}

function build_packages() {
	if [ "${ENV_DISTRO:-}" = "" ]; then
		echo "ENV_DISTRO is not set" >&2
		return 1
	fi
	export PATH=$PATH:/opt/golang/go/bin
	GIT_DIR=$(git rev-parse --show-toplevel)

	# pkg/Makefile picks the rpm's OpenSSL requirement from BUILD_DISTRO, and
	# assert_system_openssl checks the bundle by ENV_DISTRO; they must agree.
	export BUILD_DISTRO="${BUILD_DISTRO:-$ENV_DISTRO}"

	# shellcheck source=.github/bin/install_deps.sh
	source "$GIT_DIR/.github/bin/install_deps.sh"
	if builds_cryptography_from_source "$ENV_DISTRO"; then
		export PATH="$PATH:$HOME/.cargo/bin"
	fi

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
	if builds_cryptography_from_source "$ENV_DISTRO"; then
		install_cryptography_from_source
	fi
	make

	assert_dynamic_deps
	assert_system_openssl

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

}
