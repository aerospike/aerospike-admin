#!/usr/bin/env bash
# Derive Docker Hub copy tags from a VERSION string.
#
# VERSION may carry -rcN (e.g. 5.0.3-rc5). Hub aliases only want the
# three-digit semver; pkg_release.sh folds rcN into the image tag
# (5.0.3-rc5 -> 5.0.3-5).
#
# Derived tags require the git tag <VERSION> to exist so an unreleased
# bump cannot be copied as :latest. Explicit tags skip that guard.
# Derived aliases are refused when VERSION keeps a non-rc pre-release
# identifier (e.g. 5.0.3-beta1). alias-tags of "none" or "-" disables
# aliases.
#
# Usage: resolve_copy_tags.sh <version> [tags] [alias-from] [alias-tags] [tag-exists]
#   version     VERSION file contents (MAJOR.MINOR.PATCH or with suffix)
#   tags        comma-separated copy tags; empty = derive from VERSION
#   alias-from  source tag for extra dest tags; empty = VERSION release tag
#   alias-tags  extra dest tags; empty = "<semver>,latest"; none/- = no aliases
#   tag-exists  "true" if git tag <version> exists (required when tags is empty)
#
# Prints KEY=value lines: version, semver, release, tags, alias-from, alias-tags.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_RELEASE="${SCRIPT_DIR}/pkg_release.sh"

trim() {
	local value="${1:-}"
	value="${value#"${value%%[![:space:]]*}"}"
	value="${value%"${value##*[![:space:]]}"}"
	printf '%s' "$value"
}

is_none() {
	local value="$1"
	[[ "$value" == "-" || "$value" == "none" || "$value" == "NONE" || "$value" == "None" ]]
}

version="$(trim "${1:-}")"
tags_input="$(trim "${2:-}")"
alias_from_input="$(trim "${3:-}")"
alias_tags_input="$(trim "${4:-}")"
tag_exists="$(trim "${5:-false}")"

if [[ -z "$version" ]]; then
	echo "VERSION is empty." >&2
	exit 1
fi
if [[ ! "$version" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]]; then
	echo "VERSION '$version' does not start with MAJOR.MINOR.PATCH." >&2
	exit 1
fi
semver="${BASH_REMATCH[1]}"
pkg_version=$("$PKG_RELEASE" "$version" version)
release=$("$PKG_RELEASE" "$version" release)

if [[ -z "$tags_input" ]]; then
	if [[ "$tag_exists" != "true" ]]; then
		echo "VERSION ${version} has no release tag — pass explicit tags or dispatch on the release tag." >&2
		exit 1
	fi
	tags="${release},${release}-amd64,${release}-arm64"
else
	tags="$tags_input"
fi

if [[ -z "$alias_from_input" ]]; then
	alias_from="$release"
else
	alias_from="$alias_from_input"
fi

if is_none "$alias_tags_input"; then
	alias_tags=""
elif [[ -z "$alias_tags_input" ]]; then
	if [[ "$pkg_version" != "$semver" ]]; then
		echo "VERSION '$version' carries a non-rc pre-release identifier; pass alias-tags explicitly (or 'none')." >&2
		exit 1
	fi
	alias_tags="${semver},latest"
else
	alias_tags="$alias_tags_input"
fi

printf 'version=%s\n' "$version"
printf 'semver=%s\n' "$semver"
printf 'release=%s\n' "$release"
printf 'tags=%s\n' "$tags"
printf 'alias-from=%s\n' "$alias_from"
printf 'alias-tags=%s\n' "$alias_tags"
