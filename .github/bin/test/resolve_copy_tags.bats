#!/usr/bin/env bats
#
# Table tests for resolve_copy_tags.sh — the VERSION-to-Docker-Hub-tag
# derivation used by copy-tools-images-to-dockerhub.yml.

setup() {
	RESOLVE="$(cd "$BATS_TEST_DIRNAME/.." && pwd)/resolve_copy_tags.sh"
}

# assert_ok <version> <tags> <alias-from> <alias-tags> <tag-exists> \
#           <want_semver> <want_release> <want_tags> <want_alias_from> <want_alias_tags>
assert_ok() {
	local version="$1" tags="$2" alias_from="$3" alias_tags="$4" tag_exists="$5"
	local want_semver="$6" want_release="$7" want_tags="$8" want_alias_from="$9" want_alias_tags="${10}"

	run "$RESOLVE" "$version" "$tags" "$alias_from" "$alias_tags" "$tag_exists"
	[ "$status" -eq 0 ]
	[ "$output" = "version=${version}
semver=${want_semver}
release=${want_release}
tags=${want_tags}
alias-from=${want_alias_from}
alias-tags=${want_alias_tags}" ]
}

@test "rc VERSION with a release tag derives tags and aliases" {
	assert_ok "5.0.3-rc5" "" "" "" true \
		"5.0.3" "5.0.3-5" \
		"5.0.3-5,5.0.3-5-amd64,5.0.3-5-arm64" \
		"5.0.3-5" "5.0.3,latest"
}

@test "plain VERSION with a release tag derives iteration 1" {
	assert_ok "5.0.3" "" "" "" true \
		"5.0.3" "5.0.3-1" \
		"5.0.3-1,5.0.3-1-amd64,5.0.3-1-arm64" \
		"5.0.3-1" "5.0.3,latest"
}

@test "rc VERSION without a release tag refuses derived tags" {
	run "$RESOLVE" "5.0.3-rc5" "" "" "" false
	[ "$status" -eq 1 ]
	[[ "$output" == *"has no release tag"* ]]
}

@test "missing tag-exists is treated as no release tag" {
	run "$RESOLVE" "5.0.3-rc5"
	[ "$status" -eq 1 ]
	[[ "$output" == *"has no release tag"* ]]
}

@test "explicit tags bypass the release-tag guard" {
	assert_ok "5.0.4-rc1" "5.0.3-5,5.0.3-5-amd64" "" "" false \
		"5.0.4" "5.0.4-1" \
		"5.0.3-5,5.0.3-5-amd64" \
		"5.0.4-1" "5.0.4,latest"
}

@test "whitespace inputs trim and derive" {
	run "$RESOLVE" "  5.0.3-rc5  " "  " "  " "  " true
	[ "$status" -eq 0 ]
	[ "$output" = "version=5.0.3-rc5
semver=5.0.3
release=5.0.3-5
tags=5.0.3-5,5.0.3-5-amd64,5.0.3-5-arm64
alias-from=5.0.3-5
alias-tags=5.0.3,latest" ]
}

@test "alias-tags none disables aliases" {
	assert_ok "5.0.3-rc5" "" "" "none" true \
		"5.0.3" "5.0.3-5" \
		"5.0.3-5,5.0.3-5-amd64,5.0.3-5-arm64" \
		"5.0.3-5" ""
}

@test "alias-tags dash disables aliases" {
	assert_ok "5.0.3-rc5" "" "" "-" true \
		"5.0.3" "5.0.3-5" \
		"5.0.3-5,5.0.3-5-amd64,5.0.3-5-arm64" \
		"5.0.3-5" ""
}

@test "beta VERSION refuses default aliases" {
	run "$RESOLVE" "5.0.3-beta1" "" "" "" true
	[ "$status" -eq 1 ]
	[[ "$output" == *"non-rc pre-release identifier"* ]]
}

@test "beta VERSION with explicit alias-tags succeeds" {
	assert_ok "5.0.3-beta1" "" "" "beta,none-latest" true \
		"5.0.3" "5.0.3-beta1-1" \
		"5.0.3-beta1-1,5.0.3-beta1-1-amd64,5.0.3-beta1-1-arm64" \
		"5.0.3-beta1-1" "beta,none-latest"
}

@test "beta VERSION with alias-tags none copies tags only" {
	assert_ok "5.0.3-beta1" "" "" "none" true \
		"5.0.3" "5.0.3-beta1-1" \
		"5.0.3-beta1-1,5.0.3-beta1-1-amd64,5.0.3-beta1-1-arm64" \
		"5.0.3-beta1-1" ""
}

@test "explicit alias-from is kept" {
	assert_ok "5.0.3-rc5" "" "5.0.3-5" "5.0.3" true \
		"5.0.3" "5.0.3-5" \
		"5.0.3-5,5.0.3-5-amd64,5.0.3-5-arm64" \
		"5.0.3-5" "5.0.3"
}

@test "empty VERSION fails" {
	run "$RESOLVE" ""
	[ "$status" -eq 1 ]
	[[ "$output" == *"VERSION is empty"* ]]
}

@test "VERSION without MAJOR.MINOR.PATCH fails" {
	run "$RESOLVE" "rc5" "" "" "" true
	[ "$status" -eq 1 ]
	[[ "$output" == *"does not start with MAJOR.MINOR.PATCH"* ]]
}

@test "pkg_release rejection of rc0 kills the step" {
	run "$RESOLVE" "5.0.3-rc0" "5.0.3-0" "" "none" true
	[ "$status" -eq 1 ]
	[[ "$output" == *"rc numbering starts at rc1"* ]]
}
