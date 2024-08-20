package builtin.github.branch_protections.github0004_test

import rego.v1

import data.builtin.github.branch_protections.github0004 as check
import data.lib.test

test_allow_signed_commits_enabled if {
	inp := {"github": {"branchprotections": [{"requiresignedcommits": {"value": true}}]}}

	res := check.deny with input as inp
	res == set()
}

test_deny_signed_commits_disabled if {
	inp := {"github": {"branchprotections": [{"requiresignedcommits": {"value": false}}]}}

	res := check.deny with input as inp
	count(res) == 1
}
