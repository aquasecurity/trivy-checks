package builtin.github.repositories.github0001_test

import rego.v1

import data.builtin.github.repositories.github0001 as check
import data.lib.test

test_allow_private_repo if {
	inp := {"github": {"repositories": [{"public": {"value": false}}]}}

	res := check.deny with input as inp
	res == set()
}

test_deny_public_repo if {
	inp := {"github": {"repositories": [{"public": {"value": true}}]}}

	res := check.deny with input as inp
	count(res) == 1
}
