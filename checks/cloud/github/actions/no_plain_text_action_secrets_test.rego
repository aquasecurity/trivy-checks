package builtin.github.actions.github0002_test

import rego.v1

import data.builtin.github.actions.github0002 as check
import data.lib.test

test_allow_secret_without_plain_text if {
	inp := {"github": {"environmentsecrets": [{"plaintextvalue": {"value": ""}}]}}

	res := check.deny with input as inp
	res == set()
}

test_deny_secret_with_plain_text if {
	inp := {"github": {"environmentsecrets": [{"plaintextvalue": {"value": "secret"}}]}}

	res := check.deny with input as inp
	count(res) == 1
}
