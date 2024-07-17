package builtin.google.compute.google0030_test

import rego.v1

import data.builtin.google.compute.google0030 as check
import data.lib.test

test_deny_project_level_ssh_key_blocking_disabled if {
	inp := {"google": {"compute": {"instances": [{"enableprojectsshkeyblocking": {"value": false}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_project_level_ssh_key_blocking_enabled if {
	inp := {"google": {"compute": {"instances": [{"enableprojectsshkeyblocking": {"value": true}}]}}}

	res := check.deny with input as inp
	res == set()
}
