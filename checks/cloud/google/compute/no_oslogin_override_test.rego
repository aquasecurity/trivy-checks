package builtin.google.compute.google0036_test

import rego.v1

import data.builtin.google.compute.google0036 as check
import data.lib.test

test_deny_instance_os_login_disabled if {
	inp := {"google": {"compute": {"instances": [{"osloginenabled": {"value": false}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_os_login_enabled if {
	inp := {"google": {"compute": {"instances": [{"osloginenabled": {"value": true}}]}}}

	res := check.deny with input as inp
	res == set()
}
