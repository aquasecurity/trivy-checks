package builtin.google.compute.google0042_test

import rego.v1

import data.builtin.google.compute.google0042 as check
import data.lib.test

test_deny_compute_os_login_disabled if {
	inp := {"google": {"compute": {"projectmetadata": {"enableoslogin": {"value": false}}}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_compute_os_login_enabled if {
	inp := {"google": {"compute": {"projectmetadata": {"enableoslogin": {"value": true}}}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_compute_os_login_is_not_managed if {
	inp := {"google": {"compute": {"projectmetadata": {
		"__defsec_metadata": {"managed": false},
		"enableoslogin": {"value": false},
	}}}}

	res := check.deny with input as inp
	res == set()
}
