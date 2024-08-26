package builtin.google.compute.google0044_test

import rego.v1

import data.builtin.google.compute.google0044 as check
import data.lib.test

test_deny_instance_use_default_service_account if {
	inp := {"google": {"compute": {"instances": [{"serviceaccount": {"isdefault": {"value": true}}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_use_proper_service_account if {
	inp := {"google": {"compute": {"instances": [{"serviceaccount": {
		"isdefault": {"value": false},
		"email": {"value": "proper@email.com"},
	}}]}}}

	res := check.deny with input as inp
	res == set()
}
