package builtin.google.compute.google0043_test

import rego.v1

import data.builtin.google.compute.google0043 as check
import data.lib.test

test_deny_instance_ip_forwarding_enabled if {
	inp := {"google": {"compute": {"instances": [{"canipforward": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_ip_forwarding_disabled if {
	inp := {"google": {"compute": {"instances": [{"canipforward": {"value": false}}]}}}

	res := check.deny with input as inp
	res == set()
}

test_allow_instance_ip_forwarding_is_not_specified if {
	inp := {"google": {"compute": {"instances": [{}]}}}

	res := check.deny with input as inp
	res == set()
}
