package builtin.google.compute.google0031_test

import rego.v1

import data.builtin.google.compute.google0031 as check
import data.lib.test

test_deny_instance_network_interface_has_public_ip if {
	inp := {"google": {"compute": {"instances": [{"networkinterfaces": [{"haspublicip": {"value": true}}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_instance_network_interface_has_no_public_ip if {
	inp := {"google": {"compute": {"instances": [{"networkinterfaces": [{"haspublicip": {"value": false}}]}]}}}

	res := check.deny with input as inp
	res == set()
}
