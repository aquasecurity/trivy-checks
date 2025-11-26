package builtin.azure.network.azure0076_test

import rego.v1

import data.builtin.azure.network.azure0076 as check

test_deny_network_interface_has_public_ip if {
	inp := {"azure": {"network": {"networkinterfaces": [{"haspublicip": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_network_interface_no_public_ip if {
	inp := {"azure": {"network": {"networkinterfaces": [{"haspublicip": {"value": false}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
