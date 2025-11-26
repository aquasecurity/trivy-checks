package builtin.azure.network.azure0075_test

import rego.v1

import data.builtin.azure.network.azure0075 as check

test_deny_ip_forwarding_enabled if {
	inp := {"azure": {"network": {"networkinterfaces": [{"enableipforwarding": {"value": true}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_ip_forwarding_disabled if {
	inp := {"azure": {"network": {"networkinterfaces": [{"enableipforwarding": {"value": false}}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
