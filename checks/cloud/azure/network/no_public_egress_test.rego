package builtin.azure.network.azure0051_test

import rego.v1

import data.builtin.azure.network.azure0051 as check
import data.lib.test

test_deny_outbound_rule_with_wildcard_destination_address if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"allow": {"value": true},
		"outbound": {"value": true},
		"destinationaddresses": [{"value": "*"}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_outbound_rule_with_private_destination_address if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"allow": {"value": true},
		"outbound": {"value": true},
		"destinationaddresses": [{"value": "10.0.0.0/16"}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
