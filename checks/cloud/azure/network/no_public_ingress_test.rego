package builtin.azure.network.azure0047_test

import rego.v1

import data.builtin.azure.network.azure0047 as check
import data.lib.test

test_deny_inbound_rule_with_wildcard_source_address if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"allow": {"value": true},
		"outbound": {"value": false},
		"sourceaddresses": [{"value": "*"}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_inbound_rule_with_private_source_address if {
	inp := {"azure": {"network": {"securitygroups": [{"rules": [{
		"allow": {"value": true},
		"outbound": {"value": false},
		"sourceaddresses": [{"value": "10.0.0.0/16"}],
	}]}]}}}

	res := check.deny with input as inp
	count(res) == 0
}
