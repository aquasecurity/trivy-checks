package builtin.google.compute.google0035_test

import rego.v1

import data.builtin.google.compute.google0035 as check

test_deny_egress_rule_with_multiple_public_destinations if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"egressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
		},
		"destinationranges": [
			{"value": "0.0.0.0/0"},
			{"value": "1.2.3.4/32"},
		],
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_egress_rule_with_private_destination if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"egressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
		},
		"destinationranges": [{"value": "1.2.3.4/32"}],
	}]}}]}}}

	res := check.deny with input as inp
	res == set()
}
