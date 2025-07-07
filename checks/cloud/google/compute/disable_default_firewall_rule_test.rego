package builtin.google.compute.google0073_test

import rego.v1

import data.builtin.google.compute.google0073 as check

test_deny_default_firewall_rule if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
			"ports": [{"fromport": {"value": 0}, "toport": {"value": 65535}}],
		},
		"sourceranges": [{"value": "10.128.0.0/9"}],
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_custom_firewall_rule if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
			"ports": [{"fromport": {"value": 80}, "toport": {"value": 80}}],
		},
		"sourceranges": [{"value": "0.0.0.0/0"}],
	}]}}]}}}

	res := check.deny with input as inp
	res == set()
} 