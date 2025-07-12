package builtin.google.compute.google0073_test

import rego.v1

import data.builtin.google.compute.google0073 as check

test_deny_default_internal_rule if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
		},
		"sourceranges": [{"value": "10.128.0.0/9"}],
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_deny_default_public_rule if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
		},
		"sourceranges": [{"value": "0.0.0.0/0"}],
	}]}}]}}}

	res := check.deny with input as inp
	count(res) == 1
}

test_allow_restrictive_rule if {
	inp := {"google": {"compute": {"networks": [{"firewall": {"ingressrules": [{
		"firewallrule": {
			"isallow": {"value": true},
			"enforced": {"value": true},
			"protocol": {"value": "tcp"},
		},
		"sourceranges": [{"value": "10.0.1.0/24"}],
	}]}}]}}}

	res := check.deny with input as inp
	res == set()
}
